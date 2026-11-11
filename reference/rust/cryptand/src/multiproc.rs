//! `13-operations.md` §8 — multi-process readers, feature bit `MULTIPROC_READ`.
//! **One writing process, any number of reading processes.**
//!
//! Immutability makes reading from another process nearly free: every extent a
//! superblock names is one nothing will modify. The only coordination needed is
//! **retention** — the writer must not reclaim extents a reader still holds.
//! The sidecar primitives are here; [`crate::engine::Engine`] wires them in:
//! the writer publishes and heartbeats itself and folds live slots into its
//! floor at each commit, a read-only open claims a slot and heartbeats it.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::pager::{lock_byte, owner_only};
use crate::posio::PosIo;

/// PLAN 4.7: the sidecar path is predictable, so a planted symlink would
/// redirect our writes. Refuse to follow one.
fn no_follow(o: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(o, libc::O_NOFOLLOW);
    o
}

/// `"CLK1"` little-endian (§8).
pub const MAGIC: u32 = 0x314B_4C43;
pub const HEADER_BYTES: u64 = 24;
pub const SLOT_BYTES: u64 = 24;
pub const DEFAULT_SLOT_COUNT: u32 = 64;
/// §8 rule 1's default.
pub const DEFAULT_READER_HEARTBEAT_MS: u64 = 2000;
/// §8 rule 3: a slot older than this multiple of the interval is stale.
pub const STALE_MULTIPLIER: u64 = 3;
/// §8: every slot read-modify-write holds an exclusive lock on this byte, past
/// EOF so a Windows lock never blocks a plain read. The same byte in all three
/// implementations is what makes the claim a cross-language CAS.
pub const CLAIM_LOCK_BYTE: u64 = 1 << 40;

/// Wall clock in ms; a clock before 1970 reads 0 rather than panicking.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn pid() -> u64 {
    std::process::id() as u64
}

/// `<name>.cryptand-lock` (`00-conventions.md` §2).
pub fn sidecar_path(database: &Path) -> PathBuf {
    let mut s = database.as_os_str().to_os_string();
    s.push("-lock");
    PathBuf::from(s)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub index: u32,
    pub pid: u64,
    pub commit_id: u64,
    pub heartbeat_ms: u64,
}

impl Slot {
    pub fn is_free(&self) -> bool {
        self.pid == 0
    }

    /// §8 rule 3.
    pub fn is_stale(&self, now: u64, interval_ms: u64) -> bool {
        !self.is_free() && now.saturating_sub(self.heartbeat_ms) > STALE_MULTIPLIER * interval_ms
    }
}

/// A claimed slot: this reader's only while **both** `pid` and `commit_id`
/// still match (a second reader in this process, or a reused pid, has the
/// same pid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderSlot {
    pub index: u32,
    pub pid: u64,
    pub commit_id: u64,
}

/// Rule 4: which of the two ways a reader ended up volatile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolatileReason {
    /// The sidecar cannot be written (or created).
    SidecarReadOnly,
    /// Every slot is held by a live reader.
    SidecarFull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderMode {
    /// Holding a slot: the writer's floor accounts for it.
    Slotted(ReaderSlot),
    /// Pinning nothing; the superblock is revalidated before each operation.
    Volatile(VolatileReason),
}

impl ReaderMode {
    pub fn is_volatile(self) -> bool {
        matches!(self, ReaderMode::Volatile(_))
    }
}

pub struct Sidecar {
    file: File,
    slot_count: u32,
    interval_ms: u64,
    read_only: bool,
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

impl Sidecar {
    /// The writer: open the sidecar keeping live readers' slots, or create
    /// (re-initialize) it when absent or invalid; publish `writer_pid`.
    pub fn open_writer(database: &Path, interval_ms: u64) -> Result<Sidecar> {
        let s = Sidecar::open_rw(database, interval_ms, pid())?;
        s.locked(|| {
            s.write_header_u64(8, pid())?;
            s.write_header_u64(16, now_ms())
        })?;
        Ok(s)
    }

    /// A reader: open read-write, creating it with `writer_pid` 0 when absent;
    /// `None` when it can neither be written nor read (rule 4's read-only case
    /// with nothing to read either).
    pub fn open_reader(database: &Path, interval_ms: u64) -> Result<Option<Sidecar>> {
        match Sidecar::open_rw(database, interval_ms, 0) {
            Ok(s) => Ok(Some(s)),
            Err(Error::Io(_)) => {
                match no_follow(OpenOptions::new().read(true)).open(sidecar_path(database)) {
                    Ok(file) => {
                        let mut s = Sidecar { file, slot_count: 0, interval_ms, read_only: true };
                        match s.read_header()? {
                            Some(n) => {
                                s.slot_count = n;
                                Ok(Some(s))
                            }
                            None => Ok(None),
                        }
                    }
                    Err(_) => Ok(None),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn open_rw(database: &Path, interval_ms: u64, writer_pid: u64) -> Result<Sidecar> {
        let file = no_follow(owner_only(OpenOptions::new().read(true).write(true).create(true)))
            .open(sidecar_path(database))
            .map_err(|e| Error::Io(format!("lock sidecar: {e}")))?;
        let mut s = Sidecar { file, slot_count: 0, interval_ms, read_only: false };
        // Under the lock, so a concurrent creator's half-written header is
        // never mistaken for an invalid one.
        s.slot_count = s.locked(|| match s.read_header()? {
            Some(n) => Ok(n),
            None => {
                let mut b = vec![0u8; (HEADER_BYTES + DEFAULT_SLOT_COUNT as u64 * SLOT_BYTES) as usize];
                b[0..4].copy_from_slice(&MAGIC.to_le_bytes());
                b[4..8].copy_from_slice(&DEFAULT_SLOT_COUNT.to_le_bytes());
                b[8..16].copy_from_slice(&writer_pid.to_le_bytes());
                b[16..24].copy_from_slice(&now_ms().to_le_bytes());
                s.file.set_len(0)?;
                s.file.write_all_at(&b, 0)?;
                s.file.sync_data()?;
                Ok(DEFAULT_SLOT_COUNT)
            }
        })?;
        Ok(s)
    }

    /// `Some(slot_count)` for a valid header whose slots are all present.
    fn read_header(&self) -> Result<Option<u32>> {
        let mut h = [0u8; HEADER_BYTES as usize];
        if self.file.read_exact_at(&mut h, 0).is_err() {
            return Ok(None);
        }
        let n = u32::from_le_bytes(h[4..8].try_into().unwrap());
        let len = self.file.metadata()?.len();
        let ok = u32::from_le_bytes(h[0..4].try_into().unwrap()) == MAGIC
            && n > 0
            && len >= HEADER_BYTES + n as u64 * SLOT_BYTES;
        Ok(ok.then_some(n))
    }

    /// Runs `f` holding the claim lock (§8): spin, because a holder keeps it
    /// for one slot scan.
    fn locked<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.lock()?;
        let r = f();
        let _ = lock_byte(&self.file, CLAIM_LOCK_BYTE, false);
        r
    }

    fn lock(&self) -> Result<()> {
        let start = std::time::Instant::now();
        while !lock_byte(&self.file, CLAIM_LOCK_BYTE, true)? {
            if start.elapsed() > Duration::from_secs(10) {
                return Err(Error::Locked("lock sidecar claim lock held for 10 s".into()));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    pub fn slot_count(&self) -> u32 {
        self.slot_count
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn write_header_u64(&self, at: u64, v: u64) -> Result<()> {
        Ok(self.file.write_all_at(&v.to_le_bytes(), at)?)
    }

    fn header_u64(&self, at: u64) -> Result<u64> {
        let mut b = [0u8; 8];
        self.file.read_exact_at(&mut b, at)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn writer_pid(&self) -> Result<u64> {
        self.header_u64(8)
    }

    /// Rule 5: the writer refreshes on the schedule it asks of readers.
    pub fn refresh_writer(&self, now: u64) -> Result<()> {
        self.write_header_u64(16, now)
    }

    /// Writer close: `writer_pid` 0 means "no live writer" to every reader.
    pub fn clear_writer(&self) -> Result<()> {
        self.write_header_u64(8, 0)
    }

    /// Rule 5: a `writer_pid` of 0 or an aged writer heartbeat is no writer.
    pub fn writer_alive(&self, now: u64) -> Result<bool> {
        let beat = self.header_u64(16)?;
        Ok(self.writer_pid()? != 0 && now.saturating_sub(beat) <= STALE_MULTIPLIER * self.interval_ms)
    }

    pub fn read_slot(&self, index: u32) -> Result<Slot> {
        let mut b = [0u8; SLOT_BYTES as usize];
        self.file.read_exact_at(&mut b, HEADER_BYTES + index as u64 * SLOT_BYTES)?;
        Ok(Slot { index, pid: u64_at(&b, 0), commit_id: u64_at(&b, 8), heartbeat_ms: u64_at(&b, 16) })
    }

    pub fn slots(&self) -> Result<Vec<Slot>> {
        (0..self.slot_count).map(|i| self.read_slot(i)).collect()
    }

    fn write_slot(&self, index: u32, pid: u64, commit_id: u64, heartbeat_ms: u64) -> Result<()> {
        let mut b = [0u8; SLOT_BYTES as usize];
        b[0..8].copy_from_slice(&pid.to_le_bytes());
        b[8..16].copy_from_slice(&commit_id.to_le_bytes());
        b[16..24].copy_from_slice(&heartbeat_ms.to_le_bytes());
        Ok(self.file.write_all_at(&b, HEADER_BYTES + index as u64 * SLOT_BYTES)?)
    }

    fn owns(&self, s: &ReaderSlot) -> Result<bool> {
        let cur = self.read_slot(s.index)?;
        Ok(cur.pid == s.pid && cur.commit_id == s.commit_id)
    }

    /// Rule 1: claim a free or stale slot and publish `commit_id`.
    pub fn claim(&self, commit_id: u64, now: u64) -> Result<Option<ReaderSlot>> {
        if self.read_only {
            return Ok(None);
        }
        self.locked(|| {
            for i in 0..self.slot_count {
                let slot = self.read_slot(i)?;
                if slot.is_free() || slot.is_stale(now, self.interval_ms) {
                    self.write_slot(i, pid(), commit_id, now)?;
                    return Ok(Some(ReaderSlot { index: i, pid: pid(), commit_id }));
                }
            }
            Ok(None)
        })
    }

    /// Moves a held slot to a newer superblock; `false` if it was reclaimed.
    pub fn repin(&self, slot: &mut ReaderSlot, commit_id: u64, now: u64) -> Result<bool> {
        self.locked(|| {
            if !self.owns(slot)? {
                return Ok(false);
            }
            self.write_slot(slot.index, slot.pid, commit_id, now)?;
            slot.commit_id = commit_id;
            Ok(true)
        })
    }

    /// Rule 1's refresh and rule 3's detection: `false` means this reader's
    /// slot was reclaimed and it MUST reopen.
    pub fn heartbeat(&self, slot: &ReaderSlot, now: u64) -> Result<bool> {
        self.locked(|| {
            if !self.owns(slot)? {
                return Ok(false);
            }
            self.write_slot(slot.index, slot.pid, slot.commit_id, now)?;
            Ok(true)
        })
    }

    pub fn release(&self, slot: &ReaderSlot) -> Result<()> {
        self.locked(|| {
            if self.owns(slot)? {
                self.write_slot(slot.index, 0, 0, 0)?;
            }
            Ok(())
        })
    }

    /// Rules 2 and 3 for the writer, under one lock: reclaims stale slots and
    /// returns the lowest `commit_id` any live slot pins.
    pub fn reclaim_and_min_pinned(&self, now: u64) -> Result<Option<u64>> {
        self.locked(|| self.reclaim_unlocked(now))
    }

    /// F-222: [`Self::reclaim_and_min_pinned`] with the claim lock kept until
    /// the guard drops, which the writer does once the superblock carrying
    /// this floor is written. A claim then lands before this read (counted)
    /// or after that superblock (the reader's re-read sees it and re-pins);
    /// released in between, a claim could land unseen by both and the next
    /// window reused its pages.
    pub fn reclaim_and_hold(self: &Arc<Self>, now: u64) -> Result<(Option<u64>, ClaimGuard)> {
        self.lock()?;
        let guard = ClaimGuard(self.clone());
        Ok((self.reclaim_unlocked(now)?, guard))
    }

    fn reclaim_unlocked(&self, now: u64) -> Result<Option<u64>> {
        let mut min = None;
        for slot in self.slots()? {
            if slot.is_stale(now, self.interval_ms) {
                self.write_slot(slot.index, 0, 0, 0)?;
            } else if !slot.is_free() {
                min = Some(min.map_or(slot.commit_id, |m: u64| m.min(slot.commit_id)));
            }
        }
        Ok(min)
    }
}

/// The claim lock, held until dropped.
pub struct ClaimGuard(Arc<Sidecar>);

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        let _ = lock_byte(&self.0.file, CLAIM_LOCK_BYTE, false);
    }
}

/// A background heartbeat: `beat` runs every `interval / 2` until it returns
/// `false` or this is dropped.
pub struct Beat {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Beat {
    fn spawn(interval_ms: u64, mut beat: impl FnMut() -> bool + Send + 'static) -> Beat {
        let (tx, rx) = mpsc::channel::<()>();
        let period = Duration::from_millis((interval_ms / 2).max(1));
        let thread = std::thread::spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(period) {
                if !beat() {
                    break;
                }
            }
        });
        Beat { stop: Some(tx), thread: Some(thread) }
    }
}

impl Drop for Beat {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The engine's side of the sidecar.
pub enum Attached {
    Writer { sidecar: Arc<Sidecar>, _beat: Beat },
    Reader { sidecar: Option<Arc<Sidecar>>, mode: ReaderMode, lost: Arc<AtomicBool>, _beat: Option<Beat> },
}

impl Attached {
    pub(crate) fn writer(sidecar: Sidecar) -> Attached {
        let sidecar = Arc::new(sidecar);
        let s = sidecar.clone();
        let beat = Beat::spawn(sidecar.interval_ms, move || s.refresh_writer(now_ms()).is_ok());
        Attached::Writer { sidecar, _beat: beat }
    }

    pub(crate) fn reader(sidecar: Option<Sidecar>, mode: ReaderMode) -> Attached {
        let sidecar = sidecar.map(Arc::new);
        let lost = Arc::new(AtomicBool::new(false));
        let beat = match (mode, &sidecar) {
            (ReaderMode::Slotted(slot), Some(sc)) => {
                let (sc, lost) = (sc.clone(), lost.clone());
                Some(Beat::spawn(sc.interval_ms, move || {
                    let ok = sc.heartbeat(&slot, now_ms()).unwrap_or(false);
                    if !ok {
                        lost.store(true, Ordering::Release);
                    }
                    ok
                }))
            }
            _ => None,
        };
        Attached::Reader { sidecar, mode, lost, _beat: beat }
    }

    /// `None` for a writer.
    pub fn reader_mode(&self) -> Option<ReaderMode> {
        match self {
            Attached::Reader { mode, .. } => Some(*mode),
            Attached::Writer { .. } => None,
        }
    }

    /// Rule 3: this reader's slot was reclaimed.
    pub fn slot_lost(&self) -> bool {
        matches!(self, Attached::Reader { lost, .. } if lost.load(Ordering::Acquire))
    }

    /// Rule 5, for a reader to report: is a writing process live?
    pub fn writer_alive(&self) -> bool {
        match self {
            Attached::Writer { .. } => true,
            Attached::Reader { sidecar, .. } => {
                sidecar.as_ref().is_some_and(|s| s.writer_alive(now_ms()).unwrap_or(false))
            }
        }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        match self {
            Attached::Writer { sidecar, _beat } => {
                // Stop the beat before clearing, so no refresh follows it.
                drop(std::mem::replace(_beat, Beat { stop: None, thread: None }));
                let _ = sidecar.clear_writer();
            }
            Attached::Reader { sidecar: Some(sc), mode: ReaderMode::Slotted(slot), _beat, .. } => {
                _beat.take();
                let _ = sc.release(slot);
            }
            _ => {}
        }
    }
}
