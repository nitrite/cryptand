//! `13-operations.md` §8 — multi-process readers, feature bit `MULTIPROC_READ`.
//! **One writing process, any number of reading processes.**
//!
//! Immutability makes reading from another process nearly free: every extent a
//! superblock names is one nothing will modify. The only coordination needed is
//! **retention** — the writer must not reclaim extents a reader still holds —
//! and that is the whole of what this file does.
//!
//! The motivating case is ordinary: a CLI, a `dbinspect` bridge, or a
//! background service reading a database a running application owns, which no
//! backend Nitrite uses can do today.

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use crate::posio::PosIo;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, Result};

/// Windows byte-range locks are mandatory: while another process's claim
/// holds the sidecar lock (milliseconds), plain reads and writes fail with
/// ERROR_LOCK_VIOLATION instead of waiting. Wait it out, as Unix's advisory
/// lock never needed to (F-063).
///
/// ponytail: a 2 s sleep-poll; a byte-range lock outside the slots (F-067)
/// removes the need for it.
fn retry_locked<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut waited_ms = 0;
    loop {
        match f() {
            Err(e) if cfg!(windows) && e.raw_os_error() == Some(33) && waited_ms < 2000 => {
                std::thread::sleep(std::time::Duration::from_millis(1));
                waited_ms += 1;
            }
            r => return r,
        }
    }
}

/// `"CLK1"` little-endian.
pub const MAGIC: u32 = 0x314B_4C43;
pub const HEADER_BYTES: u64 = 24;
pub const SLOT_BYTES: u64 = 24;
pub const DEFAULT_SLOT_COUNT: u32 = 64;
/// §8 rule 1's default.
pub const DEFAULT_READER_HEARTBEAT_MS: u64 = 2000;
/// §8 rule 3: a slot older than this multiple of the interval is reclaimed.
pub const STALE_MULTIPLIER: u64 = 3;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// The sidecar path for a database: `<name>.cryptand-lock`
/// (`00-conventions.md` §2 — it carries no database state and is safe to delete
/// when no process holds the database open).
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
    pub fn is_stale(&self, now: u64, heartbeat_interval_ms: u64) -> bool {
        !self.is_free() && now.saturating_sub(self.heartbeat_ms) > STALE_MULTIPLIER * heartbeat_interval_ms
    }
}

/// A claimed slot. Releasing is the reader's job; `Sidecar::release` does it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderSlot {
    pub index: u32,
    pub pid: u64,
    pub commit_id: u64,
}

/// Why a reader ended up volatile. Rule 4 requires a volatile reader to
/// *report* the mode, and a reason it cannot name is a report nobody can act
/// on: "the disk is read-only" and "this database has more readers than slots"
/// call for different responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolatileReason {
    /// Rule 4's own case: the sidecar cannot be written.
    SidecarReadOnly,
    /// Every slot is taken by a live reader. Rule 1 does not say what to do
    /// here; falling back to volatile is this implementation's reading, and
    /// naming the reason is what keeps it from being a silent downgrade.
    SidecarFull,
}

/// §8 rule 4. A reader that cannot write the sidecar opens **volatile**: it may
/// read the current snapshot, MUST revalidate the superblock before each
/// operation, and MUST report that it is in volatile mode — which is why this
/// is an enum the caller cannot ignore rather than a flag it can forget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderMode {
    /// Holding slot *n*: the writer's `min_retained_commit` accounts for it.
    Slotted(ReaderSlot),
    /// Pinning nothing. A long scan may fail if the writer reclaims underneath.
    Volatile(VolatileReason),
}

impl ReaderMode {
    pub fn is_volatile(self) -> bool {
        matches!(self, ReaderMode::Volatile(_))
    }

    /// What §8 rule 4 requires a volatile reader to do before each operation.
    pub fn must_revalidate_superblock(self) -> bool {
        self.is_volatile()
    }
}

pub struct Sidecar {
    file: File,
    slot_count: u32,
    heartbeat_interval_ms: u64,
    read_only: bool,
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

impl Sidecar {
    /// The writing process creates the sidecar and publishes its own identity.
    pub fn create(path: &Path, slot_count: u32, heartbeat_interval_ms: u64) -> Result<Sidecar> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)?;
        let mut header = [0u8; HEADER_BYTES as usize];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&slot_count.to_le_bytes());
        header[8..16].copy_from_slice(&(std::process::id() as u64).to_le_bytes());
        header[16..24].copy_from_slice(&now_ms().to_le_bytes());
        retry_locked(|| file.write_all_at(&header, 0))?;
        file.write_all_at(&vec![0u8; (slot_count as u64 * SLOT_BYTES) as usize], HEADER_BYTES)?;
        file.sync_data()?;
        Ok(Sidecar { file, slot_count, heartbeat_interval_ms, read_only: false })
    }

    /// A reader opens the sidecar the writer created. Read-write if it can;
    /// a filesystem that refuses is rule 4's volatile case and is reported by
    /// `attach` rather than by an error here.
    pub fn open(path: &Path, heartbeat_interval_ms: u64) -> Result<Sidecar> {
        let (file, read_only) = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(f) => (f, false),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                (OpenOptions::new().read(true).open(path)?, true)
            }
            Err(e) => return Err(Error::Io(e)),
        };
        let mut header = [0u8; HEADER_BYTES as usize];
        retry_locked(|| file.read_exact_at(&mut header, 0))?;
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err(Error::Io(std::io::Error::other("not a cryptand lock sidecar")));
        }
        let slot_count = u32::from_le_bytes(header[4..8].try_into().unwrap());
        Ok(Sidecar { file, slot_count, heartbeat_interval_ms, read_only })
    }

    pub fn slot_count(&self) -> u32 {
        self.slot_count
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn heartbeat_interval_ms(&self) -> u64 {
        self.heartbeat_interval_ms
    }

    pub fn writer_pid(&self) -> Result<u64> {
        let mut b = [0u8; 8];
        retry_locked(|| self.file.read_exact_at(&mut b, 8))?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn writer_heartbeat_ms(&self) -> Result<u64> {
        let mut b = [0u8; 8];
        retry_locked(|| self.file.read_exact_at(&mut b, 16))?;
        Ok(u64::from_le_bytes(b))
    }

    /// The writing process refreshes its own heartbeat on the same schedule it
    /// asks of readers.
    pub fn refresh_writer(&self, now: u64) -> Result<()> {
        retry_locked(|| self.file.write_all_at(&now.to_le_bytes(), 16))?;
        Ok(())
    }

    /// Is a writing process live? The header carries `writer_pid` and
    /// `writer_heartbeat_ms` for this, and it decides two things a reader
    /// otherwise cannot see:
    ///
    /// - with no live writer nothing will ever reclaim a stale slot, so a
    ///   claimer has to do it (see `claim`), or the sidecar fills with dead
    ///   readers and every later one silently degrades to volatile;
    /// - with no live writer nothing will reclaim extents either, so the
    ///   reader's pin is costing it a heartbeat for no protection.
    pub fn writer_alive(&self, now: u64) -> Result<bool> {
        let beat = self.writer_heartbeat_ms()?;
        Ok(self.writer_pid()? != 0
            && now.saturating_sub(beat) <= STALE_MULTIPLIER * self.heartbeat_interval_ms)
    }

    pub fn read_slot(&self, index: u32) -> Result<Slot> {
        let mut b = [0u8; SLOT_BYTES as usize];
        retry_locked(|| self.file.read_exact_at(&mut b, HEADER_BYTES + index as u64 * SLOT_BYTES))?;
        Ok(Slot {
            index,
            pid: u64_at(&b, 0),
            commit_id: u64_at(&b, 8),
            heartbeat_ms: u64_at(&b, 16),
        })
    }

    pub fn slots(&self) -> Result<Vec<Slot>> {
        (0..self.slot_count).map(|i| self.read_slot(i)).collect()
    }

    fn write_slot(&self, index: u32, pid: u64, commit_id: u64, heartbeat_ms: u64) -> Result<()> {
        let mut b = [0u8; SLOT_BYTES as usize];
        b[0..8].copy_from_slice(&pid.to_le_bytes());
        b[8..16].copy_from_slice(&commit_id.to_le_bytes());
        b[16..24].copy_from_slice(&heartbeat_ms.to_le_bytes());
        retry_locked(|| self.file.write_all_at(&b, HEADER_BYTES + index as u64 * SLOT_BYTES))?;
        Ok(())
    }

    /// §8 rule 1 — claim a free slot and publish the `commit_id` pinned.
    ///
    /// The spec says compare-and-swap. A plain file offers no cross-process
    /// atomic word, so the claim's read-scan-write runs under an exclusive
    /// advisory lock on the sidecar; that is the CAS. It is taken once per
    /// reader open and never on the heartbeat path, so it costs nothing that
    /// matters. A stale slot (rule 3) is a free slot to a claimer.
    pub fn claim(&self, commit_id: u64, now: u64) -> Result<Option<ReaderSlot>> {
        if self.read_only {
            return Ok(None);
        }
        self.file.lock()?;
        let claimed = (|| -> Result<Option<ReaderSlot>> {
            for i in 0..self.slot_count {
                let slot = self.read_slot(i)?;
                if slot.is_free() || slot.is_stale(now, self.heartbeat_interval_ms) {
                    let pid = std::process::id() as u64;
                    self.write_slot(i, pid, commit_id, now)?;
                    self.file.sync_data()?;
                    return Ok(Some(ReaderSlot { index: i, pid, commit_id }));
                }
            }
            Ok(None)
        })();
        let _ = self.file.unlock();
        claimed
    }

    /// §8 rule 1's refresh, and rule 3's detection in one call: `false` means
    /// **this reader's slot was reclaimed** and it MUST reopen rather than
    /// continue against possibly-freed extents.
    pub fn heartbeat(&self, slot: &ReaderSlot, now: u64) -> Result<bool> {
        if self.read_only {
            return Ok(false);
        }
        let current = self.read_slot(slot.index)?;
        if current.pid != slot.pid {
            return Ok(false);
        }
        self.write_slot(slot.index, slot.pid, slot.commit_id, now)?;
        Ok(true)
    }

    pub fn release(&self, slot: &ReaderSlot) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        let current = self.read_slot(slot.index)?;
        if current.pid == slot.pid {
            self.write_slot(slot.index, 0, 0, 0)?;
        }
        Ok(())
    }

    /// §8 rule 3 — the writer reclaims slots whose heartbeat has aged out.
    /// Returns the indices reclaimed.
    pub fn reclaim_stale(&self, now: u64) -> Result<Vec<u32>> {
        self.file.lock()?;
        let reclaimed = (|| -> Result<Vec<u32>> {
            let mut out = Vec::new();
            for slot in self.slots()? {
                if slot.is_stale(now, self.heartbeat_interval_ms) {
                    self.write_slot(slot.index, 0, 0, 0)?;
                    out.push(slot.index);
                }
            }
            Ok(out)
        })();
        let _ = self.file.unlock();
        reclaimed
    }

    /// §8 rule 2 — `min_retained_commit` is the minimum over the writer's own
    /// snapshots **and** every live slot. A stale slot does not pin: rule 3
    /// says it is reclaimable, and a floor that honoured it would let one
    /// crashed reader hold the file's space forever.
    pub fn min_retained_commit(&self, own_minimum: u64, now: u64) -> Result<u64> {
        let mut min = own_minimum;
        for slot in self.slots()? {
            if slot.is_free() || slot.is_stale(now, self.heartbeat_interval_ms) {
                continue;
            }
            min = min.min(slot.commit_id);
        }
        Ok(min)
    }
}

/// A reader's whole open path: claim a slot if the sidecar allows it, and fall
/// back to rule 4's volatile mode if it does not — because the filesystem is
/// read-only, or because every slot is taken.
pub fn attach(sidecar: &Sidecar, commit_id: u64, now: u64) -> Result<ReaderMode> {
    Ok(match sidecar.claim(commit_id, now)? {
        Some(slot) => ReaderMode::Slotted(slot),
        None if sidecar.is_read_only() => ReaderMode::Volatile(VolatileReason::SidecarReadOnly),
        None => ReaderMode::Volatile(VolatileReason::SidecarFull),
    })
}
