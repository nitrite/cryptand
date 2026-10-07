//! PLAN M2.1 — a fault-injecting layer under the pager. Test builds only
//! (feature `faults`): the published crate never compiles it.
//!
//! A test arms a database path with a [`Plan`]; from then on every page write
//! and `fsync` the pager issues for that path is counted and may fail. A write
//! is remembered with the bytes it replaced until the next successful `fsync`,
//! so [`crash`] can model a power cut: every un-fsynced write is undone, then a
//! random subset is replayed in order (the disk may have reached any of them),
//! some torn at a 512-byte boundary.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::posio::PosIo;

#[derive(Clone, Copy, Debug, Default)]
pub struct Plan {
    /// Power is lost at this write (0-based since arming): it and all later
    /// I/O fail, as if the process died there.
    pub crash_at_write: Option<u64>,
    /// This `fsync` fails with EIO. What it covered stays un-fsynced.
    pub eio_at_sync: Option<u64>,
    /// This write fails with ENOSPC, writing nothing.
    pub enospc_at_write: Option<u64>,
    /// Every `fsync` reports success and persists nothing. The tests' control:
    /// a sweep under this plan must fail.
    pub sync_lies: bool,
}

struct Pending {
    offset: u64,
    old: Vec<u8>,
    new: Vec<u8>,
}

#[derive(Default)]
struct State {
    plan: Plan,
    writes: u64,
    syncs: u64,
    dead: bool,
    pending: Vec<Pending>,
}

// ponytail: one global map keyed by path; tests use distinct temp paths.
static ARMED: Mutex<Option<HashMap<PathBuf, State>>> = Mutex::new(None);

fn with<T>(path: &Path, f: impl FnOnce(&mut State) -> T) -> Option<T> {
    let mut g = ARMED.lock().unwrap_or_else(|e| e.into_inner());
    g.as_mut()?.get_mut(path).map(f)
}

pub fn arm(path: &Path, plan: Plan) {
    let mut g = ARMED.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new).insert(path.to_path_buf(), State { plan, ..State::default() });
}

/// `(writes, syncs)` seen since arming.
pub fn counts(path: &Path) -> (u64, u64) {
    with(path, |s| (s.writes, s.syncs)).unwrap_or((0, 0))
}

/// True once a planned crash has fired.
pub fn crashed(path: &Path) -> bool {
    with(path, |s| s.dead).unwrap_or(false)
}

fn dead() -> Error {
    Error::other("fault: power lost")
}

pub(crate) fn before_write(path: &Path, file: &File, offset: u64, data: &[u8]) -> Result<()> {
    with(path, |s| {
        if s.dead {
            return Err(dead());
        }
        let n = s.writes;
        s.writes += 1;
        if s.plan.crash_at_write == Some(n) {
            s.dead = true;
            return Err(dead());
        }
        if s.plan.enospc_at_write == Some(n) {
            return Err(Error::new(ErrorKind::StorageFull, "fault: ENOSPC"));
        }
        let mut old = vec![0u8; data.len()];
        let len = file.metadata()?.len();
        if offset < len {
            let have = ((len - offset) as usize).min(data.len());
            file.read_exact_at(&mut old[..have], offset)?;
        }
        s.pending.push(Pending { offset, old, new: data.to_vec() });
        Ok(())
    })
    .unwrap_or(Ok(()))
}

pub(crate) fn before_sync(path: &Path) -> Result<()> {
    with(path, |s| {
        if s.dead {
            return Err(dead());
        }
        let n = s.syncs;
        s.syncs += 1;
        if s.plan.eio_at_sync == Some(n) {
            return Err(Error::from_raw_os_error(5)); // EIO
        }
        if !s.plan.sync_lies {
            s.pending.clear();
        }
        Ok(())
    })
    .unwrap_or(Ok(()))
}

pub(crate) fn check_alive(path: &Path) -> Result<()> {
    if crashed(path) {
        return Err(dead());
    }
    Ok(())
}

/// Disarms `path` and rewrites the file as a power cut at this moment could
/// have left it. Call after every handle on the file is dropped. Returns the
/// number of un-fsynced writes that were dropped.
pub fn crash(path: &Path, seed: u64) -> Result<usize> {
    let state = {
        let mut g = ARMED.lock().unwrap_or_else(|e| e.into_inner());
        g.as_mut().and_then(|m| m.remove(path))
    };
    let Some(state) = state else { return Ok(0) };
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    for p in state.pending.iter().rev() {
        file.write_all_at(&p.old, p.offset)?;
    }
    if std::env::var_os("CRYPTAND_FAULT_DEBUG").is_some() {
        for p in &state.pending {
            eprintln!("pending write @{} len {}", p.offset, p.new.len());
        }
    }
    let mut rng = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut dropped = 0;
    for p in &state.pending {
        let r = splitmix(&mut rng);
        if r & 1 == 0 {
            dropped += 1;
            continue;
        }
        let blocks = p.new.len() / 512;
        let keep = if r & 6 == 0 && blocks > 1 {
            (1 + (r >> 8) as usize % (blocks - 1)) * 512 // torn
        } else {
            p.new.len()
        };
        file.write_all_at(&p.new[..keep], p.offset)?;
    }
    file.sync_all()?;
    Ok(dropped)
}

/// Removes `path`'s plan without touching the file.
pub fn disarm(path: &Path) {
    let mut g = ARMED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(m) = g.as_mut() {
        m.remove(path);
    }
}

pub fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
