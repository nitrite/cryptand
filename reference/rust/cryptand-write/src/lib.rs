//! `10-transactions.md` §2 — the concurrent write protocol, and the one part of
//! the design the Dart reference implementation could not reach: Dart has no
//! shared-memory threads, so *N* writers contending on one counter could not be
//! exercised and prediction **P3** could not be measured.
//!
//! This crate implements §2's writer and committer, §2.2's requirements, and
//! the three ordering invariants of §2.3, over real files with real threads.
//! It is **not an engine**: there is no B+tree, no manifest, no compaction and
//! no L0 flush. `README.md` says what that costs the measurement.

pub mod engine;
pub mod multiproc;
pub mod nonce;
pub mod prefix;
pub mod vlog;

pub use engine::{Durability, WriteEngine, WriteOptions};

pub type Seq = u64;

#[derive(Debug)]
pub enum Error {
    /// The open value-log segment cannot hold the reservation.
    SegmentFull,
    Io(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SegmentFull => write!(f, "value-log segment full"),
            Error::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
