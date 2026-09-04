//! `00-conventions.md` §9 — the error classes an implementation MUST
//! distinguish and MUST NOT conflate. In particular corruption ("your disk has
//! a bad sector") and tampering ("someone edited your database") are separate
//! classes because they call for different responses
//! (`14-security.md` §6.2).

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A checksum mismatch, a structural violation, an out-of-range length.
    Corrupt(String),
    /// An AEAD tag or `sb_mac` mismatch. Never repaired: repairing tampered
    /// data is laundering it (`13-operations.md` §3).
    Tamper(String),
    /// Encrypted file, no key or wrong key. Reported identically for a missing
    /// keyslot and a wrong password (`00-conventions.md` §9).
    CannotUnlock,
    /// An unknown bit in `features_required`: refuse to open, name the bit.
    UnknownFeature { bit: u32 },
    /// `version_major` above what this implementation supports.
    UnsupportedVersion(String),
    /// The caller asked for something the format forbids.
    Invalid(String),
    /// A key range taken out of service by containment (`13-operations.md` §4).
    Unavailable(String),
    /// A transaction's write set collided (`10-transactions.md` §3).
    Conflict(String),
    /// `01-container.md` §10 — another process holds the writer lock. Its own
    /// class because §10 forbids the one alternative: "MUST NOT fall back to
    /// opening anyway".
    Locked(String),
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Locked(m) => write!(f, "locked by another process: {m}"),
            Error::Corrupt(m) => write!(f, "corrupt: {m}"),
            Error::Tamper(m) => write!(f, "tampering: {m}"),
            Error::CannotUnlock => write!(f, "cannot unlock: no keyslot accepted the key"),
            Error::UnknownFeature { bit } => {
                write!(f, "unknown required feature bit {bit} ({})", feature_name(*bit))
            }
            Error::UnsupportedVersion(m) => write!(f, "unsupported version: {m}"),
            Error::Invalid(m) => write!(f, "invalid: {m}"),
            Error::Unavailable(m) => write!(f, "unavailable: {m}"),
            Error::Conflict(m) => write!(f, "conflict: {m}"),
            Error::Io(m) => write!(f, "io: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// `11-conformance.md` §2 — named so a refusal can say *which* bit.
pub fn feature_name(bit: u32) -> &'static str {
    match bit {
        0 => "CORE",
        1 => "DOCUMENTS",
        2 => "TEXT",
        3 => "SPATIAL",
        4 => "VECTOR",
        5 => "ZSTD",
        6 => "CIPHER",
        7 => "HASH64",
        8 => "DEC128",
        9 => "MULTIPROC",
        10 => "DEDUP",
        11 => "MULTIPROC_READ",
        12 => "ZDICT",
        13 => "TTL",
        14 => "CHANGEFEED",
        15 => "CHECKPOINTS",
        48..=63 => "vendor",
        _ => "unnamed",
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn corrupt<T>(why: impl Into<String>) -> Result<T> {
    Err(Error::Corrupt(why.into()))
}

pub fn invalid<T>(why: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(why.into()))
}
