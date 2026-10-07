//! **Cryptand File Format (CFF) v1.0 — the Rust reference implementation.**
//!
//! The normative source is `cryptand/spec/`. Where this code and the spec
//! disagree, **the spec wins and this code is wrong**
//! (`spec/11-conformance.md` §7). The reference implementation is not
//! normative; conformance is defined as passing the vectors.
//!
//! Layout, chapter by chapter:
//!
//! | chapter | modules |
//! |---|---|
//! | `00` conventions | [`varint`], [`hash`], [`limits`], [`error`] |
//! | `01` container | [`container`], [`pager`], [`codec`] |
//! | `02` CVE | [`value`], [`cve`], [`compare`] |
//! | `03` CKE | [`cke`] |
//! | `04` segments | [`segment`], [`filter`], [`vlog`], [`cow`], [`manifest`], [`engine`] |
//! | `05` catalog | [`catalog`] |
//! | `06` indexes | [`index`] |
//! | `07` full text | [`unicode`], [`analyzer`], [`porter2`], [`fulltext`] |
//! | `08` spatial | [`wkb`], [`geometry`], [`rtree`] |
//! | `09` vector | [`vector`] |
//! | `10` transactions | [`txn`], [`store`] |
//! | `11` conformance | the `tests/` directory |
//! | `12` profiles | [`profile`] |
//! | `13` operations | [`checkpoint`], [`backup`], [`changefeed`], [`repair`], [`verify`], [`metrics`], [`stats`], [`spaceapi`], [`multiproc`] |
//! | `14` security | [`security`] |

pub mod analyzer;
pub mod backup;
pub mod catalog;
pub mod changefeed;
pub mod checkpoint;
pub mod cke;
pub mod codec;
pub mod compare;
pub mod container;
pub mod cow;
pub mod cve;
pub mod database;
pub mod engine;
pub mod error;
pub mod filter;
pub mod fulltext;
pub mod geometry;
pub mod hash;
pub mod index;
pub mod limits;
pub mod manifest;
pub mod metrics;
pub mod multiproc;
pub mod pager;
pub mod posio;
#[cfg(feature = "faults")]
pub mod fault;
pub mod porter2;
pub mod profile;
pub mod repair;
pub mod rtree;
pub mod security;
pub mod segment;
pub mod keyapi;
pub mod spaceapi;
pub mod stats;
pub mod store;
pub mod txn;
pub mod unicode;
pub mod unicode_tables;
pub mod value;
pub mod varint;
pub mod vector;
pub mod verify;
pub mod vlog;
pub mod wkb;

pub use error::{corrupt, invalid, Error, Result};
pub use value::{NumType, Value};

/// `11-conformance.md` §1 — the level this implementation declares.
pub const CONFORMANCE_LEVEL: u8 = 4;

/// §1.1 — the concurrency capability, declared rather than assumed.
pub const WRITE_PROFILE: &str = "full";

pub const FORMAT_VERSION: (u16, u16) = (1, 0);
