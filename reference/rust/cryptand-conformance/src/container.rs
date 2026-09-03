//! `01-container.md` §2 and §3 — the superblock and the page header. Only the
//! parsing side: this crate never writes a file.

use crate::hash::crc32c;
use crate::{corrupt, Result};

pub const SUPERBLOCK_BYTES: usize = 4096;
pub const PAGE_HEADER_BYTES: usize = 40;
pub const MAGIC: &[u8; 8] = b"CRYPTAND";

/// Byte offsets of §2's table, named so a test can check them against the
/// vector rather than against this code's own reading of the table.
pub mod sb {
    pub const MAGIC: usize = 0;
    pub const VERSION_MAJOR: usize = 8;
    pub const VERSION_MINOR: usize = 10;
    pub const WRITE_VERSION_MINOR: usize = 12;
    pub const PAGE_SIZE_LOG2: usize = 14;
    pub const COMMIT_ID: usize = 16;
    pub const FEATURES_REQUIRED: usize = 24;
    pub const FEATURES_OPTIONAL: usize = 32;
    pub const PAGE_COUNT: usize = 40;
    pub const DATABASE_UUID: usize = 160;
    pub const CIPHER: usize = 178;
    pub const VLOG_MIN: usize = 184;
    pub const PROFILE: usize = 216;
    pub const WRITER_ID: usize = 256;
    pub const NEXT_NONCE: usize = 288;
    pub const SB_MAC: usize = 296;
    pub const KEYSLOTS: usize = 3512;
    pub const CHECKSUM: usize = 4092;
}

pub mod ph {
    pub const CHECKSUM: usize = 0;
    pub const PAGE_TYPE: usize = 4;
    pub const FLAGS: usize = 5;
    pub const CODEC_OR_RESERVED: usize = 6;
    pub const TREE_ID: usize = 8;
    pub const EXTENT_PAGES: usize = 12;
    pub const COMMIT_ID: usize = 16;
    pub const PAYLOAD_LEN: usize = 24;
    pub const RESERVED: usize = 28;
    pub const NONCE: usize = 32;
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[derive(Debug, Clone)]
pub struct Superblock {
    pub version_major: u16,
    pub version_minor: u16,
    pub page_size: u32,
    pub commit_id: u64,
    pub features_required: u64,
    pub page_count: u64,
    pub database_uuid: [u8; 16],
    pub cipher: u8,
    pub vlog_min: u32,
    pub profile: u8,
    pub writer_id: String,
    pub next_nonce: u64,
    pub sb_mac: [u8; 32],
    pub checksum: u32,
}

impl Superblock {
    /// §2.1 steps 2, 5 and `00-conventions.md` §8's `vlog_min` cap, which a
    /// reader MUST treat as corruption rather than as a tuning mistake.
    pub fn parse(b: &[u8]) -> Result<Superblock> {
        if b.len() < SUPERBLOCK_BYTES {
            return corrupt("superblock shorter than 4096 bytes");
        }
        if &b[sb::MAGIC..sb::MAGIC + 8] != MAGIC {
            return corrupt("not a Cryptand file: bad magic");
        }
        let checksum = u32le(b, sb::CHECKSUM);
        if crc32c(&b[0..sb::CHECKSUM]) != checksum {
            return corrupt("superblock checksum mismatch");
        }
        let version_major = u16le(b, sb::VERSION_MAJOR);
        if version_major != 1 {
            return corrupt(format!("format major version {version_major} > 1"));
        }
        let log2 = u16le(b, sb::PAGE_SIZE_LOG2);
        if !(12..=16).contains(&log2) {
            return corrupt(format!("page_size_log2 {log2} outside 12..16"));
        }
        let page_size = 1u32 << log2;
        let vlog_min = u32le(b, sb::VLOG_MIN);
        if vlog_min > page_size / 4 {
            return corrupt("vlog_min above page_size / 4");
        }
        let writer_id = String::from_utf8_lossy(&b[sb::WRITER_ID..sb::WRITER_ID + 32])
            .trim_end_matches('\0')
            .to_string();
        Ok(Superblock {
            version_major,
            version_minor: u16le(b, sb::VERSION_MINOR),
            page_size,
            commit_id: u64le(b, sb::COMMIT_ID),
            features_required: u64le(b, sb::FEATURES_REQUIRED),
            page_count: u64le(b, sb::PAGE_COUNT),
            database_uuid: b[sb::DATABASE_UUID..sb::DATABASE_UUID + 16].try_into().unwrap(),
            cipher: b[sb::CIPHER],
            vlog_min,
            profile: b[sb::PROFILE],
            writer_id,
            next_nonce: u64le(b, sb::NEXT_NONCE),
            sb_mac: b[sb::SB_MAC..sb::SB_MAC + 32].try_into().unwrap(),
            checksum,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PageHeader {
    pub checksum: u32,
    pub page_type: u8,
    pub flags: u8,
    pub codec: u16,
    pub tree_id: u32,
    pub extent_pages: u32,
    pub commit_id: u64,
    pub payload_len: u32,
    pub nonce: u64,
}

impl PageHeader {
    pub fn parse(b: &[u8]) -> Result<PageHeader> {
        if b.len() < PAGE_HEADER_BYTES {
            return corrupt("page header shorter than 40 bytes");
        }
        // `00-conventions.md` §5: a reserved field MUST be written as zero
        // and MUST be ignored on read -- so a non-zero one is not an error.
        Ok(PageHeader {
            checksum: u32le(b, ph::CHECKSUM),
            page_type: b[ph::PAGE_TYPE],
            flags: b[ph::FLAGS],
            codec: u16le(b, ph::CODEC_OR_RESERVED),
            tree_id: u32le(b, ph::TREE_ID),
            extent_pages: u32le(b, ph::EXTENT_PAGES),
            commit_id: u64le(b, ph::COMMIT_ID),
            payload_len: u32le(b, ph::PAYLOAD_LEN),
            nonce: u64le(b, ph::NONCE),
        })
    }
}
