//! `01-container.md` §7 — per page and per value-log record, never per file.
//! LZ4 block format is the only codec a Level-0 implementation MUST support;
//! Zstd is feature bit `ZSTD` and is not built here, so a writer never sets
//! `page_codec = 2` and a reader refuses a page that carries it rather than
//! guessing.

use crate::error::{corrupt, Result};

pub const NONE: u8 = 0;
pub const LZ4: u8 = 1;
pub const ZSTD: u8 = 2;

/// §7: "a page is stored compressed only if compression saves >= 12.5 % of the
/// page."
pub fn worth_compressing(raw: usize, compressed: usize) -> bool {
    compressed + raw / 8 <= raw
}

pub fn compress(codec: u8, raw: &[u8]) -> Result<Option<Vec<u8>>> {
    match codec {
        NONE => Ok(None),
        LZ4 => {
            let out = lz4_flex::block::compress(raw);
            Ok(if worth_compressing(raw.len(), out.len()) { Some(out) } else { None })
        }
        ZSTD => corrupt("codec 2 (Zstd) needs feature bit ZSTD, which this build does not set"),
        c => corrupt(format!("unknown codec id {c}")),
    }
}

/// `payload_len` gives the decompressed size, so the raw block format needs no
/// frame header (§7).
pub fn decompress(codec: u8, data: &[u8], payload_len: usize) -> Result<Vec<u8>> {
    match codec {
        NONE => Ok(data.to_vec()),
        LZ4 => lz4_flex::block::decompress(data, payload_len)
            .map_err(|e| crate::error::Error::Corrupt(format!("LZ4 block: {e}"))),
        ZSTD => corrupt("this build cannot decompress Zstd (feature bit ZSTD)"),
        c => corrupt(format!("unknown codec id {c}")),
    }
}
