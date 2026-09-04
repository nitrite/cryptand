//! `00-conventions.md` §8 — every one of these is a bound a decoder MUST
//! enforce *before* allocating, because opening a file another party produced
//! is what this format exists for (`14-security.md` §9.1).

use crate::error::{corrupt, invalid, Result};

pub const MAX_DEPTH: usize = 100;
pub const MAX_FIELDS: usize = 65535;
pub const MAX_KEY_BYTES: usize = 4096;
pub const MAX_TREE_ID: u64 = 0xFFFF_FFFE;
pub const DEFAULT_LOCK_SLOTS: u32 = 8;

pub fn check_page_size(page_size: usize) -> Result<()> {
    if !matches!(page_size, 4096 | 8192 | 16384 | 32768 | 65536) {
        return invalid(format!("page_size {page_size} is not one of 4096..65536 by powers of two"));
    }
    Ok(())
}

/// The encoded-key ceiling: page-relative, because a key must fit in a leaf
/// *with room for peers*, and a flat 4 KiB limit is unsatisfiable at 4 KiB
/// pages.
pub fn max_key_len(page_size: usize) -> usize {
    (page_size / 4).min(MAX_KEY_BYTES)
}

pub fn max_inline_value(page_size: usize) -> usize {
    page_size / 4
}

pub fn check_key_len(key: &[u8], page_size: usize) -> Result<()> {
    let cap = max_key_len(page_size);
    if key.len() > cap {
        return invalid(format!("encoded key of {} B exceeds the {cap} B limit", key.len()));
    }
    Ok(())
}

/// `00-conventions.md` §8 and `01-container.md` §2: a writer MUST reject a
/// `vlog_min` above the cap; a reader MUST treat such a file as corrupt.
pub fn check_vlog_min(vlog_min: u32, page_size: usize) -> Result<()> {
    if vlog_min as usize > page_size / 4 {
        return invalid(format!(
            "vlog_min {vlog_min} exceeds page_size / 4 = {}",
            page_size / 4
        ));
    }
    Ok(())
}

/// The untrusted-length rule, in one place so every call site reads the same.
pub fn bounded(len: u64, available: usize, what: &str) -> Result<usize> {
    if len > available as u64 {
        return corrupt(format!("{what}: declared length {len} exceeds the {available} B available"));
    }
    Ok(len as usize)
}
