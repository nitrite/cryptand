//! `00-conventions.md` §4. `uvar` is LEB128, at most 10 bytes, and a
//! non-canonical encoding is a decode error rather than a value.

use crate::{corrupt, Result};

pub fn put_uvar(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub fn put_ivar(out: &mut Vec<u8>, v: i64) {
    put_uvar(out, ((v << 1) ^ (v >> 63)) as u64);
}

/// Returns the value and the number of bytes consumed.
#[inline]
pub fn get_uvar(b: &[u8]) -> Result<(u64, usize)> {
    // Nearly every uvar a reader decodes is one byte: cell suffix lengths, cell
    // counts, name-dictionary indices. The general loop below carries a bounds
    // check, a `min(10)` and a non-canonical test per iteration, and it was the
    // single hottest leaf on the point-read profile.
    if let Some(&first) = b.first() {
        if first < 0x80 {
            return Ok((first as u64, 1));
        }
    }
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for i in 0..b.len().min(10) {
        let byte = b[i];
        // The tenth byte carries one payload bit; anything above it would not
        // round-trip through u64.
        if shift == 63 && byte > 1 {
            return corrupt("uvar overflows u64");
        }
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return corrupt("non-canonical uvar: trailing zero continuation");
            }
            return Ok((v, i + 1));
        }
        shift += 7;
    }
    if b.len() >= 10 {
        corrupt("uvar longer than 10 bytes")
    } else {
        corrupt("truncated uvar")
    }
}

pub fn get_ivar(b: &[u8]) -> Result<(i64, usize)> {
    let (u, n) = get_uvar(b)?;
    Ok((((u >> 1) as i64) ^ -((u & 1) as i64), n))
}
