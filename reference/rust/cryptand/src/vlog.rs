//! `04-segments.md` §6 — the value log: two tiers, append-only segments,
//! reserve-then-write appends, and the pointer that replaces a value in a leaf
//! cell.
//!
//! There is **no write-ahead log** (§7): the value-log record *is* the
//! durability record, so a value is written once, not twice.

use crate::container::{page_flags, page_type, u32le, u64le, PageHeader, PAGE_HEADER_BYTES};
use crate::error::{corrupt, invalid, Result};
use crate::hash::crc32c;
use crate::varint::{get_uvar, put_uvar};

pub const VLOG_MAGIC: [u8; 8] = [0x43, 0x52, 0x59, 0x5F, 0x56, 0x4C, 0x47, 0x1A];
/// §6.2: the head page's 40-byte page header plus this 64-byte header, rounded
/// up to 8. Written down so a future minor version can grow either header
/// without changing how records are addressed.
pub const DATA_OFFSET: u32 = 104;
pub const POINTER_BYTES: usize = 16;

/// §6.1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    Hot = 0,
    Cold = 1,
}

impl Tier {
    pub fn from_code(c: u8) -> Tier {
        if c == 1 {
            Tier::Cold
        } else {
            Tier::Hot
        }
    }
}

/// §6.6 — the format records the class; the classifier is the
/// implementation's. A writer with no heat information MUST use `FIRST`, which
/// is correct and merely slower.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Heat {
    First = 0,
    Warm = 1,
    Hot = 2,
}

impl Heat {
    pub fn from_code(c: u8) -> Heat {
        match c {
            1 => Heat::Warm,
            2 => Heat::Hot,
            _ => Heat::First,
        }
    }
}

/// §6.4 — 16 bytes. `offset` is extent-relative, so resolving a pointer is one
/// addition against `start_page` and needs nothing from the head page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VlogPointer {
    pub segment_id: u64,
    pub offset: u32,
    pub len: u32,
}

impl VlogPointer {
    pub fn encode(&self) -> [u8; POINTER_BYTES] {
        let mut b = [0u8; POINTER_BYTES];
        b[0..8].copy_from_slice(&self.segment_id.to_le_bytes());
        b[8..12].copy_from_slice(&self.offset.to_le_bytes());
        b[12..16].copy_from_slice(&self.len.to_le_bytes());
        b
    }

    pub fn parse(b: &[u8]) -> Result<VlogPointer> {
        if b.len() < POINTER_BYTES {
            return corrupt("VLOG pointer shorter than 16 bytes");
        }
        Ok(VlogPointer { segment_id: u64le(b, 0), offset: u32le(b, 8), len: u32le(b, 12) })
    }
}

/// §6.2's head page: the segment's **immutable identity** and nothing else.
/// Everything that changes as the segment fills lives in tree 7 (§6.7),
/// because a mutable field here would break `01-container.md` §1's rule that
/// no page a live superblock references is ever overwritten.
#[derive(Clone, Debug)]
pub struct VlogHead {
    pub segment_id: u64,
    pub created_seq: u64,
    pub capacity: u64,
    pub data_offset: u32,
    pub tier: Tier,
    pub heat: Heat,
    pub codec: u8,
    pub encrypted: bool,
    pub nonce_base: u64,
}

impl VlogHead {
    pub fn encode(&self, page_size: usize, extent_pages: u32) -> Vec<u8> {
        let mut page = vec![0u8; page_size];
        let b = PAGE_HEADER_BYTES;
        page[b..b + 8].copy_from_slice(&VLOG_MAGIC);
        page[b + 8..b + 16].copy_from_slice(&self.segment_id.to_le_bytes());
        page[b + 16..b + 24].copy_from_slice(&self.created_seq.to_le_bytes());
        page[b + 24..b + 32].copy_from_slice(&self.capacity.to_le_bytes());
        page[b + 32..b + 36].copy_from_slice(&self.data_offset.to_le_bytes());
        page[b + 36] = self.tier as u8;
        page[b + 37] = self.heat as u8;
        page[b + 38] = self.codec;
        page[b + 39] = u8::from(self.encrypted);
        page[b + 40..b + 48].copy_from_slice(&self.nonce_base.to_le_bytes());
        PageHeader {
            page_type: page_type::VLOG_SEGMENT,
            flags: page_flags::EXTENT_HEAD,
            tree_id: crate::container::NO_TREE,
            extent_pages,
            payload_len: 64,
            ..Default::default()
        }
        .write_into(&mut page);
        page
    }

    pub fn parse(page: &[u8]) -> Result<VlogHead> {
        let b = PAGE_HEADER_BYTES;
        if page.len() < b + 64 {
            return corrupt("value-log head page too small");
        }
        if page[b..b + 8] != VLOG_MAGIC {
            return corrupt("value-log head page magic mismatch");
        }
        Ok(VlogHead {
            segment_id: u64le(page, b + 8),
            created_seq: u64le(page, b + 16),
            capacity: u64le(page, b + 24),
            data_offset: u32le(page, b + 32),
            tier: Tier::from_code(page[b + 36]),
            heat: Heat::from_code(page[b + 37]),
            codec: page[b + 38],
            encrypted: page[b + 39] != 0,
            nonce_base: u64le(page, b + 40),
        })
    }
}

/// §6.7 — tree 7's value, the **authority** for everything mutable about a
/// value-log segment.
#[derive(Clone, Debug, Default)]
pub struct VlogStats {
    pub segment_id: u64,
    /// The durable contiguous watermark (§6.2, `10-transactions.md` §2.3).
    /// Only records entirely below it may be referenced by a `VLOG` pointer.
    pub bytes: u64,
    pub records: u64,
    pub sealed: bool,
    pub clustered: bool,
    pub min_key: Option<Vec<u8>>,
    pub max_key: Option<Vec<u8>>,
    pub start_page: u64,
    pub pages: u32,
    /// §6.7: an **estimate that MUST be conservative** — it may overstate
    /// liveness (GC skips a segment) and MUST NOT understate it.
    pub live_bytes: u64,
    pub live_records: u64,
    pub tier: u8,
    pub heat: u8,
    pub created_seq: u64,
    pub last_gc_seq: u64,
}

/// One decoded value-log record.
#[derive(Clone, Debug)]
pub struct VlogRecord {
    pub tree_id: u32,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// The encrypted payload, when the segment is encrypted: `key` and `value`
    /// are then empty and only a key holder can separate them.
    pub ciphertext: Vec<u8>,
    /// Total bytes on disk, `record_len` varint included — what a pointer's
    /// `len` carries so a reader issues exactly one sized read.
    pub total_len: usize,
    pub nonce: Option<u64>,
}

/// §6.2's record framing. `record_len`, `nonce` and `crc32c` stay in the clear
/// so a segment can be walked, and damage in it bounded, without the key.
pub fn encode_record(tree_id: u32, key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(key.len() + value.len() + 16);
    body.extend_from_slice(&tree_id.to_le_bytes());
    put_uvar(&mut body, key.len() as u64);
    body.extend_from_slice(key);
    put_uvar(&mut body, value.len() as u64);
    body.extend_from_slice(value);
    let crc = crc32c(&body);
    body.extend_from_slice(&crc.to_le_bytes());
    let mut out = Vec::with_capacity(body.len() + 10);
    put_uvar(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    out
}

/// Encrypted framing (`14-security.md` §5.3): the counter is in the clear
/// immediately after `record_len`, so one record decrypts without reading any
/// other — which is exactly what a point read does.
pub fn encode_record_encrypted(tree_id: u32, nonce_counter: u64, ciphertext_with_tag: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(ciphertext_with_tag.len() + 16);
    body.extend_from_slice(&nonce_counter.to_le_bytes());
    body.extend_from_slice(&tree_id.to_le_bytes());
    body.extend_from_slice(ciphertext_with_tag);
    let crc = crc32c(&body[8..]);
    body.extend_from_slice(&crc.to_le_bytes());
    let mut out = Vec::new();
    put_uvar(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    out
}

/// Decodes the record at the start of `b`. `encrypted` selects the framing.
pub fn decode_record(b: &[u8], encrypted: bool) -> Result<VlogRecord> {
    let (len, n) = get_uvar(b)?;
    let len = len as usize;
    if n + len > b.len() {
        return corrupt("value-log record runs past the buffer");
    }
    let body = &b[n..n + len];
    if body.len() < 4 {
        return corrupt("value-log record shorter than its CRC");
    }
    let (nonce, rest) = if encrypted {
        if body.len() < 12 {
            return corrupt("encrypted value-log record shorter than its nonce");
        }
        (Some(u64le(body, 0)), &body[8..])
    } else {
        (None, body)
    };
    let crc_at = rest.len() - 4;
    let stored = u32le(rest, crc_at);
    if crc32c(&rest[..crc_at]) != stored {
        return corrupt("value-log record CRC mismatch");
    }
    let payload = &rest[..crc_at];
    if payload.len() < 4 {
        return corrupt("value-log record has no tree_id");
    }
    let tree_id = u32le(payload, 0);
    if encrypted {
        // `14-security.md` §5.3 — `key_len || key || value_len || value` is
        // encrypted as one unit, so there is nothing here to parse without the
        // key. `record_len`, the counter and the CRC stay in the clear so a
        // segment can still be walked, and its damage bounded, without it.
        return Ok(VlogRecord {
            tree_id,
            key: Vec::new(),
            value: Vec::new(),
            ciphertext: payload[4..].to_vec(),
            total_len: n + len,
            nonce,
        });
    }
    let mut at = 4usize;
    let (klen, kn) = get_uvar(&payload[at..])?;
    at += kn;
    let klen = crate::limits::bounded(klen, payload.len() - at, "value-log key_len")?;
    let key = payload[at..at + klen].to_vec();
    at += klen;
    let (vlen, vn) = get_uvar(&payload[at..])?;
    at += vn;
    let vlen = crate::limits::bounded(vlen, payload.len() - at, "value-log value_len")?;
    let value = payload[at..at + vlen].to_vec();
    Ok(VlogRecord { tree_id, key, value, ciphertext: Vec::new(), total_len: n + len, nonce })
}

/// One open or sealed value-log segment, held as an extent in the page space.
pub struct VlogSegment {
    pub head: VlogHead,
    pub stats: VlogStats,
    /// The bytes reserved so far, which may exceed the durable `bytes`
    /// watermark: a crash can leave a reserved-but-unwritten hole below the
    /// tail, and that is safe because durability is defined by a *contiguous*
    /// watermark (§6.2).
    pub tail: u64,
}

impl VlogSegment {
    pub fn capacity(&self) -> u64 {
        self.head.capacity
    }
    pub fn remaining(&self) -> u64 {
        self.head.capacity.saturating_sub(self.tail)
    }
    /// §6.2's reservation: one `fetch_add` on the tail, then a write straight
    /// into the reserved range. Concurrent writers never touch the same bytes.
    pub fn reserve(&mut self, n: u64) -> Option<u64> {
        if self.remaining() < n {
            return None;
        }
        let at = self.head.data_offset as u64 + self.tail;
        self.tail += n;
        Some(at)
    }
}

/// §6.9's locality debt, over the live value-log bytes of a database.
///
/// It counts **surplus runs**, not flags: an earlier draft defined it as "live
/// bytes in segments without the clustered flag", and a database with nineteen
/// individually sorted runs read 0 % while its scans had already degraded 2.1x.
pub fn locality_debt(stats: &[VlogStats], vlog_segment_bytes: u64) -> f64 {
    let live: Vec<&VlogStats> = stats.iter().filter(|s| s.live_bytes > 0).collect();
    let total: u64 = live.iter().map(|s| s.live_bytes).sum();
    if total == 0 {
        return 0.0;
    }
    let ideal = (total.div_ceil(vlog_segment_bytes.max(1))).max(1) as usize;
    let mut sorted: Vec<&&VlogStats> = live.iter().collect();
    sorted.sort_by(|a, b| b.live_bytes.cmp(&a.live_bytes));
    let mut surplus = 0u64;
    for (i, s) in sorted.iter().enumerate() {
        // Live bytes in a run that is not key-clustered at all are surplus
        // regardless of where it sorts.
        if i >= ideal || !s.clustered {
            surplus += s.live_bytes;
        }
    }
    surplus as f64 / total as f64
}

pub fn ideal_runs(stats: &[VlogStats], vlog_segment_bytes: u64) -> u64 {
    let total: u64 = stats.iter().map(|s| s.live_bytes).sum();
    total.div_ceil(vlog_segment_bytes.max(1)).max(1)
}

pub fn live_runs(stats: &[VlogStats]) -> u64 {
    stats.iter().filter(|s| s.live_bytes > 0).count() as u64
}

/// §6.5 — the inline/value-log cut-off. A tree MAY opt out entirely with
/// `params.inline_values`; a reader MUST honour whichever `value_kind` it
/// finds, because the flag is a writer's policy, not a promise about disk.
pub fn separate(value_len: usize, vlog_min: u32, inline_values: bool) -> bool {
    !inline_values && value_len >= vlog_min as usize
}

pub fn check_pointer_in_bounds(p: &VlogPointer, stats: &VlogStats, data_offset: u32) -> Result<()> {
    let end = p.offset as u64 + p.len as u64;
    if end > data_offset as u64 + stats.bytes {
        return corrupt(format!(
            "VLOG pointer into segment {} ends at {end}, past the durable watermark {}",
            p.segment_id,
            data_offset as u64 + stats.bytes
        ));
    }
    Ok(())
}

pub fn check_segment_bytes(vlog_segment_bytes: u32) -> Result<()> {
    // §6.4: both `offset` and `len` are u32, so a value-log segment MUST NOT
    // exceed 4 GiB. `vlog_segment_bytes` is a u32 field, so this is not a new
    // constraint -- it is stated so a writer cannot drift past it.
    if vlog_segment_bytes == 0 {
        return invalid("vlog_segment_bytes must be positive");
    }
    Ok(())
}
