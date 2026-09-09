//! `04-segments.md` §1, §2, §2.5 and §8 — the internal key, the immutable
//! segment, and the cursor over it.
//!
//! A segment is built **bottom-up from a sorted stream** and written once.
//! There is no insertion path, so no split algorithm, no rebalancing, and no
//! in-place page update anywhere in this file.

use crate::container::{
    page_flags, page_type, u16le, u64le, PageHeader, PAGE_HEADER_BYTES,
};
use crate::error::{corrupt, invalid, Result};
use crate::filter::{user_key_prefix, BlockedBloom, MAGIC as FILTER_MAGIC};
use crate::limits::check_page_size;
use crate::varint::{get_uvar, put_uvar};

pub const SEGMENT_MAGIC: [u8; 8] = [0x43, 0x52, 0x59, 0x5F, 0x53, 0x45, 0x47, 0x1A];
pub const POINTER_BYTES: usize = 16;
/// `kind_flags` bit 4 — an `expiry_ms` follows. The rest of the high nibble is
/// reserved and MUST be zero.
pub const HAS_EXPIRY: u8 = 0x10;

/// §1's `op`.
pub mod op {
    pub const PUT: u8 = 0;
    pub const DELETE: u8 = 1;
    pub const MERGE: u8 = 2; // reserved
    pub const RANGE_DELETE: u8 = 3;
}

/// §2.2's `value_kind`, the low nibble of `kind_flags`.
pub mod value_kind {
    pub const INLINE: u8 = 0;
    pub const OVERFLOW: u8 = 1;
    pub const BLOB: u8 = 2;
    pub const EMPTY: u8 = 3;
    pub const VLOG: u8 = 4;
    pub const MAX: u8 = VLOG;

    /// True when the value is a fixed 16-byte pointer, so no `value_len` is
    /// written: a length field whose only legal value is 16 is not
    /// information, it is a second place for two implementations to disagree.
    pub fn is_pointer(k: u8) -> bool {
        k == VLOG || k == BLOB
    }
}

/// §2.1's `flags`.
pub mod seg_flags {
    pub const HAS_RANGE_DELETES: u8 = 0x01;
    pub const SINGLE_TREE: u8 = 0x02;
    pub const HAS_TTL: u8 = 0x04;
}

pub const NODE_IS_LEAF: u16 = 0x01;

/// `u32be(tree_id) || CKE(key) || u64be(seq XOR ~0) || u8(op)`.
pub fn internal_key(tree_id: u32, cke: &[u8], seq: u64, op: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + cke.len() + 9);
    out.extend_from_slice(&tree_id.to_be_bytes());
    out.extend_from_slice(cke);
    out.extend_from_slice(&(seq ^ u64::MAX).to_be_bytes());
    out.push(op);
    out
}

/// The `(tree_id, CKE(key))` prefix: what a filter is built over (§2.4) and
/// what a point read seeks to.
pub fn user_prefix(tree_id: u32, cke: &[u8]) -> Vec<u8> {
    user_key_prefix(tree_id, cke)
}

#[derive(Clone, Copy, Debug)]
pub struct ParsedKey<'a> {
    pub tree_id: u32,
    pub cke: &'a [u8],
    pub seq: u64,
    pub op: u8,
}

pub fn parse_internal_key(ik: &[u8]) -> Result<ParsedKey<'_>> {
    if ik.len() < 13 {
        return corrupt("internal key shorter than 13 bytes");
    }
    let cke_end = ik.len() - 9;
    Ok(ParsedKey {
        tree_id: u32::from_be_bytes(ik[0..4].try_into().unwrap()),
        cke: &ik[4..cke_end],
        seq: u64::from_be_bytes(ik[cke_end..cke_end + 8].try_into().unwrap()) ^ u64::MAX,
        op: ik[ik.len() - 1],
    })
}

/// The user-key prefix of an internal key: everything but `~seq || op`.
pub fn user_part(ik: &[u8]) -> &[u8] {
    &ik[..ik.len().saturating_sub(9)]
}

/// One entry handed to [`SegmentBuilder`].
#[derive(Clone, Debug)]
pub struct SegEntry {
    pub internal_key: Vec<u8>,
    pub value_kind: u8,
    pub value: Vec<u8>,
    pub expiry_ms: Option<u64>,
}

impl SegEntry {
    pub fn new(internal_key: Vec<u8>, value_kind: u8, value: Vec<u8>) -> SegEntry {
        SegEntry { internal_key, value_kind, value, expiry_ms: None }
    }
    pub fn seq(&self) -> u64 {
        parse_internal_key(&self.internal_key).map(|p| p.seq).unwrap_or(0)
    }
    pub fn op(&self) -> u8 {
        *self.internal_key.last().unwrap_or(&op::PUT)
    }
}

/// One decoded leaf entry.
#[derive(Clone, Debug)]
pub struct SegRecord {
    pub internal_key: Vec<u8>,
    pub value_kind: u8,
    pub value: Vec<u8>,
    pub expiry_ms: Option<u64>,
}

impl SegRecord {
    pub fn op(&self) -> u8 {
        *self.internal_key.last().unwrap()
    }
    pub fn seq(&self) -> u64 {
        parse_internal_key(&self.internal_key).map(|p| p.seq).unwrap_or(0)
    }
    pub fn user_key(&self) -> &[u8] {
        user_part(&self.internal_key)
    }
}

/// §2.2: "A writer SHOULD truncate separators to the shortest string that
/// still separates the neighbouring subtrees." Every returned separator
/// satisfies `prev < sep <= next`, which is what the descent needs.
pub fn shortest_separator(prev: Option<&[u8]>, next: &[u8]) -> Vec<u8> {
    let Some(prev) = prev else { return Vec::new() };
    if next.is_empty() {
        return Vec::new();
    }
    let n = prev.len().min(next.len());
    for i in 0..n {
        if prev[i] != next[i] {
            return next[..=i].to_vec();
        }
    }
    if prev.len() >= next.len() {
        next.to_vec()
    } else {
        next[..prev.len() + 1].to_vec()
    }
}

fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    (0..n).take_while(|&i| a[i] == b[i]).count()
}

fn uvar_len(mut v: u64) -> usize {
    let mut n = 1;
    v >>= 7;
    while v != 0 {
        n += 1;
        v >>= 7;
    }
    n
}

fn page_prefix(keys: &[Vec<u8>]) -> usize {
    let Some(first) = keys.first() else { return 0 };
    let mut n = first.len();
    for k in keys.iter().skip(1) {
        if n == 0 {
            break;
        }
        n = n.min(common_prefix(first, k));
    }
    n
}

/// Exact encoded size of a B+tree page — exact, not an upper bound, because
/// the copy-on-write trees of §3.3 decide splits by this number.
pub fn node_page_bytes(keys: &[Vec<u8>], payloads: &[Vec<u8>]) -> usize {
    let prefix_len = page_prefix(keys);
    let mut n = PAGE_HEADER_BYTES + 16 + prefix_len + 2 * keys.len();
    for i in 0..keys.len() {
        let suffix = keys[i].len() - prefix_len;
        n += uvar_len(suffix as u64) + suffix + payloads[i].len();
    }
    n
}

/// §2.2 — one encoder for both users of the format: the segment builder and
/// the copy-on-write trees. Two encoders would be two places for the same
/// bytes to drift.
pub fn encode_node_page(
    page_size: usize,
    payload_size: usize,
    is_leaf: bool,
    keys: &[Vec<u8>],
    payloads: &[Vec<u8>],
    subtree_entries: u64,
    tree_id: u32,
    commit_id: u64,
) -> Result<Vec<u8>> {
    check_page_size(page_size)?;
    if payload_size > page_size - PAGE_HEADER_BYTES {
        return invalid("payload_size exceeds the page");
    }
    let mut page = vec![0u8; page_size];
    let base = PAGE_HEADER_BYTES;
    let count = keys.len();
    let prefix_len = page_prefix(keys);

    // Cells grow downward from the payload end; cell_ptr[] grows up.
    let mut cell_top = payload_size;
    let mut ptrs = vec![0usize; count];
    for i in (0..count).rev() {
        let suffix = &keys[i][prefix_len..];
        let mut cell = Vec::with_capacity(2 + suffix.len() + payloads[i].len());
        put_uvar(&mut cell, suffix.len() as u64);
        cell.extend_from_slice(suffix);
        cell.extend_from_slice(&payloads[i]);
        cell_top -= cell.len();
        ptrs[i] = cell_top;
        page[base + cell_top..base + cell_top + cell.len()].copy_from_slice(&cell);
    }

    let free_start = 16 + prefix_len + 2 * count;
    if free_start > cell_top {
        return invalid(format!("page overflow: header+pointers {free_start}, cells at {cell_top}"));
    }
    page[base..base + 2].copy_from_slice(&(count as u16).to_le_bytes());
    page[base + 2..base + 4].copy_from_slice(&(free_start as u16).to_le_bytes());
    page[base + 4..base + 6].copy_from_slice(&(prefix_len as u16).to_le_bytes());
    page[base + 6..base + 8]
        .copy_from_slice(&(if is_leaf { NODE_IS_LEAF } else { 0 }).to_le_bytes());
    page[base + 8..base + 16].copy_from_slice(&subtree_entries.to_le_bytes());
    if prefix_len > 0 {
        page[base + 16..base + 16 + prefix_len].copy_from_slice(&keys[0][..prefix_len]);
    }
    for (i, &p) in ptrs.iter().enumerate() {
        let at = base + 16 + prefix_len + i * 2;
        page[at..at + 2].copy_from_slice(&(p as u16).to_le_bytes());
    }
    PageHeader {
        page_type: if is_leaf { page_type::BTREE_LEAF } else { page_type::BTREE_INTERNAL },
        tree_id,
        commit_id,
        payload_len: payload_size as u32,
        ..Default::default()
    }
    .write_into(&mut page);
    Ok(page)
}

/// A parsed B+tree page.
pub struct Node<'a> {
    pub page: &'a [u8],
    pub page_index: u64,
    pub cell_count: usize,
    pub free_start: usize,
    pub prefix_len: usize,
    pub is_leaf: bool,
    pub subtree_entries: u64,
    base: usize,
    ptr_base: usize,
}

impl<'a> Node<'a> {
    pub fn parse(page: &'a [u8], page_index: u64) -> Result<Node<'a>> {
        let base = PAGE_HEADER_BYTES;
        if page.len() < base + 16 {
            return corrupt(format!("page {page_index} is too small for a node header"));
        }
        let cell_count = u16le(page, base) as usize;
        let free_start = u16le(page, base + 2) as usize;
        let prefix_len = u16le(page, base + 4) as usize;
        let flags = u16le(page, base + 6);
        let subtree_entries = u64le(page, base + 8);
        if 16 + prefix_len + cell_count * 2 > page.len() - base {
            return corrupt(format!("page {page_index}: cell pointers overrun the payload"));
        }
        Ok(Node {
            page,
            page_index,
            cell_count,
            free_start,
            prefix_len,
            is_leaf: flags & NODE_IS_LEAF != 0,
            subtree_entries,
            base,
            ptr_base: base + 16 + prefix_len,
        })
    }

    pub fn prefix(&self) -> &[u8] {
        &self.page[self.base + 16..self.base + 16 + self.prefix_len]
    }

    fn cell_offset(&self, i: usize) -> Result<usize> {
        if i >= self.cell_count {
            return corrupt(format!("page {}: cell {i} out of range", self.page_index));
        }
        let off = u16le(self.page, self.ptr_base + i * 2) as usize;
        if self.base + off >= self.page.len() {
            return corrupt(format!("page {}: cell {i} points past the page", self.page_index));
        }
        Ok(self.base + off)
    }

    fn suffix_at(&self, i: usize) -> Result<(&[u8], usize)> {
        let at = self.cell_offset(i)?;
        let (len, n) = get_uvar(&self.page[at..])?;
        let start = at + n;
        let end = start
            .checked_add(len as usize)
            .filter(|e| *e <= self.page.len())
            .ok_or_else(|| crate::error::Error::Corrupt(format!("page {}: cell {i} suffix runs past the page", self.page_index)))?;
        Ok((&self.page[start..end], end))
    }

    pub fn key_at(&self, i: usize) -> Result<Vec<u8>> {
        let (suffix, _) = self.suffix_at(i)?;
        let mut out = Vec::with_capacity(self.prefix_len + suffix.len());
        out.extend_from_slice(self.prefix());
        out.extend_from_slice(suffix);
        Ok(out)
    }

    /// Compares the search key against cell `i` without materializing the key.
    pub fn compare_cell(&self, i: usize, target: &[u8]) -> Result<std::cmp::Ordering> {
        let (suffix, _) = self.suffix_at(i)?;
        let prefix = self.prefix();
        let n = prefix.len().min(target.len());
        for j in 0..n {
            if prefix[j] != target[j] {
                return Ok(prefix[j].cmp(&target[j]));
            }
        }
        if target.len() < prefix.len() {
            return Ok(std::cmp::Ordering::Greater);
        }
        for (j, &s) in suffix.iter().enumerate() {
            if prefix.len() + j >= target.len() {
                return Ok(std::cmp::Ordering::Greater);
            }
            if s != target[prefix.len() + j] {
                return Ok(s.cmp(&target[prefix.len() + j]));
            }
        }
        Ok((prefix.len() + suffix.len()).cmp(&target.len()))
    }

    /// The bytes after the key of cell `i` — the cell's payload.
    pub fn payload_at(&self, i: usize) -> Result<&[u8]> {
        let (_, end) = self.suffix_at(i)?;
        Ok(&self.page[end..])
    }

    /// `(child_page, child_subtree_entries)` of internal cell `i`.
    pub fn child_at(&self, i: usize) -> Result<(u64, u64)> {
        let p = self.payload_at(i)?;
        if p.len() < 16 {
            return corrupt("internal cell shorter than its 16-byte child pointer");
        }
        Ok((u64le(p, 0), u64le(p, 8)))
    }

    pub fn record_at(&self, i: usize) -> Result<SegRecord> {
        let key = self.key_at(i)?;
        // §1: an internal key is `u32be(tree_id) || CKE(key) || u64be(~seq) ||
        // u8 op`, so it is never shorter than 13 bytes and in particular never
        // empty. A hostile page can declare one that is — `prefix_len` and
        // `suffix_len` are both read from the file — and taking its last byte
        // for the op was a panic rather than §9.1's typed error.
        // `parse_internal_key` already holds that minimum; reusing it keeps the
        // rule in one place rather than two that can drift.
        let op_byte = parse_internal_key(&key)?.op;
        let p = self.payload_at(i)?;
        let (value_kind, expiry, value) = decode_cell_payload(p, op_byte)?;
        Ok(SegRecord { internal_key: key, value_kind, value, expiry_ms: expiry })
    }

    /// Index of the last cell whose key is <= `target`, or `None`.
    pub fn floor_index(&self, target: &[u8]) -> Result<Option<usize>> {
        let (mut lo, mut hi) = (0isize, self.cell_count as isize - 1);
        let mut ans = None;
        while lo <= hi {
            let mid = ((lo + hi) / 2) as usize;
            if self.compare_cell(mid, target)? != std::cmp::Ordering::Greater {
                ans = Some(mid);
                lo = mid as isize + 1;
            } else {
                hi = mid as isize - 1;
            }
        }
        Ok(ans)
    }

    /// Index of the first cell whose key is >= `target`, or `cell_count`.
    pub fn ceiling_index(&self, target: &[u8]) -> Result<usize> {
        let (mut lo, mut hi) = (0isize, self.cell_count as isize - 1);
        let mut ans = self.cell_count;
        while lo <= hi {
            let mid = ((lo + hi) / 2) as usize;
            if self.compare_cell(mid, target)? != std::cmp::Ordering::Less {
                ans = mid;
                hi = mid as isize - 1;
            } else {
                lo = mid as isize + 1;
            }
        }
        Ok(ans)
    }
}

/// §2.2's leaf cell payload, after the key.
pub fn decode_cell_payload(p: &[u8], op_byte: u8) -> Result<(u8, Option<u64>, Vec<u8>)> {
    if p.is_empty() {
        return corrupt("leaf cell has no kind_flags byte");
    }
    let kind_flags = p[0];
    let value_kind = kind_flags & 0x0F;
    if value_kind > value_kind::MAX {
        return corrupt(format!("value_kind {value_kind} is not 0..4"));
    }
    if kind_flags & 0xE0 != 0 {
        return corrupt("reserved kind_flags bits are set");
    }
    let mut at = 1usize;
    let expiry = if kind_flags & HAS_EXPIRY != 0 {
        if p.len() < at + 8 {
            return corrupt("truncated expiry_ms");
        }
        let v = u64le(p, at);
        at += 8;
        Some(v)
    } else {
        None
    };
    if value_kind == value_kind::EMPTY || op_byte == op::DELETE {
        return Ok((value_kind, expiry, Vec::new()));
    }
    let value = if value_kind::is_pointer(value_kind) {
        if p.len() < at + POINTER_BYTES {
            return corrupt("truncated 16-byte pointer");
        }
        p[at..at + POINTER_BYTES].to_vec()
    } else {
        let (len, n) = get_uvar(&p[at..])?;
        let start = at + n;
        let end = start
            .checked_add(len as usize)
            .filter(|e| *e <= p.len())
            .ok_or_else(|| crate::error::Error::Corrupt("value_len runs past the cell".into()))?;
        p[start..end].to_vec()
    };
    Ok((value_kind, expiry, value))
}

pub fn encode_cell_payload(e: &SegEntry) -> Result<Vec<u8>> {
    if e.value_kind > value_kind::MAX {
        return invalid(format!("value_kind {} is not 0..4", e.value_kind));
    }
    let mut out = Vec::with_capacity(e.value.len() + 12);
    let mut kind_flags = e.value_kind;
    if e.expiry_ms.is_some() {
        kind_flags |= HAS_EXPIRY;
    }
    out.push(kind_flags);
    if let Some(x) = e.expiry_ms {
        out.extend_from_slice(&x.to_le_bytes());
    }
    let op_byte = e.op();
    if e.value_kind == value_kind::EMPTY || op_byte == op::DELETE {
        return Ok(out);
    }
    if value_kind::is_pointer(e.value_kind) {
        if e.value.len() != POINTER_BYTES {
            return invalid(format!(
                "a VLOG or BLOB value is exactly {POINTER_BYTES} bytes, got {}",
                e.value.len()
            ));
        }
        out.extend_from_slice(&e.value);
    } else {
        put_uvar(&mut out, e.value.len() as u64);
        out.extend_from_slice(&e.value);
    }
    Ok(out)
}

/// §2.5 — `[start, end)` deleted at `seq`. Both bounds are user-key prefixes,
/// so a containment test is one comparison against the same bytes a point read
/// seeks with.
#[derive(Clone, Debug)]
pub struct RangeDelete {
    pub tree_id: u32,
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub seq: u64,
}

impl RangeDelete {
    pub fn covers(&self, user_key_prefix: &[u8]) -> bool {
        user_key_prefix >= &self.start[..] && user_key_prefix < &self.end[..]
    }
}

/// §2.5's payload: `uvar end_key_len || end_key`, carried as an INLINE value.
pub fn encode_range_delete_payload(end_user_prefix: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    put_uvar(&mut v, end_user_prefix.len() as u64);
    v.extend_from_slice(end_user_prefix);
    v
}

pub fn decode_range_delete_payload(p: &[u8]) -> Result<Vec<u8>> {
    let (len, n) = get_uvar(p)?;
    let end = n
        .checked_add(len as usize)
        .filter(|e| *e <= p.len())
        .ok_or_else(|| crate::error::Error::Corrupt("range delete end_key runs past the cell".into()))?;
    Ok(p[n..end].to_vec())
}

// ---------------------------------------------------------------------------
// §2.1 — the segment header
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct SegmentHeader {
    pub segment_id: u64,
    pub level: u8,
    pub flags: u8,
    pub filter_bits_per_key: u16,
    pub tree_count: u32,
    pub root_page: u64,
    pub entry_count: u64,
    pub tombstone_count: u64,
    pub min_seq: u64,
    pub max_seq: u64,
    pub filter_page: u64,
    pub value_bytes: u64,
    pub vlog_bytes: u64,
    pub min_expiry: u64,
    pub group: u8,
    pub min_key: Vec<u8>,
    pub max_key: Vec<u8>,
    pub tree_span: Vec<(u32, u64)>,
}

impl SegmentHeader {
    pub fn has_range_deletes(&self) -> bool {
        self.flags & seg_flags::HAS_RANGE_DELETES != 0
    }

    pub fn parse(page: &[u8]) -> Result<SegmentHeader> {
        let base = PAGE_HEADER_BYTES;
        if page.len() < base + 112 {
            return corrupt("segment header page too small");
        }
        let b = &page[base..];
        if b[0..8] != SEGMENT_MAGIC {
            return corrupt("segment header magic mismatch");
        }
        let tree_count = u32::from_le_bytes(b[20..24].try_into().unwrap());
        let min_key_len = u32::from_le_bytes(b[104..108].try_into().unwrap()) as usize;
        let max_key_len = u32::from_le_bytes(b[108..112].try_into().unwrap()) as usize;
        let keys_end = 112 + min_key_len + max_key_len;
        if keys_end + tree_count as usize * 12 > b.len() {
            return corrupt("segment header key bounds or tree span run past the page");
        }
        let mut tree_span = Vec::with_capacity(tree_count as usize);
        for i in 0..tree_count as usize {
            let at = keys_end + i * 12;
            tree_span.push((
                u32::from_le_bytes(b[at..at + 4].try_into().unwrap()),
                u64le(b, at + 4),
            ));
        }
        Ok(SegmentHeader {
            segment_id: u64le(b, 8),
            level: b[16],
            flags: b[17],
            filter_bits_per_key: u16le(b, 18),
            tree_count,
            root_page: u64le(b, 24),
            entry_count: u64le(b, 32),
            tombstone_count: u64le(b, 40),
            min_seq: u64le(b, 48),
            max_seq: u64le(b, 56),
            filter_page: u64le(b, 64),
            value_bytes: u64le(b, 72),
            vlog_bytes: u64le(b, 80),
            min_expiry: u64le(b, 88),
            group: b[96],
            min_key: b[112..112 + min_key_len].to_vec(),
            max_key: b[112 + min_key_len..keys_end].to_vec(),
            tree_span,
        })
    }
}

// ---------------------------------------------------------------------------
// §2.3 — bulk construction
// ---------------------------------------------------------------------------

struct PendingPage {
    is_leaf: bool,
    keys: Vec<Vec<u8>>,
    payloads: Vec<Vec<u8>>,
    sum_key_len: usize,
    sum_payload_len: usize,
    subtree_entries: u64,
    /// The **real** least and greatest internal keys reachable through this
    /// page, as opposed to the separators stored in it. A parent's separator
    /// must be computed against these, not against a stored separator, or a
    /// descent misses keys that are physically present.
    min_real: Option<Vec<u8>>,
    max_real: Option<Vec<u8>>,
}

impl PendingPage {
    fn new(is_leaf: bool) -> PendingPage {
        PendingPage {
            is_leaf,
            keys: Vec::new(),
            payloads: Vec::new(),
            sum_key_len: 0,
            sum_payload_len: 0,
            subtree_entries: 0,
            min_real: None,
            max_real: None,
        }
    }

    fn size_with(&self, extra_key: usize, extra_payload: usize, new_prefix: usize) -> usize {
        let n = self.keys.len() + 1;
        let total_key = self.sum_key_len + extra_key;
        let total_payload = self.sum_payload_len + extra_payload;
        let suffix_bytes = total_key - n * new_prefix;
        // Worst-case uvar for suffix_len; keys are capped at 4 KiB so it is
        // 1-2 bytes, and using the bound keeps the fill decision O(1).
        16 + new_prefix + n * 2 + suffix_bytes + n * 2 + total_payload
    }

    fn push(&mut self, k: Vec<u8>, payload: Vec<u8>) {
        self.sum_key_len += k.len();
        self.sum_payload_len += payload.len();
        if self.is_leaf {
            self.subtree_entries += 1;
        }
        self.keys.push(k);
        self.payloads.push(payload);
    }
}

pub struct SegmentBuilder {
    pub page_size: usize,
    pub segment_id: u64,
    pub level: u8,
    pub group: u8,
    pub single_tree: Option<u32>,
    pub filter_bits_per_key: u16,
    payload_size: usize,
    pages: Vec<Vec<u8>>,
    leaf: Option<PendingPage>,
    pending: std::collections::BTreeMap<usize, PendingPage>,
    prev_last: std::collections::BTreeMap<usize, Vec<u8>>,
    emitted: std::collections::BTreeMap<usize, usize>,
    max_level: usize,
    min_key: Option<Vec<u8>>,
    max_key: Option<Vec<u8>>,
    prev_key: Option<Vec<u8>>,
    entry_count: u64,
    tombstones: u64,
    min_seq: Option<u64>,
    max_seq: u64,
    value_bytes: u64,
    vlog_bytes: u64,
    min_expiry: u64,
    flags: u8,
    tree_span: std::collections::BTreeMap<u32, u64>,
    /// Distinct **user** keys, for the filter: all versions of a key share one
    /// entry, so `entry_count` — which counts versions — is the wrong number.
    /// `cfh64` of each distinct user key, for the filter — not the keys.
    /// See `BlockedBloom::build_from_hashes`.
    user_key_hashes: Vec<u64>,
}

impl SegmentBuilder {
    /// `tag_reserve` is `14-security.md` §5.2's AEAD tag: 16 on an encrypted
    /// database, 0 otherwise. It has to be subtracted here, before a single
    /// cell is placed, because a page filled to `page_size - 40` has nowhere
    /// left to put a tag.
    pub fn new(page_size: usize, segment_id: u64, level: u8, group: u8, filter_bits: u16) -> Result<SegmentBuilder> {
        SegmentBuilder::with_reserve(page_size, 0, segment_id, level, group, filter_bits)
    }

    pub fn with_reserve(
        page_size: usize,
        tag_reserve: usize,
        segment_id: u64,
        level: u8,
        group: u8,
        filter_bits: u16,
    ) -> Result<SegmentBuilder> {
        check_page_size(page_size)?;
        Ok(SegmentBuilder {
            page_size,
            segment_id,
            level,
            group,
            single_tree: None,
            filter_bits_per_key: filter_bits,
            payload_size: page_size - PAGE_HEADER_BYTES - tag_reserve,
            pages: Vec::new(),
            leaf: None,
            pending: Default::default(),
            prev_last: Default::default(),
            emitted: Default::default(),
            max_level: 0,
            min_key: None,
            max_key: None,
            prev_key: None,
            entry_count: 0,
            tombstones: 0,
            min_seq: None,
            max_seq: 0,
            value_bytes: 0,
            vlog_bytes: 0,
            min_expiry: 0,
            flags: 0,
            tree_span: Default::default(),
            user_key_hashes: Vec::new(),
        })
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub fn page_count(&self) -> usize {
        self.pages.len() + 1
    }

    /// Appends one entry. Keys MUST arrive strictly increasing: bulk
    /// construction is the only construction, so an out-of-order entry is a
    /// caller bug, not something to sort around.
    pub fn add(&mut self, e: SegEntry) -> Result<()> {
        let k = e.internal_key.clone();
        if k.len() > crate::limits::MAX_KEY_BYTES + 13 || k.len() > self.page_size / 4 + 13 {
            return invalid(format!(
                "internal key of {} B exceeds the limit for page_size {}",
                k.len(),
                self.page_size
            ));
        }
        if let Some(prev) = &self.prev_key {
            if prev[..] >= k[..] {
                return invalid("SegmentBuilder::add requires strictly increasing internal keys");
            }
        }
        if self.filter_bits_per_key > 0 {
            let u = user_part(&k);
            let h = crate::hash::cfh64(u);
            // The keys arrive in order, so equal user keys are adjacent and the
            // last hash is the only one worth comparing against.
            //
            // De-duplicating on the hash rather than on the bytes is exact for
            // this purpose, not an approximation: the filter's bits are a
            // function of the hash alone, so two adjacent keys that collide in
            // 64 bits would set identical bits and skipping the second changes
            // nothing a probe can observe. What it affects is
            // `distinct_keys`, which sizes the filter — one short, on a 64-bit
            // collision between neighbours.
            if self.user_key_hashes.last() != Some(&h) {
                self.user_key_hashes.push(h);
            }
        }
        self.prev_key = Some(k.clone());
        if self.min_key.is_none() {
            self.min_key = Some(k.clone());
        }
        self.max_key = Some(k.clone());

        let parsed = parse_internal_key(&k)?;
        *self.tree_span.entry(parsed.tree_id).or_insert(0) += 1;
        self.min_seq = Some(self.min_seq.map_or(parsed.seq, |m| m.min(parsed.seq)));
        self.max_seq = self.max_seq.max(parsed.seq);
        if parsed.op == op::DELETE {
            self.tombstones += 1;
        }
        if parsed.op == op::RANGE_DELETE {
            self.flags |= seg_flags::HAS_RANGE_DELETES;
        }
        if e.value_kind == value_kind::INLINE {
            self.value_bytes += e.value.len() as u64;
        }
        if e.value_kind == value_kind::VLOG {
            self.vlog_bytes += e.value.len() as u64;
        }
        if let Some(x) = e.expiry_ms {
            self.flags |= seg_flags::HAS_TTL;
            if self.min_expiry == 0 || x < self.min_expiry {
                self.min_expiry = x;
            }
        }
        self.entry_count += 1;

        let payload = encode_cell_payload(&e)?;
        let need_flush = match &self.leaf {
            None => false,
            Some(leaf) => {
                let np = common_prefix(&leaf.keys[0], &k);
                leaf.size_with(k.len(), payload.len(), np) > self.payload_size
            }
        };
        if need_flush {
            self.flush_leaf()?;
        }
        if self.leaf.is_none() {
            self.leaf = Some(PendingPage::new(true));
        }
        let leaf = self.leaf.as_mut().unwrap();
        if leaf.min_real.is_none() {
            leaf.min_real = Some(k.clone());
        }
        leaf.max_real = Some(k.clone());
        leaf.push(k, payload);
        Ok(())
    }

    fn flush_leaf(&mut self) -> Result<()> {
        let Some(leaf) = self.leaf.take() else { return Ok(()) };
        if leaf.keys.is_empty() {
            return Ok(());
        }
        self.emit_and_route(0, leaf)
    }

    fn emit_page(&mut self, p: &PendingPage) -> Result<u64> {
        let page = encode_node_page(
            self.page_size,
            self.payload_size,
            p.is_leaf,
            &p.keys,
            &p.payloads,
            p.subtree_entries,
            crate::container::NO_TREE,
            0,
        )?;
        self.pages.push(page);
        Ok(self.pages.len() as u64) // page 0 is the segment header
    }

    fn emit_and_route(&mut self, level: usize, p: PendingPage) -> Result<()> {
        let page_index = self.emit_page(&p)?;
        let min = p.min_real.clone().unwrap();
        let max = p.max_real.clone().unwrap();
        let sep = shortest_separator(self.prev_last.get(&level).map(|v| v.as_slice()), &min);
        self.prev_last.insert(level, max.clone());
        *self.emitted.entry(level).or_insert(0) += 1;
        self.add_child(level + 1, sep, page_index, p.subtree_entries, min, max)
    }

    fn add_child(
        &mut self,
        level: usize,
        sep: Vec<u8>,
        child_page: u64,
        child_entries: u64,
        child_min: Vec<u8>,
        child_max: Vec<u8>,
    ) -> Result<()> {
        self.max_level = self.max_level.max(level);
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(&child_page.to_le_bytes());
        payload.extend_from_slice(&child_entries.to_le_bytes());

        if let Some(page) = self.pending.get(&level) {
            let np = common_prefix(&page.keys[0], &sep);
            if page.size_with(sep.len(), payload.len(), np) > self.payload_size {
                let full = self.pending.remove(&level).unwrap();
                self.emit_and_route(level, full)?;
            }
        }
        let fresh_sep = if !self.pending.contains_key(&level) {
            // The first child of a fresh page: recompute its separator now
            // that we know it starts a page.
            Some(shortest_separator(self.prev_last.get(&level).map(|v| v.as_slice()), &child_min))
        } else {
            None
        };
        let page = self.pending.entry(level).or_insert_with(|| PendingPage::new(false));
        page.push(fresh_sep.unwrap_or(sep), payload);
        if page.min_real.is_none() {
            page.min_real = Some(child_min);
        }
        page.max_real = Some(child_max);
        page.subtree_entries += child_entries;
        Ok(())
    }

    /// Finishes the segment and returns the complete extent.
    pub fn build(mut self) -> Result<Vec<u8>> {
        self.flush_leaf()?;
        if self.pages.is_empty() {
            return invalid("an empty segment has no root");
        }
        let mut root_page = self.pages.len() as u64;
        let mut root_entries = self.entry_count;

        let mut level = 1usize;
        while level <= self.max_level || !self.pending.is_empty() {
            let Some(p) = self.pending.remove(&level) else {
                if level > self.max_level {
                    break;
                }
                level += 1;
                continue;
            };
            let prior = *self.emitted.get(&level).unwrap_or(&0);
            let anything_above = self.pending.keys().any(|&l| l > level);
            if prior == 0 && !anything_above {
                if p.keys.len() == 1 {
                    // A chain of one: the child is already a valid root.
                    root_page = u64le(&p.payloads[0], 0);
                    root_entries = u64le(&p.payloads[0], 8);
                } else {
                    root_entries = p.subtree_entries;
                    root_page = self.emit_page(&p)?;
                }
                break;
            }
            root_entries = p.subtree_entries;
            self.emit_and_route(level, p)?;
            root_page = self.pages.len() as u64;
            level += 1;
        }

        let filter_page = self.emit_filter()?;
        let header = self.build_header(root_page, root_entries, filter_page)?;
        let mut out = Vec::with_capacity(self.page_size * (self.pages.len() + 1));
        out.extend_from_slice(&header);
        for p in &self.pages {
            out.extend_from_slice(p);
        }
        Ok(out)
    }

    fn emit_filter(&mut self) -> Result<u64> {
        if self.filter_bits_per_key == 0 || self.user_key_hashes.is_empty() {
            return Ok(0);
        }
        let f = BlockedBloom::build_from_hashes(
            &self.user_key_hashes,
            self.filter_bits_per_key as u32,
            self.user_key_hashes.len() as u64,
        );
        let payload = f.encode_payload();
        let first = self.pages.len() as u64 + 1;
        let capacity = self.payload_size;
        let mut off = 0usize;
        while off < payload.len() {
            let n = (payload.len() - off).min(capacity);
            let mut page = vec![0u8; self.page_size];
            page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + n]
                .copy_from_slice(&payload[off..off + n]);
            PageHeader {
                page_type: page_type::SEGMENT_FILTER,
                tree_id: crate::container::NO_TREE,
                payload_len: n as u32,
                ..Default::default()
            }
            .write_into(&mut page);
            self.pages.push(page);
            off += n;
        }
        Ok(first)
    }

    fn build_header(&self, root_page: u64, root_entries: u64, filter_page: u64) -> Result<Vec<u8>> {
        let mut page = vec![0u8; self.page_size];
        let base = PAGE_HEADER_BYTES;
        let mut w: Vec<u8> = Vec::with_capacity(256);
        w.extend_from_slice(&SEGMENT_MAGIC);
        w.extend_from_slice(&self.segment_id.to_le_bytes());
        w.push(self.level);
        w.push(if self.single_tree.is_some() {
            self.flags | seg_flags::SINGLE_TREE
        } else {
            self.flags
        });
        w.extend_from_slice(&self.filter_bits_per_key.to_le_bytes());
        w.extend_from_slice(&(self.tree_span.len() as u32).to_le_bytes());
        w.extend_from_slice(&root_page.to_le_bytes());
        w.extend_from_slice(&self.entry_count.to_le_bytes());
        w.extend_from_slice(&self.tombstones.to_le_bytes());
        w.extend_from_slice(&self.min_seq.unwrap_or(0).to_le_bytes());
        w.extend_from_slice(&self.max_seq.to_le_bytes());
        w.extend_from_slice(&filter_page.to_le_bytes());
        w.extend_from_slice(&self.value_bytes.to_le_bytes());
        w.extend_from_slice(&self.vlog_bytes.to_le_bytes());
        w.extend_from_slice(&self.min_expiry.to_le_bytes());
        w.push(self.group);
        w.extend_from_slice(&[0u8; 7]); // reserved
        let _ = root_entries;

        // §2.1: min_key / max_key are BOUNDS, and the whole header MUST fit the
        // head page. Shortened bounds only widen the range a pruner considers,
        // so they cost a candidate, never a correct answer.
        let mut min_key = self.min_key.clone().unwrap_or_default();
        let mut max_key = self.max_key.clone().unwrap_or_default();
        let budget = self
            .payload_size
            .saturating_sub(w.len() + 8 + self.tree_span.len() * 12 + 8);
        if min_key.len() + max_key.len() > budget {
            let half = (budget / 2).min(min_key.len());
            min_key.truncate(half);
            let keep = budget.saturating_sub(min_key.len() + 1).min(max_key.len());
            max_key.truncate(keep);
            max_key.push(0xFF);
        }
        w.extend_from_slice(&(min_key.len() as u32).to_le_bytes());
        w.extend_from_slice(&(max_key.len() as u32).to_le_bytes());
        w.extend_from_slice(&min_key);
        w.extend_from_slice(&max_key);
        for (&t, &n) in &self.tree_span {
            w.extend_from_slice(&t.to_le_bytes());
            w.extend_from_slice(&n.to_le_bytes());
        }
        if base + w.len() > self.page_size {
            return invalid("segment header does not fit its page");
        }
        page[base..base + w.len()].copy_from_slice(&w);
        PageHeader {
            page_type: page_type::SEGMENT_HEADER,
            flags: page_flags::EXTENT_HEAD,
            tree_id: crate::container::NO_TREE,
            extent_pages: self.pages.len() as u32 + 1,
            payload_len: w.len() as u32,
            ..Default::default()
        }
        .write_into(&mut page);
        Ok(page)
    }
}

// ---------------------------------------------------------------------------
// Reading a segment
// ---------------------------------------------------------------------------

/// An immutable segment, read from its extent.
pub struct Segment {
    pub extent: Vec<u8>,
    pub page_size: usize,
    pub header: SegmentHeader,
    pub node_accesses: std::sync::atomic::AtomicU64,
    pub page_reads: std::sync::atomic::AtomicU64,
    /// The parsed `04-segments.md` §2.4 filter, decoded at most once per open
    /// segment. See [`Segment::may_contain`] for why it is not decoded per
    /// probe. `OnceLock` rather than `OnceCell` because a `Segment` is held in
    /// an `Arc` and probed from every reader thread.
    filter_cache: std::sync::OnceLock<Option<BlockedBloom>>,
    /// How many times the filter payload has actually been decoded. A counter,
    /// so the caching above is provable rather than merely faster.
    pub filter_parses: std::sync::atomic::AtomicU64,
}

impl Segment {
    pub fn open(extent: Vec<u8>, page_size: usize) -> Result<Segment> {
        check_page_size(page_size)?;
        if extent.len() < page_size || extent.len() % page_size != 0 {
            return corrupt(format!(
                "segment extent of {} B is not a whole number of {page_size} B pages",
                extent.len()
            ));
        }
        let header = SegmentHeader::parse(&extent[..page_size])?;
        Ok(Segment {
            extent,
            page_size,
            header,
            node_accesses: std::sync::atomic::AtomicU64::new(0),
            page_reads: std::sync::atomic::AtomicU64::new(0),
            filter_cache: std::sync::OnceLock::new(),
            filter_parses: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn page_count(&self) -> u64 {
        (self.extent.len() / self.page_size) as u64
    }

    pub fn node(&self, page_index: u64) -> Result<Node<'_>> {
        self.node_accesses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if page_index < 1 || page_index >= self.page_count() {
            return corrupt(format!("page index {page_index} outside the extent"));
        }
        self.page_reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let at = page_index as usize * self.page_size;
        Node::parse(&self.extent[at..at + self.page_size], page_index)
    }

    /// `01-container.md` §9 step 2 — every page checksum in the extent.
    pub fn verify_checksums(&self) -> Result<()> {
        for i in 0..self.page_count() {
            let at = i as usize * self.page_size;
            PageHeader::verify(&self.extent[at..at + self.page_size], i)?;
        }
        Ok(())
    }

    /// §2.4 — the filter, or `None` when `filter_page = 0`, which a reader
    /// MUST read as "treat every probe as a hit".
    pub fn filter(&self) -> Result<Option<BlockedBloom>> {
        if self.header.filter_page == 0 {
            return Ok(None);
        }
        self.filter_parses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut payload = Vec::new();
        let cap = self.page_size - PAGE_HEADER_BYTES;
        let mut idx = self.header.filter_page;
        while idx < self.page_count() {
            let at = idx as usize * self.page_size;
            let page = &self.extent[at..at + self.page_size];
            let h = PageHeader::parse(page)?;
            if h.page_type != page_type::SEGMENT_FILTER {
                break;
            }
            let n = (h.payload_len as usize).min(cap);
            payload.extend_from_slice(&page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + n]);
            idx += 1;
        }
        if payload.len() < 20 {
            return corrupt("filter page shorter than its 20-byte header");
        }
        let magic = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        if magic != FILTER_MAGIC {
            return corrupt("filter magic is not CFP1");
        }
        let block_count = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as u64;
        let bits_per_key = u16le(&payload, 8) as u32;
        // A reader MUST use the stored `probes`, not recompute it.
        let probes = u16le(&payload, 10) as u32;
        let distinct_keys = u64le(&payload, 12);
        // §2.4's two attacker-controlled loop/index bounds, refused here rather
        // than trusted downstream (`14-security.md` §9.1). `block_count = 0`
        // makes `locate` address byte 0 of a zero-length block array, which is
        // an out-of-bounds index and not a corruption error; `probes` is a loop
        // count a reader MUST take from the file rather than recompute.
        if block_count < 1 {
            return corrupt("filter block_count is 0");
        }
        if !(1..=16).contains(&probes) {
            return corrupt(format!("filter probes is {probes}, outside 1..16"));
        }
        let want = block_count as usize * crate::filter::BLOCK_BYTES;
        if payload.len() < 20 + want {
            return corrupt("filter blocks truncated");
        }
        Ok(Some(BlockedBloom {
            blocks: payload[20..20 + want].to_vec(),
            block_count,
            bits_per_key,
            probes,
            distinct_keys,
        }))
    }

    /// §2.4's probe.
    ///
    /// The filter is decoded **once per open segment**, not once per probe.
    /// Before this cache existed, every point read re-walked the filter's pages,
    /// copied the whole payload into a fresh `Vec`, and then copied the block
    /// array out of it a second time — for a probe that reads one bit. §12 costs
    /// a probe as "exactly one 64-byte block"; two full copies of a filter that
    /// is tens of kilobytes on a large segment is not that, and it happened on
    /// the hottest path in the engine. The Dart and Java implementations both
    /// already cached it (`_filterLoaded`, `filterLoaded`); this was a
    /// divergence, not a design.
    ///
    /// A filter that fails to decode caches as `None`, which answers "maybe" —
    /// always a sound answer for a Bloom filter, and the behaviour this method
    /// already had.
    pub fn may_contain(&self, user_key_prefix: &[u8]) -> bool {
        match self.filter_cache.get_or_init(|| self.filter().ok().flatten()) {
            Some(f) => f.may_contain(user_key_prefix),
            None => true,
        }
    }

    /// A cursor positioned at the first entry at or after `target` (§8's
    /// `seek_ceiling`).
    pub fn seek(&self, target: &[u8]) -> Result<SegmentCursor<'_>> {
        let mut c = SegmentCursor::new(self);
        c.seek_ceiling(target)?;
        Ok(c)
    }

    /// The first record for `user_key_prefix` whose seq is <= `ceiling`.
    /// Newest-first order inside a key falls out of §1's inverted seq, so this
    /// is a seek and a short forward walk.
    pub fn lookup(&self, user_key_prefix: &[u8], ceiling: Option<u64>) -> Result<Option<SegRecord>> {
        let mut target = user_key_prefix.to_vec();
        if let Some(c) = ceiling {
            target.extend_from_slice(&(c ^ u64::MAX).to_be_bytes());
            target.push(0);
        }
        let mut cur = self.seek(&target)?;
        while let Some(rec) = cur.record()? {
            if rec.internal_key.len() != user_key_prefix.len() + 9
                || !rec.internal_key.starts_with(user_key_prefix)
            {
                return Ok(None);
            }
            // A RANGE_DELETE is not a point key of this user key even though
            // its internal key has that shape (§2.5): it is the *start* of an
            // interval, and returning it as the entry would hand a reader the
            // interval's payload as a value. It is resolved separately, by
            // §4's `rd_sources` walk.
            if rec.op() != op::RANGE_DELETE && (ceiling.is_none() || rec.seq() <= ceiling.unwrap())
            {
                return Ok(Some(rec));
            }
            cur.next()?;
        }
        Ok(None)
    }

    /// Every entry, in internal-key order. Used by compaction and by scans.
    pub fn iter(&self) -> SegmentEntries<'_> {
        SegmentEntries { cursor: SegmentCursor::new(self), started: false }
    }

    /// §2.5 — every range delete in the segment, hoisted once so a scan does
    /// not pay per row.
    pub fn range_deletes(&self) -> Result<Vec<RangeDelete>> {
        let mut out = Vec::new();
        if !self.header.has_range_deletes() {
            return Ok(out);
        }
        for rec in self.iter() {
            let rec = rec?;
            if rec.op() != op::RANGE_DELETE {
                continue;
            }
            let parsed = parse_internal_key(&rec.internal_key)?;
            out.push(RangeDelete {
                tree_id: parsed.tree_id,
                start: user_part(&rec.internal_key).to_vec(),
                end: decode_range_delete_payload(&rec.value)?,
                seq: parsed.seq,
            });
        }
        Ok(out)
    }

    /// §8's `skip(n)` in O(height), via `subtree_entries`.
    pub fn skip_to(&self, n: u64) -> Result<Option<(u64, usize)>> {
        let mut page = self.header.root_page;
        let mut remaining = n;
        loop {
            let node = self.node(page)?;
            if node.is_leaf {
                if remaining >= node.cell_count as u64 {
                    return Ok(None);
                }
                return Ok(Some((page, remaining as usize)));
            }
            let mut found = false;
            for i in 0..node.cell_count {
                let (child, entries) = node.child_at(i)?;
                if remaining < entries {
                    page = child;
                    found = true;
                    break;
                }
                remaining -= entries;
            }
            if !found {
                return Ok(None);
            }
        }
    }
}

/// §8 — the cursor. A segment has no sibling pointers, so iteration keeps a
/// path stack of `(page_id, cell_index)` from the root.
pub struct SegmentCursor<'a> {
    seg: &'a Segment,
    path: Vec<(u64, usize)>,
    valid: bool,
}

impl<'a> SegmentCursor<'a> {
    pub fn new(seg: &'a Segment) -> SegmentCursor<'a> {
        SegmentCursor { seg, path: Vec::new(), valid: false }
    }

    pub fn seek_first(&mut self) -> Result<()> {
        self.path.clear();
        self.valid = self.descend(self.seg.header.root_page, None)?;
        Ok(())
    }

    pub fn seek_last(&mut self) -> Result<()> {
        self.path.clear();
        let mut page = self.seg.header.root_page;
        loop {
            let node = self.seg.node(page)?;
            if node.cell_count == 0 {
                self.valid = false;
                return Ok(());
            }
            let i = node.cell_count - 1;
            self.path.push((page, i));
            if node.is_leaf {
                self.valid = true;
                return Ok(());
            }
            page = node.child_at(i)?.0;
        }
    }

    /// Descends to the leftmost cell at or after `target` (or the leftmost cell
    /// outright when `target` is `None`). Returns whether a cell was found.
    fn descend(&mut self, mut page: u64, target: Option<&[u8]>) -> Result<bool> {
        loop {
            let node = self.seg.node(page)?;
            if node.cell_count == 0 {
                return Ok(false);
            }
            if node.is_leaf {
                let i = match target {
                    Some(t) => node.ceiling_index(t)?,
                    None => 0,
                };
                self.path.push((page, i));
                if i < node.cell_count {
                    return Ok(true);
                }
                // Past this leaf's last cell: the answer is the next leaf.
                return self.step_forward();
            }
            let i = match target {
                Some(t) => node.floor_index(t)?.unwrap_or(0),
                None => 0,
            };
            self.path.push((page, i));
            let (child, _) = node.child_at(i)?;
            if child == page {
                return corrupt("segment descent does not make progress");
            }
            page = child;
        }
    }

    pub fn seek_ceiling(&mut self, target: &[u8]) -> Result<()> {
        self.path.clear();
        self.valid = self.descend(self.seg.header.root_page, Some(target))?;
        Ok(())
    }

    pub fn valid(&self) -> bool {
        self.valid
    }

    pub fn record(&self) -> Result<Option<SegRecord>> {
        if !self.valid {
            return Ok(None);
        }
        let &(page, idx) = self.path.last().unwrap();
        let node = self.seg.node(page)?;
        if idx >= node.cell_count {
            return Ok(None);
        }
        Ok(Some(node.record_at(idx)?))
    }

    pub fn key(&self) -> Result<Option<Vec<u8>>> {
        if !self.valid {
            return Ok(None);
        }
        let &(page, idx) = self.path.last().unwrap();
        let node = self.seg.node(page)?;
        if idx >= node.cell_count {
            return Ok(None);
        }
        Ok(Some(node.key_at(idx)?))
    }

    pub fn next(&mut self) -> Result<()> {
        if !self.valid {
            return Ok(());
        }
        let &(page, idx) = self.path.last().unwrap();
        let node = self.seg.node(page)?;
        if idx + 1 < node.cell_count {
            self.path.last_mut().unwrap().1 = idx + 1;
            return Ok(());
        }
        self.path.pop();
        self.valid = self.step_forward()?;
        Ok(())
    }

    /// Walks up until a parent has an unvisited child, then descends leftmost.
    fn step_forward(&mut self) -> Result<bool> {
        while let Some(&(page, idx)) = self.path.last() {
            let node = self.seg.node(page)?;
            if node.is_leaf {
                self.path.pop();
                continue;
            }
            if idx + 1 < node.cell_count {
                self.path.last_mut().unwrap().1 = idx + 1;
                let (child, _) = node.child_at(idx + 1)?;
                return self.descend(child, None);
            }
            self.path.pop();
        }
        Ok(false)
    }

    /// **Reverse iteration is a first-class direction** (§8), not `next`
    /// collected and reversed.
    pub fn prev(&mut self) -> Result<()> {
        if !self.valid {
            return Ok(());
        }
        let &(_, idx) = self.path.last().unwrap();
        if idx > 0 {
            self.path.last_mut().unwrap().1 = idx - 1;
            return Ok(());
        }
        self.path.pop();
        self.valid = self.step_back()?;
        Ok(())
    }

    fn step_back(&mut self) -> Result<bool> {
        while let Some(&(page, idx)) = self.path.last() {
            let node = self.seg.node(page)?;
            if node.is_leaf {
                self.path.pop();
                continue;
            }
            if idx > 0 {
                self.path.last_mut().unwrap().1 = idx - 1;
                let (child, _) = node.child_at(idx - 1)?;
                return self.descend_rightmost(child);
            }
            self.path.pop();
        }
        Ok(false)
    }

    fn descend_rightmost(&mut self, mut page: u64) -> Result<bool> {
        loop {
            let node = self.seg.node(page)?;
            if node.cell_count == 0 {
                return Ok(false);
            }
            let i = node.cell_count - 1;
            self.path.push((page, i));
            if node.is_leaf {
                return Ok(true);
            }
            page = node.child_at(i)?.0;
        }
    }
}

pub struct SegmentEntries<'a> {
    cursor: SegmentCursor<'a>,
    started: bool,
}

impl<'a> Iterator for SegmentEntries<'a> {
    type Item = Result<SegRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.started {
            self.started = true;
            if let Err(e) = self.cursor.seek_first() {
                return Some(Err(e));
            }
        } else if let Err(e) = self.cursor.next() {
            return Some(Err(e));
        }
        match self.cursor.record() {
            Ok(Some(r)) => Some(Ok(r)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
