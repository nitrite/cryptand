//! `09-vector.md` — the vector index.
//!
//! The design principle is why this file is short: **specify the durable
//! layout, not the algorithm.** A proximity graph is a flat vector region plus
//! an adjacency list per node. How an implementation searches or builds that
//! graph is its own business — §8: "Recall is not specified."

use crate::cke;
use crate::container::{page_flags, page_type, u16le, u32le, u64le, PageHeader, PAGE_HEADER_BYTES};
use crate::cve;
use crate::error::{corrupt, invalid, Result};
use crate::pager::Pager;
use crate::value::{NumType, Value};
use crate::varint::{get_ivar, put_ivar};

pub const VECTOR_MAGIC: [u8; 8] = [0x43, 0x52, 0x59, 0x5F, 0x56, 0x45, 0x43, 0x1A];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DType {
    F32 = 0,
    F16 = 1,
    I8 = 2,
    /// PQ codes.
    U8 = 3,
}

impl DType {
    pub fn from_code(c: u8) -> Result<DType> {
        Ok(match c {
            0 => DType::F32,
            1 => DType::F16,
            2 => DType::I8,
            3 => DType::U8,
            _ => return corrupt(format!("vector dtype {c} is not 0..3")),
        })
    }
    pub fn size(self) -> usize {
        match self {
            DType::F32 => 4,
            DType::F16 => 2,
            DType::I8 | DType::U8 => 1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Metric {
    Cosine,
    L2,
    Dot,
}

impl Metric {
    pub fn parse(s: &str) -> Result<Metric> {
        Ok(match s {
            "cosine" => Metric::Cosine,
            "l2" => Metric::L2,
            "dot" => Metric::Dot,
            _ => return invalid(format!("metric \"{s}\" is not cosine, l2 or dot")),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Metric::Cosine => "cosine",
            Metric::L2 => "l2",
            Metric::Dot => "dot",
        }
    }
}

/// §2's region header, immediately after the head page's 40-byte page header.
#[derive(Clone, Debug)]
pub struct RegionHeader {
    pub dim: u32,
    pub dtype: DType,
    /// May exceed the natural vector size so slots land on 64-byte boundaries
    /// for SIMD; padding bytes are zero.
    pub stride: u16,
    pub slot_count: u64,
    pub live_count: u64,
    /// Page-aligned, so an implementation that can `mmap` maps the region once
    /// and reads vectors as slices with no copy.
    pub data_offset: u64,
    pub next_region: u64,
}

impl RegionHeader {
    /// `00-conventions.md` §8: `stride` is a u16, so `dim * sizeof(dtype)`
    /// MUST be <= 65535.
    pub fn natural_stride(dim: u32, dtype: DType) -> Result<u16> {
        let n = dim as usize * dtype.size();
        if n > 65535 {
            return invalid(format!(
                "dim {dim} at {} bytes per component needs {n} bytes per slot, above the u16 \
                 stride limit; split the vector across two indexes rather than widening the field",
                dtype.size()
            ));
        }
        Ok(n as u16)
    }

    pub fn encode(&self, page_size: usize, extent_pages: u32) -> Vec<u8> {
        let mut page = vec![0u8; page_size];
        let b = PAGE_HEADER_BYTES;
        page[b..b + 8].copy_from_slice(&VECTOR_MAGIC);
        page[b + 8..b + 12].copy_from_slice(&self.dim.to_le_bytes());
        page[b + 12] = self.dtype as u8;
        page[b + 14..b + 16].copy_from_slice(&self.stride.to_le_bytes());
        page[b + 16..b + 24].copy_from_slice(&self.slot_count.to_le_bytes());
        page[b + 24..b + 32].copy_from_slice(&self.live_count.to_le_bytes());
        page[b + 32..b + 40].copy_from_slice(&self.data_offset.to_le_bytes());
        page[b + 40..b + 48].copy_from_slice(&self.next_region.to_le_bytes());
        PageHeader {
            page_type: page_type::VECTOR_REGION,
            flags: page_flags::EXTENT_HEAD,
            tree_id: crate::container::NO_TREE,
            extent_pages,
            payload_len: 64,
            ..Default::default()
        }
        .write_into(&mut page);
        page
    }

    pub fn parse(page: &[u8]) -> Result<RegionHeader> {
        let b = PAGE_HEADER_BYTES;
        if page.len() < b + 64 {
            return corrupt("vector region head page too small");
        }
        if page[b..b + 8] != VECTOR_MAGIC {
            return corrupt("vector region magic mismatch");
        }
        Ok(RegionHeader {
            dim: u32le(page, b + 8),
            dtype: DType::from_code(page[b + 12])?,
            stride: u16le(page, b + 14),
            slot_count: u64le(page, b + 16),
            live_count: u64le(page, b + 24),
            data_offset: u64le(page, b + 32),
            next_region: u64le(page, b + 40),
        })
    }
}

/// A flat vector region: one contiguous, page-aligned extent.
///
/// **An implementation that cannot `mmap` reads positionally.** The layout is
/// identical; only the access method differs. No part of this format requires
/// mmap.
pub struct Region {
    pub start_page: u64,
    pub pages: u32,
    pub header: RegionHeader,
    /// The head page's `flags.ENCRYPTED`: how this region's data is chunked
    /// (14 §5.4), whatever the file's `cipher` says now (F-073).
    pub encrypted: bool,
}

impl Region {
    /// Slot 0 of the first region is reserved and never used, so `slot_id = 0`
    /// is a null pointer.
    pub const NULL_SLOT: u64 = 0;

    pub fn create(pager: &mut Pager, dim: u32, dtype: DType, slots: u64) -> Result<Region> {
        let stride = RegionHeader::natural_stride(dim, dtype)?;
        let page_size = pager.page_size as u64;
        // `data_offset` is page-aligned, which is the property that makes a
        // zero-copy mmap possible at all.
        let data_offset = page_size;
        // `14-security.md` §5.4 — an encrypted region's data area is chunked,
        // so it needs more pages than `ceil(len / page_size)`.
        let encrypted = pager.seals();
        let pages = (1 + (slots * stride as u64).div_ceil(pager.chunk_bytes(encrypted) as u64)) as u32;
        let start = pager.alloc_extent(pages)?;
        let header = RegionHeader {
            dim,
            dtype,
            stride,
            slot_count: slots,
            live_count: 0,
            data_offset,
            next_region: 0,
        };
        let page = header.encode(pager.page_size, pages);
        pager.write_page(start, &page)?;
        Ok(Region { start_page: start, pages, header, encrypted })
    }

    pub fn open(pager: &mut Pager, start_page: u64) -> Result<Region> {
        let (h, raw) = pager.read_verified(start_page)?;
        let header = RegionHeader::parse(&raw)?;
        // The flag as stored: the page read_verified returns is decrypted and
        // no longer carries it (F-075).
        let encrypted = PageHeader::parse(&pager.read_page_clear(start_page)?)?.encrypted();
        Ok(Region { start_page, pages: h.extent_pages.max(1), header, encrypted })
    }

    /// F-072 g, 14 §8.3: a copy of this region laid out for the file's current
    /// mode (sealed or clear), same header and stride. The caller frees this
    /// extent and repoints the descriptor. A chunk never written (all zero, or
    /// past the end of the file) stays unwritten.
    pub fn relocate(&self, pager: &mut Pager) -> Result<Region> {
        let encrypted = pager.seals();
        let len = self.header.slot_count * self.header.stride as u64;
        let pages = (1 + len.div_ceil(pager.chunk_bytes(encrypted) as u64)) as u32;
        let start = pager.alloc_extent(pages)?;
        pager.write_page(start, &self.header.encode(pager.page_size, pages))?;
        let out = Region { start_page: start, pages, header: self.header.clone(), encrypted };
        let ps = pager.page_size as u64;
        let step = pager.chunk_bytes(self.encrypted) as u64;
        let base = self.start_page * ps + self.header.data_offset;
        let mut off = 0u64;
        for idx in 0..len.div_ceil(step) {
            let take = step.min(len - off) as usize;
            if let Ok(raw) = pager.read_at(base + idx * ps, ps as usize) {
                if raw.iter().any(|&b| b != 0) {
                    let data = if self.encrypted {
                        let Some(c) = &pager.crypto else { return Err(crate::error::Error::CannotUnlock) };
                        let counter = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                        c.ring.decrypt_chunk(self.start_page, counter, idx, &raw[8..])?
                    } else {
                        raw
                    };
                    pager.write_extent_data(start, out.header.data_offset, off, &data[..take], encrypted)?;
                }
            }
            off += take as u64;
        }
        Ok(out)
    }

    pub fn write_slot(&mut self, pager: &mut Pager, slot: u64, v: &[f32]) -> Result<()> {
        if slot == Region::NULL_SLOT {
            return invalid("slot 0 is reserved so that slot_id 0 is a null pointer");
        }
        if slot >= self.header.slot_count {
            return invalid(format!("slot {slot} is past the region's {} slots", self.header.slot_count));
        }
        if v.len() != self.header.dim as usize {
            return invalid(format!("vector of {} components, region dim is {}", v.len(), self.header.dim));
        }
        let mut buf = vec![0u8; self.header.stride as usize]; // padding bytes are zero
        match self.header.dtype {
            DType::F32 => {
                for (i, x) in v.iter().enumerate() {
                    buf[i * 4..i * 4 + 4].copy_from_slice(&x.to_le_bytes());
                }
            }
            _ => return invalid("this build writes f32 regions only"),
        }
        pager.write_extent_data(
            self.start_page,
            self.header.data_offset,
            slot * self.header.stride as u64,
            &buf,
            self.encrypted,
        )
    }

    pub fn read_slot(&self, pager: &mut Pager, slot: u64) -> Result<Vec<f32>> {
        if slot >= self.header.slot_count {
            return corrupt(format!("slot {slot} is past the region's {} slots", self.header.slot_count));
        }
        let raw = pager.read_extent_data(
            self.start_page,
            self.header.data_offset,
            slot * self.header.stride as u64,
            self.header.stride as usize,
            self.encrypted,
        )?;
        let d = self.header.dim as usize;
        Ok(match self.header.dtype {
            DType::F32 => (0..d)
                .map(|i| f32::from_le_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()))
                .collect(),
            DType::F16 => (0..d).map(|i| f16_to_f32(u16le(&raw, i * 2))).collect(),
            DType::I8 => {
                let scale = f32::from_le_bytes(raw[d..d + 4].try_into().unwrap());
                let zero = f32::from_le_bytes(raw[d + 4..d + 8].try_into().unwrap());
                (0..d).map(|i| (raw[i] as i8 as f32) * scale + zero).collect()
            }
            DType::U8 => (0..d).map(|i| raw[i] as f32).collect(),
        })
    }
}

fn f16_to_f32(h: u16) -> f32 {
    let sign = ((h >> 15) & 1) as u32;
    let exp = ((h >> 10) & 0x1F) as u32;
    let frac = (h & 0x3FF) as u32;
    let bits = if exp == 0 {
        if frac == 0 {
            sign << 31
        } else {
            let mut e = -1i32;
            let mut f = frac;
            while f & 0x400 == 0 {
                f <<= 1;
                e -= 1;
            }
            (sign << 31) | (((127 - 15 + e + 1) as u32) << 23) | ((f & 0x3FF) << 13)
        }
    } else if exp == 0x1F {
        (sign << 31) | 0x7F80_0000 | (frac << 13)
    } else {
        (sign << 31) | ((exp + 127 - 15) << 23) | (frac << 13)
    };
    f32::from_bits(bits)
}

/// §3 — the adjacency record, a raw byte layout wrapped in a CVE `BYTES` value
/// for the same reason postings are: every INLINE cell in the format holds a
/// CVE value, with no exceptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adjacency {
    pub neighbours: Vec<u64>,
}

impl Adjacency {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.neighbours.len() as u16).to_le_bytes());
        // Deltas are zigzag because neighbour ids are not sorted in graph
        // order: a proximity graph's neighbour list is ordered by distance.
        let mut prev = 0i64;
        for (i, &n) in self.neighbours.iter().enumerate() {
            let v = n as i64;
            put_ivar(&mut b, if i == 0 { v } else { v - prev });
            prev = v;
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<Adjacency> {
        if b.len() < 2 {
            return corrupt("adjacency record shorter than its degree");
        }
        let degree = u16le(b, 0) as usize;
        let mut at = 2usize;
        let mut out = Vec::with_capacity(degree);
        let mut prev = 0i64;
        for i in 0..degree {
            let (d, n) = get_ivar(&b[at..])?;
            at += n;
            let v = if i == 0 { d } else { prev + d };
            prev = v;
            out.push(v as u64);
        }
        Ok(Adjacency { neighbours: out })
    }

    pub fn encode_value(&self) -> Vec<u8> {
        cve::encode(&Value::Bytes(self.encode()))
    }

    pub fn decode_value(v: &[u8]) -> Result<Adjacency> {
        match cve::decode_all(v, &|_| None)? {
            Value::Bytes(b) => Adjacency::decode(&b),
            _ => corrupt("an adjacency value is a CVE BYTES"),
        }
    }
}

/// §3 — `CKE(Array[U8 level, U64 slot_id])`. Keying this way puts a layer's
/// adjacency contiguously and makes a layer scan sequential.
pub fn adjacency_key(level: u8, slot_id: u64) -> Vec<u8> {
    cke::encode(&Value::Array(vec![
        Value::Int { w: NumType::U8, neg: false, mag: level as u128 },
        Value::Int { w: NumType::U64, neg: false, mag: slot_id as u128 },
    ]))
    .expect("U8 and U64 are CKE-encodable")
}

/// §6 — the two slot/document maps, both `kind = "kv"`.
pub fn slot_to_doc_key(slot: u64) -> Vec<u8> {
    cke::encode(&Value::Int { w: NumType::U64, neg: false, mag: slot as u128 })
        .expect("U64 is CKE-encodable")
}

pub fn doc_to_slot_key(id: i64) -> Vec<u8> {
    cke::encode(&Value::NitriteId(id)).expect("NITRITE_ID is CKE-encodable")
}

/// §4 — the quantization codebook, stored as a blob.
#[derive(Clone, Debug)]
pub struct Codebook {
    pub kind: u8,
    pub m: u16,
    pub k: u16,
    pub sub_dim: u16,
    pub centroids: Vec<f32>,
}

impl Codebook {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(1u8); // version
        b.push(self.kind);
        b.extend_from_slice(&self.m.to_le_bytes());
        b.extend_from_slice(&self.k.to_le_bytes());
        b.extend_from_slice(&self.sub_dim.to_le_bytes());
        for c in &self.centroids {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<Codebook> {
        if b.len() < 8 {
            return corrupt("codebook shorter than its header");
        }
        if b[0] != 1 {
            return corrupt("codebook version is not 1");
        }
        let m = u16le(b, 2);
        let k = u16le(b, 4);
        let sub_dim = u16le(b, 6);
        let want = m as usize * k as usize * sub_dim as usize;
        if b.len() < 8 + want * 4 {
            return corrupt("codebook centroids truncated");
        }
        let centroids = (0..want)
            .map(|i| f32::from_le_bytes(b[8 + i * 4..12 + i * 4].try_into().unwrap()))
            .collect();
        Ok(Codebook { kind: b[1], m, k, sub_dim, centroids })
    }

    /// §4 — `dim = m * sub_dim` MUST hold.
    pub fn check_dim(&self, dim: u32) -> Result<()> {
        if self.m as u32 * self.sub_dim as u32 != dim {
            return corrupt(format!(
                "codebook m {} x sub_dim {} != dim {dim}",
                self.m, self.sub_dim
            ));
        }
        Ok(())
    }
}

/// §8.1 — the three metrics, as **distances**: smaller is nearer.
///
/// `dot` is negated because a dot product is a similarity; `cosine` is
/// `1 - similarity`, not the similarity; `l2` is the Euclidean distance and not
/// its square. §8 requires the *true* distance to be returned, so the square is
/// not an option even though it orders identically.
///
/// **Accumulation is in `f64`** whatever the region's `dtype`. Summing 1024
/// `f32` products in `f32` — which this did — drifts by roughly 1e-4 against the
/// same sum in `f64`, so this implementation returned different distances from
/// Dart and Java for the same pair of vectors and ordered near-ties
/// differently. The stored vectors keep their `dtype`; only the arithmetic
/// widens.
pub fn distance(metric: Metric, a: &[f32], b: &[f32]) -> f32 {
    distance_f64(metric, a, b) as f32
}

/// The same, without the narrowing on the way out — the form a search should
/// use for ordering, so that two candidates differing below `f32` resolution
/// still compare in a defined direction.
pub fn distance_f64(metric: Metric, a: &[f32], b: &[f32]) -> f64 {
    match metric {
        Metric::L2 => a
            .iter()
            .zip(b)
            .map(|(x, y)| {
                let d = *x as f64 - *y as f64;
                d * d
            })
            .sum::<f64>()
            .sqrt(),
        Metric::Dot => -a.iter().zip(b).map(|(x, y)| *x as f64 * *y as f64).sum::<f64>(),
        Metric::Cosine => {
            let dot: f64 = a.iter().zip(b).map(|(x, y)| *x as f64 * *y as f64).sum();
            let na: f64 = a.iter().map(|x| *x as f64 * *x as f64).sum::<f64>().sqrt();
            let nb: f64 = b.iter().map(|x| *x as f64 * *x as f64).sum::<f64>().sqrt();
            // §8.1: a zero vector has no direction, so this is the orthogonal
            // value rather than a division by zero. A NaN here propagates into
            // a neighbour list and corrupts the ordering silently.
            if na == 0.0 || nb == 0.0 {
                1.0
            } else {
                1.0 - dot / (na * nb)
            }
        }
    }
}

/// §8 — **the brute-force fallback is a MUST**. An implementation may refuse to
/// serve a graph built by a different algorithm, but it MUST then fall back to
/// a scan of the flat region, which is always possible and always correct,
/// rather than returning nothing. That is what lets a Flutter app open a
/// database whose vector index only a Rust service maintains.
pub fn brute_force(
    pager: &mut Pager,
    region: &Region,
    live: &dyn Fn(u64) -> Option<i64>,
    query: &[f32],
    metric: Metric,
    k: usize,
) -> Result<Vec<(i64, f32)>> {
    let mut out: Vec<(i64, f32)> = Vec::new();
    for slot in 1..region.header.slot_count {
        // A search MUST skip a slot with no document mapping — this is what
        // makes deletes correct immediately even though the graph is repaired
        // later (the FreshDiskANN property).
        let Some(id) = live(slot) else { continue };
        let v = region.read_slot(pager, slot)?;
        out.push((id, distance(metric, query, &v)));
    }
    out.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    out.truncate(k);
    Ok(out)
}

/// Copied adjacency nodes held before an early write-back (F-196, as Java).
pub static ADJACENCY_DIRTY_BUDGET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(2048);

struct AdjNode {
    leaf: bool,
    /// Leaf: keys. Internal: separators, each the first key under its child.
    key: Vec<Vec<u8>>,
    /// Leaf: the CVE values.
    val: Vec<Vec<u8>>,
    child: Vec<u64>,
    cnt: Vec<u64>,
    nonce: Vec<u64>,
    kid: Vec<Option<Box<AdjNode>>>,
}

impl AdjNode {
    fn new(leaf: bool) -> AdjNode {
        AdjNode { leaf, key: vec![], val: vec![], child: vec![], cnt: vec![], nonce: vec![], kid: vec![] }
    }
    fn total(&self) -> u64 {
        if self.leaf {
            self.key.len() as u64
        } else {
            self.cnt.iter().sum()
        }
    }
    fn insert_child(&mut self, at: usize, sep: Vec<u8>, n: Box<AdjNode>) {
        self.key.insert(at, sep);
        self.cnt.insert(at, n.total());
        self.child.insert(at, 0);
        self.nonce.insert(at, 0);
        self.kid.insert(at, Some(n));
    }
    /// Leaf: the last key <= k (None if none). Internal: the child to descend.
    fn find(&self, k: &[u8]) -> Option<usize> {
        let at = self.key.partition_point(|x| x.as_slice() <= k);
        if self.leaf {
            at.checked_sub(1)
        } else {
            Some(at.saturating_sub(1))
        }
    }
}

/// A vector index's adjacency tree (§3) as a copy-on-write B+tree that copies
/// only the paths a write touches — F-196, as Java's `AdjacencyTree`.
///
/// The pages are 04 §2.2 copy-on-write pages, the bytes [`crate::cow::CowTree`]
/// writes, so a reader cannot tell the two apart. `CowTree` writes a path per
/// put; a graph insert touches ~m records, so this one keeps copied nodes in
/// memory, writes them back at commit or past [`ADJACENCY_DIRTY_BUDGET`], and
/// frees each old page when it is copied (reusable after the next commit).
/// ponytail: put and a whole-tree clear only; §6 keeps a deleted slot's
/// record, so nothing removes one key.
pub struct AdjacencyTree {
    pub tree_id: u32,
    root: Option<Box<AdjNode>>,
    root_page: u64,
    root_nonce: u64,
    size: u64,
    dirty: usize,
    rewrite_all: bool,
}

struct AdjIo<'a> {
    pager: &'a mut Pager,
    tree_id: u32,
    commit_id: u64,
    dirty: usize,
}

impl AdjIo<'_> {
    fn read(&mut self, page: u64, nonce: u64) -> Result<AdjNode> {
        let (_h, raw) = self.pager.read_bound(page, nonce)?;
        let c = crate::cow::CowNode::decode(&raw, page)?;
        let mut n = AdjNode::new(c.is_leaf);
        for (k, p) in c.keys.into_iter().zip(c.payloads) {
            if n.leaf {
                n.val.push(crate::cow::value_of(&p)?);
            } else {
                let (child, cnt, nonce) = crate::cow::child_of(&p)?;
                n.child.push(child);
                n.cnt.push(cnt);
                n.nonce.push(nonce);
                n.kid.push(None);
            }
            n.key.push(k);
        }
        Ok(n)
    }
    fn free(&mut self, page: u64) {
        self.pager.free_extent(page, 1, self.commit_id + 1);
    }
    fn child<'n>(&mut self, node: &'n mut AdjNode, i: usize) -> Result<&'n mut AdjNode> {
        if node.kid[i].is_none() {
            let n = self.read(node.child[i], node.nonce[i])?;
            self.free(node.child[i]);
            node.child[i] = 0;
            node.kid[i] = Some(Box::new(n));
            self.dirty += 1;
        }
        Ok(node.kid[i].as_mut().unwrap())
    }
    fn encode(&self, n: &AdjNode) -> Result<Vec<u8>> {
        let payloads: Vec<Vec<u8>> = if n.leaf {
            n.val.iter().map(|v| crate::cow::leaf_payload(v)).collect()
        } else {
            (0..n.key.len()).map(|i| crate::cow::child_payload(n.child[i], n.cnt[i], n.nonce[i])).collect()
        };
        crate::segment::encode_node_page(
            self.pager.page_size,
            self.pager.payload_cap(),
            n.leaf,
            &n.key,
            &payloads,
            n.total(),
            self.tree_id,
            self.commit_id,
        )
    }
    fn write_page(&mut self, n: &AdjNode) -> Result<(u64, u64)> {
        let page = self.encode(n)?;
        let id = self.pager.alloc_extent(1)?;
        self.pager.write_page(id, &page)?;
        Ok((id, self.pager.written_nonce))
    }
    fn write(&mut self, n: &mut AdjNode) -> Result<(u64, u64)> {
        for i in 0..n.kid.len() {
            if let Some(mut k) = n.kid[i].take() {
                (n.child[i], n.nonce[i]) = self.write(&mut k)?;
            }
        }
        self.write_page(n)
    }
    fn rewrite(&mut self, page: u64, nonce: u64, depth: usize) -> Result<(u64, u64)> {
        if depth > 64 {
            return corrupt("adjacency tree is deeper than 64 levels");
        }
        let mut n = self.read(page, nonce)?;
        self.free(page);
        for i in 0..n.child.len() {
            (n.child[i], n.nonce[i]) = self.rewrite(n.child[i], n.nonce[i], depth + 1)?;
        }
        self.write_page(&n)
    }
    fn free_under(&mut self, n: &AdjNode, depth: usize) -> Result<()> {
        if depth > 64 {
            return corrupt("adjacency tree is deeper than 64 levels");
        }
        for i in 0..n.child.len() {
            match &n.kid[i] {
                Some(k) => self.free_under(k, depth + 1)?,
                None => {
                    let c = self.read(n.child[i], n.nonce[i])?;
                    self.free(n.child[i]);
                    self.free_under(&c, depth + 1)?;
                }
            }
        }
        Ok(())
    }
}

impl AdjacencyTree {
    pub fn load(pager: &mut Pager, tree_id: u32, root: u64, root_nonce: u64) -> Result<AdjacencyTree> {
        let mut t = AdjacencyTree { tree_id, root: None, root_page: root, root_nonce, size: 0, dirty: 0, rewrite_all: false };
        if root != 0 {
            t.size = t.io(pager, 0).read(root, root_nonce)?.total();
        }
        Ok(t)
    }

    fn io<'a>(&self, pager: &'a mut Pager, commit_id: u64) -> AdjIo<'a> {
        AdjIo { pager, tree_id: self.tree_id, commit_id, dirty: self.dirty }
    }

    pub fn root(&self) -> (u64, u64) {
        (self.root_page, self.root_nonce)
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn mark_dirty(&mut self) {
        self.rewrite_all = true;
    }

    pub fn get(&self, pager: &mut Pager, k: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut io = self.io(pager, 0);
        let mut owned: AdjNode;
        let mut node: &AdjNode = match &self.root {
            Some(r) => r,
            None if self.root_page != 0 => {
                owned = io.read(self.root_page, self.root_nonce)?;
                &owned
            }
            None => return Ok(None),
        };
        for _ in 0..=64 {
            let Some(i) = node.find(k) else { return Ok(None) };
            if node.leaf {
                return Ok((node.key[i] == k).then(|| node.val[i].clone()));
            }
            if let Some(kid) = &node.kid[i] {
                node = kid;
            } else {
                owned = io.read(node.child[i], node.nonce[i])?;
                node = &owned;
            }
        }
        corrupt(format!("adjacency tree {} is deeper than 64 levels", self.tree_id))
    }

    pub fn put(&mut self, pager: &mut Pager, commit_id: u64, k: &[u8], v: &[u8]) -> Result<()> {
        let mut io = self.io(pager, commit_id);
        let mut r = match self.root.take() {
            Some(r) => r,
            None if self.root_page != 0 => {
                let n = io.read(self.root_page, self.root_nonce)?;
                io.free(self.root_page);
                self.root_page = 0;
                io.dirty += 1;
                Box::new(n)
            }
            None => {
                io.dirty += 1;
                Box::new(AdjNode::new(true))
            }
        };
        let mut grew = false;
        let split = Self::put_at(&mut io, &mut r, k, v, &mut grew);
        let split = match split {
            Ok(s) => s,
            Err(e) => {
                self.root = Some(r);
                self.dirty = io.dirty;
                return Err(e);
            }
        };
        if let Some(s) = split {
            let mut up = AdjNode::new(false);
            let (k0, k1) = (r.key[0].clone(), s.key[0].clone());
            up.insert_child(0, k0, r);
            up.insert_child(1, k1, s);
            r = Box::new(up);
            io.dirty += 1;
        }
        if grew {
            self.size += 1;
        }
        self.root = Some(r);
        self.dirty = io.dirty;
        if self.dirty > ADJACENCY_DIRTY_BUDGET.load(std::sync::atomic::Ordering::Relaxed) {
            self.write_out(pager, commit_id)?;
        }
        Ok(())
    }

    fn put_at(io: &mut AdjIo, n: &mut AdjNode, k: &[u8], v: &[u8], grew: &mut bool) -> Result<Option<Box<AdjNode>>> {
        if n.leaf {
            match n.find(k) {
                Some(i) if n.key[i] == k => n.val[i] = v.to_vec(),
                f => {
                    let at = f.map_or(0, |i| i + 1);
                    n.key.insert(at, k.to_vec());
                    n.val.insert(at, v.to_vec());
                    *grew = true;
                }
            }
        } else {
            let i = n.find(k).unwrap_or(0);
            let c = io.child(n, i)?;
            let s = Self::put_at(io, c, k, v, grew)?;
            let (k0, t) = (c.key[0].clone(), c.total());
            n.key[i] = k0;
            n.cnt[i] = t;
            if let Some(s) = s {
                let sep = s.key[0].clone();
                n.insert_child(i + 1, sep, s);
            }
        }
        if io.encode(n).is_ok() {
            return Ok(None);
        }
        if n.key.len() < 2 {
            return Err(crate::error::Error::Invalid(format!(
                "adjacency tree {}: one record does not fit a {}-byte page",
                io.tree_id, io.pager.page_size
            )));
        }
        let at = n.key.len() / 2;
        let mut right = AdjNode::new(n.leaf);
        right.key = n.key.split_off(at);
        if n.leaf {
            right.val = n.val.split_off(at);
        } else {
            right.child = n.child.split_off(at);
            right.cnt = n.cnt.split_off(at);
            right.nonce = n.nonce.split_off(at);
            right.kid = n.kid.split_off(at);
        }
        io.dirty += 1;
        Ok(Some(Box::new(right)))
    }

    /// Frees every page: the tree is empty after the next commit.
    pub fn clear(&mut self, pager: &mut Pager, commit_id: u64) -> Result<()> {
        let mut io = self.io(pager, commit_id);
        if let Some(r) = self.root.take() {
            io.free_under(&r, 0)?;
        } else if self.root_page != 0 {
            let r = io.read(self.root_page, self.root_nonce)?;
            io.free(self.root_page);
            io.free_under(&r, 0)?;
        }
        (self.root_page, self.root_nonce, self.size, self.dirty) = (0, 0, 0, 0);
        Ok(())
    }

    fn write_out(&mut self, pager: &mut Pager, commit_id: u64) -> Result<()> {
        if let Some(mut r) = self.root.take() {
            (self.root_page, self.root_nonce) = self.io(pager, commit_id).write(&mut r)?;
        }
        self.dirty = 0;
        Ok(())
    }

    /// Writes the copied nodes back; returns the root page and nonce.
    pub fn commit(&mut self, pager: &mut Pager, commit_id: u64) -> Result<(u64, u64)> {
        self.write_out(pager, commit_id)?;
        if self.rewrite_all {
            self.rewrite_all = false;
            if self.root_page != 0 {
                (self.root_page, self.root_nonce) = self.io(pager, commit_id).rewrite(self.root_page, self.root_nonce, 0)?;
            }
        }
        if self.root_page == 0 {
            self.root_nonce = 0;
        }
        Ok(self.root())
    }
}

/// A beam entry, ordered by distance (total order: `dot` distances are negative).
#[derive(Clone, Copy)]
struct Scored(f64, u64);
impl PartialEq for Scored {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == std::cmp::Ordering::Equal
    }
}
impl Eq for Scored {}
impl PartialOrd for Scored {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Scored {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&o.0).then(self.1.cmp(&o.1))
    }
}

/// A vector index, `09-vector.md` — F-196, as Java's `VectorIndex`.
///
/// A Vamana graph built as documents arrive: a put runs a beam search
/// (`ef_construction` wide) from the entry point, keeps the robust-pruned
/// ([`ALPHA`]) nearest `m` as the new slot's neighbours and adds the reverse
/// edges, pruning a list that overflows. A search is the same beam,
/// [`EF_SEARCH`] wide, re-ranked by true distance; a filtered search, and an
/// index small enough that the beam would visit it all, use §8's brute force.
/// Vectors live in the region, adjacency in an [`AdjacencyTree`], both on
/// pages; the slot maps are KV trees, cached here as plain arrays.
/// ponytail: deleted slots stay in the graph and are walked through (§6);
/// consolidation (§7) is not implemented, so a delete-heavy index degrades
/// toward the brute-force fallback.
pub struct VectorIndex {
    pub name: String,
    pub owner: String,
    pub field: String,
    pub dim: u32,
    pub metric: Metric,
    slot_to_doc: u32,
    doc_to_slot: u32,
    descriptor: crate::catalog::TreeDescriptor,
    region: Region,
    adjacency: AdjacencyTree,
    slot_doc: Vec<i64>,
    live: Vec<bool>,
    live_count: u64,
    doc_slot: std::collections::HashMap<i64, u64>,
    next_slot: u64,
    entry: u64,
    m: usize,
    ef_construction: usize,
    region_dirty: bool,
    /// Unfiltered searches the beam could not answer (a broken graph hides behind the scan).
    pub fallbacks: u64,
}

/// Robust-prune slack: a candidate is dropped if a kept neighbour is ALPHA times nearer to it.
pub const ALPHA: f64 = 1.2;
/// Beam width of an unfiltered search (at least k).
pub const EF_SEARCH: usize = 100;

fn u64v(v: u64) -> Value {
    Value::int(NumType::U64, v as i128)
}

impl VectorIndex {
    pub fn open(e: &mut crate::engine::Engine, name: &str, d: crate::catalog::TreeDescriptor) -> Result<VectorIndex> {
        let shape = |what: &str| -> Result<VectorIndex> { corrupt(format!("vector index '{name}' has no valid params.{what}")) };
        let Some(field) = d.param_str("field").map(str::to_string) else { return shape("field") };
        let Some(dim) = d.param_u64("dim") else { return shape("dim") };
        let Some(metric) = d.param_str("metric").and_then(|m| Metric::parse(m).ok()) else { return shape("metric") };
        let (Some(s2d), Some(d2s)) = (d.param_u64("slot_to_doc"), d.param_u64("doc_to_slot")) else {
            return shape("slot_to_doc");
        };
        let Some(region_at) = d.param_u64("vector_region") else { return shape("vector_region") };
        let region = Region::open(&mut e.pager, region_at)?;
        let adjacency = AdjacencyTree::load(&mut e.pager, d.tree_id(), d.root().unwrap_or(0), d.root_nonce())?;
        let entry = match d.param("entry_points") {
            Some(Value::Array(a)) => match a.first() {
                Some(Value::Int { mag, .. }) => *mag as u64,
                _ => 0,
            },
            _ => 0,
        };
        let mut ix = VectorIndex {
            name: name.to_string(),
            owner: d.owner().unwrap_or("").to_string(),
            field,
            dim: dim as u32,
            metric,
            slot_to_doc: s2d as u32,
            doc_to_slot: d2s as u32,
            m: d.param_u64("m").unwrap_or(32) as usize,
            ef_construction: d.param_u64("ef_construction").unwrap_or(200) as usize,
            descriptor: d,
            region,
            adjacency,
            slot_doc: Vec::new(),
            live: Vec::new(),
            live_count: 0,
            doc_slot: std::collections::HashMap::new(),
            next_slot: 1,
            entry,
            region_dirty: false,
            fallbacks: 0,
        };
        let mut c = e.scan_cursor(ix.slot_to_doc, None, None, None, true)?;
        while let Some((k, v)) = c.next(e)? {
            let slot = match cke::decode_all(&k)? {
                Value::Int { mag, .. } => mag as u64,
                _ => return corrupt(format!("vector index '{name}': a slot_to_doc key is not an integer")),
            };
            let Value::NitriteId(doc) = cve::decode_all(&v, &|_| None)? else {
                return corrupt(format!("vector index '{name}': a slot_to_doc value is not a NITRITE_ID"));
            };
            if slot == 0 || slot >= ix.region.header.slot_count {
                return corrupt(format!("vector index '{name}': slot {slot} is outside the region"));
            }
            ix.map(slot, doc);
            ix.next_slot = ix.next_slot.max(slot + 1);
        }
        Ok(ix)
    }

    pub fn tree_id(&self) -> u32 {
        self.descriptor.tree_id()
    }

    pub fn len(&self) -> u64 {
        self.live_count
    }

    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }

    fn map(&mut self, slot: u64, doc: i64) {
        let s = slot as usize;
        if s >= self.slot_doc.len() {
            let n = (s + 1).max(self.slot_doc.len() * 2);
            self.slot_doc.resize(n, 0);
            self.live.resize(n, false);
        }
        self.slot_doc[s] = doc;
        if !self.live[s] {
            self.live[s] = true;
            self.live_count += 1;
        }
        self.doc_slot.insert(doc, slot);
    }

    fn is_live(&self, slot: u64) -> bool {
        self.live.get(slot as usize).copied().unwrap_or(false)
    }

    fn vector_of(&self, doc: &Value) -> Option<Vec<f32>> {
        let path = crate::index::parse_field_path(&self.field);
        crate::index::resolve(doc, &path)?.into_iter().find_map(|v| match v {
            Value::VectorF32(x) => Some(x),
            _ => None,
        })
    }

    /// Indexes `doc`'s vector field, replacing any slot it already owns.
    pub fn put(&mut self, e: &mut crate::engine::Engine, id: i64, doc: &Value) -> Result<()> {
        let Some(v) = self.vector_of(doc) else { return self.remove(e, id) };
        if v.len() != self.dim as usize {
            return invalid(format!("vector has {} dimensions, index {} declares {}", v.len(), self.name, self.dim));
        }
        let slot = match self.doc_slot.get(&id) {
            Some(&s) => s,
            None => {
                let s = self.next_slot;
                self.next_slot += 1;
                self.grow_to(e, s)?;
                s
            }
        };
        self.region.write_slot(&mut e.pager, slot, &v)?;
        self.map(slot, id);
        self.link(e, slot, v)?;
        e.put(self.slot_to_doc, &u64v(slot), &cve::encode(&Value::NitriteId(id)))?;
        e.put(self.doc_to_slot, &Value::NitriteId(id), &cve::encode(&u64v(slot)))?;
        Ok(())
    }

    /// §6: both mappings go; the slot stays in the graph and a search skips
    /// it, which is what makes a delete correct immediately.
    pub fn remove(&mut self, e: &mut crate::engine::Engine, id: i64) -> Result<()> {
        let Some(slot) = self.doc_slot.remove(&id) else { return Ok(()) };
        if self.is_live(slot) {
            self.live[slot as usize] = false;
            self.live_count -= 1;
        }
        e.remove(self.slot_to_doc, &u64v(slot))?;
        e.remove(self.doc_to_slot, &Value::NitriteId(id))?;
        Ok(())
    }

    fn grow_to(&mut self, e: &mut crate::engine::Engine, slot: u64) -> Result<()> {
        if slot < self.region.header.slot_count {
            return Ok(());
        }
        let want = (slot + 1).max(self.region.header.slot_count * 2);
        let bigger = Region::create(&mut e.pager, self.dim, self.region.header.dtype, want)?;
        let mut bigger = bigger;
        for s in 1..self.live.len() as u64 {
            if self.is_live(s) {
                let v = self.region.read_slot(&mut e.pager, s)?;
                bigger.write_slot(&mut e.pager, s, &v)?;
            }
        }
        e.pager.free_extent(self.region.start_page, self.region.pages, e.sb.commit_id + 1);
        self.region = bigger;
        self.descriptor = self.descriptor.with_param("vector_region", Some(u64v(self.region.start_page)));
        self.region_dirty = true;
        Ok(())
    }

    /// F-072 g: the region re-laid and the graph rewritten in the pager's current mode.
    pub fn convert_in_place(&mut self, e: &mut crate::engine::Engine) -> Result<()> {
        if self.region.encrypted != e.pager.seals() {
            let new = self.region.relocate(&mut e.pager)?;
            e.pager.free_extent(self.region.start_page, self.region.pages, e.sb.commit_id + 1);
            self.region = new;
            self.descriptor = self.descriptor.with_param("vector_region", Some(u64v(self.region.start_page)));
            self.region_dirty = true;
        }
        self.adjacency.mark_dirty();
        Ok(())
    }

    /// Writes the graph's copied pages back and republishes the descriptor.
    pub fn commit(&mut self, e: &mut crate::engine::Engine) -> Result<()> {
        let root = self.adjacency.commit(&mut e.pager, e.sb.commit_id)?;
        let d = &self.descriptor;
        let eps = if self.entry == 0 { vec![] } else { vec![u64v(self.entry)] };
        let changed = d.root() != Some(root.0)
            || d.root_nonce() != root.1
            || d.entries() != self.live_count
            || d.param("entry_points") != Some(&Value::Array(eps.clone()));
        if changed || self.region_dirty {
            self.region_dirty = false;
            self.descriptor = d
                .with_root(root)
                .with(vec![("entries", Some(u64v(self.live_count)))])
                .with_param("entry_points", Some(Value::Array(eps)));
            e.catalog.put(&mut e.pager, &self.name, &self.descriptor)?;
        }
        Ok(())
    }

    pub fn neighbours(&self, e: &mut crate::engine::Engine, slot: u64) -> Result<Vec<u64>> {
        self.adjacency_of(&mut e.pager, slot)
    }

    fn adjacency_of(&self, pager: &mut Pager, slot: u64) -> Result<Vec<u64>> {
        Ok(match self.adjacency.get(pager, &adjacency_key(0, slot))? {
            Some(raw) => Adjacency::decode_value(&raw)?.neighbours,
            None => Vec::new(),
        })
    }

    fn set_adjacency(&mut self, e: &mut crate::engine::Engine, slot: u64, n: Vec<u64>) -> Result<()> {
        let v = Adjacency { neighbours: n }.encode_value();
        self.adjacency.put(&mut e.pager, e.sb.commit_id, &adjacency_key(0, slot), &v)
    }

    fn vector(&self, pager: &mut Pager, slot: u64, cache: &mut Option<&mut std::collections::HashMap<u64, Vec<f32>>>) -> Result<Vec<f32>> {
        if slot == 0 || slot >= self.region.header.slot_count {
            return corrupt(format!("vector index '{}': neighbour slot {slot} is outside the region", self.name));
        }
        match cache {
            Some(c) => {
                if let Some(v) = c.get(&slot) {
                    return Ok(v.clone());
                }
                let v = self.region.read_slot(pager, slot)?;
                c.insert(slot, v.clone());
                Ok(v)
            }
            None => self.region.read_slot(pager, slot),
        }
    }

    /// Beam search from the entry point: the `ef` nearest slots seen, nearest first.
    fn beam(&self, pager: &mut Pager, q: &[f32], ef: usize, mut cache: Option<&mut std::collections::HashMap<u64, Vec<f32>>>) -> Result<Vec<Scored>> {
        use std::cmp::Reverse;
        use std::collections::{BinaryHeap, HashSet};
        if self.entry == 0 {
            return Ok(Vec::new());
        }
        let mut open = BinaryHeap::new();
        let mut best: BinaryHeap<Scored> = BinaryHeap::new();
        let mut seen = HashSet::new();
        let first = Scored(distance_f64(self.metric, q, &self.vector(pager, self.entry, &mut cache)?), self.entry);
        open.push(Reverse(first));
        best.push(first);
        seen.insert(self.entry);
        while let Some(Reverse(c)) = open.pop() {
            if best.len() >= ef && c.0 > best.peek().unwrap().0 {
                break;
            }
            for n in self.adjacency_of(pager, c.1)? {
                if !seen.insert(n) {
                    continue;
                }
                let d = distance_f64(self.metric, q, &self.vector(pager, n, &mut cache)?);
                if best.len() < ef || d < best.peek().unwrap().0 {
                    let s = Scored(d, n);
                    open.push(Reverse(s));
                    best.push(s);
                    if best.len() > ef {
                        best.pop();
                    }
                }
            }
        }
        Ok(best.into_sorted_vec())
    }

    /// Vamana's robust prune: nearest first, dropping a candidate a kept one
    /// covers, up to `m - m/8`; F-201: the last `m/8` slots go to the farthest
    /// candidates left. In high dimensions near neighbours rarely cover each
    /// other, so a cluster larger than `m` filled every list with itself, the
    /// edges out of it were pruned away, and a search never left the entry
    /// point's cluster (recall@10 0.010 at 10^5 x 128-d in 1000 clusters).
    fn prune(&self, pager: &mut Pager, me: u64, nearest_first: &[Scored], cache: &mut std::collections::HashMap<u64, Vec<f32>>) -> Result<Vec<u64>> {
        let near = self.m - (self.m / 8).max(1);
        let mut kept: Vec<u64> = Vec::new();
        let mut kept_v: Vec<Vec<f32>> = Vec::new();
        for c in nearest_first {
            if kept.len() >= near {
                break;
            }
            if c.1 == me || kept.contains(&c.1) {
                continue;
            }
            let v = self.vector(pager, c.1, &mut Some(&mut *cache))?;
            if !kept_v.iter().any(|k| ALPHA * distance_f64(self.metric, k, &v) <= c.0) {
                kept.push(c.1);
                kept_v.push(v);
            }
        }
        for c in nearest_first.iter().rev() {
            if kept.len() >= self.m {
                break;
            }
            if c.1 != me && !kept.contains(&c.1) {
                kept.push(c.1);
            }
        }
        Ok(kept)
    }

    /// Links `slot` into the graph, reverse edges included.
    fn link(&mut self, e: &mut crate::engine::Engine, slot: u64, v: Vec<f32>) -> Result<()> {
        if self.entry == 0 || self.entry == slot {
            self.entry = slot;
            if self.adjacency.get(&mut e.pager, &adjacency_key(0, slot))?.is_none() {
                self.set_adjacency(e, slot, Vec::new())?;
            }
            return Ok(());
        }
        let mut cache = std::collections::HashMap::new();
        let q = v.clone();
        cache.insert(slot, v);
        let near = self.beam(&mut e.pager, &q, self.ef_construction, Some(&mut cache))?;
        let mine = self.prune(&mut e.pager, slot, &near, &mut cache)?;
        self.set_adjacency(e, slot, mine.clone())?;
        for n in mine {
            let mut theirs = self.adjacency_of(&mut e.pager, n)?;
            if theirs.contains(&slot) {
                continue;
            }
            theirs.push(slot);
            if theirs.len() > self.m {
                let nv = self.vector(&mut e.pager, n, &mut Some(&mut cache))?;
                let mut scored = Vec::with_capacity(theirs.len());
                for t in &theirs {
                    let tv = self.vector(&mut e.pager, *t, &mut Some(&mut cache))?;
                    scored.push(Scored(distance_f64(self.metric, &nv, &tv), *t));
                }
                scored.sort();
                theirs = self.prune(&mut e.pager, n, &scored, &mut cache)?;
            }
            self.set_adjacency(e, n, theirs)?;
        }
        Ok(())
    }

    /// §8 `search(query, k, filter?)`, nearest first, with **true** distances,
    /// and never a slot with no live document.
    pub fn search(&mut self, e: &mut crate::engine::Engine, query: &[f32], k: usize, filter: Option<&dyn Fn(i64) -> bool>) -> Result<Vec<(i64, f64)>> {
        self.search_ef(e, query, k, filter, EF_SEARCH)
    }

    /// [`Self::search`] with beam width `ef` (F-205): recall against speed,
    /// which §8 leaves to the caller. 3e5 x 128-d: ef 100 recall 0.948 p50
    /// 4.2 ms, ef 400 0.987 / 13.5 ms.
    pub fn search_ef(&mut self, e: &mut crate::engine::Engine, query: &[f32], k: usize, filter: Option<&dyn Fn(i64) -> bool>, ef: usize) -> Result<Vec<(i64, f64)>> {
        if query.len() != self.dim as usize {
            return invalid(format!("query has {} dimensions, index {} declares {}", query.len(), self.name, self.dim));
        }
        let ef = k.max(ef);
        if filter.is_none() && self.live_count as usize > ef {
            let mut hits = Vec::new();
            for c in self.beam(&mut e.pager, query, ef, None)? {
                if self.is_live(c.1) {
                    hits.push((self.slot_doc[c.1 as usize], c.0));
                }
                if hits.len() == k {
                    return Ok(hits);
                }
            }
            // Fewer than k live slots in the beam (deletes): the scan answers.
            self.fallbacks += 1;
        }
        let mut hits = Vec::new();
        for s in 1..self.live.len() as u64 {
            if !self.is_live(s) {
                continue;
            }
            let doc = self.slot_doc[s as usize];
            if filter.is_some_and(|f| !f(doc)) {
                continue;
            }
            let v = self.region.read_slot(&mut e.pager, s)?;
            hits.push((doc, distance_f64(self.metric, query, &v)));
        }
        hits.sort_by(|a, b| a.1.total_cmp(&b.1));
        hits.truncate(k);
        Ok(hits)
    }
}
