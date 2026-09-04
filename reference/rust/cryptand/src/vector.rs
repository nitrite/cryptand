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
        let bytes = data_offset + slots * stride as u64;
        let pages = bytes.div_ceil(page_size) as u32;
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
        Ok(Region { start_page: start, pages, header })
    }

    pub fn open(pager: &mut Pager, start_page: u64) -> Result<Region> {
        let (h, raw) = pager.read_verified(start_page)?;
        let header = RegionHeader::parse(&raw)?;
        Ok(Region { start_page, pages: h.extent_pages.max(1), header })
    }

    fn slot_offset(&self, page_size: usize, slot: u64) -> u64 {
        self.start_page * page_size as u64 + self.header.data_offset + slot * self.header.stride as u64
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
        let at = self.slot_offset(pager.page_size, slot);
        pager.write_at(at, &buf)
    }

    pub fn read_slot(&self, pager: &mut Pager, slot: u64) -> Result<Vec<f32>> {
        if slot >= self.header.slot_count {
            return corrupt(format!("slot {slot} is past the region's {} slots", self.header.slot_count));
        }
        let at = self.slot_offset(pager.page_size, slot);
        let raw = pager.read_at(at, self.header.stride as usize)?;
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

pub fn distance(metric: Metric, a: &[f32], b: &[f32]) -> f32 {
    match metric {
        Metric::L2 => a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum::<f32>().sqrt(),
        Metric::Dot => -a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>(),
        Metric::Cosine => {
            let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
            let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
            let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
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
