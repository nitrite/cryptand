//! `08-spatial.md` §2 — the in-container R-tree.
//!
//! What goes away versus `nitrite-rust`'s `disk_rtree` is its *private
//! container*: the file header, the free list, the migration manager and the
//! integrity checker are all duplicates of things `01-container.md` already
//! specifies for every page in the database.
//!
//! **The split algorithm is deliberately not specified** (§2.3), so a
//! conformance test compares **query results, never tree shape**.

use crate::container::{page_flags, page_type, u16le, u64le, PageHeader, PAGE_HEADER_BYTES};
use crate::error::{corrupt, invalid, Result};
use crate::pager::Pager;
use crate::wkb::Envelope;

pub const IS_LEAF: u8 = 0x01;

/// §2.1 — `16 x dimensions + 16` for an internal entry, `16 x dimensions + 8`
/// for a leaf entry. Fixed-width, no varints: a bounding-box comparison is the
/// hot loop of every spatial query, and a fixed stride lets an implementation
/// scan a node without decoding it.
pub fn entry_stride(dimensions: u8, is_leaf: bool) -> usize {
    16 * dimensions as usize + if is_leaf { 8 } else { 16 }
}

pub fn max_entries_for(page_size: usize, dimensions: u8, is_leaf: bool) -> usize {
    (page_size - PAGE_HEADER_BYTES - 16) / entry_stride(dimensions, is_leaf)
}

#[derive(Clone, Copy, Debug)]
pub struct RTreeEntry {
    pub bbox: Envelope,
    /// `child_page` for an internal entry, `nitrite_id` for a leaf entry.
    pub payload: i64,
    pub child_entries: u64,
}

#[derive(Clone, Debug)]
pub struct RTreeNode {
    pub is_leaf: bool,
    pub dimensions: u8,
    pub entries: Vec<RTreeEntry>,
}

impl RTreeNode {
    pub fn subtree_entries(&self) -> u64 {
        if self.is_leaf {
            self.entries.len() as u64
        } else {
            self.entries.iter().map(|e| e.child_entries).sum()
        }
    }

    pub fn bbox(&self) -> Envelope {
        let mut e = Envelope::empty();
        for x in &self.entries {
            e.union(&x.bbox);
        }
        e
    }

    pub fn encode(&self, page_size: usize) -> Result<Vec<u8>> {
        let d = self.dimensions as usize;
        let stride = entry_stride(self.dimensions, self.is_leaf);
        let need = PAGE_HEADER_BYTES + 16 + self.entries.len() * stride;
        if need > page_size {
            return invalid("R-tree node does not fit its page");
        }
        let mut page = vec![0u8; page_size];
        let b = PAGE_HEADER_BYTES;
        page[b..b + 2].copy_from_slice(&(self.entries.len() as u16).to_le_bytes());
        page[b + 2] = self.dimensions;
        page[b + 3] = if self.is_leaf { IS_LEAF } else { 0 };
        page[b + 8..b + 16].copy_from_slice(&self.subtree_entries().to_le_bytes());
        let mut at = b + 16;
        for e in &self.entries {
            for i in 0..d {
                page[at..at + 8].copy_from_slice(&e.bbox.min[i].to_le_bytes());
                at += 8;
            }
            for i in 0..d {
                page[at..at + 8].copy_from_slice(&e.bbox.max[i].to_le_bytes());
                at += 8;
            }
            page[at..at + 8].copy_from_slice(&e.payload.to_le_bytes());
            at += 8;
            if !self.is_leaf {
                page[at..at + 8].copy_from_slice(&e.child_entries.to_le_bytes());
                at += 8;
            }
        }
        PageHeader {
            page_type: if self.is_leaf { page_type::RTREE_LEAF } else { page_type::RTREE_INTERNAL },
            flags: page_flags::EXTENT_HEAD,
            tree_id: crate::container::NO_TREE,
            extent_pages: 1,
            payload_len: (16 + self.entries.len() * stride) as u32,
            ..Default::default()
        }
        .write_into(&mut page);
        Ok(page)
    }

    /// §3 — a reader MUST use the page's own `dimensions` and MUST reject a
    /// page whose `dimensions` disagrees with the descriptor.
    pub fn parse(page: &[u8], expect_dimensions: u8) -> Result<RTreeNode> {
        let b = PAGE_HEADER_BYTES;
        if page.len() < b + 16 {
            return corrupt("R-tree page too small");
        }
        let count = u16le(page, b) as usize;
        let dimensions = page[b + 2];
        if dimensions != expect_dimensions {
            return corrupt(format!(
                "R-tree page declares {dimensions} dimensions, the descriptor says {expect_dimensions}"
            ));
        }
        if !(2..=4).contains(&dimensions) {
            return corrupt(format!("R-tree dimensions {dimensions} outside 2..4"));
        }
        let is_leaf = page[b + 3] & IS_LEAF != 0;
        let stride = entry_stride(dimensions, is_leaf);
        if b + 16 + count * stride > page.len() {
            return corrupt("R-tree entries overrun the page");
        }
        let d = dimensions as usize;
        let mut entries = Vec::with_capacity(count);
        let mut at = b + 16;
        for _ in 0..count {
            let mut bbox = Envelope { min: [0.0; 4], max: [0.0; 4] };
            for i in 0..4 {
                bbox.min[i] = if i < d { f64::INFINITY } else { 0.0 };
                bbox.max[i] = if i < d { f64::NEG_INFINITY } else { 0.0 };
            }
            for i in 0..d {
                bbox.min[i] = f64::from_le_bytes(page[at..at + 8].try_into().unwrap());
                at += 8;
            }
            for i in 0..d {
                bbox.max[i] = f64::from_le_bytes(page[at..at + 8].try_into().unwrap());
                at += 8;
            }
            let payload = i64::from_le_bytes(page[at..at + 8].try_into().unwrap());
            at += 8;
            let child_entries = if is_leaf {
                1
            } else {
                let v = u64le(page, at);
                at += 8;
                v
            };
            entries.push(RTreeEntry { bbox, payload, child_entries });
        }
        Ok(RTreeNode { is_leaf, dimensions, entries })
    }
}

/// One `(bbox, NitriteId)` row.
#[derive(Clone, Copy, Debug)]
pub struct SpatialEntry {
    pub bbox: Envelope,
    pub id: i64,
}

/// An R-tree rooted from its catalog descriptor, over the container's pages.
pub struct RTree {
    pub root: u64,
    pub dimensions: u8,
    pub max_entries: usize,
    pub tree_id: u32,
}

impl RTree {
    pub fn new(tree_id: u32, dimensions: u8, max_entries: usize) -> RTree {
        RTree { root: 0, dimensions, max_entries, tree_id }
    }

    fn load(&self, pager: &mut Pager, page: u64) -> Result<RTreeNode> {
        let (_h, raw) = pager.read_verified(page)?;
        RTreeNode::parse(&raw, self.dimensions)
    }

    fn store(&self, pager: &mut Pager, n: &RTreeNode) -> Result<u64> {
        let id = pager.alloc_extent(1)?;
        let page = n.encode(pager.page_size)?;
        pager.write_page(id, &page)?;
        Ok(id)
    }

    /// Bulk-loads from a sorted-by-x list. Bulk loading is one of the free
    /// choices §2.3 leaves open; what matters is that every internal entry's
    /// box is the **exact** union of its children (a superset silently
    /// degrades every query).
    pub fn build(&mut self, pager: &mut Pager, mut rows: Vec<SpatialEntry>) -> Result<()> {
        if rows.is_empty() {
            self.root = 0;
            return Ok(());
        }
        rows.sort_by(|a, b| {
            a.bbox.min[0].partial_cmp(&b.bbox.min[0]).unwrap_or(std::cmp::Ordering::Equal)
        });
        let fanout = self
            .max_entries
            .min(max_entries_for(pager.page_size, self.dimensions, true))
            .max(2);
        let mut level: Vec<(u64, Envelope, u64)> = Vec::new();
        for chunk in rows.chunks(fanout) {
            let entries: Vec<RTreeEntry> = chunk
                .iter()
                .map(|r| RTreeEntry { bbox: r.bbox, payload: r.id, child_entries: 1 })
                .collect();
            let node = RTreeNode { is_leaf: true, dimensions: self.dimensions, entries };
            let bbox = node.bbox();
            let n = node.entries.len() as u64;
            let page = self.store(pager, &node)?;
            level.push((page, bbox, n));
        }
        let inner_fanout = self
            .max_entries
            .min(max_entries_for(pager.page_size, self.dimensions, false))
            .max(2);
        while level.len() > 1 {
            let mut up = Vec::new();
            for chunk in level.chunks(inner_fanout) {
                let entries: Vec<RTreeEntry> = chunk
                    .iter()
                    .map(|(p, b, n)| RTreeEntry {
                        bbox: *b,
                        payload: *p as i64,
                        child_entries: *n,
                    })
                    .collect();
                let node = RTreeNode { is_leaf: false, dimensions: self.dimensions, entries };
                let bbox = node.bbox();
                let n = node.subtree_entries();
                let page = self.store(pager, &node)?;
                up.push((page, bbox, n));
            }
            level = up;
        }
        self.root = level[0].0;
        Ok(())
    }

    /// Phase 1 of §4's two-phase rule: candidates by bounding box.
    pub fn search(&self, pager: &mut Pager, query: &Envelope) -> Result<Vec<i64>> {
        let mut out = Vec::new();
        if self.root == 0 {
            return Ok(out);
        }
        let mut stack = vec![self.root];
        while let Some(p) = stack.pop() {
            let n = self.load(pager, p)?;
            for e in &n.entries {
                if !e.bbox.intersects(query, self.dimensions as usize) {
                    continue;
                }
                if n.is_leaf {
                    out.push(e.payload);
                } else {
                    stack.push(e.payload as u64);
                }
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// §4's `nearest_k`: best-first search with a priority queue over node
    /// distances.
    pub fn nearest_k(&self, pager: &mut Pager, point: &[f64], k: usize) -> Result<Vec<(i64, f64)>> {
        let mut out: Vec<(i64, f64)> = Vec::new();
        if self.root == 0 {
            return Ok(out);
        }
        let d = self.dimensions as usize;
        let dist = |b: &Envelope| -> f64 {
            let mut s = 0.0;
            for i in 0..d.min(point.len()) {
                let v = point[i];
                let dd = if v < b.min[i] {
                    b.min[i] - v
                } else if v > b.max[i] {
                    v - b.max[i]
                } else {
                    0.0
                };
                s += dd * dd;
            }
            s.sqrt()
        };
        let mut queue: Vec<(f64, u64, bool, i64)> = vec![(0.0, self.root, false, 0)];
        while let Some(i) = queue
            .iter()
            .enumerate()
            .min_by(|a, b| a.1 .0.partial_cmp(&b.1 .0).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
        {
            let (dd, page, is_row, id) = queue.remove(i);
            if is_row {
                out.push((id, dd));
                if out.len() == k {
                    break;
                }
                continue;
            }
            let n = self.load(pager, page)?;
            for e in &n.entries {
                if n.is_leaf {
                    queue.push((dist(&e.bbox), 0, true, e.payload));
                } else {
                    queue.push((dist(&e.bbox), e.payload as u64, false, 0));
                }
            }
        }
        Ok(out)
    }

    /// §2.2's verifier: all leaves at the same depth, and every internal
    /// entry's box the **exact** union of its children's.
    pub fn verify(&self, pager: &mut Pager) -> Result<()> {
        if self.root == 0 {
            return Ok(());
        }
        let mut depths = Vec::new();
        self.verify_node(pager, self.root, 0, &mut depths)?;
        depths.sort_unstable();
        depths.dedup();
        if depths.len() > 1 {
            return corrupt("R-tree leaves are not all at the same depth");
        }
        Ok(())
    }

    fn verify_node(&self, pager: &mut Pager, page: u64, depth: usize, depths: &mut Vec<usize>) -> Result<Envelope> {
        let n = self.load(pager, page)?;
        if n.is_leaf {
            depths.push(depth);
            return Ok(n.bbox());
        }
        let mut union = Envelope::empty();
        for e in &n.entries {
            let child = self.verify_node(pager, e.payload as u64, depth + 1, depths)?;
            let d = self.dimensions as usize;
            for i in 0..d {
                if child.min[i] != e.bbox.min[i] || child.max[i] != e.bbox.max[i] {
                    return corrupt(
                        "an R-tree internal box is not the exact union of its children; a superset \
                         silently degrades every query (spec/08-spatial.md section 2.2)",
                    );
                }
            }
            union.union(&child);
        }
        Ok(union)
    }
}

/// §3 — the dimension order is fixed: X, Y, Z, M. `dimensions = 3` therefore
/// always means Z, never M: silently indexing M in Z's slot would make two
/// geometries comparable that are not.
pub fn check_dimensions(dimensions: u8, has_z: bool, has_m: bool) -> Result<()> {
    match dimensions {
        2 => Ok(()),
        3 if has_z => Ok(()),
        3 => invalid("a 3-dimensional index needs Z; an XYM geometry cannot go into it"),
        4 if has_z && has_m => Ok(()),
        4 => invalid("a 4-dimensional index needs both Z and M"),
        d => invalid(format!("R-tree dimensions {d} outside 2..4")),
    }
}
