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
use crate::value::Value;
use crate::wkb::Envelope;

pub const IS_LEAF: u8 = 0x01;

/// §2.1 — `16 x dimensions + 24` for an internal entry (F-128 `child_nonce`), `16 x dimensions + 8`
/// for a leaf entry. Fixed-width, no varints: a bounding-box comparison is the
/// hot loop of every spatial query, and a fixed stride lets an implementation
/// scan a node without decoding it.
pub fn entry_stride(dimensions: u8, is_leaf: bool) -> usize {
    16 * dimensions as usize + if is_leaf { 8 } else { 24 }
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
    /// F-128, 14 §5.5: the child's header nonce; internal entries only.
    pub child_nonce: u64,
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
        self.encode_for(page_size, crate::container::NO_TREE)
    }

    /// [`Self::encode`] with the owning tree's id in the page header.
    pub fn encode_for(&self, page_size: usize, tree_id: u32) -> Result<Vec<u8>> {
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
                page[at + 8..at + 16].copy_from_slice(&e.child_nonce.to_le_bytes());
                at += 16;
            }
        }
        PageHeader {
            page_type: if self.is_leaf { page_type::RTREE_LEAF } else { page_type::RTREE_INTERNAL },
            flags: page_flags::EXTENT_HEAD,
            tree_id,
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
            let (child_entries, child_nonce) = if is_leaf {
                (1, 0)
            } else {
                let v = (u64le(page, at), u64le(page, at + 8));
                at += 16;
                v
            };
            entries.push(RTreeEntry { bbox, payload, child_entries, child_nonce });
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
    /// F-128: the root's header nonce, as the descriptor's `root_nonce`.
    pub root_nonce: u64,
    pub dimensions: u8,
    pub max_entries: usize,
    pub tree_id: u32,
}

impl RTree {
    pub fn new(tree_id: u32, dimensions: u8, max_entries: usize) -> RTree {
        RTree { root: 0, root_nonce: 0, dimensions, max_entries, tree_id }
    }

    fn load(&self, pager: &mut Pager, (page, nonce): (u64, u64)) -> Result<RTreeNode> {
        let (_h, raw) = pager.read_bound(page, nonce)?;
        RTreeNode::parse(&raw, self.dimensions)
    }

    /// The page id and the nonce it was sealed under.
    fn store(&self, pager: &mut Pager, n: &RTreeNode) -> Result<(u64, u64)> {
        let id = pager.alloc_extent(1)?;
        let page = n.encode_for(pager.page_size, self.tree_id)?;
        pager.write_page(id, &page)?;
        Ok((id, pager.written_nonce))
    }

    /// Bulk-loads from a sorted-by-x list. Bulk loading is one of the free
    /// choices §2.3 leaves open; what matters is that every internal entry's
    /// box is the **exact** union of its children (a superset silently
    /// degrades every query).
    pub fn build(&mut self, pager: &mut Pager, mut rows: Vec<SpatialEntry>) -> Result<()> {
        if rows.is_empty() {
            (self.root, self.root_nonce) = (0, 0);
            return Ok(());
        }
        rows.sort_by(|a, b| {
            a.bbox.min[0].partial_cmp(&b.bbox.min[0]).unwrap_or(std::cmp::Ordering::Equal)
        });
        let fanout = self
            .max_entries
            .min(max_entries_for(pager.page_size, self.dimensions, true))
            .max(2);
        let mut level: Vec<((u64, u64), Envelope, u64)> = Vec::new();
        for chunk in rows.chunks(fanout) {
            let entries: Vec<RTreeEntry> = chunk
                .iter()
                .map(|r| RTreeEntry { bbox: r.bbox, payload: r.id, child_entries: 1, child_nonce: 0 })
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
                        payload: p.0 as i64,
                        child_entries: *n,
                        child_nonce: p.1,
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
        (self.root, self.root_nonce) = level[0].0;
        Ok(())
    }

    /// Phase 1 of §4's two-phase rule: candidates by bounding box.
    pub fn search(&self, pager: &mut Pager, query: &Envelope) -> Result<Vec<i64>> {
        let mut out = Vec::new();
        if self.root == 0 {
            return Ok(out);
        }
        let mut stack = vec![(self.root, self.root_nonce)];
        while let Some(p) = stack.pop() {
            let n = self.load(pager, p)?;
            for e in &n.entries {
                if !e.bbox.intersects(query, self.dimensions as usize) {
                    continue;
                }
                if n.is_leaf {
                    out.push(e.payload);
                } else {
                    stack.push((e.payload as u64, e.child_nonce));
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
        let mut queue: Vec<(f64, (u64, u64), bool, i64)> = vec![(0.0, (self.root, self.root_nonce), false, 0)];
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
                    queue.push((dist(&e.bbox), (0, 0), true, e.payload));
                } else {
                    queue.push((dist(&e.bbox), (e.payload as u64, e.child_nonce), false, 0));
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
        self.verify_node(pager, (self.root, self.root_nonce), 0, &mut depths)?;
        depths.sort_unstable();
        depths.dedup();
        if depths.len() > 1 {
            return corrupt("R-tree leaves are not all at the same depth");
        }
        Ok(())
    }

    fn verify_node(&self, pager: &mut Pager, page: (u64, u64), depth: usize, depths: &mut Vec<usize>) -> Result<Envelope> {
        let n = self.load(pager, page)?;
        if n.is_leaf {
            depths.push(depth);
            return Ok(n.bbox());
        }
        let mut union = Envelope::empty();
        for e in &n.entries {
            let child = self.verify_node(pager, (e.payload as u64, e.child_nonce), depth + 1, depths)?;
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

/// Copied nodes held before an early write-back (F-195, as Java): ~10 KB
/// each, so ~20 MB. A test lowers it to exercise the write-back.
pub static DIRTY_BUDGET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(2048);

/// One entry of a node held for a write.
struct Slot {
    bbox: Envelope,
    /// Leaf: nitrite id. Internal: child page, 0 while the child is only in `kid`.
    r: u64,
    cnt: u64,
    nonce: u64,
    kid: Option<Box<CowNode>>,
}

struct CowNode {
    leaf: bool,
    e: Vec<Slot>,
}

impl CowNode {
    fn total(&self) -> u64 {
        if self.leaf {
            self.e.len() as u64
        } else {
            self.e.iter().map(|s| s.cnt).sum()
        }
    }
    fn cover(&self) -> Envelope {
        let mut c = Envelope::empty();
        for s in &self.e {
            c.union(&s.bbox);
        }
        c
    }
}

/// The page-level context a tree operation needs.
struct Io<'a> {
    pager: &'a mut Pager,
    tree_id: u32,
    dims: u8,
    /// Frees go to the next commit: the published one may still name them.
    free_at: u64,
    dirty: usize,
}

impl Io<'_> {
    fn fanout(&self, leaf: bool) -> usize {
        ((self.pager.payload_cap() - 16) / entry_stride(self.dims, leaf)).max(2)
    }
    fn read(&mut self, page: u64, nonce: u64) -> Result<CowNode> {
        let (_h, raw) = self.pager.read_bound(page, nonce)?;
        let n = RTreeNode::parse(&raw, self.dims)?;
        Ok(CowNode {
            leaf: n.is_leaf,
            e: n.entries
                .into_iter()
                .map(|x| Slot { bbox: x.bbox, r: x.payload as u64, cnt: x.child_entries, nonce: x.child_nonce, kid: None })
                .collect(),
        })
    }
    fn free(&mut self, page: u64) {
        self.pager.free_extent(page, 1, self.free_at);
    }
    /// Child `i` for a write: copied from its page, which is freed.
    fn child<'n>(&mut self, node: &'n mut CowNode, i: usize) -> Result<&'n mut CowNode> {
        if node.e[i].kid.is_none() {
            let (p, nc) = (node.e[i].r, node.e[i].nonce);
            node.e[i].kid = Some(Box::new(self.read(p, nc)?));
            self.free(p);
            node.e[i].r = 0;
            self.dirty += 1;
        }
        Ok(node.e[i].kid.as_mut().unwrap())
    }
    fn write_page(&mut self, node: &CowNode) -> Result<(u64, u64)> {
        let n = RTreeNode {
            is_leaf: node.leaf,
            dimensions: self.dims,
            entries: node
                .e
                .iter()
                .map(|s| RTreeEntry { bbox: s.bbox, payload: s.r as i64, child_entries: s.cnt, child_nonce: s.nonce })
                .collect(),
        };
        let mut page = n.encode_for(self.pager.page_size, self.tree_id)?;
        page[crate::container::PAGE_HEADER_BYTES + 8..crate::container::PAGE_HEADER_BYTES + 16]
            .copy_from_slice(&node.total().to_le_bytes());
        let id = self.pager.alloc_extent(1)?;
        self.pager.write_page(id, &page)?;
        Ok((id, self.pager.written_nonce))
    }
    /// Writes `node`'s copied children, then `node`.
    fn write(&mut self, node: &mut CowNode) -> Result<(u64, u64)> {
        if !node.leaf {
            for s in node.e.iter_mut() {
                if let Some(mut k) = s.kid.take() {
                    (s.r, s.nonce) = self.write(&mut k)?;
                }
            }
        }
        self.write_page(node)
    }
    /// Streams a subtree through fresh pages, O(depth) in memory.
    fn rewrite(&mut self, page: u64, nonce: u64, depth: usize) -> Result<(u64, u64)> {
        if depth > 64 {
            return corrupt("R-tree is deeper than 64 levels");
        }
        let mut node = self.read(page, nonce)?;
        self.free(page);
        if !node.leaf {
            for s in node.e.iter_mut() {
                (s.r, s.nonce) = self.rewrite(s.r, s.nonce, depth + 1)?;
            }
        }
        self.write_page(&node)
    }
}

/// Fills the dimensions past `dims` the way [`RTreeNode::parse`] does, so a
/// box read back compares equal to the one written.
fn normalise(mut b: Envelope, dims: u8) -> Envelope {
    for i in dims as usize..4 {
        b.min[i] = 0.0;
        b.max[i] = 0.0;
    }
    b
}

fn area(b: &Envelope, dims: usize) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    (0..dims).map(|i| b.max[i] - b.min[i]).product()
}

fn union_of(a: &Envelope, b: &Envelope) -> Envelope {
    let mut u = *a;
    u.union(b);
    u
}

fn centre(b: &Envelope, axis: usize) -> f64 {
    if b.is_empty() {
        0.0
    } else {
        (b.min[axis] + b.max[axis]) / 2.0
    }
}

fn same_box(a: &Envelope, b: &Envelope, dims: usize) -> bool {
    (0..dims).all(|i| a.min[i].to_bits() == b.min[i].to_bits() && a.max[i].to_bits() == b.max[i].to_bits())
}

fn sq_distance(b: &Envelope, point: &[f64], dims: usize) -> f64 {
    let mut s = 0.0;
    for i in 0..dims.min(point.len()) {
        let v = point[i];
        let d = if v < b.min[i] { b.min[i] - v } else if v > b.max[i] { v - b.max[i] } else { 0.0 };
        s += d * d;
    }
    s
}

/// The spatial index's R-tree, copy-on-write and incremental (F-195, as Java).
///
/// A write copies the path it touches into memory and frees the old pages
/// (reusable after the next commit, 01 §6); [`Self::commit`] writes the copied
/// nodes back as fresh pages, and past [`DIRTY_BUDGET`] copied nodes the same
/// write-back runs early, so memory holds a bounded part of the tree whatever
/// its size. Inserts by least enlargement, splits at the median of the widest
/// axis. Removal needs the entry's box, which the caller derives from the
/// previous document.
/// ponytail: no reinsertion on underflow (2.2 allows any population from 1);
/// a long delete-heavy life leaves sparse nodes, R*-tree condense is the upgrade.
pub struct CowRTree {
    pub tree_id: u32,
    pub dimensions: u8,
    root: Option<Box<CowNode>>,
    root_page: u64,
    root_nonce: u64,
    size: u64,
    dirty: usize,
    rewrite_all: bool,
}

impl CowRTree {
    pub fn load(pager: &mut Pager, tree_id: u32, dimensions: u8, root: u64, root_nonce: u64) -> Result<CowRTree> {
        let mut t = CowRTree { tree_id, dimensions, root: None, root_page: root, root_nonce, size: 0, dirty: 0, rewrite_all: false };
        if root != 0 {
            let mut io = t.io(pager, 0);
            t.size = io.read(root, root_nonce)?.total();
        }
        Ok(t)
    }

    fn io<'a>(&self, pager: &'a mut Pager, commit_id: u64) -> Io<'a> {
        Io { pager, tree_id: self.tree_id, dims: self.dimensions, free_at: commit_id + 1, dirty: self.dirty }
    }

    /// The published root and its nonce, valid after [`Self::commit`].
    pub fn root(&self) -> (u64, u64) {
        (self.root_page, self.root_nonce)
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// The next [`Self::commit`] rewrites every page (F-072: conversion in place).
    pub fn mark_dirty(&mut self) {
        self.rewrite_all = true;
    }

    /// `commit_id` is the engine's last published commit.
    pub fn insert(&mut self, pager: &mut Pager, commit_id: u64, bbox: Envelope, id: i64) -> Result<()> {
        let bbox = normalise(bbox, self.dimensions);
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
                Box::new(CowNode { leaf: true, e: Vec::new() })
            }
        };
        let split = Self::insert_at(&mut io, &mut r, bbox, id as u64)?;
        if let Some(s) = split {
            let up = CowNode {
                leaf: false,
                e: vec![
                    Slot { bbox: r.cover(), r: 0, cnt: r.total(), nonce: 0, kid: Some(r) },
                    Slot { bbox: s.cover(), r: 0, cnt: s.total(), nonce: 0, kid: Some(s) },
                ],
            };
            r = Box::new(up);
            io.dirty += 1;
        }
        self.root = Some(r);
        self.size += 1;
        self.dirty = io.dirty;
        self.spill_if_over(pager, commit_id)
    }

    fn insert_at(io: &mut Io, node: &mut CowNode, bbox: Envelope, id: u64) -> Result<Option<Box<CowNode>>> {
        if node.leaf {
            node.e.push(Slot { bbox, r: id, cnt: 0, nonce: 0, kid: None });
        } else {
            let i = Self::choose(node, &bbox, io.dims as usize);
            let c = io.child(node, i)?;
            let s = Self::insert_at(io, c, bbox, id)?;
            let (cb, ct) = (c.cover(), c.total());
            node.e[i].bbox = cb;
            node.e[i].cnt = ct;
            if let Some(s) = s {
                node.e.push(Slot { bbox: s.cover(), r: 0, cnt: s.total(), nonce: 0, kid: Some(s) });
            }
        }
        Ok(if node.e.len() > io.fanout(node.leaf) { Some(Self::split(io, node)) } else { None })
    }

    /// Least area enlargement, then least area.
    fn choose(node: &CowNode, bbox: &Envelope, dims: usize) -> usize {
        let (mut best, mut grow_best, mut area_best) = (0, f64::INFINITY, f64::INFINITY);
        for (i, s) in node.e.iter().enumerate() {
            let a = area(&s.bbox, dims);
            let grow = area(&union_of(&s.bbox, bbox), dims) - a;
            if grow < grow_best || (grow == grow_best && a < area_best) {
                (best, grow_best, area_best) = (i, grow, a);
            }
        }
        best
    }

    /// Median split on the axis whose entry centres spread widest; the upper half moves out.
    fn split(io: &mut Io, node: &mut CowNode) -> Box<CowNode> {
        let mut axis = 0;
        let mut widest = -1.0;
        for a in 0..io.dims as usize {
            let (mut lo, mut hi) = (f64::INFINITY, f64::NEG_INFINITY);
            for s in &node.e {
                let c = centre(&s.bbox, a);
                lo = lo.min(c);
                hi = hi.max(c);
            }
            if hi - lo > widest {
                widest = hi - lo;
                axis = a;
            }
        }
        node.e.sort_by(|x, y| centre(&x.bbox, axis).total_cmp(&centre(&y.bbox, axis)));
        let hi = node.e.split_off(node.e.len() / 2);
        io.dirty += 1;
        Box::new(CowNode { leaf: node.leaf, e: hi })
    }

    /// Removes one entry of `id` whose box is `bbox`; false if there is none.
    pub fn remove(&mut self, pager: &mut Pager, commit_id: u64, bbox: Envelope, id: i64) -> Result<bool> {
        if self.size == 0 {
            return Ok(false);
        }
        let bbox = normalise(bbox, self.dimensions);
        let mut io = self.io(pager, commit_id);
        let mut path = Vec::new();
        let found = match &self.root {
            Some(r) => Self::find(&mut io, r, &bbox, id as u64, &mut path, 0)?,
            None => {
                let r = io.read(self.root_page, self.root_nonce)?;
                Self::find(&mut io, &r, &bbox, id as u64, &mut path, 0)?
            }
        };
        if !found {
            return Ok(false);
        }
        let mut r = match self.root.take() {
            Some(r) => r,
            None => {
                let n = io.read(self.root_page, self.root_nonce)?;
                io.free(self.root_page);
                self.root_page = 0;
                io.dirty += 1;
                Box::new(n)
            }
        };
        Self::remove_at(&mut io, &mut r, &path)?;
        while !r.leaf && r.e.len() == 1 {
            io.child(&mut r, 0)?;
            r = r.e.pop().unwrap().kid.unwrap();
            io.dirty = io.dirty.saturating_sub(1);
        }
        if r.e.is_empty() {
            io.dirty = io.dirty.saturating_sub(1);
        } else {
            self.root = Some(r);
        }
        self.size -= 1;
        self.dirty = io.dirty;
        self.spill_if_over(pager, commit_id)?;
        Ok(true)
    }

    fn remove_at(io: &mut Io, node: &mut CowNode, path: &[usize]) -> Result<()> {
        let i = path[0];
        if path.len() == 1 {
            node.e.swap_remove(i);
            return Ok(());
        }
        let c = io.child(node, i)?;
        Self::remove_at(io, c, &path[1..])?;
        if c.e.is_empty() {
            node.e.swap_remove(i);
            io.dirty = io.dirty.saturating_sub(1);
        } else {
            let (cb, ct) = (c.cover(), c.total());
            node.e[i].bbox = cb;
            node.e[i].cnt = ct;
        }
        Ok(())
    }

    fn find(io: &mut Io, node: &CowNode, bbox: &Envelope, id: u64, path: &mut Vec<usize>, depth: usize) -> Result<bool> {
        if depth > 64 {
            return corrupt("R-tree is deeper than 64 levels");
        }
        let dims = io.dims as usize;
        for (i, s) in node.e.iter().enumerate() {
            if node.leaf {
                if s.r == id && same_box(&s.bbox, bbox, dims) {
                    path.push(i);
                    return Ok(true);
                }
            } else if bbox.is_empty() || s.bbox.contains(bbox, dims) {
                path.push(i);
                let hit = match &s.kid {
                    Some(k) => Self::find(io, k, bbox, id, path, depth + 1)?,
                    None => {
                        let k = io.read(s.r, s.nonce)?;
                        Self::find(io, &k, bbox, id, path, depth + 1)?
                    }
                };
                if hit {
                    return Ok(true);
                }
                path.pop();
            }
        }
        Ok(false)
    }

    fn spill_if_over(&mut self, pager: &mut Pager, commit_id: u64) -> Result<()> {
        if self.dirty > DIRTY_BUDGET.load(std::sync::atomic::Ordering::Relaxed) {
            self.write_out(pager, commit_id)?;
        }
        Ok(())
    }

    fn write_out(&mut self, pager: &mut Pager, commit_id: u64) -> Result<()> {
        if let Some(mut r) = self.root.take() {
            let mut io = self.io(pager, commit_id);
            (self.root_page, self.root_nonce) = io.write(&mut r)?;
        }
        self.dirty = 0;
        Ok(())
    }

    /// Writes the copied nodes back; returns the root page and nonce (0, 0: empty).
    pub fn commit(&mut self, pager: &mut Pager, commit_id: u64) -> Result<(u64, u64)> {
        self.write_out(pager, commit_id)?;
        if self.rewrite_all {
            self.rewrite_all = false;
            if self.root_page != 0 {
                let mut io = self.io(pager, commit_id);
                (self.root_page, self.root_nonce) = io.rewrite(self.root_page, self.root_nonce, 0)?;
            }
        }
        if self.root_page == 0 {
            self.root_nonce = 0;
        }
        Ok(self.root())
    }

    /// Ids whose box intersects `query`: §4's phase one, candidates only.
    pub fn candidates(&self, pager: &mut Pager, query: &Envelope) -> Result<Vec<i64>> {
        let mut out = Vec::new();
        let mut io = self.io(pager, 0);
        let dims = self.dimensions as usize;
        match &self.root {
            Some(r) => Self::descend(&mut io, r, query, dims, &mut out, 0)?,
            None if self.root_page != 0 => {
                let r = io.read(self.root_page, self.root_nonce)?;
                Self::descend(&mut io, &r, query, dims, &mut out, 0)?
            }
            None => {}
        }
        Ok(out)
    }

    fn descend(io: &mut Io, node: &CowNode, q: &Envelope, dims: usize, out: &mut Vec<i64>, depth: usize) -> Result<()> {
        if depth > 64 {
            return corrupt("R-tree is deeper than 64 levels");
        }
        for s in &node.e {
            if !s.bbox.intersects(q, dims) {
                continue;
            }
            if node.leaf {
                out.push(s.r as i64);
            } else if let Some(k) = &s.kid {
                Self::descend(io, k, q, dims, out, depth + 1)?;
            } else {
                let k = io.read(s.r, s.nonce)?;
                Self::descend(io, &k, q, dims, out, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Best-first search over box distances, §4's `nearest_k`: a subtree
    /// further than the k-th best entry is never opened.
    pub fn nearest(&self, pager: &mut Pager, point: &[f64], k: usize) -> Result<Vec<i64>> {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;
        // Ordered by the distance's bits: non-negative floats order as their bits.
        let mut heap: BinaryHeap<Reverse<(u64, u64, u64, bool, usize)>> = BinaryHeap::new();
        // Copied subtrees are referenced by address into `held`, read pages are loaded on pop.
        let mut held: Vec<&CowNode> = Vec::new();
        let mut loaded: Vec<CowNode> = Vec::new();
        let mut out = Vec::new();
        let dims = self.dimensions as usize;
        let mut io = self.io(pager, 0);
        // (dist, payload, nonce, is_entry, held index + 1 or 0)
        match &self.root {
            Some(r) => {
                held.push(r);
                heap.push(Reverse((0, 0, 0, false, 1)));
            }
            None if self.root_page != 0 => heap.push(Reverse((0, self.root_page, self.root_nonce, false, 0))),
            None => return Ok(out),
        }
        while let Some(Reverse((_, payload, nonce, is_entry, h))) = heap.pop() {
            if out.len() >= k {
                break;
            }
            if is_entry {
                out.push(payload as i64);
                continue;
            }
            let node: &CowNode = if h > 0 {
                held[h - 1]
            } else {
                loaded.push(io.read(payload, nonce)?);
                let at = loaded.len() - 1;
                for s in &loaded[at].e {
                    let d = sq_distance(&s.bbox, point, dims).to_bits();
                    heap.push(Reverse((d, s.r, s.nonce, loaded[at].leaf, 0)));
                }
                continue;
            };
            for s in &node.e {
                let d = sq_distance(&s.bbox, point, dims).to_bits();
                match &s.kid {
                    Some(k) => {
                        held.push(k);
                        heap.push(Reverse((d, 0, 0, false, held.len())));
                    }
                    None => heap.push(Reverse((d, s.r, s.nonce, node.leaf, 0))),
                }
            }
        }
        Ok(out)
    }
}

/// A spatial index bound to a collection, `08-spatial.md` §2 and §4 — the
/// engine holds it ([`crate::engine::Engine::spatial_indexes`]) so every
/// commit writes its copied nodes back and republishes its root, as Java's
/// commit hook does.
///
/// Every query is **two-phase**, which §4 makes normative: candidates by box,
/// then the exact predicate on the document's geometry.
pub struct SpatialIndex {
    pub name: String,
    pub owner: String,
    pub field: String,
    pub dimensions: u8,
    pub srid: Option<u32>,
    descriptor: crate::catalog::TreeDescriptor,
    tree: CowRTree,
}

impl SpatialIndex {
    pub fn open(e: &mut crate::engine::Engine, name: &str, d: crate::catalog::TreeDescriptor) -> Result<SpatialIndex> {
        let Some(field) = d.param_str("field").map(str::to_string) else {
            return corrupt(format!("spatial index '{name}' has no params.field"));
        };
        let dimensions = d.param_u64("dimensions").unwrap_or(2);
        if !(2..=4).contains(&dimensions) {
            return corrupt(format!("spatial index '{name}' declares {dimensions} dimensions"));
        }
        let tree = CowRTree::load(&mut e.pager, d.tree_id(), dimensions as u8, d.root().unwrap_or(0), d.root_nonce())?;
        Ok(SpatialIndex {
            name: name.to_string(),
            owner: d.owner().unwrap_or("").to_string(),
            field,
            dimensions: dimensions as u8,
            srid: d.param_u64("srid").map(|s| s as u32),
            descriptor: d,
            tree,
        })
    }

    pub fn tree_id(&self) -> u32 {
        self.descriptor.tree_id()
    }

    pub fn len(&self) -> u64 {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// F-072: the next commit rewrites every page in the pager's current mode.
    pub fn mark_dirty(&mut self) {
        self.tree.mark_dirty();
    }

    fn geometries(&self, doc: &Value) -> Vec<Vec<u8>> {
        let path = crate::index::parse_field_path(&self.field);
        crate::index::resolve(doc, &path)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| match v {
                Value::Geometry(w) => Some(w),
                _ => None,
            })
            .collect()
    }

    fn boxes(&self, doc: &Value) -> Result<Vec<Envelope>> {
        self.geometries(doc).iter().map(|w| Ok(crate::wkb::decode(w)?.envelope())).collect()
    }

    /// Indexes `doc`'s geometry field; `previous`, the document it replaces,
    /// names the entries to retract (an R-tree removal needs the box).
    pub fn put(&mut self, e: &mut crate::engine::Engine, id: i64, doc: &Value, previous: Option<&Value>, declared_srid: Option<u32>) -> Result<()> {
        if let (Some(a), Some(b)) = (declared_srid, self.srid) {
            if a != b {
                return invalid(format!(
                    "geometry declares SRID {a} but index {} works in SRID {b}; the format does not \
                     reproject (spec/08-spatial.md section 1)",
                    self.name
                ));
            }
        }
        let boxes = self.boxes(doc)?;
        self.remove(e, id, previous)?;
        for b in boxes {
            self.tree.insert(&mut e.pager, e.sb.commit_id, b, id)?;
        }
        Ok(())
    }

    pub fn remove(&mut self, e: &mut crate::engine::Engine, id: i64, previous: Option<&Value>) -> Result<()> {
        if let Some(p) = previous {
            for b in self.boxes(p)? {
                self.tree.remove(&mut e.pager, e.sb.commit_id, b, id)?;
            }
        }
        Ok(())
    }

    /// Writes the copied nodes back and republishes the root; the engine's
    /// commit runs it before the catalog is published.
    pub fn commit(&mut self, e: &mut crate::engine::Engine) -> Result<()> {
        let root = self.tree.commit(&mut e.pager, e.sb.commit_id)?;
        let d = &self.descriptor;
        if d.root() != Some(root.0) || d.root_nonce() != root.1 || d.entries() != self.tree.len() {
            self.descriptor = d
                .with_root(root)
                .with(vec![("entries", Some(Value::int(crate::value::NumType::U64, self.tree.len() as i128)))]);
            e.catalog.put(&mut e.pager, &self.name, &self.descriptor)?;
        }
        Ok(())
    }

    fn query_box(&self, wkb: &[u8]) -> Result<(crate::wkb::Geometry, Envelope)> {
        let g = crate::wkb::decode(wkb)?;
        let b = g.envelope();
        Ok((g, b))
    }

    fn exact(
        &self,
        e: &mut crate::engine::Engine,
        c: &crate::database::Collection,
        candidates: Vec<i64>,
        pred: impl Fn(&crate::wkb::Geometry) -> bool,
    ) -> Result<Vec<i64>> {
        let mut out = Vec::new();
        for id in candidates {
            if let Some(g) = self.geometry_of(e, c, id)? {
                if pred(&g) {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }

    fn geometry_of(&self, e: &mut crate::engine::Engine, c: &crate::database::Collection, id: i64) -> Result<Option<crate::wkb::Geometry>> {
        let Some(doc) = c.get(e, id)? else { return Ok(None) };
        match self.geometries(&doc).first() {
            Some(w) => Ok(Some(crate::wkb::decode(w)?)),
            None => Ok(None),
        }
    }

    pub fn intersects(&self, e: &mut crate::engine::Engine, c: &crate::database::Collection, wkb: &[u8]) -> Result<Vec<i64>> {
        let (q, b) = self.query_box(wkb)?;
        let cands = self.tree.candidates(&mut e.pager, &b)?;
        self.exact(e, c, cands, |g| crate::geometry::intersects(g, &q))
    }

    pub fn within(&self, e: &mut crate::engine::Engine, c: &crate::database::Collection, wkb: &[u8]) -> Result<Vec<i64>> {
        let (q, b) = self.query_box(wkb)?;
        let cands = self.tree.candidates(&mut e.pager, &b)?;
        self.exact(e, c, cands, |g| crate::geometry::within(g, &q))
    }

    pub fn contains(&self, e: &mut crate::engine::Engine, c: &crate::database::Collection, wkb: &[u8]) -> Result<Vec<i64>> {
        let (q, b) = self.query_box(wkb)?;
        let cands = self.tree.candidates(&mut e.pager, &b)?;
        self.exact(e, c, cands, |g| crate::geometry::contains(g, &q))
    }

    pub fn near(&self, e: &mut crate::engine::Engine, c: &crate::database::Collection, x: f64, y: f64, radius: f64) -> Result<Vec<i64>> {
        let centre = crate::wkb::Coord::xy(x, y);
        let mut b = Envelope::empty();
        b.add(&centre);
        let cands = self.tree.candidates(&mut e.pager, &b.expanded(radius, 2))?;
        self.exact(e, c, cands, |g| crate::geometry::near(g, &centre, radius))
    }

    /// The k nearest by exact distance. Box distance is a lower bound on the
    /// geometry's, so the candidates are widened before the exact ranking.
    pub fn nearest_k(&self, e: &mut crate::engine::Engine, c: &crate::database::Collection, x: f64, y: f64, k: usize) -> Result<Vec<i64>> {
        let cands = self.tree.nearest(&mut e.pager, &[x, y], (k * 4).max(k + 8))?;
        let p = crate::wkb::Geometry::Point(Some(crate::wkb::Coord::xy(x, y)));
        let mut ranked = Vec::new();
        for id in cands {
            if let Some(g) = self.geometry_of(e, c, id)? {
                ranked.push((crate::geometry::distance(&g, &p), id));
            }
        }
        ranked.sort_by(|a, b| a.0.total_cmp(&b.0));
        Ok(ranked.into_iter().take(k).map(|r| r.1).collect())
    }
}
