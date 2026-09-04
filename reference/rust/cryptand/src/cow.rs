//! `04-segments.md` §3.3 — the reserved trees of `05-catalog.md` §2 are
//! **plain copy-on-write B+trees**, not levelled segment sets. They are small,
//! hot and almost entirely cached; levelling them would mean the manifest
//! needed a manifest.
//!
//! A write copies the path from leaf to root, appends the copied pages, and
//! publishes the new root in the next superblock. Freed pages go to the free
//! tree at the committing `commit_id` (`01-container.md` §6).

use crate::error::{corrupt, invalid, Result};
use crate::pager::Pager;
use crate::segment::{
    decode_cell_payload, encode_node_page, node_page_bytes, value_kind, Node, op,
};
use crate::varint::{get_uvar, put_uvar};

/// One node held for editing: the decoded form of a §2.2 page.
#[derive(Clone)]
struct CowNode {
    is_leaf: bool,
    keys: Vec<Vec<u8>>,
    payloads: Vec<Vec<u8>>,
}

impl CowNode {
    fn count(&self) -> usize {
        self.keys.len()
    }

    fn subtree_entries(&self) -> u64 {
        if self.is_leaf {
            return self.keys.len() as u64;
        }
        self.payloads.iter().map(|p| child_of(p).map(|c| c.1).unwrap_or(0)).sum()
    }

    fn decode(page: &[u8], page_id: u64) -> Result<CowNode> {
        let n = Node::parse(page, page_id)?;
        let mut keys = Vec::with_capacity(n.cell_count);
        let mut payloads = Vec::with_capacity(n.cell_count);
        for i in 0..n.cell_count {
            keys.push(n.key_at(i)?);
            let p = n.payload_at(i)?;
            if n.is_leaf {
                // A reserved tree's keys are user keys with no trailing `op`
                // byte, so the cell decoder is told PUT explicitly rather than
                // reading a byte that is part of the key.
                let (kind, _, value) = decode_cell_payload(p, op::PUT)?;
                if kind != value_kind::INLINE {
                    return corrupt(format!(
                        "copy-on-write leaf cell {i} has value_kind {kind}; \
                         reserved trees hold inline values only"
                    ));
                }
                payloads.push(leaf_payload(&value));
            } else {
                let (child, entries) = n.child_at(i)?;
                payloads.push(child_payload(child, entries));
            }
        }
        Ok(CowNode { is_leaf: n.is_leaf, keys, payloads })
    }
}

/// `u8 kind_flags = INLINE || uvar len || value`.
fn leaf_payload(value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(value.len() + 6);
    v.push(value_kind::INLINE);
    put_uvar(&mut v, value.len() as u64);
    v.extend_from_slice(value);
    v
}

fn child_payload(page: u64, entries: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&page.to_le_bytes());
    v.extend_from_slice(&entries.to_le_bytes());
    v
}

fn value_of(payload: &[u8]) -> Result<Vec<u8>> {
    let (len, n) = get_uvar(&payload[1..])?;
    let start = 1 + n;
    let end = crate::limits::bounded(len, payload.len() - start, "cow leaf value")? + start;
    Ok(payload[start..end].to_vec())
}

fn child_of(payload: &[u8]) -> Result<(u64, u64)> {
    if payload.len() < 16 {
        return corrupt("copy-on-write internal cell shorter than 16 bytes");
    }
    Ok((
        u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        u64::from_le_bytes(payload[8..16].try_into().unwrap()),
    ))
}

/// A reserved tree. `root` is the published root page id; 0 means empty, which
/// is what an unset superblock root field says.
pub struct CowTree {
    pub tree_id: u32,
    pub root: u64,
    pub commit_id: u64,
    /// Pages a path copy has orphaned, to be added to the free tree at the
    /// committing `commit_id`.
    pub freed: Vec<u64>,
    pub pages_copied: u64,
}

impl CowTree {
    pub fn new(tree_id: u32, root: u64) -> CowTree {
        CowTree { tree_id, root, commit_id: 0, freed: Vec::new(), pages_copied: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.root == 0
    }

    fn load(&self, pager: &mut Pager, page_id: u64) -> Result<CowNode> {
        let (_h, page) = pager.read_verified(page_id)?;
        CowNode::decode(&page, page_id)
    }

    fn write(&mut self, pager: &mut Pager, n: &CowNode) -> Result<u64> {
        let id = pager.alloc_extent(1)?;
        let page = encode_node_page(
            pager.page_size,
            pager.payload_cap(),
            n.is_leaf,
            &n.keys,
            &n.payloads,
            n.subtree_entries(),
            self.tree_id,
            self.commit_id,
        )?;
        pager.write_page(id, &page)?;
        self.pages_copied += 1;
        Ok(id)
    }

    pub fn entry_count(&self, pager: &mut Pager) -> Result<u64> {
        if self.root == 0 {
            return Ok(0);
        }
        Ok(self.load(pager, self.root)?.subtree_entries())
    }

    // -----------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------

    pub fn get(&self, pager: &mut Pager, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.root == 0 {
            return Ok(None);
        }
        let mut page_id = self.root;
        loop {
            let n = self.load(pager, page_id)?;
            if n.is_leaf {
                return match find(&n.keys, key) {
                    Some(i) => Ok(Some(value_of(&n.payloads[i])?)),
                    None => Ok(None),
                };
            }
            if n.count() == 0 {
                return Ok(None);
            }
            page_id = child_of(&n.payloads[descend(&n.keys, key)])?.0;
        }
    }

    /// Every entry in `[lower, upper)`, in key order.
    pub fn scan(
        &self,
        pager: &mut Pager,
        lower: Option<&[u8]>,
        upper: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        if self.root == 0 {
            return Ok(out);
        }
        self.walk(pager, self.root, lower, upper, &mut out)?;
        Ok(out)
    }

    fn walk(
        &self,
        pager: &mut Pager,
        page_id: u64,
        lower: Option<&[u8]>,
        upper: Option<&[u8]>,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<bool> {
        let n = self.load(pager, page_id)?;
        if n.is_leaf {
            for i in 0..n.count() {
                let k = &n.keys[i];
                if let Some(l) = lower {
                    if k.as_slice() < l {
                        continue;
                    }
                }
                if let Some(u) = upper {
                    if k.as_slice() >= u {
                        return Ok(false);
                    }
                }
                out.push((k.clone(), value_of(&n.payloads[i])?));
            }
            return Ok(true);
        }
        let start = lower.map_or(0, |l| descend(&n.keys, l));
        for i in start..n.count() {
            // Separators are lower bounds on their subtree, so a child whose
            // separator is already at or past `upper` holds nothing in range.
            if let Some(u) = upper {
                if i > start && n.keys[i].as_slice() >= u {
                    return Ok(false);
                }
            }
            if !self.walk(pager, child_of(&n.payloads[i])?.0, lower, upper, out)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Every page the tree reaches, for the verifier's reachability pass
    /// (`01-container.md` §9 step 7).
    pub fn reachable(&self, pager: &mut Pager, out: &mut Vec<u64>) -> Result<()> {
        if self.root == 0 {
            return Ok(());
        }
        self.reach(pager, self.root, out)
    }

    fn reach(&self, pager: &mut Pager, page_id: u64, out: &mut Vec<u64>) -> Result<()> {
        out.push(page_id);
        let n = self.load(pager, page_id)?;
        if n.is_leaf {
            return Ok(());
        }
        for p in &n.payloads {
            self.reach(pager, child_of(p)?.0, out)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Writing
    // -----------------------------------------------------------------

    pub fn put(&mut self, pager: &mut Pager, key: &[u8], value: &[u8]) -> Result<()> {
        let payload = leaf_payload(value);
        self.edit(pager, key, Some(payload))
    }

    pub fn remove(&mut self, pager: &mut Pager, key: &[u8]) -> Result<bool> {
        if self.root == 0 || self.get(pager, key)?.is_none() {
            return Ok(false);
        }
        self.edit(pager, key, None)?;
        Ok(true)
    }

    fn edit(&mut self, pager: &mut Pager, key: &[u8], payload: Option<Vec<u8>>) -> Result<()> {
        let Some(payload_present) = payload.clone() else {
            if self.root == 0 {
                return Ok(());
            }
            return self.edit_existing(pager, key, None);
        };
        if self.root == 0 {
            // Through `publish`, not straight to `write`: a first entry too
            // large for a page must be refused by the same check every later
            // one meets.
            let node = CowNode { is_leaf: true, keys: vec![key.to_vec()], payloads: vec![payload_present] };
            return self.publish(pager, vec![(0, node, usize::MAX)]);
        }
        self.edit_existing(pager, key, payload)
    }

    fn edit_existing(&mut self, pager: &mut Pager, key: &[u8], payload: Option<Vec<u8>>) -> Result<()> {
        let mut path: Vec<(u64, CowNode, usize)> = Vec::new();
        let mut page_id = self.root;
        loop {
            let n = self.load(pager, page_id)?;
            if n.is_leaf {
                path.push((page_id, n, usize::MAX));
                break;
            }
            let i = descend(&n.keys, key);
            let child = child_of(&n.payloads[i])?.0;
            path.push((page_id, n, i));
            page_id = child;
        }
        {
            let leaf = &mut path.last_mut().unwrap().1;
            let at = lower_bound(&leaf.keys, key);
            let hit = at < leaf.count() && leaf.keys[at] == key;
            match payload {
                None => {
                    if !hit {
                        return Ok(());
                    }
                    leaf.keys.remove(at);
                    leaf.payloads.remove(at);
                }
                Some(p) => {
                    if hit {
                        leaf.payloads[at] = p;
                    } else {
                        leaf.keys.insert(at, key.to_vec());
                        leaf.payloads.insert(at, p);
                    }
                }
            }
        }
        self.publish(pager, path)
    }

    /// Writes the copied path back up, splitting where a page no longer fits.
    fn publish(&mut self, pager: &mut Pager, mut path: Vec<(u64, CowNode, usize)>) -> Result<()> {
        let mut level = path.len() - 1;
        let cap = pager.payload_cap() + crate::container::PAGE_HEADER_BYTES;
        let mut replacements = self.split(cap, path[level].1.clone())?;
        if path[level].0 != 0 {
            self.freed.push(path[level].0);
        }

        while level > 0 {
            let mut children = Vec::with_capacity(replacements.len());
            for n in &replacements {
                children.push((self.write(pager, n)?, n.clone()));
            }
            let (parent_id, parent, child_index) = &mut path[level - 1];
            if *parent_id != 0 {
                self.freed.push(*parent_id);
            }
            let ci = *child_index;
            parent.keys.remove(ci);
            parent.payloads.remove(ci);
            let mut at = ci;
            for (id, n) in &children {
                if n.count() == 0 {
                    continue; // an emptied page is unlinked, not written
                }
                parent.keys.insert(at, n.keys[0].clone());
                parent.payloads.insert(at, child_payload(*id, n.subtree_entries()));
                at += 1;
            }
            replacements = self.split(cap, parent.clone())?;
            level -= 1;
        }

        if replacements.len() == 1 {
            let only = &replacements[0];
            self.root = if only.count() == 0 {
                0
            } else if !only.is_leaf && only.count() == 1 {
                // A root with one child is a chain of one; its child is already
                // a valid root, so the level is dropped rather than written.
                child_of(&only.payloads[0])?.0
            } else {
                self.write(pager, only)?
            };
            return Ok(());
        }
        // The root split: a new level above it.
        let mut keys = Vec::new();
        let mut payloads = Vec::new();
        for n in &replacements {
            if n.count() == 0 {
                continue;
            }
            keys.push(n.keys[0].clone());
            let id = self.write(pager, n)?;
            payloads.push(child_payload(id, n.subtree_entries()));
        }
        let node = CowNode { is_leaf: false, keys, payloads };
        self.root = self.write(pager, &node)?;
        Ok(())
    }

    fn split(&self, page_size: usize, n: CowNode) -> Result<Vec<CowNode>> {
        if n.count() == 0 || node_page_bytes(&n.keys, &n.payloads) <= page_size {
            return Ok(vec![n]);
        }
        if n.count() == 1 {
            return invalid(format!(
                "a single cell of {} B does not fit a {page_size} B page",
                node_page_bytes(&n.keys, &n.payloads)
            ));
        }
        let mid = n.count() / 2;
        let left = CowNode {
            is_leaf: n.is_leaf,
            keys: n.keys[..mid].to_vec(),
            payloads: n.payloads[..mid].to_vec(),
        };
        let right = CowNode {
            is_leaf: n.is_leaf,
            keys: n.keys[mid..].to_vec(),
            payloads: n.payloads[mid..].to_vec(),
        };
        let mut out = self.split(page_size, left)?;
        out.extend(self.split(page_size, right)?);
        Ok(out)
    }

    pub fn height(&self, pager: &mut Pager) -> Result<usize> {
        if self.root == 0 {
            return Ok(0);
        }
        let mut h = 1;
        let mut n = self.load(pager, self.root)?;
        while !n.is_leaf {
            h += 1;
            n = self.load(pager, child_of(&n.payloads[0])?.0)?;
        }
        Ok(h)
    }
}

fn find(keys: &[Vec<u8>], key: &[u8]) -> Option<usize> {
    let (mut lo, mut hi) = (0isize, keys.len() as isize - 1);
    while lo <= hi {
        let mid = ((lo + hi) / 2) as usize;
        match keys[mid].as_slice().cmp(key) {
            std::cmp::Ordering::Equal => return Some(mid),
            std::cmp::Ordering::Less => lo = mid as isize + 1,
            std::cmp::Ordering::Greater => hi = mid as isize - 1,
        }
    }
    None
}

fn lower_bound(keys: &[Vec<u8>], key: &[u8]) -> usize {
    let (mut lo, mut hi) = (0usize, keys.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        if keys[mid].as_slice() < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// The child to descend into: the last separator <= `key`, clamped to 0. The
/// clamp is what lets a separator be a child's exact minimum key — the descent
/// only needs a separator never to *exceed* its subtree's minimum.
fn descend(keys: &[Vec<u8>], key: &[u8]) -> usize {
    let (mut lo, mut hi) = (0isize, keys.len() as isize - 1);
    let mut ans = -1isize;
    while lo <= hi {
        let mid = ((lo + hi) / 2) as usize;
        if keys[mid].as_slice() <= key {
            ans = mid as isize;
            lo = mid as isize + 1;
        } else {
            hi = mid as isize - 1;
        }
    }
    if ans < 0 {
        0
    } else {
        ans as usize
    }
}
