//! `01-container.md` §9 and `04-segments.md` §11 — the verification pass.
//!
//! Verification **reports**; `13-operations.md` §3 specifies repair. The three
//! outcome classes are kept apart deliberately: a leak is repairable, a
//! double-allocation is corruption, and **a failed AEAD tag or `sb_mac` is
//! neither** — it is tampering, because "your disk has a bad sector" and
//! "someone edited your database" call for different responses.

use std::collections::{HashMap, HashSet};

use crate::container::PageHeader;
use crate::engine::Engine;
use crate::error::Result;
use crate::segment::{parse_internal_key, user_part};
use crate::vlog::{self, VlogPointer};

/// The page ids of an extent, refused rather than walked when it runs past the
/// end of the file.
///
/// `start_page` and `pages` come out of the file and are untrusted. Each caller
/// below inserts one map entry per page in the range, so an extent claiming
/// 0xFFFF_FFFF pages is four billion inserts and an allocation failure —
/// `14-security.md` §9.1's "MUST bounds-check ... **before allocating**"
/// applies to the verifier's own working set, not only to its decoders. The
/// leak report at the end of `page_accounting` already caps itself for exactly
/// this reason; these three callers did not.
fn extent_pages(start_page: u64, pages: u64, page_count: u64) -> Option<std::ops::Range<u64>> {
    if pages > page_count || start_page > page_count || start_page + pages > page_count {
        return None;
    }
    Some(start_page..start_page + pages)
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Corruption,
    Tampering,
    Leak,
    Warning,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub class: Class,
    pub what: String,
}

#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    pub findings: Vec<Finding>,
    pub segments: u64,
    pub entries: u64,
    pub pages_reachable: u64,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.findings.is_empty()
    }
    fn add(&mut self, class: Class, what: impl Into<String>) {
        self.findings.push(Finding { class, what: what.into() });
    }
    pub fn of(&self, class: Class) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.class == class).collect()
    }
}

pub trait EngineVerify {
    fn verify(&mut self) -> Result<VerifyReport>;
}

impl EngineVerify for Engine {
    fn verify(&mut self) -> Result<VerifyReport> {
        let mut r = VerifyReport::default();

        // Step 1 — validate both superblocks.
        for slot in 0..2u8 {
            match self.pager.read_slot(slot) {
                Ok(b) => {
                    if let Err(e) = crate::container::Superblock::parse(&b) {
                        // One invalid slot is normal on a fresh file: slots are
                        // written alternately, so slot B is empty until commit 2.
                        if self.sb.commit_id > 2 {
                            r.add(Class::Corruption, format!("superblock slot {slot}: {e}"));
                        }
                    }
                }
                Err(e) => r.add(Class::Corruption, format!("superblock slot {slot}: {e}")),
            }
        }
        // Step 8 — with a key, `sb_mac` is verified. Without one, steps 1–7
        // still run: that is the point of leaving headers in the clear.
        if let Some(ring) = &self.keys {
            if let Err(e) = ring.verify_superblock(&self.sb) {
                r.add(Class::Tampering, e.to_string());
            }
        }

        let refs = self.all_refs()?;
        r.segments = refs.len() as u64;
        let mut reachable: HashMap<u64, u64> = HashMap::new(); // page -> owner
        // Pages 0 and 1 are the superblock slots.
        reachable.insert(0, u64::MAX);
        reachable.insert(1, u64::MAX);

        for rf in &refs {
            let seg = match self.segment(rf) {
                Ok(s) => s,
                Err(e) => {
                    r.add(Class::Corruption, format!("segment {}: {e}", rf.segment_id));
                    continue;
                }
            };
            // Step 2 — page checksums.
            if let Err(e) = seg.verify_checksums() {
                r.add(Class::Corruption, format!("segment {}: {e}", rf.segment_id));
                continue;
            }
            // §11 invariant 5 — the manifest entry, including `level` and
            // `group`, matches the header. The redundancy has to be *complete*
            // for `13-operations.md` §3's rebuild claim to hold.
            let h = &seg.header;
            if h.level != rf.level || h.group != rf.group || h.segment_id != rf.segment_id {
                r.add(
                    Class::Corruption,
                    format!(
                        "segment {} header says L{}.g{} but the manifest says L{}.g{}",
                        rf.segment_id, h.level, h.group, rf.level, rf.group
                    ),
                );
            }
            if h.min_seq != rf.min_seq || h.max_seq != rf.max_seq || h.entry_count != rf.entries {
                r.add(
                    Class::Corruption,
                    format!("segment {} header and manifest disagree on seq or entry counts", rf.segment_id),
                );
            }

            // §11 invariants 1, 5, 7 and §9 step 4.
            let filter = seg.filter()?;
            let mut prev: Option<Vec<u8>> = None;
            let mut count = 0u64;
            let mut min_seq = u64::MAX;
            let mut max_seq = 0u64;
            for rec in seg.iter() {
                let rec = rec?;
                count += 1;
                if let Some(p) = &prev {
                    if p >= &rec.internal_key {
                        r.add(
                            Class::Corruption,
                            format!("segment {}: internal keys do not strictly increase", rf.segment_id),
                        );
                    }
                }
                prev = Some(rec.internal_key.clone());
                let parsed = parse_internal_key(&rec.internal_key)?;
                min_seq = min_seq.min(parsed.seq);
                max_seq = max_seq.max(parsed.seq);
                // Invariant 7 — every key in a segment passes its filter.
                if let Some(f) = &filter {
                    if !f.may_contain(user_part(&rec.internal_key)) {
                        r.add(
                            Class::Corruption,
                            format!(
                                "segment {}: a key it holds fails its own filter (a false negative)",
                                rf.segment_id
                            ),
                        );
                    }
                }
                // §11 invariant 5 — min_key/max_key *bound* the contents.
                if rec.internal_key < rf.min_key || rec.internal_key > rf.max_key {
                    r.add(
                        Class::Corruption,
                        format!("segment {}: an entry falls outside its declared key bounds", rf.segment_id),
                    );
                }
                // §9 step 4 and §11 invariant 8.
                if rec.value_kind == crate::segment::value_kind::VLOG {
                    let p = VlogPointer::parse(&rec.value)?;
                    match self.vlog_stats.get(&p.segment_id).cloned() {
                        None => r.add(
                            Class::Corruption,
                            format!("VLOG pointer names unknown value-log segment {}", p.segment_id),
                        ),
                        Some(s) => {
                            if let Err(e) = vlog::check_pointer_in_bounds(&p, &s, vlog::DATA_OFFSET) {
                                r.add(Class::Corruption, e.to_string());
                            } else {
                                match self.read_vlog_record(&p) {
                                    Err(e) => r.add(Class::Corruption, e.to_string()),
                                    Ok(vr) => {
                                        let want = &user_part(&rec.internal_key)[4..];
                                        if self.sb.cipher == 0 && vr.key != want {
                                            r.add(
                                                Class::Corruption,
                                                format!(
                                                    "VLOG record at ({}, {}) stores a different key \
                                                     than the entry pointing at it",
                                                    p.segment_id, p.offset
                                                ),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            r.entries += count;
            if count != rf.entries {
                r.add(
                    Class::Corruption,
                    format!("segment {}: {count} entries walked, manifest says {}", rf.segment_id, rf.entries),
                );
            }
            if count > 0 && (min_seq != h.min_seq || max_seq != h.max_seq) {
                r.add(
                    Class::Corruption,
                    format!("segment {}: min_seq/max_seq do not match its contents", rf.segment_id),
                );
            }
            match extent_pages(rf.start_page, rf.pages as u64, self.pager.page_count) {
                None => r.add(
                    Class::Corruption,
                    format!(
                        "segment {} claims {} pages from {}, but the file holds {}",
                        rf.segment_id, rf.pages, rf.start_page, self.pager.page_count
                    ),
                ),
                Some(range) => {
                    for p in range {
                        if let Some(other) = reachable.insert(p, rf.segment_id) {
                            r.add(
                                Class::Corruption,
                                format!("page {p} is allocated to both {other} and {}", rf.segment_id),
                            );
                        }
                    }
                }
            }
        }

        // Step 3 and §3.1.1 — a levelled level's segments MUST NOT overlap **in
        // user keys**, `u32be(tree_id) || CKE(key)`. Testing this on whole
        // internal keys is wrong: they carry `~seq`, so two segments holding
        // different versions of one key test as disjoint while the level has
        // quietly stopped being disjoint and reads return stale versions.
        // §11 invariant 6: "Segments at the last level do not overlap; segments
        // within one tiered level-group do not overlap." **L0 is excluded**,
        // and deliberately: §3.1 makes it the overlapping level, one segment
        // per memtable-shard flush.
        let last = self.policy.last_level();
        for level in 1..=last {
            let mut groups: HashMap<u8, Vec<&crate::manifest::SegmentRef>> = HashMap::new();
            for rf in refs.iter().filter(|r| r.level == level) {
                groups.entry(rf.group).or_default().push(rf);
            }
            for (g, mut list) in groups {
                list.sort_by(|a, b| a.min_key.cmp(&b.min_key));
                for w in list.windows(2) {
                    let a_max = user_part(&w[0].max_key);
                    let b_min = user_part(&w[1].min_key);
                    if a_max >= b_min {
                        r.add(
                            Class::Corruption,
                            format!(
                                "segments {} and {} overlap in user keys at level {level} group {g}",
                                w[0].segment_id, w[1].segment_id
                            ),
                        );
                    }
                }
            }
        }

        // §11 invariants 8b, 9 and 10.
        for (id, s) in self.vlog_stats.clone() {
            if s.pages == 0 {
                continue;
            }
            let head_page = self.pager.read_page(s.start_page)?;
            match crate::vlog::VlogHead::parse(&head_page) {
                Err(e) => r.add(Class::Corruption, format!("value-log segment {id}: {e}")),
                Ok(h) => {
                    if h.segment_id != s.segment_id
                        || h.tier as u8 != s.tier
                        || h.heat as u8 != s.heat
                        || h.created_seq != s.created_seq
                    {
                        r.add(
                            Class::Corruption,
                            format!(
                                "value-log segment {id}: head page and tree 7 disagree on immutable identity"
                            ),
                        );
                    }
                }
            }
            // §9 — a segment marked `clustered` really is in key order.
            if s.clustered && self.sb.cipher == 0 {
                let mut off = 0u64;
                let mut prev: Option<Vec<u8>> = None;
                while off < s.bytes {
                    let at = s.start_page * self.pager.page_size as u64
                        + vlog::DATA_OFFSET as u64
                        + off;
                    let want = ((s.bytes - off) as usize).min(1 << 20);
                    let raw = self.pager.read_at(at, want)?;
                    let rec = match vlog::decode_record(&raw, false) {
                        Ok(x) => x,
                        Err(e) => {
                            r.add(Class::Corruption, format!("value-log segment {id}: {e}"));
                            break;
                        }
                    };
                    let k = {
                        let mut v = rec.tree_id.to_be_bytes().to_vec();
                        v.extend_from_slice(&rec.key);
                        v
                    };
                    if let Some(p) = &prev {
                        if p > &k {
                            r.add(
                                Class::Corruption,
                                format!("value-log segment {id} is marked clustered but is not in key order"),
                            );
                            break;
                        }
                    }
                    prev = Some(k);
                    off += rec.total_len as u64;
                }
            }
            match extent_pages(s.start_page, s.pages as u64, self.pager.page_count) {
                None => r.add(
                    Class::Corruption,
                    format!(
                        "value-log segment {} claims {} pages from {}, but the file holds {}",
                        s.segment_id, s.pages, s.start_page, self.pager.page_count
                    ),
                ),
                Some(range) => {
                    for p in range {
                        if let Some(other) = reachable.insert(p, u64::MAX - 1) {
                            if other != u64::MAX - 1 {
                                r.add(Class::Corruption, format!("page {p} is double-allocated"));
                            }
                        }
                    }
                }
            }
        }

        // Step 7 — reconcile reachable pages against the free tree, and report
        // leaks (neither reachable nor free) and double-allocations.
        for t in [
            &self.catalog.tree,
            &self.catalog.by_id,
            &self.attributes.tree,
            &self.manifest.tree,
            &self.vlog_stats_tree,
            &self.checkpoints,
            &self.changefeed,
            &self.freelist,
        ] {
            let mut pages = Vec::new();
            let tree = crate::cow::CowTree::new(t.tree_id, t.root);
            tree.reachable(&mut self.pager, &mut pages)?;
            for p in pages {
                if let Some(other) = reachable.insert(p, u64::MAX - 2) {
                    if other != u64::MAX - 2 {
                        r.add(Class::Corruption, format!("page {p} is double-allocated"));
                    }
                }
            }
        }
        let page_count = self.pager.page_count;
        let free: HashSet<u64> = self
            .pager
            .free_list()
            .into_iter()
            .filter_map(|e| extent_pages(e.start_page, e.pages as u64, page_count))
            .flatten()
            .collect();
        r.pages_reachable = reachable.len() as u64;
        for p in 2..self.pager.page_count {
            if !reachable.contains_key(&p) && !free.contains(&p) {
                r.add(Class::Leak, format!("page {p} is neither reachable nor free"));
            }
        }

        // §11 invariant 11.
        let debt = self.locality_debt() * 100.0;
        if debt > self.sb.locality_debt_pct as f64 {
            r.add(
                Class::Warning,
                format!(
                    "locality_debt {debt:.1} % is above locality_debt_pct {} %",
                    self.sb.locality_debt_pct
                ),
            );
        }
        Ok(r)
    }
}

/// A single page's checksum, used by containment: a caller that reads a page
/// and gets this error names the segment and quarantines it.
pub fn verify_page(page: &[u8], page_id: u64) -> Result<PageHeader> {
    PageHeader::verify(page, page_id)
}
