//! `13-operations.md` §3 — repair. Verification reports; repair fixes.
//!
//! **The manifest is deliberately redundant with the segment headers.** That
//! duplication costs a few dozen bytes per segment and is what makes the single
//! most likely catastrophic failure — a damaged manifest root — a
//! scan-and-rebuild rather than a total loss. `group` is in the header for no
//! other reason, because it is part of the manifest key and nothing else would
//! recover it.

use crate::container::{page_type, PageHeader};
use crate::engine::Engine;
use crate::error::Result;
use crate::manifest::{Manifest, SegmentRef};
use crate::segment::{Segment, SegmentHeader};
use crate::vlog::{self, VlogHead, VlogStats};

#[derive(Clone, Debug, Default)]
pub struct RepairReport {
    pub segments_recovered: u64,
    pub leaks_reclaimed: u64,
    pub vlog_entries_rebuilt: u64,
    pub notes: Vec<String>,
}

pub trait EngineRepair {
    fn rebuild_manifest(&mut self) -> Result<RepairReport>;
    fn rebuild_vlog_stats(&mut self) -> Result<RepairReport>;
    fn reclaim_leaks(&mut self) -> Result<RepairReport>;
}

impl EngineRepair for Engine {
    /// §3 — rebuild the manifest by scanning the file for `SEGMENT_HEADER`
    /// pages and reading their `level`, `group`, key bounds and seq range.
    fn rebuild_manifest(&mut self) -> Result<RepairReport> {
        let mut rep = RepairReport::default();
        let mut fresh = Manifest::new(0);
        fresh.tree.commit_id = self.sb.commit_id;
        // A retired segment's extent is freed but is never overwritten until it
        // is reallocated, so the file still holds its `SEGMENT_HEADER` page. The
        // free tree is a separate root and survives a lost manifest, so it is
        // what tells a rebuild which of those headers are debris.
        let freed: std::collections::HashSet<u64> =
            self.pager.free_list().iter().map(|e| e.start_page).collect();
        let mut page = 2u64;
        while page < self.pager.page_count {
            let raw = match self.pager.read_page(page) {
                Ok(p) => p,
                Err(_) => {
                    page += 1;
                    continue;
                }
            };
            let Ok(h) = PageHeader::verify(&raw, page) else {
                page += 1;
                continue;
            };
            if h.page_type != page_type::SEGMENT_HEADER {
                page += if h.extent_pages > 1 { h.extent_pages as u64 } else { 1 };
                continue;
            }
            let Ok(sh) = SegmentHeader::parse(&raw) else {
                page += 1;
                continue;
            };
            let pages = h.extent_pages.max(1);
            if freed.contains(&page) {
                page += pages as u64;
                continue;
            }
            let extent = self.pager.read_extent(page, pages)?;
            match Segment::open(extent, self.pager.page_size) {
                Ok(seg) => {
                    let r = SegmentRef::of(&seg, sh.level, sh.group, page);
                    if fresh.add(&mut self.pager, &r).is_ok() {
                        rep.segments_recovered += 1;
                    }
                }
                Err(e) => rep.notes.push(format!("segment header at page {page}: {e}")),
            }
            page += pages as u64;
        }
        self.manifest = fresh;
        Ok(rep)
    }

    /// §3 — a lost tree-7 entry is rebuilt by scanning the segment's records
    /// forward from `data_offset`, accepting the longest prefix whose
    /// per-record CRCs all validate, and setting `bytes` to the end of it.
    fn rebuild_vlog_stats(&mut self) -> Result<RepairReport> {
        let mut rep = RepairReport::default();
        let mut page = 2u64;
        let mut found: Vec<(u64, VlogStats)> = Vec::new();
        while page < self.pager.page_count {
            let raw = match self.pager.read_page(page) {
                Ok(p) => p,
                Err(_) => {
                    page += 1;
                    continue;
                }
            };
            let Ok(h) = PageHeader::verify(&raw, page) else {
                page += 1;
                continue;
            };
            if h.page_type != page_type::VLOG_SEGMENT {
                page += if h.extent_pages > 1 { h.extent_pages as u64 } else { 1 };
                continue;
            }
            let pages = h.extent_pages.max(1);
            let head = VlogHead::parse(&raw)?;
            let mut off = 0u64;
            let mut records = 0u64;
            let capacity = pages as u64 * self.pager.page_size as u64 - head.data_offset as u64;
            loop {
                let at = page * self.pager.page_size as u64 + head.data_offset as u64 + off;
                let want = ((capacity - off) as usize).min(1 << 20);
                if want == 0 {
                    break;
                }
                let raw = match self.pager.read_at(at, want) {
                    Ok(b) => b,
                    Err(_) => break,
                };
                match vlog::decode_record(&raw, head.encrypted) {
                    Ok(rec) => {
                        off += rec.total_len as u64;
                        records += 1;
                    }
                    Err(_) => break,
                }
            }
            found.push((
                head.segment_id,
                VlogStats {
                    segment_id: head.segment_id,
                    bytes: off,
                    records,
                    // A rebuilt segment is sealed: `14-security.md` §4.3
                    // forbids re-appending to a segment this session did not
                    // open, and a repair is by definition a new session.
                    sealed: true,
                    clustered: false,
                    min_key: None,
                    max_key: None,
                    start_page: page,
                    pages,
                    // §6.7: liveness may overstate and MUST NOT understate, so
                    // a rebuild starts from "everything live" and lets the next
                    // compaction lower it.
                    live_bytes: off,
                    live_records: records,
                    tier: head.tier as u8,
                    heat: head.heat as u8,
                    created_seq: head.created_seq,
                    last_gc_seq: 0,
                },
            ));
            page += pages as u64;
        }
        for (id, s) in found {
            self.vlog_stats.insert(id, s);
            rep.vlog_entries_rebuilt += 1;
        }
        let ids: Vec<u64> = self.vlog_stats.keys().copied().collect();
        for id in ids {
            self.write_vlog_stats_public(id)?;
        }
        Ok(rep)
    }

    /// §3 — leaked extents (neither reachable nor free) are added to the free
    /// tree. A double-allocation is **not** repairable and is reported instead.
    fn reclaim_leaks(&mut self) -> Result<RepairReport> {
        use crate::verify::{Class, EngineVerify};
        let mut rep = RepairReport::default();
        let report = self.verify()?;
        for f in report.of(Class::Leak) {
            if let Some(p) = f.what.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok()) {
                self.pager.free_extent(p, 1, self.sb.commit_id);
                rep.leaks_reclaimed += 1;
            }
        }
        for f in report.of(Class::Corruption) {
            if f.what.contains("double-allocated") || f.what.contains("allocated to both") {
                rep.notes.push(format!("NOT REPAIRABLE: {}", f.what));
            }
        }
        for f in report.of(Class::Tampering) {
            // Repairing tampered data is laundering it.
            rep.notes.push(format!("TAMPERING, not repaired: {}", f.what));
        }
        Ok(rep)
    }
}

impl Engine {
    pub fn write_vlog_stats_public(&mut self, id: u64) -> Result<()> {
        use crate::cke;
        use crate::value::{NumType, Value};
        let Some(s) = self.vlog_stats.get(&id).cloned() else { return Ok(()) };
        let key = cke::encode(&Value::Int { w: NumType::U64, neg: false, mag: id as u128 })?;
        let v = crate::engine::encode_vlog_stats(&s);
        let mut t = std::mem::replace(
            &mut self.vlog_stats_tree,
            crate::cow::CowTree::new(crate::catalog::tree_id::VLOG_STATS, 0),
        );
        t.commit_id = self.sb.commit_id;
        let r = t.put(&mut self.pager, &key, &v);
        self.vlog_stats_tree = t;
        r
    }
}
