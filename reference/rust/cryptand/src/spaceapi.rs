//! `13-operations.md` §5 — the compaction and space-management API.
//!
//! **All of it MUST be incremental and resumable**, and none may block longer
//! than `max_foreground_stall_ms` per step (`12-profiles.md` §4).

use crate::container::Durability;
use crate::engine::Engine;
use crate::error::{invalid, Result};
use crate::profile::ProfileConstants;

/// One bounded unit of work, and whether more remains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    More,
    Done,
}

pub trait SpaceApi {
    fn compact_step(&mut self) -> Result<Step>;
    fn collect_pass(&mut self) -> Result<Step>;
    fn cluster_pass(&mut self) -> Result<Step>;
    fn shrink(&mut self) -> Result<u64>;
    fn reprofile(&mut self, to: crate::container::Profile) -> Result<()>;
    fn set_profile(&mut self, to: crate::container::Profile) -> Result<()>;
}

impl SpaceApi for Engine {
    fn compact_step(&mut self) -> Result<Step> {
        let budget = self.profile.compaction_step_bytes as u64;
        let before = self.refs_at(0)?.len();
        self.maybe_compact(Some(budget))?;
        let after = self.refs_at(0)?.len();
        Ok(if before == after && self.pick_compaction()?.is_none() { Step::Done } else { Step::More })
    }

    fn collect_pass(&mut self) -> Result<Step> {
        self.collect()?;
        Ok(if self.locality_debt() * 100.0 <= self.sb.locality_debt_pct as f64 {
            Step::Done
        } else {
            Step::More
        })
    }

    /// §5's `cluster()` — drive `locality_debt` back under its bound.
    fn cluster_pass(&mut self) -> Result<Step> {
        self.collect_while_over_debt(1)?;
        Ok(if self.locality_debt() * 100.0 <= self.sb.locality_debt_pct as f64 {
            Step::Done
        } else {
            Step::More
        })
    }

    /// `01-container.md` §6 — relocate live extents downward and truncate.
    /// It is an ordinary sequence of commits and is interruptible.
    fn shrink(&mut self) -> Result<u64> {
        let before = self.pager.page_count;
        // Everything at or beyond the highest reachable page is debris or free
        // space; truncating to it is the safe half of relocation, and the only
        // half that never rewrites a page a live superblock references.
        let mut high = 2u64;
        for r in self.all_refs()? {
            high = high.max(r.start_page + r.pages as u64);
        }
        for s in self.vlog_stats.values() {
            high = high.max(s.start_page + s.pages as u64);
        }
        let mut pages = Vec::new();
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
            let tree = crate::cow::CowTree::new(t.tree_id, t.root);
            tree.reachable(&mut self.pager, &mut pages)?;
        }
        for p in pages {
            high = high.max(p + 1);
        }
        if high < before {
            self.pager.set_page_count(high);
            self.pager.truncate_to_page_count()?;
            self.commit(Durability::Sync)?;
        }
        Ok(before.saturating_sub(self.pager.page_count))
    }

    /// `12-profiles.md` §6 — `set_profile(p)` writes the new constants into the
    /// superblock; from that commit onward, new writes follow them. Existing
    /// data converts lazily, through ordinary compaction.
    fn set_profile(&mut self, to: crate::container::Profile) -> Result<()> {
        let c = ProfileConstants::of(to);
        if c.page_size != self.pager.page_size {
            return invalid(format!(
                "page_size is fixed at creation: {} cannot become {} \
                 (spec/12-profiles.md section 6). Use a profile pair that shares a page size.",
                self.pager.page_size, c.page_size
            ));
        }
        c.apply_to(&mut self.sb)?;
        self.profile = ProfileConstants::from_superblock(&self.sb);
        self.policy = crate::engine::LevelPolicy {
            l0_trigger: self.sb.l0_trigger,
            tier_width: self.sb.tier_width,
            overlap_bound: self.sb.overlap_bound,
            level_count: self.sb.level_count,
            fanout: self.sb.fanout,
        };
        self.commit(Durability::Sync)?;
        Ok(())
    }

    /// §5's `reprofile()` — force the conversion eagerly rather than waiting
    /// for organic compaction. Incremental and resumable.
    fn reprofile(&mut self, to: crate::container::Profile) -> Result<()> {
        self.set_profile(to)?;
        self.compact()
    }
}
