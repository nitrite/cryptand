//! `13-operations.md` §6 — the required metrics.
//!
//! **A metric an implementation cannot compute MUST be reported as
//! unavailable, by name, and MUST NOT be given a plausible-looking value.** A
//! fabricated answer defeats this section more thoroughly than a missing one,
//! because a caller cannot tell the two apart: `page_cache_hit_rate: 1.0` from
//! an engine with no page-cache accounting reads exactly like a perfect cache.

use crate::engine::Engine;
use crate::error::Result;
use crate::vlog;
use std::collections::BTreeMap;

/// A metric value, or the reason it is not available.
#[derive(Clone, Debug, PartialEq)]
pub enum Metric {
    Count(u64),
    Ratio(f64),
    Text(String),
    List(Vec<String>),
    /// Reported by name, never as a plausible value.
    Unavailable(&'static str),
}

impl std::fmt::Display for Metric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Metric::Count(v) => write!(f, "{v}"),
            Metric::Ratio(v) => write!(f, "{v:.4}"),
            Metric::Text(v) => write!(f, "{v}"),
            Metric::List(v) => write!(f, "[{}]", v.join(", ")),
            Metric::Unavailable(why) => write!(f, "unavailable ({why})"),
        }
    }
}

pub fn percentile(samples: &[u32], p: f64) -> u32 {
    if samples.is_empty() {
        return 0;
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    let i = (((s.len() - 1) as f64) * p).round() as usize;
    s[i]
}

pub trait Metrics {
    fn metrics(&mut self) -> Result<BTreeMap<String, Metric>>;
}

impl Metrics for Engine {
    fn metrics(&mut self) -> Result<BTreeMap<String, Metric>> {
        let mut m = BTreeMap::new();
        let c = self.counters.clone();

        // Write path
        m.insert("bytes_written_logical".into(), Metric::Count(c.bytes_written_logical));
        m.insert("bytes_written_device".into(), Metric::Count(self.pager.bytes_written_device));
        m.insert("write_amp_value".into(), Metric::Count(c.write_amp_value));
        m.insert("write_amp_key_index".into(), Metric::Count(c.write_amp_key_index));
        m.insert("write_amp_gc".into(), Metric::Count(c.write_amp_gc));
        let bp = crate::txn::Backpressure::compute(&crate::txn::bounds_of(self)?);
        m.insert("backpressure_delay_ms".into(), Metric::Ratio(bp.delay_ms));
        m.insert(
            "backpressure_cause".into(),
            match bp.cause {
                Some(name) => Metric::Text(name.to_string()),
                None => Metric::Text("none".into()),
            },
        );
        // §6: "A metric an implementation cannot compute MUST be reported as
        // unavailable, by name, and MUST NOT be given a plausible-looking
        // value."
        //
        // These two were `Count(self.counters.stall_events)` against a counter
        // **nothing anywhere increments**, so they reported 0 — and 0 stalls is
        // the most plausible-looking value there is. `Backpressure::compute`
        // above derives a delay for reporting, but this engine never applies
        // one and never emits `StoreEvent::Backpressure`, which is declared and
        // never constructed. Until the foreground actually waits, there is
        // nothing to count, and §6's answer to that is this variant rather than
        // a reassuring zero.
        //
        // Java increments a real `stallEvents` in its committer; Dart reports
        // `stallViolations.length`. This is the implementation that had neither.
        m.insert(
            "stall_events".into(),
            Metric::Unavailable("this engine applies no foreground write delay, so no stall is ever entered"),
        );
        m.insert(
            "stall_total_ms".into(),
            Metric::Unavailable("this engine applies no foreground write delay, so no stall is ever entered"),
        );

        // Space
        let allocated = self.pager.page_count * self.pager.page_size as u64;
        let vlog_live: u64 = self.vlog_stats.values().map(|s| s.live_bytes).sum();
        let vlog_alloc: u64 =
            self.vlog_stats.values().map(|s| s.pages as u64 * self.pager.page_size as u64).sum();
        let stats: Vec<_> = self.vlog_stats.values().cloned().collect();
        m.insert("allocated_bytes".into(), Metric::Count(allocated));
        m.insert(
            "live_bytes".into(),
            Metric::Count(self.all_refs()?.iter().map(|r| r.value_bytes).sum::<u64>() + vlog_live),
        );
        m.insert("vlog_live_bytes".into(), Metric::Count(vlog_live));
        m.insert("vlog_allocated_bytes".into(), Metric::Count(vlog_alloc));
        m.insert("locality_debt".into(), Metric::Ratio(self.locality_debt()));
        m.insert("vlog_live_runs".into(), Metric::Count(vlog::live_runs(&stats)));
        m.insert(
            "vlog_ideal_runs".into(),
            Metric::Count(vlog::ideal_runs(&stats, self.sb.vlog_segment_bytes as u64)),
        );
        // §6: **not** derivable as `allocated - live`; a live snapshot stops
        // bytes from *becoming* dead, so those bytes never enter that
        // difference and the obvious derivation reads 0.
        m.insert("pinned_by_snapshots".into(), Metric::Count(c.pinned_by_snapshots));
        // Same shape as the two above: the counter existed and nothing wrote
        // it. This is the coarse attribution Dart and Java both make — if a
        // checkpoint holds the visible watermark down, the bytes snapshots are
        // pinning are pinned by it too. Attributing them per checkpoint needs a
        // per-checkpoint walk none of the three does, and §6's point is that
        // the number must not read 0 while a checkpoint is holding space.
        let has_checkpoint = {
            use crate::checkpoint::Checkpoints;
            !self.list_checkpoints()?.is_empty()
        };
        let c = &self.counters;
        let checkpoint_pins = if has_checkpoint { c.pinned_by_snapshots } else { 0 };
        m.insert("pinned_by_checkpoints".into(), Metric::Count(checkpoint_pins));
        // §8.3 — "that is the one place where a reassuring answer is a
        // dangerous one". Counted on the read path, where a page's own
        // `flags.ENCRYPTED` says which it is, and never inferred from `cipher`.
        // A database with no reads yet has observed nothing and says so, rather
        // than reporting the 0 that reads as "fully encrypted".
        let seen = self.pager.encrypted_pages + self.pager.unencrypted_pages;
        m.insert(
            "unencrypted_pages".into(),
            if self.sb.cipher == 0 {
                Metric::Count(0)
            } else if seen == 0 {
                Metric::Unavailable("no page has been read in this session")
            } else {
                Metric::Count(self.pager.unencrypted_pages + c.unencrypted_pages)
            },
        );
        m.insert("encrypted_pages".into(), Metric::Count(self.pager.encrypted_pages));
        m.insert("nonces_allocated".into(), Metric::Count(c.nonces_allocated));
        m.insert("nonce_floor".into(), Metric::Count(self.sb.next_nonce));

        // Read path
        let probes = self.pager.page_reads;
        let hits = c.page_cache_hits;
        let total = hits + c.page_cache_misses;
        m.insert(
            "page_cache_hit_rate".into(),
            if total == 0 {
                Metric::Unavailable("no segment fetches have happened yet")
            } else {
                Metric::Ratio(hits as f64 / total as f64)
            },
        );
        let _ = probes;
        m.insert(
            "segments_probed_per_lookup_p50".into(),
            Metric::Count(percentile(&c.segments_probed, 0.50) as u64),
        );
        m.insert(
            "segments_probed_per_lookup_p99".into(),
            Metric::Count(percentile(&c.segments_probed, 0.99) as u64),
        );
        m.insert(
            "filter_false_positive_rate".into(),
            if c.filter_probes == 0 {
                Metric::Unavailable("no filter probes have happened yet")
            } else {
                Metric::Ratio(c.filter_false_positives as f64 / c.filter_probes as f64)
            },
        );
        m.insert(
            "value_reads_per_scanned_row".into(),
            if c.scanned_rows == 0 {
                Metric::Unavailable("no rows have been scanned yet")
            } else {
                Metric::Ratio(c.value_reads as f64 / c.scanned_rows as f64)
            },
        );

        // Structure
        for level in 0..=self.policy.last_level() {
            let refs = self.refs_at(level)?;
            m.insert(format!("level_{level}_segments"), Metric::Count(refs.len() as u64));
            m.insert(
                format!("level_{level}_bytes"),
                Metric::Count(
                    refs.iter().map(|r| r.pages as u64 * self.pager.page_size as u64).sum(),
                ),
            );
        }
        m.insert(
            "oldest_snapshot_age_ms".into(),
            match self.oldest_snapshot_age_ms() {
                Some(v) => Metric::Count(v.max(0) as u64),
                None => Metric::Count(0),
            },
        );
        m.insert(
            "compaction_backlog_bytes".into(),
            Metric::Count(
                self.refs_at(0)?.iter().map(|r| r.pages as u64 * self.pager.page_size as u64).sum(),
            ),
        );
        // §4's containment is observable only by *hitting* it without this.
        // 0 is the normal state.
        m.insert("unavailable_ranges".into(), Metric::Count(self.quarantined.len() as u64));
        m.insert(
            "unavailable_range_detail".into(),
            Metric::List(
                self.quarantined
                    .values()
                    .map(|r| {
                        format!(
                            "segment {} L{} [{}..{}]",
                            r.segment_id,
                            r.level,
                            hex(&r.min_key),
                            hex(&r.max_key)
                        )
                    })
                    .collect(),
            ),
        );
        m.insert(
            "durability_achieved".into(),
            Metric::Text(self.durability_achieved.name().to_string()),
        );
        Ok(m)
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
