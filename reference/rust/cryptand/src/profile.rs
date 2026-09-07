//! `12-profiles.md` — device profiles.
//!
//! **§3 is the load-bearing rule**: the superblock's `profile` field is
//! advisory metadata. A reader MUST NOT change its behaviour based on it and
//! MUST NOT refuse a file because of it. Every profile-dependent constant is
//! either its own superblock field or purely about a writer's runtime
//! behaviour, which leaves no trace in the file.

use crate::container::{Profile, Superblock};
use crate::error::{invalid, Result};

/// §1's table, plus the runtime constants that never reach the file.
#[derive(Clone, Copy, Debug)]
pub struct ProfileConstants {
    pub profile: Profile,
    pub page_size: usize,
    pub page_cache_bytes: usize,
    pub memtable_bytes: usize,
    pub memtable_entries: usize,
    pub memtable_shards: u8,
    pub vlog_min: u32,
    pub blob_threshold: u32,
    pub l0_trigger: u8,
    pub fanout: u8,
    pub tier_width: u8,
    pub overlap_bound: u8,
    pub level_count: u8,
    pub segment_target_bytes: u32,
    pub vlog_segment_bytes: u32,
    /// `12-profiles.md`'s `page_codec` row and `01-container.md` §7.
    ///
    /// **0 in every profile, and measured rather than assumed.** A page is a
    /// fixed-size slot addressed by page id, so a compressed page occupies the
    /// same slot and is written with the same `page_size`-byte write:
    /// 20 000 documents at codec 0 and codec 1 produced identical bytes to
    /// device, identical page count and identical file size. It cost CPU and
    /// leaked compressibility through the cleartext `payload_len`.
    ///
    /// The write path stays implemented and a writer may set this field
    /// deliberately; the **read** path is not optional, because another SDK or
    /// a future minor version may write a compressed page and refusing it
    /// turns a readable file into an unreadable one.
    pub page_codec: u8,
    pub filter_bits_upper: u8,
    pub filter_bits_last: u8,
    pub vlog_space_target_pct: u32,
    pub locality_debt_pct: u8,
    pub readahead_window: u32,
    pub compaction_threads: u8,
    pub compaction_step_bytes: u32,
    pub max_foreground_stall_ms: u32,
    pub argon2_t_cost: u32,
    pub argon2_m_cost_kib: u32,
    pub argon2_parallelism: u32,
}

impl ProfileConstants {
    pub fn of(p: Profile) -> ProfileConstants {
        match p {
            Profile::Mobile => ProfileConstants {
                profile: p,
                page_size: 4096,
                page_cache_bytes: 4 << 20,
                memtable_bytes: 2 << 20,
                memtable_entries: 2000,
                memtable_shards: 1,
                // §2.1: 1024, not 4096 — `vlog_min` MUST be <= page_size / 4,
                // and mobile uses 4 KiB pages. The earlier 4096 would have sent
                // every 1–4 KiB value into an overflow chain: two I/Os, exactly
                // the cost inlining was chosen to avoid.
                vlog_min: 1024,
                blob_threshold: 65536,
                l0_trigger: 2,
                fanout: 4,
                tier_width: 2,
                overlap_bound: 1,
                level_count: 4,
                segment_target_bytes: 2 << 20,
                vlog_segment_bytes: 4 << 20,
                page_codec: crate::codec::NONE,
                filter_bits_upper: 12,
                filter_bits_last: 10,
                vlog_space_target_pct: 120,
                locality_debt_pct: 20,
                readahead_window: 128,
                compaction_threads: 1,
                compaction_step_bytes: 256 << 10,
                max_foreground_stall_ms: 8,
                argon2_t_cost: 3,
                argon2_m_cost_kib: 65536,
                argon2_parallelism: 1,
            },
            Profile::Tablet => ProfileConstants {
                profile: p,
                page_size: 4096,
                page_cache_bytes: 16 << 20,
                memtable_bytes: 8 << 20,
                memtable_entries: 8000,
                memtable_shards: 2,
                vlog_min: 1024,
                blob_threshold: 131072,
                l0_trigger: 4,
                fanout: 6,
                tier_width: 3,
                overlap_bound: 2,
                level_count: 4,
                segment_target_bytes: 8 << 20,
                vlog_segment_bytes: 16 << 20,
                page_codec: crate::codec::NONE,
                filter_bits_upper: 14,
                filter_bits_last: 10,
                vlog_space_target_pct: 130,
                locality_debt_pct: 20,
                readahead_window: 256,
                compaction_threads: 2,
                compaction_step_bytes: 1 << 20,
                max_foreground_stall_ms: 8,
                argon2_t_cost: 3,
                argon2_m_cost_kib: 131072,
                argon2_parallelism: 2,
            },
            Profile::Server => ProfileConstants {
                profile: p,
                page_size: 16384,
                page_cache_bytes: 512 << 20,
                memtable_bytes: 256 << 20,
                memtable_entries: 200000,
                memtable_shards: 32,
                vlog_min: 256,
                blob_threshold: 262144,
                l0_trigger: 8,
                fanout: 10,
                tier_width: 6,
                overlap_bound: 3,
                level_count: 4,
                segment_target_bytes: 128 << 20,
                vlog_segment_bytes: 256 << 20,
                page_codec: crate::codec::NONE,
                filter_bits_upper: 16,
                filter_bits_last: 10,
                vlog_space_target_pct: 150,
                locality_debt_pct: 25,
                readahead_window: 1024,
                compaction_threads: 8,
                compaction_step_bytes: 32 << 20,
                max_foreground_stall_ms: 100,
                argon2_t_cost: 4,
                argon2_m_cost_kib: 262144,
                argon2_parallelism: 4,
            },
            // §2.3 — the balanced default, and the profile the rest of the
            // specification quotes.
            _ => ProfileConstants {
                profile: Profile::Desktop,
                page_size: 8192,
                page_cache_bytes: 64 << 20,
                memtable_bytes: 32 << 20,
                memtable_entries: 20000,
                memtable_shards: 8,
                vlog_min: 256,
                blob_threshold: 262144,
                l0_trigger: 4,
                fanout: 8,
                tier_width: 4,
                overlap_bound: 2,
                level_count: 4,
                segment_target_bytes: 32 << 20,
                vlog_segment_bytes: 64 << 20,
                page_codec: crate::codec::NONE,
                filter_bits_upper: 16,
                filter_bits_last: 10,
                vlog_space_target_pct: 150,
                locality_debt_pct: 20,
                readahead_window: 256,
                compaction_threads: 4,
                compaction_step_bytes: 8 << 20,
                max_foreground_stall_ms: 25,
                argon2_t_cost: 4,
                argon2_m_cost_kib: 262144,
                argon2_parallelism: 4,
            },
        }
    }

    /// §3 — a reader uses the *values* in the superblock, never the profile
    /// name. This is that rule as code: the file's own fields win, and only
    /// the runtime-only constants come from the named profile.
    pub fn from_superblock(sb: &Superblock) -> ProfileConstants {
        let mut c = ProfileConstants::of(Profile::from_code(sb.profile));
        c.page_size = sb.page_size();
        c.vlog_min = sb.vlog_min;
        c.blob_threshold = sb.blob_threshold;
        c.l0_trigger = sb.l0_trigger;
        c.fanout = sb.fanout;
        c.tier_width = sb.tier_width;
        c.overlap_bound = sb.overlap_bound;
        c.level_count = sb.level_count;
        c.memtable_shards = sb.memtable_shards;
        c.segment_target_bytes = sb.segment_target_bytes;
        c.vlog_segment_bytes = sb.vlog_segment_bytes;
        c.page_codec = sb.page_codec;
        c.filter_bits_upper = sb.filter_bits_upper;
        c.filter_bits_last = sb.filter_bits_last;
        c.vlog_space_target_pct = sb.vlog_space_target_pct;
        c.locality_debt_pct = sb.locality_debt_pct;
        c.readahead_window = sb.readahead_window;
        c
    }

    /// §6 — `set_profile` writes the new constants into the superblock; from
    /// that commit onward, new writes follow them. Existing data converts
    /// lazily, through ordinary compaction.
    ///
    /// **`page_size` cannot change.** It is fixed at creation, and changing it
    /// requires a full copy through `13-operations.md` §2 — which is why
    /// `11-conformance.md` §6's profile round-trip test must use a pair that
    /// shares a page size (`mobile` <-> `tablet`).
    pub fn apply_to(&self, sb: &mut Superblock) -> Result<()> {
        if self.page_size != sb.page_size() {
            return invalid(format!(
                "page_size is fixed at creation: cannot change {} -> {} \
                 (spec/12-profiles.md section 6)",
                sb.page_size(),
                self.page_size
            ));
        }
        crate::limits::check_vlog_min(self.vlog_min, self.page_size)?;
        sb.profile = self.profile.code();
        sb.vlog_min = self.vlog_min;
        sb.blob_threshold = self.blob_threshold;
        sb.l0_trigger = self.l0_trigger;
        sb.fanout = self.fanout;
        sb.tier_width = self.tier_width;
        sb.overlap_bound = self.overlap_bound;
        sb.level_count = self.level_count;
        sb.memtable_shards = self.memtable_shards;
        sb.segment_target_bytes = self.segment_target_bytes;
        sb.vlog_segment_bytes = self.vlog_segment_bytes;
        sb.page_codec = self.page_codec;
        sb.filter_bits_upper = self.filter_bits_upper;
        sb.filter_bits_last = self.filter_bits_last;
        sb.vlog_space_target_pct = self.vlog_space_target_pct;
        sb.locality_debt_pct = self.locality_debt_pct;
        sb.readahead_window = self.readahead_window;
        Ok(())
    }
}

/// §5 — the three host hints. Only the host knows when spending battery and
/// thermal headroom on compaction is acceptable.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostHints {
    pub idle: bool,
    pub charging: bool,
    pub thermal_pressure: bool,
}

impl HostHints {
    /// §5: non-urgent maintenance is deferred until `idle` or `charging` on
    /// mobile and tablet — but the engine must never deadlock waiting for a
    /// hint that never arrives, so backpressure-driven work is never deferred.
    pub fn may_run_background(&self, profile: Profile, urgent: bool) -> bool {
        if urgent {
            return true;
        }
        match profile {
            Profile::Mobile | Profile::Tablet => self.idle || self.charging,
            _ => true,
        }
    }

    pub fn compaction_threads(&self, c: &ProfileConstants) -> u8 {
        if self.thermal_pressure {
            1
        } else {
            c.compaction_threads
        }
    }
}
