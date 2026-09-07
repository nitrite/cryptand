//! The engine: memtables, L0 flush, the level policy of `04-segments.md` §3.1,
//! read resolution (§4), compaction (§5), the value log (§6) and cursors (§8),
//! over the container of `01-container.md` and the commit protocol of
//! `10-transactions.md`.
//!
//! Everything structural lives here; `store.rs` layers the concurrent write
//! path of `10-transactions.md` §2 on top without duplicating any of it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::catalog::{tree_id, Attributes, Catalog};
use crate::cke;
use crate::codec;
use crate::container::{
    feature, page_flags, page_type, Durability, PageHeader, Profile, Superblock, PAGE_HEADER_BYTES,
};
use crate::cow::CowTree;
use crate::cve;
use crate::error::{corrupt, invalid, Error, Result};
use crate::manifest::{Manifest, SegmentRef};
use crate::pager::{FreeExtent, Pager};
use crate::profile::ProfileConstants;
use crate::security::KeyRing;
use crate::segment::{
    encode_range_delete_payload, internal_key, op, parse_internal_key, user_part, user_prefix,
    value_kind, RangeDelete, SegEntry, SegRecord, Segment, SegmentBuilder,
};
use crate::value::{NumType, Value};
use crate::vlog::{
    self, encode_record, Heat, Tier, VlogHead, VlogPointer, VlogRecord, VlogStats, DATA_OFFSET,
};

/// One memtable entry, before it becomes a segment cell.
#[derive(Clone, Debug)]
pub struct MemEntry {
    pub value_kind: u8,
    pub value: Vec<u8>,
    pub expiry_ms: Option<u64>,
}

/// `10-transactions.md` §1 — a sequence number plus **all nine** superblock
/// roots. A snapshot that omits one is not a consistent view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Snapshot {
    pub seq: u64,
    pub commit_id: u64,
    pub catalog_root: u64,
    pub freelist_root: u64,
    pub attributes_root: u64,
    pub manifest_root: u64,
    pub vlog_stats_root: u64,
    pub checkpoint_root: u64,
    pub changefeed_root: u64,
    pub created_ms: i64,
}

/// `10-transactions.md` §9.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreEvent {
    Opened,
    Commit { commit_id: u64, visible_seq: u64 },
    Flushed { segment_id: u64, entries: u64 },
    Compacted { from: u8, to: u8, bytes: u64 },
    Backpressure { delay_ms: u64, bound: String },
    Closing,
    Closed,
}

/// §3.1's policy. A conforming reader MUST NOT depend on it
/// (`11-conformance.md` §1.3); it is recorded here because a writer needs one.
#[derive(Clone, Copy, Debug)]
pub struct LevelPolicy {
    pub l0_trigger: u8,
    pub tier_width: u8,
    pub overlap_bound: u8,
    pub level_count: u8,
    pub fanout: u8,
}

impl LevelPolicy {
    pub fn last_level(&self) -> u8 {
        self.level_count.saturating_sub(1)
    }
    /// **Plain tiering is this policy with `overlap_bound = tier_width`** — the
    /// control is one superblock field.
    pub fn plain_tiered(self) -> LevelPolicy {
        LevelPolicy { overlap_bound: self.tier_width, ..self }
    }
}

/// §5.2 — a compaction job, decomposable into steps of at most
/// `compaction_step_bytes`, between which it can yield.
pub struct CompactionJob {
    pub inputs: Vec<SegmentRef>,
    pub target_level: u8,
    pub target_group: u8,
    entries: Vec<SegEntry>,
    cursor: usize,
    builder: Option<SegmentBuilder>,
    outputs: Vec<(Vec<u8>, u64)>,
    per_output: u64,
    pub bytes_written: u64,
}

impl CompactionJob {
    pub fn input_ids(&self) -> HashSet<u64> {
        self.inputs.iter().map(|r| r.segment_id).collect()
    }
}

/// The engine's measured counters. `13-operations.md` §6 forbids a fabricated
/// value, so a counter that is not measured is simply absent here.
#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub bytes_written_logical: u64,
    pub bytes_written_device: u64,
    pub write_amp_value: u64,
    pub write_amp_key_index: u64,
    pub write_amp_gc: u64,
    pub stall_events: u64,
    pub stall_total_ms: u64,
    pub page_cache_hits: u64,
    pub page_cache_misses: u64,
    pub segments_probed: Vec<u32>,
    pub filter_probes: u64,
    pub filter_false_positives: u64,
    pub value_reads: u64,
    pub scanned_rows: u64,
    pub pinned_by_snapshots: u64,
    pub pinned_by_checkpoints: u64,
    pub nonces_allocated: u64,
    pub unencrypted_pages: u64,
    pub encrypted_pages: u64,
}

pub struct Engine {
    /// Records the bounded scans have examined. See
    /// [`Engine::scan_records_examined`] for why this counter exists.
    pub scan_examined: u64,
    pub pager: Pager,
    pub sb: Superblock,
    pub manifest: Manifest,
    pub catalog: Catalog,
    pub attributes: Attributes,
    /// Tree 1.
    pub freelist: CowTree,
    /// Tree 7 (`04-segments.md` §6.7).
    pub vlog_stats_tree: CowTree,
    /// Tree 8 (`13-operations.md` §1).
    pub checkpoints: CowTree,
    /// Tree 9 (`13-operations.md` §7).
    pub changefeed: CowTree,

    /// §2 step 5's shards: writers to different shards never meet.
    memtable: Vec<BTreeMap<Vec<u8>, MemEntry>>,
    memtable_bytes: usize,
    pub memtable_entry_limit: usize,

    pub policy: LevelPolicy,
    pub profile: ProfileConstants,
    /// Whether a lookup stops at the first candidate that holds the key. §4
    /// permits it only under the level-discipline proof, which this policy
    /// satisfies; it is a switch because §4.1's bound belongs to the early exit.
    pub early_exit: bool,
    pub filters: bool,
    /// Whether `compact()` drives `locality_debt` back under its bound when it
    /// finishes. On by default because §6.8 makes collection half of §6.9's
    /// bound rather than optional maintenance; off is the control that shows
    /// what promotion alone buys.
    pub auto_collect: bool,

    /// Open segment extents, cached by `segment_id`.
    segments: HashMap<u64, Arc<Segment>>,
    /// `13-operations.md` §4 — segments a checksum failure has taken out of
    /// service, and the key range each covered.
    pub quarantined: HashMap<u64, SegmentRef>,

    /// Value-log segments: open ones by heat class, and every one's stats.
    pub vlog_open: BTreeMap<u8, u64>,
    pub vlog_cold_open: Option<u64>,
    pub vlog_stats: BTreeMap<u64, VlogStats>,
    vlog_tail: BTreeMap<u64, u64>,
    /// Value-log segments whose tree-7 entry has changed since the last commit.
    /// `10-transactions.md` §2.3 invariant 2 puts the durable `bytes`
    /// watermark in tree 7 precisely so advancing it is an ordinary
    /// transactional write, not a rewrite of a write-once head page.
    vlog_dirty: HashSet<u64>,

    /// §9's wall clock, injectable so a backwards jump can be tested.
    pub now_ms: u64,

    pub visible_seq: u64,
    pub next_seq: u64,
    live_snapshots: Vec<Snapshot>,
    written_at: HashMap<Vec<u8>, u64>,
    pub events: Vec<StoreEvent>,
    pub durability_achieved: Durability,
    pub counters: Counters,
    pub keys: Option<KeyRing>,
    /// `(min seq, min commit_id)` over tree 8, cached; see
    /// [`Engine::refresh_checkpoint_floors`].
    checkpoint_floor: (Option<u64>, Option<u64>),
    /// Free extents already written into tree 1, so a commit writes only what
    /// is new.
    persisted_free: HashSet<(u64, u64)>,
    /// `11-conformance.md` §5 — trees whose `params.change_feed` is true.
    pub changefeed_trees: HashSet<u32>,
    job: Option<CompactionJob>,
    closed: bool,
    /// `14-security.md` §4.1 — the session's nonce allocation cursor and
    /// the published floor it must not reach. Equal means "publish first".
    nonce_next: u64,
    nonce_limit: u64,
}

impl Engine {
    // ---------------------------------------------------------------
    // Creation, open, close
    // ---------------------------------------------------------------

    pub fn create_in_memory(profile: Profile) -> Result<Engine> {
        let pc = ProfileConstants::of(profile);
        let pager = Pager::in_memory(pc.page_size);
        Engine::bootstrap(pager, pc, None)
    }

    pub fn create(path: &Path, profile: Profile) -> Result<Engine> {
        let pc = ProfileConstants::of(profile);
        let pager = Pager::create(path, pc.page_size)?;
        Engine::bootstrap(pager, pc, None)
    }

    /// Creates a database that is encrypted from its **first** page.
    ///
    /// Without this there is no way to get one: turning `cipher` on after
    /// `create` is `14-security.md` §8.3's *conversion*, which leaves every
    /// page written before the switch in the clear — correct, reported by
    /// `unencrypted_pages`, and not what someone asking for an encrypted
    /// database means. `kdf = 0` takes a key the host already holds (§3.3);
    /// `kdf = 1` derives it with Argon2id at `t_cost`/`m_cost_kib`/`lanes`.
    pub fn create_encrypted(
        path: &Path,
        profile: Profile,
        credential: &[u8],
        kdf: u8,
        t_cost: u32,
        m_cost_kib: u32,
        lanes: u32,
    ) -> Result<Engine> {
        let pc = ProfileConstants::of(profile);
        let pager = Pager::create(path, pc.page_size)?;
        Engine::bootstrap(pager, pc, Some((credential, kdf, t_cost, m_cost_kib, lanes)))
    }

    pub fn create_encrypted_in_memory(
        profile: Profile,
        credential: &[u8],
        kdf: u8,
        t_cost: u32,
        m_cost_kib: u32,
        lanes: u32,
    ) -> Result<Engine> {
        let pc = ProfileConstants::of(profile);
        let pager = Pager::in_memory(pc.page_size);
        Engine::bootstrap(pager, pc, Some((credential, kdf, t_cost, m_cost_kib, lanes)))
    }

    fn bootstrap(
        pager: Pager,
        pc: ProfileConstants,
        key: Option<(&[u8], u8, u32, u32, u32)>,
    ) -> Result<Engine> {
        let mut sb = Superblock {
            page_size_log2: pc.page_size.trailing_zeros() as u16,
            profile: pc.profile.code(),
            vlog_min: pc.vlog_min,
            blob_threshold: pc.blob_threshold,
            vlog_segment_bytes: pc.vlog_segment_bytes,
            vlog_space_target_pct: pc.vlog_space_target_pct,
            locality_debt_pct: pc.locality_debt_pct,
            l0_trigger: pc.l0_trigger,
            tier_width: pc.tier_width,
            overlap_bound: pc.overlap_bound,
            fanout: pc.fanout,
            level_count: pc.level_count,
            memtable_shards: pc.memtable_shards,
            page_codec: pc.page_codec,
            filter_bits_upper: pc.filter_bits_upper,
            filter_bits_last: pc.filter_bits_last,
            readahead_window: pc.readahead_window,
            segment_target_bytes: pc.segment_target_bytes,
            created_utc_ms: now_millis(),
            modified_utc_ms: now_millis(),
            writer_id: format!("cryptand-rust/{}", env!("CARGO_PKG_VERSION")),
            ..Default::default()
        };
        crate::limits::check_vlog_min(sb.vlog_min, pc.page_size)?;
        sb.database_uuid = random_uuid_v4();
        sb.set_feature(feature::CORE, true);
        let shards = pc.memtable_shards.max(1) as usize;
        let mut e = Engine {
            scan_examined: 0,
            pager,
            manifest: Manifest::new(0),
            catalog: Catalog::new(0, 0, tree_id::FIRST_USER_TREE as u64),
            attributes: Attributes::new(0),
            freelist: CowTree::new(tree_id::FREE_SPACE, 0),
            vlog_stats_tree: CowTree::new(tree_id::VLOG_STATS, 0),
            checkpoints: CowTree::new(tree_id::CHECKPOINTS, 0),
            changefeed: CowTree::new(tree_id::CHANGE_FEED, 0),
            memtable: (0..shards).map(|_| BTreeMap::new()).collect(),
            memtable_bytes: 0,
            memtable_entry_limit: pc.memtable_entries,
            policy: LevelPolicy {
                l0_trigger: sb.l0_trigger,
                tier_width: sb.tier_width,
                overlap_bound: sb.overlap_bound,
                level_count: sb.level_count,
                fanout: sb.fanout,
            },
            profile: pc,
            early_exit: true,
            filters: true,
            auto_collect: true,
            segments: HashMap::new(),
            quarantined: HashMap::new(),
            vlog_open: BTreeMap::new(),
            vlog_cold_open: None,
            vlog_stats: BTreeMap::new(),
            vlog_tail: BTreeMap::new(),
            vlog_dirty: HashSet::new(),
            now_ms: 0,
            visible_seq: 0,
            next_seq: 1,
            live_snapshots: Vec::new(),
            written_at: HashMap::new(),
            events: Vec::new(),
            durability_achieved: Durability::None,
            counters: Counters::default(),
            keys: None,
            checkpoint_floor: (None, None),
            persisted_free: HashSet::new(),
            changefeed_trees: HashSet::new(),
            job: None,
            closed: false,
            nonce_next: 0,
            nonce_limit: 0,
            sb,
        };
        e.events.push(StoreEvent::Opened);
        // `01-container.md` §7 — the profile's codec becomes the file's
        // default before the first page is written.
        e.pager.page_codec = e.sb.page_codec;
        if let Some((cred, kdf, t_cost, m_cost_kib, lanes)) = key {
            let master = crate::security::random_bytes::<32>();
            let slot = crate::security::make_keyslot(
                &master,
                &e.sb.database_uuid,
                0,
                cred,
                kdf,
                t_cost,
                m_cost_kib,
                lanes,
                "keyslot 0",
            )?;
            e.sb.keyslots[..crate::security::keyslot::SIZE].copy_from_slice(&slot.encode());
            e.sb.cipher = 1;
            e.sb.set_feature(feature::CIPHER, true);
            e.keys = Some(KeyRing::from_master(master, e.sb.database_uuid, 0));
            // Before `write_store_metadata`, which is the first page write.
            e.arm()?;
        }
        e.write_store_metadata()?;
        e.commit(Durability::Sync)?;
        Ok(e)
    }

    /// `01-container.md` §2.1 and `10-transactions.md` §4 — no log replay.
    pub fn open(path: &Path, key: Option<&[u8]>) -> Result<Engine> {
        // Read both slots without knowing the page size yet: slot A is always
        // at offset 0 and is exactly 4096 bytes.
        let mut probe = Pager::open_shared(path, 4096, u64::MAX)?;
        let a = Superblock::parse(&probe.read_at(0, 4096)?).ok();
        let page_size = match &a {
            Some(sb) => sb.page_size(),
            None => 4096,
        };
        let mut probe = Pager::open_shared(path, page_size, u64::MAX)?;
        let b = Superblock::parse(&probe.read_at(page_size as u64, 4096)?).ok();
        // Step 3: the valid slot with the greater commit_id.
        let sb = match (a, b) {
            (Some(x), Some(y)) => {
                if x.commit_id >= y.commit_id {
                    x
                } else {
                    y
                }
            }
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (None, None) => {
                return corrupt("neither superblock slot is valid: not a Cryptand database")
            }
        };
        sb.check_features()?;
        crate::limits::check_vlog_min(sb.vlog_min, sb.page_size())?;

        // `14-security.md` §6.1 — the downgrade, and it has to be checked
        // *before* the `cipher != 0` branch below, not inside it.
        //
        // Turning `cipher` off is one byte, and the whole of §6.2's argument
        // for `sb_mac` is that otherwise "anyone can set `cipher = 0` or weaken
        // Argon2id cost". A reader that only verifies the MAC when the file
        // says it is encrypted has made the MAC conditional on the field the
        // MAC exists to protect.
        //
        // What it looked like before: the shared conformance corpus's
        // `v1.0-security-tamper-sb.cryptand` was reported as **corruption**,
        // because the reader believed the file was plaintext, read a page of
        // ciphertext as a B+tree, and found the cell pointers overrunning the
        // payload. That is the wrong class and the difference is not cosmetic:
        // `13-operations.md` §3 lets a repair pass run over corruption and
        // forbids it over tampering, so the wrong class here invites a rebuild
        // driven by bytes an attacker chose.
        //
        // An occupied keyslot on a `cipher = 0` file is the signature, and it
        // is one an attacker cannot erase without also destroying the thing
        // they want to read.
        if sb.cipher == 0 {
            for i in 0..crate::security::keyslot::COUNT {
                let at = i * crate::security::keyslot::SIZE;
                if sb.keyslots[at + crate::security::keyslot::STATE] != 0 {
                    return Err(Error::Tamper(format!(
                        "the superblock says cipher = 0 and keyslot {i} is occupied: \
                         14-security.md §6.1's downgrade"
                    )));
                }
            }
        }

        // Step 4: unwrap and verify `sb_mac` before acting on any other field.
        let keys = if sb.cipher != 0 {
            let Some(k) = key else { return Err(Error::CannotUnlock) };
            let ring = KeyRing::unlock(&sb, k)?;
            ring.verify_superblock(&sb)?;
            Some(ring)
        } else {
            None
        };

        let pager = Pager::open(path, sb.page_size(), sb.page_count)?;
        let pc = ProfileConstants::from_superblock(&sb);
        let shards = sb.memtable_shards.max(1) as usize;
        let mut e = Engine {
            scan_examined: 0,
            pager,
            manifest: Manifest::new(sb.manifest_root),
            catalog: Catalog::new(sb.catalog_root, 0, sb.next_tree_id),
            attributes: Attributes::new(sb.attributes_root),
            freelist: CowTree::new(tree_id::FREE_SPACE, sb.freelist_root),
            vlog_stats_tree: CowTree::new(tree_id::VLOG_STATS, sb.vlog_stats_root),
            checkpoints: CowTree::new(tree_id::CHECKPOINTS, sb.checkpoint_root),
            changefeed: CowTree::new(tree_id::CHANGE_FEED, sb.changefeed_root),
            memtable: (0..shards).map(|_| BTreeMap::new()).collect(),
            memtable_bytes: 0,
            memtable_entry_limit: pc.memtable_entries,
            policy: LevelPolicy {
                l0_trigger: sb.l0_trigger,
                tier_width: sb.tier_width,
                overlap_bound: sb.overlap_bound,
                level_count: sb.level_count,
                fanout: sb.fanout,
            },
            profile: pc,
            early_exit: true,
            filters: true,
            auto_collect: true,
            segments: HashMap::new(),
            quarantined: HashMap::new(),
            vlog_open: BTreeMap::new(),
            vlog_cold_open: None,
            vlog_stats: BTreeMap::new(),
            vlog_tail: BTreeMap::new(),
            vlog_dirty: HashSet::new(),
            now_ms: 0,
            visible_seq: sb.visible_seq,
            next_seq: sb.next_seq,
            live_snapshots: Vec::new(),
            written_at: HashMap::new(),
            events: Vec::new(),
            durability_achieved: Durability::from_code(sb.durability_achieved),
            counters: Counters::default(),
            keys,
            checkpoint_floor: (None, None),
            persisted_free: HashSet::new(),
            changefeed_trees: HashSet::new(),
            job: None,
            closed: false,
            nonce_next: 0,
            nonce_limit: 0,
            sb,
        };
        e.pager.min_retained_commit = e.sb.min_retained_commit;
        // `01-container.md` §7 — the codec is a *default* for newly written
        // pages and comes from the file, not from this build's profile, so a
        // desktop that opens a phone's database keeps writing the codec the
        // phone chose.
        e.pager.page_codec = e.sb.page_codec;
        // `14-security.md` §5.2 — the page cipher goes in before the first
        // read. Every `reload_*` below walks copy-on-write pages, and a pager
        // without the ring hands back ciphertext that parses as a corrupt node.
        if let Some(k) = &e.keys {
            let ring = k.clone();
            e.pager.crypto = Some(crate::pager::PageCrypto { ring, next: 0, limit: 0 });
        }
        e.reload_freelist()?;
        e.reload_vlog_stats()?;
        e.reload_tree_index()?;
        e.reload_changefeed_trees()?;
        e.refresh_checkpoint_floors()?;
        // `01-container.md` §2.1 step 8 and `14-security.md` §4.1 and §4.3.
        if e.sb.cipher != 0 {
            e.publish_nonce_floor()?;
        }
        e.seal_unsealed_vlog_segments()?;
        e.events.push(StoreEvent::Opened);
        Ok(e)
    }

    /// §2: "Every other tree's root is in its catalog descriptor — including
    /// tree 3's, which is bootstrapped by scanning the catalog if its
    /// descriptor is missing."
    ///
    /// The descriptor has to be *written*, not only read: without it every open
    /// rebuilds tree 3 from scratch, and the pages of the tree it replaces are
    /// reachable from nothing and recorded in no free tree — a leak per open,
    /// which `01-container.md` §9 step 7 finds and which nothing else would.
    pub const TREE_INDEX_DESCRIPTOR: &'static str = "$tree_index";

    fn reload_tree_index(&mut self) -> Result<()> {
        let root = match self.catalog.get(&mut self.pager, Engine::TREE_INDEX_DESCRIPTOR)? {
            Some(d) => d.root().unwrap_or(0),
            None => 0,
        };
        self.catalog.by_id.root = root;
        if root == 0 {
            self.catalog.rebuild_tree_index(&mut self.pager)?;
        }
        Ok(())
    }

    fn publish_tree_index_root(&mut self) -> Result<()> {
        let root = self.catalog.by_id.root;
        if root == 0 {
            return Ok(());
        }
        let mut cat = std::mem::replace(&mut self.catalog, Catalog::new(0, 0, 16));
        let existing = cat.get(&mut self.pager, Engine::TREE_INDEX_DESCRIPTOR)?;
        let d = match existing {
            Some(d) if d.root() == Some(root) => {
                self.catalog = cat;
                return Ok(());
            }
            Some(d) => d.with(vec![(
                "root",
                Some(Value::Int { w: NumType::U64, neg: false, mag: root as u128 }),
            )]),
            None => crate::catalog::TreeDescriptor::create(
                tree_id::TREE_INDEX,
                crate::catalog::kind::INTERNAL,
                None,
                None,
                Some("u32"),
                0,
                vec![],
                now_millis(),
            )
            .with(vec![
                ("root", Some(Value::Int { w: NumType::U64, neg: false, mag: root as u128 })),
                ("levelled", Some(Value::Bool(false))),
            ]),
        };
        // Straight into the catalog tree: `create` would allocate a fresh
        // `tree_id`, and tree 3's is reserved (§2).
        let r = cat.tree.put(
            &mut self.pager,
            &crate::catalog::name_key(Engine::TREE_INDEX_DESCRIPTOR),
            &d.encode(),
        );
        self.catalog = cat;
        r
    }

    fn reload_changefeed_trees(&mut self) -> Result<()> {
        self.changefeed_trees.clear();
        for (_, d) in self.catalog.all(&mut self.pager)? {
            if d.param_bool("change_feed") {
                self.changefeed_trees.insert(d.tree_id());
            }
        }
        Ok(())
    }

    fn reload_freelist(&mut self) -> Result<()> {
        let mut extents = Vec::new();
        for (k, v) in self.freelist.scan(&mut self.pager, None, None)? {
            let key = cke::decode_all(&k)?;
            let Value::Array(items) = key else { continue };
            let num = |v: &Value| match v {
                Value::Int { mag, .. } => *mag as u64,
                _ => 0,
            };
            let pages = match cve::decode_all(&v, &|_| None)?.field("pages") {
                Some(Value::Int { mag, .. }) => *mag as u32,
                _ => 0,
            };
            extents.push(FreeExtent {
                commit_id: num(&items[0]),
                start_page: num(&items[1]),
                pages,
            });
        }
        self.persisted_free = extents.iter().map(|e| (e.commit_id, e.start_page)).collect();
        self.pager.set_free_list(extents);
        Ok(())
    }

    fn reload_vlog_stats(&mut self) -> Result<()> {
        self.vlog_stats.clear();
        for (k, v) in self.vlog_stats_tree.scan(&mut self.pager, None, None)? {
            let id = match cke::decode_all(&k)? {
                Value::Int { mag, .. } => mag as u64,
                _ => continue,
            };
            self.vlog_stats.insert(id, decode_vlog_stats(id, &v)?);
        }
        Ok(())
    }

    /// `14-security.md` §4.3 and `10-transactions.md` §4: on open, every
    /// unsealed value-log segment is sealed at its durable watermark and a
    /// fresh segment is opened for new writes. Unencrypted this is harmless
    /// housekeeping; encrypted, re-appending would reuse a nonce.
    fn seal_unsealed_vlog_segments(&mut self) -> Result<()> {
        let ids: Vec<u64> =
            self.vlog_stats.iter().filter(|(_, s)| !s.sealed).map(|(&id, _)| id).collect();
        for id in ids {
            if let Some(s) = self.vlog_stats.get_mut(&id) {
                s.sealed = true;
            }
            self.write_vlog_stats(id)?;
        }
        self.vlog_open.clear();
        self.vlog_cold_open = None;
        Ok(())
    }

    /// `14-security.md` §4.1 rules 1 and 3 — durably publish
    /// `persisted_next_nonce + 2^20` and allocate from the persisted value
    /// upward, never reaching what was published.
    ///
    /// The session's allocation cursor is held here rather than derived from
    /// `sb.next_nonce - NONCE_GAP`: the derivation is only correct if rule 1
    /// has already run, and encryption can be switched on *after* open
    /// (§8.3's conversion), which is a writer that never passed through the
    /// open-time publish. Deriving it there underflows on the first allocation
    /// of a converting database and, where the subtraction wraps rather than
    /// panics, hands out nonces from a floor that was never published — which
    /// is precisely the crash-reuse hole §4.1 exists to close.
    fn publish_nonce_floor(&mut self) -> Result<()> {
        self.nonce_next = self.sb.next_nonce;
        self.sb.next_nonce = self.sb.next_nonce.saturating_add(crate::security::NONCE_GAP);
        self.nonce_limit = self.sb.next_nonce;
        if let Some(c) = &mut self.pager.crypto {
            c.next = self.nonce_next;
            c.limit = self.nonce_limit;
        }
        self.write_superblock(Durability::Sync)
    }

    /// Reserves `n` nonce values without handing any out, so a page-write loop
    /// that cannot stop halfway does not have to publish mid-extent.
    pub fn ensure_nonces(&mut self, n: u64) -> Result<()> {
        if self.sb.cipher == 0 || self.keys.is_none() {
            return Ok(());
        }
        if self.pager.crypto.is_none() {
            let ring = self.keys.as_ref().unwrap().clone();
            self.pager.crypto = Some(crate::pager::PageCrypto { ring, next: 0, limit: 0 });
            self.nonce_next = 0;
            self.nonce_limit = 0;
        }
        if self.nonce_next + n > self.nonce_limit {
            self.publish_nonce_floor()?;
        }
        Ok(())
    }

    /// Headroom armed at the start of every unit of work. A flush writes one
    /// memtable's worth of pages and a compaction step is byte-budgeted, so
    /// neither comes near 2^16 pages between two of these calls; running out
    /// anyway is an error from [`crate::pager::PageCrypto`], never a reuse.
    const NONCE_HEADROOM: u64 = 1 << 16;

    /// Installs the page cipher (idempotent) and arms the nonce window.
    /// Encryption can be switched on after open — `14-security.md` §8.3's
    /// conversion — so this cannot live in `open` alone.
    fn arm(&mut self) -> Result<()> {
        self.ensure_nonces(Engine::NONCE_HEADROOM)
    }

    pub fn close(&mut self, flush_memtable: bool) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.events.push(StoreEvent::Closing);
        if flush_memtable {
            self.flush()?;
        }
        self.seal_unsealed_vlog_segments()?;
        self.commit(Durability::Sync)?;
        if let Some(k) = &mut self.keys {
            k.zeroize();
        }
        if let Some(c) = &mut self.pager.crypto {
            c.ring.zeroize();
        }
        self.pager.crypto = None;
        self.closed = true;
        // §10: the exclusive advisory lock is held for the writing lifetime,
        // and this is the end of it.
        self.pager.release();
        self.events.push(StoreEvent::Closed);
        Ok(())
    }

    fn write_store_metadata(&mut self) -> Result<()> {
        // §7 — replaces `$nitrite_store_info`.
        let writers = Value::Array(vec![Value::Str(self.sb.writer_id.clone())]);
        let fields = vec![
            ("created".to_string(), Value::Timestamp(self.sb.created_utc_ms)),
            ("format_version".to_string(), Value::Str("1.0".into())),
            ("nitrite_version".to_string(), Value::Str(env!("CARGO_PKG_VERSION").into())),
            (
                "schema_version".to_string(),
                Value::Int { w: NumType::U32, neg: false, mag: 1 },
            ),
            ("writers".to_string(), writers),
        ];
        let mut attrs = std::mem::replace(&mut self.attributes, Attributes::new(0));
        let r = attrs.put(&mut self.pager, crate::catalog::STORE_ATTRIBUTES_KEY, fields);
        self.attributes = attrs;
        r
    }

    // ---------------------------------------------------------------
    // §2 — sequencing and the write path
    // ---------------------------------------------------------------

    fn shard_of(&self, key: &[u8]) -> usize {
        let h = crate::hash::cfh64(key);
        (h % self.memtable.len() as u64) as usize
    }

    pub fn allocate_seq(&mut self, n: u64) -> u64 {
        let base = self.next_seq;
        self.next_seq += n;
        base
    }

    pub fn put(&mut self, tree: u32, key: &Value, value: &[u8]) -> Result<u64> {
        self.write(tree, key, op::PUT, value, None)
    }

    pub fn put_with_expiry(&mut self, tree: u32, key: &Value, value: &[u8], expiry_ms: u64) -> Result<u64> {
        self.arm()?;
        self.write(tree, key, op::PUT, value, Some(expiry_ms))
    }

    pub fn remove(&mut self, tree: u32, key: &Value) -> Result<u64> {
        self.write(tree, key, op::DELETE, &[], None)
    }

    /// An index entry: `06-indexes.md` §1's `value = EMPTY`.
    pub fn put_empty(&mut self, tree: u32, key: &Value) -> Result<u64> {
        let cke_key = cke::encode(key)?;
        crate::limits::check_key_len(&cke_key, self.pager.page_size)?;
        let seq = self.allocate_seq(1);
        let ik = internal_key(tree, &cke_key, seq, op::PUT);
        self.insert_mem(ik, MemEntry { value_kind: value_kind::EMPTY, value: Vec::new(), expiry_ms: None });
        self.feed(tree, seq, "insert", &cke_key)?;
        Ok(seq)
    }

    /// §2.5 — `[start, end)` deleted at one seq. This is what makes `clear()`,
    /// `drop()` and rollback of a bulk insert O(1) writes rather than O(n)
    /// tombstones.
    pub fn remove_range(&mut self, tree: u32, start: &Value, end: &Value) -> Result<u64> {
        self.arm()?;
        let s = user_prefix(tree, &cke::encode(start)?);
        let e = user_prefix(tree, &cke::encode(end)?);
        if e <= s {
            return invalid("a range delete needs end > start");
        }
        let seq = self.allocate_seq(1);
        let ik = internal_key(tree, &cke::encode(start)?, seq, op::RANGE_DELETE);
        self.insert_mem(
            ik,
            MemEntry {
                value_kind: value_kind::INLINE,
                value: encode_range_delete_payload(&e),
                expiry_ms: None,
            },
        );
        Ok(seq)
    }

    fn write(&mut self, tree: u32, key: &Value, op_code: u8, value: &[u8], expiry_ms: Option<u64>) -> Result<u64> {
        if self.closed {
            return invalid("the database is closed");
        }
        let cke_key = cke::encode(key)?;
        crate::limits::check_key_len(&cke_key, self.pager.page_size)?;
        let seq = self.allocate_seq(1);
        let ik = internal_key(tree, &cke_key, seq, op_code);
        self.counters.bytes_written_logical += (cke_key.len() + value.len()) as u64;

        let entry = if op_code == op::DELETE {
            MemEntry { value_kind: value_kind::EMPTY, value: Vec::new(), expiry_ms }
        } else if vlog::separate(value.len(), self.sb.vlog_min, self.inline_values(tree)) {
            let p = self.append_value(tree, &cke_key, value, Heat::First)?;
            MemEntry { value_kind: value_kind::VLOG, value: p.encode().to_vec(), expiry_ms }
        } else {
            MemEntry { value_kind: value_kind::INLINE, value: value.to_vec(), expiry_ms }
        };
        if expiry_ms.is_some() {
            self.sb.set_feature(feature::TTL, true);
        }
        self.insert_mem(ik, entry);
        let feed_op = if op_code == op::DELETE { "delete" } else { "insert" };
        self.feed(tree, seq, feed_op, &cke_key)?;
        Ok(seq)
    }

    fn inline_values(&self, _tree: u32) -> bool {
        false
    }

    /// Takes one already-sequenced row from a concurrent writer's shard
    /// (`store.rs`). The seq was allocated by the shared counter, so the
    /// engine adopts it rather than issuing a new one.
    pub fn adopt_entry(&mut self, ik: Vec<u8>, e: MemEntry) {
        self.insert_mem(ik, e);
    }

    fn insert_mem(&mut self, ik: Vec<u8>, e: MemEntry) {
        self.memtable_bytes += ik.len() + e.value.len() + 16;
        let user = user_part(&ik).to_vec();
        let seq = parse_internal_key(&ik).map(|p| p.seq).unwrap_or(0);
        self.written_at.insert(user, seq);
        let s = self.shard_of(&ik);
        self.memtable[s].insert(ik, e);
    }

    fn memtable_len(&self) -> usize {
        self.memtable.iter().map(|m| m.len()).sum()
    }

    /// `13-operations.md` §7 — appended in the same batch as the mutation, so
    /// the feed is exactly consistent with the data.
    fn feed(&mut self, tree: u32, seq: u64, op_name: &str, cke_key: &[u8]) -> Result<()> {
        if !self.changefeed_trees.contains(&tree) {
            return Ok(());
        }
        let key = cke::encode(&Value::Array(vec![
            Value::Int { w: NumType::U32, neg: false, mag: tree as u128 },
            Value::Int { w: NumType::U64, neg: false, mag: seq as u128 },
        ]))?;
        let v = cve::encode(&Value::Doc(vec![
            ("op".into(), Value::Str(op_name.into())),
            ("key".into(), Value::Bytes(cke_key.to_vec())),
        ]));
        let mut t = std::mem::replace(&mut self.changefeed, CowTree::new(tree_id::CHANGE_FEED, 0));
        t.commit_id = self.sb.commit_id;
        let r = t.put(&mut self.pager, &key, &v);
        self.changefeed = t;
        self.sb.set_feature(feature::CHANGEFEED, false);
        r
    }

    // ---------------------------------------------------------------
    // §6 — the value log
    // ---------------------------------------------------------------

    fn open_vlog_segment(&mut self, tier: Tier, heat: Heat) -> Result<u64> {
        let page_size = self.pager.page_size as u64;
        let want = self.sb.vlog_segment_bytes as u64;
        let pages = (want + DATA_OFFSET as u64).div_ceil(page_size).max(2) as u32;
        let start = self.pager.alloc_extent(pages)?;
        let id = self.sb.next_vlog_segment_id;
        self.sb.next_vlog_segment_id += 1;
        let capacity = pages as u64 * page_size - DATA_OFFSET as u64;
        let nonce_base = if self.sb.cipher != 0 { self.allocate_nonce()? } else { 0 };
        let head = VlogHead {
            segment_id: id,
            created_seq: self.next_seq,
            capacity,
            data_offset: DATA_OFFSET,
            tier,
            heat,
            codec: codec::NONE,
            encrypted: self.sb.cipher != 0,
            nonce_base,
        };
        let page = head.encode(self.pager.page_size, pages);
        // §5.1: a value-log segment's head page stays in the clear — its
        // records are appended into its tail and encrypted one by one (§5.3).
        self.pager.write_page_clear(start, &page)?;
        self.vlog_stats.insert(
            id,
            VlogStats {
                segment_id: id,
                bytes: 0,
                records: 0,
                sealed: false,
                clustered: tier == Tier::Cold,
                min_key: None,
                max_key: None,
                start_page: start,
                pages,
                live_bytes: 0,
                live_records: 0,
                tier: tier as u8,
                heat: heat as u8,
                created_seq: self.next_seq,
                last_gc_seq: 0,
            },
        );
        self.vlog_tail.insert(id, 0);
        match tier {
            Tier::Hot => {
                self.vlog_open.insert(heat as u8, id);
            }
            Tier::Cold => self.vlog_cold_open = Some(id),
        }
        Ok(id)
    }

    /// §6.2's reserve-then-write append. The number of open segments is
    /// bounded by the number of **heat classes**, not by the number of
    /// writers, so write-path memory is O(1) in concurrency.
    pub fn append_value(&mut self, tree: u32, cke_key: &[u8], value: &[u8], heat: Heat) -> Result<VlogPointer> {
        self.append_into(Tier::Hot, heat, tree, cke_key, value)
    }

    /// §6.3 — promotion writes into the COLD tier, in key order, so the cold
    /// log is key-clustered by construction.
    pub fn append_cold(&mut self, tree: u32, cke_key: &[u8], value: &[u8]) -> Result<VlogPointer> {
        self.append_into(Tier::Cold, Heat::First, tree, cke_key, value)
    }

    fn append_into(&mut self, tier: Tier, heat: Heat, tree: u32, cke_key: &[u8], value: &[u8]) -> Result<VlogPointer> {
        let record = if self.sb.cipher != 0 {
            let counter = self.allocate_nonce()?;
            let seg = self.current_vlog(tier, heat)?;
            let offset = *self.vlog_tail.get(&seg).unwrap();
            let ring = self.keys.as_ref().unwrap();
            let ct = ring.encrypt_vlog(seg, DATA_OFFSET as u64 + offset, tree, counter, cke_key, value)?;
            vlog::encode_record_encrypted(tree, counter, &ct)
        } else {
            encode_record(tree, cke_key, value)
        };
        let mut seg = self.current_vlog(tier, heat)?;
        if self.vlog_stats[&seg].bytes + record.len() as u64 > self.vlog_stats[&seg].pages as u64 * self.pager.page_size as u64 - DATA_OFFSET as u64 {
            self.seal_vlog(seg)?;
            seg = self.open_vlog_segment(tier, heat)?;
        }
        let stats = self.vlog_stats.get(&seg).unwrap();
        let start_page = stats.start_page;
        let offset = *self.vlog_tail.get(&seg).unwrap();
        let at = start_page * self.pager.page_size as u64 + DATA_OFFSET as u64 + offset;
        self.pager.write_at(at, &record)?;
        self.vlog_tail.insert(seg, offset + record.len() as u64);
        {
            let s = self.vlog_stats.get_mut(&seg).unwrap();
            // The watermark advances only over a contiguous prefix of
            // completed reservations (§6.2, `10-transactions.md` §2.3); this
            // writer completes each reservation before returning, so the
            // prefix is the tail.
            s.bytes = offset + record.len() as u64;
            s.records += 1;
            s.live_bytes += record.len() as u64;
            s.live_records += 1;
            if s.min_key.is_none() || s.min_key.as_deref() > Some(cke_key) {
                s.min_key = Some(cke_key.to_vec());
            }
            // §6.3: the implementation MUST set `clustered` only when the
            // ordering actually holds. A cold segment is written in key order
            // by promotion and by a sorted bulk write, so it starts clustered
            // and an out-of-order append clears the flag.
            if s.tier == Tier::Cold as u8 && s.max_key.as_deref() > Some(cke_key) {
                s.clustered = false;
            }
            if s.max_key.as_deref() < Some(cke_key) {
                s.max_key = Some(cke_key.to_vec());
            }
        }
        self.vlog_dirty.insert(seg);
        self.counters.write_amp_value += record.len() as u64;
        Ok(VlogPointer {
            segment_id: seg,
            offset: DATA_OFFSET + offset as u32,
            len: record.len() as u32,
        })
    }

    fn current_vlog(&mut self, tier: Tier, heat: Heat) -> Result<u64> {
        let existing = match tier {
            Tier::Hot => self.vlog_open.get(&(heat as u8)).copied(),
            Tier::Cold => self.vlog_cold_open,
        };
        match existing {
            Some(id) => Ok(id),
            None => self.open_vlog_segment(tier, heat),
        }
    }

    pub fn seal_vlog(&mut self, id: u64) -> Result<()> {
        if let Some(s) = self.vlog_stats.get_mut(&id) {
            s.sealed = true;
        }
        self.write_vlog_stats(id)?;
        if self.vlog_cold_open == Some(id) {
            self.vlog_cold_open = None;
        }
        self.vlog_open.retain(|_, v| *v != id);
        Ok(())
    }

    pub fn mark_clustered(&mut self, id: u64, clustered: bool) -> Result<()> {
        if let Some(s) = self.vlog_stats.get_mut(&id) {
            s.clustered = clustered;
        }
        self.write_vlog_stats(id)
    }

    fn write_vlog_stats(&mut self, id: u64) -> Result<()> {
        let Some(s) = self.vlog_stats.get(&id).cloned() else { return Ok(()) };
        let key = cke::encode(&Value::Int { w: NumType::U64, neg: false, mag: id as u128 })?;
        let v = encode_vlog_stats(&s);
        let mut t = std::mem::replace(&mut self.vlog_stats_tree, CowTree::new(tree_id::VLOG_STATS, 0));
        t.commit_id = self.sb.commit_id;
        let r = t.put(&mut self.pager, &key, &v);
        self.vlog_stats_tree = t;
        r
    }

    pub fn read_vlog(&mut self, p: &VlogPointer) -> Result<Vec<u8>> {
        self.counters.value_reads += 1;
        self.pager.page_reads += 1;
        self.read_vlog_uncounted(p)
    }

    /// The same read without the metric, for the coalescing path that counts
    /// I/Os rather than dereferences.
    pub fn read_vlog_uncounted(&mut self, p: &VlogPointer) -> Result<Vec<u8>> {
        let Some(stats) = self.vlog_stats.get(&p.segment_id).cloned() else {
            return corrupt(format!("VLOG pointer names unknown segment {}", p.segment_id));
        };
        vlog::check_pointer_in_bounds(p, &stats, DATA_OFFSET)?;
        let at = stats.start_page * self.pager.page_size as u64 + p.offset as u64;
        let raw = self.pager.read_at(at, p.len as usize)?;
        let encrypted = self.sb.cipher != 0;
        let rec = vlog::decode_record(&raw, encrypted)?;
        if encrypted {
            let ring = self.keys.as_ref().unwrap();
            let (_k, v) = ring.decrypt_vlog(
                p.segment_id,
                p.offset as u64,
                rec.tree_id,
                rec.nonce.unwrap_or(0),
                &raw,
            )?;
            Ok(v)
        } else {
            Ok(rec.value)
        }
    }

    pub fn read_vlog_record(&mut self, p: &VlogPointer) -> Result<VlogRecord> {
        let Some(stats) = self.vlog_stats.get(&p.segment_id).cloned() else {
            return corrupt(format!("VLOG pointer names unknown segment {}", p.segment_id));
        };
        let at = stats.start_page * self.pager.page_size as u64 + p.offset as u64;
        let raw = self.pager.read_at(at, p.len as usize)?;
        vlog::decode_record(&raw, self.sb.cipher != 0)
    }

    pub fn allocate_nonce(&mut self) -> Result<u64> {
        // §4.1 rules 2 and 3: allocate from the persisted watermark upward and
        // never reach the published value; on reaching it, publish another gap
        // and only then continue. One cursor serves both pages and value-log
        // records — two would be two chances to hand the same value out twice.
        self.ensure_nonces(1)?;
        let n = match &mut self.pager.crypto {
            Some(c) => {
                let n = c.next;
                c.next += 1;
                n
            }
            None => {
                let n = self.nonce_next;
                self.nonce_next += 1;
                n
            }
        };
        self.nonce_next = n + 1;
        self.counters.nonces_allocated += 1;
        Ok(n)
    }

    // ---------------------------------------------------------------
    // §2 step D — the flush, and the level policy of §3.1
    // ---------------------------------------------------------------

    pub fn filter_bits_at(&self, level: u8) -> u16 {
        if !self.filters {
            return 0;
        }
        if level == self.policy.last_level() {
            self.sb.filter_bits_last as u16
        } else {
            self.sb.filter_bits_upper as u16
        }
    }

    /// §3.1's output-size rule. Both bounds require it, and an implementation
    /// that picks the size freely cannot satisfy them: a fixed size makes
    /// every tiered level compact after its *second* run, so no level ever
    /// holds more than one run.
    pub fn segment_entries_at(&self, level: u8) -> u64 {
        let l0 = self.memtable_entry_limit as u64;
        if level == 0 {
            return l0;
        }
        let ob = self.policy.overlap_bound.max(1) as u64;
        let mut run = self.policy.l0_trigger.max(1) as u64 * l0;
        for _ in 1..level {
            run *= ob;
        }
        let segments_per_run = (self.policy.tier_width.max(1) as u64 / ob).max(1);
        run.div_ceil(segments_per_run).max(1)
    }

    /// §2 step D. `10-transactions.md` §8: `visible_seq` advances whenever a
    /// batch's records become durable, which for a single writer is this
    /// flush — an engine whose watermark never advances retains every
    /// superseded version forever.
    pub fn flush(&mut self) -> Result<()> {
        self.arm()?;
        if self.memtable_len() == 0 {
            self.visible_seq = self.next_seq.saturating_sub(1);
            return Ok(());
        }
        let mut all: Vec<(Vec<u8>, MemEntry)> = Vec::with_capacity(self.memtable_len());
        for shard in &mut self.memtable {
            all.extend(std::mem::take(shard).into_iter());
        }
        all.sort_by(|a, b| a.0.cmp(&b.0));
        self.memtable_bytes = 0;

        let mut b = SegmentBuilder::with_reserve(
            self.pager.page_size,
            self.pager.tag_reserve(),
            self.sb.next_segment_id,
            0,
            0,
            self.filter_bits_at(0),
        )?;
        self.sb.next_segment_id += 1;
        for (ik, e) in all {
            b.add(SegEntry { internal_key: ik, value_kind: e.value_kind, value: e.value, expiry_ms: e.expiry_ms })?;
        }
        let entries = b.entry_count();
        let seg_id = b.segment_id;
        self.publish_segment(b, 0, 0)?;
        self.visible_seq = self.next_seq.saturating_sub(1);
        self.events.push(StoreEvent::Flushed { segment_id: seg_id, entries });
        Ok(())
    }

    fn publish_segment(&mut self, b: SegmentBuilder, level: u8, group: u8) -> Result<SegmentRef> {
        let extent = b.build()?;
        let pages = (extent.len() / self.pager.page_size) as u32;
        let start = self.pager.alloc_extent(pages)?;
        self.pager.write_extent(start, &extent)?;
        self.counters.write_amp_key_index += extent.len() as u64;
        let seg = Segment::open(extent, self.pager.page_size)?;
        let r = SegmentRef::of(&seg, level, group, start);
        self.segments.insert(r.segment_id, Arc::new(seg));
        let mut m = std::mem::replace(&mut self.manifest, Manifest::new(0));
        m.tree.commit_id = self.sb.commit_id;
        let res = m.add(&mut self.pager, &r);
        self.manifest = m;
        res?;
        Ok(r)
    }

    pub fn segment(&mut self, r: &SegmentRef) -> Result<Arc<Segment>> {
        if let Some(s) = self.segments.get(&r.segment_id) {
            self.counters.page_cache_hits += 1;
            return Ok(s.clone());
        }
        self.counters.page_cache_misses += 1;
        let extent = self.pager.read_extent(r.start_page, r.pages)?;
        let s = Arc::new(Segment::open(extent, self.pager.page_size)?);
        self.segments.insert(r.segment_id, s.clone());
        Ok(s)
    }

    /// Every manifest entry at `level`, **quarantined ones included**.
    ///
    /// `13-operations.md` §4 step 4 is why: a read that lands inside a
    /// quarantined range MUST fail with a specific corruption error naming the
    /// range, "never with a wrong or empty answer". Dropping the entry here
    /// would make the read silently resolve against whatever survives lower
    /// down, which is exactly the wrong answer that rule forbids.
    pub fn refs_at(&mut self, level: u8) -> Result<Vec<SegmentRef>> {
        let m = std::mem::replace(&mut self.manifest, Manifest::new(0));
        let r = m.level(&mut self.pager, level);
        self.manifest = m;
        r
    }

    /// The subset a compaction may read.
    pub fn healthy_refs_at(&mut self, level: u8) -> Result<Vec<SegmentRef>> {
        Ok(self
            .refs_at(level)?
            .into_iter()
            .filter(|s| !self.quarantined.contains_key(&s.segment_id))
            .collect())
    }

    pub fn all_refs(&mut self) -> Result<Vec<SegmentRef>> {
        let m = std::mem::replace(&mut self.manifest, Manifest::new(0));
        let r = m.all(&mut self.pager);
        self.manifest = m;
        r
    }

    // ---------------------------------------------------------------
    // §4 — read resolution
    // ---------------------------------------------------------------

    /// §4's candidate order: L0 newest-flush-first, then strictly increasing
    /// level; within a level, **descending `segment_id`** is newest-first,
    /// because `segment_id` is globally unique and never reused. (`max_seq`
    /// cannot serve: §4 disqualifies it as a per-segment aggregate.)
    pub fn candidates_for(&mut self, user_key_prefix: &[u8]) -> Result<Vec<SegmentRef>> {
        let mut out = Vec::new();
        for level in 0..=self.policy.last_level() {
            let mut refs = self.refs_at(level)?;
            refs.sort_by(|a, b| b.segment_id.cmp(&a.segment_id));
            for r in refs {
                if r.covers(user_key_prefix) {
                    out.push(r);
                }
            }
        }
        Ok(out)
    }

    pub fn get(&mut self, tree: u32, key: &Value) -> Result<Option<Vec<u8>>> {
        self.get_at(tree, key, None)
    }

    pub fn get_at(&mut self, tree: u32, key: &Value, at: Option<&Snapshot>) -> Result<Option<Vec<u8>>> {
        let cke_key = cke::encode(key)?;
        let prefix = user_prefix(tree, &cke_key);
        let ceiling = at.map(|s| s.seq);
        let mut probes = 0u32;

        // The memtable holds every write since the last flush; a point read
        // that skipped it would not see them.
        let mut best: Option<SegRecord> = self.memtable_lookup(&prefix, ceiling);

        let cands = self.candidates_for(&prefix)?;
        for r in &cands {
            if self.quarantined.contains_key(&r.segment_id) {
                return Err(Error::Unavailable(format!(
                    "segment {} is quarantined and covers this key",
                    r.segment_id
                )));
            }
            let seg = self.segment(r)?;
            if self.filters && !r.has_range_deletes {
                self.counters.filter_probes += 1;
                if !seg.may_contain(&prefix) {
                    continue;
                }
            }
            probes += 1;
            if let Some(rec) = seg.lookup(&prefix, ceiling)? {
                let newer = best.as_ref().map_or(true, |b| rec.seq() > b.seq());
                if newer {
                    best = Some(rec);
                }
                // §4: an implementation MAY stop early only when it can prove
                // no unexamined candidate can hold a newer version of *this*
                // key. Level discipline is that proof, and `candidates_for`
                // emits candidates in exactly that order.
                if self.early_exit {
                    break;
                }
            } else {
                self.counters.filter_false_positives += 1;
            }
        }
        self.counters.segments_probed.push(probes);

        // §4: a segment that may hold a covering RANGE_DELETE MUST NOT be
        // pruned by its filter, because the filter holds point keys only.
        let rd = self.range_delete_seq(tree, &prefix, ceiling)?;
        let Some(best) = best else { return Ok(None) };
        if rd > best.seq() {
            return Ok(None);
        }
        if best.op() == op::DELETE || self.expired(&best) {
            return Ok(None);
        }
        self.resolve_value(&best).map(Some)
    }

    fn expired(&self, rec: &SegRecord) -> bool {
        // §9: expiry is evaluated at read time, so it is exact regardless of
        // when compaction runs; a backwards clock jump resurrects entries.
        matches!(rec.expiry_ms, Some(x) if x <= self.now_ms)
    }

    pub fn resolve_value(&mut self, rec: &SegRecord) -> Result<Vec<u8>> {
        match rec.value_kind {
            value_kind::VLOG => {
                let p = VlogPointer::parse(&rec.value)?;
                self.read_vlog(&p)
            }
            _ => Ok(rec.value.clone()),
        }
    }

    fn memtable_lookup(&self, prefix: &[u8], ceiling: Option<u64>) -> Option<SegRecord> {
        let mut best: Option<SegRecord> = None;
        for shard in &self.memtable {
            for (ik, e) in shard.range(prefix.to_vec()..) {
                if !ik.starts_with(prefix) || ik.len() != prefix.len() + 9 {
                    break;
                }
                let Ok(parsed) = parse_internal_key(ik) else { continue };
                // As in `Segment::lookup`: a RANGE_DELETE shares the internal
                // key shape of a point key and is resolved separately.
                if parsed.op == op::RANGE_DELETE {
                    continue;
                }
                let seq = parsed.seq;
                if let Some(c) = ceiling {
                    if seq > c {
                        continue;
                    }
                }
                if best.as_ref().map_or(true, |b| seq > b.seq()) {
                    best = Some(SegRecord {
                        internal_key: ik.clone(),
                        value_kind: e.value_kind,
                        value: e.value.clone(),
                        expiry_ms: e.expiry_ms,
                    });
                }
            }
        }
        best
    }

    /// Every range delete over `tree`, hoisted once per scan rather than per
    /// row — a per-row lookup makes a scan O(rows x segments).
    pub fn range_deletes_for(&mut self, tree: u32) -> Result<Vec<RangeDelete>> {
        let mut out = Vec::new();
        for shard in &self.memtable {
            for (ik, e) in shard.iter() {
                let p = parse_internal_key(ik)?;
                if p.op != op::RANGE_DELETE || p.tree_id != tree {
                    continue;
                }
                out.push(RangeDelete {
                    tree_id: tree,
                    start: user_part(ik).to_vec(),
                    end: crate::segment::decode_range_delete_payload(&e.value)?,
                    seq: p.seq,
                });
            }
        }
        let refs = self.all_refs()?;
        for r in refs {
            if !r.has_range_deletes {
                continue;
            }
            let seg = self.segment(&r)?;
            for rd in seg.range_deletes()? {
                if rd.tree_id == tree {
                    out.push(rd);
                }
            }
        }
        Ok(out)
    }

    fn range_delete_seq(&mut self, tree: u32, prefix: &[u8], ceiling: Option<u64>) -> Result<u64> {
        let mut best = 0u64;
        for rd in self.range_deletes_for(tree)? {
            if !rd.covers(prefix) {
                continue;
            }
            if let Some(c) = ceiling {
                if rd.seq > c {
                    continue;
                }
            }
            best = best.max(rd.seq);
        }
        Ok(best)
    }

    // ---------------------------------------------------------------
    // §8 — scans
    // ---------------------------------------------------------------

    /// Every live entry of one tree, in key order, at `at` (or the current
    /// snapshot). `value()` is lazy in the cursor sense: a key-only scan never
    /// touches the value log, so `values` selects that.
    /// Records a bounded scan actually examined, since the engine was opened.
    ///
    /// This exists because the answers a scan returns are identical whether the
    /// bounds were pushed into the segment walk or applied to the result, and
    /// the page-read counter is identical too once the segments are cached. So
    /// neither the tests nor the interop gate could see that this
    /// implementation materialised the whole tree for a one-row lookup, while
    /// the Dart and Java ones seeked. Only a counter over *records examined*
    /// distinguishes them.
    pub fn scan_records_examined(&self) -> u64 {
        self.scan_examined
    }

    pub fn reset_scan_counters(&mut self) {
        self.scan_examined = 0;
    }

    pub fn scan_tree(
        &mut self,
        tree: u32,
        lower: Option<&[u8]>,
        upper: Option<&[u8]>,
        at: Option<&Snapshot>,
        values: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let ceiling = at.map(|s| s.seq).unwrap_or(u64::MAX);
        let rds = self.range_deletes_for(tree)?;

        // The bounds, as **user keys** — `u32be(tree_id) || CKE(key)`, which is
        // the order a segment is laid out in (§1). Pushing them down here is
        // what makes a bounded scan cost the range rather than the tree.
        //
        // It did not, and the shape of the miss is worth keeping: every
        // segment's every record was collected into a `BTreeMap` and `lower` /
        // `upper` were applied to the *result*. A one-row index lookup on
        // 20 000 documents therefore walked all 20 000 index entries and all
        // 20 000 data entries, and measured **7.76 ms**. The page-read counter
        // read 2 the whole time, because the segments were already in memory —
        // so the counter this project relies on as its primary result was
        // perfect while the CPU cost was linear in the tree. `04-segments.md`
        // §8 makes cursors mandatory for exactly this reason.
        let lower_uk: Option<Vec<u8>> = lower.map(|l| {
            let mut v = tree.to_be_bytes().to_vec();
            v.extend_from_slice(l);
            v
        });
        let upper_uk: Option<Vec<u8>> = upper.map(|u| {
            let mut v = tree.to_be_bytes().to_vec();
            v.extend_from_slice(u);
            v
        });
        let in_range = |uk: &[u8]| -> bool {
            if uk.len() < 4 || uk[..4] != tree.to_be_bytes() {
                return false;
            }
            if let Some(l) = &lower_uk {
                if uk < l.as_slice() {
                    return false;
                }
            }
            if let Some(u) = &upper_uk {
                if uk >= u.as_slice() {
                    return false;
                }
            }
            true
        };

        // Collect every version in range, then collapse per user key.
        let mut best: BTreeMap<Vec<u8>, SegRecord> = BTreeMap::new();
        let consider = |best: &mut BTreeMap<Vec<u8>, SegRecord>, rec: SegRecord| {
            if rec.seq() > ceiling {
                return;
            }
            let uk = rec.user_key().to_vec();
            match best.get(&uk) {
                Some(b) if b.seq() >= rec.seq() => {}
                _ => {
                    best.insert(uk, rec);
                }
            }
        };
        for shard in &self.memtable {
            // The memtable is ordered by internal key, so the range is a
            // sub-map rather than a filtered walk.
            let from = lower_uk.clone().unwrap_or_else(|| tree.to_be_bytes().to_vec());
            for (ik, e) in shard.range(from..) {
                if !in_range(&ik[..ik.len().saturating_sub(9)]) {
                    // Past the upper bound, or into another tree: both mean
                    // there is nothing further to find in this shard.
                    if ik.len() >= 4 && ik[..4] == tree.to_be_bytes() {
                        if let Some(u) = &upper_uk {
                            if &ik[..ik.len() - 9] >= u.as_slice() {
                                break;
                            }
                        }
                        continue;
                    }
                    break;
                }
                let p = parse_internal_key(ik)?;
                if p.op == op::RANGE_DELETE {
                    continue;
                }
                consider(
                    &mut best,
                    SegRecord {
                        internal_key: ik.clone(),
                        value_kind: e.value_kind,
                        value: e.value.clone(),
                        expiry_ms: e.expiry_ms,
                    },
                );
            }
        }
        let refs = self.all_refs()?;
        for r in refs {
            if self.quarantined.contains_key(&r.segment_id) {
                continue;
            }
            // The manifest already carries each segment's `[min_key, max_key]`
            // as user keys, so a segment that cannot hold anything in range is
            // never opened at all.
            if let Some(u) = &upper_uk {
                if !r.min_key.is_empty() && r.min_key.as_slice() >= u.as_slice() {
                    continue;
                }
            }
            if let Some(l) = &lower_uk {
                if !r.max_key.is_empty() && r.max_key.as_slice() < l.as_slice() {
                    continue;
                }
            }
            let seg = self.segment(&r)?;
            // Seek to the lower bound, or to this **tree's own prefix** when
            // there is none -- never to the first cell. A segment holds the
            // entries of every tree an L0 flush covered, ordered by
            // `u32be(tree_id) || CKE(key)`, so seeking to cell 0 lands in
            // whichever tree sorts first and the `break` below would end the
            // walk before reaching this one. That is what it did: an unbounded
            // scan of an index tree returned zero rows.
            let seek_to = lower_uk.clone().unwrap_or_else(|| tree.to_be_bytes().to_vec());
            let mut cur = seg.seek(&seek_to)?;
            let mut examined = 0u64;
            while let Some(rec) = cur.record()? {
                examined += 1;
                let uk = rec.user_key();
                if uk.len() >= 4 && uk[..4] != tree.to_be_bytes() {
                    // Past this tree: the order is by tree id first, and the
                    // seek above started at or after this tree's prefix.
                    break;
                }
                if let Some(u) = &upper_uk {
                    if uk >= u.as_slice() {
                        break;
                    }
                }
                if in_range(uk) && rec.op() != op::RANGE_DELETE {
                    consider(&mut best, rec);
                }
                cur.next()?;
            }
            self.scan_examined += examined;
        }

        let mut out = Vec::new();
        // §8.1 — a cursor that dereferences values MUST issue its value-log
        // reads in non-decreasing (segment, offset) order within a sliding
        // window of at least `readahead_window` entries. Collecting the
        // pointers for a window and sorting them is exactly that.
        let window = self.sb.readahead_window.max(1) as usize;
        let mut pending: Vec<(usize, VlogPointer)> = Vec::new();
        let mut rows: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        for (uk, rec) in best {
            let cke_key = &uk[4..];
            if let Some(l) = lower {
                if cke_key < l {
                    continue;
                }
            }
            if let Some(u) = upper {
                if cke_key >= u {
                    continue;
                }
            }
            let rd = rds
                .iter()
                .filter(|d| d.covers(&uk) && d.seq <= ceiling)
                .map(|d| d.seq)
                .max()
                .unwrap_or(0);
            if rd > rec.seq() || rec.op() == op::DELETE || self.expired(&rec) {
                continue;
            }
            self.counters.scanned_rows += 1;
            if !values {
                rows.push((cke_key.to_vec(), None));
                continue;
            }
            if rec.value_kind == value_kind::VLOG {
                pending.push((rows.len(), VlogPointer::parse(&rec.value)?));
                rows.push((cke_key.to_vec(), None));
                if pending.len() >= window {
                    self.drain_readahead(&mut pending, &mut rows)?;
                }
            } else {
                rows.push((cke_key.to_vec(), Some(rec.value.clone())));
            }
        }
        self.drain_readahead(&mut pending, &mut rows)?;
        for (k, v) in rows {
            out.push((k, v.unwrap_or_default()));
        }
        Ok(out)
    }

    /// §8.1 — sort the window by `(vlog_segment_id, offset)` and **coalesce
    /// reads of records that fall in the same page**. The coalescing is what
    /// `value_reads_per_scanned_row` measures: over a `clustered` cold segment
    /// the scattered reads become strictly sequential, and the metric falls
    /// from ~1 per row to ~1 per page of rows.
    fn drain_readahead(
        &mut self,
        pending: &mut Vec<(usize, VlogPointer)>,
        rows: &mut [(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<()> {
        pending.sort_by_key(|(_, p)| (p.segment_id, p.offset));
        let page_size = self.pager.page_size as u64;
        let mut last: Option<(u64, u64)> = None; // (segment, page index in extent)
        for (i, p) in pending.drain(..) {
            let page = p.offset as u64 / page_size;
            let same_page = last == Some((p.segment_id, page));
            let v = self.read_vlog_uncounted(&p)?;
            if !same_page {
                self.counters.value_reads += 1;
                self.pager.page_reads += 1;
                last = Some((p.segment_id, page));
            }
            rows[i].1 = Some(v);
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // §5 — compaction
    // ---------------------------------------------------------------

    pub fn groups_at(&mut self, level: u8) -> Result<Vec<u8>> {
        let mut g: Vec<u8> = self.refs_at(level)?.into_iter().map(|r| r.group).collect();
        g.sort_unstable();
        g.dedup();
        Ok(g)
    }

    /// Picks the level with the worst overshoot and starts a job, or returns
    /// `None`.
    ///
    /// The picker is an implementation choice (`11-conformance.md` §1.3), but
    /// *which* level it picks is not free of consequences: always draining L0
    /// first lets a deeper level accumulate segments without bound, and §4.1's
    /// read-tail bound is stated over `overlap_bound` segments per level. So
    /// the deepest level over its bound wins ties.
    pub fn pick_compaction(&mut self) -> Result<Option<CompactionJob>> {
        let last = self.policy.last_level();
        let mut best: Option<(f64, u8, Vec<SegmentRef>)> = None;
        for level in 0..last {
            let refs = self.healthy_refs_at(level)?;
            let bound = if level == 0 {
                self.policy.l0_trigger.max(1)
            } else {
                self.policy.tier_width.max(1)
            } as usize;
            if refs.len() < bound {
                continue;
            }
            let score = refs.len() as f64 / bound as f64;
            let better = match &best {
                None => true,
                Some((s, l, _)) => score > *s || (score == *s && level > *l),
            };
            if better {
                best = Some((score, level, refs));
            }
        }
        match best {
            Some((_, level, refs)) => self.begin_compaction(refs, (level + 1).min(last)),
            None => Ok(None),
        }
    }

    /// §5 — merges inputs by internal key, drops what is unreachable, and
    /// writes new output segments. The outcome is normative, the mechanism is
    /// not: after a compaction every `get` at every live snapshot returns
    /// exactly what it returned before.
    pub fn begin_compaction(&mut self, inputs: Vec<SegmentRef>, target: u8) -> Result<Option<CompactionJob>> {
        if inputs.is_empty() {
            return Ok(None);
        }
        let target = target.min(self.policy.last_level());
        let last = self.policy.last_level();
        // §3.1.1 — the last level is **levelled**: its segments partition the
        // user key space with no overlap. A compaction into it must therefore
        // take every last-level segment whose user-key range overlaps the
        // inputs, or the level quietly stops being disjoint and §4's early exit
        // starts returning stale versions while every checksum stays valid.
        let mut inputs = inputs;
        if target == last {
            let have: HashSet<u64> = inputs.iter().map(|r| r.segment_id).collect();
            let lo = inputs.iter().map(|r| user_part(&r.min_key).to_vec()).min().unwrap_or_default();
            let hi = inputs.iter().map(|r| user_part(&r.max_key).to_vec()).max().unwrap_or_default();
            for r in self.healthy_refs_at(last)? {
                if have.contains(&r.segment_id) {
                    continue;
                }
                if user_part(&r.max_key) >= &lo[..] && user_part(&r.min_key) <= &hi[..] {
                    inputs.push(r);
                }
            }
        }
        // §5 condition 3: the compaction must include every segment that could
        // hold an older version, i.e. it reaches the last level, or no lower
        // level overlaps the key.
        let reaches_last = target == last;
        let min_retained = self.min_retained_seq();

        // Merge every input, newest version of a key first (§1's inverted seq
        // makes that the natural order).
        let mut merged: Vec<(Vec<u8>, SegRecord)> = Vec::new();
        for r in &inputs {
            let seg = self.segment(r)?;
            for rec in seg.iter() {
                let rec = rec?;
                merged.push((rec.internal_key.clone(), rec));
            }
        }
        merged.sort_by(|a, b| a.0.cmp(&b.0));

        let mut kept: Vec<SegEntry> = Vec::new();
        let mut last_user: Option<Vec<u8>> = None;
        let mut newer_visible_seq: Option<u64> = None;
        for (ik, rec) in merged {
            let uk = user_part(&ik).to_vec();
            let same_key = last_user.as_deref() == Some(uk.as_slice());
            if !same_key {
                last_user = Some(uk.clone());
                newer_visible_seq = None;
            }
            let seq = rec.seq();
            let drop_it = if same_key {
                // Conditions 1 and 2: a newer version exists in this
                // compaction and its seq is <= the oldest live snapshot's.
                matches!(newer_visible_seq, Some(ns) if ns <= min_retained) && reaches_last
            } else {
                false
            };
            if newer_visible_seq.is_none() {
                newer_visible_seq = Some(seq);
            }
            if drop_it {
                // §6.7 — `live_bytes` is decremented when a compaction observes
                // a record superseded or deleted. Without this the hot tier's
                // liveness never falls, so `locality_debt` reads ~100 % on a
                // database whose values have all been promoted or superseded,
                // and collection never fires.
                self.release_if_vlog(&rec);
                continue;
            }
            if !same_key && matches!(newer_visible_seq, Some(ns) if ns > min_retained) {
                // Kept solely because condition 2 was not met — that is what
                // `pinned_by_snapshots` accumulates (`13-operations.md` §6).
                self.counters.pinned_by_snapshots +=
                    (rec.internal_key.len() + rec.value.len()) as u64;
            }
            // An expired entry may be dropped when condition 3 holds and its
            // deadline is older than the oldest live snapshot's wall clock.
            if reaches_last {
                if let Some(x) = rec.expiry_ms {
                    if x <= self.now_ms && seq <= min_retained {
                        self.release_if_vlog(&rec);
                        continue;
                    }
                }
                // A tombstone may be dropped only when its own seq is <= the
                // oldest live snapshot's; dropping it earlier resurrects the
                // versions it hides.
                if (rec.op() == op::DELETE || rec.op() == op::RANGE_DELETE) && seq <= min_retained {
                    self.release_if_vlog(&rec);
                    continue;
                }
            }
            kept.push(SegEntry {
                internal_key: ik,
                value_kind: rec.value_kind,
                value: rec.value.clone(),
                expiry_ms: rec.expiry_ms,
            });
        }

        // §6.3 — promotion clusters a *generation* of surviving values. Each
        // last-level compaction therefore starts a **fresh** cold segment:
        // appending a second generation into the open one would leave a segment
        // holding two runs, which is not key-clustered and which §6.9 counts as
        // surplus. Merging generations back into one run is collection's job
        // (§6.8), not promotion's.
        if reaches_last {
            if let Some(open) = self.vlog_cold_open {
                self.seal_vlog(open)?;
            }
        }
        let group = if target == last { 0 } else { self.free_group(target)? };
        let per_output = self.segment_entries_at(target);
        Ok(Some(CompactionJob {
            inputs,
            target_level: target,
            target_group: group,
            entries: kept,
            cursor: 0,
            builder: None,
            outputs: Vec::new(),
            per_output,
            bytes_written: 0,
        }))
    }

    fn free_group(&mut self, level: u8) -> Result<u8> {
        let used = self.groups_at(level)?;
        let bound = self.policy.overlap_bound.max(1);
        for g in 0..bound {
            if !used.contains(&g) {
                return Ok(g);
            }
        }
        Ok(used.first().copied().unwrap_or(0))
    }

    /// §5.2 — one step, bounded by `compaction_step_bytes`. A step boundary is
    /// any point between two output leaf pages; the partially built output is
    /// just a prefix, so abandoning it costs the work done and nothing else.
    pub fn step_compaction(&mut self, job: &mut CompactionJob, budget_bytes: Option<u64>) -> Result<bool> {
        self.arm()?;
        let budget = budget_bytes.unwrap_or(self.profile.compaction_step_bytes as u64);
        let mut spent = 0u64;
        while job.cursor < job.entries.len() {
            if job.builder.is_none() {
                let b = SegmentBuilder::with_reserve(
                    self.pager.page_size,
                    self.pager.tag_reserve(),
                    self.sb.next_segment_id,
                    job.target_level,
                    job.target_group,
                    self.filter_bits_at(job.target_level),
                )?;
                self.sb.next_segment_id += 1;
                job.builder = Some(b);
            }
            let mut e = job.entries[job.cursor].clone();
            // §6.3 — during a compaction that outputs the last level, every
            // surviving HOT-tier value is promoted into a COLD segment. The
            // entries arrive in internal-key order, so the cold log is
            // key-clustered by construction.
            if job.target_level == self.policy.last_level() && e.value_kind == value_kind::VLOG {
                let p = VlogPointer::parse(&e.value)?;
                let hot = self.vlog_stats.get(&p.segment_id).map(|s| s.tier == Tier::Hot as u8);
                if hot == Some(true) {
                    let rec = self.read_vlog_record(&p)?;
                    let value = self.read_vlog(&p)?;
                    let parsed = parse_internal_key(&e.internal_key)?;
                    let np = self.append_cold(parsed.tree_id, &rec.key, &value)?;
                    self.release_vlog(&p);
                    e.value = np.encode().to_vec();
                }
            }
            let bytes = e.internal_key.len() + e.value.len() + 16;
            job.builder.as_mut().unwrap().add(e)?;
            job.cursor += 1;
            spent += bytes as u64;
            job.bytes_written += bytes as u64;
            let full = job.builder.as_ref().unwrap().entry_count() >= job.per_output;
            if full {
                self.rotate_output(job)?;
            }
            if spent >= budget {
                return Ok(job.cursor < job.entries.len());
            }
        }
        self.rotate_output(job)?;
        Ok(false)
    }

    fn rotate_output(&mut self, job: &mut CompactionJob) -> Result<()> {
        let Some(b) = job.builder.take() else { return Ok(()) };
        if b.entry_count() == 0 {
            return Ok(());
        }
        let extent = b.build()?;
        let pages = (extent.len() / self.pager.page_size) as u32;
        let start = self.pager.alloc_extent(pages)?;
        self.pager.write_extent(start, &extent)?;
        self.counters.write_amp_key_index += extent.len() as u64;
        job.outputs.push((extent, start));
        Ok(())
    }

    /// `10-transactions.md` §5 — publishing the manifest edit is the only
    /// place concurrent compactions serialize, and it is microseconds.
    pub fn finish_compaction(&mut self, mut job: CompactionJob) -> Result<()> {
        self.arm()?;
        self.rotate_output(&mut job)?;
        let mut m = std::mem::replace(&mut self.manifest, Manifest::new(0));
        m.tree.commit_id = self.sb.commit_id;
        let mut err = None;
        // Inputs are removed **before** outputs are added: a compaction whose
        // output shares a `min_internal_key` with one of its own inputs — which
        // is the normal case for a last-level merge — would otherwise collide
        // with itself in the manifest key space.
        for r in &job.inputs {
            m.remove(&mut self.pager, r)?;
        }
        for (extent, start) in std::mem::take(&mut job.outputs) {
            match Segment::open(extent, self.pager.page_size) {
                Ok(seg) => {
                    let r = SegmentRef::of(&seg, job.target_level, job.target_group, start);
                    self.segments.insert(r.segment_id, Arc::new(seg));
                    if let Err(e) = m.add(&mut self.pager, &r) {
                        err = Some(e);
                    }
                }
                Err(e) => err = Some(e),
            }
        }
        self.manifest = m;
        if let Some(e) = err {
            return Err(e);
        }
        // Input segments removed from the manifest are added to the free tree
        // at the publishing commit_id (`01-container.md` §6).
        for r in &job.inputs {
            self.pager.free_extent(r.start_page, r.pages, self.sb.commit_id);
            self.segments.remove(&r.segment_id);
        }
        self.events.push(StoreEvent::Compacted {
            from: job.inputs[0].level,
            to: job.target_level,
            bytes: job.bytes_written,
        });
        Ok(())
    }

    /// Runs the whole cascade. `12-profiles.md` §4 exempts an explicitly
    /// requested bulk operation from the foreground stall budget, and this is
    /// one; `step_compaction` is the bounded path.
    pub fn drain_compaction(&mut self) -> Result<()> {
        for _ in 0..64 {
            let Some(mut job) = self.pick_compaction()? else { break };
            while self.step_compaction(&mut job, Some(u64::MAX))? {}
            self.finish_compaction(job)?;
        }
        Ok(())
    }

    /// One bounded unit of compaction work, for the foreground path.
    pub fn maybe_compact(&mut self, budget_bytes: Option<u64>) -> Result<()> {
        if self.job.is_none() {
            self.job = self.pick_compaction()?;
        }
        let Some(mut job) = self.job.take() else { return Ok(()) };
        if self.step_compaction(&mut job, budget_bytes)? {
            self.job = Some(job);
        } else {
            self.finish_compaction(job)?;
        }
        Ok(())
    }

    /// §5's full compaction to the last level.
    pub fn compact(&mut self) -> Result<()> {
        let last = self.policy.last_level();
        self.flush()?;
        loop {
            let mut all: Vec<SegmentRef> = Vec::new();
            for level in 0..=last {
                all.extend(self.healthy_refs_at(level)?);
            }
            let above: Vec<SegmentRef> = all.iter().filter(|r| r.level < last).cloned().collect();
            if above.is_empty() {
                break;
            }
            let Some(mut job) = self.begin_compaction(all, last)? else { break };
            while self.step_compaction(&mut job, Some(u64::MAX))? {}
            self.finish_compaction(job)?;
        }
        if self.auto_collect {
            self.collect_while_over_debt(4)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // §6.8, §6.9 — garbage collection and the locality bound
    // ---------------------------------------------------------------

    fn release_if_vlog(&mut self, rec: &SegRecord) {
        if rec.value_kind == value_kind::VLOG {
            if let Ok(p) = VlogPointer::parse(&rec.value) {
                self.release_vlog(&p);
            }
        }
    }

    fn release_vlog(&mut self, p: &VlogPointer) {
        if let Some(s) = self.vlog_stats.get_mut(&p.segment_id) {
            s.live_bytes = s.live_bytes.saturating_sub(p.len as u64);
            s.live_records = s.live_records.saturating_sub(1);
            self.vlog_dirty.insert(p.segment_id);
        }
    }

    pub fn locality_debt(&self) -> f64 {
        let stats: Vec<VlogStats> = self.vlog_stats.values().cloned().collect();
        vlog::locality_debt(&stats, self.sb.vlog_segment_bytes as u64)
    }

    /// §6.8 — a collection MUST be triggered by `locality_debt` as well as by
    /// `vlog_space_target_pct`. A space-only trigger left an aged scan at
    /// 1.58x where a debt trigger held it at 1.00x.
    pub fn collect(&mut self) -> Result<()> {
        self.arm()?;
        // Merge the live records of every cold segment holding live data into
        // one clustered run. Survivors are emitted in `(tree_id, CKE(key))`
        // order and the output keeps `clustered` (§6.8's last MUST).
        let victims: Vec<u64> = self
            .vlog_stats
            .iter()
            .filter(|(_, s)| s.live_bytes > 0 && s.tier == Tier::Cold as u8)
            .map(|(&id, _)| id)
            .collect();
        if victims.len() < 2 {
            return Ok(());
        }
        // Build the survivor set by walking the trees, which is what §6.8's
        // invariant 1 requires: a record is live only if the tree's current
        // entry for its key is a VLOG pointer to this exact (segment, offset).
        let mut live: BTreeMap<Vec<u8>, (u32, VlogPointer, Vec<u8>)> = BTreeMap::new();
        let refs = self.all_refs()?;
        for r in refs {
            let seg = self.segment(&r)?;
            let mut hits = Vec::new();
            for rec in seg.iter() {
                let rec = rec?;
                if rec.value_kind != value_kind::VLOG {
                    continue;
                }
                let p = VlogPointer::parse(&rec.value)?;
                if !victims.contains(&p.segment_id) {
                    continue;
                }
                let uk = rec.user_key().to_vec();
                let parsed = parse_internal_key(&rec.internal_key)?;
                hits.push((uk, parsed.tree_id, p, rec.internal_key.clone()));
            }
            for (uk, tree, p, ik) in hits {
                // Only the current entry counts; a superseded record carries
                // the same key, so a key match alone is not sufficient.
                let current = self.current_pointer(&uk)?;
                if current == Some(p) {
                    live.insert(uk, (tree, p, ik));
                }
            }
        }
        if live.is_empty() {
            return Ok(());
        }
        let dest = self.open_vlog_segment(Tier::Cold, Heat::First)?;
        let mut rewrites: Vec<(Vec<u8>, VlogPointer)> = Vec::new();
        for (uk, (tree, p, _ik)) in &live {
            let rec = self.read_vlog_record(p)?;
            let value = self.read_vlog(p)?;
            let np = self.append_into(Tier::Cold, Heat::First, *tree, &rec.key, &value)?;
            self.counters.write_amp_gc += np.len as u64;
            rewrites.push((uk.clone(), np));
        }
        self.mark_clustered(dest, true)?;
        self.seal_vlog(dest)?;
        // Step 4: write the updated pointers through the normal commit path.
        for (uk, np) in rewrites {
            self.rewrite_pointer(&uk, np)?;
        }
        for v in victims {
            if let Some(s) = self.vlog_stats.get_mut(&v) {
                s.live_bytes = 0;
                s.live_records = 0;
                s.last_gc_seq = self.next_seq;
            }
            self.write_vlog_stats(v)?;
            // Step 5: the extent is freed once the rewrite commit is durable
            // and no live snapshot predates it — `min_retained_commit` is what
            // enforces the second half.
            if let Some(s) = self.vlog_stats.get(&v).cloned() {
                self.pager.free_extent(s.start_page, s.pages, self.sb.commit_id);
            }
        }
        Ok(())
    }

    fn current_pointer(&mut self, user_key: &[u8]) -> Result<Option<VlogPointer>> {
        let tree = u32::from_be_bytes(user_key[0..4].try_into().unwrap());
        let key = cke::decode_all(&user_key[4..])?;
        let _ = tree;
        let _ = key;
        // Resolve by the ordinary read path so the liveness test uses exactly
        // the entry a reader would see.
        let cands = self.candidates_for(user_key)?;
        let mut best: Option<SegRecord> = self.memtable_lookup(user_key, None);
        for r in &cands {
            let seg = self.segment(r)?;
            if let Some(rec) = seg.lookup(user_key, None)? {
                if best.as_ref().map_or(true, |b| rec.seq() > b.seq()) {
                    best = Some(rec);
                }
            }
        }
        match best {
            Some(rec) if rec.value_kind == value_kind::VLOG => {
                Ok(Some(VlogPointer::parse(&rec.value)?))
            }
            _ => Ok(None),
        }
    }

    fn rewrite_pointer(&mut self, user_key: &[u8], np: VlogPointer) -> Result<()> {
        let tree = u32::from_be_bytes(user_key[0..4].try_into().unwrap());
        let cke_key = &user_key[4..];
        let seq = self.allocate_seq(1);
        let ik = internal_key(tree, cke_key, seq, op::PUT);
        self.insert_mem(
            ik,
            MemEntry { value_kind: value_kind::VLOG, value: np.encode().to_vec(), expiry_ms: None },
        );
        Ok(())
    }

    /// §6.9's bound, enforced as an outcome. Collection is triggered when a
    /// compaction *starts* over the bound, so a merge that begins inside it
    /// can still end above it — hence the loop.
    pub fn collect_while_over_debt(&mut self, max_passes: usize) -> Result<()> {
        for _ in 0..max_passes {
            if self.locality_debt() * 100.0 <= self.sb.locality_debt_pct as f64 {
                return Ok(());
            }
            self.collect()?;
            self.flush()?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // §8 — snapshots and retention
    // ---------------------------------------------------------------

    pub fn snapshot(&mut self) -> Snapshot {
        let s = Snapshot {
            seq: self.visible_seq,
            commit_id: self.sb.commit_id,
            catalog_root: self.catalog.tree.root,
            freelist_root: self.freelist.root,
            attributes_root: self.attributes.tree.root,
            manifest_root: self.manifest.root(),
            vlog_stats_root: self.vlog_stats_tree.root,
            checkpoint_root: self.checkpoints.root,
            changefeed_root: self.changefeed.root,
            created_ms: now_millis(),
        };
        self.live_snapshots.push(s);
        s
    }

    pub fn release(&mut self, s: &Snapshot) {
        if let Some(i) = self.live_snapshots.iter().position(|x| x == s) {
            self.live_snapshots.remove(i);
        }
    }

    /// §8 — both floor at `visible_seq`, and that watermark has to keep moving
    /// or retention is unbounded.
    pub fn min_retained_seq(&self) -> u64 {
        self.live_snapshots
            .iter()
            .map(|s| s.seq)
            .chain(self.checkpoint_seqs())
            .min()
            .unwrap_or(self.visible_seq)
            .min(self.visible_seq)
    }

    pub fn min_retained_commit(&self) -> u64 {
        self.live_snapshots
            .iter()
            .map(|s| s.commit_id)
            .chain(self.checkpoint_commits())
            .min()
            .unwrap_or(self.sb.commit_id)
            .min(self.sb.commit_id)
            .saturating_sub(1)
    }

    /// `13-operations.md` §1 — "A checkpoint holds `min_retained_commit` and
    /// `min_retained_seq` down to its own values, exactly as a live reader
    /// does. It therefore **pins space**." Without this, the pages its roots
    /// name are reclaimed and a restore reads whatever was written over them.
    ///
    /// Cached rather than scanned: retention is consulted on every commit, and
    /// tree 8 only changes when a checkpoint is created, dropped or restored.
    pub fn refresh_checkpoint_floors(&mut self) -> Result<()> {
        let tree = CowTree::new(tree_id::CHECKPOINTS, self.checkpoints.root);
        let rows = tree.scan(&mut self.pager, None, None)?;
        let (mut seq, mut commit) = (None, None);
        for (_, v) in rows {
            let Ok(d) = cve::decode_all(&v, &|_| None) else { continue };
            let u = |f: &str| match d.field(f) {
                Some(Value::Int { mag, .. }) => Some(*mag as u64),
                _ => None,
            };
            if let Some(s) = u("seq") {
                seq = Some(seq.map_or(s, |m: u64| m.min(s)));
            }
            if let Some(c) = u("commit_id") {
                commit = Some(commit.map_or(c, |m: u64| m.min(c)));
            }
        }
        self.checkpoint_floor = (seq, commit);
        Ok(())
    }

    fn checkpoint_seqs(&self) -> Vec<u64> {
        self.checkpoint_floor.0.into_iter().collect()
    }

    fn checkpoint_commits(&self) -> Vec<u64> {
        self.checkpoint_floor.1.into_iter().collect()
    }
 pub fn oldest_snapshot_age_ms(&self) -> Option<i64> {
        self.live_snapshots.iter().map(|s| now_millis() - s.created_ms).max()
    }

    pub fn live_snapshot_count(&self) -> usize {
        self.live_snapshots.len()
    }

    // ---------------------------------------------------------------
    // §2 steps F and G — the commit
    // ---------------------------------------------------------------

    pub fn commit(&mut self, durability: Durability) -> Result<u64> {
        self.arm()?;
        self.publish_tree_index_root()?;
        // §2.3 invariant 2 — the value-log watermark is published here, through
        // the ordinary commit path, because tree 7 is the authority for it and
        // the head page (written once) is not.
        for id in std::mem::take(&mut self.vlog_dirty) {
            self.write_vlog_stats(id)?;
        }
        // Trees the commit itself edits, published as roots below.
        self.persist_freelist()?;
        let new_commit = self.sb.commit_id + 1;
        self.sb.commit_id = new_commit;
        self.sb.visible_seq = self.visible_seq;
        self.sb.next_seq = self.next_seq;
        self.sb.next_tree_id = self.catalog.next_tree_id;
        self.sb.catalog_root = self.catalog.tree.root;
        self.sb.freelist_root = self.freelist.root;
        self.sb.attributes_root = self.attributes.tree.root;
        self.sb.manifest_root = self.manifest.root();
        self.sb.vlog_stats_root = self.vlog_stats_tree.root;
        self.sb.checkpoint_root = self.checkpoints.root;
        self.sb.changefeed_root = self.changefeed.root;
        self.sb.min_retained_commit = self.min_retained_commit();
        self.sb.min_retained_seq = self.min_retained_seq();
        self.sb.modified_utc_ms = now_millis();
        self.pager.min_retained_commit = self.sb.min_retained_commit;
        self.write_superblock(durability)?;
        self.prune_written_at();
        self.events.push(StoreEvent::Commit {
            commit_id: new_commit,
            visible_seq: self.visible_seq,
        });
        Ok(new_commit)
    }

    /// §6's free tree, written through the ordinary commit path.
    ///
    /// **The free tree is the one tree whose own churn it cannot record in the
    /// same commit**: writing an entry copies a root-to-leaf path, which
    /// orphans pages, which are new entries, which orphan more pages. Recording
    /// them lands in the pager's list and is persisted by the *next* commit —
    /// a bounded one-commit lag, whose residue `01-container.md` §9 step 7
    /// reports as a **leak** (repairable) rather than as corruption, and which
    /// `13-operations.md` §3 reclaims.
    ///
    /// Only entries this commit has not already written are put, or re-putting
    /// the whole list would copy a path per entry and the lag would grow
    /// instead of shrinking.
    fn persist_freelist(&mut self) -> Result<()> {
        let mut freed: Vec<u64> = Vec::new();
        for t in [
            &mut self.catalog.tree,
            &mut self.catalog.by_id,
            &mut self.attributes.tree,
            &mut self.manifest.tree,
            &mut self.vlog_stats_tree,
            &mut self.checkpoints,
            &mut self.changefeed,
            &mut self.freelist,
        ] {
            freed.append(&mut t.freed);
        }
        for p in &freed {
            self.pager.free_extent(*p, 1, self.sb.commit_id);
        }
        // Tree 1 must be the free list, not a log of everything that was ever
        // freed. An earlier version only ever *inserted*, on the reasoning that
        // "a commit writes only what is new" — but an extent leaves the free
        // list when it is reclaimed (§6), and a best-fit allocation that takes
        // part of one moves the remainder to a different key. Neither was ever
        // removed, so the persisted tree was a strict superset of the truth.
        //
        // That is invisible to the implementation that wrote it, which keeps
        // its own list in memory and never reads tree 1 back within a session.
        // It is fatal to any *other* implementation: it allocates a page tree 1
        // calls free, the live superblock still names it, and the catalog it
        // overwrites is gone. Found by the round-trip gate the moment the Dart
        // side started reading tree 1 at all — which is what a second
        // implementation is for.
        let extents = self.pager.free_list();
        let mut t = std::mem::replace(&mut self.freelist, CowTree::new(tree_id::FREE_SPACE, 0));
        t.commit_id = self.sb.commit_id;
        let key_of = |commit_id: u64, start_page: u64| {
            cke::encode(&Value::Array(vec![
                Value::Int { w: NumType::U64, neg: false, mag: commit_id as u128 },
                Value::Int { w: NumType::U64, neg: false, mag: start_page as u128 },
            ]))
        };
        let now: HashSet<(u64, u64)> = extents.iter().map(|e| (e.commit_id, e.start_page)).collect();
        for gone in self.persisted_free.difference(&now).cloned().collect::<Vec<_>>() {
            t.remove(&mut self.pager, &key_of(gone.0, gone.1)?)?;
        }
        for e in &extents {
            if self.persisted_free.contains(&(e.commit_id, e.start_page)) {
                continue;
            }
            let v = cve::encode(&Value::Doc(vec![(
                "pages".into(),
                Value::Int { w: NumType::U32, neg: false, mag: e.pages as u128 },
            )]));
            t.put(&mut self.pager, &key_of(e.commit_id, e.start_page)?, &v)?;
        }
        self.persisted_free = now;
        self.freelist = t;
        Ok(())
    }

    pub fn write_superblock(&mut self, durability: Durability) -> Result<()> {
        self.sb.page_count = self.pager.page_count;
        self.sb.durability_achieved = self.durability_achieved as u8;
        // §2's alternate-slot rule: a crash during a superblock write leaves
        // the previous superblock intact.
        let offset = self.pager.slot_offset(self.sb.commit_id);
        // C then E then G: barrier over the data before the superblock, and
        // again after it.
        let achieved = self.pager.sync(durability)?;
        let mut image = self.sb.encode();
        if let Some(ring) = &self.keys {
            ring.seal_superblock(&mut image);
            // The MAC just written is now the file's, so it has to be the
            // in-memory superblock's too. Without this, `verify_superblock`
            // recomputes over the *current* fields and compares against the
            // MAC parsed at open — which described the fields as they were
            // *before* this write. Every encrypted file therefore failed §9
            // step 8 as **tampering** the moment anything wrote a superblock,
            // and `14-security.md` §4.1's open-time nonce publish is a
            // superblock write, so it was every encrypted file after every
            // open. Invisible here because the only verifier that checked was
            // the other implementation's.
            self.sb.sb_mac.copy_from_slice(
                &image[crate::container::sb::SB_MAC..crate::container::sb::SB_MAC + 32],
            );
        }
        self.pager.write_at(offset, &image)?;
        let achieved2 = self.pager.sync(durability)?;
        self.durability_achieved = achieved.min(achieved2);
        self.sb.durability_achieved = self.durability_achieved as u8;
        Ok(())
    }

    fn prune_written_at(&mut self) {
        let floor = self.min_retained_seq();
        self.written_at.retain(|_, seq| *seq >= floor);
    }

    /// `10-transactions.md` §3 — conflict detection compares a transaction's
    /// written key set against keys written by batches sequenced in between.
    pub fn conflicts(&self, keys: &[Vec<u8>], start_seq: u64) -> bool {
        keys.iter().any(|k| matches!(self.written_at.get(k), Some(&s) if s > start_seq))
    }

    // ---------------------------------------------------------------
    // `13-operations.md` §4 — corruption containment
    // ---------------------------------------------------------------

    /// Takes a segment out of service after a checksum failure, steps 1–2.
    /// The affected key range is knowable without touching the damaged extent
    /// at all, which is what makes containment cheap.
    pub fn quarantine(&mut self, segment_id: u64) -> Result<Option<SegmentRef>> {
        if let Some(r) = self.quarantined.get(&segment_id) {
            return Ok(Some(r.clone()));
        }
        for r in self.all_refs()? {
            if r.segment_id == segment_id {
                self.quarantined.insert(segment_id, r.clone());
                self.segments.remove(&segment_id);
                return Ok(Some(r));
            }
        }
        Ok(None)
    }

    pub fn affected_trees(&self) -> HashSet<u32> {
        self.quarantined.values().flat_map(|r| r.trees.iter().copied()).collect()
    }

    pub fn memtable_pressure(&self) -> (usize, usize) {
        (self.memtable_len(), self.memtable_entry_limit)
    }

    pub fn page_size(&self) -> usize {
        self.pager.page_size
    }
}

pub fn encode_vlog_stats(s: &VlogStats) -> Vec<u8> {
    let u = |v: u64| Value::Int { w: NumType::U64, neg: false, mag: v as u128 };
    let mut f = vec![
        ("bytes".to_string(), u(s.bytes)),
        ("records".to_string(), u(s.records)),
        ("sealed".to_string(), Value::Bool(s.sealed)),
        ("clustered".to_string(), Value::Bool(s.clustered)),
        ("start_page".to_string(), u(s.start_page)),
        ("pages".to_string(), Value::Int { w: NumType::U32, neg: false, mag: s.pages as u128 }),
        ("live_bytes".to_string(), u(s.live_bytes)),
        ("live_records".to_string(), u(s.live_records)),
        ("tier".to_string(), Value::Int { w: NumType::U8, neg: false, mag: s.tier as u128 }),
        ("heat".to_string(), Value::Int { w: NumType::U8, neg: false, mag: s.heat as u128 }),
        ("created_seq".to_string(), u(s.created_seq)),
        ("last_gc_seq".to_string(), u(s.last_gc_seq)),
    ];
    // §6.7: `min_key`/`max_key` are present iff clustered.
    if s.clustered {
        if let Some(k) = &s.min_key {
            f.push(("min_key".to_string(), Value::Bytes(k.clone())));
        }
        if let Some(k) = &s.max_key {
            f.push(("max_key".to_string(), Value::Bytes(k.clone())));
        }
    }
    cve::encode(&Value::Doc(f))
}

pub fn decode_vlog_stats(id: u64, v: &[u8]) -> Result<VlogStats> {
    let d = cve::decode_all(v, &|_| None)?;
    let u = |f: &str| -> u64 {
        match d.field(f) {
            Some(Value::Int { mag, .. }) => *mag as u64,
            _ => 0,
        }
    };
    let b = |f: &str| matches!(d.field(f), Some(Value::Bool(true)));
    let by = |f: &str| match d.field(f) {
        Some(Value::Bytes(x)) => Some(x.clone()),
        _ => None,
    };
    Ok(VlogStats {
        segment_id: id,
        bytes: u("bytes"),
        records: u("records"),
        sealed: b("sealed"),
        clustered: b("clustered"),
        min_key: by("min_key"),
        max_key: by("max_key"),
        start_page: u("start_page"),
        pages: u("pages") as u32,
        live_bytes: u("live_bytes"),
        live_records: u("live_records"),
        tier: u("tier") as u8,
        heat: u("heat") as u8,
        created_seq: u("created_seq"),
        last_gc_seq: u("last_gc_seq"),
    })
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// RFC 4122 v4, from the OS entropy the AEAD already needs.
pub fn random_uuid_v4() -> [u8; 16] {
    let mut b = crate::security::random_bytes::<16>();
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    b
}

/// A convenience for the page-level codec path, kept here because it is the
/// only place `01-container.md` §7's order (compress, then encrypt) and §8's
/// read order (verify checksum, decrypt, then decompress) both apply.
pub fn encode_data_page(
    page_size: usize,
    page_type_id: u8,
    tree: u32,
    commit_id: u64,
    payload: &[u8],
    page_codec: u8,
) -> Result<Vec<u8>> {
    let mut page = vec![0u8; page_size];
    let cap = page_size - PAGE_HEADER_BYTES;
    let (body, flags, codec_id) = match codec::compress(page_codec, payload)? {
        Some(c) if c.len() <= cap => (c, page_flags::COMPRESSED, page_codec as u16),
        _ => (payload.to_vec(), 0u8, 0u16),
    };
    if body.len() > cap {
        return invalid("page payload does not fit");
    }
    page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + body.len()].copy_from_slice(&body);
    PageHeader {
        page_type: page_type_id,
        flags,
        codec: codec_id,
        tree_id: tree,
        extent_pages: 1,
        commit_id,
        payload_len: payload.len() as u32,
        ..Default::default()
    }
    .write_into(&mut page);
    Ok(page)
}

pub fn decode_data_page(page: &[u8], page_id: u64) -> Result<Vec<u8>> {
    let h = PageHeader::verify(page, page_id)?;
    let body = &page[PAGE_HEADER_BYTES..];
    if h.compressed() {
        codec::decompress(h.codec as u8, body, h.payload_len as usize)
    } else {
        Ok(body[..(h.payload_len as usize).min(body.len())].to_vec())
    }
}

pub const _PAGE_TYPES: [u8; 3] =
    [page_type::BTREE_LEAF, page_type::BTREE_INTERNAL, page_type::OVERFLOW];
