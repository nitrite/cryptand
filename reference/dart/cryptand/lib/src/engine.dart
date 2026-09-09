/// An LSM engine over the segments of `spec/04-segments.md`: a memtable, an
/// L0, range-partitioned tiered levels, a levelled last level, the manifest as
/// a copy-on-write tree, and the two-tier value log.
///
/// **Scope, stated plainly.** Phase 2 built the smallest engine that could
/// measure prediction P8 — an aged scan over separated values — and had one
/// L0 and one last level. Phase 3 adds §3's level policy and §3.2's manifest,
/// which is what prediction P10 (the bounded read tail) is a claim about. It
/// still does **not** implement range deletes, TTL, transactions, or
/// concurrency: Dart has no threads, so `spec/10-transactions.md` §2 cannot be
/// measured here at all, and `REPORT.md` says so rather than pretending.
library;

import 'dart:collection';
import 'dart:typed_data';

import 'bytes.dart';
import 'changefeed.dart';
import 'container.dart';
import 'checkpoint.dart';
import 'cke.dart';
import 'cow.dart';
import 'errors.dart';
import 'manifest.dart';
import 'security.dart';
import 'segment.dart';
import 'txn.dart';
import 'value.dart';
import 'vlog.dart';

/// One compaction in progress, `spec/04-segments.md` §5.2.
///
/// A compaction job is **decomposable into steps of at most
/// `compaction_step_bytes`, between which it can yield**. That is a normative
/// MUST and it is what `spec/12-profiles.md` §4's foreground stall budget rests
/// on: on a runtime with no threads to move compaction to, the only way not to
/// block the caller for 22 ms is to do 256 KiB of the work and come back.
///
/// The reason it is cheap to hold this state is §5.2's own: "Because segments
/// are built bottom-up from a sorted stream, the partially built output is just
/// a prefix — abandoning it costs the work done and nothing else, and no reader
/// can see it." Nothing here is published until [Engine.finishCompaction], so a
/// job may be dropped at any point without touching a live structure.
final class CompactionJob {
  CompactionJob({
    required this.inputs,
    required this.target,
    required this.levelled,
    required this.group,
    required this.sources,
    required this.out,
    required this.retained,
    required this.published,
    required this.nowMs,
    required this.recluster,
  });

  final List<SegmentRef> inputs;
  final int target;
  final bool levelled;
  final int group;
  final List<SegmentCursor> sources;
  final List<VlogPointer> dead = [];
  final List<Segment> outputs = [];

  SegmentBuilder out;
  Uint8List? lastUserKey;
  int newestSeq = 0;
  int pinned = 0;

  final int retained;
  final int published;
  final int nowMs;
  final bool recluster;

  /// Logical bytes merged, which is what the step budget is measured in.
  int bytesMerged = 0;
  int steps = 0;
  bool exhausted = false;

  /// The input segment ids, so a job can be abandoned when the manifest moves
  /// underneath it (§5: "A job whose input segments were removed by another
  /// job in the meantime MUST abort and be rescheduled").
  Set<int> get inputIds => {for (final r in inputs) r.segmentId};
}

/// One buffered write, before it reaches a segment.
final class _Pending {
  _Pending(this.internalKey, this.valueKind, this.value, {this.expiryMs});
  final Uint8List internalKey;
  final int valueKind;
  final Uint8List value;

  /// `spec/04-segments.md` §9 — Unix milliseconds, UTC.
  final int? expiryMs;
}

/// How aggressively the engine keeps values near their keys.
///
/// Every one of these is a MUST in the spec. They are switchable here for one
/// reason: prediction P8 says an aged scan costs "≥ 6× with all three
/// disabled", and a claim about what happens when a mechanism is off can only
/// be measured by turning it off.
final class LocalityPolicy {
  const LocalityPolicy({
    this.clusteredPromotion = true,
    this.readahead = true,
    this.readaheadWindow = 256,
  });

  /// `spec/04-segments.md` §6.3 — promote surviving hot values into the cold
  /// tier during last-level compaction, in key order.
  final bool clusteredPromotion;

  /// §8.1 — a cursor dereferencing values issues its reads in non-decreasing
  /// `(segment, offset)` order over a sliding window.
  final bool readahead;
  final int readaheadWindow;

  static const LocalityPolicy none =
      LocalityPolicy(clusteredPromotion: false, readahead: false);
}

/// The level policy of `spec/04-segments.md` §3.1 — lazy levelling with
/// range-partitioned tiers.
///
/// **Deliberately not in the file format.** §3.1: "A conforming reader MUST
/// NOT depend on the policy. It reads the manifest and resolves by `seq`."
/// These are superblock fields (`spec/01-container.md` §2, offsets 181, 182,
/// 217), advisory to a reader and binding only on the writer.
final class LevelPolicy {
  const LevelPolicy({
    this.l0Trigger = 4,
    this.tierWidth = 4,
    this.overlapBound = 2,
    this.levelCount = 4,
  });

  /// L0 segments before compaction.
  final int l0Trigger;

  /// Segments per tiered level.
  final int tierWidth;

  /// Max segments at one tiered level covering any single key. Each group is
  /// one mutually disjoint run, so this is also the group count.
  final int overlapBound;

  /// L0 … L(levelCount-1); the last is levelled and disjoint.
  final int levelCount;

  /// `desktop`, `spec/12-profiles.md` §1.
  static const LevelPolicy desktop = LevelPolicy();

  /// `mobile`: `overlap_bound = 1` makes tiered levels fully range-partitioned,
  /// so a lookup consults one segment per level (`spec/12-profiles.md` §4).
  static const LevelPolicy mobile =
      LevelPolicy(l0Trigger: 2, tierWidth: 2, overlapBound: 1);

  /// **Plain tiering**, which is this policy with `overlap_bound = tier_width`
  /// and nothing else changed.
  ///
  /// That equality is the whole content of §3.1's addition: "Plain tiering lets
  /// all `tier_width` segments at a level overlap a key, so a point lookup's
  /// worst case grows with the tier width. Range partitioning splits each
  /// tiered level's segments into `overlap_bound` groups of mutually disjoint
  /// segments." A level holds `overlap_bound` disjoint runs of
  /// `tier_width / overlap_bound` segments each; setting the two equal gives
  /// `tier_width` runs of one whole-range segment, which is plain tiering.
  /// It is therefore the control for prediction P10, and it needs no switch in
  /// the engine — only a different policy.
  LevelPolicy get plainTiered => LevelPolicy(
        l0Trigger: l0Trigger,
        tierWidth: tierWidth,
        overlapBound: tierWidth,
        levelCount: levelCount,
      );

  /// The candidate bound of §4.1:
  /// `l0_trigger + overlap_bound × (level_count − 2) + 1`.
  int get candidateBound =>
      l0Trigger + overlapBound * (levelCount - 2) + 1;
}

/// A store over the trees of one file.
final class Engine {
  Engine({
    this.pageSize = 4096,
    this.vlogMin = 2048,
    this.memtableEntries = 20000,
    this.policy = const LocalityPolicy(),
    this.levels = LevelPolicy.desktop,
    this.vlogSpaceTargetPct = 150,
    this.localityDebtPct = 20,
    this.filters = true,
    this.earlyExit = true,
    int? segmentEntries,
    int? vlogSegmentBytes,
    int cachePages = 256,
    PageStore? store,
    int manifestRoot = 0,
    int freelistRoot = 0,
    int checkpointRoot = 0,
    int changefeedRoot = 0,
  })  : segmentEntries = segmentEntries ?? memtableEntries,
        store = store ?? PageStore(pageSize: pageSize),
        vlog = ValueLog(
          pageSize: pageSize,
          segmentBytes: vlogSegmentBytes ?? (4 << 20),
          cachePages: cachePages,
        ) {
    manifest = Manifest(this.store, root: manifestRoot);
    freelist = CowTree(this.store, treeId: TreeId.freeSpace, root: freelistRoot);
    checkpoints = CheckpointStore(this.store, root: checkpointRoot);
    changeFeed = ChangeFeed(this.store, root: changefeedRoot);
    _refreshRetention();
  }

  /// Adopts the counters a file carries (`spec/01-container.md` §2).
  ///
  /// Ids are "never reused" (`spec/00-conventions.md` §7), and that has to
  /// survive a reopen for the same reason it has to survive a crash — so the
  /// counters are restored, never recomputed from what happens to be present.
  void restoreCounters({
    required int nextSeq,
    required int nextSegmentId,
    required int visibleSeq,
    required int commitId,
  }) {
    _nextSeq = nextSeq;
    _nextSegmentId = nextSegmentId;
    this.visibleSeq = visibleSeq;
    this.commitId = commitId;
    _refreshRetention();
  }

  int get nextSeq => _nextSeq;
  int get nextSegmentId => _nextSegmentId;

  final int pageSize;

  /// `spec/00-conventions.md` §8: MUST be ≤ page_size / 4.
  final int vlogMin;
  final int memtableEntries;

  /// Entries per L0 segment; higher levels scale from it, see
  /// [segmentEntriesAt].
  final int segmentEntries;

  final LocalityPolicy policy;
  final LevelPolicy levels;

  /// Whether segments carry a §2.4 filter. Off is the second control for
  /// prediction P10, and it is also what `filter_page = 0` means on disk.
  final bool filters;

  /// Whether a lookup stops at the first candidate that holds the key.
  ///
  /// §4 permits this "only when it can prove no unexamined candidate can hold
  /// a newer version of *this* key — the standard proof is level discipline:
  /// L0 newest-flush-first, then strictly increasing level." That proof holds
  /// for this level policy, and [candidatesFor] emits candidates in exactly
  /// that order. Off, every candidate is examined and the winner is chosen by
  /// its own seq, which is what §4 requires absent the proof.
  ///
  /// It is a switch because prediction P10's arithmetic silently assumes the
  /// early exit — it counts false positives and nothing else — and the two
  /// paths measure very different numbers under an update-heavy load.
  final bool earlyExit;

  /// `vlog_space_target_pct` (`spec/01-container.md` §2). Crossing it is what
  /// triggers a cold-tier collection, which is also what restores clustering
  /// across compactions.
  final int vlogSpaceTargetPct;

  /// `locality_debt_pct` (`spec/01-container.md` §2, `spec/04-segments.md`
  /// §6.9). The ceiling on the fraction of live value bytes in surplus runs.
  final int localityDebtPct;

  /// Wall clock used for §9's expiry when a caller supplies none.
  ///
  /// §9: "expiry uses wall-clock time and is therefore subject to clock
  /// changes... an implementation MUST treat a backwards clock jump as
  /// resurrecting entries rather than as corruption." Making the clock an
  /// injectable field is what lets that rule be tested rather than asserted.
  int nowMs = 0;

  final ValueLog vlog;

  /// `database_uuid` (`spec/01-container.md` §2).
  ///
  /// Load-bearing beyond identity: `spec/14-security.md` §3.4 derives every
  /// subkey with it as the HKDF salt, so two files sharing a uuid share a
  /// content key — which is why `13-operations.md` §2.1 forbids a backup from
  /// copying it, with one stated exception.
  Uint8List databaseUuid = Uint8List(16);

  /// `writer_id` (`spec/01-container.md` §2) — accumulated into the `writers`
  /// list of `05-catalog.md` §7.
  String writerId = 'cryptand-dart';

  /// Every distinct writer that has modified this file (`05-catalog.md` §7).
  /// "A genuinely useful field the moment a file is being handed between SDKs,
  /// and the first thing to look at when a file misbehaves."
  final List<String> writers = ['cryptand-dart'];

  /// The file's page space. The manifest lives in it; segment extents do not,
  /// which `REPORT.md` §5 states as a limit of this implementation.
  final PageStore store;

  /// Tree 6.
  late final Manifest manifest;

  /// Tree 1, `spec/01-container.md` §6. Held across saves rather than rebuilt,
  /// so the pages of the previous free tree are freed rather than orphaned.
  late final CowTree freelist;

  /// Tree 8, `spec/13-operations.md` §1.
  late final CheckpointStore checkpoints;

  /// Tree 9, `spec/13-operations.md` §7. Off by default: it costs a write per
  /// mutation and most databases do not sync.
  late final ChangeFeed changeFeed;

  /// Trees whose mutations are appended to the feed —
  /// `params.change_feed = true` (`05-catalog.md` §3.1).
  final Set<int> changeFeedTrees = {};

  // -------------------------------------------------------------------------
  // Sequencing and visibility — `spec/10-transactions.md` §1, §2
  // -------------------------------------------------------------------------

  /// The greatest seq that is committed and durable, §1. A new reader takes
  /// `S.seq = visible_seq`.
  int visibleSeq = 0;

  int commitId = 1;

  /// Live snapshots, §8. They pin space, versions **and value-log segments**,
  /// and the amount "is not obvious from the outside", which is why §8 requires
  /// the watermarks and the age to be exposed.
  final Set<Snapshot> _liveSnapshots = {};

  /// Keys written by committed batches, with the seq that wrote them.
  ///
  /// This is what §3's conflict detection compares against. It is pruned at
  /// [minRetainedSeq] — no live snapshot can be older, so an entry below it can
  /// never conflict with a transaction that is still open — which is what keeps
  /// it bounded by the oldest live reader rather than by history.
  final Map<String, int> _writtenAt = {};

  /// §9. Events are appended after durability, never before.
  final List<StoreEvent> events = [];

  /// §7. What this implementation actually performs, not what was asked for.
  ///
  /// In-memory extents with no file under them cannot survive a process crash,
  /// so the honest report is `none`. §7's rule is that an implementation
  /// records what it did; claiming a mode it did not reach is the silent
  /// failure the chapter exists to prevent.
  Durability durabilityAchieved = Durability.none;

  bool _closed = false;

  /// Segment extents by `segment_id`, standing in for `start_page`/`pages`.
  final Map<int, Segment> extents = {};

  /// Segments a checksum failure has taken out of service, and the key range
  /// each one covered — `spec/13-operations.md` §4.
  ///
  /// "A single damaged page MUST NOT make the whole database unreadable." The
  /// alternative, which every engine Nitrite uses today exhibits, is that one
  /// bad block turns a phone user's entire journal into an error message.
  final Map<int, SegmentRef> quarantined = {};

  /// §4 step 5: trees whose data is now incomplete, so a planner must not
  /// silently substitute an index scan that would return partial results.
  Set<int> get affectedTrees =>
      {for (final r in quarantined.values) ...r.trees};

  /// Takes a segment out of service after a checksum failure, §4 steps 1–2.
  ///
  /// Returns the manifest entry, whose `min_key`/`max_key` are the affected
  /// key range the chapter requires be *reported* — the range is knowable
  /// without touching the damaged extent at all, which is what makes
  /// containment cheap.
  SegmentRef quarantine(int segmentId) {
    final existing = quarantined[segmentId];
    if (existing != null) return existing;
    for (var l = 0; l <= lastLevel; l++) {
      for (final r in refsAt(l)) {
        if (r.segmentId == segmentId) {
          quarantined[segmentId] = r;
          return r;
        }
      }
    }
    throw InvalidArgumentException('no segment $segmentId in the manifest');
  }

  /// Verifies every live segment's page checksums, quarantining what fails.
  ///
  /// `spec/01-container.md` §9 step 2, with §4's containment applied rather
  /// than an exception thrown: verification **reports**.
  List<SegmentRef> verify() {
    final bad = <SegmentRef>[];
    for (var l = 0; l <= lastLevel; l++) {
      for (final r in refsAt(l)) {
        if (quarantined.containsKey(r.segmentId)) continue;
        try {
          extents[r.segmentId]!.verifyChecksums();
        } on CorruptionException {
          bad.add(quarantine(r.segmentId));
        }
      }
    }
    return bad;
  }

  /// The memtable, ordered by internal key.
  ///
  /// This was a `Map<Uint8List, _Pending>`, and a plain `Map` keyed by
  /// `Uint8List` cannot be looked up at all: Dart gives `Uint8List` identity
  /// equality, so a key rebuilt from the same bytes is a *different* key. Every
  /// point read therefore walked the whole memtable comparing prefixes by hand
  /// — O(pending writes) per `get`, against `memtableEntries` of 4096 — and the
  /// scan path sorted a filtered copy of the keys on every call.
  ///
  /// The Rust implementation range-seeks an ordered map and breaks when the
  /// prefix stops matching; Java uses a `ConcurrentSkipListMap`. An ordered map
  /// here makes the lookup O(log n), makes `_memtable[k]` work by content, and
  /// makes the two sorts below redundant, because `keys` is already in
  /// `compareKeys` order.
  final SplayTreeMap<Uint8List, _Pending> _memtable =
      SplayTreeMap<Uint8List, _Pending>(compareKeys);

  int _nextSeq = 1;
  int _nextSegmentId = 1;

  /// The compaction in flight, if any. At most one, because this SDK is
  /// single-writer (`spec/11-conformance.md` §1.1); §5.1's parallel jobs on
  /// disjoint ranges need threads.
  CompactionJob? _job;

  /// Whether a compaction is part-done. Exposed because a caller pacing
  /// maintenance needs to know there is work outstanding.
  bool get hasPendingCompaction => _job != null;

  int get lastLevel => levels.levelCount - 1;

  /// The oldest live snapshot's seq, or [visibleSeq] when none is live.
  ///
  /// §8: it "bounds version collapsing in compaction" — a compaction may drop
  /// a superseded version only when the *newer* version is at or below this.
  ///
  /// **A checkpoint counts exactly as a live reader does**
  /// (`13-operations.md` §1): it holds the watermarks down to its own values,
  /// which is what makes `open_at` work later and what makes a forgotten
  /// checkpoint an unbounded space leak.
  int get minRetainedSeq {
    var m = visibleSeq;
    for (final s in _liveSnapshots) {
      if (s.seq < m) m = s.seq;
    }
    for (final c in checkpoints.all) {
      if (c.seq < m) m = c.seq;
    }
    return m;
  }

  // -------------------------------------------------------------------------
  // `spec/14-security.md` — the ring, and the one nonce cursor under it
  // -------------------------------------------------------------------------

  /// The unlocked key material, or null on an unencrypted database.
  KeyRing? keys;

  NonceAllocator? _nonces;

  /// Installs the page cipher (section 5.2) and the value-log record cipher
  /// (section 5.3) from **one** allocator.
  ///
  /// One cursor for both, because two would be two chances to hand the same
  /// counter out twice, and section 4 opens by saying nonce uniqueness "is not
  /// a hardening measure; it is the whole thing".
  void installKeys(KeyRing ring, NonceAllocator nonces) {
    keys = ring;
    _nonces = nonces;
    store.crypto = PageCrypto(ring, nonces);
    vlog.crypto = VlogCrypto(ring, nonces.allocate);
  }

  NonceAllocator? get nonces => _nonces;

  /// The superblock this engine was opened from, when there is a file under
  /// it. `spec/01-container.md` §9 step 8 needs it: `sb_mac` is verified
  /// against the fields it authenticates, and only the container has them.
  Superblock? superblock;

  /// Section 11: "an implementation MUST zero the master key and every subkey
  /// on close()."
  void destroyKeys() {
    keys?.destroy();
    keys = null;
    store.crypto = null;
    vlog.crypto = null;
    _nonces = null;
  }

  /// §8: bounds page reuse.
  ///
  /// One below the minimum, not the minimum. The reclamation rule of
  /// `spec/01-container.md` §6 is "an extent freed at `commit_id = N` may be
  /// reallocated once `N <= min_retained_commit`", so returning the current
  /// commit id would make a page freed by *this* commit immediately
  /// reallocatable — and the previous superblock still names it. That is the
  /// one thing copy-on-write must never do: "no page that a live superblock
  /// references is ever overwritten."
  int get minRetainedCommit {
    var m = commitId;
    for (final s in _liveSnapshots) {
      if (s.commitId < m) m = s.commitId;
    }
    for (final c in checkpoints.all) {
      if (c.commitId < m) m = c.commitId;
    }
    return m > 0 ? m - 1 : 0;
  }

  /// Opens a new commit for a superblock that is about to be published.
  ///
  /// Publishing a superblock **is** a commit (`spec/01-container.md` §2), and
  /// the commit id is what §6's reclamation rule is stated over: pages the new
  /// superblock orphans are attributed to it, and everything the *previous*
  /// commits freed becomes reallocatable. Without this a file written by
  /// `save` alone never advances past commit 1, `min_retained_commit` stays 0,
  /// and the free tree accumulates space no session may ever reuse.
  int beginPublish() {
    commitId++;
    _refreshRetention();
    return commitId;
  }

  /// Pushes §6's retention floor and the committing id into the page space.
  /// The store is what allocates, so it is what has to know both.
  void _refreshRetention() {
    store
      ..commitId = commitId
      ..minRetainedCommit = minRetainedCommit;
  }

  // -------------------------------------------------------------------------
  // Checkpoints — `spec/13-operations.md` §1
  // -------------------------------------------------------------------------

  /// §1: refuse by default to create a checkpoint pinning more than this
  /// fraction of the live size. Default 25 %.
  int checkpointSpaceLimitPct = 25;

  /// Creates a named, retained snapshot.
  ///
  /// One small write; it costs nothing until the data diverges from it.
  Checkpoint createCheckpoint(String name,
      {int? expires, int nowMs = 0, bool force = false}) {
    if (checkpoints.get(name) != null) {
      throw InvalidArgumentException('a checkpoint named "$name" exists');
    }
    if (!force) {
      final pinned = checkpointWouldPin();
      final live = vlog.liveBytes;
      if (live > 0 && pinned * 100 > live * checkpointSpaceLimitPct) {
        throw LimitException(
            'this checkpoint would pin $pinned B against a live size of '
            '$live B, over checkpoint_space_limit of '
            '$checkpointSpaceLimitPct% — pass force to override');
      }
    }
    final s = snapshot(nowMs: nowMs);
    release(s); // the checkpoint pins it from now on; the snapshot need not
    final c = Checkpoint.of(name, s, expires: expires);
    checkpoints.put(c);
    return c;
  }

  /// What a checkpoint taken now would pin, §1's "report the space each
  /// checkpoint pins".
  int checkpointWouldPin() => vlog.allocatedBytes - vlog.liveBytes;

  /// Space each existing checkpoint is holding down.
  Map<String, int> get checkpointPinning => {
        for (final c in checkpoints.all) c.name: pinnedBySnapshots,
      };

  /// `open_at(checkpoint)` — a read-only view at that snapshot, §1.
  Snapshot openAt(String name) {
    final c = checkpoints.get(name);
    if (c == null) throw InvalidArgumentException('no checkpoint "$name"');
    final s = c.snapshot;
    _liveSnapshots.add(s);
    return s;
  }

  /// Restores the database to a checkpoint, §1.
  ///
  /// **Roots roll back; counters never do.** `next_seq`, `next_segment_id` and
  /// the rest keep their current values — and on an encrypted file so does
  /// `next_nonce`, because rolling it back would reissue nonce values the
  /// abandoned commits already used against pages still present in the file:
  /// same key, same nonce, two plaintexts. Ids that are "never reused" must
  /// survive a restore for the same reason they survive a crash.
  ///
  /// `checkpoint_root` is *not* restored, so a restore does not delete the
  /// other checkpoints — including the one just used.
  void restore(String name) {
    final c = checkpoints.get(name);
    if (c == null) throw InvalidArgumentException('no checkpoint "$name"');

    final seqBefore = _nextSeq;
    final segBefore = _nextSegmentId;
    final commitBefore = commitId;

    // §5.2: a job whose inputs the manifest no longer names must be abandoned,
    // and abandoning costs only the work done.
    abandonCompaction();
    manifest.tree.root = c.manifestRoot;
    _levelCache.clear();
    visibleSeq = c.seq;
    commitId = commitBefore + 1; // a restore is itself a commit

    // The counters MUST NOT move backwards.
    assert(_nextSeq == seqBefore, 'restore rolled next_seq back');
    assert(_nextSegmentId == segBefore, 'restore rolled next_segment_id back');

    _emit(StoreEvent(StoreEventKind.commit,
        commitId: commitId,
        visibleSeq: visibleSeq,
        detail: 'restored checkpoint "$name"'));
  }

  /// §1: honour `expires` and drop the checkpoint automatically past it.
  List<String> dropExpiredCheckpoints(int nowMs) =>
      checkpoints.dropExpired(nowMs);

  int get liveSnapshotCount => _liveSnapshots.length;

  /// §6 / `13-operations.md` §6: how old the oldest live snapshot is.
  int oldestSnapshotAgeMs(int nowMs) {
    var oldest = 0;
    for (final s in _liveSnapshots) {
      if (s.takenAtMs != 0 && (oldest == 0 || s.takenAtMs < oldest)) {
        oldest = s.takenAtMs;
      }
    }
    return oldest == 0 ? 0 : nowMs - oldest;
  }

  /// Takes a read snapshot at `visible_seq`, §1.
  ///
  /// The snapshot carries **all nine** roots. It needs no locks, no copying and
  /// no coordination with writers, because segments are immutable and every
  /// version carries its own seq.
  Snapshot snapshot({int nowMs = 0}) {
    final s = Snapshot(
      seq: visibleSeq,
      commitId: commitId,
      catalogRoot: 0,
      freelistRoot: 0,
      attributesRoot: 0,
      manifestRoot: manifest.root,
      vlogStatsRoot: 0,
      checkpointRoot: 0,
      changefeedRoot: 0,
      takenAtMs: nowMs,
    );
    _liveSnapshots.add(s);
    return s;
  }

  /// Releases a snapshot. §8: "never break a live snapshot to reclaim space" —
  /// the corollary is that an unreleased one holds space indefinitely, and
  /// abandoned cursors are the realistic failure mode.
  void release(Snapshot s) {
    _liveSnapshots.remove(s);
    // `spec/13-operations.md` §6: `pinned_by_snapshots` is "bytes retained
    // because a live snapshot needs them". With no live snapshot there is
    // nothing retaining them, whether or not a compaction has got around to
    // collapsing the versions yet — so the answer is exactly 0, not the last
    // figure a levelled compaction happened to record. Leaving the stale
    // number is the same failure §6 already names: a metric that cannot be
    // computed must be reported unavailable, never given a plausible value.
    if (_liveSnapshots.isEmpty) pinnedBySnapshots = 0;
    _pruneWrittenAt();
  }

  void _pruneWrittenAt() {
    final floor = minRetainedSeq;
    _writtenAt.removeWhere((_, seq) => seq < floor);
  }

  /// Space a snapshot is holding that would otherwise be reclaimable, §8.
  ///
  /// **Measured where it happens, not inferred.** The first version of this
  /// metric reported `allocated − live` value-log bytes, which is exactly
  /// wrong: a live snapshot's effect is to stop superseded versions from
  /// *becoming* dead in the first place, so the very bytes it pins never enter
  /// that difference and the metric read 0 on a database holding a large
  /// pinned set. It is now accumulated during compaction — the bytes of every
  /// entry retained *solely* because §5's condition 2 was not met.
  ///
  /// §8 requires a warning past a configurable amount, default 64 MiB, because
  /// "a reader held open across a heavy update burst can hold far more space
  /// than its own data, and the amount is not obvious from the outside".
  int pinnedBySnapshots = 0;

  int snapshotPinWarningBytes = 64 << 20;

  bool get snapshotPinExceeded =>
      _liveSnapshots.isNotEmpty && pinnedBySnapshots > snapshotPinWarningBytes;

  /// How many cold-tier collections have run. A collection is a third write of
  /// a value, which §6.3's "at most twice" does not account for.
  int coldCollections = 0;

  /// Keys this writer has seen before, for the heat classifier of §6.6.
  final Set<int> _seen = {};

  int keyPageReads = 0;
  int get valuePageReads => vlog.valuePageReads;
  int get valueReads => vlog.valueReads;

  /// Rows returned by the most recent [scanDocuments], so
  /// `value_reads_per_scanned_row` has a denominator.
  int lastScanRows = 0;

  /// `segments_probed_per_lookup` (`spec/13-operations.md` §6), one sample per
  /// [get]. This is the metric prediction P10 bounds.
  final List<int> segmentsProbed = [];

  /// Probes the filter admitted that the segment did not in fact hold, over
  /// probes the filter admitted: `filter_false_positive_rate`.
  int filterAdmitted = 0;
  int filterFalsePositives = 0;

  void resetCounters() {
    keyPageReads = 0;
    segmentsProbed.clear();
    filterAdmitted = 0;
    filterFalsePositives = 0;
    vlog.resetCounters();
    for (final s in extents.values) {
      s.resetCounters();
    }
    store.resetCounters();
  }

  int _collectKeyReads() {
    var n = keyPageReads;
    for (final s in extents.values) {
      n += s.pageReads;
    }
    return n;
  }


  // -------------------------------------------------------------------------
  // Write path
  // -------------------------------------------------------------------------

  /// Writes one document.
  ///
  /// [expiryMs] is §9's per-entry time to live, in Unix milliseconds UTC. A
  /// tree may also carry `params.ttl_ms`, which the layer above applies.
  void put(int treeId, CValue key, Uint8List encodedValue, {int? expiryMs}) =>
      _write(treeId, key, encodedValue, Op.put, expiryMs: expiryMs);

  /// Deletes the half-open interval `[start, end)` in one write,
  /// `spec/04-segments.md` §2.5.
  ///
  /// This is what makes `clear()`, `drop()` and the rollback of a bulk insert
  /// **O(1) writes rather than O(n) tombstones** — the single largest
  /// asymptotic difference between this format and a per-key tombstone engine
  /// on those three operations.
  void removeRange(int treeId, CValue start, CValue end) {
    final startCke = encodeKey(start);
    final endCke = encodeKey(end);
    if (compareKeys(startCke, endCke) >= 0) {
      throw const InvalidArgumentException(
          'a range delete needs start < end; the interval is half-open');
    }
    final seq = _nextSeq++;
    final ik = internalKey(treeId, startCke, seq, Op.rangeDelete);
    // §2.5: "The value payload holds `uvar end_key_len || end_key`."
    final w = ByteWriter(endCke.length + 4)
      ..uvar(endCke.length)
      ..bytes(endCke);
    _memtable[ik] = _Pending(ik, ValueKind.inline, w.takeBytes());
    _feed(treeId, seq, 'range_delete', startCke, start);
    if (_memtable.length >= memtableEntries) flush();
  }

  /// §7: "Entries are appended in the same batch as the mutation, so the feed
  /// is exactly consistent with the data." There is no window in which a
  /// change exists and its feed entry does not, and none in which the reverse
  /// is true — which is the only property a replication layer can build on.
  void _feed(int treeId, int seq, String op, Uint8List cke, CValue key) {
    if (!changeFeedTrees.contains(treeId)) return;
    changeFeed.append(Change(
      treeId: treeId,
      seq: seq,
      op: op,
      key: cke,
      id: key,
    ));
  }

  /// Writes a tombstone.
  void remove(int treeId, CValue key) =>
      _write(treeId, key, Uint8List(0), Op.delete);

  /// Writes an entry whose value is `EMPTY` (`value_kind` 3, zero bytes).
  ///
  /// Every secondary-index entry is one of these: `spec/06-indexes.md` §1 puts
  /// the indexed values *and* the document id in the key, so the value carries
  /// nothing and an index entry costs no value bytes at all.
  void putEmpty(int treeId, CValue key) {
    final cke = encodeKey(key);
    final seq = _nextSeq++;
    final ik = internalKey(treeId, cke, seq, Op.put);
    _memtable[ik] = _Pending(ik, ValueKind.empty, Uint8List(0));
    _writtenAt[Transaction.keyOf(treeId, cke)] = seq;
    _feed(treeId, seq, 'put', cke, key);
    if (_memtable.length >= memtableEntries) flush();
  }

  // -------------------------------------------------------------------------
  // Transactions — §3
  // -------------------------------------------------------------------------

  /// Begins a transaction at a fresh snapshot, §3.
  ///
  /// Writes are buffered and sequenced at [Transaction.commit]; nothing
  /// durable exists before then, which is what makes rollback free and what
  /// makes an abort leave no trace.
  Transaction begin({Isolation isolation = Isolation.snapshot, int nowMs = 0}) {
    final s = snapshot(nowMs: nowMs);
    return Transaction(
      snapshot: s,
      isolation: isolation,
      writtenSeqOf: (key) => _writtenAt[key] ?? 0,
      onCommit: (txn) {
        for (final w in txn.writes) {
          final seq = _nextSeq++;
          final ik = internalKey(
              w.treeId, w.cke, seq, w.isDelete ? Op.delete : Op.put);
          _memtable[ik] = _Pending(
              ik,
              w.isDelete ? ValueKind.empty : ValueKind.inline,
              w.isDelete ? Uint8List(0) : w.value);
          _writtenAt[Transaction.keyOf(w.treeId, w.cke)] = seq;
        }
        release(s);
        commit();
      },
    );
  }

  void _write(int treeId, CValue key, Uint8List encodedValue, int op,
      {int? expiryMs}) {
    final cke = encodeKey(key);
    final seq = _nextSeq++;
    final ik = internalKey(treeId, cke, seq, op);

    int kind;
    Uint8List stored;
    if (op == Op.delete) {
      kind = ValueKind.empty;
      stored = Uint8List(0);
    } else if (encodedValue.length >= vlogMin) {
      // §6.6: FIRST for a key this writer has not seen, WARM once it has.
      final h = Object.hashAll(cke);
      final heat = _seen.add(h) ? HeatClass.first : HeatClass.warm;
      final ptr = vlog.append(
          treeId: treeId, ckeKey: cke, value: encodedValue, heat: heat);
      kind = ValueKind.vlog;
      stored = ptr.encode();
    } else {
      kind = ValueKind.inline;
      stored = encodedValue;
    }
    _memtable[ik] = _Pending(ik, kind, stored, expiryMs: expiryMs);
    _writtenAt[Transaction.keyOf(treeId, cke)] = seq;
    _feed(treeId, seq, op == Op.delete ? 'delete' : 'put', cke, key);
    if (_memtable.length >= memtableEntries) flush();
  }

  // -------------------------------------------------------------------------
  // Commit — `spec/10-transactions.md` §2, §5, §9, §10
  // -------------------------------------------------------------------------

  /// The committer of §2 steps A–G, in its single-writer form.
  ///
  /// **The step order is the correctness, not the performance.** §2.3 states
  /// two ordering invariants whose violation "produces a database that opens
  /// cleanly and is wrong", and both are about this sequence:
  ///
  ///  1. A superblock MUST NOT name a segment whose value-log records are not
  ///     already durable — so the value-log barrier (C) precedes the segment
  ///     write (D) and the superblock (F). Reversed, the key index points into
  ///     bytes that were never written, "a dangling pointer that no checksum
  ///     catches, because the key side is intact".
  ///  2. The `bytes` watermark of a value-log segment advances only over a
  ///     **contiguous prefix of completed reservations** — a writer that
  ///     reserved and died leaves a hole, and advancing past it publishes
  ///     garbage as a live record.
  ///
  /// `visible_seq` advancing past a batch's seq range is the commit: §2.3,
  /// "there is no commit record and no two-phase protocol; the watermark is
  /// the commit".
  int commit({Durability durability = Durability.sync}) {
    if (_closed) throw const InvalidArgumentException('engine is closed');
    // B/C: barrier over the open value-log segments' tails BEFORE anything
    // names them (§2.3 invariant 1).
    //
    // Step B **flushes**; it does not seal. Sealing is `04-segments.md` §6.2's
    // terminal state, and doing it here retires the open run on every commit —
    // one value-log run per commit, which is exactly the surplus §6.9 bounds.
    // This implementation used to seal here and read 45 % locality debt on a
    // freshly written database. Sealing belongs at close, and at open for a
    // segment a previous session left open (`14-security.md` §4.3).
    vlog.flushTails();
    _barrier(durability);

    // D: memtable -> L0, and the manifest edit that names it.
    final sequenced = _nextSeq - 1;
    flush();

    // E: barrier over the segment and manifest writes.
    _barrier(durability);

    // F/G: publish. Everything at or below `sequenced` is now durable.
    commitId++;
    visibleSeq = sequenced;
    _refreshRetention();
    _pruneWrittenAt();
    _emit(StoreEvent(StoreEventKind.commit,
        commitId: commitId, visibleSeq: visibleSeq));
    return commitId;
  }

  /// §7: an implementation records what it actually performed.
  ///
  /// There is no file under this implementation, so no barrier reaches stable
  /// storage and the honest record is `none` whatever was requested. Claiming
  /// the requested mode here is precisely the silent failure §7 exists to
  /// prevent.
  void _barrier(Durability requested) {
    durabilityAchieved = Durability.none;
  }

  void _emit(StoreEvent e) => events.add(e);

  /// §10. Close is not a special case: "the file is valid at every commit, and
  /// reopening after a kill takes the same path as after a clean close".
  void close({bool flushMemtable = true}) {
    if (_closed) return;
    _emit(const StoreEvent(StoreEventKind.closing));
    if (flushMemtable && _memtable.isNotEmpty) commit();
    vlog.sealOpen();
    _closed = true;
    _emit(const StoreEvent(StoreEventKind.closed));
  }

  bool get isClosed => _closed;

  // -------------------------------------------------------------------------
  // Backpressure — §6
  // -------------------------------------------------------------------------

  /// The bounds §6 requires an implementation to keep, with their soft and
  /// hard thresholds.
  List<Bound> get bounds => [
        Bound('l0_segment_count', refsAt(0).length, levels.l0Trigger,
            levels.l0Trigger * 4),
        for (var l = 1; l < lastLevel; l++)
          Bound('segments_at_L$l', refsAt(l).length, levels.tierWidth,
              levels.tierWidth * 2),
        Bound('memtable_entries', _memtable.length, memtableEntries,
            memtableEntries * 2),
        Bound('vlog_space_amplification', vlog.spaceAmplification,
            vlogSpaceTargetPct / 100, 2 * vlogSpaceTargetPct / 100),
        Bound('locality_debt', vlog.localityDebt * 100, localityDebtPct,
            2 * localityDebtPct),
      ];

  /// §6's normative curve. An implementation MUST expose the delay and the
  /// bound that caused it (`13-operations.md` §6).
  Backpressure get backpressure => Backpressure.compute(bounds);

  /// Turns the memtable into an L0 segment, §2.3, and publishes it.
  void flush() {
    if (_memtable.isEmpty) return;
    // Already in `compareKeys` order: the memtable is a SplayTreeMap.
    final keys = _memtable.keys.toList();
    final b = _builder(level: 0);
    for (final k in keys) {
      final p = _memtable[k]!;
      b.add(SegEntry(p.internalKey, p.valueKind, p.value,
          expiryMs: p.expiryMs));
    }
    _publish(b, level: 0, group: 0);
    _memtable.clear();
    // §2 steps D and F: once a memtable's records are in a segment the
    // manifest names, they are published, and `visible_seq` is "the highest
    // fully durable seq". With one writer and no separate committer thread
    // those two steps are the same event, so the watermark advances here
    // rather than only in [commit].
    //
    // This is load-bearing beyond visibility: `min_retained_seq` floors at
    // `visible_seq` (§8), and a watermark that never advanced would make every
    // superseded versionpermanently retained — compaction could never collapse a key,
    // and the key index would grow without bound. That is exactly what
    // happened when this line was missing: the aged scan's key-page count went
    // from 34 to 369 while its value side was untouched.
    visibleSeq = _nextSeq - 1;
    _emit(const StoreEvent(StoreEventKind.flushed));
    // §5.2: bounded work on the caller's thread. Whatever is left resumes on
    // the next flush, or on an explicit [drainCompaction].
    maybeCompact(budgetBytes: compactionStepBytes);
  }

  /// `compaction_step_bytes`, `spec/12-profiles.md` §1.
  ///
  /// Settable so a test can shrink it; the profile default is what a real
  /// caller gets.
  int compactionStepBytes = 256 << 10;

  /// Entries per output segment at [level].
  ///
  /// §3.1 wants a tiered level to hold up to `tier_width` **size-similar**
  /// segments arranged in `overlap_bound` disjoint runs. That fixes the size:
  /// a run at level 1 is `l0_trigger` memtables, a run at level *l* is
  /// `overlap_bound` runs of the level below, and a run occupies
  /// `tier_width / overlap_bound` segments. Sizing outputs any other way makes
  /// one of the two bounds unreachable and the level policy thrash.
  int segmentEntriesAt(int level) {
    if (level == 0) return segmentEntries;
    var runEntries = levels.l0Trigger * segmentEntries;
    for (var i = 1; i < level; i++) {
      runEntries *= levels.overlapBound;
    }
    final perRun = (levels.tierWidth ~/ levels.overlapBound).clamp(1, 1 << 20);
    return (runEntries / perRun).ceil();
  }

  SegmentBuilder _builder({required int level, int group = 0}) =>
      SegmentBuilder(
        pageSize: pageSize,
        tagReserve: store.tagReserve,
        segmentId: _nextSegmentId++,
        level: level,
        group: group,
        // §2.4: 16 bits above the last level, 10 at it. The upper levels hold
        // little data, so a high rate there is nearly free and it is what
        // bounds the read tail.
        filterBitsPerKey: !filters ? 0 : (level == lastLevel ? 10 : 16),
      );

  Segment _publish(SegmentBuilder b, {required int level, required int group}) {
    final seg = Segment(b.build(), pageSize);
    extents[seg.header.segmentId] = seg;
    manifest.add(SegmentRef.of(seg, level: level, group: group));
    _levelCache.remove(level);
    return seg;
  }

  void _retire(SegmentRef ref) {
    manifest.remove(ref);
    extents.remove(ref.segmentId);
    _levelCache.remove(ref.level);
  }

  // -------------------------------------------------------------------------
  // Levels
  // -------------------------------------------------------------------------

  /// The manifest entries at [level], from an in-memory mirror.
  ///
  /// §4.1 costs manifest key-range pruning at **no I/O**, which is a statement
  /// that the manifest is resident. Decoding a CVE descriptor per candidate per
  /// lookup is not what the chapter describes and it dominates everything else
  /// when measured. The mirror is rebuilt from tree 6 whenever the manifest
  /// changes, so tree 6 stays the authority.
  /// Every segment the manifest currently names, quarantined ones excluded.
  ///
  /// The manifest is the authority on what is live; [extents] merely holds the
  /// bytes. Every scan and every lookup goes through here.
  Iterable<Segment> get liveSegments sync* {
    for (var l = 0; l <= lastLevel; l++) {
      for (final r in refsAt(l)) {
        if (quarantined.containsKey(r.segmentId)) continue;
        final seg = extents[r.segmentId];
        if (seg != null) yield seg;
      }
    }
  }

  List<SegmentRef> refsAt(int level) {
    final cached = _levelCache[level];
    if (cached != null) return cached;
    return _levelCache[level] = manifest.level(level).toList();
  }

  final Map<int, List<SegmentRef>> _levelCache = {};

  /// Drops the in-memory manifest mirror. Repair rewrites tree 6 underneath
  /// the engine, so the mirror has to be told.
  void clearLevelCache() => _levelCache.clear();

  /// Group ids in use at [level].
  Set<int> groupsAt(int level) => {for (final r in refsAt(level)) r.group};

  /// Runs the level policy of §3.1 until every bound holds.
  ///
  /// **Bounded when [budgetBytes] is given** — that is `spec/04-segments.md`
  /// §5.2, and it is what keeps a `put` inside `spec/12-profiles.md` §4's
  /// foreground stall budget. Work left over is picked up by the next call;
  /// nothing is published until a job finishes, so stopping is free.
  void maybeCompact({int? budgetBytes}) {
    var spent = 0;

    // Finish what is already in flight before starting anything new.
    final pending = _job;
    if (pending != null) {
      final before = pending.bytesMerged;
      final done = stepCompaction(pending,
          budgetBytes: budgetBytes == null ? null : budgetBytes - spent);
      spent += pending.bytesMerged - before;
      if (!done) return;
      finishCompaction(pending);
      _job = null;
      if (budgetBytes != null && spent >= budgetBytes) return;
    }

    var guard = 0;
    while (guard++ < 1000) {
      final next = _pickCompaction();
      if (next == null) return;
      final job = beginCompaction(next.$1, next.$2);
      if (job == null) return;
      final done =
          stepCompaction(job, budgetBytes: budgetBytes == null ? null : budgetBytes - spent);
      spent += job.bytesMerged;
      if (!done) {
        _job = job; // resume on the next call
        return;
      }
      finishCompaction(job);
      if (budgetBytes != null && spent >= budgetBytes) return;
    }
    throw StateError('compaction did not converge');
  }

  /// The next compaction the level policy wants, or null when every bound
  /// holds. `(inputs, target)`.
  (List<SegmentRef>, int)? _pickCompaction() {
    if (refsAt(0).length >= levels.l0Trigger) {
      final inputs = refsAt(0);
      return (inputs, lastLevel <= 1 ? lastLevel : 1);
    }
    for (var l = 1; l < lastLevel; l++) {
      final refs = refsAt(l);
      if (refs.length > levels.tierWidth ||
          groupsAt(l).length > levels.overlapBound) {
        return (refs, l + 1 >= lastLevel ? lastLevel : l + 1);
      }
    }
    return null;
  }

  /// Runs the level policy to quiescence.
  ///
  /// An **explicitly requested bulk operation**, which `spec/12-profiles.md`
  /// §4 exempts from the stall budget — the ordinary write path uses the
  /// bounded form instead.
  void drainCompaction() => maybeCompact();

  /// Drops a part-done compaction, §5.2.
  ///
  /// "The partially built output is just a prefix — abandoning it costs the
  /// work done and nothing else, and no reader can see it." Called whenever
  /// the manifest moves under a job: a checkpoint restore, or a repair.
  void abandonCompaction() => _job = null;

  /// Merges everything down into the last level.
  ///
  /// The public "make it tidy" operation, and what the P8 harness calls: it
  /// forces the last-level compaction that promotion and cold-tier collection
  /// hang off (§6.3, §6.8).
  void compact() {
    flush();
    drainCompaction();
    for (var l = 0; l < lastLevel; l++) {
      if (refsAt(l).isNotEmpty) _compactInto(refsAt(l), lastLevel);
    }
    collectWhileOverDebt();
  }

  /// Collects the cold tier until `locality_debt` is back inside its bound.
  ///
  /// **§6.9's bound is on the state, not on the moment a compaction starts.**
  /// A merge that promotes a fresh generation without collecting — because the
  /// debt was inside the bound when it began — leaves a new surplus run behind
  /// and can end *above* it, and nothing looks again until the next compaction
  /// happens to. At 20 000 documents that window never showed; at 2×10⁵ the
  /// aged scan ended at 25.6 % debt against a 20 % bound, which is the failure
  /// `REPORT.md` asked for when it said "P8 is a claim about databases that get
  /// old and large, and only one of those two has been tested".
  void collectWhileOverDebt({int maxPasses = 4}) {
    var passes = 0;
    while (vlog.localityDebt * 100 > localityDebtPct && passes++ < maxPasses) {
      final refs = refsAt(lastLevel);
      if (refs.isEmpty) return;
      _compactInto(refs, lastLevel, forceRecluster: true);
    }
  }

  /// Runs a whole compaction to completion. The bulk path.
  ///
  /// Used by [compact], which `spec/12-profiles.md` §4 exempts from the stall
  /// budget because the application asked for it explicitly. The incremental
  /// path is [beginCompaction] + [stepCompaction] + [finishCompaction].
  void _compactInto(List<SegmentRef> inputs, int target,
      {bool forceRecluster = false}) {
    final job = beginCompaction(inputs, target, forceRecluster: forceRecluster);
    if (job == null) return;
    while (!stepCompaction(job)) {}
    finishCompaction(job);
  }

  /// Sets a compaction up without doing any of its work, §5.2.
  CompactionJob? beginCompaction(List<SegmentRef> inputs, int target,
      {bool forceRecluster = false}) {
    if (inputs.isEmpty) return null;
    final levelled = target == lastLevel;
    final all = <SegmentRef>[...inputs];
    final seen = {for (final r in inputs) r.segmentId};
    if (levelled) {
      // The last level is disjoint, so the compaction must include every
      // last-level segment whose range the inputs touch — that is also §5's
      // condition 3, the one that makes dropping a superseded version legal.
      //
      // **The test is on USER keys, and testing it on internal keys is a
      // silent correctness bug.** An internal key is
      // `tree_id || CKE(key) || ~seq || op` (§1), so two segments holding
      // *different versions of the same key* occupy disjoint internal-key
      // ranges — one holds `~11 … ~5`, the other `~4 … ~1`. An overlap test on
      // internal keys reports them as non-overlapping, the merge leaves both
      // in place, and the last level stops being disjoint while every
      // structural check still passes (`04-segments.md` §3.1.1).
      final lo = _userLow(_minOf(inputs));
      final hi = _maxOf(inputs);
      for (final r in refsAt(lastLevel)) {
        if (seen.contains(r.segmentId)) continue;
        if (compareKeys(_userLow(r.minKey), hi) <= 0 &&
            compareKeys(r.maxKey, lo) >= 0) {
          all.add(r);
        }
      }
    }

    // §6.8 step 1: collection is triggered by whichever bound is breached
    // first — the space target, or the locality debt. The two have the same
    // cause (surplus runs) without being the same quantity.
    final recluster = levelled &&
        (forceRecluster ||
            vlog.allocatedBytes > vlog.liveBytes * vlogSpaceTargetPct / 100 ||
            vlog.localityDebt * 100 > localityDebtPct);

    // **The group is decided before the outputs are built, not after.**
    // `group` is written into each segment's header (§2.1) *and* into its
    // manifest key (§3.2), and `13-operations.md` §3 rebuilds the manifest by
    // reading it back out of the headers — so a header that disagrees makes the
    // rebuild silently re-file two disjoint runs into one group, which then
    // overlaps and breaks §4's early exit. The verifier of `verify.dart` is
    // what caught that, which is the rot `13-operations.md` §3 says the check
    // exists to prevent.
    final group = levelled ? 0 : _freeGroup(target);

    // §9: an expired entry may be dropped only when its deadline is older than
    // the oldest live snapshot's wall-clock floor.
    final floor = _liveSnapshots.isEmpty
        ? nowMs
        : _liveSnapshots
            .map((s) => s.takenAtMs == 0 ? nowMs : s.takenAtMs)
            .reduce((a, b) => a < b ? a : b);

    return CompactionJob(
      inputs: all,
      target: target,
      levelled: levelled,
      group: group,
      sources: [
        for (final r in all) extents[r.segmentId]!.cursor()..seekFirst(),
      ],
      out: _builder(level: target, group: group),
      // §5's conditions 2 and 3: a version may be dropped only at the last
      // level, and only once the version superseding it is visible to every
      // live snapshot.
      retained: minRetainedSeq,
      published: visibleSeq,
      nowMs: floor,
      recluster: recluster,
    );
  }

  /// Merges at most [budgetBytes] and returns true when the job is finished.
  ///
  /// §5.2: "A step boundary is any point between two output leaf pages." This
  /// yields at a **user-key** boundary, which is stricter — two versions of one
  /// key must not be split across output segments (§3.1) — and is therefore
  /// always a legal place to stop.
  bool stepCompaction(CompactionJob job, {int? budgetBytes}) {
    if (job.exhausted) return true;
    job.steps++;
    final startBytes = job.bytesMerged;

    while (true) {
      // Pick the smallest internal key across the sources. Newest-first is
      // built into the key: seq is inverted (§1), so the first entry seen for
      // a user key is the newest version of it.
      SegmentCursor? pick;
      for (final c in job.sources) {
        if (!c.isValid) continue;
        if (pick == null || compareKeys(c.key(), pick.key()) < 0) pick = c;
      }
      if (pick == null) {
        job.exhausted = true;
        return true;
      }

      final rec = pick.record();
      final parsed = parseInternalKey(rec.internalKey);
      final userKey = Uint8List.sublistView(
          rec.internalKey, 0, rec.internalKey.length - 9);
      final isNewest = job.lastUserKey == null ||
          compareKeys(job.lastUserKey!, userKey) != 0;

      if (isNewest) {
        // The only legal step boundary, checked before anything is consumed.
        if (budgetBytes != null && job.bytesMerged - startBytes >= budgetBytes) {
          return false;
        }
        job.lastUserKey = Uint8List.fromList(userKey);
        job.newestSeq = parsed.seq;
        // A segment boundary is only legal between user keys: two versions of
        // one key in two segments of the same disjoint run would break the
        // "at most one segment per group covers a key" invariant of §3.1.
        if (job.out.entryCount >= segmentEntriesAt(job.target)) _rotate(job);
        if (job.levelled &&
            (rec.op == Op.delete ||
                _isExpired(rec, job.nowMs) && rec.op != Op.rangeDelete) &&
            rec.seq <= job.retained) {
          // §5: a tombstone may be dropped when the compaction reaches the
          // last level **and** its own seq is at or below the oldest live
          // snapshot's. The second half is not optional: a snapshot older than
          // the tombstone still sees the versions it hides, so dropping the
          // tombstone alone would resurrect them for every later reader.
        } else {
          job.out.add(_promote(rec, parsed.treeId, job.dead, job.recluster,
              levelled: job.levelled));
        }
      } else if (job.levelled && job.newestSeq <= job.retained) {
        // §5 condition 3 holds only at the last level, so a superseded version
        // may be dropped only here — and only once the version that supersedes
        // it is itself visible to every live snapshot (condition 2). A tiered
        // compaction keeps every version, which is what makes tiering cheap on
        // the write side.
        if (rec.valueKind == ValueKind.vlog) {
          // §6.7 lets liveness be decremented only when a compaction has
          // *observed* the value superseded, which is here.
          job.dead.add(VlogPointer.decode(rec.value));
        }
      } else {
        if (job.levelled && job.newestSeq <= job.published) {
          // Kept only because a snapshot older than the superseding version is
          // live: without it, §5 would have dropped this entry here.
          job.pinned += rec.value.length + rec.internalKey.length;
        }
        job.out.add(SegEntry(rec.internalKey, rec.valueKind, rec.value,
            expiryMs: rec.expiryMs));
      }
      job.bytesMerged += rec.internalKey.length + rec.value.length;
      pick.next();
    }
  }

  void _rotate(CompactionJob job) {
    if (job.out.entryCount == 0) return;
    job.outputs.add(Segment(job.out.build(), pageSize));
    job.out = _builder(level: job.target, group: job.group);
  }

  /// Publishes a finished job: retire the inputs, add the outputs, §5 and §5.2.
  void finishCompaction(CompactionJob job) {
    _rotate(job);
    for (final r in job.inputs) {
      _retire(r);
    }
    for (final s in job.outputs) {
      extents[s.header.segmentId] = s;
      manifest.add(SegmentRef.of(s, level: job.target, group: job.group));
    }
    _levelCache.remove(job.target);

    if (job.levelled) pinnedBySnapshots = job.pinned;
    if (job.recluster) coldCollections++;
    _emit(StoreEvent(StoreEventKind.compacted,
        detail: 'level ${job.target}, ${job.outputs.length} segments, '
            '${job.inputs.length} inputs, ${job.steps} steps'));
    for (final p in job.dead) {
      vlog.markDead(p);
    }
    vlog
      ..sealCold()
      ..reclaimEmpty();

    // §6.9's bound is a MUST on the *state*, and promotion is what moves it:
    // every levelled compaction lands a fresh cold generation, so a database
    // written without anyone ever calling `compact()` accumulates one surplus
    // run per compaction and ends over the bound with nothing looking. It read
    // 45 % on a plainly written 400-document database, which §11's invariant
    // 11 flags and which the writer had no way to see.
    //
    // Collection compacts, so the flag is what stops it recursing into itself.
    // After **every** compaction, not only a levelled one. Promotion into the
    // cold tier is what creates a generation, and by the time
    // `finishCompaction` runs the job that did it no longer reports itself as
    // levelled — so gating on `job.levelled` never fired, and a database
    // written without anyone calling `compact()` accumulated one surplus run
    // per compaction and ended at 45 % against a 20 % bound with nothing
    // looking. Collection compacts, so `_collecting` is what stops the
    // recursion.
    if (autoCollect && !_collecting) {
      _collecting = true;
      try {
        collectWhileOverDebt();
      } finally {
        _collecting = false;
      }
    }
  }

  /// §6.8's collection runs automatically once §6.9's bound is exceeded.
  /// Off only for the controls that measure what it is worth.
  bool autoCollect = true;
  bool _collecting = false;

  /// The lowest group id not in use at [level].
  ///
  /// One compaction's output is one **disjoint run**, so it becomes one group.
  /// That is range partitioning (§3.1): a lookup consults at most one segment
  /// per group and there are at most `overlap_bound` groups, which converts an
  /// unbounded read tail into a bounded one.
  int _freeGroup(int level) {
    final used = groupsAt(level);
    for (var g = 0; g < 256; g++) {
      if (!used.contains(g)) return g;
    }
    throw const LimitException('a tiered level cannot hold 256 groups');
  }

  /// The user-key prefix of a segment bound, for the disjointness test.
  ///
  /// Conservative in both directions, which is what a correctness test wants:
  /// `min_key` may have been *shortened* by §2.1's truncation and is then
  /// already at or below every user key in the segment, and an internal key is
  /// always at or above its own user prefix, so an untruncated `max_key` is a
  /// valid upper bound on user keys as it stands. Erring toward "overlaps"
  /// merges more than strictly necessary; erring the other way loses a key.
  static String _hexBound(Uint8List b) {
    final sb = StringBuffer();
    for (var i = 0; i < b.length && i < 8; i++) {
      sb.write(b[i].toRadixString(16).padLeft(2, '0'));
    }
    if (b.length > 8) sb.write('…');
    return sb.toString();
  }

  static Uint8List _userLow(Uint8List bound) =>
      bound.length >= 13 ? Uint8List.sublistView(bound, 0, bound.length - 9) : bound;

  Uint8List _minOf(List<SegmentRef> refs) {
    var m = refs.first.minKey;
    for (final r in refs) {
      if (compareKeys(r.minKey, m) < 0) m = r.minKey;
    }
    return m;
  }

  Uint8List _maxOf(List<SegmentRef> refs) {
    var m = refs.first.maxKey;
    for (final r in refs) {
      if (compareKeys(r.maxKey, m) > 0) m = r.maxKey;
    }
    return m;
  }

  /// §9: an entry whose `expiry_ms` is at or before the clock is invisible,
  /// "treated exactly as a `DELETE`". Evaluated at read time, so it is exact
  /// regardless of when compaction runs.
  static bool _isExpired(SegRecord rec, int nowMs) =>
      rec.expiryMs != null && rec.expiryMs! <= nowMs;

  /// §6.3 — **during a compaction that outputs the last level**, every
  /// surviving hot-tier value is promoted into a cold segment. The entries
  /// arrive in internal-key order, so the cold log is key-clustered for free.
  ///
  /// The `levelled` gate is the whole mechanism and it was missing. Promoting
  /// during a tiered merge produces a cold run ordered by that merge rather
  /// than by key, and — worse — one that collection can never reach:
  /// [collectWhileOverDebt] reclusters *last-level* segments, and a database
  /// whose compactions never reached the last level had no last-level segments
  /// at all. It accumulated one unreachable cold generation per compaction and
  /// sat at 45 % locality debt against a 20 % bound, with collection running
  /// and returning immediately every time.
  SegEntry _promote(SegRecord rec, int treeId, List<VlogPointer> dead,
      bool recluster,
      {required bool levelled}) {
    if (!levelled) {
      return SegEntry(rec.internalKey, rec.valueKind, rec.value,
          expiryMs: rec.expiryMs);
    }
    if (rec.valueKind != ValueKind.vlog || !policy.clusteredPromotion) {
      return SegEntry(rec.internalKey, rec.valueKind, rec.value,
          expiryMs: rec.expiryMs);
    }
    final ptr = VlogPointer.decode(rec.value);
    final seg = vlog.segments[ptr.segmentId];
    if (seg == null) {
      return SegEntry(rec.internalKey, rec.valueKind, rec.value,
          expiryMs: rec.expiryMs);
    }
    if (seg.tier == VlogTier.cold && !recluster) {
      // Already clustered within its own generation, and the log is inside its
      // space target, so leave it: §6.3's "values are written at most twice".
      return SegEntry(rec.internalKey, rec.valueKind, rec.value,
          expiryMs: rec.expiryMs);
    }
    final value = vlog.readValue(ptr);
    final cke = parseInternalKey(rec.internalKey).cke;
    final moved = vlog.append(
      treeId: treeId,
      ckeKey: Uint8List.fromList(cke),
      value: value,
      tier: VlogTier.cold,
    );
    dead.add(ptr);
    return SegEntry(rec.internalKey, ValueKind.vlog, moved.encode(),
        expiryMs: rec.expiryMs);
  }

  // -------------------------------------------------------------------------
  // Read path — `spec/04-segments.md` §4
  // -------------------------------------------------------------------------

  /// Every segment that may hold [userKeyPrefix], in the order §4 walks them.
  ///
  /// Manifest key-range pruning costs no I/O; the filter costs one page read
  /// of an already-hot page. What survives both is what gets descended into,
  /// and its count is `segments_probed_per_lookup`.
  /// Segments that may hold a `RANGE_DELETE` covering [userKeyPrefix], §4.
  ///
  /// **These MUST NOT be filter-pruned.** The filter holds the segment's
  /// *point* keys (§2.4); a range delete covers keys that are not in it, so
  /// filtering such a segment out loses the delete and resurrects a deleted
  /// key. `flags.HAS_RANGE_DELETES` exists exactly so this test costs no I/O.
  List<RangeDelete> rangeDeletesFor(Uint8List prefix) {
    final out = <RangeDelete>[];
    for (var l = 0; l <= lastLevel; l++) {
      for (final ref in refsAt(l)) {
        if (!ref.hasRangeDeletes) continue;
        for (final rd in extents[ref.segmentId]!.rangeDeletes) {
          if (rd.covers(prefix)) out.add(rd);
        }
      }
    }
    for (final e in _memtable.entries) {
      final k = e.key;
      if (k[k.length - 1] != Op.rangeDelete) continue;
      final p = parseInternalKey(k);
      final r = ByteReader(e.value.value);
      final end = r.bytesCopy(r.uvar());
      final rd = RangeDelete(
        treeId: p.treeId,
        start: userKeyPrefix(p.treeId, Uint8List.fromList(p.cke)),
        end: userKeyPrefix(p.treeId, end),
        seq: p.seq,
      );
      if (rd.covers(prefix)) out.add(rd);
    }
    return out;
  }

  /// Whether any live segment or buffered write carries a `RANGE_DELETE`.
  ///
  /// §4: "range deletes are rare, so the number of segments in `rd_sources` is
  /// normally zero." This makes that the *measured* common case rather than an
  /// assumption — with no range deletes anywhere, the read and scan paths skip
  /// the whole mechanism on one boolean instead of walking the manifest.
  bool get hasAnyRangeDeletes {
    for (var l = 0; l <= lastLevel; l++) {
      for (final r in refsAt(l)) {
        if (r.hasRangeDeletes) return true;
      }
    }
    for (final k in _memtable.keys) {
      if (k[k.length - 1] == Op.rangeDelete) return true;
    }
    return false;
  }

  /// The greatest range-delete seq covering [prefix] at or below [ceiling],
  /// or 0 when none does. §4's `rd`.
  int _rangeDeleteSeq(Uint8List prefix, int? ceiling) {
    if (!hasAnyRangeDeletes) return 0;
    return _rangeDeleteSeqIn(rangeDeletesFor(prefix), prefix, ceiling);
  }

  static int _rangeDeleteSeqIn(
      List<RangeDelete> all, Uint8List prefix, int? ceiling) {
    var rd = 0;
    for (final r in all) {
      if (!r.covers(prefix)) continue;
      if (ceiling != null && r.seq > ceiling) continue;
      if (r.seq > rd) rd = r.seq;
    }
    return rd;
  }

  /// Every range delete in [treeId], gathered once.
  ///
  /// A scan hoists this: recomputing it per row would make a scan cost
  /// O(rows × segments) for a mechanism that is normally not in use at all.
  List<RangeDelete> _allRangeDeletes(int treeId) {
    if (!hasAnyRangeDeletes) return const [];
    final out = <RangeDelete>[];
    for (var l = 0; l <= lastLevel; l++) {
      for (final ref in refsAt(l)) {
        if (!ref.hasRangeDeletes) continue;
        for (final rd in extents[ref.segmentId]!.rangeDeletes) {
          if (rd.treeId == treeId) out.add(rd);
        }
      }
    }
    for (final e in _memtable.entries) {
      final k = e.key;
      if (k[k.length - 1] != Op.rangeDelete) continue;
      final p = parseInternalKey(k);
      if (p.treeId != treeId) continue;
      final r = ByteReader(e.value.value);
      final end = r.bytesCopy(r.uvar());
      out.add(RangeDelete(
        treeId: p.treeId,
        start: userKeyPrefix(p.treeId, Uint8List.fromList(p.cke)),
        end: userKeyPrefix(p.treeId, end),
        seq: p.seq,
      ));
    }
    return out;
  }

  List<Segment> candidatesFor(Uint8List userKeyPrefix) {
    final out = <Segment>[];

    void consider(List<SegmentRef> refs) {
      refs = [
        for (final r in refs)
          if (!quarantined.containsKey(r.segmentId)) r
      ];
      // **Level discipline, and the ordering §4 does not spell out.** §4 names
      // "L0 newest-flush-first, then strictly increasing level", which predates
      // §3.1's range-partition groups: a *tiered* level holds up to
      // `overlap_bound` runs and a key may sit in more than one of them, so the
      // proof needs an order inside a level too. `segment_id` supplies it at no
      // cost — `spec/00-conventions.md` §7 makes it globally unique and never
      // reused, allocated from the superblock's `next_segment_id`, so a higher
      // id was created later, and a later run at a level was compacted from
      // later data. Descending `segment_id` within a level is therefore
      // newest-first, and `max_seq` — which §4 explicitly disqualifies for
      // picking a winner — is not needed for the ordering either.
      refs.sort((a, b) => b.segmentId.compareTo(a.segmentId));
      for (final ref in refs) {
        if (!ref.covers(userKeyPrefix)) continue;
        final seg = extents[ref.segmentId]!;
        final f = seg.filter;
        // §4: a segment that may hold a covering range delete MUST NOT be
        // pruned by its filter, which contains point keys only.
        if (f != null && !ref.hasRangeDeletes && !f.mayContain(userKeyPrefix)) {
          continue;
        }
        if (f != null) filterAdmitted++;
        out.add(seg);
      }
    }

    for (var l = 0; l <= lastLevel; l++) {
      consider(refsAt(l));
    }
    return out;
  }

  /// Reads one key at the current snapshot.
  ///
  /// §4, with the two rules that were wrong in an earlier draft: every
  /// candidate is examined and the winner is the entry with the greatest seq,
  /// never the first hit in segment order.
  Uint8List? get(int treeId, CValue key, {Snapshot? at}) {
    final prefix = userKeyPrefix(treeId, encodeKey(key));
    final ceiling = at?.seq;

    // The memtable holds records that are sequenced but not yet in a segment.
    // `spec/10-transactions.md` §2 step 5 publishes into it, and a reader at
    // `visible_seq` sees them; a `get` that skipped it would lose every write
    // since the last flush.
    SegRecord? best = _memtableLookup(prefix, ceiling);
    if (best != null && earlyExit) {
      // Nothing in a segment can be newer than an unflushed record.
      segmentsProbed.add(0);
      return best.op == Op.delete ? null : _resolve(best);
    }

    // §4 step 4: a read landing inside an unavailable range fails naming the
    // range, "never with a wrong or empty answer". The test is on the manifest
    // entry, so it costs no I/O and works even though the extent is unreadable.
    for (final r in quarantined.values) {
      if (r.covers(prefix)) {
        throw UnavailableRangeException(
            'key falls inside the range of quarantined segment '
            '${r.segmentId} (level ${r.level}); '
            '${_hexBound(r.minKey)}..${_hexBound(r.maxKey)} is unavailable',
            segmentId: r.segmentId,
            treeIds: r.trees);
      }
    }

    final candidates = candidatesFor(prefix);
    var probed = 0;
    for (final s in candidates) {
      probed++;
      final rec = _seekIn(s, prefix, ceiling);
      if (rec == null) {
        if (s.filter != null) filterFalsePositives++;
        continue;
      }
      if (best == null || rec.seq > best.seq) best = rec;
      if (earlyExit) break;
    }
    segmentsProbed.add(probed);

    // §4: `rd` is the greatest RANGE_DELETE seq covering this key at or below
    // the snapshot. A delete newer than the winning entry hides it.
    final rd = _rangeDeleteSeq(prefix, ceiling);
    if (best == null || rd > best.seq) return null;
    if (best.op == Op.delete || best.op == Op.rangeDelete) return null;
    // §9: an expired entry is invisible, "treated exactly as a DELETE".
    if (_isExpired(best, nowMs)) return null;
    return _resolve(best);
  }

  SegRecord? _memtableLookup(Uint8List prefix, int? ceiling) {
    // Every internal key for this user key is `prefix || u64 ~seq || u8 op`, so
    // they form one contiguous run in the ordered memtable. Seek to the start
    // of that run and stop at its end, rather than walking every pending write.
    final lo = Uint8List(prefix.length + 9)..setRange(0, prefix.length, prefix);
    SegRecord? best;
    Uint8List? k = _memtable.containsKey(lo) ? lo : _memtable.firstKeyAfter(lo);
    while (k != null && k.length == prefix.length + 9) {
      var match = true;
      for (var i = 0; i < prefix.length; i++) {
        if (k[i] != prefix[i]) {
          match = false;
          break;
        }
      }
      if (!match) break;
      if (ceiling == null || parseInternalKey(k).seq <= ceiling) {
        final p = _memtable[k]!;
        final rec = SegRecord(k, p.valueKind, p.value, null);
        if (best == null || rec.seq > best.seq) best = rec;
      }
      k = _memtable.firstKeyAfter(k);
    }
    return best;
  }

  /// The newest entry for [prefix] in [s] at or below [ceiling].
  ///
  /// §1: "A read at snapshot S sees exactly the records with `seq ≤ S.seq`."
  /// Because seq is inverted in the internal key (§1 of `04`), versions of one
  /// key run newest-first, so the walk stops at the first visible one.
  SegRecord? _seekIn(Segment s, Uint8List prefix, int? ceiling) {
    final c = s.cursor()..seekCeiling(prefix);
    while (c.isValid) {
      final k = c.key();
      if (k.length < prefix.length) return null;
      for (var i = 0; i < prefix.length; i++) {
        if (k[i] != prefix[i]) return null;
      }
      final rec = c.record();
      if (ceiling == null || rec.seq <= ceiling) return rec;
      c.next(); // a version newer than the snapshot; keep walking down
    }
    return null;
  }

  Uint8List _resolve(SegRecord rec, {bool coalesce = true}) =>
      rec.valueKind == ValueKind.vlog
          ? vlog.readValue(VlogPointer.decode(rec.value), coalesce: coalesce)
          : Uint8List.fromList(rec.value);

  /// A key-ordered scan of one tree, optionally bounded by [range].
  ///
  /// This is what `spec/06-indexes.md` §7 is written against: every predicate
  /// it permits is a half-open `[lower, upper)` over CKE bytes, and every one
  /// of them arrives here. Versions are resolved as §4 requires — the newest
  /// entry for a user key wins, and a `DELETE` hides it.
  Iterable<({Uint8List cke, Uint8List value})> scanTree(int treeId,
      {KeyRange? range, Snapshot? at}) sync* {
    final ceiling = at?.seq;
    final rangeDeletes = _allRangeDeletes(treeId);
    final lower = userKeyPrefix(treeId, range?.lower ?? Uint8List(0));
    final upperKey = range?.upper;
    final upper = upperKey == null ? null : userKeyPrefix(treeId, upperKey);

    // The memtable is ordered, so filtering preserves the order and no sort
    // is needed here any more.
    final pending = <Uint8List>[
      for (final k in _memtable.keys)
        if (_inRange(k, treeId, lower, upper)) k
    ];
    var pi = 0;

    // **Sourced from the manifest, not from the extent map.** The manifest is
    // what says which segments are live (§3.2); `extents` is only where their
    // bytes are. A scan that walked the extent map would read segments the
    // manifest has retired — which is invisible while the two are kept in step
    // by compaction, and wrong the moment they are not: after a checkpoint
    // restore (`13-operations.md` §1) the manifest points at an older root
    // while every later segment's bytes are still present, so an extent-driven
    // scan would return data the restore was supposed to abandon.
    final sources = <SegmentCursor>[
      for (final seg in liveSegments) seg.cursor()..seekCeiling(lower),
    ];

    Uint8List? lastUserKey;
    while (true) {
      // The memtable is one more source in the same k-way merge, and it is
      // newest, so on a tie its entry has the greater seq and sorts first
      // anyway (§1 inverts seq in the internal key).
      Uint8List? bestKey;
      SegmentCursor? pick;
      var fromMem = false;
      if (pi < pending.length) {
        bestKey = pending[pi];
        fromMem = true;
      }
      for (final c in sources) {
        if (!c.isValid) continue;
        final k = c.key();
        if (bestKey == null || compareKeys(k, bestKey) < 0) {
          bestKey = k;
          pick = c;
          fromMem = false;
        }
      }
      if (bestKey == null) return;
      if (!_inRange(bestKey, treeId, lower, upper)) return;

      final int op;
      final int valueKind;
      final Uint8List value;
      final int? expiry;
      if (fromMem) {
        final p = _memtable[bestKey]!;
        op = bestKey[bestKey.length - 1];
        valueKind = p.valueKind;
        value = p.value;
        expiry = p.expiryMs;
        pi++;
      } else {
        final rec = pick!.record();
        op = rec.op;
        valueKind = rec.valueKind;
        value = rec.value;
        expiry = rec.expiryMs;
        pick.next();
      }

      final userKey =
          Uint8List.sublistView(bestKey, 0, bestKey.length - 9);
      if (ceiling != null && parseInternalKey(bestKey).seq > ceiling) {
        continue; // invisible at this snapshot; a lower version may still show
      }
      if (op == Op.rangeDelete) continue; // not an entry, a tombstone interval
      if (lastUserKey != null && compareKeys(lastUserKey, userKey) == 0) {
        continue; // an older version of a key already yielded
      }
      lastUserKey = Uint8List.fromList(userKey);
      if (op == Op.delete) continue;
      final entrySeq = parseInternalKey(bestKey).seq;
      if (rangeDeletes.isNotEmpty &&
          _rangeDeleteSeqIn(rangeDeletes, userKey, ceiling) > entrySeq) {
        continue;
      }
      if (expiry != null && expiry <= nowMs) continue;
      yield (
        cke: Uint8List.sublistView(userKey, 4),
        value: valueKind == ValueKind.vlog
            ? vlog.readValue(VlogPointer.decode(value))
            : Uint8List.fromList(value),
      );
    }
  }

  static bool _inRange(
      Uint8List ik, int treeId, Uint8List lower, Uint8List? upper) {
    if (ik.length < 13) return false;
    final t = (ik[0] << 24) | (ik[1] << 16) | (ik[2] << 8) | ik[3];
    if (t != treeId) return false;
    final user = Uint8List.sublistView(ik, 0, ik.length - 9);
    if (compareKeys(user, lower) < 0) return false;
    if (upper != null && compareKeys(user, upper) >= 0) return false;
    return true;
  }

  /// A full scan returning whole documents.
  ///
  /// With [LocalityPolicy.readahead] on, values are dereferenced in
  /// non-decreasing `(segment, offset)` order over a sliding window of
  /// [LocalityPolicy.readaheadWindow] entries, which is §8.1's MUST. Turning
  /// it off is what lets P8's "≥ 6× with the mechanisms disabled" be measured
  /// rather than asserted.
  ScanResult scanDocuments() {
    resetCounters();
    final entries = <SegRecord>[];
    final seen = <String>{};
    final sources = <SegmentCursor>[
      for (final seg in liveSegments) seg.cursor()..seekFirst(),
    ];
    while (true) {
      SegmentCursor? pick;
      for (final c in sources) {
        if (!c.isValid) continue;
        if (pick == null || compareKeys(c.key(), pick.key()) < 0) pick = c;
      }
      if (pick == null) break;
      final rec = pick.record();
      final userKey = String.fromCharCodes(Uint8List.sublistView(
          rec.internalKey, 0, rec.internalKey.length - 9));
      if (seen.add(userKey) && rec.op != Op.delete) entries.add(rec);
      pick.next();
    }

    var bytes = 0;
    if (policy.readahead) {
      for (var i = 0; i < entries.length; i += policy.readaheadWindow) {
        final end = (i + policy.readaheadWindow).clamp(0, entries.length);
        final window = entries.sublist(i, end)
          ..sort((a, b) {
            if (a.valueKind != ValueKind.vlog) return -1;
            if (b.valueKind != ValueKind.vlog) return 1;
            final pa = VlogPointer.decode(a.value);
            final pb = VlogPointer.decode(b.value);
            final c = pa.segmentId.compareTo(pb.segmentId);
            return c != 0 ? c : pa.offset.compareTo(pb.offset);
          });
        for (final e in window) {
          bytes += _resolve(e).length;
        }
      }
    } else {
      // §8.1's other half goes with it: without the window there is nothing to
      // coalesce reads *within*, so every dereference is its own I/O. Keeping
      // the coalescing here is what made this control inert.
      for (final e in entries) {
        bytes += _resolve(e, coalesce: false).length;
      }
    }

    lastScanRows = entries.length;
    return ScanResult(
      rows: entries.length,
      bytes: bytes,
      keyPageReads: _collectKeyReads(),
      valuePageReads: vlog.valuePageReads,
      valueReads: vlog.valueReads,
      localityDebt: vlog.localityDebt,
      liveVlogSegments: vlog.liveSegments,
      spaceAmplification: vlog.spaceAmplification,
    );
  }
}

/// What one scan cost. The counters, not the clock, are the result:
/// `design/performance-model.md` §8 forbids gating on wall time.
final class ScanResult {
  const ScanResult({
    required this.rows,
    required this.bytes,
    required this.keyPageReads,
    required this.valuePageReads,
    required this.valueReads,
    required this.localityDebt,
    required this.liveVlogSegments,
    required this.spaceAmplification,
  });

  final int rows;
  final int bytes;
  final int keyPageReads;
  final int valuePageReads;
  final int valueReads;
  final double localityDebt;

  /// The number of value-log segments a key-ordered scan interleaves. One is
  /// perfect clustering; nineteen is what ageing produced before the cold tier
  /// was collected.
  final int liveVlogSegments;

  final double spaceAmplification;

  int get totalPageReads => keyPageReads + valuePageReads;

  /// The metric `spec/13-operations.md` §6 calls "the number that predicts
  /// scan decay", and that P8 bounds at 0.3.
  double get valueReadsPerScannedRow =>
      rows == 0 ? 0 : valuePageReads / rows;

  @override
  String toString() => 'rows $rows, key pages $keyPageReads, '
      'value pages $valuePageReads, '
      'v/row ${valueReadsPerScannedRow.toStringAsFixed(3)}, '
      'debt ${(localityDebt * 100).toStringAsFixed(1)}%';
}

/// A percentile over a sample of `segments_probed_per_lookup`, the metric
/// `spec/13-operations.md` §6 requires at p50 and p99 and that prediction P10
/// bounds at p99 ≤ 2 and p99.9 ≤ 3.
int percentile(List<int> samples, double p) {
  if (samples.isEmpty) return 0;
  final sorted = [...samples]..sort();
  final i = ((sorted.length - 1) * p).round();
  return sorted[i];
}
