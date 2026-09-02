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

import 'dart:typed_data';

import 'cke.dart';
import 'cow.dart';
import 'errors.dart';
import 'manifest.dart';
import 'segment.dart';
import 'value.dart';
import 'vlog.dart';

/// One buffered write, before it reaches a segment.
final class _Pending {
  _Pending(this.internalKey, this.valueKind, this.value);
  final Uint8List internalKey;
  final int valueKind;
  final Uint8List value;
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
    this.vlogMin = 256,
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
  })  : segmentEntries = segmentEntries ?? memtableEntries,
        store = PageStore(pageSize: pageSize),
        vlog = ValueLog(
          pageSize: pageSize,
          segmentBytes: vlogSegmentBytes ?? (4 << 20),
          cachePages: cachePages,
        ) {
    manifest = Manifest(store);
  }

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

  final ValueLog vlog;

  /// The file's page space. The manifest lives in it; segment extents do not,
  /// which `REPORT.md` §5 states as a limit of this implementation.
  final PageStore store;

  /// Tree 6.
  late final Manifest manifest;

  /// Segment extents by `segment_id`, standing in for `start_page`/`pages`.
  final Map<int, Segment> extents = {};

  final Map<Uint8List, _Pending> _memtable = {};

  int _nextSeq = 1;
  int _nextSegmentId = 1;
  bool _recluster = false;

  int get lastLevel => levels.levelCount - 1;

  /// How many cold-tier collections have run. A collection is a third write of
  /// a value, which §6.3's "at most twice" does not account for.
  int coldCollections = 0;

  /// Keys this writer has seen before, for the heat classifier of §6.6.
  final Set<int> _seen = {};

  int keyPageReads = 0;
  int get valuePageReads => vlog.valuePageReads;
  int get valueReads => vlog.valueReads;

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
  void put(int treeId, CValue key, Uint8List encodedValue) =>
      _write(treeId, key, encodedValue, Op.put);

  /// Writes a tombstone.
  void remove(int treeId, CValue key) =>
      _write(treeId, key, Uint8List(0), Op.delete);

  /// Writes an entry whose value is `EMPTY` (`value_kind` 3, zero bytes).
  ///
  /// Every secondary-index entry is one of these: `spec/06-indexes.md` §1 puts
  /// the indexed values *and* the document id in the key, so the value carries
  /// nothing and an index entry costs no value bytes at all.
  void putEmpty(int treeId, CValue key) {
    final ik = internalKey(treeId, encodeKey(key), _nextSeq++, Op.put);
    _memtable[ik] = _Pending(ik, ValueKind.empty, Uint8List(0));
    if (_memtable.length >= memtableEntries) flush();
  }

  void _write(int treeId, CValue key, Uint8List encodedValue, int op) {
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
    _memtable[ik] = _Pending(ik, kind, stored);
    if (_memtable.length >= memtableEntries) flush();
  }

  /// Turns the memtable into an L0 segment, §2.3, and publishes it.
  void flush() {
    if (_memtable.isEmpty) return;
    final keys = _memtable.keys.toList()..sort(compareKeys);
    final b = _builder(level: 0);
    for (final k in keys) {
      final p = _memtable[k]!;
      b.add(SegEntry(p.internalKey, p.valueKind, p.value));
    }
    _publish(b, level: 0, group: 0);
    _memtable.clear();
    maybeCompact();
  }

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

  SegmentBuilder _builder({required int level}) => SegmentBuilder(
        pageSize: pageSize,
        segmentId: _nextSegmentId++,
        level: level,
        group: 0,
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
  List<SegmentRef> refsAt(int level) {
    final cached = _levelCache[level];
    if (cached != null) return cached;
    return _levelCache[level] = manifest.level(level).toList();
  }

  final Map<int, List<SegmentRef>> _levelCache = {};

  /// Group ids in use at [level].
  Set<int> groupsAt(int level) => {for (final r in refsAt(level)) r.group};

  /// Runs the level policy of §3.1 until every bound holds.
  void maybeCompact() {
    var guard = 0;
    while (guard++ < 1000) {
      if (refsAt(0).length >= levels.l0Trigger) {
        _compactFrom(0);
        continue;
      }
      var moved = false;
      for (var l = 1; l < lastLevel; l++) {
        final refs = refsAt(l);
        if (refs.length > levels.tierWidth ||
            groupsAt(l).length > levels.overlapBound) {
          _compactFrom(l);
          moved = true;
          break;
        }
      }
      if (!moved) return;
    }
    throw StateError('compaction did not converge');
  }

  /// Merges everything down into the last level.
  ///
  /// The public "make it tidy" operation, and what the P8 harness calls: it
  /// forces the last-level compaction that promotion and cold-tier collection
  /// hang off (§6.3, §6.8).
  void compact() {
    flush();
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

  /// Compacts every segment at [level] into the next level.
  void _compactFrom(int level) {
    final inputs = refsAt(level);
    if (inputs.isEmpty) return;
    _compactInto(inputs, level + 1 >= lastLevel ? lastLevel : level + 1);
  }

  void _compactInto(List<SegmentRef> inputs, int target,
      {bool forceRecluster = false}) {
    final levelled = target == lastLevel;
    final all = <SegmentRef>[...inputs];
    final seen = {for (final r in inputs) r.segmentId};
    if (levelled) {
      // The last level is disjoint, so the compaction must include every
      // last-level segment whose range the inputs touch — that is also §5's
      // condition 3, the one that makes dropping a superseded version legal.
      final lo = _minOf(inputs);
      final hi = _maxOf(inputs);
      for (final r in refsAt(lastLevel)) {
        if (seen.contains(r.segmentId)) continue;
        if (compareKeys(r.minKey, hi) <= 0 && compareKeys(r.maxKey, lo) >= 0) {
          all.add(r);
        }
      }
    }

    // §6.8 step 1: collection is triggered by whichever bound is breached
    // first — the space target, or the locality debt. The second is the one an
    // earlier draft did not have, and the two have the same cause (surplus
    // runs) without being the same quantity.
    _recluster = levelled &&
        (forceRecluster ||
            vlog.allocatedBytes > vlog.liveBytes * vlogSpaceTargetPct / 100 ||
            vlog.localityDebt * 100 > localityDebtPct);

    final sources = <SegmentCursor>[
      for (final r in all) extents[r.segmentId]!.cursor()..seekFirst(),
    ];
    final dead = <VlogPointer>[];
    final outputs = <Segment>[];
    var out = _builder(level: target);
    Uint8List? lastUserKey;

    void rotate() {
      if (out.entryCount == 0) return;
      outputs.add(Segment(out.build(), pageSize));
      out = _builder(level: target);
    }

    while (true) {
      // Pick the smallest internal key across the sources. Newest-first is
      // built into the key: seq is inverted (§1), so the first entry seen for
      // a user key is the newest version of it.
      SegmentCursor? pick;
      for (final c in sources) {
        if (!c.isValid) continue;
        if (pick == null || compareKeys(c.key(), pick.key()) < 0) pick = c;
      }
      if (pick == null) break;

      final rec = pick.record();
      final parsed = parseInternalKey(rec.internalKey);
      final userKey = Uint8List.sublistView(
          rec.internalKey, 0, rec.internalKey.length - 9);
      final isNewest =
          lastUserKey == null || compareKeys(lastUserKey, userKey) != 0;

      if (isNewest) {
        lastUserKey = Uint8List.fromList(userKey);
        // A segment boundary is only legal between user keys: two versions of
        // one key in two segments of the same disjoint run would break the
        // "at most one segment per group covers a key" invariant of §3.1.
        if (out.entryCount >= segmentEntriesAt(target)) rotate();
        if (levelled && rec.op == Op.delete) {
          // §5: a tombstone may be dropped when the compaction reaches the
          // last level and its seq is at or below the oldest live snapshot's.
          // There are no snapshots here, so that second half is trivially true.
        } else {
          out.add(_promote(rec, parsed.treeId, dead));
        }
      } else if (levelled) {
        // §5 condition 3 holds only at the last level, so a superseded
        // version may be dropped only here. A tiered compaction keeps every
        // version, which is what makes tiering cheap on the write side.
        if (rec.valueKind == ValueKind.vlog) {
          // §6.7 lets liveness be decremented only when a compaction has
          // *observed* the value superseded, which is here.
          dead.add(VlogPointer.decode(rec.value));
        }
      } else {
        out.add(SegEntry(rec.internalKey, rec.valueKind, rec.value));
      }
      pick.next();
    }
    rotate();

    for (final r in all) {
      _retire(r);
    }
    final group = levelled ? 0 : _freeGroup(target);
    for (final s in outputs) {
      extents[s.header.segmentId] = s;
      manifest.add(SegmentRef.of(s, level: target, group: group));
    }
    _levelCache.remove(target);

    if (_recluster) coldCollections++;
    _recluster = false;
    for (final p in dead) {
      vlog.markDead(p);
    }
    vlog
      ..sealOpen()
      ..reclaimEmpty();
  }

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

  SegEntry _promote(SegRecord rec, int treeId, List<VlogPointer> dead) {
    if (rec.valueKind != ValueKind.vlog || !policy.clusteredPromotion) {
      return SegEntry(rec.internalKey, rec.valueKind, rec.value);
    }
    final ptr = VlogPointer.decode(rec.value);
    final seg = vlog.segments[ptr.segmentId];
    if (seg == null) {
      return SegEntry(rec.internalKey, rec.valueKind, rec.value);
    }
    if (seg.tier == VlogTier.cold && !_recluster) {
      // Already clustered within its own generation, and the log is inside its
      // space target, so leave it: §6.3's "values are written at most twice".
      return SegEntry(rec.internalKey, rec.valueKind, rec.value);
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
    return SegEntry(rec.internalKey, ValueKind.vlog, moved.encode());
  }

  // -------------------------------------------------------------------------
  // Read path — `spec/04-segments.md` §4
  // -------------------------------------------------------------------------

  /// Every segment that may hold [userKeyPrefix], in the order §4 walks them.
  ///
  /// Manifest key-range pruning costs no I/O; the filter costs one page read
  /// of an already-hot page. What survives both is what gets descended into,
  /// and its count is `segments_probed_per_lookup`.
  List<Segment> candidatesFor(Uint8List userKeyPrefix) {
    final out = <Segment>[];

    void consider(List<SegmentRef> refs) {
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
  Uint8List? get(int treeId, CValue key) {
    final prefix = userKeyPrefix(treeId, encodeKey(key));

    // The memtable holds records that are sequenced but not yet in a segment.
    // `spec/10-transactions.md` §2 step 5 publishes into it, and a reader at
    // `visible_seq` sees them; a `get` that skipped it would lose every write
    // since the last flush.
    SegRecord? best = _memtableLookup(prefix);
    if (best != null && earlyExit) {
      // Nothing in a segment can be newer than an unflushed record.
      segmentsProbed.add(0);
      return best.op == Op.delete ? null : _resolve(best);
    }

    final candidates = candidatesFor(prefix);
    var probed = 0;
    for (final s in candidates) {
      probed++;
      final rec = _seekIn(s, prefix);
      if (rec == null) {
        if (s.filter != null) filterFalsePositives++;
        continue;
      }
      if (best == null || rec.seq > best.seq) best = rec;
      if (earlyExit) break;
    }
    segmentsProbed.add(probed);
    if (best == null || best.op == Op.delete) return null;
    return _resolve(best);
  }

  SegRecord? _memtableLookup(Uint8List prefix) {
    SegRecord? best;
    for (final e in _memtable.entries) {
      final k = e.key;
      if (k.length != prefix.length + 9) continue;
      var match = true;
      for (var i = 0; i < prefix.length; i++) {
        if (k[i] != prefix[i]) {
          match = false;
          break;
        }
      }
      if (!match) continue;
      final rec = SegRecord(k, e.value.valueKind, e.value.value, null);
      if (best == null || rec.seq > best.seq) best = rec;
    }
    return best;
  }

  SegRecord? _seekIn(Segment s, Uint8List prefix) {
    final c = s.cursor()..seekCeiling(prefix);
    if (!c.isValid) return null;
    final k = c.key();
    if (k.length < prefix.length) return null;
    for (var i = 0; i < prefix.length; i++) {
      if (k[i] != prefix[i]) return null;
    }
    return c.record();
  }

  Uint8List _resolve(SegRecord rec) => rec.valueKind == ValueKind.vlog
      ? vlog.readValue(VlogPointer.decode(rec.value))
      : Uint8List.fromList(rec.value);

  /// A key-ordered scan of one tree, optionally bounded by [range].
  ///
  /// This is what `spec/06-indexes.md` §7 is written against: every predicate
  /// it permits is a half-open `[lower, upper)` over CKE bytes, and every one
  /// of them arrives here. Versions are resolved as §4 requires — the newest
  /// entry for a user key wins, and a `DELETE` hides it.
  Iterable<({Uint8List cke, Uint8List value})> scanTree(int treeId,
      {KeyRange? range}) sync* {
    final lower = userKeyPrefix(treeId, range?.lower ?? Uint8List(0));
    final upperKey = range?.upper;
    final upper = upperKey == null ? null : userKeyPrefix(treeId, upperKey);

    // The memtable is unsorted; the range of it that matters is sorted once.
    final pending = <Uint8List>[
      for (final k in _memtable.keys)
        if (_inRange(k, treeId, lower, upper)) k
    ]..sort(compareKeys);
    var pi = 0;

    final sources = <SegmentCursor>[
      for (final s in extents.values) s.cursor()..seekCeiling(lower),
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
      if (fromMem) {
        final p = _memtable[bestKey]!;
        op = bestKey[bestKey.length - 1];
        valueKind = p.valueKind;
        value = p.value;
        pi++;
      } else {
        final rec = pick!.record();
        op = rec.op;
        valueKind = rec.valueKind;
        value = rec.value;
        pick.next();
      }

      final userKey =
          Uint8List.sublistView(bestKey, 0, bestKey.length - 9);
      if (lastUserKey != null && compareKeys(lastUserKey, userKey) == 0) {
        continue; // an older version of a key already yielded
      }
      lastUserKey = Uint8List.fromList(userKey);
      if (op == Op.delete) continue;
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
      for (final s in extents.values) s.cursor()..seekFirst(),
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
      for (final e in entries) {
        bytes += _resolve(e).length;
      }
    }

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
