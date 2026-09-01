/// A minimal LSM engine over the segments of `spec/04-segments.md`: a
/// memtable, an L0, a levelled last level, and the two-tier value log.
///
/// **Scope, stated plainly.** This is the smallest engine that can measure
/// prediction P8 honestly — an aged scan over separated values. It implements
/// key-value separation (§6), clustered promotion (§6.3), the read-resolution
/// rules of §4, cursor value readahead (§8.1), and the locality-debt metric
/// (§6.9). It does **not** implement tiered intermediate levels, range
/// partitioning, range deletes, TTL, transactions, or the manifest as a
/// copy-on-write tree — all orthogonal to P8, and all named in `REPORT.md` as
/// not built.
library;

import 'dart:typed_data';

import 'cke.dart';
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

/// A tiny store over one tree. Enough for P8, and no more.
final class Engine {
  Engine({
    this.pageSize = 4096,
    this.vlogMin = 256,
    this.memtableEntries = 20000,
    this.policy = const LocalityPolicy(),
    this.vlogSpaceTargetPct = 150,
    this.localityDebtPct = 20,
    int? vlogSegmentBytes,
    int cachePages = 256,
  }) : vlog = ValueLog(
          pageSize: pageSize,
          segmentBytes: vlogSegmentBytes ?? (4 << 20),
          cachePages: cachePages,
        );

  final int pageSize;

  /// `spec/00-conventions.md` §8: MUST be ≤ page_size / 4.
  final int vlogMin;
  final int memtableEntries;
  final LocalityPolicy policy;

  /// `vlog_space_target_pct` (`spec/01-container.md` §2). Crossing it is what
  /// triggers a cold-tier collection, which is also what restores clustering
  /// across compactions — see [compact].
  final int vlogSpaceTargetPct;

  /// `locality_debt_pct` (`spec/01-container.md` §2, `spec/04-segments.md`
  /// §6.9). The ceiling on the fraction of live value bytes in surplus runs.
  final int localityDebtPct;

  final ValueLog vlog;

  final Map<Uint8List, _Pending> _memtable = {};
  final List<Uint8List> _memOrder = [];

  /// L0: newest first. Section 4 resolves by entry seq, not by segment order,
  /// but keeping L0 ordered lets the early exit of §4 be provable.
  final List<Segment> l0 = [];

  /// The last level: disjoint, so at most one segment covers any key.
  Segment? last;

  int _nextSeq = 1;
  int _nextSegmentId = 1;
  bool _recluster = false;

  /// How many cold-tier collections have run. A collection is a third write of
  /// a value, which §6.3's "at most twice" does not account for.
  int coldCollections = 0;

  /// Keys this writer has seen before, for the heat classifier of §6.6.
  final Set<int> _seen = {};

  int keyPageReads = 0;
  int get valuePageReads => vlog.valuePageReads;
  int get valueReads => vlog.valueReads;

  void resetCounters() {
    keyPageReads = 0;
    vlog.resetCounters();
    for (final s in [...l0, if (last != null) last!]) {
      s.resetCounters();
    }
  }

  int _collectKeyReads() {
    var n = 0;
    for (final s in [...l0, if (last != null) last!]) {
      n += s.pageReads;
    }
    return n + keyPageReads;
  }

  /// Writes one document.
  void put(int treeId, CValue key, Uint8List encodedValue) {
    final cke = encodeKey(key);
    final seq = _nextSeq++;
    final ik = internalKey(treeId, cke, seq, Op.put);

    int kind;
    Uint8List stored;
    if (encodedValue.length >= vlogMin) {
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
    _memOrder.add(ik);
    _memtable[ik] = _Pending(ik, kind, stored);
    if (_memtable.length >= memtableEntries) flush();
  }

  /// Turns the memtable into an L0 segment, §2.3.
  void flush() {
    if (_memtable.isEmpty) return;
    final keys = _memtable.keys.toList()..sort(compareKeys);
    final b = SegmentBuilder(
        pageSize: pageSize, segmentId: _nextSegmentId++, level: 0);
    for (final k in keys) {
      final p = _memtable[k]!;
      b.add(SegEntry(p.internalKey, p.valueKind, p.value));
    }
    l0.insert(0, Segment(b.build(), pageSize));
    _memtable.clear();
    _memOrder.clear();
  }

  /// Merges L0 and the last level into a new last level.
  ///
  /// This is where **clustered promotion** happens (§6.3): the merge already
  /// walks keys in sorted order, so appending each surviving hot value to a
  /// cold segment as it passes produces a key-clustered log at no extra cost.
  ///
  /// It also **collects the cold tier** when the value log crosses
  /// `vlog_space_target_pct`. That is §6.8's "Collecting a COLD segment MUST
  /// preserve key clustering", and without it a promoted value stays where its
  /// first promotion put it: after ten rounds of ageing the reference
  /// implementation measured nineteen live cold segments holding 8 MB of live
  /// data in 48 MB of extents, every one of them internally sorted, and a
  /// key-ordered scan interleaving all nineteen at 2.1x the cost of a fresh
  /// one. Promotion alone clusters a *generation*; collection is what merges
  /// the generations back into one run.
  void compact() {
    flush();
    // §6.8 step 1: pick by liveness. Collection is triggered by whichever
    // bound is breached first — the space target, or the locality debt.
    //
    // The second trigger is the one that matters and the one an earlier
    // draft did not have: space amplification and scan locality have the same
    // *cause* here (surplus runs) but they are not the same quantity, and a
    // database can sit comfortably inside its space target while a key-ordered
    // scan interleaves nineteen runs.
    _recluster = vlog.allocatedBytes >
            vlog.liveBytes * vlogSpaceTargetPct / 100 ||
        vlog.localityDebt * 100 > localityDebtPct;
    final sources = <SegmentCursor>[
      for (final s in l0) s.cursor()..seekFirst(),
      if (last != null) last!.cursor()..seekFirst(),
    ];
    if (sources.isEmpty) return;

    final out = SegmentBuilder(
        pageSize: pageSize, segmentId: _nextSegmentId++, level: 1);
    Uint8List? lastUserKey;
    final dead = <VlogPointer>[];

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
        if (rec.op != Op.delete) {
          out.add(_promote(rec, parsed.treeId, dead));
        }
      } else if (rec.valueKind == ValueKind.vlog) {
        // A superseded separated value: §6.7 lets liveness be decremented only
        // when a compaction has *observed* it superseded, which is here.
        dead.add(VlogPointer.decode(rec.value));
      }
      pick.next();
    }

    if (out.entryCount == 0) {
      l0.clear();
      return;
    }
    last = Segment(out.build(), pageSize);
    if (_recluster) coldCollections++;
    _recluster = false;
    l0.clear();
    for (final p in dead) {
      vlog.markDead(p);
    }
    vlog
      ..sealOpen()
      ..reclaimEmpty();
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

  /// Reads one key at the current snapshot.
  ///
  /// Section 4, with the two rules that were wrong in an earlier draft: every
  /// candidate is examined and the winner is the entry with the greatest seq,
  /// never the first hit in segment order.
  Uint8List? get(int treeId, CValue key) {
    final prefix = userKeyPrefix(treeId, encodeKey(key));
    SegRecord? best;
    for (final s in [...l0, if (last != null) last!]) {
      final c = s.cursor()..seekCeiling(prefix);
      if (!c.isValid) continue;
      final k = c.key();
      if (k.length < prefix.length) continue;
      var match = true;
      for (var i = 0; i < prefix.length; i++) {
        if (k[i] != prefix[i]) {
          match = false;
          break;
        }
      }
      if (!match) continue;
      final rec = c.record();
      if (best == null || rec.seq > best.seq) best = rec;
    }
    if (best == null || best.op == Op.delete) return null;
    return _resolve(best);
  }

  Uint8List _resolve(SegRecord rec) => rec.valueKind == ValueKind.vlog
      ? vlog.readValue(VlogPointer.decode(rec.value))
      : Uint8List.fromList(rec.value);

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
      for (final s in l0) s.cursor()..seekFirst(),
      if (last != null) last!.cursor()..seekFirst(),
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
