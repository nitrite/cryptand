/// The value log, `spec/04-segments.md` section 6.
///
/// Two tiers, and the whole point of the second one:
///
///   > "Promotion happens during last-level compaction, which already walks
///   >  keys in sorted order. Appending each surviving value to the cold log as
///   >  it passes therefore produces a key-clustered cold log *by
///   >  construction* -- the ordering is free, because the sort had to happen
///   >  anyway."
///
/// Records are laid out over real pages and read through a bounded page cache,
/// because that is the only way `value_reads_per_scanned_row` -- the metric
/// `spec/13-operations.md` section 6 says "predicts scan decay" -- means
/// anything. A value log held in a flat map would make every locality claim
/// vacuously true.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'cke.dart';
import 'container.dart';
import 'crc32c.dart';
import 'errors.dart';

/// Value-log tiers, section 6.1.
class VlogTier {
  static const int hot = 0;
  static const int cold = 1;
}

/// Heat classes, section 6.6. The format records the class; the classifier is
/// the implementation's.
class HeatClass {
  /// First write of this key that this writer has seen. Correct, and merely
  /// slower, for a writer with no heat information.
  static const int first = 0;
  static const int warm = 1;
  static const int hot = 2;
}

/// A 16-byte value-log pointer, section 6.4.
final class VlogPointer {
  const VlogPointer(this.segmentId, this.offset, this.len);
  final int segmentId;
  final int offset;
  final int len;

  Uint8List encode() {
    final w = ByteWriter(16)
      ..u64(segmentId)
      ..u32(offset)
      ..u32(len);
    return w.takeBytes();
  }

  static VlogPointer decode(Uint8List b) {
    if (b.length != 16) {
      throw CorruptionException('VLOG pointer is 16 bytes, got ${b.length}');
    }
    final r = ByteReader(b);
    return VlogPointer(r.u64(), r.u32(), r.u32());
  }

  @override
  String toString() => 'vlog($segmentId+$offset, $len B)';
}

/// One value-log segment: a page-aligned extent plus the mutable state that
/// section 6.2 puts in tree 7 rather than in the head page.
final class VlogSegment {
  VlogSegment({
    required this.id,
    required this.tier,
    required this.heatClass,
    required this.pageSize,
    required this.capacity,
  }) : _buf = Uint8List(dataOffset + capacity) {
    _writeHeadPage();
  }

  /// Head page header (40) + the 64-byte segment header, rounded up to 8.
  static const int dataOffset = 104;

  final int id;
  final int tier;
  final int heatClass;
  final int pageSize;
  final int capacity;

  final Uint8List _buf;

  /// Tree-7 state, section 6.7. `bytes` is the durable contiguous watermark.
  int bytes = 0;
  int records = 0;
  bool sealed = false;
  bool clustered = false;
  Uint8List? minKey;
  Uint8List? maxKey;
  int liveBytes = 0;
  int liveRecords = 0;

  Uint8List? _lastKey;
  bool _orderHolds = true;

  int get pageCount => (dataOffset + capacity + pageSize - 1) ~/ pageSize;
  int get remaining => capacity - bytes;

  void _writeHeadPage() {
    // Section 6.2: the head page is written once and never rewritten, so it
    // carries only immutable identity.
    final w = ByteWriter(64)
      ..bytes(const [0x43, 0x52, 0x59, 0x5F, 0x56, 0x4C, 0x47, 0x1A])
      ..u64(id)
      ..u64(0) // created_seq
      ..u64(capacity)
      ..u32(dataOffset)
      ..u8(tier)
      ..u8(heatClass)
      ..u8(0) // codec
      ..u8(0) // encrypted
      ..u64(0) // nonce_base
      ..bytes(Uint8List(16));
    _buf.setRange(PageHeader.size, PageHeader.size + w.length, w.view);
  }

  /// Appends one record, returning its pointer, or null when full.
  ///
  /// Record framing, section 6.2:
  /// `uvar record_len | u32 tree_id | uvar key_len | key | uvar value_len |
  ///  value | u32 crc32c`.
  VlogPointer? append(int treeId, Uint8List ckeKey, Uint8List value) {
    if (sealed) {
      throw StateError('cannot append to a sealed value-log segment');
    }
    final body = ByteWriter(value.length + ckeKey.length + 16)
      ..u32(treeId)
      ..uvar(ckeKey.length)
      ..bytes(ckeKey)
      ..uvar(value.length)
      ..bytes(value);
    final crc = crc32c(body.view);
    final recordLen = body.length + 4;
    final head = ByteWriter(10)..uvar(recordLen);
    final total = head.length + recordLen;
    if (total > remaining) return null;

    final offset = dataOffset + bytes;
    var p = offset;
    _buf.setRange(p, p + head.length, head.view);
    p += head.length;
    _buf.setRange(p, p + body.length, body.view);
    p += body.length;
    ByteData.view(_buf.buffer).setUint32(p, crc, Endian.little);

    bytes += total;
    records++;
    liveBytes += total;
    liveRecords++;

    // Section 6.2: KEY_CLUSTERED asserts non-decreasing (tree_id, CKE(key)).
    if (_lastKey != null && compareKeys(_lastKey!, ckeKey) > 0) {
      _orderHolds = false;
    }
    _lastKey = Uint8List.fromList(ckeKey);
    minKey ??= Uint8List.fromList(ckeKey);
    maxKey = Uint8List.fromList(ckeKey);

    return VlogPointer(id, offset, total);
  }

  /// Seals the segment. Sets `clustered` **only when the ordering actually
  /// holds** (section 6.3).
  void seal({required bool claimClustered}) {
    sealed = true;
    clustered = claimClustered && _orderHolds;
  }

  /// Reads a record body. [pageOf] is called for every page the read touches,
  /// so a caller can account for I/O.
  (int treeId, Uint8List key, Uint8List value) read(
      VlogPointer ptr, void Function(int pageIndex) pageOf) {
    if (ptr.segmentId != id) {
      throw CorruptionException('pointer names segment ${ptr.segmentId}, '
          'this is $id');
    }
    if (ptr.offset < dataOffset || ptr.offset + ptr.len > dataOffset + bytes) {
      // Section 6.4: a pointer past the durable watermark is corruption.
      throw CorruptionException(
          'VLOG pointer $ptr resolves past the durable watermark');
    }
    for (var p = ptr.offset ~/ pageSize;
        p <= (ptr.offset + ptr.len - 1) ~/ pageSize;
        p++) {
      pageOf(p);
    }
    final r = ByteReader(_buf, ptr.offset, ptr.offset + ptr.len);
    final recordLen = r.uvar();
    final bodyStart = r.position;
    final treeId = r.u32();
    final key = r.bytesCopy(r.uvar());
    final value = r.bytesCopy(r.uvar());
    final stored = ByteData.view(_buf.buffer)
        .getUint32(bodyStart + recordLen - 4, Endian.little);
    if (crc32c(_buf, bodyStart, bodyStart + recordLen - 4) != stored) {
      throw CorruptionException('value-log record CRC mismatch at $ptr');
    }
    return (treeId, key, value);
  }

  /// Iterates every record in order, for garbage collection and verification.
  Iterable<(VlogPointer, int, Uint8List, Uint8List)> scan() sync* {
    var off = dataOffset;
    final end = dataOffset + bytes;
    while (off < end) {
      final r = ByteReader(_buf, off, end);
      final recordLen = r.uvar();
      final total = (r.position - off) + recordLen;
      final treeId = r.u32();
      final key = r.bytesCopy(r.uvar());
      final value = r.bytesCopy(r.uvar());
      yield (VlogPointer(id, off, total), treeId, key, value);
      off += total;
    }
  }
}

/// The value log: every segment, plus the page cache reads go through.
final class ValueLog {
  ValueLog({
    required this.pageSize,
    required this.segmentBytes,
    this.cachePages = 256,
  });

  final int pageSize;
  final int segmentBytes;

  /// Pages the reader may hold. Bounded, because an unbounded cache would make
  /// every locality measurement meaningless.
  final int cachePages;

  final Map<int, VlogSegment> segments = {};
  int _nextId = 1;

  /// One open segment per (tier, heat class). Section 6.2: "the number of open
  /// value-log segments is bounded by the number of **heat classes**, *not* by
  /// the number of writer threads".
  final Map<int, VlogSegment> _open = {};

  // --- instrumentation -----------------------------------------------------
  int valuePageReads = 0;
  int valueReads = 0;

  /// Every byte ever appended, including bytes since reclaimed. This is the
  /// value-side write amplification of `design/performance-model.md` §3.1,
  /// and the price a cold-tier collection charges.
  int totalBytesAppended = 0;
  int totalRecordsAppended = 0;

  /// Bytes appended by a promotion or a collection, rather than by the write
  /// path. §6.3 says a value is written "at most twice"; this counts the
  /// times that is not true.
  int promotedBytes = 0;
  final _Lru _cache = _Lru();

  void resetCounters() {
    valuePageReads = 0;
    valueReads = 0;
  }

  void clearCache() => _cache.clear();

  int _slot(int tier, int heat) => tier * 16 + heat;

  VlogSegment _segmentFor(int tier, int heat, int need) {
    final k = _slot(tier, heat);
    var seg = _open[k];
    if (seg != null && seg.remaining >= need) return seg;
    if (seg != null) seg.seal(claimClustered: tier == VlogTier.cold);
    seg = VlogSegment(
      id: _nextId++,
      tier: tier,
      heatClass: heat,
      pageSize: pageSize,
      capacity: need > segmentBytes ? need : segmentBytes,
    );
    segments[seg.id] = seg;
    _open[k] = seg;
    return seg;
  }

  /// Appends a value and returns its pointer.
  VlogPointer append({
    required int treeId,
    required Uint8List ckeKey,
    required Uint8List value,
    int tier = VlogTier.hot,
    int heat = HeatClass.first,
  }) {
    final need = value.length + ckeKey.length + 24;
    final seg = _segmentFor(tier, heat, need);
    final ptr = seg.append(treeId, ckeKey, value);
    if (ptr == null) {
      throw StateError('value-log segment ${seg.id} rejected a sized append');
    }
    totalBytesAppended += ptr.len;
    totalRecordsAppended++;
    if (tier == VlogTier.cold) promotedBytes += ptr.len;
    return ptr;
  }

  /// Seals every open segment. `spec/14-security.md` section 4.3 makes this
  /// mandatory on open; here it is what a flush or a close does.
  void sealOpen() {
    for (final e in _open.entries) {
      e.value.seal(claimClustered: e.value.tier == VlogTier.cold);
    }
    _open.clear();
  }

  Uint8List readValue(VlogPointer ptr) {
    valueReads++;
    final seg = segments[ptr.segmentId];
    if (seg == null) {
      throw CorruptionException('no value-log segment ${ptr.segmentId}');
    }
    final (_, _, value) = seg.read(ptr, (page) {
      final key = ptr.segmentId * 1000000 + page;
      if (!_cache.touch(key, cachePages)) valuePageReads++;
    });
    return value;
  }

  /// Section 6.9's `locality_debt` **as it was originally defined**: live bytes
  /// in segments without the clustered flag, over total live value bytes.
  ///
  /// The reference implementation found this measures the wrong thing. After
  /// ageing, a database can hold nineteen cold segments each of which is
  /// perfectly sorted internally — so this reads **0 %** — while a key-ordered
  /// scan interleaves all nineteen and costs 2.1x a fresh scan. Individually
  /// sorted runs are not the same property as *one* sorted run.
  /// [scanFragmentation] is what actually predicts scan decay, and
  /// `spec/04-segments.md` §6.9 now defines the bound in terms of it.
  double get clusteredFlagDebt {
    var live = 0, unclustered = 0;
    for (final s in segments.values) {
      live += s.liveBytes;
      if (!s.clustered) unclustered += s.liveBytes;
    }
    return live == 0 ? 0 : unclustered / live;
  }

  /// `locality_debt` as `spec/04-segments.md` §6.9 now defines it: **the
  /// fraction of live value bytes sitting in surplus runs**.
  ///
  /// A key-ordered scan over separated values costs one sequential pass per
  /// run it has to interleave. The minimum number of runs is set by how much
  /// live data there is and how large a segment may be; anything beyond that
  /// minimum is surplus, and the bytes in it are what a scan pays extra for.
  ///
  /// So: sort the live segments by live bytes, descending; the first
  /// `ceil(liveBytes / segmentBytes)` of them are the runs the data genuinely
  /// needs; every byte in the rest is debt.
  ///
  /// This replaces the original definition, which counted only segments
  /// *lacking the clustered flag* and therefore read 0 % on a database whose
  /// scans had already degraded 2.1x — see [clusteredFlagDebt].
  double get localityDebt {
    final live = segments.values.where((s) => s.liveRecords > 0).toList()
      ..sort((a, b) => b.liveBytes.compareTo(a.liveBytes));
    final total = live.fold<int>(0, (a, s) => a + s.liveBytes);
    if (total == 0) return 0;
    final ideal = ((total + segmentBytes - 1) ~/ segmentBytes).clamp(1, live.length);
    var surplus = 0;
    for (var i = ideal; i < live.length; i++) {
      surplus += live[i].liveBytes;
    }
    // Bytes in a run that is *not* key-clustered are surplus whatever the
    // count, since a scan cannot read them sequentially at all.
    for (var i = 0; i < ideal; i++) {
      if (!live[i].clustered) surplus += live[i].liveBytes;
    }
    final debt = surplus / total;
    return debt > 1 ? 1 : debt;
  }

  /// The minimum number of runs this much live data needs.
  int get idealSegments {
    final total = liveBytes;
    if (total == 0) return 0;
    return (total + segmentBytes - 1) ~/ segmentBytes;
  }

  /// Live cold segments, the number a key-ordered scan interleaves.
  int get liveSegments =>
      segments.values.where((s) => s.liveRecords > 0).length;

  /// Allocated over live: the value-log side of space amplification, bounded
  /// by `vlog_space_target_pct` (§6.9, and the backpressure table of
  /// `spec/10-transactions.md` §6).
  double get spaceAmplification =>
      liveBytes == 0 ? 1 : allocatedBytes / liveBytes;

  int get liveBytes =>
      segments.values.fold(0, (a, s) => a + s.liveBytes);
  int get allocatedBytes =>
      segments.values.fold(0, (a, s) => a + s.bytes);

  /// Marks a record dead. Section 6.7: `live_bytes` may overstate liveness and
  /// MUST NOT understate it, so this is only ever called when a compaction has
  /// *observed* the record superseded.
  void markDead(VlogPointer ptr) {
    final s = segments[ptr.segmentId];
    if (s == null) return;
    s.liveBytes -= ptr.len;
    s.liveRecords--;
    if (s.liveBytes < 0) s.liveBytes = 0;
  }

  /// Drops segments with no live bytes. The cheap half of section 6.8.
  int reclaimEmpty() {
    final dead = segments.values
        .where((s) => s.sealed && s.liveRecords <= 0)
        .map((s) => s.id)
        .toList();
    for (final id in dead) {
      segments.remove(id);
    }
    return dead.length;
  }
}

/// A tiny LRU used only to make page-read counting realistic.
class _Lru {
  final Map<int, bool> _m = {};

  /// Returns true on a hit.
  bool touch(int key, int capacity) {
    if (_m.remove(key) != null) {
      _m[key] = true;
      return true;
    }
    _m[key] = true;
    if (_m.length > capacity) {
      _m.remove(_m.keys.first);
    }
    return false;
  }

  void clear() => _m.clear();
}
