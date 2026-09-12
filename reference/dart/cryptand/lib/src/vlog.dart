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
import 'security.dart';

/// `spec/14-security.md` section 5.3 — the ring and the nonce source a
/// value-log record needs. Separate from the page cipher's window only in the
/// sense that it draws from the same allocator: one counter, because two would
/// be two chances to hand the same value out twice.
final class VlogCrypto {
  VlogCrypto(this.ring, this._allocate);

  final KeyRing ring;
  final int Function() _allocate;

  int allocate() => _allocate();
}

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

const List<int> _vlogMagic = [0x43, 0x52, 0x59, 0x5F, 0x56, 0x4C, 0x47, 0x1A];

/// One value-log segment: a page-aligned extent plus the mutable state that
/// section 6.2 puts in tree 7 rather than in the head page.
final class VlogSegment {
  VlogSegment({
    required this.id,
    required this.tier,
    required this.heatClass,
    required this.pageSize,
    required this.capacity,
    this.createdSeq = 0,
  }) : _buf = Uint8List(
            ((dataOffset + capacity + pageSize - 1) ~/ pageSize) * pageSize) {
    _writeHeadPage();
  }

  /// Rebuilds a segment from the extent bytes a file holds, for
  /// `DatabaseFile.open`. The mutable state comes from tree 7, which
  /// section 6.7 makes the authority for it.
  factory VlogSegment.fromExtent(Uint8List extent, int pageSize,
      {required int bytes,
      required int records,
      required bool sealed,
      required bool clustered,
      Uint8List? minKey,
      Uint8List? maxKey,
      required int liveBytes,
      required int liveRecords}) {
    final head = PageHeader.read(extent);
    if (head.pageType != PageType.vlogSegment) {
      throw const CorruptionException('not a value-log head page');
    }
    final r = ByteReader(extent, PageHeader.size, extent.length);
    final magic = r.bytesView(8);
    for (var i = 0; i < 8; i++) {
      if (magic[i] != _vlogMagic[i]) {
        throw const CorruptionException('value-log head page magic mismatch');
      }
    }
    final id = r.u64();
    final createdSeq = r.u64();
    final capacity = r.u64();
    final off = r.u32();
    final tier = r.u8();
    final heat = r.u8();
    if (off != dataOffset) {
      throw CorruptionException('data_offset $off is not $dataOffset');
    }
    final s = VlogSegment._raw(
        id: id,
        tier: tier,
        heatClass: heat,
        pageSize: pageSize,
        capacity: capacity,
        createdSeq: createdSeq,
        buf: extent);
    s.bytes = bytes;
    s.records = records;
    s.sealed = sealed;
    s.clustered = clustered;
    s.minKey = minKey;
    s.maxKey = maxKey;
    s.liveBytes = liveBytes;
    s.liveRecords = liveRecords;
    return s;
  }

  VlogSegment._raw({
    required this.id,
    required this.tier,
    required this.heatClass,
    required this.pageSize,
    required this.capacity,
    required this.createdSeq,
    required Uint8List buf,
  }) : _buf = buf;

  /// Head page header (40) + the 64-byte segment header, rounded up to 8.
  static const int dataOffset = 104;

  final int id;
  final int tier;
  final int heatClass;
  final int pageSize;
  final int capacity;
  final int createdSeq;

  final Uint8List _buf;

  /// The extent as a file holds it: a whole number of pages, head page first.
  Uint8List get extent => _buf;

  /// Tree-7 state, section 6.7. `bytes` is the durable contiguous watermark.
  int bytes = 0;
  int records = 0;
  bool sealed = false;
  bool clustered = false;
  Uint8List? minKey;
  Uint8List? maxKey;
  int liveBytes = 0;
  int liveRecords = 0;

  /// Where a file holds this extent, or 0 when it has never been written.
  /// Keeping it means a re-save reuses the placement rather than appending a
  /// second copy of every segment.
  int startPage = 0;

  Uint8List? _lastKey;
  bool _orderHolds = true;

  int get pageCount => (dataOffset + capacity + pageSize - 1) ~/ pageSize;
  int get remaining => capacity - bytes;

  void _writeHeadPage() {
    // Section 6.2: the head page is written once and never rewritten, so it
    // carries only immutable identity.
    final w = ByteWriter(64)
      ..bytes(_vlogMagic)
      ..u64(id)
      ..u64(createdSeq)
      ..u64(capacity)
      ..u32(dataOffset)
      ..u8(tier)
      ..u8(heatClass)
      ..u8(0) // codec
      ..u8(0) // encrypted
      ..u64(0) // nonce_base
      ..bytes(Uint8List(16));
    _buf.setRange(PageHeader.size, PageHeader.size + w.length, w.view);
    // The head page is a page, so it carries the 40-byte header of
    // `spec/01-container.md` section 3 like every other page. Without it a
    // repair pass that scans the file for `VLOG_SEGMENT` pages
    // (`spec/13-operations.md` section 3) cannot find the segment at all, and
    // section 11's invariant 8b — head page and tree 7 agree on immutable
    // identity — has nothing to check.
    PageHeader(
      pageType: PageType.vlogSegment,
      flags: PageFlags.extentHead,
      treeId: TreeId.noTree,
      extentPages: pageCount,
      payloadLen: 64,
    ).writeInto(_buf);
  }

  /// Appends one record, returning its pointer, or null when full.
  ///
  /// Record framing, section 6.2:
  /// `uvar record_len | u32 tree_id | uvar key_len | key | uvar value_len |
  ///  value | u32 crc32c`.
  /// [crypto] encrypts the record per `spec/14-security.md` section 5.3:
  /// `record_len`, the `counter` and the trailing `crc32c` stay in the clear so
  /// a segment can be walked, and its damage bounded, without the key, while
  /// `key_len || key || value_len || value` is one AEAD message. The counter is
  /// stored per record — "that is the price of being able to decrypt one record
  /// without reading the segment, which is exactly what a point read does".
  VlogPointer? append(int treeId, Uint8List ckeKey, Uint8List value,
      {VlogCrypto? crypto}) {
    if (sealed) {
      throw StateError('cannot append to a sealed value-log segment');
    }
    final ByteWriter body;
    if (crypto == null) {
      body = ByteWriter(value.length + ckeKey.length + 16)
        ..u32(treeId)
        ..uvar(ckeKey.length)
        ..bytes(ckeKey)
        ..uvar(value.length)
        ..bytes(value);
    } else {
      final pt = ByteWriter(value.length + ckeKey.length + 12)
        ..uvar(ckeKey.length)
        ..bytes(ckeKey)
        ..uvar(value.length)
        ..bytes(value);
      final counter = crypto.allocate();
      final r = encryptVlogRecord(
        keys: crypto.ring,
        segmentId: id,
        recordOffset: dataOffset + bytes,
        treeId: treeId,
        nonceCounter: counter,
        body: pt.view,
      );
      body = ByteWriter(r.ciphertext.length + 32)
        ..u64(counter)
        ..u32(treeId)
        ..bytes(r.ciphertext)
        ..bytes(r.tag);
    }
    // Section 5.3: the CRC covers the stored (ciphertext) bytes, and on an
    // encrypted record it starts after the clear counter, so a walker that has
    // no key still bounds the damage.
    final crc = crypto == null
        ? crc32c(body.view)
        : crc32c(body.view, 8, body.length);
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
      VlogPointer ptr, void Function(int pageIndex) pageOf,
      {VlogCrypto? crypto}) {
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
    final crcAt = bodyStart + recordLen - 4;
    final stored = ByteData.view(_buf.buffer).getUint32(crcAt, Endian.little);
    final crcFrom = crypto == null ? bodyStart : bodyStart + 8;
    if (crc32c(_buf, crcFrom, crcAt) != stored) {
      throw CorruptionException('value-log record CRC mismatch at $ptr');
    }
    if (crypto == null) {
      final treeId = r.u32();
      final key = r.bytesCopy(r.uvar());
      final value = r.bytesCopy(r.uvar());
      return (treeId, key, value);
    }
    final counter = r.u64();
    final treeId = r.u32();
    final sealed = Uint8List.sublistView(_buf, r.position, crcAt);
    final pt = decryptVlogRecord(
      keys: crypto.ring,
      segmentId: id,
      recordOffset: ptr.offset,
      treeId: treeId,
      nonceCounter: counter,
      ciphertext: Uint8List.sublistView(sealed, 0, sealed.length - 16),
      tag: Uint8List.sublistView(sealed, sealed.length - 16),
    );
    if (pt == null) {
      throw CorruptionException(
          'value-log record authentication failed at $ptr: this record has '
          'been modified by someone without the key '
          '(spec/14-security.md section 6.2)');
    }
    final pr = ByteReader(pt, 0, pt.length);
    final key = pr.bytesCopy(pr.uvar());
    final value = pr.bytesCopy(pr.uvar());
    return (treeId, key, value);
  }

  /// Iterates every record in order, for garbage collection and verification.
  Iterable<(VlogPointer, int, Uint8List, Uint8List)> scan(
      {VlogCrypto? crypto}) sync* {
    var off = dataOffset;
    final end = dataOffset + bytes;
    while (off < end) {
      final r = ByteReader(_buf, off, end);
      final recordLen = r.uvar();
      final total = (r.position - off) + recordLen;
      final ptr = VlogPointer(id, off, total);
      // The framing walks without the key either way (section 5.3 keeps
      // `record_len`, the counter and the CRC in the clear); only the payload
      // needs one.
      final (treeId, key, value) = read(ptr, (_) {}, crypto: crypto);
      yield (ptr, treeId, key, value);
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

  /// `spec/14-security.md` section 5.3's record cipher. `null` on an
  /// unencrypted database; set by the engine when the ring is installed.
  VlogCrypto? crypto;

  final int segmentBytes;

  /// Pages the reader may hold. Bounded, because an unbounded cache would make
  /// every locality measurement meaningless.
  final int cachePages;

  final Map<int, VlogSegment> segments = {};
  int _nextId = 1;

  int get nextId => _nextId;

  /// Registers a segment rebuilt from a file, for `DatabaseFile.open`.
  /// Everything a file holds is sealed: section 4.3 of `spec/14-security.md`
  /// forbids appending to a segment this session did not open, and a reopen is
  /// by definition a new session.
  void adopt(VlogSegment s) {
    segments[s.id] = s;
    if (s.id >= _nextId) _nextId = s.id + 1;
  }

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
    // An encrypted record carries a clear counter and a Poly1305 tag on top
            // of the framing (section 5.3).
    final need = value.length + ckeKey.length + (crypto == null ? 24 : 48);
    final seg = _segmentFor(tier, heat, need);
    final ptr = seg.append(treeId, ckeKey, value, crypto: crypto);
    if (ptr == null) {
      throw StateError('value-log segment ${seg.id} rejected a sized append');
    }
    totalBytesAppended += ptr.len;
    totalRecordsAppended++;
    if (tier == VlogTier.cold) promotedBytes += ptr.len;
    return ptr;
  }

  /// `spec/10-transactions.md` section 2 step B — a durability barrier over the
  /// bytes appended so far, which for an in-memory buffer is a no-op that
  /// exists so the commit path names the step it is performing.
  ///
  /// It deliberately does **not** seal: see [sealOpen].
  void flushTails() {}

  /// Seals the open **cold** run only.
  ///
  /// Section 6.3 clusters a *generation*: a last-level compaction promotes one
  /// generation into one key-ordered run, so the run has to close when that
  /// compaction ends or the next generation appends into it and the run loses
  /// its ordering. The hot run is untouched — sealing it here retires the
  /// write path's tail on every compaction and manufactures the surplus runs
  /// section 6.9 bounds.
  void sealCold() {
    for (final k in _open.keys.toList()) {
      final seg = _open[k]!;
      if (seg.tier != VlogTier.cold) continue;
      seg.seal(claimClustered: true);
      _open.remove(k);
    }
  }

  /// Seals every open segment. `spec/14-security.md` section 4.3 makes this
  /// mandatory on open; here it is what a close does. **Not** the commit path:
  /// sealing per commit yields one value-log run per commit, which is the
  /// surplus `spec/04-segments.md` section 6.9 bounds.
  void sealOpen() {
    for (final e in _open.entries) {
      e.value.seal(claimClustered: e.value.tier == VlogTier.cold);
    }
    _open.clear();
  }

  /// [coalesce] is the second half of `spec/04-segments.md` section 8.1's MUST
  /// — "MUST coalesce reads of records that fall in the same page". It is
  /// separable from the first half (issuing reads in `(segment, offset)` order)
  /// because the two are worth different things, and only by separating them
  /// can P8's control actually fail.
  ///
  /// It could not before. Over a clustered cold run the entries already arrive
  /// in value order, so sorting a window is a no-op and disabling it changed
  /// nothing: `no readahead` measured exactly the same 0.100 v/row as
  /// `all three on`. A control that cannot fail measures nothing.
  Uint8List readValue(VlogPointer ptr, {bool coalesce = true}) {
    valueReads++;
    final seg = segments[ptr.segmentId];
    if (seg == null) {
      throw CorruptionException('no value-log segment ${ptr.segmentId}');
    }
    final (_, _, value) = seg.read(ptr, (page) {
      if (!coalesce) {
        valuePageReads++;
        return;
      }
      final key = ptr.segmentId * 1000000 + page;
      if (!_cache.touch(key, cachePages)) valuePageReads++;
    }, crypto: crypto);
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
    final total =
        segments.values.fold<int>(0, (a, s) => a + (s.liveRecords > 0 ? s.liveBytes : 0));
    if (total == 0) return 0;
    // **Cold-tier runs only.** A hot run is the write path's tail: it holds
    // everything written since the last last-level compaction, it is
    // unclustered by construction (section 6.3 clusters a generation when it
    // is *promoted*), and neither remedy section 6.9 names can act on it.
    // Counting it made a healthy database with one clustered cold run and a
    // live tail read 40 %, which collecting could not move — a bound whose
    // remedies cannot reach the bytes it counts is not a bound.
    final live = segments.values
        .where((s) => s.liveRecords > 0 && s.tier == VlogTier.cold)
        .toList()
      ..sort((a, b) => b.liveBytes.compareTo(a.liveBytes));
    if (live.isEmpty) return 0;
    final cold = live.fold<int>(0, (a, s) => a + s.liveBytes);
    final ideal =
        ((cold + segmentBytes - 1) ~/ segmentBytes).clamp(1, live.length);
    var surplus = 0;
    for (var i = ideal; i < live.length; i++) {
      surplus += live[i].liveBytes;
    }
    // Bytes in a cold run that is not key-clustered are surplus whatever the
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

  /// Returns a dropped segment's file extent to the page space. Set by the
  /// engine, which owns the store; a log with no file under it has no extents.
  void Function(int startPage, int pages)? freeExtent;

  /// Drops segments with no live bytes. The cheap half of section 6.8.
  int reclaimEmpty() {
    final dead = segments.values
        .where((s) => s.sealed && s.liveRecords <= 0)
        .map((s) => s.id)
        .toList();
    for (final id in dead) {
      final s = segments.remove(id)!;
      // A segment a file placed keeps its extent there, and nothing else
      // frees it: without this the file leaked the whole preallocated extent
      // of every segment collected after a reopen.
      if (s.startPage != 0) freeExtent?.call(s.startPage, s.pageCount);
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
