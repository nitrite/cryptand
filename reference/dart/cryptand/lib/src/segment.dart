/// Segments: immutable, sorted, page-indexed B+trees.
/// `spec/04-segments.md` sections 1, 2 and 8.
///
/// A segment is built **bottom-up from a sorted stream** and written once.
/// There is no insertion path, and therefore no split algorithm, no
/// rebalancing and no in-place page update anywhere in this file — which is
/// what section 2.3 says and what makes two independent implementations
/// produce the same bytes.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'cke.dart';
import 'container.dart';
import 'errors.dart';
import 'filter.dart';
import 'limits.dart';

/// Entry operations, `spec/04-segments.md` section 1.
class Op {
  static const int put = 0;
  static const int delete = 1;
  static const int merge = 2; // reserved
  static const int rangeDelete = 3;
}

/// How a leaf cell carries its value, `spec/04-segments.md` section 2.2.
///
/// The kind occupies the **low nibble** of the cell's `kind_flags` byte; the
/// high nibble carries [kHasExpiry]. Sharing one byte, and omitting
/// `value_len` for the two kinds whose length is always 16, is what brings a
/// separated leaf cell to the 32 bytes `design/performance-model.md` section 1
/// costs the write-amplification argument against.
class ValueKind {
  static const int inline = 0;
  static const int overflow = 1;
  static const int blob = 2;
  static const int empty = 3;
  static const int vlog = 4;

  static const int max = vlog;

  /// True when the value is a fixed 16-byte pointer, so no `value_len` is
  /// written: a length field whose only legal value is 16 is not information,
  /// it is a second place for two implementations to disagree.
  static bool isPointer(int kind) => kind == vlog || kind == blob;
}

/// `kind_flags` bit 4: an `expiry_ms` follows. The rest of the high nibble is
/// reserved and MUST be zero.
const int kHasExpiry = 0x10;

/// Size of a `VLOG` or `BLOB` pointer, `spec/04-segments.md` section 6.4 and
/// `spec/01-container.md` section 5.
const int kPointerBytes = 16;

/// Segment header flags, section 2.1.
class SegFlags {
  static const int hasRangeDeletes = 0x01;
  static const int singleTree = 0x02;
  static const int hasTtl = 0x04;
}

/// B+tree page flags, section 2.2.
class NodeFlags {
  static const int isLeaf = 0x01;
}

const int _u64Mask = -1; // all ones

/// Builds an internal key: `u32be(tree_id) || CKE(key) || u64be(seq XOR ~0) ||
/// u8(op)`.
///
/// `tree_id` leads and is big-endian so a tree's entries form one contiguous
/// range of the global key space. `seq` is inverted so the **newest** version
/// of a key sorts **first**, which is what lets a read seek the key and walk
/// forward to the first entry at or below its snapshot.
Uint8List internalKey(int treeId, Uint8List ckeKey, int seq, int op) {
  final out = Uint8List(4 + ckeKey.length + 9);
  out[0] = (treeId >>> 24) & 0xFF;
  out[1] = (treeId >>> 16) & 0xFF;
  out[2] = (treeId >>> 8) & 0xFF;
  out[3] = treeId & 0xFF;
  out.setRange(4, 4 + ckeKey.length, ckeKey);
  final inv = seq ^ _u64Mask;
  var p = 4 + ckeKey.length;
  for (var s = 56; s >= 0; s -= 8) {
    out[p++] = (inv >>> s) & 0xFF;
  }
  out[p] = op;
  return out;
}

/// The `(tree_id, CKE(key))` prefix of an internal key: what a segment filter
/// is built over (section 2.4) and what a point read seeks to.
Uint8List userKeyPrefix(int treeId, Uint8List ckeKey) {
  final out = Uint8List(4 + ckeKey.length);
  out[0] = (treeId >>> 24) & 0xFF;
  out[1] = (treeId >>> 16) & 0xFF;
  out[2] = (treeId >>> 8) & 0xFF;
  out[3] = treeId & 0xFF;
  out.setRange(4, out.length, ckeKey);
  return out;
}

/// Splits an internal key back into its parts.
({int treeId, Uint8List cke, int seq, int op}) parseInternalKey(Uint8List ik) {
  if (ik.length < 13) {
    throw const CorruptionException('internal key shorter than 13 bytes');
  }
  final treeId = (ik[0] << 24) | (ik[1] << 16) | (ik[2] << 8) | ik[3];
  final ckeEnd = ik.length - 9;
  var inv = 0;
  for (var i = ckeEnd; i < ckeEnd + 8; i++) {
    inv = (inv << 8) | ik[i];
  }
  return (
    treeId: treeId,
    cke: Uint8List.sublistView(ik, 4, ckeEnd),
    seq: inv ^ _u64Mask,
    op: ik[ik.length - 1],
  );
}

/// One entry handed to [SegmentBuilder].
final class SegEntry {
  SegEntry(this.internalKey, this.valueKind, this.value, {this.expiryMs});
  final Uint8List internalKey;
  final int valueKind;
  final Uint8List value;
  final int? expiryMs;
}

/// The shortest byte string that separates [prev] from [next].
///
/// Section 2.2: "A writer SHOULD truncate separators to the shortest string
/// that still separates the neighbouring subtrees." Every returned separator
/// satisfies `prev < sep <= next`, which is what the descent needs.
Uint8List shortestSeparator(Uint8List? prev, Uint8List next) {
  // The first child of a page has no left neighbour, so the empty string --
  // which is below every key -- is the correct separator.
  if (prev == null || next.isEmpty) return Uint8List(0);
  final n = prev.length < next.length ? prev.length : next.length;
  for (var i = 0; i < n; i++) {
    if (prev[i] != next[i]) {
      return Uint8List.fromList(Uint8List.sublistView(next, 0, i + 1));
    }
  }
  // prev is a prefix of next; keep one byte more than prev.
  if (prev.length >= next.length) return Uint8List.fromList(next);
  return Uint8List.fromList(Uint8List.sublistView(next, 0, prev.length + 1));
}

int _commonPrefix(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  var i = 0;
  while (i < n && a[i] == b[i]) {
    i++;
  }
  return i;
}

int _uvarLen(int v) {
  var n = 1;
  var x = v >>> 7;
  while (x != 0) {
    n++;
    x >>>= 7;
  }
  return n;
}


/// The shared prefix of a page's keys, which the page stores once.
int _pagePrefix(List<Uint8List> keys) {
  if (keys.isEmpty) return 0;
  var n = keys.first.length;
  for (var i = 1; i < keys.length && n > 0; i++) {
    final c = _commonPrefix(keys.first, keys[i]);
    if (c < n) n = c;
  }
  return n;
}

/// Exact encoded size of a B+tree page holding [keys] and [payloads],
/// including the 40-byte page header. `spec/04-segments.md` §2.2.
///
/// Exact, not an upper bound: the copy-on-write trees of §3.3 decide splits by
/// this number, and an approximation there either wastes space or overflows a
/// page after the split decision has already been taken.
int nodePageBytes(List<Uint8List> keys, List<Uint8List> payloads) {
  final prefixLen = _pagePrefix(keys);
  var n = PageHeader.size + 16 + prefixLen + 2 * keys.length;
  for (var i = 0; i < keys.length; i++) {
    final suffixLen = keys[i].length - prefixLen;
    n += _uvarLen(suffixLen) + suffixLen + payloads[i].length;
  }
  return n;
}

/// Serializes one B+tree page, `spec/04-segments.md` §2.2.
///
/// One encoder for both users of the format: [SegmentBuilder], which writes
/// pages into an immutable extent, and the copy-on-write trees of §3.3, which
/// write them one at a time into the page space. Two encoders would be two
/// places for the same bytes to drift, and §2.2 is a format the conformance
/// vectors pin.
Uint8List encodeNodePage({
  required int pageSize,
  required bool isLeaf,
  /// `spec/14-security.md` section 5.2's AEAD tag, reserved before a single
  /// cell is placed: a page filled to `page_size - 40` has nowhere left to put
  /// one, and discovering that at write time means a page that cannot be
  /// written at all. Defaults to the whole payload, which is the unencrypted
  /// case and every conformance vector.
  int? payloadSize,
  required List<Uint8List> keys,
  required List<Uint8List> payloads,
  required int subtreeEntries,
  int treeId = TreeId.noTree,
  int commitId = 0,
}) {
  checkPageSize(pageSize);
  final page = Uint8List(pageSize);
  final bd = ByteData.view(page.buffer);
  final base = PageHeader.size;
  payloadSize ??= pageSize - base;
  if (payloadSize > pageSize - base) {
    throw const InvalidArgumentException('payloadSize exceeds the page');
  }
  final count = keys.length;
  final prefixLen = _pagePrefix(keys);

  // Cells grow downward from the payload end; cell_ptr[] grows up.
  var cellTop = payloadSize;
  final ptrs = List<int>.filled(count, 0);
  for (var i = count - 1; i >= 0; i--) {
    final k = keys[i];
    final suffixLen = k.length - prefixLen;
    final cellSize = _uvarLen(suffixLen) + suffixLen + payloads[i].length;
    cellTop -= cellSize;
    ptrs[i] = cellTop;
    final w = ByteWriter(cellSize)
      ..uvar(suffixLen)
      ..bytes(Uint8List.sublistView(k, prefixLen))
      ..bytes(payloads[i]);
    page.setRange(base + cellTop, base + cellTop + cellSize, w.view);
  }

  final freeStart = 16 + prefixLen + 2 * count;
  if (freeStart > cellTop) {
    throw StateError(
        'page overflow: header+pointers $freeStart, cells at $cellTop');
  }
  bd
    ..setUint16(base + 0, count, Endian.little)
    ..setUint16(base + 2, freeStart, Endian.little)
    ..setUint16(base + 4, prefixLen, Endian.little)
    ..setUint16(base + 6, isLeaf ? NodeFlags.isLeaf : 0, Endian.little)
    ..setUint64(base + 8, subtreeEntries, Endian.little);
  if (prefixLen > 0) {
    page.setRange(base + 16, base + 16 + prefixLen,
        Uint8List.sublistView(keys.first, 0, prefixLen));
  }
  for (var i = 0; i < count; i++) {
    bd.setUint16(base + 16 + prefixLen + i * 2, ptrs[i], Endian.little);
  }

  PageHeader(
    pageType: isLeaf ? PageType.btreeLeaf : PageType.btreeInternal,
    treeId: treeId,
    commitId: commitId,
    payloadLen: payloadSize,
  ).writeInto(page);
  return page;
}

/// A page under construction.
class _PendingPage {
  _PendingPage(this.isLeaf);
  final bool isLeaf;
  final List<Uint8List> keys = [];
  final List<Uint8List> payloads = [];
  int prefixLen = -1; // -1 until the first key arrives
  int sumKeyLen = 0;
  int sumPayloadLen = 0;
  int subtreeEntries = 0;

  /// The **real** least and greatest internal keys reachable through this
  /// page, as opposed to the separators stored in it.
  ///
  /// These are what a parent's separator must be computed against. An earlier
  /// version truncated a page's separator against the previous page's last
  /// *separator*, which is far below that page's true maximum -- so at height
  /// three, where every page's first separator is the empty string, later
  /// pages claimed an empty lower bound and small keys descended into them.
  /// The descent then missed keys that were physically present.
  Uint8List? minReal;
  Uint8List? maxReal;

  int get count => keys.length;

  /// Exact encoded size of this page's payload, given the current prefix.
  int sizeWith(int extraKeyLen, int extraPayloadLen, int newPrefixLen) {
    final n = count + (extraKeyLen >= 0 ? 1 : 0);
    if (n == 0) return 16;
    final totalKey = sumKeyLen + (extraKeyLen >= 0 ? extraKeyLen : 0);
    final totalPayload =
        sumPayloadLen + (extraPayloadLen >= 0 ? extraPayloadLen : 0);
    final suffixBytes = totalKey - n * newPrefixLen;
    // Worst-case uvar for suffix_len; keys are capped at 4 KiB so it is 1-2
    // bytes, and using the bound keeps the fill decision O(1).
    final lenBytes = n * 2;
    return 16 + newPrefixLen + n * 2 + suffixBytes + lenBytes + totalPayload;
  }
}

/// Bulk-builds one segment extent from a sorted stream of entries.
final class SegmentBuilder {
  SegmentBuilder({
    required this.pageSize,
    required this.segmentId,
    this.level = 0,
    this.group = 0,
    this.treeId,
    this.filterBitsPerKey = 0,
    this.tagReserve = 0,
  }) {
    checkPageSize(pageSize);
    _payloadSize = pageSize - PageHeader.size - tagReserve;
  }

  final int pageSize;

  /// `spec/14-security.md` section 5.2's AEAD tag: 16 on an encrypted
  /// database, 0 otherwise. Subtracted from every page's usable payload.
  final int tagReserve;

  final int segmentId;
  final int level;
  final int group;

  /// When set, every entry belongs to this tree and `SINGLE_TREE` is flagged.
  final int? treeId;

  /// §2.4's filter bit rate, or 0 for no filter.
  ///
  /// **Set per level, not globally**: 16 above the last level, 10 at it. The
  /// upper levels hold little data, so a high rate there is nearly free and it
  /// is what bounds the read tail (§4.1). Zero writes `filter_page = 0`, which
  /// a reader MUST read as "treat every probe as a hit".
  final int filterBitsPerKey;

  late final int _payloadSize;

  final List<Uint8List> _pages = []; // page 0 reserved for the header
  _PendingPage? _leaf;

  /// Leaves are level 0; internal levels are 1 and above.
  ///
  /// Per level: the page currently filling, the last key of the page most
  /// recently *emitted* at that level (which is what the next page's
  /// separator is truncated against), and how many pages that level has
  /// emitted.
  final Map<int, _PendingPage> _pending = {};
  final Map<int, Uint8List> _prevLast = {};
  final Map<int, int> _emitted = {};
  int _maxLevel = 0;

  Uint8List? _minKey;
  Uint8List? _maxKey;
  Uint8List? _prevKey;
  int _entryCount = 0;
  int _tombstones = 0;
  int _minSeq = -1;
  int _maxSeq = 0;
  int _valueBytes = 0;
  int _vlogBytes = 0;
  int _minExpiry = 0;
  int _flags = 0;
  final Map<int, int> _treeSpan = {};

  /// Distinct **user** keys, `u32be(tree_id) || CKE(key)`, for the filter.
  /// §2.4: all versions of a key share one entry, so `entry_count` from the
  /// header — which counts versions — is the wrong number for `block_count`.
  final List<Uint8List> _userKeys = [];

  int get entryCount => _entryCount;

  /// Appends one entry. Keys MUST arrive strictly increasing.
  void add(SegEntry e) {
    final k = e.internalKey;
    if (k.length > kMaxKeyBytesAbsolute || k.length > pageSize ~/ 4 + 13) {
      throw LimitException('internal key of ${k.length} B exceeds the limit '
          'for page_size $pageSize');
    }
    final prev = _prevKey;
    if (prev != null && compareKeys(prev, k) >= 0) {
      // Bulk construction is the only construction: an out-of-order entry is
      // a caller bug, not something to sort around.
      throw const InvalidArgumentException(
          'SegmentBuilder.add requires strictly increasing internal keys');
    }
    if (filterBitsPerKey > 0) {
      final u = Uint8List.sublistView(k, 0, k.length - 9);
      if (_userKeys.isEmpty || compareKeys(_userKeys.last, u) != 0) {
        _userKeys.add(Uint8List.fromList(u));
      }
    }
    _prevKey = k;
    _minKey ??= Uint8List.fromList(k);
    _maxKey = Uint8List.fromList(k);

    final parsed = parseInternalKey(k);
    _treeSpan[parsed.treeId] = (_treeSpan[parsed.treeId] ?? 0) + 1;
    if (_minSeq < 0 || parsed.seq < _minSeq) _minSeq = parsed.seq;
    if (parsed.seq > _maxSeq) _maxSeq = parsed.seq;
    if (parsed.op == Op.delete) _tombstones++;
    if (parsed.op == Op.rangeDelete) _flags |= SegFlags.hasRangeDeletes;
    if (e.valueKind == ValueKind.inline) _valueBytes += e.value.length;
    if (e.valueKind == ValueKind.vlog) _vlogBytes += e.value.length;
    if (e.expiryMs != null) {
      _flags |= SegFlags.hasTtl;
      if (_minExpiry == 0 || e.expiryMs! < _minExpiry) _minExpiry = e.expiryMs!;
    }
    _entryCount++;

    final payload = _leafCellPayload(e);
    var leaf = _leaf;
    if (leaf == null) {
      leaf = _leaf = _PendingPage(true);
      _pushInto(leaf, k, payload);
      leaf.minReal ??= k;
      leaf.maxReal = k;
      return;
    }
    final newPrefix = _commonPrefix(leaf.keys.first, k);
    if (leaf.sizeWith(k.length, payload.length, newPrefix) > _payloadSize) {
      _flushLeaf();
      leaf = _leaf = _PendingPage(true);
    }
    final target = _leaf!;
    _pushInto(target, k, payload);
    target.minReal ??= k;
    target.maxReal = k;
  }

  void _pushInto(_PendingPage p, Uint8List k, Uint8List payload) {
    p.prefixLen =
        p.keys.isEmpty ? k.length : _commonPrefix(p.keys.first, k);
    p.keys.add(k);
    p.payloads.add(payload);
    p.sumKeyLen += k.length;
    p.sumPayloadLen += payload.length;
    if (p.isLeaf) p.subtreeEntries++;
  }

  Uint8List _leafCellPayload(SegEntry e) {
    if (e.valueKind < 0 || e.valueKind > ValueKind.max) {
      throw InvalidArgumentException('value_kind ${e.valueKind} is not 0..4');
    }
    final w = ByteWriter(e.value.length + 12);
    var kindFlags = e.valueKind;
    if (e.expiryMs != null) kindFlags |= kHasExpiry;
    w.u8(kindFlags);
    if (e.expiryMs != null) w.u64(e.expiryMs!);

    final op = e.internalKey[e.internalKey.length - 1];
    // Section 2.2: nothing follows for EMPTY, or when op == DELETE.
    if (e.valueKind == ValueKind.empty || op == Op.delete) return w.takeBytes();

    if (ValueKind.isPointer(e.valueKind)) {
      if (e.value.length != kPointerBytes) {
        throw InvalidArgumentException(
            'a VLOG or BLOB value is exactly $kPointerBytes bytes, '
            'got ${e.value.length}');
      }
      w.bytes(e.value); // no value_len: the width is fixed
    } else {
      w
        ..uvar(e.value.length)
        ..bytes(e.value);
    }
    return w.takeBytes();
  }

  void _flushLeaf() {
    final leaf = _leaf;
    if (leaf == null || leaf.count == 0) return;
    _leaf = null;
    _emitAndRoute(0, leaf);
  }

  /// Writes [p] out and hands a child pointer to the level above.
  ///
  /// The separator is truncated against the previous page's **true maximum
  /// key**, and the page's true minimum is what the separator must not
  /// exceed. Both come from [_PendingPage.minReal] / [_PendingPage.maxReal],
  /// not from the separators the page happens to store.
  void _emitAndRoute(int level, _PendingPage p) {
    final pageIndex = _emitPage(p);
    final min = p.minReal!;
    final max = p.maxReal!;
    final sep = shortestSeparator(_prevLast[level], min);
    _prevLast[level] = max;
    _emitted[level] = (_emitted[level] ?? 0) + 1;
    _addChild(level + 1, sep, pageIndex, p.subtreeEntries, min, max);
  }

  /// Adds one child pointer to the internal page at [level], emitting that
  /// page first when it is full.
  void _addChild(int level, Uint8List sep, int childPage, int childEntries,
      Uint8List childMin, Uint8List childMax) {
    if (level > _maxLevel) _maxLevel = level;
    final payload = (ByteWriter(20)
          ..u64(childPage)
          ..u64(childEntries))
        .takeBytes();

    var page = _pending[level];
    if (page != null) {
      final newPrefix = _commonPrefix(page.keys.first, sep);
      if (page.sizeWith(sep.length, payload.length, newPrefix) > _payloadSize) {
        _pending.remove(level);
        _emitAndRoute(level, page); // may recurse further up
        page = null;
      }
    }
    page ??= (_pending[level] = _PendingPage(false));
    if (page.keys.isEmpty) {
      // The first child of a fresh page: its separator was truncated against
      // the previous page at this level, so recompute it now that we know it
      // starts a page.
      final fresh = shortestSeparator(_prevLast[level], childMin);
      _pushInto(page, fresh, payload);
    } else {
      _pushInto(page, sep, payload);
    }
    page.minReal ??= childMin;
    page.maxReal = childMax;
    page.subtreeEntries += childEntries;
  }

  /// Serializes one page and returns its index within the extent.
  int _emitPage(_PendingPage p) {
    _pages.add(encodeNodePage(
      pageSize: pageSize,
      payloadSize: _payloadSize,
      isLeaf: p.isLeaf,
      keys: p.keys,
      payloads: p.payloads,
      subtreeEntries: p.subtreeEntries,
    ));
    return _pages.length; // page 0 is the segment header
  }

  /// Finishes the segment and returns the complete extent.
  ///
  /// Drains the internal levels bottom-up. A level that has emitted no page
  /// and has nothing above it is the top; if its single pending page holds
  /// exactly one child, that page is a chain of one and its child is already
  /// a valid root, so it is dropped rather than written. Without that
  /// collapse a one-entry segment would carry a pointless internal page.
  Uint8List build() {
    _flushLeaf();
    if (_pages.isEmpty) {
      throw const InvalidArgumentException('an empty segment has no root');
    }

    var rootPage = _pages.length;
    var rootEntries = _entryCount;

    var level = 1;
    while (level <= _maxLevel || _pending.isNotEmpty) {
      final p = _pending.remove(level);
      if (p == null) {
        if (level > _maxLevel) break;
        level++;
        continue;
      }
      final prior = _emitted[level] ?? 0;
      final anythingAbove = _pending.keys.any((l) => l > level);
      if (prior == 0 && !anythingAbove) {
        if (p.count == 1) {
          final r = ByteReader(p.payloads[0]);
          rootPage = r.u64();
          rootEntries = r.u64();
        } else {
          rootEntries = p.subtreeEntries;
          rootPage = _emitPage(p);
        }
        break;
      }
      _emitAndRoute(level, p);
      rootPage = _pages.length;
      rootEntries = p.subtreeEntries;
      level++;
    }

    final filterPage = _emitFilter();
    final header = _buildHeader(rootPage, rootEntries, filterPage);
    final out = Uint8List(pageSize * (_pages.length + 1))
      ..setRange(0, pageSize, header);
    for (var i = 0; i < _pages.length; i++) {
      out.setRange(pageSize * (i + 1), pageSize * (i + 2), _pages[i]);
    }
    return out;
  }

  /// Appends the filter's pages to the extent and returns the index of the
  /// first, or 0 when there is no filter.
  int _emitFilter() {
    if (filterBitsPerKey <= 0 || _userKeys.isEmpty) return 0;
    final payload = BlockedBloom.build(_userKeys,
            bitsPerKey: filterBitsPerKey, distinctKeys: _userKeys.length)
        .encodePayload();
    final first = _pages.length + 1;
    final capacity = _payloadSize;
    for (var off = 0; off < payload.length; off += capacity) {
      final n = (payload.length - off).clamp(0, capacity);
      final page = Uint8List(pageSize)
        ..setRange(PageHeader.size, PageHeader.size + n, payload, off);
      PageHeader(
        pageType: PageType.segmentFilter,
        treeId: TreeId.noTree,
        payloadLen: n,
      ).writeInto(page);
      _pages.add(page);
    }
    return first;
  }

  Uint8List _buildHeader(int rootPage, int rootEntries, int filterPage) {
    final page = Uint8List(pageSize);
    final base = PageHeader.size;
    final w = ByteWriter(256)
      ..bytes(const [0x43, 0x52, 0x59, 0x5F, 0x53, 0x45, 0x47, 0x1A])
      ..u64(segmentId)
      ..u8(level)
      ..u8(treeId != null ? _flags | SegFlags.singleTree : _flags)
      ..u16(filterBitsPerKey)
      ..u32(_treeSpan.length)
      ..u64(rootPage)
      ..u64(_entryCount)
      ..u64(_tombstones)
      ..u64(_minSeq < 0 ? 0 : _minSeq)
      ..u64(_maxSeq)
      ..u64(filterPage)
      ..u64(_valueBytes)
      ..u64(_vlogBytes)
      ..u64(_minExpiry)
      ..u8(group)
      ..bytes(Uint8List(7)); // reserved
    // min_key / max_key are BOUNDS: section 2.1 permits shortening them, and
    // the whole header MUST fit the head page.
    var minKey = _minKey ?? Uint8List(0);
    var maxKey = _maxKey ?? Uint8List(0);
    final budget = _payloadSize - w.length - 8 - _treeSpan.length * 12 - 8;
    if (minKey.length + maxKey.length > budget) {
      // Widen the bounds by truncating: a shorter min_key is <= every key, and
      // a max_key extended with 0xFF is >= every key.
      final half = budget ~/ 2;
      minKey = Uint8List.sublistView(minKey, 0, half.clamp(0, minKey.length));
      final keep = (budget - minKey.length - 1).clamp(0, maxKey.length);
      final t = Uint8List(keep + 1)
        ..setRange(0, keep, Uint8List.sublistView(maxKey, 0, keep));
      t[keep] = 0xFF;
      maxKey = t;
    }
    w
      ..u32(minKey.length)
      ..u32(maxKey.length)
      ..bytes(minKey)
      ..bytes(maxKey);
    for (final e in _treeSpan.entries) {
      w
        ..u32(e.key)
        ..u64(e.value);
    }
    if (base + w.length > pageSize) {
      throw StateError('segment header does not fit its page');
    }
    page.setRange(base, base + w.length, w.view);
    PageHeader(
      pageType: PageType.segmentHeader,
      flags: PageFlags.extentHead,
      treeId: TreeId.noTree,
      extentPages: _pages.length + 1,
      payloadLen: w.length,
    ).writeInto(page);
    return page;
  }
}


// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// One decoded leaf entry.
final class SegRecord {
  const SegRecord(this.internalKey, this.valueKind, this.value, this.expiryMs);
  final Uint8List internalKey;
  final int valueKind;
  final Uint8List value;
  final int? expiryMs;

  int get op => internalKey[internalKey.length - 1];

  /// Read straight out of the key: [parseInternalKey] built a record and a
  /// view to hand back one field, and a point read asks for it per candidate.
  int get seq {
    final ik = internalKey;
    if (ik.length < 13) {
      throw const CorruptionException('internal key shorter than 13 bytes');
    }
    var inv = 0;
    for (var i = ik.length - 9; i < ik.length - 1; i++) {
      inv = (inv << 8) | ik[i];
    }
    return inv ^ _u64Mask;
  }
}

/// A parsed B+tree page inside a segment.
final class Node {
  Node(this.page, this.pageIndex) {
    final base = PageHeader.size;
    final bd = ByteData.view(page.buffer, page.offsetInBytes, page.length);
    cellCount = bd.getUint16(base + 0, Endian.little);
    _freeStart = bd.getUint16(base + 2, Endian.little);
    prefixLen = bd.getUint16(base + 4, Endian.little);
    final flags = bd.getUint16(base + 6, Endian.little);
    isLeaf = flags & NodeFlags.isLeaf != 0;
    subtreeEntries = bd.getUint64(base + 8, Endian.little);
    if (16 + prefixLen + cellCount * 2 > page.length - base) {
      throw CorruptionException(
          'page $pageIndex: cell pointers overrun the payload');
    }
    _ptrBase = base + 16 + prefixLen;
    _base = base;
    _bd = bd;
  }

  final Uint8List page;
  final int pageIndex;
  late final int cellCount;
  late final int _freeStart;
  late final int prefixLen;
  late final bool isLeaf;
  late final int subtreeEntries;
  late final int _ptrBase;
  late final int _base;
  late final ByteData _bd;

  int get freeStart => _freeStart;

  Uint8List get prefix =>
      Uint8List.sublistView(page, _base + 16, _base + 16 + prefixLen);

  int _cellOffset(int i) {
    if (i < 0 || i >= cellCount) {
      throw CorruptionException('page $pageIndex: cell $i out of range');
    }
    final off = _bd.getUint16(_ptrBase + i * 2, Endian.little);
    if (_base + off >= page.length) {
      throw CorruptionException('page $pageIndex: cell $i points past the page');
    }
    return _base + off;
  }

  /// The full key of cell [i], with the page prefix restored.
  Uint8List keyAt(int i) {
    final r = ByteReader(page, _cellOffset(i), page.length);
    final suffixLen = r.uvar();
    if (suffixLen > page.length) {
      throw CorruptionException('page $pageIndex: cell $i suffix too long');
    }
    final out = Uint8List(prefixLen + suffixLen);
    if (prefixLen > 0) {
      out.setRange(0, prefixLen, page, _base + 16);
    }
    final suffix = r.bytesView(suffixLen);
    out.setRange(prefixLen, out.length, suffix);
    return out;
  }

  /// How **every** key on this page compares to [target] on the shared prefix
  /// alone, or 0 when the prefix matches and only the suffixes can decide.
  ///
  /// Every key in a node begins with the same `prefixLen` bytes (§2.2), so this
  /// answer does not depend on the cell and does not belong inside a binary
  /// search. It was inside both of them, re-compared on each of the ~20 probes
  /// a point read makes.
  int prefixCompare(Uint8List target) {
    final n = prefixLen < target.length ? prefixLen : target.length;
    final at = _base + 16;
    for (var j = 0; j < n; j++) {
      final d = page[at + j] - target[j];
      if (d != 0) return d < 0 ? -1 : 1;
    }
    // The target ran out inside the shared prefix: every key sorts after it.
    if (target.length < prefixLen) return 1;
    return 0;
  }

  /// Cell [i]'s key against [target], given that [prefixCompare] returned 0.
  ///
  /// The suffix is compared **straight out of the page**: this used to build a
  /// [ByteReader] and a `Uint8List` view per probe, two allocations for a
  /// comparison of about twenty bytes.
  int compareSuffix(int i, Uint8List target) {
    // `_cellOffset` inlined: it is two bounds tests and a `getUint16`, and at
    // one call per probe of every binary search it was 8 % of the read profile
    // on its own.
    if (i < 0 || i >= cellCount) {
      throw CorruptionException('page $pageIndex: cell $i out of range');
    }
    final off = _base + _bd.getUint16(_ptrBase + i * 2, Endian.little);
    if (off >= page.length) {
      throw CorruptionException('page $pageIndex: cell $i points past the page');
    }
    // Fast path: a suffix under 128 bytes has a one-byte length, which is
    // every cell this format produces.
    final b0 = page[off];
    int suffixLen;
    int at;
    if (b0 < 0x80) {
      suffixLen = b0;
      at = off + 1;
    } else {
      final r = ByteReader(page, off, page.length);
      suffixLen = r.uvar();
      at = r.position;
    }
    if (at + suffixLen > page.length) {
      throw CorruptionException(
          'page $pageIndex: cell $i suffix runs past the page');
    }
    final rest = target.length - prefixLen;
    final m = suffixLen < rest ? suffixLen : rest;
    for (var j = 0; j < m; j++) {
      final d = page[at + j] - target[prefixLen + j];
      if (d != 0) return d < 0 ? -1 : 1;
    }
    return suffixLen == rest ? 0 : (suffixLen < rest ? -1 : 1);
  }

  /// The length of cell [i]'s key, without building it.
  int keyLen(int i) {
    final off = _cellOffset(i);
    final b0 = page[off];
    if (b0 < 0x80) return prefixLen + b0;
    final r = ByteReader(page, off, page.length);
    return prefixLen + r.uvar();
  }

  /// Whether cell [i]'s key begins with [p], without building it.
  ///
  /// A point read tests this once per candidate segment, and it used to do it
  /// by materializing the whole key -- an allocation and two copies -- and then
  /// materializing it a second time inside [recordAt] for the record it
  /// returned.
  bool keyHasPrefix(int i, Uint8List p) {
    final n = prefixLen < p.length ? prefixLen : p.length;
    final at = _base + 16;
    for (var j = 0; j < n; j++) {
      if (page[at + j] != p[j]) return false;
    }
    if (p.length <= prefixLen) return true;
    final off = _cellOffset(i);
    final b0 = page[off];
    int suffixLen;
    int sat;
    if (b0 < 0x80) {
      suffixLen = b0;
      sat = off + 1;
    } else {
      final r = ByteReader(page, off, page.length);
      suffixLen = r.uvar();
      sat = r.position;
    }
    final rest = p.length - prefixLen;
    if (suffixLen < rest) return false;
    if (sat + rest > page.length) {
      throw CorruptionException(
          'page $pageIndex: cell $i suffix runs past the page');
    }
    for (var j = 0; j < rest; j++) {
      if (page[sat + j] != p[prefixLen + j]) return false;
    }
    return true;
  }

  /// The `seq` in cell [i]'s key -- the eight bytes before the trailing `op`
  /// (§1), stored inverted -- read in place.
  int seqAt(int i) {
    final off = _cellOffset(i);
    final b0 = page[off];
    int suffixLen;
    int sat;
    if (b0 < 0x80) {
      suffixLen = b0;
      sat = off + 1;
    } else {
      final r = ByteReader(page, off, page.length);
      suffixLen = r.uvar();
      sat = r.position;
    }
    final total = prefixLen + suffixLen;
    if (total < 9) {
      throw CorruptionException(
          'page $pageIndex: cell $i key is shorter than 9 bytes');
    }
    var inv = 0;
    final start = total - 9;
    for (var j = 0; j < 8; j++) {
      final at = start + j;
      final b = at < prefixLen ? page[_base + 16 + at] : page[sat + at - prefixLen];
      inv = (inv << 8) | b;
    }
    return ~inv;
  }

  /// Compares the search key against cell [i] without materializing the key.
  int compareCell(int i, Uint8List target) {
    final pc = prefixCompare(target);
    return pc != 0 ? pc : compareSuffix(i, target);
  }

  /// A reader positioned at the start of cell [i]'s payload.
  ///
  /// A segment leaf decodes this as [recordAt] does; a copy-on-write tree
  /// (§3.3) decodes it itself, because its keys are user keys with no trailing
  /// `op` byte and [recordAt]'s `op == DELETE` test would misread one.
  ByteReader payloadAt(int i) {
    final r = ByteReader(page, _cellOffset(i), page.length);
    final suffixLen = r.uvar();
    r.position = r.position + suffixLen;
    return r;
  }

  /// `(child_page, child_subtree_entries)` of internal cell [i].
  (int, int) childAt(int i) {
    final r = ByteReader(page, _cellOffset(i), page.length);
    final suffixLen = r.uvar();
    r.position = r.position + suffixLen;
    return (r.u64(), r.u64());
  }

  /// Whether cell [i]'s key is exactly `prefix || u64be(~seq) || op` -- one
  /// version of the user key [prefix] -- in one pass over the cell, where
  /// [keyLen] and [keyHasPrefix] each decoded the pointer and the length.
  bool isVersionOf(int i, Uint8List prefix) {
    final off = _cellOffset(i);
    final b0 = page[off];
    if (b0 >= 0x80) return keyLen(i) == prefix.length + 9 && keyHasPrefix(i, prefix);
    if (prefixLen + b0 != prefix.length + 9) return false;
    final n = prefixLen < prefix.length ? prefixLen : prefix.length;
    final at = _base + 16;
    for (var j = 0; j < n; j++) {
      if (page[at + j] != prefix[j]) return false;
    }
    final sat = off + 1;
    if (sat + b0 > page.length) {
      throw CorruptionException('page $pageIndex: cell $i suffix runs past the page');
    }
    for (var j = prefixLen; j < prefix.length; j++) {
      if (page[sat + j - prefixLen] != prefix[j]) return false;
    }
    return true;
  }

  /// [recordAt] of cell [i] when its key is a version of [prefix] -- as
  /// [isVersionOf] decides -- and null otherwise, in one pass over the cell.
  ///
  /// The point read's hot path. The two calls it replaces decoded the cell
  /// pointer twice and built a [ByteReader], whose `ByteData` view is an
  /// allocation, per read. Encodings off the common path -- a suffix or value
  /// length of three or more uvar bytes -- are left to those two, which
  /// validate them.
  SegRecord? recordIfVersionOf(int i, Uint8List prefix) {
    final off = _cellOffset(i);
    final suffixLen = page[off];
    if (suffixLen >= 0x80) return isVersionOf(i, prefix) ? recordAt(i) : null;
    final keyLen = prefixLen + suffixLen;
    if (keyLen != prefix.length + 9) return null;
    final sat = off + 1;
    var p = sat + suffixLen;
    if (p >= page.length) {
      throw CorruptionException('page $pageIndex: cell $i suffix runs past the page');
    }
    final n = prefixLen < prefix.length ? prefixLen : prefix.length;
    final pat = _base + 16;
    for (var j = 0; j < n; j++) {
      if (page[pat + j] != prefix[j]) return null;
    }
    for (var j = prefixLen; j < prefix.length; j++) {
      if (page[sat + j - prefixLen] != prefix[j]) return null;
    }
    final key = Uint8List(keyLen);
    if (prefixLen > 0) key.setRange(0, prefixLen, page, pat);
    key.setRange(prefixLen, keyLen, page, sat);

    final kindFlags = page[p++];
    final valueKind = kindFlags & 0x0F;
    if (valueKind > ValueKind.max || kindFlags & 0xE0 != 0) return recordAt(i);
    int? expiry;
    if (kindFlags & kHasExpiry != 0) {
      if (p + 8 > page.length) return recordAt(i);
      expiry = _bd.getUint64(p, Endian.little);
      p += 8;
    }
    var value = Uint8List(0);
    if (valueKind != ValueKind.empty && key[keyLen - 1] != Op.delete) {
      int len;
      if (ValueKind.isPointer(valueKind)) {
        len = kPointerBytes;
      } else {
        if (p + 2 > page.length) return recordAt(i);
        final b0 = page[p];
        if (b0 < 0x80) {
          len = b0;
          p += 1;
        } else {
          final b1 = page[p + 1];
          // Two bytes, canonical (a zero final byte is not); anything else
          // goes the general way.
          if (b1 >= 0x80 || b1 == 0) return recordAt(i);
          len = (b0 & 0x7F) | (b1 << 7);
          p += 2;
        }
      }
      if (p + len > page.length) return recordAt(i);
      value = Uint8List.sublistView(page, p, p + len);
    }
    return SegRecord(key, valueKind, value, expiry);
  }

  SegRecord recordAt(int i) {
    final r = ByteReader(page, _cellOffset(i), page.length);
    final suffixLen = r.uvar();
    if (suffixLen > page.length) {
      throw CorruptionException('page $pageIndex: cell $i suffix too long');
    }
    // The key is built from the page directly: [keyAt] decoded the same
    // pointer and length again, through a second reader and a view.
    final at = r.position;
    if (at + suffixLen > page.length) {
      throw CorruptionException('page $pageIndex: cell $i suffix runs past the page');
    }
    final key = Uint8List(prefixLen + suffixLen);
    if (prefixLen > 0) key.setRange(0, prefixLen, page, _base + 16);
    key.setRange(prefixLen, key.length, page, at);
    r.position = at + suffixLen;

    final kindFlags = r.u8();
    final valueKind = kindFlags & 0x0F;
    if (valueKind > ValueKind.max) {
      throw CorruptionException(
          'page $pageIndex cell $i: value_kind $valueKind is not 0..4');
    }
    if (kindFlags & 0xE0 != 0) {
      throw CorruptionException(
          'page $pageIndex cell $i: reserved kind_flags bits are set');
    }
    final expiry = kindFlags & kHasExpiry != 0 ? r.u64() : null;

    final op = key[key.length - 1];
    var value = Uint8List(0);
    if (valueKind != ValueKind.empty && op != Op.delete) {
      value = ValueKind.isPointer(valueKind)
          ? r.bytesView(kPointerBytes)
          : r.bytesView(r.uvar());
    }
    return SegRecord(key, valueKind, value, expiry);
  }

  /// Index of the last cell whose key is <= [target], or -1.
  int floorIndex(Uint8List target) {
    final pc = prefixCompare(target);
    // Every key on the page sorts after `target`: there is no floor.
    if (pc > 0) return -1;
    // Every key sorts before it: the floor is the last cell.
    if (pc < 0) return cellCount - 1;
    var lo = 0, hi = cellCount - 1, ans = -1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      if (compareSuffix(mid, target) <= 0) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans;
  }

  /// Index of the first cell whose key is >= [target], or [cellCount].
  int ceilingIndex(Uint8List target) {
    final pc = prefixCompare(target);
    // Every key sorts after `target`: the first cell is the ceiling.
    if (pc > 0) return 0;
    // Every key sorts before it: there is none.
    if (pc < 0) return cellCount;
    var lo = 0, hi = cellCount - 1, ans = cellCount;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      if (compareSuffix(mid, target) >= 0) {
        ans = mid;
        hi = mid - 1;
      } else {
        lo = mid + 1;
      }
    }
    return ans;
  }
}

/// One `RANGE_DELETE`, section 2.5: `[start, end)` deleted at `seq`.
///
/// Both bounds are **user key prefixes** — `u32be(tree_id) || CKE(key)` — so a
/// containment test is one comparison against the same bytes a point read
/// seeks with.
final class RangeDelete {
  const RangeDelete({
    required this.treeId,
    required this.start,
    required this.end,
    required this.seq,
  });

  final int treeId;
  final Uint8List start;
  final Uint8List end;
  final int seq;

  /// §2.5: "an entry at `seq' < seq` whose key falls in the interval is
  /// invisible". The interval is half-open.
  bool covers(Uint8List userKeyPrefix) =>
      compareKeys(userKeyPrefix, start) >= 0 &&
      compareKeys(userKeyPrefix, end) < 0;

  @override
  String toString() => 'RANGE_DELETE seq $seq over tree $treeId';
}

/// The segment header, section 2.1.
final class SegmentHeader {
  const SegmentHeader({
    required this.segmentId,
    required this.level,
    required this.group,
    required this.flags,
    required this.filterBitsPerKey,
    required this.treeCount,
    required this.rootPage,
    required this.entryCount,
    required this.tombstoneCount,
    required this.minSeq,
    required this.maxSeq,
    required this.filterPage,
    required this.valueBytes,
    required this.vlogBytes,
    required this.minExpiry,
    required this.minKey,
    required this.maxKey,
    required this.treeSpan,
  });

  final int segmentId;
  final int level;
  final int group;
  final int flags;
  final int filterBitsPerKey;
  final int treeCount;
  final int rootPage;
  final int entryCount;
  final int tombstoneCount;
  final int minSeq;
  final int maxSeq;
  final int filterPage;
  final int valueBytes;
  final int vlogBytes;
  final int minExpiry;
  final Uint8List minKey;
  final Uint8List maxKey;
  final Map<int, int> treeSpan;

  bool get hasRangeDeletes => flags & SegFlags.hasRangeDeletes != 0;
}

/// An immutable segment, read from its extent.
final class Segment {
  Segment(this.extent, this.pageSize) {
    checkPageSize(pageSize);
    if (extent.length < pageSize || extent.length % pageSize != 0) {
      throw CorruptionException(
          'segment extent of ${extent.length} B is not a whole number of '
          '$pageSize B pages');
    }
    header = _readHeader();
  }

  final Uint8List extent;
  final int pageSize;
  late final SegmentHeader header;

  int get pageCount => extent.length ~/ pageSize;

  /// Every page fetch, cached or not: the algorithmic work of the descent.
  int nodeAccesses = 0;

  /// Cache misses only: what would reach the device.
  ///
  /// Counting store counters rather than wall time is what
  /// `design/performance-model.md` section 8 asks for: "Performance
  /// assertions go on plan shape or a store counter (page reads, bytes
  /// written); wall time is recorded and charted, not gated."
  int pageReads = 0;

  /// When false every fetch is a miss, modelling an engine with no page cache
  /// at all -- the pessimistic bound.
  bool cacheEnabled = true;

  /// Parsed nodes by page index. A list rather than a map: every point read
  /// and every descent step looks a node up here, and the page index is
  /// already a dense array index.
  late final List<Node?> _cache = List<Node?>.filled(pageCount, null);

  void resetCounters() {
    nodeAccesses = 0;
    pageReads = 0;
  }

  void clearCache() => _cache.fillRange(0, _cache.length, null);

  Node node(int pageIndex) {
    nodeAccesses++;
    // `_cache.length` is `pageCount`, without its division.
    if (pageIndex < 1 || pageIndex >= _cache.length) {
      throw CorruptionException('page index $pageIndex outside the extent');
    }
    if (cacheEnabled) {
      final cached = _cache[pageIndex];
      if (cached != null) return cached;
    }
    pageReads++;
    final page = Uint8List.sublistView(
        extent, pageIndex * pageSize, (pageIndex + 1) * pageSize);
    final n = Node(page, pageIndex);
    if (cacheEnabled) _cache[pageIndex] = n;
    return n;
  }

  /// Verifies every page checksum in the extent. `spec/01-container.md`
  /// section 9 step 2.
  void verifyChecksums() {
    for (var i = 0; i < pageCount; i++) {
      PageHeader.read(
          Uint8List.sublistView(extent, i * pageSize, (i + 1) * pageSize),
          pageId: i);
    }
  }

  SegmentHeader _readHeader() {
    final page = Uint8List.sublistView(extent, 0, pageSize);
    final h = PageHeader.read(page, pageId: 0);
    if (h.pageType != PageType.segmentHeader) {
      throw CorruptionException(
          'extent head page is type ${h.pageType}, expected SEGMENT_HEADER');
    }
    final r = ByteReader(page, PageHeader.size, pageSize);
    const magic = [0x43, 0x52, 0x59, 0x5F, 0x53, 0x45, 0x47, 0x1A];
    for (var i = 0; i < 8; i++) {
      if (r.u8() != magic[i]) {
        throw const CorruptionException('bad CRY_SEG magic');
      }
    }
    final segmentId = r.u64();
    final level = r.u8();
    final flags = r.u8();
    final filterBits = r.u16();
    final treeCount = r.u32();
    final rootPage = r.u64();
    final entryCount = r.u64();
    final tombstones = r.u64();
    final minSeq = r.u64();
    final maxSeq = r.u64();
    final filterPage = r.u64();
    final valueBytes = r.u64();
    final vlogBytes = r.u64();
    final minExpiry = r.u64();
    final group = r.u8();
    r.position = r.position + 7; // reserved
    final minKeyLen = r.u32();
    final maxKeyLen = r.u32();
    final minKey = r.bytesCopy(minKeyLen);
    final maxKey = r.bytesCopy(maxKeyLen);
    final span = <int, int>{};
    for (var i = 0; i < treeCount; i++) {
      span[r.u32()] = r.u64();
    }
    // `spec/14-security.md` section 9.1 — every one of these came out of the
    // file and two of them are page indices into this extent. Checking them
    // here, once, is what stops a hostile header from steering a slice.
    //
    // `u64` matters: [ByteReader.u64] returns the raw 64-bit pattern, so a
    // `filter_page` of `0xFFFF_FFFF_FFF0_0000` arrives as a *negative* int and
    // `first < pageCount` is true. `Uint8List.sublistView` then gets a negative
    // start and raises a `RangeError` — an untyped failure, which is the
    // violation regardless of what the field meant. Found by
    // `lib/src/fuzz.dart`; a bound written as `< pageCount` alone would not
    // have caught it, which is why both ends are checked.
    void checkPage(int v, String field) {
      if (v < 0 || v >= pageCount) {
        throw CorruptionException(
            'segment header $field $v outside its $pageCount-page extent');
      }
    }

    checkPage(rootPage, 'root_page');
    // 0 is "no filter" (section 2.4), and is the only value outside the extent
    // that means anything.
    if (filterPage != 0) checkPage(filterPage, 'filter_page');
    if (entryCount < 0) {
      throw CorruptionException('segment header entry_count $entryCount');
    }
    return SegmentHeader(
      segmentId: segmentId,
      level: level,
      group: group,
      flags: flags,
      filterBitsPerKey: filterBits,
      treeCount: treeCount,
      rootPage: rootPage,
      entryCount: entryCount,
      tombstoneCount: tombstones,
      minSeq: minSeq,
      maxSeq: maxSeq,
      filterPage: filterPage,
      valueBytes: valueBytes,
      vlogBytes: vlogBytes,
      minExpiry: minExpiry,
      minKey: minKey,
      maxKey: maxKey,
      treeSpan: span,
    );
  }

  /// Height in pages from the root to a leaf, root included.
  int get height {
    var h = 1;
    var n = node(header.rootPage);
    while (!n.isLeaf) {
      h++;
      n = node(n.childAt(0).$1);
    }
    return h;
  }

  /// Bytes occupied by internal (non-leaf) pages: the part of the key index
  /// that `design/performance-model.md` prediction P1 says stays cached.
  int get interiorBytes {
    var bytes = 0;
    for (var i = 1; i < pageCount; i++) {
      if (!node(i).isLeaf) bytes += pageSize;
    }
    return bytes;
  }

  List<RangeDelete>? _rangeDeletes;

  /// The segment's range deletes, §2.5 — its "range-delete summary".
  ///
  /// §4 SHOULDs keeping this "in memory alongside the manifest entry, so
  /// `rd_sources` is normally empty after an in-memory test rather than after a
  /// page read". It is built once, lazily, and only for a segment whose header
  /// carries `HAS_RANGE_DELETES` — so a segment without range deletes, which is
  /// almost all of them, never pays for this at all.
  List<RangeDelete> get rangeDeletes {
    final cached = _rangeDeletes;
    if (cached != null) return cached;
    if (!header.hasRangeDeletes) return _rangeDeletes = const [];
    final out = <RangeDelete>[];
    final c = cursor()..seekFirst();
    while (c.isValid) {
      final k = c.key();
      if (k[k.length - 1] == Op.rangeDelete) {
        final rec = c.record();
        final r = ByteReader(rec.value);
        final end = r.bytesCopy(r.uvar());
        final p = parseInternalKey(k);
        out.add(RangeDelete(
          treeId: p.treeId,
          start: userKeyPrefix(p.treeId, Uint8List.fromList(p.cke)),
          end: userKeyPrefix(p.treeId, end),
          seq: p.seq,
        ));
      }
      c.next();
    }
    return _rangeDeletes = out;
  }

  BlockedBloom? _filter;
  bool _filterLoaded = false;

  /// The segment's membership filter, or null when `filter_page = 0`.
  ///
  /// §4: a reader with no filter MUST treat every probe as a hit, which is
  /// what a null here means at the call site.
  BlockedBloom? get filter {
    if (_filterLoaded) return _filter;
    _filterLoaded = true;
    final first = header.filterPage;
    if (first == 0) return null;
    final out = BytesBuilder();
    for (var i = first; i < pageCount; i++) {
      final page = Uint8List.sublistView(
          extent, i * pageSize, (i + 1) * pageSize);
      final h = PageHeader.read(page, pageId: i);
      if (h.pageType != PageType.segmentFilter) break;
      out.add(h.payloadIn(page, pageId: i));
    }
    return _filter = BlockedBloom.decodePayload(out.takeBytes());
  }

  /// True when this segment's key range can contain [userKeyPrefix].
  ///
  /// §4.1's first mechanism: manifest key-range pruning, with no I/O. The
  /// internal keys of one user key occupy `[prefix, successor(prefix))`, so
  /// the segment is pruned when that interval misses `[min_key, max_key]`.
  /// `min_key` and `max_key` may have been *widened* by §2.1's truncation,
  /// which keeps the test conservative — never the other way.
  bool covers(Uint8List userKeyPrefix) {
    if (compareKeys(userKeyPrefix, header.maxKey) > 0) return false;
    final sup = Keys.successor(userKeyPrefix);
    if (sup != null && compareKeys(sup, header.minKey) <= 0) return false;
    return true;
  }

  SegmentCursor cursor() => SegmentCursor(this);

  /// What [pointLookup] returns when it cannot answer and the ordered seek
  /// must. Compared with `identical`.
  static final SegRecord unindexed = SegRecord(Uint8List(0), 0, Uint8List(0), null);

  /// A hash table from user key to that key's **first** cell -- its newest
  /// version, by §1's inverted seq. Not part of the format: a segment is
  /// immutable, so a table built from its cells cannot go stale. It turns a
  /// point read's B+tree descent -- 60 % of a read, about fifteen binary-search
  /// probes over three pages -- into one hash, usually one slot and one
  /// in-place cell comparison.
  ///
  /// Each slot is `page << 32 | cell << 16 | tag`, zero when empty (page 0 is
  /// the segment header, never a leaf); `tag` is sixteen more bits of the
  /// hash. Linear probing at a load factor of at most one half. Empty when the
  /// segment could not be indexed, which leaves it to the ordered seek.
  Int64List? _pointIndex;

  /// Lookups served before the index existed; what decides when to build it.
  int _pointLookups = 0;

  /// Whether the point index has been built, so a test can prove it read
  /// through one.
  bool get pointIndexed => (_pointIndex?.length ?? 0) > 0;

  /// The entry the ordered seek for [prefix] at [ceiling] would return, when
  /// the index can say; `null` when the segment holds no entry for [prefix]
  /// at all; [unindexed] when only the seek can say.
  ///
  /// The key's first cell is the seek's answer exactly when its seq is at or
  /// below the ceiling, which for a read with no snapshot is always. Until
  /// the segment has served one lookup per 32 entries there is no index:
  /// building it is one pass over every cell, and by then the descents
  /// already paid for cost about as much.
  SegRecord? pointLookup(Uint8List prefix, int hash, int? ceiling) {
    var ix = _pointIndex;
    if (ix == null) {
      final threshold = header.entryCount ~/ 32;
      if (++_pointLookups < (threshold < 8 ? 8 : threshold)) return unindexed;
      ix = _pointIndex = _buildPointIndex();
    }
    if (ix.isEmpty) return unindexed;
    final mask = ix.length - 1;
    final tag = hash >>> 48;
    for (var i = hash & mask;; i = (i + 1) & mask) {
      final s = ix[i];
      if (s == 0) return null; // every user key in the segment is in the table
      if (s & 0xFFFF != tag) continue;
      final n = node(s >>> 32);
      final cell = (s >>> 16) & 0xFFFF;
      if (!n.isLeaf || cell >= n.cellCount) {
        throw CorruptionException(
            'point index names cell $cell of page ${n.pageIndex}, which does not hold it');
      }
      final rec = n.recordIfVersionOf(cell, prefix);
      if (rec == null) continue;
      if (ceiling != null && rec.seq > ceiling) return unindexed;
      return rec;
    }
  }

  Int64List _buildPointIndex() {
    final found = <int>[];
    try {
      Uint8List? prev;
      final c = cursor()..seekFirst();
      while (c.isValid) {
        final k = c.key();
        if (k.length < 9) {
          throw CorruptionException('segment cell key is shorter than 9 bytes');
        }
        final user = Uint8List.sublistView(k, 0, k.length - 9);
        if (prev == null || compareKeys(prev, user) != 0) {
          prev = user;
          final h = cfh64(user);
          found
            ..add(h)
            ..add(c.leafPage << 32 | c.cellIndex << 16 | h >>> 48);
        }
        c.next();
      }
    } on CorruptionException {
      // Left to the ordered seek, which reports it for the key that actually
      // lands on the damage, not for every read of the segment.
      return Int64List(0);
    }
    var cap = 16;
    while (cap < found.length) {
      cap <<= 1;
    }
    final slots = Int64List(cap);
    final mask = cap - 1;
    for (var k = 0; k < found.length; k += 2) {
      var i = found[k] & mask;
      while (slots[i] != 0) {
        i = (i + 1) & mask;
      }
      slots[i] = found[k + 1];
    }
    return slots;
  }
}

/// A cursor over one segment.
///
/// `spec/04-segments.md` section 8 makes this the **only** iteration
/// mechanism, and requires `next` to be O(1) amortized inside a page. That is
/// the direct fix for the defect measured in `research/nitrite-survey.md`
/// section 7: `nitrite-rust` navigates by repeated `higher_key` from the root
/// and pays 40.4x on a paged walk. Advancing here is a pointer bump inside a
/// leaf; the root is descended once.
final class SegmentCursor {
  SegmentCursor(this.segment);

  final Segment segment;

  /// `(node, cellIndex)` from the root down to the current leaf.
  final List<(Node, int)> _path = [];
  bool _valid = false;

  bool get isValid => _valid;

  /// Descents performed. A paged walk that re-seeks per page costs one
  /// descent per page; a cursor that is merely advanced costs zero.
  int descents = 0;

  Node get _leaf => _path.last.$1;
  int get _index => _path.last.$2;

  /// The page and cell the cursor stands on.
  int get leafPage => _leaf.pageIndex;
  int get cellIndex => _index;

  void _setLast(int i) => _path[_path.length - 1] = (_path.last.$1, i);

  void seekFirst() {
    _path.clear();
    descents++;
    var n = segment.node(segment.header.rootPage);
    while (true) {
      _path.add((n, 0));
      if (n.isLeaf) break;
      n = segment.node(n.childAt(0).$1);
    }
    _valid = _leaf.cellCount > 0;
  }

  void seekLast() {
    _path.clear();
    descents++;
    var n = segment.node(segment.header.rootPage);
    while (true) {
      final i = n.cellCount - 1;
      _path.add((n, i));
      if (n.isLeaf) break;
      n = segment.node(n.childAt(i).$1);
    }
    _valid = _leaf.cellCount > 0;
  }

  /// Positions at the first entry whose internal key is >= [target].
  void seekCeiling(Uint8List target) {
    _path.clear();
    descents++;
    var n = segment.node(segment.header.rootPage);
    while (!n.isLeaf) {
      // Separators are lower bounds on their subtree, so descend into the
      // last child whose separator is <= target.
      var i = n.floorIndex(target);
      if (i < 0) i = 0;
      _path.add((n, i));
      n = segment.node(n.childAt(i).$1);
    }
    final i = n.ceilingIndex(target);
    _path.add((n, i));
    if (i >= n.cellCount) {
      _valid = true;
      next(); // roll into the following leaf
    } else {
      _valid = true;
    }
  }

  /// Advances one entry. Returns false when the segment is exhausted.
  bool next() {
    if (!_valid) return false;
    if (_index + 1 < _leaf.cellCount) {
      _setLast(_index + 1);
      return true;
    }
    // Walk up until a parent has another child, then down its left spine.
    // No sibling pointers: section 2.2 removed them, and this is the cost.
    var level = _path.length - 2;
    while (level >= 0) {
      final (n, i) = _path[level];
      if (i + 1 < n.cellCount) {
        _path.removeRange(level + 1, _path.length);
        _path[level] = (n, i + 1);
        var child = segment.node(n.childAt(i + 1).$1);
        while (true) {
          _path.add((child, 0));
          if (child.isLeaf) break;
          child = segment.node(child.childAt(0).$1);
        }
        return _valid = _leaf.cellCount > 0;
      }
      level--;
    }
    return _valid = false;
  }

  bool prev() {
    if (!_valid) return false;
    if (_index > 0) {
      _setLast(_index - 1);
      return true;
    }
    var level = _path.length - 2;
    while (level >= 0) {
      final (n, i) = _path[level];
      if (i > 0) {
        _path.removeRange(level + 1, _path.length);
        _path[level] = (n, i - 1);
        var child = segment.node(n.childAt(i - 1).$1);
        while (true) {
          _path.add((child, child.cellCount - 1));
          if (child.isLeaf) break;
          child = segment.node(child.childAt(child.cellCount - 1).$1);
        }
        return _valid = _leaf.cellCount > 0;
      }
      level--;
    }
    return _valid = false;
  }

  /// Positions at ordinal [n] (0-based) using `subtree_entries`.
  ///
  /// Section 2.2: "subtree_entries is what makes skip(n) cost O(height)
  /// instead of O(n)." This is the second half of the paging fix, next to the
  /// cursor itself.
  void skipTo(int n) {
    if (n < 0 || n >= segment.header.entryCount) {
      _valid = false;
      return;
    }
    _path.clear();
    descents++;
    var node = segment.node(segment.header.rootPage);
    var remaining = n;
    while (!node.isLeaf) {
      var i = 0;
      while (i < node.cellCount) {
        final (_, entries) = node.childAt(i);
        if (remaining < entries) break;
        remaining -= entries;
        i++;
      }
      if (i >= node.cellCount) {
        _valid = false;
        return;
      }
      _path.add((node, i));
      node = segment.node(node.childAt(i).$1);
    }
    if (remaining >= node.cellCount) {
      _valid = false;
      return;
    }
    _path.add((node, remaining));
    _valid = true;
  }

  Uint8List key() {
    if (!_valid) throw StateError('cursor is not positioned');
    return _leaf.keyAt(_index);
  }

  /// The record at the cursor. Lazy: nothing is decoded until this is called,
  /// so a key-only scan never touches a value (section 8).
  SegRecord record() {
    if (!_valid) throw StateError('cursor is not positioned');
    return _leaf.recordAt(_index);
  }

  /// Whether the current entry's key is exactly `prefix || u64be(~seq) || op`
  /// -- one version of the user key [prefix] -- without building the key.
  bool keyIsVersionOf(Uint8List prefix) {
    if (!_valid) return false;
    final n = _leaf;
    final i = _index;
    if (i >= n.cellCount) return false;
    return n.keyLen(i) == prefix.length + 9 && n.keyHasPrefix(i, prefix);
  }

  /// The current entry's `seq`, read in place.
  int seq() {
    if (!_valid) throw StateError('cursor is not positioned');
    return _leaf.seqAt(_index);
  }
}
