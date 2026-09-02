/// The manifest: reserved tree 6, `spec/04-segments.md` §3.2.
///
/// The manifest is what makes the level policy *not* part of the format. It
/// records only a segment's level, group, key range and seq range (§3.1: "a
/// conforming reader MUST NOT depend on the policy"), and a reader answers
/// "which segments at level L can hold key k" with `overlap_bound` seeks.
///
/// It is a plain copy-on-write B+tree (§3.3), keyed
/// `CKE(Array[U8 level, U8 group, BYTES min_internal_key])`, so segments sort
/// by level, then group, then key — exactly the order the read path of §4
/// walks them in.
library;

import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'segment.dart';
import 'value.dart';

/// One segment's manifest entry, §3.2.
///
/// `start_page`, `pages`, `root` and `filter` are page addresses in the file;
/// this implementation keeps extents in memory (`REPORT.md` §5) and addresses
/// them by [segmentId], so those four are carried and round-tripped but the
/// extent registry is what resolves them.
final class SegmentRef {
  const SegmentRef({
    required this.segmentId,
    required this.level,
    required this.group,
    required this.minKey,
    required this.maxKey,
    required this.minSeq,
    required this.maxSeq,
    required this.entries,
    required this.tombstones,
    required this.hasRangeDeletes,
    this.startPage = 0,
    this.pages = 0,
    this.root = 0,
    this.filter = 0,
    this.minExpiry = 0,
    this.valueBytes = 0,
    this.vlogBytes = 0,
    this.trees = const [],
  });

  factory SegmentRef.of(Segment s, {required int level, required int group}) {
    final h = s.header;
    return SegmentRef(
      segmentId: h.segmentId,
      level: level,
      group: group,
      minKey: h.minKey,
      maxKey: h.maxKey,
      minSeq: h.minSeq,
      maxSeq: h.maxSeq,
      entries: h.entryCount,
      tombstones: h.tombstoneCount,
      hasRangeDeletes: h.hasRangeDeletes,
      pages: s.pageCount,
      root: h.rootPage,
      filter: h.filterPage,
      minExpiry: h.minExpiry,
      valueBytes: h.valueBytes,
      vlogBytes: h.vlogBytes,
      trees: h.treeSpan.keys.toList()..sort(),
    );
  }

  final int segmentId;
  final int level;
  final int group;
  final Uint8List minKey;
  final Uint8List maxKey;
  final int minSeq;
  final int maxSeq;
  final int entries;
  final int tombstones;
  final bool hasRangeDeletes;
  final int startPage;
  final int pages;
  final int root;
  final int filter;
  final int minExpiry;
  final int valueBytes;
  final int vlogBytes;
  final List<int> trees;

  /// True when this segment's key range can hold [userKeyPrefix].
  ///
  /// §4.1's first mechanism, and the reason it costs no I/O: the test runs on
  /// the manifest entry, not on the segment.
  bool covers(Uint8List userKeyPrefix) {
    if (compareKeys(userKeyPrefix, maxKey) > 0) return false;
    final sup = Keys.successor(userKeyPrefix);
    if (sup != null && compareKeys(sup, minKey) <= 0) return false;
    return true;
  }

  /// The manifest key, §3.2.
  Uint8List get key => manifestKey(level, group, minKey);

  Uint8List encode() => encodeValue(CDoc({
        'segment_id': CInt.of(NumType.u64, segmentId),
        'start_page': CInt.of(NumType.u64, startPage),
        'pages': CInt.of(NumType.u32, pages),
        'root': CInt.of(NumType.u64, root),
        'filter': CInt.of(NumType.u64, filter),
        'min_seq': CInt.of(NumType.u64, minSeq),
        'max_seq': CInt.of(NumType.u64, maxSeq),
        'entries': CInt.of(NumType.u64, entries),
        'tombstones': CInt.of(NumType.u64, tombstones),
        'min_expiry': CInt.of(NumType.u64, minExpiry),
        'min_key': CBytes(minKey),
        'max_key': CBytes(maxKey),
        'value_bytes': CInt.of(NumType.u64, valueBytes),
        'vlog_bytes': CInt.of(NumType.u64, vlogBytes),
        'range_deletes': CBool(hasRangeDeletes),
        'trees': CArray([for (final t in trees) CInt.of(NumType.u32, t)]),
      }));

  static SegmentRef decode(Uint8List key, Uint8List value) {
    final k = decodeKey(key) as CArray;
    final d = decodeValue(value) as CDoc;
    int u(String f) => ((d[f]! as CInt).magnitude).lo;
    return SegmentRef(
      level: ((k.items[0] as CInt).magnitude).lo,
      group: ((k.items[1] as CInt).magnitude).lo,
      segmentId: u('segment_id'),
      startPage: u('start_page'),
      pages: u('pages'),
      root: u('root'),
      filter: u('filter'),
      minSeq: u('min_seq'),
      maxSeq: u('max_seq'),
      entries: u('entries'),
      tombstones: u('tombstones'),
      minExpiry: u('min_expiry'),
      minKey: (d['min_key']! as CBytes).value,
      maxKey: (d['max_key']! as CBytes).value,
      valueBytes: u('value_bytes'),
      vlogBytes: u('vlog_bytes'),
      hasRangeDeletes: (d['range_deletes']! as CBool).value,
      trees: [
        for (final t in (d['trees']! as CArray).items)
          ((t as CInt).magnitude).lo
      ],
    );
  }

  @override
  String toString() => 'seg $segmentId L$level.g$group '
      '${entries}e ${pages}p seq $minSeq..$maxSeq';
}

/// `CKE(Array[U8 level, U8 group, BYTES min_internal_key])`.
Uint8List manifestKey(int level, int group, Uint8List minInternalKey) =>
    encodeKey(CArray([
      CInt.of(NumType.u8, level),
      CInt.of(NumType.u8, group),
      CBytes(minInternalKey),
    ]));

/// Tree 6.
final class Manifest {
  Manifest(PageStore store, {int root = 0})
      : tree = CowTree(store, treeId: TreeId.manifest, root: root);

  final CowTree tree;

  int get root => tree.root;

  void add(SegmentRef ref) {
    // Two segments in one (level, group) cannot share a min_internal_key:
    // every entry carries a distinct seq, so two segments' first entries
    // differ. A collision would silently unlink a live segment — losing every
    // key in it with no checksum able to see it — so it is refused here rather
    // than trusted.
    if (tree.get(ref.key) != null) {
      throw StateError('manifest already holds a segment at ${ref.key} '
          '(level ${ref.level}, group ${ref.group})');
    }
    tree.put(ref.key, ref.encode());
  }

  bool remove(SegmentRef ref) => tree.remove(ref.key);

  Iterable<SegmentRef> get all sync* {
    for (final (k, v) in tree.scan()) {
      yield SegmentRef.decode(k, v);
    }
  }

  /// Every segment in one range-partition group of one level, in key order.
  Iterable<SegmentRef> group(int level, int group) sync* {
    final lower = manifestKey(level, group, Uint8List(0));
    final upper = manifestKey(level, group + 1, Uint8List(0));
    for (final (k, v) in tree.scan(lower: lower, upper: upper)) {
      yield SegmentRef.decode(k, v);
    }
  }

  Iterable<SegmentRef> level(int level) sync* {
    final lower = manifestKey(level, 0, Uint8List(0));
    final upper = manifestKey(level + 1, 0, Uint8List(0));
    for (final (k, v) in tree.scan(lower: lower, upper: upper)) {
      yield SegmentRef.decode(k, v);
    }
  }

  /// The segments of one group that can hold [userKeyPrefix].
  ///
  /// Within a group the segments are disjoint, so this yields **at most one** —
  /// which is the whole point of range partitioning (§3.1) and half of the
  /// bounded read tail (§4.1).
  Iterable<SegmentRef> covering(int level, int group, Uint8List userKeyPrefix) {
    return this.group(level, group).where((r) => r.covers(userKeyPrefix));
  }
}
