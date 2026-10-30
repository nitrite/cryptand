/// The R-tree — `spec/08-spatial.md` §2.
///
/// Pages of type `RTREE_INTERNAL` (8) and `RTREE_LEAF` (9), **in the same
/// container**. §6 is the point of that: Rust's `disk_rtree` today has its own
/// file header, free list, migration manager and integrity checker, and every
/// one of those is a duplicate of something `01-container.md` already specifies
/// for every page in the database. What survives is the good part — paged
/// nodes, an LRU, lazy loading, per-page checksums — with the private container
/// deleted.
///
/// **The split algorithm is deliberately not specified** (§2.2), so this
/// implementation picks one (quadratic split) and §2.3 is why that is safe: "two
/// implementations inserting the same documents will produce different (equally
/// valid) trees. A conformance test therefore compares **query results**, never
/// tree shape."
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'catalog.dart';
import 'container.dart';
import 'cow.dart';
import 'database.dart';
import 'errors.dart';
import 'geometry_ops.dart';
import 'index.dart';
import 'value.dart';
import 'wkb.dart';

/// §2.1 node flags.
class RTreeFlags {
  static const int isLeaf = 0x01;
}

/// One entry of an R-tree node.
final class RTreeEntry {
  const RTreeEntry(this.box,
      {this.childPage = 0,
      this.childEntries = 0,
      this.childNonce = 0,
      this.docId = 0});

  final Envelope box;

  /// Internal entries only. [childNonce] is F-128's: the child's header nonce
  /// (`14-security.md` §5.5).
  final int childPage;
  final int childEntries;
  final int childNonce;

  /// Leaf entries only.
  final int docId;
}

/// A decoded R-tree node.
final class RTreeNode {
  RTreeNode(this.isLeaf, this.dimensions, this.entries);

  final bool isLeaf;
  final int dimensions;
  final List<RTreeEntry> entries;

  int get subtreeEntries {
    if (isLeaf) return entries.length;
    var n = 0;
    for (final e in entries) {
      n += e.childEntries;
    }
    return n;
  }

  Envelope get box {
    var b = Envelope.empty(dimensions);
    for (final e in entries) {
      b = b.union(e.box);
    }
    return b;
  }

  /// §2.1. Fixed-width entries, no varints — "a bounding-box comparison is the
  /// hot loop of every spatial query, and a fixed stride lets an implementation
  /// scan a node without decoding it".
  ///
  /// All `f64` are little-endian: §2.1 notes that R-tree keys are compared
  /// numerically in code and never by `memcmp`, so `00-conventions.md` §3's
  /// big-endian CKE rule does not apply here.
  Uint8List encode(int pageSize, {int treeId = TreeId.noTree}) {
    final page = Uint8List(pageSize);
    final bd = ByteData.view(page.buffer);
    final base = PageHeader.size;
    final stride = entryStride(dimensions, isLeaf);
    final need = 16 + entries.length * stride;
    if (base + need > pageSize) {
      throw LimitException(
          '${entries.length} entries at $dimensions dimensions need $need B, '
          'over the ${pageSize - base} B a page holds');
    }

    bd
      ..setUint16(base + 0, entries.length, Endian.little)
      ..setUint8(base + 2, dimensions)
      ..setUint8(base + 3, isLeaf ? RTreeFlags.isLeaf : 0)
      ..setUint32(base + 4, 0, Endian.little)
      ..setUint64(base + 8, subtreeEntries, Endian.little);

    var off = base + 16;
    for (final e in entries) {
      for (var i = 0; i < dimensions; i++) {
        bd.setFloat64(off + i * 8, e.box.min[i], Endian.little);
        bd.setFloat64(off + (dimensions + i) * 8, e.box.max[i], Endian.little);
      }
      final after = off + dimensions * 16;
      if (isLeaf) {
        bd.setInt64(after, e.docId, Endian.little);
      } else {
        bd
          ..setUint64(after, e.childPage, Endian.little)
          ..setUint64(after + 8, e.childEntries, Endian.little)
          ..setUint64(after + 16, e.childNonce, Endian.little);
      }
      off += stride;
    }

    PageHeader(
      pageType: isLeaf ? PageType.rtreeLeaf : PageType.rtreeInternal,
      treeId: treeId,
      payloadLen: need,
    ).writeInto(page);
    return page;
  }

  static RTreeNode decode(Uint8List page, {int? expectedDimensions}) {
    final h = PageHeader.read(page);
    if (h.pageType != PageType.rtreeInternal &&
        h.pageType != PageType.rtreeLeaf) {
      throw CorruptionException('page type ${h.pageType} is not an R-tree node');
    }
    final base = PageHeader.size;
    final bd = ByteData.view(page.buffer, page.offsetInBytes, page.length);
    final count = bd.getUint16(base + 0, Endian.little);
    final dims = bd.getUint8(base + 2);
    final flags = bd.getUint8(base + 3);
    final isLeaf = flags & RTreeFlags.isLeaf != 0;

    // §3: "A reader MUST use the page's own `dimensions` field and MUST reject
    // a page whose `dimensions` disagrees with the descriptor."
    if (expectedDimensions != null && dims != expectedDimensions) {
      throw CorruptionException(
          'R-tree page declares $dims dimensions, descriptor says '
          '$expectedDimensions');
    }
    if (dims < 2 || dims > 4) {
      throw CorruptionException('R-tree page declares $dims dimensions');
    }

    final stride = entryStride(dims, isLeaf);
    final entries = <RTreeEntry>[];
    var off = base + 16;
    for (var i = 0; i < count; i++) {
      final min = <double>[], max = <double>[];
      for (var d = 0; d < dims; d++) {
        min.add(bd.getFloat64(off + d * 8, Endian.little));
        max.add(bd.getFloat64(off + (dims + d) * 8, Endian.little));
      }
      final after = off + dims * 16;
      entries.add(isLeaf
          ? RTreeEntry(Envelope(min, max), docId: bd.getInt64(after, Endian.little))
          : RTreeEntry(Envelope(min, max),
              childPage: bd.getUint64(after, Endian.little),
              childEntries: bd.getUint64(after + 8, Endian.little),
              childNonce: bd.getUint64(after + 16, Endian.little)));
      off += stride;
    }
    return RTreeNode(isLeaf, dims, entries);
  }
}

/// §2.1: internal entries are `16 × dimensions + 24` bytes (F-128's
/// `child_nonce`), leaf entries `16 × dimensions + 8`.
int entryStride(int dimensions, bool isLeaf) =>
    16 * dimensions + (isLeaf ? 8 : 24);

/// The maximum entries a page holds at a given shape.
int maxEntriesFor(int pageSize, int dimensions, bool isLeaf) =>
    (pageSize - PageHeader.size - 16) ~/ entryStride(dimensions, isLeaf);


/// Copied nodes held before an early write-back (F-195, as Java): ~10 KB
/// each, so ~20 MB. A test lowers it to exercise the write-back.
int rtreeDirtyBudget = 2048;

final class _Slot {
  _Slot(this.box, this.r, [this.cnt = 0, this.nonce = 0, this.kid]);
  Envelope box;

  /// Leaf: nitrite id. Internal: child page, 0 while the child is only in [kid].
  int r;
  int cnt;
  int nonce;
  _RNode? kid;
}

final class _RNode {
  _RNode(this.leaf, [List<_Slot>? e]) : e = e ?? [];
  final bool leaf;
  List<_Slot> e;

  int get total {
    if (leaf) return e.length;
    var t = 0;
    for (final s in e) {
      t += s.cnt;
    }
    return t;
  }

  Envelope cover(int dims) {
    var c = Envelope.empty(dims);
    for (final s in e) {
      c = c.union(s.box);
    }
    return c;
  }
}

double _centre(Envelope b, int axis) =>
    b.isEmpty ? 0 : (b.min[axis] + b.max[axis]) / 2;

/// The spatial index's R-tree, copy-on-write and incremental (F-195, as Java
/// and Rust).
///
/// A write copies the path it touches into memory and frees the old pages
/// (reusable after the next commit, 01 §6); [commit] writes the copied nodes
/// back as fresh pages, and past [rtreeDirtyBudget] copied nodes the same
/// write-back runs early, so memory holds a bounded part of the tree whatever
/// its size. Inserts by least enlargement, splits at the median of the widest
/// axis (§2.3 leaves the split open). Removal needs the entry's box, which the
/// caller derives from the previous document.
/// ponytail: no reinsertion on underflow (2.2 allows any population from 1);
/// a long delete-heavy life leaves sparse nodes, R*-tree condense is the upgrade.
final class RTree {
  RTree(this.store,
      {this.dimensions = 2,
      this.treeId = TreeId.noTree,
      int root = 0,
      int rootNonce = 0})
      : _rootPage = root,
        _rootNonce = rootNonce {
    if (root != 0) size = _read(root, rootNonce).total;
  }

  final PageStore store;
  final int dimensions;
  final int treeId;
  _RNode? _root;
  int _rootPage;
  int _rootNonce;
  int size = 0;
  int _dirty = 0;
  bool _rewriteAll = false;

  /// The published root page and nonce, valid after [commit] (0: empty).
  int get root => _rootPage;
  int get rootNonce => _rootNonce;

  /// The next [commit] rewrites every page (F-072: conversion in place).
  void markDirty() => _rewriteAll = true;

  int _fanout(bool leaf) =>
      math.max(2, (store.payloadCap - 16) ~/ entryStride(dimensions, leaf));

  _RNode _read(int page, int nonce) {
    final n = RTreeNode.decode(store.readBound(page, nonce),
        expectedDimensions: dimensions);
    return _RNode(n.isLeaf, [
      for (final x in n.entries)
        _Slot(x.box, n.isLeaf ? x.docId : x.childPage, x.childEntries,
            x.childNonce)
    ]);
  }

  /// Child [i] for a write: copied from its page, which is freed.
  _RNode _child(_RNode node, int i) {
    final s = node.e[i];
    if (s.kid == null) {
      s.kid = _read(s.r, s.nonce);
      store.free(s.r);
      s.r = 0;
      _dirty++;
    }
    return s.kid!;
  }

  _RNode _rootForWrite() {
    if (_root == null && _rootPage != 0) {
      _root = _read(_rootPage, _rootNonce);
      store.free(_rootPage);
      _rootPage = 0;
      _dirty++;
    }
    return _root ??= (() {
      _dirty++;
      return _RNode(true);
    })();
  }

  _RNode? get _rootView =>
      _root ?? (_rootPage == 0 ? null : _read(_rootPage, _rootNonce));

  void insert(Envelope box, int docId) {
    final r = _rootForWrite();
    final s = _insert(r, box, docId);
    if (s != null) {
      _root = _RNode(false, [
        _Slot(r.cover(dimensions), 0, r.total, 0, r),
        _Slot(s.cover(dimensions), 0, s.total, 0, s),
      ]);
      _dirty++;
    }
    size++;
    _spillIfOver();
  }

  _RNode? _insert(_RNode node, Envelope box, int docId) {
    if (node.leaf) {
      node.e.add(_Slot(box, docId));
    } else {
      final i = _choose(node, box);
      final c = _child(node, i);
      final s = _insert(c, box, docId);
      node.e[i]
        ..box = c.cover(dimensions)
        ..cnt = c.total;
      if (s != null) node.e.add(_Slot(s.cover(dimensions), 0, s.total, 0, s));
    }
    return node.e.length > _fanout(node.leaf) ? _split(node) : null;
  }

  /// Least area enlargement, then least area.
  static int _choose(_RNode node, Envelope box) {
    var best = 0;
    var bestGrow = double.infinity, bestArea = double.infinity;
    for (var i = 0; i < node.e.length; i++) {
      final a = node.e[i].box.area;
      final grow = node.e[i].box.union(box).area - a;
      if (grow < bestGrow || (grow == bestGrow && a < bestArea)) {
        best = i;
        bestGrow = grow;
        bestArea = a;
      }
    }
    return best;
  }

  /// Median split on the axis whose entry centres spread widest; the upper half moves out.
  _RNode _split(_RNode node) {
    var axis = 0;
    var widest = -1.0;
    for (var a = 0; a < dimensions; a++) {
      var lo = double.infinity, hi = double.negativeInfinity;
      for (final s in node.e) {
        final c = _centre(s.box, a);
        lo = math.min(lo, c);
        hi = math.max(hi, c);
      }
      if (hi - lo > widest) {
        widest = hi - lo;
        axis = a;
      }
    }
    node.e.sort((x, y) => _centre(x.box, axis).compareTo(_centre(y.box, axis)));
    final half = node.e.length ~/ 2;
    final hi = node.e.sublist(half);
    node.e = node.e.sublist(0, half);
    _dirty++;
    return _RNode(node.leaf, hi);
  }

  static bool _sameBox(Envelope a, Envelope b, int dims) {
    for (var i = 0; i < dims; i++) {
      if (a.min[i] != b.min[i] || a.max[i] != b.max[i]) {
        // NaN-free here: boxes come from finite or ±infinite coordinates.
        return false;
      }
    }
    return true;
  }

  /// Removes one entry of [docId] whose box is [box]; false if there is none.
  bool remove(Envelope box, int docId) {
    if (size == 0) return false;
    final path = <int>[];
    final view = _rootView;
    if (view == null || !_find(view, box, docId, path, 0)) return false;
    final nodes = <_RNode>[_rootForWrite()];
    for (var d = 0; d < path.length - 1; d++) {
      nodes.add(_child(nodes.last, path[d]));
    }
    nodes.last.e.removeAt(path.last);
    for (var d = nodes.length - 2; d >= 0; d--) {
      final parent = nodes[d], c = nodes[d + 1], i = path[d];
      if (c.e.isEmpty) {
        parent.e.removeAt(i);
        _dirty--;
      } else {
        parent.e[i]
          ..box = c.cover(dimensions)
          ..cnt = c.total;
      }
    }
    var r = _root!;
    while (!r.leaf && r.e.length == 1) {
      r = _child(r, 0);
      _dirty--;
    }
    _root = r.e.isEmpty ? null : r;
    if (r.e.isEmpty) _dirty--;
    size--;
    _spillIfOver();
    return true;
  }

  bool _find(_RNode node, Envelope box, int docId, List<int> path, int depth) {
    if (depth > 64) {
      throw CorruptionException('R-tree $treeId is deeper than 64 levels');
    }
    for (var i = 0; i < node.e.length; i++) {
      final s = node.e[i];
      if (node.leaf) {
        if (s.r == docId && _sameBox(s.box, box, dimensions)) {
          path.add(i);
          return true;
        }
      } else if (box.isEmpty || s.box.containsEnvelope(box)) {
        path.add(i);
        if (_find(s.kid ?? _read(s.r, s.nonce), box, docId, path, depth + 1)) {
          return true;
        }
        path.removeLast();
      }
    }
    return false;
  }

  void _spillIfOver() {
    if (_dirty > rtreeDirtyBudget) _writeOut();
  }

  void _writeOut() {
    final r = _root;
    if (r != null) {
      final at = _write(r);
      _rootPage = at.$1;
      _rootNonce = at.$2;
      _root = null;
    }
    _dirty = 0;
  }

  /// Writes the copied nodes back; returns the root page and nonce (0, 0: empty).
  (int, int) commit() {
    _writeOut();
    if (_rewriteAll) {
      _rewriteAll = false;
      if (_rootPage != 0) {
        final at = _rewrite(_rootPage, _rootNonce, 0);
        _rootPage = at.$1;
        _rootNonce = at.$2;
      }
    }
    if (_rootPage == 0) _rootNonce = 0;
    return (_rootPage, _rootNonce);
  }

  (int, int) _rewrite(int page, int nonce, int depth) {
    if (depth > 64) {
      throw CorruptionException('R-tree $treeId is deeper than 64 levels');
    }
    final node = _read(page, nonce);
    store.free(page);
    if (!node.leaf) {
      for (final s in node.e) {
        final at = _rewrite(s.r, s.nonce, depth + 1);
        s.r = at.$1;
        s.nonce = at.$2;
      }
    }
    return _writePage(node);
  }

  (int, int) _write(_RNode node) {
    if (!node.leaf) {
      for (final s in node.e) {
        final k = s.kid;
        if (k != null) {
          final at = _write(k);
          s.r = at.$1;
          s.nonce = at.$2;
          s.kid = null;
        }
      }
    }
    return _writePage(node);
  }

  (int, int) _writePage(_RNode node) {
    final n = RTreeNode(node.leaf, dimensions, [
      for (final s in node.e)
        node.leaf
            ? RTreeEntry(s.box, docId: s.r)
            : RTreeEntry(s.box,
                childPage: s.r, childEntries: s.cnt, childNonce: s.nonce)
    ]);
    final id = store.alloc();
    store.write(id, n.encode(store.pageSize, treeId: treeId));
    return (id, store.writtenNonce);
  }

  // -------------------------------------------------------------------------
  // Queries — §4, phase one: candidates by box
  // -------------------------------------------------------------------------

  /// Candidate document ids whose **box** meets [box]. Phase one.
  List<int> candidates(Envelope box) {
    final out = <int>[];
    void walk(_RNode n, int depth) {
      if (depth > 64) {
        throw CorruptionException('R-tree $treeId is deeper than 64 levels');
      }
      for (final s in n.e) {
        if (!s.box.intersects(box)) continue;
        if (n.leaf) {
          out.add(s.r);
        } else {
          walk(s.kid ?? _read(s.r, s.nonce), depth + 1);
        }
      }
    }

    final r = _rootView;
    if (r != null) walk(r, 0);
    return out;
  }

  /// Best-first search over box distances, §4's `nearest_k`: a subtree
  /// further than the k-th best entry is never opened. Candidates only.
  List<int> nearest(List<double> point, int k) {
    final out = <int>[];
    final r = _rootView;
    if (r == null || k <= 0) return out;
    // (distance, isEntry, id or page, nonce, held node)
    final heap = MinHeap<(double, bool, int, int, _RNode?)>(
        (a, b) => a.$1.compareTo(b.$1));
    heap.add((0, false, 0, 0, r));
    while (heap.isNotEmpty && out.length < k) {
      final top = heap.removeFirst();
      if (top.$2) {
        out.add(top.$3);
        continue;
      }
      final node = top.$5 ?? _read(top.$3, top.$4);
      for (final s in node.e) {
        final d = s.box.squaredDistanceTo(point);
        heap.add(node.leaf ? (d, true, s.r, 0, null) : (d, false, s.r, s.nonce, s.kid));
      }
    }
    return out;
  }

  /// §2.2's structural invariants over the published tree, for a verifier.
  List<String> verify() {
    final problems = <String>[];
    if (_rootPage == 0) return problems;
    final depths = <int>{};

    Envelope walk(int page, int nonce, int depth) {
      final n = RTreeNode.decode(store.readBound(page, nonce),
          expectedDimensions: dimensions);
      if (n.isLeaf) {
        depths.add(depth);
        return n.box;
      }
      var union = Envelope.empty(dimensions);
      for (final e in n.entries) {
        final actual = walk(e.childPage, e.childNonce, depth + 1);
        for (var i = 0; i < dimensions; i++) {
          if (e.box.min[i] != actual.min[i] || e.box.max[i] != actual.max[i]) {
            problems.add(
                'page $page entry box is not the exact union of its child: '
                'declared ${e.box}, actual $actual');
            break;
          }
        }
        union = union.union(actual);
      }
      return union;
    }

    walk(_rootPage, _rootNonce, 0);
    if (depths.length > 1) {
      problems.add('leaves are at depths $depths; all must be at one depth');
    }
    return problems;
  }
}

/// A spatial index bound to a collection, `08-spatial.md` §2 and §4. The
/// [Database] holds it, so the engine's commit writes its copied nodes back
/// and republishes its root (Java's commit hook).
///
/// Every query is **two-phase**, which §4 makes normative: candidates by box,
/// then the exact predicate on the document's geometry.
final class SpatialIndex {
  SpatialIndex(this.db, this.name, TreeDescriptor d)
      : descriptor = d,
        owner = d.owner ?? '',
        field = d.paramStr('field') ??
            (throw CorruptionException('spatial index "$name" has no params.field')),
        dimensions = (d.param('dimensions') as CInt?)?.magnitude.lo ?? 2,
        srid = (d.param('srid') as CInt?)?.magnitude.lo {
    if (dimensions < 2 || dimensions > 4) {
      throw CorruptionException('spatial index "$name" declares $dimensions dimensions');
    }
    tree = RTree(db.engine.store,
        dimensions: dimensions,
        treeId: d.treeId,
        root: d.root ?? 0,
        rootNonce: d.rootNonce);
  }

  final Database db;
  final String name;
  final String owner;
  final String field;
  final int dimensions;
  final int? srid;
  TreeDescriptor descriptor;
  late final RTree tree;
  Collection? _owner;

  int get size => tree.size;

  List<Uint8List> _geometries(CDoc doc) => [
        for (final v in resolvePath(doc, field) ?? const <CValue>[])
          if (v is CGeometry) v.wkb
      ];

  List<Envelope> _boxes(CDoc doc) => [
        for (final w in _geometries(doc)) decodeWkb(w).envelope(dims: dimensions)
      ];

  /// Indexes [doc]'s geometry field; [previous], the document it replaces,
  /// names the entries to retract (an R-tree removal needs the box).
  void put(int docId, CDoc doc, CDoc? previous, {int? declaredSrid}) {
    final s = srid;
    if (declaredSrid != null && s != null && declaredSrid != s) {
      throw InvalidArgumentException(
          'geometry declares SRID $declaredSrid but index $name works in SRID '
          '$s; the format does not reproject (spec/08-spatial.md section 1)');
    }
    final boxes = _boxes(doc);
    remove(docId, previous);
    for (final b in boxes) {
      tree.insert(b, docId);
    }
  }

  void remove(int docId, CDoc? previous) {
    if (previous == null) return;
    for (final b in _boxes(previous)) {
      tree.remove(b, docId);
    }
  }

  /// Writes the copied nodes back and republishes the root; the engine's
  /// commit runs it before the catalog is published.
  void commit() {
    final (root, nonce) = tree.commit();
    final d = descriptor;
    final entries = (d.doc.fields['entries'] as CInt?)?.magnitude.lo ?? 0;
    if (d.root != root || d.rootNonce != nonce || entries != tree.size) {
      descriptor = d
          .withRoot(root, nonce)
          .with_({'entries': CInt.of(NumType.u64, tree.size)});
      db.catalog.put(name, descriptor);
    }
  }

  Geometry? _geometryOf(int docId) {
    final doc = (_owner ??= db.collection(owner))?.get(CNitriteId(docId));
    if (doc == null) return null;
    final gs = _geometries(doc);
    return gs.isEmpty ? null : decodeWkb(gs.first);
  }

  List<int> _exact(Envelope box, bool Function(Geometry g) predicate) {
    final out = <int>[];
    for (final id in tree.candidates(box)) {
      // §4: "An implementation MUST NOT return box-level results as if they
      // were exact."
      final g = _geometryOf(id);
      if (g != null && predicate(g)) out.add(id);
    }
    return out;
  }

  List<int> intersects(Geometry q) =>
      _exact(q.envelope(dims: dimensions), (g) => Spatial.intersects(g, q));

  /// The document's geometry lies inside [q].
  List<int> within(Geometry q) =>
      _exact(q.envelope(dims: dimensions), (g) => Spatial.within(g, q));

  /// The document's geometry contains [q].
  List<int> contains(Geometry q) =>
      _exact(q.envelope(dims: dimensions), (g) => Spatial.contains(g, q));

  List<int> near(Coord centre, double radius) {
    final box = Envelope(
      [for (var i = 0; i < dimensions; i++) i < 2 ? centre.axis(i) : double.negativeInfinity],
      [for (var i = 0; i < dimensions; i++) i < 2 ? centre.axis(i) : double.infinity],
    ).expandedBy(radius);
    return _exact(box, (g) => Spatial.withinDistance(g, centre, radius));
  }

  /// The k nearest by exact distance, nearest first. Box distance is a lower
  /// bound on the geometry's, so the candidates are widened before ranking.
  List<(int, double)> nearestK(Coord centre, int k) {
    final cands =
        tree.nearest([centre.x, centre.y], math.max(k * 4, k + 8));
    final probe = Geometry(
        type: GeometryType.point, hasZ: false, hasM: false, coords: [centre]);
    final ranked = <(int, double)>[];
    for (final id in cands) {
      final g = _geometryOf(id);
      if (g != null) ranked.add((id, Spatial.distance(g, probe)));
    }
    ranked.sort((a, b) => a.$2.compareTo(b.$2));
    return ranked.take(k).toList();
  }
}

/// A binary min-heap (no package dependency).
final class MinHeap<T> {
  MinHeap(this._cmp);
  final int Function(T a, T b) _cmp;
  final List<T> _a = [];

  int get length => _a.length;
  bool get isEmpty => _a.isEmpty;
  bool get isNotEmpty => _a.isNotEmpty;
  T get first => _a.first;

  void add(T v) {
    _a.add(v);
    var i = _a.length - 1;
    while (i > 0) {
      final p = (i - 1) >> 1;
      if (_cmp(_a[i], _a[p]) >= 0) break;
      final t = _a[i];
      _a[i] = _a[p];
      _a[p] = t;
      i = p;
    }
  }

  T removeFirst() {
    final top = _a.first;
    final last = _a.removeLast();
    if (_a.isNotEmpty) {
      _a[0] = last;
      var i = 0;
      while (true) {
        final l = 2 * i + 1, r = l + 1;
        var m = i;
        if (l < _a.length && _cmp(_a[l], _a[m]) < 0) m = l;
        if (r < _a.length && _cmp(_a[r], _a[m]) < 0) m = r;
        if (m == i) break;
        final t = _a[i];
        _a[i] = _a[m];
        _a[m] = t;
        i = m;
      }
    }
    return top;
  }

  /// The elements, in no order.
  List<T> toList() => List.of(_a);
}
