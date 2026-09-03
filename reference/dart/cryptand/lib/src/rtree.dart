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

import 'container.dart';
import 'cow.dart';
import 'errors.dart';
import 'geometry_ops.dart';
import 'wkb.dart';

/// §2.1 node flags.
class RTreeFlags {
  static const int isLeaf = 0x01;
}

/// One entry of an R-tree node.
final class RTreeEntry {
  const RTreeEntry(this.box, {this.childPage = 0, this.childEntries = 0, this.docId = 0});

  final Envelope box;

  /// Internal entries only.
  final int childPage;
  final int childEntries;

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
          ..setUint64(after + 8, e.childEntries, Endian.little);
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
              childEntries: bd.getUint64(after + 8, Endian.little)));
      off += stride;
    }
    return RTreeNode(isLeaf, dims, entries);
  }
}

/// §2.1: internal entries are `16 × dimensions + 16` bytes, leaf entries
/// `16 × dimensions + 8`.
int entryStride(int dimensions, bool isLeaf) =>
    16 * dimensions + (isLeaf ? 8 : 16);

/// The maximum entries a page holds at a given shape.
int maxEntriesFor(int pageSize, int dimensions, bool isLeaf) =>
    (pageSize - PageHeader.size - 16) ~/ entryStride(dimensions, isLeaf);

/// One document's spatial entry.
final class SpatialEntry {
  const SpatialEntry(this.docId, this.geometry);
  final int docId;
  final Geometry geometry;
}

/// An R-tree over a [PageStore], rooted from its catalog descriptor.
final class RTree {
  RTree(this.store, {this.dimensions = 2, this.treeId = TreeId.noTree, int? maxEntries})
      : maxEntries = maxEntries ??
            math.min(maxEntriesFor(store.pageSize, dimensions, true),
                maxEntriesFor(store.pageSize, dimensions, false));

  final PageStore store;
  final int dimensions;
  final int treeId;

  /// §2.2: "`max_entries` is a writer's choice; a reader MUST handle any node
  /// population from 1 to what the page holds."
  final int maxEntries;

  int root = 0;

  /// The document geometries, by id. §4's second phase needs the geometry
  /// itself, and the R-tree stores only boxes.
  final Map<int, Geometry> geometries = {};

  int get _minEntries => math.max(2, maxEntries ~/ 2);

  RTreeNode _load(int page) =>
      RTreeNode.decode(store.read(page), expectedDimensions: dimensions);

  int _write(RTreeNode n) {
    final id = store.alloc();
    store.write(id, n.encode(store.pageSize, treeId: treeId));
    return id;
  }

  // -------------------------------------------------------------------------
  // Insertion
  // -------------------------------------------------------------------------

  void insert(int docId, Geometry g) {
    geometries[docId] = g;
    final box = g.envelope(dims: dimensions);
    final entry = RTreeEntry(box, docId: docId);

    if (root == 0) {
      root = _write(RTreeNode(true, dimensions, [entry]));
      return;
    }
    final split = _insert(root, entry, 0);
    if (split != null) {
      // The root split, so the tree grows a level.
      root = _write(RTreeNode(false, dimensions, [
        RTreeEntry(split.$1.box,
            childPage: _write(split.$1), childEntries: split.$1.subtreeEntries),
        RTreeEntry(split.$2.box,
            childPage: _write(split.$2), childEntries: split.$2.subtreeEntries),
      ]));
    }
  }

  /// Returns the two halves when [page] split, else null. The node at [page] is
  /// rewritten in place (a fresh page id — the store is append-only).
  (RTreeNode, RTreeNode)? _insert(int page, RTreeEntry entry, int depth) {
    final node = _load(page);
    if (node.isLeaf) {
      node.entries.add(entry);
      if (node.entries.length <= maxEntries) {
        store.write(page, node.encode(store.pageSize, treeId: treeId));
        return null;
      }
      return _split(node);
    }

    final i = _chooseSubtree(node, entry.box);
    final child = node.entries[i];
    final split = _insert(child.childPage, entry, depth + 1);

    if (split == null) {
      final updated = _load(child.childPage);
      node.entries[i] = RTreeEntry(updated.box,
          childPage: child.childPage, childEntries: updated.subtreeEntries);
    } else {
      node.entries[i] = RTreeEntry(split.$1.box,
          childPage: _write(split.$1), childEntries: split.$1.subtreeEntries);
      node.entries.add(RTreeEntry(split.$2.box,
          childPage: _write(split.$2), childEntries: split.$2.subtreeEntries));
    }

    if (node.entries.length <= maxEntries) {
      store.write(page, node.encode(store.pageSize, treeId: treeId));
      return null;
    }
    return _split(node);
  }

  /// Least enlargement, ties broken by smaller area — the classic rule.
  int _chooseSubtree(RTreeNode node, Envelope box) {
    var best = 0;
    var bestEnlargement = double.infinity;
    var bestArea = double.infinity;
    for (var i = 0; i < node.entries.length; i++) {
      final b = node.entries[i].box;
      final enlargement = b.union(box).area - b.area;
      if (enlargement < bestEnlargement ||
          (enlargement == bestEnlargement && b.area < bestArea)) {
        best = i;
        bestEnlargement = enlargement;
        bestArea = b.area;
      }
    }
    return best;
  }

  /// Quadratic split. §2.2: the algorithm is a writer's choice, and this is one
  /// valid choice — "R*-tree, quadratic, linear and Hilbert-ordered bulk
  /// loading all produce valid trees".
  (RTreeNode, RTreeNode) _split(RTreeNode node) {
    final all = [...node.entries];
    var seedA = 0, seedB = 1;
    var worst = double.negativeInfinity;
    for (var i = 0; i < all.length; i++) {
      for (var j = i + 1; j < all.length; j++) {
        final d = all[i].box.union(all[j].box).area -
            all[i].box.area -
            all[j].box.area;
        if (d > worst) {
          worst = d;
          seedA = i;
          seedB = j;
        }
      }
    }

    final a = <RTreeEntry>[all[seedA]];
    final b = <RTreeEntry>[all[seedB]];
    var boxA = all[seedA].box, boxB = all[seedB].box;
    final rest = [
      for (var i = 0; i < all.length; i++)
        if (i != seedA && i != seedB) all[i]
    ];

    for (final e in rest) {
      // Keep both halves above the minimum fill.
      if (a.length + rest.length - rest.indexOf(e) == _minEntries) {
        a.add(e);
        boxA = boxA.union(e.box);
        continue;
      }
      if (b.length + rest.length - rest.indexOf(e) == _minEntries) {
        b.add(e);
        boxB = boxB.union(e.box);
        continue;
      }
      final growA = boxA.union(e.box).area - boxA.area;
      final growB = boxB.union(e.box).area - boxB.area;
      if (growA < growB || (growA == growB && boxA.area <= boxB.area)) {
        a.add(e);
        boxA = boxA.union(e.box);
      } else {
        b.add(e);
        boxB = boxB.union(e.box);
      }
    }
    return (
      RTreeNode(node.isLeaf, dimensions, a),
      RTreeNode(node.isLeaf, dimensions, b)
    );
  }

  // -------------------------------------------------------------------------
  // Queries — §4
  // -------------------------------------------------------------------------

  /// Candidate document ids whose **box** meets [box]. Phase one.
  List<int> candidates(Envelope box) {
    final out = <int>[];
    if (root == 0) return out;
    void walk(int page) {
      final n = _load(page);
      for (final e in n.entries) {
        if (!e.box.intersects(box)) continue;
        if (n.isLeaf) {
          out.add(e.docId);
        } else {
          walk(e.childPage);
        }
      }
    }

    walk(root);
    return out;
  }

  /// `intersects(g)` — §4, both phases.
  List<int> intersects(Geometry g) => _exact(
      g.envelope(dims: dimensions), (d) => Spatial.intersects(geometries[d]!, g));

  /// `within(g)` — the document's geometry lies inside [g].
  List<int> within(Geometry g) => _exact(
      g.envelope(dims: dimensions), (d) => Spatial.within(geometries[d]!, g));

  /// `contains(g)` — the document's geometry contains [g].
  List<int> contains(Geometry g) => _exact(
      g.envelope(dims: dimensions), (d) => Spatial.contains(geometries[d]!, g));

  /// `near(point, radius)` — §4.
  List<int> near(Coord centre, double radius) {
    final box = Envelope(
      [for (var i = 0; i < dimensions; i++) centre.axis(i)],
      [for (var i = 0; i < dimensions; i++) centre.axis(i)],
    ).expandedBy(radius);
    return _exact(box, (d) => Spatial.withinDistance(geometries[d]!, centre, radius));
  }

  /// `nearest_k(point, k)` — §4's best-first search over node distances.
  List<(int, double)> nearestK(Coord centre, int k) {
    if (root == 0 || k <= 0) return const [];
    final p = [for (var i = 0; i < dimensions; i++) centre.axis(i)];
    final queue = <(double, int, bool, int)>[]; // (dist2, page|doc, isLeafEntry, doc)
    final results = <(int, double)>[];

    void push(double d, int page, bool isDoc, int doc) {
      queue.add((d, page, isDoc, doc));
      queue.sort((x, y) => x.$1.compareTo(y.$1));
    }

    push(0, root, false, 0);
    final probe =
        Geometry(type: GeometryType.point, hasZ: false, hasM: false, coords: [centre]);

    while (queue.isNotEmpty && results.length < k) {
      final item = queue.removeAt(0);
      if (item.$3) {
        results.add((item.$4, item.$1));
        continue;
      }
      final n = _load(item.$2);
      for (final e in n.entries) {
        if (n.isLeaf) {
          // The exact distance, not the box distance: §4's two-phase rule
          // applies to nearest_k as much as to intersects.
          push(Spatial.distance(geometries[e.docId]!, probe), 0, true, e.docId);
        } else {
          push(math.sqrt(e.box.squaredDistanceTo(p)), e.childPage, false, 0);
        }
      }
    }
    return results;
  }

  List<int> _exact(Envelope box, bool Function(int docId) predicate) {
    final out = <int>[];
    for (final d in candidates(box)) {
      // §4: "An implementation MUST NOT return box-level results as if they
      // were exact."
      if (geometries.containsKey(d) && predicate(d)) out.add(d);
    }
    out.sort();
    return out;
  }

  /// §2.2's structural invariants, for a verifier.
  List<String> verify() {
    final problems = <String>[];
    if (root == 0) return problems;
    final depths = <int>{};

    Envelope walk(int page, int depth) {
      final n = _load(page);
      if (n.isLeaf) {
        depths.add(depth);
        return n.box;
      }
      var union = Envelope.empty(dimensions);
      for (final e in n.entries) {
        final actual = walk(e.childPage, depth + 1);
        // §2.2: "Every internal entry's box is the exact union of its child's
        // boxes. A verifier checks this; a box that is merely a superset is a
        // defect because it silently degrades every query."
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

    walk(root, 0);
    if (depths.length > 1) {
      problems.add('leaves are at depths $depths; all must be at one depth');
    }
    return problems;
  }
}
