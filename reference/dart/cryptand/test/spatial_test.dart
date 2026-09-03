/// `spec/08-spatial.md` — WKB geometry and the in-container R-tree.
///
/// The chapter replaces three geometry representations and two R-trees with
/// one of each. The two rules that would silently corrupt or silently mislead
/// are tested first: EWKB rejection (§1) and the two-phase query rule (§4).
library;

import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

Geometry point(double x, double y) => Geometry(
    type: GeometryType.point, hasZ: false, hasM: false, coords: [Coord(x, y)]);

Geometry box(double x1, double y1, double x2, double y2) => Geometry(
      type: GeometryType.polygon,
      hasZ: false,
      hasM: false,
      rings: [
        [Coord(x1, y1), Coord(x2, y1), Coord(x2, y2), Coord(x1, y2), Coord(x1, y1)]
      ],
    );

Geometry line(List<(double, double)> pts) => Geometry(
    type: GeometryType.lineString,
    hasZ: false,
    hasM: false,
    coords: [for (final p in pts) Coord(p.$1, p.$2)]);

void main() {
  group('WKB, section 1', () {
    test('a point round-trips, little-endian as a writer must emit', () {
      final wkb = encodeWkb(point(30, 10));
      expect(wkb[0], 1, reason: 'little-endian byte order marker');
      final back = decodeWkb(wkb);
      expect(back.type, GeometryType.point);
      expect(back.coords.single.x, 30);
      expect(back.coords.single.y, 10);
    });

    test('a reader accepts big-endian even though a writer must not emit it',
        () {
      // Section 1: "a writer MUST emit little-endian; a reader MUST accept
      // both."
      final be = BytesBuilder()
        ..add([0x00]) // big-endian marker
        ..add((ByteData(4)..setUint32(0, 1, Endian.big)).buffer.asUint8List())
        ..add((ByteData(8)..setFloat64(0, 30, Endian.big)).buffer.asUint8List())
        ..add((ByteData(8)..setFloat64(0, 10, Endian.big)).buffer.asUint8List());
      final g = decodeWkb(be.takeBytes());
      expect(g.coords.single.x, 30);
      expect(g.coords.single.y, 10);
    });

    test('EWKB is REJECTED — the ambiguity that reads coordinates as garbage',
        () {
      // Section 1: "a PointZ is 1001 in ISO and 0x80000001 in EWKB, and a
      // decoder that guesses wrong reads coordinates as garbage. A reader MUST
      // reject a type word with any of those three bits set."
      for (final flag in [EwkbFlags.z, EwkbFlags.m, EwkbFlags.srid]) {
        final ewkb = BytesBuilder()
          ..add([0x01])
          ..add((ByteData(4)..setUint32(0, 1 | flag, Endian.little))
              .buffer
              .asUint8List())
          ..add((ByteData(8)..setFloat64(0, 1, Endian.little)).buffer.asUint8List())
          ..add((ByteData(8)..setFloat64(0, 2, Endian.little)).buffer.asUint8List());
        expect(() => decodeWkb(ewkb.takeBytes()),
            throwsA(predicate((e) =>
                e is CorruptionException && e.message.contains('EWKB'))),
            reason: 'flag 0x${flag.toRadixString(16)}');
      }
    });

    test('ISO Z, M and ZM are additive and round-trip', () {
      // Section 1: Z, M and ZM "are encoded the ISO way — by adding 1000 (Z),
      // 2000 (M) or 3000 (ZM) to the base geometry type code."
      final pz = Geometry(
          type: GeometryType.point,
          hasZ: true,
          hasM: false,
          coords: [const Coord(1, 2, z: 3)]);
      final wkb = encodeWkb(pz);
      final typeWord = ByteData.view(wkb.buffer).getUint32(1, Endian.little);
      expect(typeWord, 1001);
      final back = decodeWkb(wkb);
      expect(back.hasZ, isTrue);
      expect(back.hasM, isFalse);
      expect(back.coords.single.z, 3);

      final pzm = Geometry(
          type: GeometryType.point,
          hasZ: true,
          hasM: true,
          coords: [const Coord(1, 2, z: 3, m: 4)]);
      expect(ByteData.view(encodeWkb(pzm).buffer).getUint32(1, Endian.little),
          3001);
      expect(decodeWkb(encodeWkb(pzm)).coords.single.m, 4);
    });

    test('polygons with holes and nested collections round-trip', () {
      final poly = Geometry(
        type: GeometryType.polygon,
        hasZ: false,
        hasM: false,
        rings: [
          [const Coord(0, 0), const Coord(10, 0), const Coord(10, 10),
           const Coord(0, 10), const Coord(0, 0)],
          [const Coord(3, 3), const Coord(6, 3), const Coord(6, 6),
           const Coord(3, 6), const Coord(3, 3)],
        ],
      );
      expect(decodeWkb(encodeWkb(poly)).rings.length, 2);

      final coll = Geometry(
          type: GeometryType.geometryCollection,
          hasZ: false,
          hasM: false,
          parts: [point(1, 1), poly, line([(0, 0), (5, 5)])]);
      final back = decodeWkb(encodeWkb(coll));
      expect(back.parts.length, 3);
      expect(back.parts[1].rings.length, 2);
    });

    test('trailing bytes and truncation are corruption', () {
      final wkb = encodeWkb(point(1, 2));
      expect(() => decodeWkb(Uint8List.fromList([...wkb, 0])),
          throwsA(isA<CorruptionException>()));
      expect(() => decodeWkb(wkb.sublist(0, wkb.length - 2)),
          throwsA(isA<CorruptionException>()));
    });

    test('an empty geometry has the +Inf/-Inf envelope section 2.1 specifies',
        () {
      final empty = Geometry(
          type: GeometryType.lineString, hasZ: false, hasM: false, coords: []);
      final e = empty.envelope();
      expect(e.isEmpty, isTrue);
      expect(e.min[0], double.infinity);
      expect(e.max[0], double.negativeInfinity);
      expect(e.intersects(box(0, 0, 10, 10).envelope()), isFalse);
    });
  });

  group('the R-tree page format, section 2.1', () {
    test('entry strides are exactly what the table says', () {
      // Internal: 16 x dimensions + 16. Leaf: 16 x dimensions + 8.
      expect(entryStride(2, false), 48);
      expect(entryStride(2, true), 40);
      expect(entryStride(3, false), 64);
      expect(entryStride(4, true), 72);
    });

    test('a node round-trips through its page', () {
      final n = RTreeNode(true, 2, [
        RTreeEntry(Envelope([0, 0], [1, 1]), docId: 7),
        RTreeEntry(Envelope([2, 2], [3, 3]), docId: 9),
      ]);
      final back = RTreeNode.decode(n.encode(4096));
      expect(back.isLeaf, isTrue);
      expect(back.dimensions, 2);
      expect(back.entries.length, 2);
      expect(back.entries[1].docId, 9);
      expect(back.entries[0].box.max[0], 1);
      expect(back.subtreeEntries, 2);
    });

    test('a page whose dimensions disagree with the descriptor is rejected',
        () {
      // Section 3: "A reader MUST use the page's own dimensions field and MUST
      // reject a page whose dimensions disagrees with the descriptor."
      final n = RTreeNode(true, 2, [RTreeEntry(Envelope([0, 0], [1, 1]), docId: 1)]);
      final page = n.encode(4096);
      expect(() => RTreeNode.decode(page, expectedDimensions: 3),
          throwsA(isA<CorruptionException>()));
      expect(() => RTreeNode.decode(page, expectedDimensions: 2),
          returnsNormally);
    });

    test('a node too large for its page is refused', () {
      final many = [
        for (var i = 0; i < 200; i++)
          RTreeEntry(Envelope([i.toDouble(), 0], [i + 1.0, 1]), docId: i)
      ];
      expect(() => RTreeNode(true, 2, many).encode(4096),
          throwsA(isA<LimitException>()));
    });
  });

  group('queries, section 4 — the two-phase rule', () {
    late RTree t;

    setUp(() {
      t = RTree(PageStore(), dimensions: 2);
      // A diagonal line of points.
      for (var i = 0; i < 50; i++) {
        t.insert(i, point(i.toDouble(), i.toDouble()));
      }
      // A triangle whose BOX covers the origin but whose AREA does not — this
      // is the shape that separates a box result from an exact one.
      t.insert(100, Geometry(
        type: GeometryType.polygon,
        hasZ: false,
        hasM: false,
        rings: [
          [const Coord(0, 10), const Coord(10, 10), const Coord(10, 0),
           const Coord(0, 10)]
        ],
      ));
    });

    test('the R-tree stays structurally valid as it splits', () {
      // Section 2.2: all leaves at one depth, and every internal box the
      // EXACT union of its children.
      expect(t.verify(), isEmpty);
      final many = RTree(PageStore(), dimensions: 2);
      for (var i = 0; i < 500; i++) {
        many.insert(i, point((i * 37 % 500).toDouble(), (i * 91 % 500).toDouble()));
      }
      expect(many.verify(), isEmpty);
    });

    test('a box candidate that fails the exact predicate is NOT returned', () {
      // Section 4: "An implementation MUST NOT return box-level results as if
      // they were exact." The triangle's bounding box contains (1,1); the
      // triangle itself does not.
      final probe = point(1, 1);
      expect(t.candidates(probe.envelope()), contains(100),
          reason: 'phase one: the box does match');
      expect(t.intersects(probe), isNot(contains(100)),
          reason: 'phase two: the geometry does not');
      expect(t.intersects(probe), contains(1),
          reason: 'the point at (1,1) is a real hit');
    });

    test('intersects, within and contains', () {
      final area = box(5, 5, 15, 15);
      final hits = t.intersects(area);
      expect(hits, containsAll([5, 6, 7, 8, 9, 10]));
      expect(hits, isNot(contains(0)));

      // within: the document's geometry lies inside the query.
      expect(t.within(box(-1, -1, 3.5, 3.5)), [0, 1, 2, 3]);

      // contains: the document's geometry contains the query point.
      expect(t.contains(point(6, 8)), [100],
          reason: 'only the triangle contains that point');
    });

    test('near returns exactly what is inside the radius', () {
      final hits = t.near(const Coord(0, 0), 5);
      // Points at (i,i) are at distance i*sqrt(2): 0, 1.41, 2.83, 4.24, 5.66…
      expect(hits, containsAll([0, 1, 2, 3]));
      expect(hits, isNot(contains(4)), reason: '4*sqrt(2) = 5.66 > 5');
    });

    test('nearest_k is ordered and uses exact distances', () {
      final k = t.nearestK(const Coord(0, 0), 4);
      expect(k.length, 4);
      expect(k.map((e) => e.$1).take(3), [0, 1, 2]);
      for (var i = 1; i < k.length; i++) {
        expect(k[i].$2, greaterThanOrEqualTo(k[i - 1].$2),
            reason: 'ordered nearest first');
      }
      expect(k.first.$2, 0.0);
    });

    test('an empty tree answers every query without failing', () {
      final e = RTree(PageStore());
      expect(e.intersects(point(0, 0)), isEmpty);
      expect(e.nearestK(const Coord(0, 0), 5), isEmpty);
      expect(e.verify(), isEmpty);
    });
  });

  group('exact predicates', () {
    test('a point in a polygon with a hole is outside the hole', () {
      final donut = Geometry(
        type: GeometryType.polygon,
        hasZ: false,
        hasM: false,
        rings: [
          [const Coord(0, 0), const Coord(10, 0), const Coord(10, 10),
           const Coord(0, 10), const Coord(0, 0)],
          [const Coord(4, 4), const Coord(6, 4), const Coord(6, 6),
           const Coord(4, 6), const Coord(4, 4)],
        ],
      );
      expect(Spatial.contains(donut, point(1, 1)), isTrue);
      expect(Spatial.contains(donut, point(5, 5)), isFalse,
          reason: 'inside the hole is outside the polygon');
      expect(Spatial.intersects(donut, point(5, 5)), isFalse);
    });

    test('crossing lines intersect, parallel ones do not', () {
      expect(Spatial.intersects(line([(0, 0), (10, 10)]),
          line([(0, 10), (10, 0)])), isTrue);
      expect(Spatial.intersects(line([(0, 0), (10, 0)]),
          line([(0, 5), (10, 5)])), isFalse);
    });

    test('distance is planar Euclidean, and zero when they meet', () {
      expect(Spatial.distance(point(0, 0), point(3, 4)), closeTo(5, 1e-9));
      expect(Spatial.distance(point(0, 0), box(1, 1, 2, 2)),
          closeTo(1.4142135, 1e-6));
      expect(Spatial.distance(point(1.5, 1.5), box(1, 1, 2, 2)), 0);
    });

    test('a multi-geometry is handled part by part', () {
      final multi = Geometry(
          type: GeometryType.multiPoint,
          hasZ: false,
          hasM: false,
          parts: [point(0, 0), point(100, 100)]);
      expect(Spatial.intersects(multi, box(-1, -1, 1, 1)), isTrue);
      expect(Spatial.intersects(multi, box(50, 50, 60, 60)), isFalse);
      expect(Spatial.distance(multi, point(101, 100)), closeTo(1, 1e-9));
    });
  });
}
