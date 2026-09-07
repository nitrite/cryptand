/// `spec/09-vector.md` — the durable layout of a vector index.
///
/// The chapter's principle is what this file tests and what it deliberately
/// does not: "**specify the durable layout, not the algorithm.**" So the region
/// header, the adjacency record, the codebook, the two maps and §8's search
/// contract are all here; recall is not, because §8 says "Recall is not
/// specified. Two conforming implementations may return different neighbours
/// for the same query; ANN is approximate by definition."
library;

import 'dart:convert';
import 'dart:io';

import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

void main() {
  _metrics();
  group('the vector region, section 2', () {
    test('the head page round-trips with its magic and page alignment', () {
      final r = VectorRegion(dim: 8, dtype: RegionDType.f32, slotCount: 100);
      final head = VectorRegionHeader.decode(r.headPage());
      expect(head.dim, 8);
      expect(head.dtype, RegionDType.f32);
      expect(head.slotCount, 100);
      expect(head.dataOffset % 4096, 0,
          reason: 'section 2: data_offset is page-aligned');
      expect(head.nextRegion, 0);
    });

    test('stride pads to a 64-byte boundary for SIMD', () {
      // Section 2: "stride may exceed the natural vector size so slots land on
      // 64-byte boundaries for SIMD. stride >= dim x sizeof(dtype)."
      final r = VectorRegion(dim: 3, dtype: RegionDType.f32, slotCount: 4);
      expect(r.stride, 64);
      expect(r.stride, greaterThanOrEqualTo(3 * 4));
      final wide = VectorRegion(dim: 20, dtype: RegionDType.f32, slotCount: 4);
      expect(wide.stride, 128);
    });

    test('slot 0 is the null pointer and cannot be written', () {
      // Section 2: "Slot 0 of the first region is reserved and never used, so
      // slot_id = 0 is a null pointer."
      final r = VectorRegion(dim: 4, dtype: RegionDType.f32, slotCount: 10);
      expect(VectorRegion.nullSlot, 0);
      expect(() => r.writeVector(0, [1, 2, 3, 4]),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => r.readVector(0), throwsA(isA<InvalidArgumentException>()));
      expect(() => r.writeVector(1, [1, 2, 3, 4]), returnsNormally);
    });

    test('vectors round-trip positionally, with no mmap anywhere', () {
      // Section 2: "An implementation that cannot mmap reads positionally.
      // Dart does exactly this... No part of this format requires mmap."
      final r = VectorRegion(dim: 4, dtype: RegionDType.f32, slotCount: 50);
      for (var i = 1; i < 20; i++) {
        r.writeVector(i, [i * 1.0, i * 2.0, i * 3.0, i * 4.0]);
      }
      for (var i = 1; i < 20; i++) {
        final v = r.readVector(i);
        expect(v[0], closeTo(i * 1.0, 1e-6));
        expect(v[3], closeTo(i * 4.0, 1e-6));
      }
    });

    test('a vector too wide for a u16 stride is refused, with the reason', () {
      // Section 2: "a region's dim x sizeof(dtype) MUST be <= 65535... A model
      // beyond that is served by splitting the vector across two indexes, not
      // by widening the field, because a 64 KiB vector is not an embedding a
      // proximity graph is the right structure for."
      expect(
          () => const VectorRegionHeader(
                  dim: 20000, // 80 000 B at f32
                  dtype: RegionDType.f32,
                  stride: 64,
                  slotCount: 1,
                  liveCount: 0,
                  dataOffset: 4096,
                  nextRegion: 0)
              .encode(4096),
          throwsA(isA<LimitException>()));
      // 16 383 dimensions at f32 is the documented ceiling and fits.
      expect(
          () => VectorRegionHeader(
                  dim: 16383,
                  dtype: RegionDType.f32,
                  stride: 65535,
                  slotCount: 1,
                  liveCount: 0,
                  dataOffset: 4096,
                  nextRegion: 0)
              .encode(4096),
          returnsNormally);
    });

    test('a non-page-aligned data_offset is refused', () {
      expect(
          () => const VectorRegionHeader(
                  dim: 4,
                  dtype: RegionDType.f32,
                  stride: 64,
                  slotCount: 1,
                  liveCount: 0,
                  dataOffset: 100,
                  nextRegion: 0)
              .encode(4096),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('a head page without EXTENT_HEAD is corruption', () {
      final page = VectorRegion(dim: 4, dtype: RegionDType.f32, slotCount: 4)
          .headPage();
      // Clear the EXTENT_HEAD flag and repair the checksum the way a naive
      // editor would.
      final tampered = Uint8List.fromList(page);
      tampered[5] = 0;
      PageHeader(
        pageType: PageType.vectorRegion,
        treeId: TreeId.noTree,
        payloadLen: 64,
      ).writeInto(tampered);
      expect(() => VectorRegionHeader.decode(tampered),
          throwsA(isA<CorruptionException>()));
    });
  });

  group('the adjacency record, section 3', () {
    test('neighbours round-trip in graph order, not sorted order', () {
      // Section 3: "Deltas are zigzag because neighbour ids are not sorted in
      // graph order — a proximity graph's neighbour list is ordered by
      // distance, not by id."
      const a = Adjacency([500, 12, 900, 3, 77]);
      final back = Adjacency.decodeRaw(a.encodeRaw());
      expect(back.neighbours, [500, 12, 900, 3, 77],
          reason: 'the distance ordering survives the delta coding');
      expect(back.degree, 5);
    });

    test('an empty and a single-neighbour record round-trip', () {
      expect(Adjacency.decodeRaw(const Adjacency([]).encodeRaw()).neighbours,
          isEmpty);
      expect(Adjacency.decodeRaw(const Adjacency([42]).encodeRaw()).neighbours,
          [42]);
    });

    test('a typical degree-32 record is under 100 bytes', () {
      // Section 3 says so, and it is the reason the chapter recommends keeping
      // adjacency inline rather than in the value log.
      final a = Adjacency([for (var i = 0; i < 32; i++) 1000 + i * 7]);
      expect(a.encodeRaw().length, lessThan(100));
    });
  });

  group('the codebook, section 4', () {
    test('centroids are stored explicitly and round-trip', () {
      // Section 4: "Centroids are stored explicitly rather than as a training
      // seed, because two implementations running the same k-means on the same
      // data will not produce the same centroids — and if they did not match,
      // an index written by one would be unreadable by the other."
      final c = Codebook(
        kind: Codebook.kindProduct,
        m: 2,
        k: 3,
        subDim: 2,
        centroids: [for (var i = 0; i < 2 * 3 * 2; i++) i * 0.5],
      );
      final back = Codebook.decode(c.encode());
      expect(back.kind, Codebook.kindProduct);
      expect(back.m, 2);
      expect(back.k, 3);
      expect(back.subDim, 2);
      expect(back.centroids.length, 12);
      expect(back.centroids[5], closeTo(2.5, 1e-6));
    });

    test('a centroid count that does not match m x k x sub_dim is refused', () {
      expect(
          () => const Codebook(
                  kind: Codebook.kindProduct,
                  m: 2,
                  k: 3,
                  subDim: 2,
                  centroids: [1, 2, 3])
              .encode(),
          throwsA(isA<InvalidArgumentException>()));
    });
  });

  group('distances, section 5 and section 8', () {
    test('l2, cosine and dot behave as their names say', () {
      expect(vectorDistance([0, 0], [3, 4], VectorMetric.l2), closeTo(5, 1e-9));
      expect(vectorDistance([1, 0], [1, 0], VectorMetric.cosine),
          closeTo(0, 1e-9));
      expect(vectorDistance([1, 0], [0, 1], VectorMetric.cosine),
          closeTo(1, 1e-9));
      // dot is negated so that "smaller is nearer" holds for every metric,
      // which section 8's "ordered nearest first" needs.
      expect(vectorDistance([1, 2], [3, 4], VectorMetric.dot), closeTo(-11, 1e-9));
    });

    test('mismatched dimensions are refused', () {
      expect(() => vectorDistance([1, 2], [1], VectorMetric.l2),
          throwsA(isA<InvalidArgumentException>()));
    });
  });

  group('the index, sections 6 and 8', () {
    VectorIndex build() {
      final idx = VectorIndex(
          region: VectorRegion(dim: 2, dtype: RegionDType.f32, slotCount: 100),
          metric: VectorMetric.l2);
      for (var i = 1; i <= 20; i++) {
        idx.add(i, [i.toDouble(), 0]);
      }
      return idx;
    }

    test('the two maps are exact inverses', () {
      // Section 6: "a verifier checks that they are exact inverses."
      final idx = build();
      expect(idx.verifyMaps(), isEmpty);
      expect(idx.slotToDoc.length, 20);
      expect(idx.docToSlot.length, 20);
    });

    test('search is ordered nearest first with true distances', () {
      final idx = build();
      final r = idx.search([0, 0], 3);
      expect(r.map((e) => e.$1), [1, 2, 3]);
      expect(r[0].$2, closeTo(1, 1e-6));
      expect(r[2].$2, closeTo(3, 1e-6));
      for (var i = 1; i < r.length; i++) {
        expect(r[i].$2, greaterThanOrEqualTo(r[i - 1].$2));
      }
    });

    test('a deleted document disappears IMMEDIATELY, before consolidation', () {
      // Section 6: "A search MUST skip a slot with no document mapping — this
      // is what makes deletes correct immediately even though the graph is
      // repaired later, which is the FreshDiskANN property nitrite-vector
      // already implements."
      final idx = build();
      expect(idx.search([0, 0], 1).single.$1, 1);
      expect(idx.remove(1), isTrue);
      expect(idx.search([0, 0], 1).single.$1, 2,
          reason: 'the deleted document is gone from results at once');
      expect(idx.verifyMaps(), isEmpty,
          reason: 'both mappings were removed, so they stay inverses');
      // The slot itself is still there until consolidation.
      expect(idx.region.readVector(1), isNotEmpty);
    });

    test('a filter excludes documents without breaking the ordering', () {
      final idx = build();
      final r = idx.search([0, 0], 3, filter: (d) => d.isEven);
      expect(r.map((e) => e.$1), [2, 4, 6]);
    });

    test('a foreign algorithm falls back to brute force, never to nothing', () {
      // Section 8: "An implementation MAY refuse to serve a graph built by a
      // different algorithm — but it MUST then fall back to a brute-force scan
      // of the vector region, which is always possible and always correct,
      // rather than returning nothing."
      final idx = build();
      expect(idx.willTraverse('hnsw'), isTrue);
      expect(idx.willTraverse('vamana'), isFalse);
      final r = idx.search([0, 0], 3, bruteForce: true);
      expect(r.map((e) => e.$1), [1, 2, 3],
          reason: 'the fallback is correct, not empty');
    });

    test('entry points live in the descriptor, not in the tree', () {
      // Section 5: "The entry point(s) for a search are in the descriptor, not
      // in the tree, so a search starts with zero tree lookups."
      final idx = build();
      expect(idx.entryPoints, isNotEmpty);
      expect(idx.graph, isEmpty,
          reason: 'no adjacency lookup is needed to start');
    });
  });
}

void _metrics() {
  /// `spec/09-vector.md` section 8.1 — the metrics, numerically.
  ///
  /// Section 5's descriptor names `"cosine" | "l2" | "dot"` and section 8 said
  /// nothing about what they compute. "Ordered nearest first" needs a value
  /// where smaller means closer, and a dot product is a *similarity* — so an
  /// implementation returning it unchanged sorts every result set backwards
  /// while satisfying every other sentence in the chapter. Section 8.1 pins all
  /// three; this is the shared vector for it.
  ///
  /// The `wide_1024` case is the one with teeth: it fails for an implementation
  /// that accumulates in f32 rather than f64.
  group('09 section 8.1 -- the metrics', () {
    final path =
        '${Directory.current.path}/../../conformance/vectors/vector/metrics.json';
    final file = File(path);
    if (!file.existsSync()) {
      test('the metric corpus is present', () => fail('$path does not exist'));
      return;
    }
    final doc = jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
    final tol = (doc['tolerance']! as num).toDouble();
    final cases = (doc['cases']! as List).cast<Map<String, Object?>>();

    test('every published metric value is reproduced', () {
      expect(cases.length, greaterThanOrEqualTo(8));
      for (final c in cases) {
        List<double> v(String k) =>
            (c[k]! as List).map((x) => (x as num).toDouble()).toList();
        final a = v('a');
        final b = v('b');
        for (final metric in ['l2', 'dot', 'cosine']) {
          final want = (c[metric]! as num).toDouble();
          final got = vectorDistance(a, b, metric);
          expect((got - want).abs() <= tol, isTrue,
              reason: '${c['name']}/$metric: want $want, got $got '
                  '(delta ${(got - want).abs()}, tolerance $tol)\n'
                  '  ${c['note']}');
        }
      }
    });
  });
}
