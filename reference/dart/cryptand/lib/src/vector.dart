/// The vector index — `spec/09-vector.md`.
///
/// The chapter's design principle is the reason this file is short where a
/// vector database would be long:
///
/// > "**specify the durable layout, not the algorithm.** A proximity graph is a
/// > flat vector region plus an adjacency list per node. How an implementation
/// > searches or builds that graph is its own business, as long as the recall
/// > it achieves is a quality question and not a correctness one."
///
/// So what is implemented here is the layout — the `VECTOR_REGION` extent (§2),
/// the adjacency record (§3), the codebook (§4) and the slot↔document maps
/// (§6) — plus the search contract of §8, whose fallback is the part that makes
/// interchange work at all: an implementation that will not traverse a graph
/// some other SDK built "MUST then fall back to a brute-force scan of the
/// vector region, which is always possible and always correct, rather than
/// returning nothing".
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'bytes.dart';
import 'container.dart';
import 'errors.dart';
import 'limits.dart';

/// §2's region `dtype`.
///
/// Distinct from `value.dart`'s [VectorDType], which is the CVE `VECTOR` value
/// dtype of `02-value-encoding.md` §6: that one has no PQ-code width, because a
/// document field holds a vector and never a quantized code.
class RegionDType {
  static const int f32 = 0;
  static const int f16 = 1;
  static const int i8 = 2;

  /// PQ codes.
  static const int u8 = 3;

  static int naturalSize(int dtype) => switch (dtype) {
        f32 => 4,
        f16 => 2,
        i8 => 1,
        u8 => 1,
        _ => throw InvalidArgumentException('unknown dtype $dtype'),
      };
}

/// §5's `metric`.
class VectorMetric {
  static const String cosine = 'cosine';
  static const String l2 = 'l2';
  static const String dot = 'dot';
}

/// The `VECTOR_REGION` head-page header, §2.
final class VectorRegionHeader {
  const VectorRegionHeader({
    required this.dim,
    required this.dtype,
    required this.stride,
    required this.slotCount,
    required this.liveCount,
    required this.dataOffset,
    required this.nextRegion,
  });

  static const List<int> magic = [0x43, 0x52, 0x59, 0x5F, 0x56, 0x45, 0x43, 0x1A];

  final int dim;
  final int dtype;

  /// §2: "`stride` may exceed the natural vector size so slots land on 64-byte
  /// boundaries for SIMD."
  final int stride;

  final int slotCount;
  final int liveCount;

  /// §2: "`data_offset` is page-aligned", which is what lets an implementation
  /// that can `mmap` read vectors as slices with no copy.
  final int dataOffset;

  final int nextRegion;

  Uint8List encode(int pageSize) {
    final natural = dim * RegionDType.naturalSize(dtype);
    // §2: "`stride` is a `u16`, so a region's `dim × sizeof(dtype)` MUST be
    // ≤ 65535 — 16383 dimensions at f32... A model beyond that is served by
    // splitting the vector across two indexes, not by widening the field."
    if (natural > 0xFFFF) {
      throw LimitException(
          'dim $dim at dtype $dtype needs $natural B per vector, over the '
          '65535 B a u16 stride can address (spec/09-vector.md section 2)');
    }
    if (stride < natural) {
      throw InvalidArgumentException(
          'stride $stride is below the natural size $natural');
    }
    if (dataOffset % pageSize != 0) {
      throw InvalidArgumentException(
          'data_offset $dataOffset is not page-aligned; section 2 requires it '
          'so a region can be mapped and sliced without copying');
    }

    final page = Uint8List(pageSize);
    final w = ByteWriter(64)
      ..bytes(magic)
      ..u32(dim)
      ..u8(dtype)
      ..u8(0)
      ..u16(stride)
      ..u64(slotCount)
      ..u64(liveCount)
      ..u64(dataOffset)
      ..u64(nextRegion)
      ..bytes(Uint8List(16));
    page.setRange(PageHeader.size, PageHeader.size + w.length, w.view);
    PageHeader(
      pageType: PageType.vectorRegion,
      flags: PageFlags.extentHead,
      treeId: TreeId.noTree,
      payloadLen: w.length,
    ).writeInto(page);
    return page;
  }

  static VectorRegionHeader decode(Uint8List page) {
    final h = PageHeader.read(page);
    if (h.pageType != PageType.vectorRegion) {
      throw CorruptionException(
          'page type ${h.pageType} is not a VECTOR_REGION head');
    }
    if (h.flags & PageFlags.extentHead == 0) {
      throw const CorruptionException(
          'a VECTOR_REGION head page must set EXTENT_HEAD');
    }
    final r = ByteReader(page, PageHeader.size, page.length);
    for (var i = 0; i < 8; i++) {
      if (r.u8() != magic[i]) {
        throw const CorruptionException('bad CRY_VEC magic');
      }
    }
    final dim = r.u32();
    final dtype = r.u8();
    r.u8();
    return VectorRegionHeader(
      dim: dim,
      dtype: dtype,
      stride: r.u16(),
      slotCount: r.u64(),
      liveCount: r.u64(),
      dataOffset: r.u64(),
      nextRegion: r.u64(),
    );
  }
}

/// A vector region: the flat, page-aligned extent of §2.
///
/// §2's second property is why this class has no `mmap` and does not need one:
/// "**An implementation that cannot `mmap` reads positionally.** Dart does
/// exactly this... The layout is identical; only the access method differs. No
/// part of this format requires mmap."
final class VectorRegion {
  VectorRegion({
    required this.dim,
    required this.dtype,
    required this.slotCount,
    int? stride,
    this.pageSize = 4096,
  }) : stride = stride ?? _align64(dim * RegionDType.naturalSize(dtype)) {
    checkPageSize(pageSize);
    dataOffset = pageSize; // one head page, then the slots
    _bytes = Uint8List(dataOffset + slotCount * this.stride);
  }

  final int dim;
  final int dtype;
  final int slotCount;
  final int stride;
  final int pageSize;

  late final int dataOffset;
  late final Uint8List _bytes;

  int liveCount = 0;

  static int _align64(int n) => (n + 63) ~/ 64 * 64;

  /// §2: "Slot 0 of the first region is reserved and never used, so
  /// `slot_id = 0` is a null pointer."
  static const int nullSlot = 0;

  int _offsetOf(int slot) {
    if (slot <= 0 || slot >= slotCount) {
      throw InvalidArgumentException(
          'slot $slot is outside 1..${slotCount - 1} (slot 0 is the null '
          'pointer, spec/09-vector.md section 2)');
    }
    return dataOffset + slot * stride;
  }

  void writeVector(int slot, List<double> v) {
    if (v.length != dim) {
      throw InvalidArgumentException('vector has ${v.length} dimensions, '
          'the region declares $dim');
    }
    final off = _offsetOf(slot);
    final bd = ByteData.view(_bytes.buffer, off, stride);
    switch (dtype) {
      case RegionDType.f32:
        for (var i = 0; i < dim; i++) {
          bd.setFloat32(i * 4, v[i], Endian.little);
        }
      default:
        throw UnsupportedFeatureException(
            'this build stores f32 regions; dtype $dtype is specified but not '
            'implemented here');
    }
    if (slot >= liveCount) liveCount = slot + 1;
  }

  List<double> readVector(int slot) {
    final off = _offsetOf(slot);
    final bd = ByteData.view(_bytes.buffer, off, stride);
    return [for (var i = 0; i < dim; i++) bd.getFloat32(i * 4, Endian.little)];
  }

  /// The head page, so the region can be written into a container.
  Uint8List headPage({int nextRegion = 0}) => VectorRegionHeader(
        dim: dim,
        dtype: dtype,
        stride: stride,
        slotCount: slotCount,
        liveCount: liveCount,
        dataOffset: dataOffset,
        nextRegion: nextRegion,
      ).encode(pageSize);

  int get byteLength => _bytes.length;
}

/// An adjacency record, §3.
final class Adjacency {
  const Adjacency(this.neighbours);

  final List<int> neighbours;

  int get degree => neighbours.length;

  /// §3: "Deltas are zigzag because neighbour ids are not sorted in graph
  /// order — a proximity graph's neighbour list is ordered by distance, not by
  /// id."
  Uint8List encodeRaw() {
    final w = ByteWriter(4 + neighbours.length * 4)..u16(neighbours.length);
    var prev = 0;
    for (var i = 0; i < neighbours.length; i++) {
      final v = i == 0 ? neighbours[i] : neighbours[i] - prev;
      w.uvar(_zigzag(v));
      prev = neighbours[i];
    }
    return w.takeBytes();
  }

  static Adjacency decodeRaw(Uint8List raw) {
    final r = ByteReader(raw);
    final degree = r.u16();
    final out = <int>[];
    var prev = 0;
    for (var i = 0; i < degree; i++) {
      final d = _unzigzag(r.uvar());
      prev = i == 0 ? d : prev + d;
      out.add(prev);
    }
    return Adjacency(out);
  }

  /// §3's key: `CKE(Array[U8 level, U64 slot_id])`.
  static (int, int) keyParts(int level, int slotId) => (level, slotId);

  static int _zigzag(int v) => (v << 1) ^ (v >> 63);
  static int _unzigzag(int v) => (v >>> 1) ^ -(v & 1);
}

/// The quantization codebook, §4.
final class Codebook {
  const Codebook({
    required this.kind,
    required this.m,
    required this.k,
    required this.subDim,
    required this.centroids,
  });

  static const int kindNone = 0;
  static const int kindProduct = 1;
  static const int kindScalar = 2;
  static const int version = 1;

  final int kind;
  final int m;
  final int k;
  final int subDim;

  /// `centroids[m][k][sub_dim]`, flattened.
  final List<double> centroids;

  Uint8List encode() {
    // §4: "`dim = m × sub_dim` MUST hold."
    if (centroids.length != m * k * subDim) {
      throw InvalidArgumentException(
          'codebook declares m=$m k=$k sub_dim=$subDim, which needs '
          '${m * k * subDim} centroid values, got ${centroids.length}');
    }
    final w = ByteWriter(8 + centroids.length * 4)
      ..u8(version)
      ..u8(kind)
      ..u16(m)
      ..u16(k)
      ..u16(subDim);
    final b = ByteData(centroids.length * 4);
    for (var i = 0; i < centroids.length; i++) {
      b.setFloat32(i * 4, centroids[i], Endian.little);
    }
    w.bytes(b.buffer.asUint8List());
    return w.takeBytes();
  }

  static Codebook decode(Uint8List bytes) {
    final r = ByteReader(bytes);
    final v = r.u8();
    if (v != version) {
      throw CorruptionException('codebook version $v, expected $version');
    }
    final kind = r.u8();
    final m = r.u16(), k = r.u16(), subDim = r.u16();
    final n = m * k * subDim;
    final raw = r.bytesCopy(n * 4);
    final bd = ByteData.view(raw.buffer, raw.offsetInBytes, raw.length);
    return Codebook(
      kind: kind,
      m: m,
      k: k,
      subDim: subDim,
      centroids: [for (var i = 0; i < n; i++) bd.getFloat32(i * 4, Endian.little)],
    );
  }
}

/// Distance in the declared metric, §5 and §8.
double vectorDistance(List<double> a, List<double> b, String metric) {
  if (a.length != b.length) {
    throw InvalidArgumentException(
        'vectors have ${a.length} and ${b.length} dimensions');
  }
  switch (metric) {
    case VectorMetric.l2:
      var s = 0.0;
      for (var i = 0; i < a.length; i++) {
        final d = a[i] - b[i];
        s += d * d;
      }
      return math.sqrt(s);
    case VectorMetric.dot:
      var s = 0.0;
      for (var i = 0; i < a.length; i++) {
        s += a[i] * b[i];
      }
      return -s; // nearest-first ordering wants smaller to mean closer
    case VectorMetric.cosine:
      var dot = 0.0, na = 0.0, nb = 0.0;
      for (var i = 0; i < a.length; i++) {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
      }
      if (na == 0 || nb == 0) return 1.0;
      return 1.0 - dot / (math.sqrt(na) * math.sqrt(nb));
    default:
      throw InvalidArgumentException('unknown metric "$metric"');
  }
}

/// A vector index: the region, the graph, and the two maps of §6.
///
/// §8's search contract is the whole public surface:
/// `search(query_vector, k, filter?) → [(NitriteId, distance)]`, "with
/// distances in the declared metric, ordered nearest first, and MUST exclude
/// slots with no live document".
final class VectorIndex {
  VectorIndex({
    required this.region,
    required this.metric,
    this.algorithm = 'hnsw',
    this.neighboursSorted = false,
  });

  final VectorRegion region;
  final String metric;
  final String algorithm;
  final bool neighboursSorted;

  /// §3: adjacency by `(level, slot_id)`. Keying this way "puts a layer's
  /// adjacency contiguously and makes a layer scan sequential, which is what
  /// index construction and repair need".
  final Map<(int, int), Adjacency> graph = {};

  /// §5: "The entry point(s) for a search are in the descriptor, not in the
  /// tree, so a search starts with zero tree lookups."
  final List<int> entryPoints = [];

  /// §6: `params.slot_to_doc` and `params.doc_to_slot`. **Two trees**, because
  /// "search returns slots, filtering needs documents, and deletion needs to
  /// find a document's slot."
  final Map<int, int> slotToDoc = {};
  final Map<int, int> docToSlot = {};

  int _nextSlot = 1; // slot 0 is the null pointer

  int add(int docId, List<double> vector) {
    final slot = _nextSlot++;
    region.writeVector(slot, vector);
    slotToDoc[slot] = docId;
    docToSlot[docId] = slot;
    if (entryPoints.isEmpty) entryPoints.add(slot);
    return slot;
  }

  /// §6: "A deleted document's slot is marked by removing both mappings; the
  /// slot itself stays in the graph until consolidation repairs the
  /// neighbourhoods. A search MUST skip a slot with no document mapping — this
  /// is what makes deletes correct immediately even though the graph is
  /// repaired later."
  bool remove(int docId) {
    final slot = docToSlot.remove(docId);
    if (slot == null) return false;
    slotToDoc.remove(slot);
    return true;
  }

  /// §6: "a verifier checks that they are exact inverses."
  List<String> verifyMaps() {
    final problems = <String>[];
    for (final e in slotToDoc.entries) {
      if (docToSlot[e.value] != e.key) {
        problems.add('slot ${e.key} maps to doc ${e.value}, which maps back to '
            '${docToSlot[e.value]}');
      }
    }
    for (final e in docToSlot.entries) {
      if (slotToDoc[e.value] != e.key) {
        problems.add('doc ${e.key} maps to slot ${e.value}, which maps back to '
            '${slotToDoc[e.value]}');
      }
    }
    return problems;
  }

  /// §8's search.
  ///
  /// [bruteForce] forces the fallback §8 requires of an implementation that
  /// will not traverse a graph another SDK built: "it MUST then fall back to a
  /// brute-force scan of the vector region, which is always possible and always
  /// correct, rather than returning nothing. Brute force over a flat region is
  /// exactly the operation the region layout is designed to make fast."
  List<(int, double)> search(
    List<double> query,
    int k, {
    bool Function(int docId)? filter,
    bool bruteForce = false,
  }) {
    final scored = <(int, double)>[];
    for (final entry in slotToDoc.entries) {
      final docId = entry.value;
      if (filter != null && !filter(docId)) continue;
      // §8: "the distances returned are the true distances to the documents
      // returned (an implementation using PQ codes for traversal MUST re-rank
      // against the full vectors before returning)".
      scored.add((docId, vectorDistance(region.readVector(entry.key), query, metric)));
    }
    scored.sort((a, b) => a.$2.compareTo(b.$2));
    return scored.take(k).toList();
  }

  /// Whether this implementation will traverse a graph built by [algorithm].
  ///
  /// §8: "An implementation MAY refuse to serve a graph built by a different
  /// algorithm — but it MUST then fall back to a brute-force scan."
  bool willTraverse(String graphAlgorithm) => graphAlgorithm == algorithm;
}
