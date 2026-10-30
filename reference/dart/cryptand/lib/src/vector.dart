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
import 'catalog.dart';
import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'database.dart';
import 'errors.dart';
import 'index.dart';
import 'rtree.dart' show MinHeap;
import 'value.dart';

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

  Uint8List encode(int pageSize, {int extentPages = 1}) {
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
      extentPages: extentPages,
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

/// A vector region: the flat, page-aligned extent of §2, on the store's pages.
///
/// §2's second property is why this class has no `mmap` and does not need one:
/// "**An implementation that cannot `mmap` reads positionally.**" The data
/// area is encrypted per chunk when the file seals (`14-security.md` §5.4).
final class VectorRegion {
  VectorRegion._(this.store, this.startPage, this.pages, this.header, this.encrypted);

  final PageStore store;
  final int startPage;
  final int pages;
  final VectorRegionHeader header;

  /// The head page's `flags.ENCRYPTED`: how this region's data is chunked,
  /// whatever the file's `cipher` says now (F-073).
  final bool encrypted;

  int get dim => header.dim;
  int get dtype => header.dtype;
  int get slotCount => header.slotCount;
  int get stride => header.stride;

  static int _align64(int n) => (n + 63) ~/ 64 * 64;

  /// §2: "Slot 0 of the first region is reserved and never used, so
  /// `slot_id = 0` is a null pointer."
  static const int nullSlot = 0;

  /// Allocates and writes a region of [slots] slots (slot 0 included).
  factory VectorRegion.create(PageStore store,
      {required int dim, int dtype = RegionDType.f32, required int slots}) {
    final natural = dim * RegionDType.naturalSize(dtype);
    // Rounded to 64 bytes so slots land on a SIMD boundary, inside the u16.
    final aligned = _align64(natural);
    final stride = aligned <= 0xFFFF ? aligned : natural;
    final encrypted = store.crypto != null && !store.writePlain;
    final chunk = store.chunkBytes(encrypted);
    final pages = 1 + (slots * stride + chunk - 1) ~/ chunk;
    final start = store.allocExtent(pages);
    final header = VectorRegionHeader(
        dim: dim,
        dtype: dtype,
        stride: stride,
        slotCount: slots,
        liveCount: 0,
        dataOffset: store.pageSize,
        nextRegion: 0);
    store.writeInExtent(start, header.encode(store.pageSize, extentPages: pages));
    // A reused extent holds whatever was there; a sealed chunk is read before
    // it is rewritten, so a never-written one must read as blank (as Java).
    for (var p = 1; p < pages; p++) {
      store.writeAt((start + p) * store.pageSize, Uint8List(store.pageSize));
    }
    return VectorRegion._(store, start, pages, header, encrypted);
  }

  factory VectorRegion.open(PageStore store, int startPage) {
    final clear = store.readClear(startPage);
    final h = PageHeader.read(clear, pageId: startPage);
    final header = VectorRegionHeader.decode(store.read(startPage));
    return VectorRegion._(
        store, startPage, math.max(1, h.extentPages), header, h.isEncrypted);
  }

  void _check(int slot) {
    if (slot <= 0 || slot >= slotCount) {
      throw InvalidArgumentException(
          'slot $slot is outside 1..${slotCount - 1} (slot 0 is the null '
          'pointer, spec/09-vector.md section 2)');
    }
  }

  void writeVector(int slot, List<double> v) {
    _check(slot);
    if (v.length != dim) {
      throw InvalidArgumentException('vector has ${v.length} dimensions, '
          'the region declares $dim');
    }
    if (dtype != RegionDType.f32) {
      throw UnsupportedFeatureException(
          'this build writes f32 regions; dtype $dtype is specified but not '
          'implemented here');
    }
    final buf = Uint8List(stride); // padding bytes are zero
    final bd = ByteData.sublistView(buf);
    for (var i = 0; i < dim; i++) {
      bd.setFloat32(i * 4, v[i], Endian.little);
    }
    store.writeExtentData(
        startPage, header.dataOffset, slot * stride, buf, encrypted);
  }

  List<double> readVector(int slot) {
    if (slot <= 0) _check(slot);
    if (slot >= slotCount) {
      throw CorruptionException('slot $slot is past the region\'s $slotCount slots',
          pageId: startPage);
    }
    final raw = store.readExtentData(
        startPage, header.dataOffset, slot * stride, stride, encrypted);
    final bd = ByteData.sublistView(raw);
    switch (dtype) {
      case RegionDType.f32:
        return [for (var i = 0; i < dim; i++) bd.getFloat32(i * 4, Endian.little)];
      default:
        throw UnsupportedFeatureException(
            'this build reads f32 regions; dtype $dtype is specified but not '
            'implemented here');
    }
  }
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

/// Robust-prune slack: a candidate is dropped if a kept neighbour is ALPHA
/// times nearer to it.
const double vectorAlpha = 1.2;

/// Beam width of an unfiltered search (at least k).
const int vectorEfSearch = 100;

/// A vector index, `09-vector.md` — F-196, as Java's `VectorIndex` and Rust's.
///
/// A Vamana graph built as documents arrive: a put runs a beam search
/// (`ef_construction` wide) from the entry point, keeps the robust-pruned
/// ([vectorAlpha]) nearest `m` as the new slot's neighbours and adds the
/// reverse edges, pruning a list that overflows. A search is the same beam,
/// [vectorEfSearch] wide, re-ranked by true distance; a filtered search, and
/// an index small enough that the beam would visit it all, use §8's brute
/// force. Vectors live in the [VectorRegion], adjacency in an
/// [AdjacencyTree], both on pages; the slot maps are KV trees, cached here as
/// plain lists. The [Database] holds it, so the engine's commit republishes it.
/// ponytail: deleted slots stay in the graph and are walked through (§6);
/// consolidation (§7) is not implemented, so a delete-heavy index degrades
/// toward the brute-force fallback.
final class VectorIndex {
  VectorIndex(this.db, this.name, TreeDescriptor d) : descriptor = d {
    Never shape(String what) =>
        throw CorruptionException('vector index "$name" has no valid params.$what');
    int u(String k) => (d.param(k) as CInt?)?.magnitude.lo ?? shape(k);
    owner = d.owner ?? '';
    field = d.paramStr('field') ?? shape('field');
    dim = u('dim');
    metric = d.paramStr('metric') ?? shape('metric');
    vectorDistance(const [0.0], const [0.0], metric); // refuses an unknown one
    slotToDocTree = u('slot_to_doc');
    docToSlotTree = u('doc_to_slot');
    m = (d.param('m') as CInt?)?.magnitude.lo ?? 32;
    efConstruction = (d.param('ef_construction') as CInt?)?.magnitude.lo ?? 200;
    final store = db.engine.store;
    region = VectorRegion.open(store, u('vector_region'));
    adjacency = AdjacencyTree(store,
        treeId: d.treeId, root: d.root ?? 0, rootNonce: d.rootNonce);
    final eps = d.param('entry_points');
    if (eps is CArray && eps.items.isNotEmpty) {
      _entry = (eps.items.first as CInt).magnitude.lo;
    }
    for (final e in db.engine.scanTree(slotToDocTree)) {
      final k = decodeKey(e.cke), v = decodeValue(e.value);
      if (k is! CInt || v is! CNitriteId) {
        throw CorruptionException('vector index "$name": a slot_to_doc row has the wrong shape');
      }
      final slot = k.magnitude.lo;
      if (slot <= 0 || slot >= region.slotCount) {
        throw CorruptionException('vector index "$name": slot $slot is outside the region');
      }
      _map(slot, v.id);
      if (slot >= _nextSlot) _nextSlot = slot + 1;
    }
  }

  final Database db;
  final String name;
  late final String owner;
  late final String field;
  late final int dim;
  late final String metric;
  late final int slotToDocTree;
  late final int docToSlotTree;
  late final int m;
  late final int efConstruction;
  TreeDescriptor descriptor;
  late VectorRegion region;
  late final AdjacencyTree adjacency;

  final List<int> _slotDoc = [];
  final List<bool> _live = [];
  final Map<int, int> _docSlot = {};
  int _nextSlot = 1; // slot 0 is the null pointer
  int _entry = 0;
  int size = 0;
  bool _regionDirty = false;

  /// Unfiltered searches the beam could not answer (a broken graph hides
  /// behind the scan).
  int fallbacks = 0;

  bool _isLive(int slot) => slot < _live.length && _live[slot];

  void _map(int slot, int doc) {
    while (_slotDoc.length <= slot) {
      _slotDoc.add(0);
      _live.add(false);
    }
    _slotDoc[slot] = doc;
    if (!_live[slot]) {
      _live[slot] = true;
      size++;
    }
    _docSlot[doc] = slot;
  }

  List<double>? _vectorOf(CDoc doc) {
    for (final v in resolvePath(doc, field) ?? const <CValue>[]) {
      if (v is CVector) {
        final f = v.f32Values;
        if (f != null) return f;
        final i8 = v.i8Values!;
        return [for (final c in i8) c * v.scale + v.zeroPoint];
      }
    }
    return null;
  }

  /// Indexes [doc]'s vector field, replacing any slot it already owns.
  void put(int docId, CDoc doc) {
    final v = _vectorOf(doc);
    if (v == null) {
      remove(docId);
      return;
    }
    if (v.length != dim) {
      throw InvalidArgumentException(
          'vector has ${v.length} dimensions, index $name declares $dim');
    }
    var slot = _docSlot[docId];
    if (slot == null) {
      slot = _nextSlot++;
      _growTo(slot);
    }
    region.writeVector(slot, v);
    _map(slot, docId);
    _link(slot, v);
    db.engine
      ..put(slotToDocTree, CInt.of(NumType.u64, slot), encodeValue(CNitriteId(docId)))
      ..put(docToSlotTree, CNitriteId(docId), encodeValue(CInt.of(NumType.u64, slot)));
  }

  /// §6: both mappings go; the slot stays in the graph and a search skips
  /// it, which is what makes a delete correct immediately.
  void remove(int docId) {
    final slot = _docSlot.remove(docId);
    if (slot == null) return;
    if (_isLive(slot)) {
      _live[slot] = false;
      size--;
    }
    db.engine
      ..remove(slotToDocTree, CInt.of(NumType.u64, slot))
      ..remove(docToSlotTree, CNitriteId(docId));
  }

  void _growTo(int slot) {
    if (slot < region.slotCount) return;
    final store = db.engine.store;
    final bigger = VectorRegion.create(store,
        dim: dim,
        dtype: region.dtype,
        slots: math.max(slot + 1, region.slotCount * 2));
    for (var s = 1; s < _live.length; s++) {
      if (_live[s]) bigger.writeVector(s, region.readVector(s));
    }
    store.freeExtent(region.startPage, region.pages);
    region = bigger;
    descriptor = descriptor.with_({
      'params': CDoc({
        ...descriptor.params.fields,
        'vector_region': CInt.of(NumType.u64, region.startPage)
      })
    });
    _regionDirty = true;
  }

  /// Writes the graph's copied pages back and republishes the descriptor.
  void commit() {
    final (root, nonce) = adjacency.commit();
    final d = descriptor;
    final eps = CArray([if (_entry != 0) CInt.of(NumType.u64, _entry)]);
    final entries = (d.doc.fields['entries'] as CInt?)?.magnitude.lo ?? 0;
    final changed = d.root != root ||
        d.rootNonce != nonce ||
        entries != size ||
        d.param('entry_points') != eps;
    if (changed || _regionDirty) {
      _regionDirty = false;
      descriptor = d.withRoot(root, nonce).with_({
        'entries': CInt.of(NumType.u64, size),
        'params': CDoc({...d.params.fields, 'entry_points': eps}),
      });
      db.catalog.put(name, descriptor);
    }
  }

  List<int> neighbours(int slot) {
    final raw = adjacency.get(_adjKey(slot));
    return raw == null
        ? const []
        : Adjacency.decodeRaw(expectValue<CBytes>(decodeValue(raw), 'adjacency').value)
            .neighbours;
  }

  static Uint8List _adjKey(int slot) =>
      encodeKey(CArray([CInt.of(NumType.u8, 0), CInt.of(NumType.u64, slot)]));

  void _setAdjacency(int slot, List<int> n) =>
      adjacency.put(_adjKey(slot), encodeValue(CBytes(Adjacency(n).encodeRaw())));

  List<double> _vector(int slot, Map<int, List<double>>? cache) {
    if (slot <= 0 || slot >= region.slotCount) {
      throw CorruptionException(
          'vector index "$name": neighbour slot $slot is outside the region');
    }
    if (cache == null) return region.readVector(slot);
    return cache[slot] ??= region.readVector(slot);
  }

  double _d(List<double> a, List<double> b) => vectorDistance(a, b, metric);

  /// Beam search from the entry point: the [ef] nearest slots seen, nearest
  /// first, as `(distance, slot)`.
  List<(double, int)> _beam(List<double> q, int ef, Map<int, List<double>>? cache) {
    if (_entry == 0) return [];
    int byD((double, int) a, (double, int) b) =>
        a.$1 != b.$1 ? a.$1.compareTo(b.$1) : a.$2.compareTo(b.$2);
    final open = MinHeap<(double, int)>(byD);
    final best = MinHeap<(double, int)>((a, b) => byD(b, a)); // max-heap
    final seen = <int>{_entry};
    final first = (_d(q, _vector(_entry, cache)), _entry);
    open.add(first);
    best.add(first);
    while (open.isNotEmpty) {
      final c = open.removeFirst();
      if (best.length >= ef && c.$1 > best.first.$1) break;
      for (final n in neighbours(c.$2)) {
        if (!seen.add(n)) continue;
        final d = _d(q, _vector(n, cache));
        if (best.length < ef || d < best.first.$1) {
          open.add((d, n));
          best.add((d, n));
          if (best.length > ef) best.removeFirst();
        }
      }
    }
    return best.toList()..sort(byD);
  }

  /// Vamana's robust prune: nearest first, dropping a candidate a kept one covers.
  List<int> _prune(int me, List<(double, int)> nearestFirst, Map<int, List<double>> cache) {
    final kept = <int>[];
    final keptV = <List<double>>[];
    for (final c in nearestFirst) {
      if (kept.length >= m) break;
      if (c.$2 == me || kept.contains(c.$2)) continue;
      final v = _vector(c.$2, cache);
      if (!keptV.any((k) => vectorAlpha * _d(k, v) <= c.$1)) {
        kept.add(c.$2);
        keptV.add(v);
      }
    }
    return kept;
  }

  /// Links [slot] into the graph, reverse edges included.
  void _link(int slot, List<double> v) {
    if (_entry == 0 || _entry == slot) {
      _entry = slot;
      if (adjacency.get(_adjKey(slot)) == null) _setAdjacency(slot, const []);
      return;
    }
    final cache = <int, List<double>>{slot: v};
    final mine = _prune(slot, _beam(v, efConstruction, cache), cache);
    _setAdjacency(slot, mine);
    for (final n in mine) {
      var theirs = [...neighbours(n)];
      if (theirs.contains(slot)) continue;
      theirs.add(slot);
      if (theirs.length > m) {
        final nv = _vector(n, cache);
        final scored = [for (final t in theirs) (_d(nv, _vector(t, cache)), t)]
          ..sort((a, b) => a.$1 != b.$1 ? a.$1.compareTo(b.$1) : a.$2.compareTo(b.$2));
        theirs = _prune(n, scored, cache);
      }
      _setAdjacency(n, theirs);
    }
  }

  /// §8's `search(query, k, filter?)`, nearest first, with **true** distances
  /// and never a slot with no live document.
  List<(int, double)> search(List<double> query, int k,
      {bool Function(int docId)? filter}) {
    if (query.length != dim) {
      throw InvalidArgumentException(
          'query has ${query.length} dimensions, index $name declares $dim');
    }
    final ef = math.max(k, vectorEfSearch);
    if (filter == null && size > ef) {
      final hits = <(int, double)>[];
      for (final c in _beam(query, ef, null)) {
        if (_isLive(c.$2)) hits.add((_slotDoc[c.$2], c.$1));
        if (hits.length == k) return hits;
      }
      // Fewer than k live slots in the beam (deletes): the scan answers.
      fallbacks++;
    }
    final hits = <(int, double)>[];
    for (var s = 1; s < _live.length; s++) {
      if (!_live[s]) continue;
      final doc = _slotDoc[s];
      if (filter != null && !filter(doc)) continue;
      hits.add((doc, _d(query, region.readVector(s))));
    }
    hits.sort((a, b) => a.$2.compareTo(b.$2));
    return hits.take(k).toList();
  }

  /// §6: "a verifier checks that they are exact inverses."
  List<String> verifyMaps() {
    final problems = <String>[];
    for (var s = 1; s < _live.length; s++) {
      if (_live[s] && _docSlot[_slotDoc[s]] != s) {
        problems.add('slot $s maps to doc ${_slotDoc[s]}, which maps back to '
            '${_docSlot[_slotDoc[s]]}');
      }
    }
    for (final e in _docSlot.entries) {
      if (!_isLive(e.value) || _slotDoc[e.value] != e.key) {
        problems.add('doc ${e.key} maps to slot ${e.value}, which does not map back');
      }
    }
    return problems;
  }
}
