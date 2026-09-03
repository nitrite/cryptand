/// Geometry as ISO Well-Known Binary — `spec/08-spatial.md` §1.
///
/// WKB replaces three representations at once: Java's WKT text (and the
/// `WKTReader` round trip that costs a text parse per geometry), Rust's
/// `Geometry` enum, and Dart's third form.
///
/// **The EWKB rule is the one that would silently corrupt data**, and §1 spells
/// out why: PostGIS signals Z, M and an embedded SRID by setting high bits of
/// the same type word that ISO uses *additively*, so the two conventions are
/// not distinguishable by a reader that accepts both — "a `PointZ` is `1001` in
/// ISO and `0x80000001` in EWKB, and a decoder that guesses wrong reads
/// coordinates as garbage". So a type word with any of those bits set is
/// rejected outright.
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'errors.dart';

/// ISO WKB base geometry types.
class GeometryType {
  static const int point = 1;
  static const int lineString = 2;
  static const int polygon = 3;
  static const int multiPoint = 4;
  static const int multiLineString = 5;
  static const int multiPolygon = 6;
  static const int geometryCollection = 7;

  static const Map<int, String> names = {
    point: 'Point',
    lineString: 'LineString',
    polygon: 'Polygon',
    multiPoint: 'MultiPoint',
    multiLineString: 'MultiLineString',
    multiPolygon: 'MultiPolygon',
    geometryCollection: 'GeometryCollection',
  };
}

/// The EWKB flag bits §1 requires a reader to reject.
class EwkbFlags {
  static const int z = 0x80000000;
  static const int m = 0x40000000;
  static const int srid = 0x20000000;
  static const int any = z | m | srid;
}

/// One coordinate. `m` and `z` are null when the geometry does not carry them.
final class Coord {
  const Coord(this.x, this.y, {this.z, this.m});
  final double x, y;
  final double? z, m;

  /// §3's fixed axis order: X, Y, Z, M.
  double axis(int i) => switch (i) {
        0 => x,
        1 => y,
        2 => z ?? double.nan,
        3 => m ?? double.nan,
        _ => throw RangeError('axis $i'),
      };

  @override
  String toString() => 'Coord($x, $y${z != null ? ", z=$z" : ""}'
      '${m != null ? ", m=$m" : ""})';
}

/// A decoded geometry.
final class Geometry {
  const Geometry({
    required this.type,
    required this.hasZ,
    required this.hasM,
    this.coords = const [],
    this.rings = const [],
    this.parts = const [],
  });

  /// The base type, without the ISO Z/M offsets.
  final int type;
  final bool hasZ, hasM;

  /// Point and LineString coordinates.
  final List<Coord> coords;

  /// Polygon rings — the first is the shell, the rest are holes.
  final List<List<Coord>> rings;

  /// Multi* and GeometryCollection members.
  final List<Geometry> parts;

  int get dimensions => 2 + (hasZ ? 1 : 0) + (hasM ? 1 : 0);

  /// Every coordinate in the geometry, at any depth.
  Iterable<Coord> get allCoords sync* {
    yield* coords;
    for (final r in rings) {
      yield* r;
    }
    for (final p in parts) {
      yield* p.allCoords;
    }
  }

  /// The bounding box over [dims] axes, in §3's X, Y, Z, M order.
  ///
  /// §2.1: "An empty bounding box (a geometry with no coordinates) is encoded
  /// as `min = +Inf, max = -Inf` in every dimension and is never returned by a
  /// query."
  Envelope envelope({int dims = 2}) {
    final min = List<double>.filled(dims, double.infinity);
    final max = List<double>.filled(dims, double.negativeInfinity);
    var any = false;
    for (final c in allCoords) {
      any = true;
      for (var i = 0; i < dims; i++) {
        final v = c.axis(i);
        if (v.isNaN) continue;
        if (v < min[i]) min[i] = v;
        if (v > max[i]) max[i] = v;
      }
    }
    if (!any) return Envelope.empty(dims);
    return Envelope(min, max);
  }

  @override
  String toString() =>
      '${GeometryType.names[type]}${hasZ ? "Z" : ""}${hasM ? "M" : ""}';
}

/// An axis-aligned bounding box.
final class Envelope {
  Envelope(this.min, this.max);

  factory Envelope.empty(int dims) => Envelope(
        List<double>.filled(dims, double.infinity),
        List<double>.filled(dims, double.negativeInfinity),
      );

  final List<double> min;
  final List<double> max;

  int get dimensions => min.length;

  bool get isEmpty {
    for (var i = 0; i < min.length; i++) {
      if (min[i] > max[i]) return true;
    }
    return false;
  }

  bool intersects(Envelope other) {
    if (isEmpty || other.isEmpty) return false;
    for (var i = 0; i < min.length; i++) {
      if (min[i] > other.max[i] || max[i] < other.min[i]) return false;
    }
    return true;
  }

  bool containsEnvelope(Envelope other) {
    if (isEmpty || other.isEmpty) return false;
    for (var i = 0; i < min.length; i++) {
      if (other.min[i] < min[i] || other.max[i] > max[i]) return false;
    }
    return true;
  }

  /// The exact union — §2.2: "Every internal entry's box is the exact union of
  /// its child's boxes... a box that is merely a superset is a defect because
  /// it silently degrades every query."
  Envelope union(Envelope other) {
    if (isEmpty) return Envelope([...other.min], [...other.max]);
    if (other.isEmpty) return Envelope([...min], [...max]);
    return Envelope(
      [for (var i = 0; i < min.length; i++) math.min(min[i], other.min[i])],
      [for (var i = 0; i < max.length; i++) math.max(max[i], other.max[i])],
    );
  }

  Envelope expandedBy(double r) => isEmpty
      ? this
      : Envelope([for (final v in min) v - r], [for (final v in max) v + r]);

  double get area {
    if (isEmpty) return 0;
    var a = 1.0;
    for (var i = 0; i < min.length; i++) {
      a *= max[i] - min[i];
    }
    return a;
  }

  /// Squared distance from a point to this box; 0 when inside.
  double squaredDistanceTo(List<double> p) {
    if (isEmpty) return double.infinity;
    var d = 0.0;
    for (var i = 0; i < min.length && i < p.length; i++) {
      final v = p[i];
      final delta = v < min[i] ? min[i] - v : (v > max[i] ? v - max[i] : 0.0);
      d += delta * delta;
    }
    return d;
  }

  @override
  String toString() => 'Envelope($min, $max)';
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

final class _WkbReader {
  _WkbReader(this.bytes) : _bd = ByteData.view(bytes.buffer, bytes.offsetInBytes, bytes.length);

  final Uint8List bytes;
  final ByteData _bd;
  int pos = 0;
  late Endian endian;

  int u8() {
    if (pos >= bytes.length) {
      throw const CorruptionException('WKB ends mid-value');
    }
    return bytes[pos++];
  }

  int u32() {
    if (pos + 4 > bytes.length) {
      throw const CorruptionException('WKB ends mid-value');
    }
    final v = _bd.getUint32(pos, endian);
    pos += 4;
    return v;
  }

  double f64() {
    if (pos + 8 > bytes.length) {
      throw const CorruptionException('WKB ends mid-value');
    }
    final v = _bd.getFloat64(pos, endian);
    pos += 8;
    return v;
  }
}

/// Decodes ISO WKB, §1.
Geometry decodeWkb(Uint8List bytes) {
  final r = _WkbReader(bytes);
  final g = _readGeometry(r);
  if (r.pos != bytes.length) {
    throw CorruptionException(
        'WKB has ${bytes.length - r.pos} trailing bytes');
  }
  return g;
}

Geometry _readGeometry(_WkbReader r) {
  // §1: "Little-endian byte order marker (0x01) — a writer MUST emit
  // little-endian; a reader MUST accept both."
  final order = r.u8();
  if (order != 0 && order != 1) {
    throw CorruptionException('WKB byte order marker is $order, not 0 or 1');
  }
  r.endian = order == 1 ? Endian.little : Endian.big;

  final raw = r.u32();
  if (raw & EwkbFlags.any != 0) {
    final which = [
      if (raw & EwkbFlags.z != 0) 'Z',
      if (raw & EwkbFlags.m != 0) 'M',
      if (raw & EwkbFlags.srid != 0) 'SRID',
    ].join('|');
    throw CorruptionException(
        'this is EWKB, not ISO WKB: type word 0x${raw.toRadixString(16)} sets '
        'the $which high bit. ISO signals Z and M additively (+1000/+2000), so '
        'the two conventions are indistinguishable and a decoder that guesses '
        'wrong reads coordinates as garbage (spec/08-spatial.md section 1)');
  }

  // ISO: +1000 for Z, +2000 for M, +3000 for ZM.
  final base = raw % 1000;
  final variant = raw ~/ 1000;
  if (variant > 3) {
    throw CorruptionException('unknown ISO WKB type word $raw');
  }
  final hasZ = variant == 1 || variant == 3;
  final hasM = variant == 2 || variant == 3;
  if (!GeometryType.names.containsKey(base)) {
    throw CorruptionException('unknown WKB geometry type $base');
  }

  Coord coord() {
    final x = r.f64(), y = r.f64();
    return Coord(x, y, z: hasZ ? r.f64() : null, m: hasM ? r.f64() : null);
  }

  List<Coord> points() => [for (var i = r.u32(); i > 0; i--) coord()];

  switch (base) {
    case GeometryType.point:
      return Geometry(
          type: base, hasZ: hasZ, hasM: hasM, coords: [coord()]);
    case GeometryType.lineString:
      return Geometry(
          type: base, hasZ: hasZ, hasM: hasM, coords: points());
    case GeometryType.polygon:
      final n = r.u32();
      return Geometry(
          type: base,
          hasZ: hasZ,
          hasM: hasM,
          rings: [for (var i = 0; i < n; i++) points()]);
    default:
      final n = r.u32();
      // §1: Multi* and GeometryCollection members are complete WKB geometries,
      // each with its own byte-order marker.
      return Geometry(
          type: base,
          hasZ: hasZ,
          hasM: hasM,
          parts: [for (var i = 0; i < n; i++) _readGeometry(r)]);
  }
}

/// Encodes ISO WKB, little-endian as §1 requires of a writer.
Uint8List encodeWkb(Geometry g) {
  final out = BytesBuilder();
  _writeGeometry(out, g);
  return out.takeBytes();
}

void _writeGeometry(BytesBuilder out, Geometry g) {
  final head = ByteData(5)
    ..setUint8(0, 1) // little-endian
    ..setUint32(
        1,
        g.type +
            (g.hasZ && g.hasM ? 3000 : (g.hasZ ? 1000 : (g.hasM ? 2000 : 0))),
        Endian.little);
  out.add(head.buffer.asUint8List());

  void coord(Coord c) {
    final n = 2 + (g.hasZ ? 1 : 0) + (g.hasM ? 1 : 0);
    final b = ByteData(n * 8)
      ..setFloat64(0, c.x, Endian.little)
      ..setFloat64(8, c.y, Endian.little);
    var off = 16;
    if (g.hasZ) {
      b.setFloat64(off, c.z ?? 0, Endian.little);
      off += 8;
    }
    if (g.hasM) b.setFloat64(off, c.m ?? 0, Endian.little);
    out.add(b.buffer.asUint8List());
  }

  void count(int n) =>
      out.add((ByteData(4)..setUint32(0, n, Endian.little)).buffer.asUint8List());

  switch (g.type) {
    case GeometryType.point:
      coord(g.coords.single);
    case GeometryType.lineString:
      count(g.coords.length);
      g.coords.forEach(coord);
    case GeometryType.polygon:
      count(g.rings.length);
      for (final ring in g.rings) {
        count(ring.length);
        ring.forEach(coord);
      }
    default:
      count(g.parts.length);
      for (final p in g.parts) {
        _writeGeometry(out, p);
      }
  }
}
