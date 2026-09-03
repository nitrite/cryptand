/// Exact geometric predicates — `spec/08-spatial.md` §4.
///
/// **The two-phase rule is normative**, and this file is its second phase:
///
/// > "the R-tree returns candidates by bounding box; the exact predicate is
/// > evaluated on the geometry. An implementation MUST NOT return box-level
/// > results as if they were exact. This is the difference between Nitrite's
/// > spatial queries meaning the same thing in Java and in Rust."
///
/// So a box test is never the answer here. Everything below works on
/// coordinates.
///
/// **Scope, stated rather than discovered.** These are planar predicates over
/// the XY projection, which is what §3 says the R-tree indexes by default and
/// what §4's "planar Euclidean in the coordinate system of the data" specifies
/// for distance. Geodesic distance is an SDK-level query option (§4) and is not
/// here. Self-intersecting polygons are not validated: OGC calls them invalid
/// geometries, and the predicates below assume valid input rather than silently
/// producing a plausible answer for input the standard excludes.
library;

import 'dart:math' as math;

import 'wkb.dart';

/// The §4 predicates, namespaced.
///
/// They are static methods rather than top-level functions because `contains`,
/// `within` and `distance` are common enough names to collide with a caller's
/// own — `package:matcher` exports `contains`, for one — and a spatial
/// predicate silently shadowed by a test matcher is a bad afternoon.
class Spatial {
  Spatial._();

  static bool intersects(Geometry a, Geometry b) => _intersects(a, b);
  static bool contains(Geometry a, Geometry b) => _contains(a, b);
  static bool within(Geometry a, Geometry b) => _within(a, b);
  static double distance(Geometry a, Geometry b) => _distance(a, b);
  static bool withinDistance(Geometry g, Coord centre, double radius) =>
      _withinDistance(g, centre, radius);
}

/// `intersects(a, b)` — §4.
bool _intersects(Geometry a, Geometry b) {
  for (final x in _flatten(a)) {
    for (final y in _flatten(b)) {
      if (_simpleIntersects(x, y)) return true;
    }
  }
  return false;
}

/// `contains(a, b)` — every point of `b` is in `a`, §4.
bool _contains(Geometry a, Geometry b) {
  final parts = _flatten(b).toList();
  if (parts.isEmpty) return false;
  for (final y in parts) {
    var covered = false;
    for (final x in _flatten(a)) {
      if (_simpleContains(x, y)) {
        covered = true;
        break;
      }
    }
    if (!covered) return false;
  }
  return true;
}

/// `within(a, b)` — §4, the converse of `contains`.
bool _within(Geometry a, Geometry b) => _contains(b, a);

/// Planar Euclidean distance between two geometries, §4.
double _distance(Geometry a, Geometry b) {
  var best = double.infinity;
  for (final x in _flatten(a)) {
    for (final y in _flatten(b)) {
      final d = _simpleDistance(x, y);
      if (d < best) best = d;
      if (best == 0) return 0;
    }
  }
  return best;
}

/// `near(point, radius)` — §4's exact phase.
bool _withinDistance(Geometry g, Coord centre, double radius) =>
    _distance(g, Geometry(type: GeometryType.point, hasZ: false, hasM: false,
        coords: [centre])) <= radius;

// ---------------------------------------------------------------------------

/// Flattens Multi* and GeometryCollection into simple geometries.
Iterable<Geometry> _flatten(Geometry g) sync* {
  switch (g.type) {
    case GeometryType.point:
    case GeometryType.lineString:
    case GeometryType.polygon:
      yield g;
    default:
      for (final p in g.parts) {
        yield* _flatten(p);
      }
  }
}

bool _simpleIntersects(Geometry a, Geometry b) {
  if (a.type == GeometryType.polygon || b.type == GeometryType.polygon) {
    final poly = a.type == GeometryType.polygon ? a : b;
    final other = identical(poly, a) ? b : a;
    if (other.type == GeometryType.polygon) {
      return _polygonsIntersect(poly, other);
    }
    // A point or line meets a polygon if any vertex is inside, or any of its
    // segments crosses the boundary.
    for (final c in other.coords) {
      if (_pointInPolygon(c, poly)) return true;
    }
    return _crossesBoundary(other.coords, poly);
  }
  // Point/line against point/line.
  if (a.type == GeometryType.point && b.type == GeometryType.point) {
    return _same(a.coords.single, b.coords.single);
  }
  if (a.type == GeometryType.point) return _pointOnLine(a.coords.single, b.coords);
  if (b.type == GeometryType.point) return _pointOnLine(b.coords.single, a.coords);
  return _segmentsCross(a.coords, b.coords);
}

bool _simpleContains(Geometry a, Geometry b) {
  if (a.type == GeometryType.polygon) {
    for (final c in b.allCoords) {
      if (!_pointInPolygon(c, a)) return false;
    }
    // A shape whose vertices are all inside can still leave through a hole or
    // a concavity, so the boundary must not be crossed.
    return !_crossesBoundary(
        b.type == GeometryType.polygon ? b.rings.first : b.coords, a,
        strict: true);
  }
  if (a.type == GeometryType.lineString) {
    if (b.type != GeometryType.point) return false;
    return _pointOnLine(b.coords.single, a.coords);
  }
  if (a.type == GeometryType.point) {
    return b.type == GeometryType.point &&
        _same(a.coords.single, b.coords.single);
  }
  return false;
}

double _simpleDistance(Geometry a, Geometry b) {
  if (_simpleIntersects(a, b)) return 0;
  var best = double.infinity;

  List<List<Coord>> lines(Geometry g) => switch (g.type) {
        GeometryType.point => [g.coords],
        GeometryType.lineString => [g.coords],
        _ => g.rings,
      };

  for (final la in lines(a)) {
    for (final lb in lines(b)) {
      if (la.length == 1 && lb.length == 1) {
        best = math.min(best, _dist(la[0], lb[0]));
        continue;
      }
      if (la.length == 1) {
        best = math.min(best, _pointToPath(la[0], lb));
        continue;
      }
      if (lb.length == 1) {
        best = math.min(best, _pointToPath(lb[0], la));
        continue;
      }
      for (var i = 0; i + 1 < la.length; i++) {
        for (var j = 0; j + 1 < lb.length; j++) {
          best = math.min(
              best, _segmentDistance(la[i], la[i + 1], lb[j], lb[j + 1]));
        }
      }
    }
  }
  return best;
}

bool _same(Coord a, Coord b) => a.x == b.x && a.y == b.y;

double _dist(Coord a, Coord b) {
  final dx = a.x - b.x, dy = a.y - b.y;
  return math.sqrt(dx * dx + dy * dy);
}

double _pointToSegment(Coord p, Coord a, Coord b) {
  final dx = b.x - a.x, dy = b.y - a.y;
  final len2 = dx * dx + dy * dy;
  if (len2 == 0) return _dist(p, a);
  var t = ((p.x - a.x) * dx + (p.y - a.y) * dy) / len2;
  t = t.clamp(0.0, 1.0);
  final cx = a.x + t * dx, cy = a.y + t * dy;
  final ex = p.x - cx, ey = p.y - cy;
  return math.sqrt(ex * ex + ey * ey);
}

double _pointToPath(Coord p, List<Coord> path) {
  if (path.length == 1) return _dist(p, path.first);
  var best = double.infinity;
  for (var i = 0; i + 1 < path.length; i++) {
    best = math.min(best, _pointToSegment(p, path[i], path[i + 1]));
  }
  return best;
}

double _segmentDistance(Coord a1, Coord a2, Coord b1, Coord b2) {
  if (_segmentIntersect(a1, a2, b1, b2)) return 0;
  return [
    _pointToSegment(a1, b1, b2),
    _pointToSegment(a2, b1, b2),
    _pointToSegment(b1, a1, a2),
    _pointToSegment(b2, a1, a2),
  ].reduce(math.min);
}

int _orientation(Coord a, Coord b, Coord c) {
  final v = (b.y - a.y) * (c.x - b.x) - (b.x - a.x) * (c.y - b.y);
  if (v == 0) return 0;
  return v > 0 ? 1 : 2;
}

bool _onSegment(Coord a, Coord b, Coord c) =>
    b.x <= math.max(a.x, c.x) &&
    b.x >= math.min(a.x, c.x) &&
    b.y <= math.max(a.y, c.y) &&
    b.y >= math.min(a.y, c.y);

bool _segmentIntersect(Coord p1, Coord q1, Coord p2, Coord q2) {
  final o1 = _orientation(p1, q1, p2);
  final o2 = _orientation(p1, q1, q2);
  final o3 = _orientation(p2, q2, p1);
  final o4 = _orientation(p2, q2, q1);
  if (o1 != o2 && o3 != o4) return true;
  if (o1 == 0 && _onSegment(p1, p2, q1)) return true;
  if (o2 == 0 && _onSegment(p1, q2, q1)) return true;
  if (o3 == 0 && _onSegment(p2, p1, q2)) return true;
  if (o4 == 0 && _onSegment(p2, q1, q2)) return true;
  return false;
}

bool _pointOnLine(Coord p, List<Coord> line) {
  if (line.length == 1) return _same(p, line.first);
  for (var i = 0; i + 1 < line.length; i++) {
    if (_pointToSegment(p, line[i], line[i + 1]) == 0) return true;
  }
  return false;
}

/// Ray casting with holes: inside the shell and outside every hole.
bool _pointInPolygon(Coord p, Geometry poly) {
  if (poly.rings.isEmpty) return false;
  if (!_inRing(p, poly.rings.first)) return false;
  for (var i = 1; i < poly.rings.length; i++) {
    if (_inRing(p, poly.rings[i], boundaryCounts: false)) return false;
  }
  return true;
}

bool _inRing(Coord p, List<Coord> ring, {bool boundaryCounts = true}) {
  // A point exactly on the boundary is inside the shell and, for a hole, is
  // still part of the polygon — hence the flag.
  for (var i = 0; i + 1 < ring.length; i++) {
    if (_pointToSegment(p, ring[i], ring[i + 1]) == 0) return boundaryCounts;
  }
  var inside = false;
  for (var i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    final a = ring[i], b = ring[j];
    if ((a.y > p.y) != (b.y > p.y)) {
      final x = (b.x - a.x) * (p.y - a.y) / (b.y - a.y) + a.x;
      if (p.x < x) inside = !inside;
    }
  }
  return inside;
}

bool _crossesBoundary(List<Coord> path, Geometry poly, {bool strict = false}) {
  if (path.length < 2) return false;
  for (final ring in poly.rings) {
    for (var i = 0; i + 1 < path.length; i++) {
      for (var j = 0; j + 1 < ring.length; j++) {
        if (_segmentIntersect(path[i], path[i + 1], ring[j], ring[j + 1])) {
          if (!strict) return true;
          // For containment, touching the boundary is allowed; properly
          // crossing it is not. A midpoint outside the polygon proves a cross.
          final mid = Coord((path[i].x + path[i + 1].x) / 2,
              (path[i].y + path[i + 1].y) / 2);
          if (!_pointInPolygon(mid, poly)) return true;
        }
      }
    }
  }
  return false;
}

bool _polygonsIntersect(Geometry a, Geometry b) {
  for (final c in b.rings.first) {
    if (_pointInPolygon(c, a)) return true;
  }
  for (final c in a.rings.first) {
    if (_pointInPolygon(c, b)) return true;
  }
  for (final ra in a.rings) {
    for (final rb in b.rings) {
      if (_segmentsCross(ra, rb)) return true;
    }
  }
  return false;
}

bool _segmentsCross(List<Coord> a, List<Coord> b) {
  for (var i = 0; i + 1 < a.length; i++) {
    for (var j = 0; j + 1 < b.length; j++) {
      if (_segmentIntersect(a[i], a[i + 1], b[j], b[j + 1])) return true;
    }
  }
  return false;
}
