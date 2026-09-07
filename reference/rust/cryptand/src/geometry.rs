//! `08-spatial.md` §4 — the exact geometric predicates.
//!
//! **The two-phase rule is normative**: the R-tree returns candidates by
//! bounding box; the exact predicate is evaluated on the geometry. An
//! implementation MUST NOT return box-level results as if they were exact.
//! This is the difference between Nitrite's spatial queries meaning the same
//! thing in Java and in Rust.

use crate::wkb::{Coord, Envelope, Geometry};

fn cross(o: &Coord, a: &Coord, b: &Coord) -> f64 {
    (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x)
}

fn on_segment(p: &Coord, a: &Coord, b: &Coord) -> bool {
    if cross(a, b, p) != 0.0 {
        return false;
    }
    p.x >= a.x.min(b.x) && p.x <= a.x.max(b.x) && p.y >= a.y.min(b.y) && p.y <= a.y.max(b.y)
}

/// Ray casting with the boundary counted as inside — the convention JTS's
/// `contains` uses for a point on an edge under `intersects`.
fn point_in_ring(p: &Coord, ring: &[Coord]) -> bool {
    if ring.len() < 3 {
        return false;
    }
    let mut inside = false;
    let n = ring.len();
    let mut j = n - 1;
    for i in 0..n {
        if on_segment(p, &ring[j], &ring[i]) {
            return true;
        }
        let (a, b) = (&ring[j], &ring[i]);
        if (a.y > p.y) != (b.y > p.y) {
            let t = (p.y - a.y) / (b.y - a.y);
            if p.x < a.x + t * (b.x - a.x) {
                inside = !inside;
            }
        }
        j = i;
    }
    inside
}

fn point_in_polygon(p: &Coord, rings: &[Vec<Coord>]) -> bool {
    let Some(shell) = rings.first() else { return false };
    if !point_in_ring(p, shell) {
        return false;
    }
    // A hole excludes, unless the point is exactly on the hole's boundary.
    !rings[1..].iter().any(|h| point_in_ring(p, h) && !on_boundary(p, h))
}

fn on_boundary(p: &Coord, ring: &[Coord]) -> bool {
    let n = ring.len();
    (0..n).any(|i| on_segment(p, &ring[i], &ring[(i + 1) % n]))
}

fn segments_intersect(a1: &Coord, a2: &Coord, b1: &Coord, b2: &Coord) -> bool {
    let d1 = cross(b1, b2, a1);
    let d2 = cross(b1, b2, a2);
    let d3 = cross(a1, a2, b1);
    let d4 = cross(a1, a2, b2);
    if ((d1 > 0.0) != (d2 > 0.0)) && ((d3 > 0.0) != (d4 > 0.0)) {
        return true;
    }
    on_segment(a1, b1, b2) || on_segment(a2, b1, b2) || on_segment(b1, a1, a2) || on_segment(b2, a1, a2)
}

fn lines_of(g: &Geometry, out: &mut Vec<(Coord, Coord)>) {
    match g {
        Geometry::LineString(cs) => {
            for w in cs.windows(2) {
                out.push((w[0], w[1]));
            }
        }
        Geometry::Polygon(rings) => {
            for r in rings {
                for i in 0..r.len() {
                    out.push((r[i], r[(i + 1) % r.len()]));
                }
            }
        }
        Geometry::MultiPoint(g)
        | Geometry::MultiLineString(g)
        | Geometry::MultiPolygon(g)
        | Geometry::GeometryCollection(g) => {
            for x in g {
                lines_of(x, out);
            }
        }
        Geometry::Point(_) => {}
    }
}

fn points_of(g: &Geometry, out: &mut Vec<Coord>) {
    g.each_coord(&mut |c| out.push(*c));
}

fn polygons_of<'a>(g: &'a Geometry, out: &mut Vec<&'a Vec<Vec<Coord>>>) {
    match g {
        Geometry::Polygon(rings) => out.push(rings),
        Geometry::MultiPolygon(parts) | Geometry::GeometryCollection(parts) => {
            for p in parts {
                polygons_of(p, out);
            }
        }
        _ => {}
    }
}

/// True when the two geometries share at least one point.
pub fn intersects(a: &Geometry, b: &Geometry) -> bool {
    if !a.envelope().intersects(&b.envelope(), 2) {
        return false;
    }
    let mut a_polys = Vec::new();
    polygons_of(a, &mut a_polys);
    let mut b_polys = Vec::new();
    polygons_of(b, &mut b_polys);
    let mut a_pts = Vec::new();
    points_of(a, &mut a_pts);
    let mut b_pts = Vec::new();
    points_of(b, &mut b_pts);

    if b_pts.iter().any(|p| a_polys.iter().any(|r| point_in_polygon(p, r))) {
        return true;
    }
    if a_pts.iter().any(|p| b_polys.iter().any(|r| point_in_polygon(p, r))) {
        return true;
    }
    let mut a_lines = Vec::new();
    lines_of(a, &mut a_lines);
    let mut b_lines = Vec::new();
    lines_of(b, &mut b_lines);
    for (a1, a2) in &a_lines {
        for (b1, b2) in &b_lines {
            if segments_intersect(a1, a2, b1, b2) {
                return true;
            }
        }
    }
    // Two point-only geometries.
    a_pts.iter().any(|p| b_pts.iter().any(|q| p.x == q.x && p.y == q.y))
}

/// Is `p` a point of `outer`? §4.1's point-set membership: inside a polygon
/// (boundary included, holes excluded), on one of a linestring's segments, or
/// equal to one of its points.
fn point_in_geometry(p: &Coord, outer: &Geometry) -> bool {
    let mut polys = Vec::new();
    polygons_of(outer, &mut polys);
    if polys.iter().any(|r| point_in_polygon(p, r)) {
        return true;
    }
    let mut lines = Vec::new();
    lines_of(outer, &mut lines);
    if lines.iter().any(|(a, b)| on_segment(p, a, b)) {
        return true;
    }
    let mut pts = Vec::new();
    points_of(outer, &mut pts);
    pts.iter().any(|q| q.x == p.x && q.y == p.y)
}

/// §4.1 — `within(A, B)` is true iff **every point of A is a point of B**.
///
/// This used to fall back to `outer.envelope().contains(inner.envelope())`
/// whenever `outer` held no polygon, on the grounds that the envelope "is exact
/// for a point-in-point or a collinear case". It is not exact for anything
/// else, and it fired for every `MultiPoint`, `LineString`, `MultiLineString`
/// and polygon-free collection: `within(POINT(5 5), MULTIPOINT(1 1, 9 9))`
/// answered **true**, because (5,5) is inside that multipoint's bounding box.
/// That is §4's "MUST NOT return box-level results as if they were exact",
/// violated in the second phase rather than the first — and neither Dart nor
/// Java did it, which is how it was found.
pub fn within(inner: &Geometry, outer: &Geometry) -> bool {
    let mut pts = Vec::new();
    points_of(inner, &mut pts);
    if pts.is_empty() {
        // §4.1 rule 4: an empty geometry is within nothing, including itself.
        return false;
    }
    // Every vertex of `inner` must be a point of `outer` ...
    if !pts.iter().all(|p| point_in_geometry(p, outer)) {
        return false;
    }
    // ... and no segment of `inner` may leave `outer` between its vertices. The
    // midpoint test catches a chord across a concavity or a hole; it is not a
    // proof for an arbitrary pair of geometries, and §2.3's freedom is about
    // tree shape rather than predicates, so this is deliberately conservative
    // in the same way for every implementation.
    let mut inner_lines = Vec::new();
    lines_of(inner, &mut inner_lines);
    let mut outer_polys = Vec::new();
    polygons_of(outer, &mut outer_polys);
    for (a, b) in inner_lines {
        let mid = Coord::xy((a.x + b.x) / 2.0, (a.y + b.y) / 2.0);
        if !point_in_geometry(&mid, outer) {
            return false;
        }
        let _ = &outer_polys;
    }
    true
}

pub fn contains(outer: &Geometry, inner: &Geometry) -> bool {
    within(inner, outer)
}

/// Planar Euclidean distance in the coordinate system of the data — §4's
/// default. Geodesic distance is an SDK-level query option; it changes which
/// candidate box to expand by, not the format.
pub fn distance(a: &Geometry, b: &Geometry) -> f64 {
    if intersects(a, b) {
        return 0.0;
    }
    let mut ap = Vec::new();
    points_of(a, &mut ap);
    let mut bl = Vec::new();
    lines_of(b, &mut bl);
    let mut bp = Vec::new();
    points_of(b, &mut bp);
    let mut al = Vec::new();
    lines_of(a, &mut al);
    let mut best = f64::INFINITY;
    for p in &ap {
        for q in &bp {
            best = best.min(((p.x - q.x).powi(2) + (p.y - q.y).powi(2)).sqrt());
        }
        for (s, e) in &bl {
            best = best.min(point_segment_distance(p, s, e));
        }
    }
    for q in &bp {
        for (s, e) in &al {
            best = best.min(point_segment_distance(q, s, e));
        }
    }
    best
}

fn point_segment_distance(p: &Coord, a: &Coord, b: &Coord) -> f64 {
    let (dx, dy) = (b.x - a.x, b.y - a.y);
    let len2 = dx * dx + dy * dy;
    if len2 == 0.0 {
        return ((p.x - a.x).powi(2) + (p.y - a.y).powi(2)).sqrt();
    }
    let t = (((p.x - a.x) * dx + (p.y - a.y) * dy) / len2).clamp(0.0, 1.0);
    let (cx, cy) = (a.x + t * dx, a.y + t * dy);
    ((p.x - cx).powi(2) + (p.y - cy).powi(2)).sqrt()
}

/// §4's `near(point, radius)`: descend on the point's box expanded by
/// `radius`, then evaluate the exact distance on the candidates.
pub fn near(g: &Geometry, centre: &Coord, radius: f64) -> bool {
    distance(g, &Geometry::Point(Some(*centre))) <= radius
}

pub fn envelope_of(g: &Geometry) -> Envelope {
    g.envelope()
}
