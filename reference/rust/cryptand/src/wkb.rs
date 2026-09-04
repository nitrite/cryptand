//! `08-spatial.md` §1 — geometry as **ISO WKB, and only ISO WKB**.
//!
//! The EWKB rejection is the silent-corruption rule. PostGIS signals Z, M and
//! an embedded SRID by setting high bits (`0x80000000`, `0x40000000`,
//! `0x20000000`) of the same type word ISO uses *additively*, so the two
//! conventions are not distinguishable by a reader that accepts both — a
//! `PointZ` is `1001` in ISO and `0x80000001` in EWKB, and a decoder that
//! guesses wrong reads coordinates as garbage **without error**.

use crate::error::{corrupt, invalid, Result};

pub mod ewkb_flag {
    pub const Z: u32 = 0x8000_0000;
    pub const M: u32 = 0x4000_0000;
    pub const SRID: u32 = 0x2000_0000;
    pub const ANY: u32 = Z | M | SRID;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeometryType {
    Point = 1,
    LineString = 2,
    Polygon = 3,
    MultiPoint = 4,
    MultiLineString = 5,
    MultiPolygon = 6,
    GeometryCollection = 7,
}

impl GeometryType {
    pub fn from_code(c: u32) -> Option<GeometryType> {
        use GeometryType::*;
        Some(match c {
            1 => Point,
            2 => LineString,
            3 => Polygon,
            4 => MultiPoint,
            5 => MultiLineString,
            6 => MultiPolygon,
            7 => GeometryCollection,
            _ => return None,
        })
    }
}

/// One coordinate. `z` and `m` are preserved on round trip (§1).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Coord {
    pub x: f64,
    pub y: f64,
    pub z: Option<f64>,
    pub m: Option<f64>,
}

impl Coord {
    pub fn xy(x: f64, y: f64) -> Coord {
        Coord { x, y, z: None, m: None }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Geometry {
    Point(Option<Coord>),
    LineString(Vec<Coord>),
    /// Rings: the first is the shell, the rest are holes.
    Polygon(Vec<Vec<Coord>>),
    MultiPoint(Vec<Geometry>),
    MultiLineString(Vec<Geometry>),
    MultiPolygon(Vec<Geometry>),
    GeometryCollection(Vec<Geometry>),
}

/// The XY bounding box. An **empty** box (a geometry with no coordinates) is
/// `min = +Inf, max = -Inf` in every dimension and is never returned by a
/// query (§2.1).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Envelope {
    pub min: [f64; 4],
    pub max: [f64; 4],
}

impl Envelope {
    pub fn empty() -> Envelope {
        Envelope { min: [f64::INFINITY; 4], max: [f64::NEG_INFINITY; 4] }
    }
    pub fn is_empty(&self) -> bool {
        self.min[0] > self.max[0]
    }
    pub fn add(&mut self, c: &Coord) {
        let vals = [Some(c.x), Some(c.y), c.z, c.m];
        for (i, v) in vals.iter().enumerate() {
            if let Some(v) = v {
                self.min[i] = self.min[i].min(*v);
                self.max[i] = self.max[i].max(*v);
            }
        }
    }
    pub fn union(&mut self, other: &Envelope) {
        if other.is_empty() {
            return;
        }
        for i in 0..4 {
            self.min[i] = self.min[i].min(other.min[i]);
            self.max[i] = self.max[i].max(other.max[i]);
        }
    }
    pub fn intersects(&self, other: &Envelope, dims: usize) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        (0..dims).all(|i| self.min[i] <= other.max[i] && other.min[i] <= self.max[i])
    }
    pub fn contains(&self, other: &Envelope, dims: usize) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        (0..dims).all(|i| self.min[i] <= other.min[i] && other.max[i] <= self.max[i])
    }
    pub fn expanded(&self, r: f64, dims: usize) -> Envelope {
        let mut e = *self;
        for i in 0..dims {
            e.min[i] -= r;
            e.max[i] += r;
        }
        e
    }
}

impl Geometry {
    pub fn envelope(&self) -> Envelope {
        let mut e = Envelope::empty();
        self.each_coord(&mut |c| e.add(c));
        e
    }

    pub fn each_coord(&self, f: &mut impl FnMut(&Coord)) {
        match self {
            Geometry::Point(Some(c)) => f(c),
            Geometry::Point(None) => {}
            Geometry::LineString(cs) => cs.iter().for_each(|c| f(c)),
            Geometry::Polygon(rings) => rings.iter().flatten().for_each(|c| f(c)),
            Geometry::MultiPoint(g)
            | Geometry::MultiLineString(g)
            | Geometry::MultiPolygon(g)
            | Geometry::GeometryCollection(g) => g.iter().for_each(|x| x.each_coord(f)),
        }
    }

    pub fn geometry_type(&self) -> GeometryType {
        match self {
            Geometry::Point(_) => GeometryType::Point,
            Geometry::LineString(_) => GeometryType::LineString,
            Geometry::Polygon(_) => GeometryType::Polygon,
            Geometry::MultiPoint(_) => GeometryType::MultiPoint,
            Geometry::MultiLineString(_) => GeometryType::MultiLineString,
            Geometry::MultiPolygon(_) => GeometryType::MultiPolygon,
            Geometry::GeometryCollection(_) => GeometryType::GeometryCollection,
        }
    }

    fn dims(&self) -> (bool, bool) {
        let mut z = false;
        let mut m = false;
        self.each_coord(&mut |c| {
            z |= c.z.is_some();
            m |= c.m.is_some();
        });
        (z, m)
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    little: bool,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8> {
        if self.at >= self.b.len() {
            return corrupt("WKB truncated");
        }
        self.at += 1;
        Ok(self.b[self.at - 1])
    }
    fn u32(&mut self) -> Result<u32> {
        if self.at + 4 > self.b.len() {
            return corrupt("WKB truncated");
        }
        let s: [u8; 4] = self.b[self.at..self.at + 4].try_into().unwrap();
        self.at += 4;
        Ok(if self.little { u32::from_le_bytes(s) } else { u32::from_be_bytes(s) })
    }
    fn f64(&mut self) -> Result<f64> {
        if self.at + 8 > self.b.len() {
            return corrupt("WKB truncated");
        }
        let s: [u8; 8] = self.b[self.at..self.at + 8].try_into().unwrap();
        self.at += 8;
        Ok(if self.little { f64::from_le_bytes(s) } else { f64::from_be_bytes(s) })
    }
}

/// A reader MUST accept both byte orders; a writer MUST emit little-endian.
pub fn decode(b: &[u8]) -> Result<Geometry> {
    let mut r = Reader { b, at: 0, little: true };
    let g = read_geometry(&mut r)?;
    if r.at != b.len() {
        return corrupt("trailing bytes after a complete WKB geometry");
    }
    Ok(g)
}

fn read_geometry(r: &mut Reader<'_>) -> Result<Geometry> {
    let order = r.u8()?;
    r.little = match order {
        0 => false,
        1 => true,
        o => return corrupt(format!("WKB byte order marker {o} is neither 0 nor 1")),
    };
    let word = r.u32()?;
    // §1 — a reader MUST reject a type word with any EWKB bit set.
    if word & ewkb_flag::ANY != 0 {
        return corrupt(
            "EWKB is not accepted: PostGIS sets Z/M/SRID as high bits of the same type word ISO \
             uses additively, so accepting both decodes coordinates as garbage without error \
             (spec/08-spatial.md section 1)",
        );
    }
    let base = word % 1000;
    let variant = word / 1000;
    let (has_z, has_m) = match variant {
        0 => (false, false),
        1 => (true, false),
        2 => (false, true),
        3 => (true, true),
        v => return corrupt(format!("WKB dimension variant {v} is not 0..3")),
    };
    let Some(t) = GeometryType::from_code(base) else {
        return corrupt(format!("WKB geometry type {base} is not 1..7"));
    };
    let read_coord = |r: &mut Reader<'_>| -> Result<Coord> {
        let x = r.f64()?;
        let y = r.f64()?;
        let z = if has_z { Some(r.f64()?) } else { None };
        let m = if has_m { Some(r.f64()?) } else { None };
        Ok(Coord { x, y, z, m })
    };
    let read_ring = |r: &mut Reader<'_>| -> Result<Vec<Coord>> {
        let n = r.u32()? as usize;
        if n > 1 << 24 {
            return corrupt("WKB ring point count is implausible");
        }
        (0..n).map(|_| read_coord(r)).collect()
    };
    Ok(match t {
        GeometryType::Point => {
            let c = read_coord(r)?;
            // An all-NaN point is WKB's representation of POINT EMPTY.
            if c.x.is_nan() && c.y.is_nan() {
                Geometry::Point(None)
            } else {
                Geometry::Point(Some(c))
            }
        }
        GeometryType::LineString => Geometry::LineString(read_ring(r)?),
        GeometryType::Polygon => {
            let n = r.u32()? as usize;
            let mut rings = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                rings.push(read_ring(r)?);
            }
            Geometry::Polygon(rings)
        }
        GeometryType::MultiPoint
        | GeometryType::MultiLineString
        | GeometryType::MultiPolygon
        | GeometryType::GeometryCollection => {
            let n = r.u32()? as usize;
            let mut parts = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                parts.push(read_geometry(r)?);
            }
            match t {
                GeometryType::MultiPoint => Geometry::MultiPoint(parts),
                GeometryType::MultiLineString => Geometry::MultiLineString(parts),
                GeometryType::MultiPolygon => Geometry::MultiPolygon(parts),
                _ => Geometry::GeometryCollection(parts),
            }
        }
    })
}

pub fn encode(g: &Geometry) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_geometry(&mut out, g)?;
    Ok(out)
}

fn write_geometry(out: &mut Vec<u8>, g: &Geometry) -> Result<()> {
    let (has_z, has_m) = g.dims();
    let variant = match (has_z, has_m) {
        (false, false) => 0u32,
        (true, false) => 1,
        (false, true) => 2,
        (true, true) => 3,
    };
    out.push(1); // little-endian, as a writer MUST emit
    out.extend_from_slice(&(variant * 1000 + g.geometry_type() as u32).to_le_bytes());
    let put_coord = |out: &mut Vec<u8>, c: &Coord| {
        out.extend_from_slice(&c.x.to_le_bytes());
        out.extend_from_slice(&c.y.to_le_bytes());
        if has_z {
            out.extend_from_slice(&c.z.unwrap_or(0.0).to_le_bytes());
        }
        if has_m {
            out.extend_from_slice(&c.m.unwrap_or(0.0).to_le_bytes());
        }
    };
    match g {
        Geometry::Point(Some(c)) => put_coord(out, c),
        Geometry::Point(None) => put_coord(out, &Coord { x: f64::NAN, y: f64::NAN, z: None, m: None }),
        Geometry::LineString(cs) => {
            out.extend_from_slice(&(cs.len() as u32).to_le_bytes());
            for c in cs {
                put_coord(out, c);
            }
        }
        Geometry::Polygon(rings) => {
            out.extend_from_slice(&(rings.len() as u32).to_le_bytes());
            for ring in rings {
                out.extend_from_slice(&(ring.len() as u32).to_le_bytes());
                for c in ring {
                    put_coord(out, c);
                }
            }
        }
        Geometry::MultiPoint(parts)
        | Geometry::MultiLineString(parts)
        | Geometry::MultiPolygon(parts)
        | Geometry::GeometryCollection(parts) => {
            out.extend_from_slice(&(parts.len() as u32).to_le_bytes());
            for p in parts {
                write_geometry(out, p)?;
            }
        }
    }
    Ok(())
}

/// §1 — `Circle` has no WKB representation and is not a stored geometry. It is
/// a *query* shape; an SDK that persists one MUST convert it to a polygon
/// approximation on migration, with the segment count recorded so the
/// conversion is reproducible.
pub fn circle_to_polygon(cx: f64, cy: f64, r: f64, segments: usize) -> Result<Geometry> {
    if segments < 3 {
        return invalid("a circle approximation needs at least 3 segments");
    }
    let mut ring = Vec::with_capacity(segments + 1);
    for i in 0..segments {
        let a = 2.0 * std::f64::consts::PI * i as f64 / segments as f64;
        ring.push(Coord::xy(cx + r * a.cos(), cy + r * a.sin()));
    }
    ring.push(ring[0]);
    Ok(Geometry::Polygon(vec![ring]))
}
