//! Level 3 — `08-spatial.md`. WKB, the exact predicates, and the in-container
//! R-tree.

mod support;
use support::*;

use cryptand::container::Profile;
use cryptand::geometry as g;
use cryptand::rtree::{check_dimensions, max_entries_for, RTree, SpatialEntry};
use cryptand::wkb::{decode, encode, Coord, Envelope, Geometry};

fn point(x: f64, y: f64) -> Geometry {
    Geometry::Point(Some(Coord::xy(x, y)))
}

fn square(x0: f64, y0: f64, x1: f64, y1: f64) -> Geometry {
    Geometry::Polygon(vec![vec![
        Coord::xy(x0, y0),
        Coord::xy(x1, y0),
        Coord::xy(x1, y1),
        Coord::xy(x0, y1),
        Coord::xy(x0, y0),
    ]])
}

#[test]
fn every_supported_geometry_round_trips_through_iso_wkb() {
    let cases = vec![
        point(1.0, 2.0),
        Geometry::LineString(vec![Coord::xy(0.0, 0.0), Coord::xy(3.0, 4.0)]),
        square(0.0, 0.0, 10.0, 10.0),
        Geometry::MultiPoint(vec![point(1.0, 1.0), point(2.0, 2.0)]),
        Geometry::MultiLineString(vec![Geometry::LineString(vec![
            Coord::xy(0.0, 0.0),
            Coord::xy(1.0, 1.0),
        ])]),
        Geometry::MultiPolygon(vec![square(0.0, 0.0, 1.0, 1.0)]),
        Geometry::GeometryCollection(vec![point(5.0, 5.0), square(0.0, 0.0, 2.0, 2.0)]),
    ];
    for c in cases {
        let bytes = encode(&c).unwrap();
        assert_eq!(bytes[0], 1, "a writer MUST emit little-endian");
        assert_eq!(decode(&bytes).unwrap(), c);
    }
}

#[test]
fn z_and_m_variants_are_iso_additive_and_preserved() {
    let g = Geometry::Point(Some(Coord { x: 1.0, y: 2.0, z: Some(3.0), m: None }));
    let bytes = encode(&g).unwrap();
    let word = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
    assert_eq!(word, 1001, "PointZ is 1001 in ISO WKB");
    assert_eq!(decode(&bytes).unwrap(), g);

    let zm = Geometry::Point(Some(Coord { x: 1.0, y: 2.0, z: Some(3.0), m: Some(4.0) }));
    let bytes = encode(&zm).unwrap();
    assert_eq!(u32::from_le_bytes(bytes[1..5].try_into().unwrap()), 3001);
    assert_eq!(decode(&bytes).unwrap(), zm);
}

#[test]
fn ewkb_is_rejected_because_accepting_both_reads_coordinates_as_garbage() {
    // §1 — PostGIS sets Z/M/SRID as high bits of the same type word ISO uses
    // additively, so a `PointZ` is `1001` in ISO and `0x80000001` in EWKB. A
    // decoder that guesses wrong reads coordinates as garbage **without
    // error**, which is why all three flag bits are refused.
    for flag in [0x8000_0000u32, 0x4000_0000, 0x2000_0000] {
        let mut b = vec![1u8];
        b.extend_from_slice(&(flag | 1).to_le_bytes());
        b.extend_from_slice(&1.0f64.to_le_bytes());
        b.extend_from_slice(&2.0f64.to_le_bytes());
        let e = decode(&b).unwrap_err();
        assert!(format!("{e}").contains("EWKB"), "{e}");
    }
}

#[test]
fn a_reader_accepts_both_byte_orders() {
    let mut b = vec![0u8]; // big-endian
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1.5f64.to_be_bytes());
    b.extend_from_slice(&2.5f64.to_be_bytes());
    assert_eq!(decode(&b).unwrap(), point(1.5, 2.5));
}

#[test]
fn the_two_phase_rule_rejects_what_the_box_alone_would_return() {
    // §4 is normative: the R-tree returns candidates by bounding box, and the
    // exact predicate is evaluated on the geometry. This triangle's BOX
    // contains the origin and its AREA does not — a box-only implementation
    // gives a wrong answer that looks reasonable.
    let triangle = Geometry::Polygon(vec![vec![
        Coord::xy(1.0, -1.0),
        Coord::xy(1.0, 1.0),
        Coord::xy(-1.0, 1.0),
        Coord::xy(1.0, -1.0),
    ]]);
    let origin = point(-0.9, -0.9);
    let mut box_of = Envelope::empty();
    triangle.each_coord(&mut |c| box_of.add(c));
    assert!(box_of.intersects(&origin.envelope(), 2), "phase 1 returns it");
    assert!(!g::intersects(&triangle, &origin), "phase 2 must reject it");
}

#[test]
fn the_predicates_agree_with_geometry_not_with_boxes() {
    let poly = square(0.0, 0.0, 10.0, 10.0);
    assert!(g::intersects(&poly, &point(5.0, 5.0)));
    assert!(!g::intersects(&poly, &point(11.0, 5.0)));
    assert!(g::within(&point(5.0, 5.0), &poly));
    assert!(!g::within(&point(15.0, 5.0), &poly));
    assert!(g::contains(&poly, &square(1.0, 1.0, 2.0, 2.0)));
    assert!(!g::contains(&poly, &square(9.0, 9.0, 12.0, 12.0)));
    assert_eq!(g::distance(&poly, &point(5.0, 5.0)), 0.0);
    assert!((g::distance(&poly, &point(13.0, 5.0)) - 3.0).abs() < 1e-9);
    assert!(g::near(&poly, &Coord::xy(13.0, 5.0), 3.5));
    assert!(!g::near(&poly, &Coord::xy(13.0, 5.0), 2.5));
}

#[test]
fn a_hole_excludes_the_points_inside_it() {
    let with_hole = Geometry::Polygon(vec![
        vec![
            Coord::xy(0.0, 0.0),
            Coord::xy(10.0, 0.0),
            Coord::xy(10.0, 10.0),
            Coord::xy(0.0, 10.0),
            Coord::xy(0.0, 0.0),
        ],
        vec![
            Coord::xy(4.0, 4.0),
            Coord::xy(6.0, 4.0),
            Coord::xy(6.0, 6.0),
            Coord::xy(4.0, 6.0),
            Coord::xy(4.0, 4.0),
        ],
    ]);
    assert!(g::intersects(&with_hole, &point(1.0, 1.0)));
    assert!(!g::intersects(&with_hole, &point(5.0, 5.0)));
}

#[test]
fn an_empty_box_is_plus_inf_to_minus_inf_and_never_matches() {
    let e = Envelope::empty();
    assert!(e.is_empty());
    assert_eq!(e.min[0], f64::INFINITY);
    assert_eq!(e.max[0], f64::NEG_INFINITY);
    let world = Envelope { min: [-1e9; 4], max: [1e9; 4] };
    assert!(!e.intersects(&world, 2), "an empty box is never returned by a query");
}

#[test]
fn a_circle_becomes_a_reproducible_polygon() {
    // §1 — `Circle` has no WKB representation and is not a stored geometry.
    let p = cryptand::wkb::circle_to_polygon(0.0, 0.0, 1.0, 16).unwrap();
    let Geometry::Polygon(rings) = &p else { panic!() };
    assert_eq!(rings[0].len(), 17, "closed ring: the segment count is recorded by construction");
    assert!(cryptand::wkb::circle_to_polygon(0.0, 0.0, 1.0, 2).is_err());
}

#[test]
fn the_rtree_returns_the_same_results_as_a_scan_whatever_its_shape() {
    // §2.3 — the split algorithm is not specified, so a conformance test
    // compares **query results, never tree shape**.
    let (_t, mut e) = engine("rtree", Profile::Desktop);
    let mut rows = Vec::new();
    let mut rng = Rng::new(11);
    for id in 0..500i64 {
        let x = (rng.below(1000) as f64) / 10.0;
        let y = (rng.below(1000) as f64) / 10.0;
        let mut b = Envelope::empty();
        b.add(&Coord::xy(x, y));
        b.add(&Coord::xy(x + 1.0, y + 1.0));
        rows.push(SpatialEntry { bbox: b, id });
    }
    let mut t = RTree::new(20, 2, max_entries_for(e.page_size(), 2, true));
    t.build(&mut e.pager, rows.clone()).unwrap();
    t.verify(&mut e.pager).unwrap();

    let query = Envelope { min: [20.0, 20.0, 0.0, 0.0], max: [40.0, 40.0, 0.0, 0.0] };
    let mut want: Vec<i64> =
        rows.iter().filter(|r| r.bbox.intersects(&query, 2)).map(|r| r.id).collect();
    want.sort_unstable();
    assert_eq!(t.search(&mut e.pager, &query).unwrap(), want);

    let near = t.nearest_k(&mut e.pager, &[50.0, 50.0], 5).unwrap();
    assert_eq!(near.len(), 5);
    for w in near.windows(2) {
        assert!(w[0].1 <= w[1].1, "nearest_k must be ordered nearest first");
    }
}

#[test]
fn a_three_dimensional_index_always_means_z_never_m() {
    // §3 — silently indexing M in Z's slot would make two geometries
    // comparable that are not.
    assert!(check_dimensions(2, false, false).is_ok());
    assert!(check_dimensions(3, true, false).is_ok());
    assert!(check_dimensions(3, false, true).is_err(), "an XYM geometry cannot enter a 3D index");
    assert!(check_dimensions(4, true, true).is_ok());
    assert!(check_dimensions(4, true, false).is_err());
}

#[test]
fn a_page_whose_dimensions_disagree_with_the_descriptor_is_rejected() {
    use cryptand::rtree::{RTreeEntry, RTreeNode};
    let n = RTreeNode {
        is_leaf: true,
        dimensions: 2,
        entries: vec![RTreeEntry {
            bbox: Envelope { min: [0.0; 4], max: [1.0; 4] },
            payload: 1,
            child_entries: 1,
        }],
    };
    let page = n.encode(8192).unwrap();
    assert!(RTreeNode::parse(&page, 2).is_ok());
    assert!(RTreeNode::parse(&page, 3).is_err());
}
