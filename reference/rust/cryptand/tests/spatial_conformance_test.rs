//! `08-spatial.md` §§1, 3 and 4, against the shared vector corpus.
//!
//! §2.3 says what a spatial conformance test may compare:
//!
//! > "Because the split algorithm is free, two implementations inserting the
//! > same documents will produce different (equally valid) trees. A conformance
//! > test therefore compares **query results**, never tree shape."
//!
//! So this corpus carries no tree. It carries geometries, their envelopes, and
//! the pairwise predicate matrices — all properties of the geometry rather than
//! of anybody's R-tree — plus the reject list §1 makes normative.
//!
//! Chapter 08 had **no shared vectors at all** before this, which is the same
//! structural gap `02-value-encoding.md` §8 was in: the predicates are consumed
//! in memory, so three implementations can disagree about what `within` means
//! and every direction of the cross-language file gate still passes.

mod support_v;
use support_v::{load, unhex};

use cryptand::geometry;
use cryptand::wkb;

fn matrix(kind: &str, gs: &[wkb::Geometry]) -> Vec<String> {
    gs.iter()
        .map(|a| {
            gs.iter()
                .map(|b| {
                    let r = match kind {
                        "intersects" => geometry::intersects(a, b),
                        "contains" => geometry::contains(a, b),
                        "within" => geometry::within(a, b),
                        _ => unreachable!(),
                    };
                    if r { '1' } else { '0' }
                })
                .collect()
        })
        .collect()
}

fn corpus() -> (Vec<wkb::Geometry>, Vec<String>, serde_json::Value) {
    let doc = load("spatial/geometries");
    let entries = doc["geometries"].as_array().expect("geometries").clone();
    let gs = entries
        .iter()
        .map(|e| {
            let b = unhex(e["wkb"].as_str().unwrap());
            wkb::decode(&b)
                .unwrap_or_else(|err| panic!("{}: {err}", e["name"].as_str().unwrap()))
        })
        .collect();
    let names = entries.iter().map(|e| e["name"].as_str().unwrap().to_string()).collect();
    (gs, names, doc)
}

/// §1's envelope, which every query's first phase is computed from. An envelope
/// that is wrong makes every predicate below it wrong in the same direction.
#[test]
fn every_published_envelope_is_reproduced() {
    let (gs, names, doc) = corpus();
    for (i, e) in doc["geometries"].as_array().unwrap().iter().enumerate() {
        let want: Vec<f64> =
            e["envelope"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
        let env = gs[i].envelope();
        let got = vec![env.min[0], env.min[1], env.max[0], env.max[1]];
        assert_eq!(want, got, "envelope of {}", names[i]);
    }
}

/// §1: "**EWKB MUST NOT be written and MUST be rejected on read.**" — plus the
/// rest of the reject list. Each must fail with a typed error, not a panic and
/// not a wrong answer.
#[test]
fn every_published_reject_is_refused() {
    let doc = load("spatial/geometries");
    for r in doc["rejects"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let b = unhex(r["wkb"].as_str().unwrap());
        let outcome = std::panic::catch_unwind(|| wkb::decode(&b).is_err());
        match outcome {
            Err(_) => panic!("{name} panicked; §1 requires a typed refusal"),
            Ok(false) => panic!("{name} was ACCEPTED: {}", r["why"].as_str().unwrap()),
            Ok(true) => {}
        }
    }
}

/// §1: "a writer MUST emit little-endian; a reader MUST accept both."
///
/// The negative control for the test above: a reader that refused everything
/// would pass it, and this is the case that fails such a reader.
#[test]
fn a_big_endian_geometry_is_accepted() {
    let doc = load("spatial/geometries");
    let be = &doc["accept_big_endian"];
    let g = wkb::decode(&unhex(be["wkb"].as_str().unwrap()))
        .expect("§1: a reader MUST accept big-endian WKB");
    let want: Vec<f64> =
        be["envelope"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
    let e = g.envelope();
    assert_eq!(want, vec![e.min[0], e.min[1], e.max[0], e.max[1]]);
}

#[test]
fn the_predicate_matrices_match_the_published_vectors() {
    let (gs, names, doc) = corpus();
    for kind in ["intersects", "contains", "within"] {
        let rows = matrix(kind, &gs);
        let want = doc["matrix"][kind]
            .as_array()
            .unwrap_or_else(|| panic!("spatial/geometries.json carries no `{kind}` matrix"));
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(
                want[i].as_str().unwrap(),
                row,
                "{kind} row {i} ({}) differs from the published vector",
                names[i]
            );
        }
    }
}

/// Dumps the three matrices for cross-implementation diffing.
#[test]
#[ignore]
fn dump_matrices() {
    let (gs, _, _) = corpus();
    let out = std::env::var("CRYPTAND_SPATIAL_OUT").unwrap_or_else(|_| "/tmp/spatial_rust.txt".into());
    let mut s = String::new();
    for kind in ["intersects", "contains", "within"] {
        s.push_str(kind);
        s.push('\n');
        for row in matrix(kind, &gs) {
            s.push_str(&row);
            s.push('\n');
        }
    }
    std::fs::write(&out, s).unwrap();
    eprintln!("wrote {out}");
}

/// The corpus's **named** rules, each citing a §4.1 rule number, a predicate and
/// two indices.
///
/// The matrix proves the three implementations agree. It cannot prove they are
/// right, and here it could not have: before §4.1 was written the three
/// disagreed on **32** of these pairs while each was internally consistent, and
/// each was wrong in a different way — this one returned envelope containment
/// whenever the outer geometry held no polygon.
#[test]
fn the_named_rules_of_section_4_1_hold() {
    let (gs, names, doc) = corpus();
    let rules = doc["rules"].as_array().expect("spatial/geometries.json carries no `rules`");
    assert!(rules.len() > 10, "the rule set is suspiciously small: {}", rules.len());
    for r in rules {
        let a = r["a"].as_u64().unwrap() as usize;
        let b = r["b"].as_u64().unwrap() as usize;
        let kind = r["predicate"].as_str().unwrap();
        let want = r["expect"].as_bool().unwrap();
        let got = match kind {
            "intersects" => geometry::intersects(&gs[a], &gs[b]),
            "contains" => geometry::contains(&gs[a], &gs[b]),
            "within" => geometry::within(&gs[a], &gs[b]),
            k => panic!("unknown predicate {k}"),
        };
        assert_eq!(
            want,
            got,
            "§{} — {}\n  {kind}({}, {})",
            r["rule"].as_str().unwrap_or("?"),
            r["note"].as_str().unwrap_or(""),
            names[a],
            names[b]
        );
    }
}
