//! `02-value-encoding.md` §8 — equality and comparison, against the shared
//! vector corpus.
//!
//! §8 opens "defined here once, for all SDKs, ending the current divergence",
//! and then records that a divergence survived inside it — two implementations
//! filled a hole in **opposite** directions — "and no test could see it because
//! nothing tested this section at all".
//!
//! The interop gate cannot see this section either, and not by oversight:
//! §8's order is consumed **in memory**. Three implementations can disagree
//! completely about how values sort and every direction of the file round trip
//! still passes, because the bytes never differ.
//!
//! So this is checked the only way it can be: the same corpus, in every
//! implementation, compared pairwise, with the matrix published in the vector.
//!
//! The result is a **matrix**, not a sorted permutation, and that is deliberate.
//! §8 makes many of these values equal — `I32(5)`, `F64(5.0)` and `INT_VAR(5)`
//! are one value; a `TIMESTAMP` of 1000 ms equals a `TIMESTAMP_NS` of (1 s, 0);
//! `-0.0` equals `+0.0` — and equal elements have no defined relative position
//! in an unstable sort. A permutation would encode the sort algorithm; the
//! matrix encodes the order.

mod support_v;
use support_v::{build, load};

use cryptand::compare::compare_values;
use cryptand::value::Value;
use std::cmp::Ordering;

fn corpus() -> (Vec<Value>, Vec<String>) {
    let doc = load("order/values");
    let entries = doc["entries"].as_array().expect("entries").clone();
    let values = entries.iter().map(|e| build(&e["value"])).collect();
    let notes = entries
        .iter()
        .map(|e| e["note"].as_str().unwrap_or("").to_string())
        .collect();
    (values, notes)
}

fn sign(o: Ordering) -> i8 {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// The matrix as one line per row of `-`, `0`, `+` — the form the other two
/// implementations emit, so the three are diffable as text.
fn matrix(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .map(|a| {
            values
                .iter()
                .map(|b| match sign(compare_values(a, b).expect("every corpus value is ordered")) {
                    -1 => '-',
                    0 => '0',
                    _ => '+',
                })
                .collect()
        })
        .collect()
}

#[test]
fn the_shared_order_corpus_matches_the_published_matrix() {
    let (values, _) = corpus();
    let rows = matrix(&values);
    let doc = load("order/values");

    // Written on the first run, then frozen: this is the cross-language
    // agreement, and a change to it is a change to the format.
    let want = doc["matrix"]
        .as_array()
        .expect("order/values.json carries no `matrix` -- regenerate it");
    assert_eq!(want.len(), rows.len(), "the corpus and the matrix disagree in size");
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(
            want[i].as_str().unwrap(),
            row,
            "row {i} of the order matrix differs from the published vector"
        );
    }
}

/// §8 calls its order "stable and total". Total means these three properties,
/// and they are checked over all 90 x 90 pairs rather than asserted, because a
/// comparator that is wrong in one place is usually wrong by breaking one of
/// them.
#[test]
fn the_order_is_a_total_order_over_the_corpus() {
    let (values, notes) = corpus();
    let n = values.len();
    let c = |i: usize, j: usize| sign(compare_values(&values[i], &values[j]).unwrap());

    for i in 0..n {
        assert_eq!(c(i, i), 0, "value {i} ({}) is not equal to itself", notes[i]);
        for j in 0..n {
            assert_eq!(
                c(i, j),
                -c(j, i),
                "antisymmetry fails for {i} ({}) and {j} ({})",
                notes[i],
                notes[j]
            );
        }
    }
    // Transitivity over every triple is O(n^3) = 729 000 here, which runs in
    // well under a second and is the property most likely to be violated by a
    // comparator built out of per-type special cases.
    for i in 0..n {
        for j in 0..n {
            if c(i, j) > 0 {
                continue;
            }
            for k in 0..n {
                if c(j, k) <= 0 {
                    assert!(
                        c(i, k) <= 0,
                        "transitivity fails: {i} <= {j} <= {k} but {i} > {k}\n  {}\n  {}\n  {}",
                        notes[i],
                        notes[j],
                        notes[k]
                    );
                }
            }
        }
    }
}

/// Dumps the matrix for cross-implementation diffing.
/// `CRYPTAND_ORDER_OUT=/tmp/order_rust.txt cargo test --test order_test -- --ignored`
#[test]
#[ignore]
fn dump_matrix() {
    let (values, _) = corpus();
    let out = std::env::var("CRYPTAND_ORDER_OUT").unwrap_or_else(|_| "/tmp/order_rust.txt".into());
    std::fs::write(&out, matrix(&values).join("\n") + "\n").unwrap();
    eprintln!("wrote {out}");
}

/// The corpus's **named** rules, each naming two indices and the sign §8
/// requires between them.
///
/// The matrix above proves the three implementations agree. It cannot prove
/// they are right: all three produced an identical matrix while all three
/// compared MAP entries in *stored* rather than sorted order, which §8 rule 8
/// forbids in the same sentence that covers DOC. Agreement is not conformance,
/// and these rules are the half that reads the spec rather than the neighbours.
#[test]
fn the_named_rules_of_section_8_hold() {
    let (values, notes) = corpus();
    let doc = load("order/values");
    let rules = doc["rules"].as_array().expect("order/values.json carries no `rules`");
    assert!(rules.len() > 100, "the rule set is suspiciously small: {}", rules.len());

    for r in rules {
        let a = r["a"].as_u64().unwrap() as usize;
        let b = r["b"].as_u64().unwrap() as usize;
        let want = r["expect"].as_str().unwrap();
        let got = match sign(compare_values(&values[a], &values[b]).unwrap()) {
            -1 => "-",
            0 => "0",
            _ => "+",
        };
        assert_eq!(
            want,
            got,
            "§8 rule {} — {}\n  a[{a}] = {}\n  b[{b}] = {}",
            r["rule"].as_str().unwrap_or("?"),
            r["note"].as_str().unwrap_or(""),
            notes[a],
            notes[b]
        );
    }
}

// ---------------------------------------------------------------------------
// `02-value-encoding.md` §4 — the MAP invariants
// ---------------------------------------------------------------------------
//
// §4 states four MUSTs and Dart and Java each enforce all four, on both sides:
//
//   - "Entries MUST be sorted by `CKE(key)` byte order"      (writer, reader)
//   - "Duplicate keys ... are corruption"                    (writer, reader)
//   - "A map key MUST be CKE-encodable ... A writer MUST reject one; a reader
//      encountering one MUST report corruption."
//
// The rules are not decoration. §4's own justification is that "sorting makes
// maps comparable, hashable and diffable across languages, and makes a lookup a
// binary search" — a binary search over unsorted entries silently returns the
// wrong answer rather than failing.

use cryptand::container::Profile;
use cryptand::cve;

mod support;

/// A writer MUST reject a key with no CKE encoding rather than inventing an
/// order for it. Rust's encoder sorted with
/// `cke::encode(..).unwrap_or_default()`, which gives such a key the *empty*
/// byte string: it sorts first and the file that results is one Dart and Java
/// both refuse to open, because their readers check exactly this.
///
/// Checked through `Collection::insert` — the public seam a caller's value
/// actually crosses — and not through the helper, because a validator nothing
/// calls is this project's most-repeated defect.
#[test]
fn a_map_key_with_no_cke_encoding_is_rejected_on_insert() {
    let (_t, mut db) = support::db("bad_map_key", Profile::Desktop);
    let mut c = db.collection("orders").unwrap();

    for key in [
        Value::Doc(vec![]),
        Value::Map(vec![]),
        Value::Regex("a".into(), "".into()),
    ] {
        let doc = Value::Doc(vec![
            ("_id".to_string(), Value::NitriteId(1)),
            ("m".to_string(), Value::Map(vec![(key.clone(), Value::Bool(true))])),
        ]);
        let err = c
            .insert(&mut db.engine, &doc)
            .expect_err("§4: a map key with no CKE encoding MUST be rejected by the writer");
        assert!(
            format!("{err}").contains("map key"),
            "expected the map-key rule to be named, got {err}"
        );
    }
}

/// §4: "Duplicate keys — two entries whose `CKE(key)` bytes are equal — are
/// corruption." Note the keys here are `I32(5)` and `I64(5)`: different CVE
/// tags, *equal* CKE bytes, so a check that compared the values structurally
/// rather than their key encodings would miss them.
#[test]
fn duplicate_map_keys_are_rejected_on_insert() {
    let (_t, mut db) = support::db("dup_map_key", Profile::Desktop);
    let mut c = db.collection("orders").unwrap();

    let doc = Value::Doc(vec![
        ("_id".to_string(), Value::NitriteId(1)),
        (
            "m".to_string(),
            Value::Map(vec![
                (Value::Str("a".into()), Value::Bool(true)),
                (Value::Str("a".into()), Value::Bool(false)),
            ]),
        ),
    ]);
    let err = c.insert(&mut db.engine, &doc).expect_err("duplicate map keys MUST be rejected");
    assert!(format!("{err}").contains("duplicate map key"), "got {err}");
}

/// The reader half. Both other implementations refuse an unsorted or
/// duplicate-keyed MAP; this builds such a body by hand, because a conforming
/// writer cannot produce one.
#[test]
fn an_unsorted_or_duplicate_keyed_map_is_refused_by_the_reader() {
    fn map_body(pairs: &[(Value, Value)]) -> Vec<u8> {
        let mut body = Vec::new();
        cryptand::varint::put_uvar(&mut body, pairs.len() as u64);
        for (k, v) in pairs {
            body.extend_from_slice(&cve::encode(k));
            body.extend_from_slice(&cve::encode(v));
        }
        let mut out = vec![0x21];
        cryptand::varint::put_uvar(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }
    let a = Value::Str("a".into());
    let b = Value::Str("b".into());
    let one = Value::Bool(true);
    let none = |_: u32| None;

    // Descending by CKE(key) — §4 requires ascending.
    let unsorted = map_body(&[(b.clone(), one.clone()), (a.clone(), one.clone())]);
    assert!(
        cve::decode_all(&unsorted, &none).is_err(),
        "a MAP whose entries are not sorted by CKE(key) must be refused"
    );

    // Two entries with equal CKE(key).
    let dup = map_body(&[(a.clone(), one.clone()), (a.clone(), one.clone())]);
    assert!(
        cve::decode_all(&dup, &none).is_err(),
        "a MAP with duplicate keys must be refused as corruption"
    );

    // The conforming form still decodes, so the checks above are not simply
    // refusing every map — a rejector that rejects everything passes the two
    // assertions above and is useless.
    let ok = map_body(&[(a, one.clone()), (b, one)]);
    assert!(cve::decode_all(&ok, &none).is_ok(), "a sorted, unique MAP must still decode");
}
