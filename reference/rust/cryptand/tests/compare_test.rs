//! `02-value-encoding.md` §8 — the definition of value order.
//!
//! This file exists because it was missing. `compare.rs` is a public module and
//! the coverage run that found this reported **7 of 134 lines**: `is_ordered`
//! and `values_equal` are called from `index.rs` and `txn.rs`, and
//! `compare_values` — the chapter itself — was called from nowhere and checked
//! by nothing.
//!
//! The invariant that matters, and the reason §8 and `03-key-encoding.md` are
//! two chapters describing one thing:
//!
//! ```text
//! sign(compare_values(a, b)) == sign(memcmp(CKE(a), CKE(b)))
//! ```
//!
//! A divergence there is a wrong query result, not a slow one: the B+tree
//! navigates by bytes and the application reasons in values.

use cryptand::compare::{compare_numeric, compare_values, is_ordered, values_equal};
use cryptand::value::{NumType, Value};
use cryptand::cke;
use std::cmp::Ordering;

/// `compare_values` is fallible now (§8's closing paragraph). Every call in
/// this file is on a pair the test has already established is ordered, so
/// unwrapping is the assertion, not a shortcut.
fn cmp(a: &Value, b: &Value) -> Ordering {
    compare_values(a, b).expect("both sides are ordered")
}

fn sign(o: Ordering) -> i32 {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn f32v(v: f32) -> Value {
    Value::Float { w: NumType::F32, v: v as f64 }
}

/// Every boundary that has historically broken an implementation, in every
/// integer width the format has.
fn tortured_numbers() -> Vec<Value> {
    let mut out = Vec::new();
    for (w, bits) in [
        (NumType::I8, 8u32),
        (NumType::I16, 16),
        (NumType::I32, 32),
        (NumType::I64, 64),
    ] {
        let hi = 1i128 << (bits - 1);
        for v in [0, 1, -1, hi - 1, -hi] {
            out.push(Value::int(w, v));
        }
    }
    for (w, bits) in [
        (NumType::U8, 8u32),
        (NumType::U16, 16),
        (NumType::U32, 32),
        (NumType::U64, 64),
    ] {
        for v in [0i128, 1, (1i128 << bits) - 1] {
            out.push(Value::int(w, v));
        }
    }
    // i128 / u128 extremes, which no 64-bit fold can hold.
    out.push(Value::Int { w: NumType::I128, neg: false, mag: (1u128 << 127) - 1 });
    out.push(Value::Int { w: NumType::I128, neg: true, mag: 1u128 << 127 });
    out.push(Value::Int { w: NumType::U128, neg: false, mag: u128::MAX });
    out.push(Value::Int { w: NumType::U128, neg: false, mag: 1u128 << 127 });
    // The 2^53 neighbourhood, where a fold through f64 stops being exact.
    for d in [-1i128, 0, 1] {
        out.push(Value::int(NumType::I64, (1i128 << 53) + d));
        out.push(Value::int(NumType::U64, (1i128 << 53) + d));
        out.push(Value::int(NumType::I64, -((1i128 << 53) + d)));
    }
    // Snowflake-shaped ids.
    for v in [1234567890123456789i128, 9007199254740993, i64::MAX as i128] {
        out.push(Value::int(NumType::I64, v));
    }
    for v in [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        5e-324, // the smallest subnormal
        f64::MAX,
        f64::MIN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        9007199254740992.0, // 2^53
        9007199254740994.0,
    ] {
        out.push(Value::f64(v));
    }
    for v in [0.0f32, -0.0, 1.0, -1.0, f32::MAX, f32::MIN, f32::INFINITY] {
        out.push(f32v(v));
    }
    out
}

/// At least one value per ordered group, deliberately heterogeneous: rule 10's
/// cross-type order is only exercised if the corpus crosses group boundaries.
fn ordered_corpus() -> Vec<Value> {
    let mut out = vec![Value::Null, Value::Bool(false), Value::Bool(true)];
    out.extend(tortured_numbers());
    out.extend([
        Value::Char(0x41),
        Value::Char(0x00),
        Value::Char(0x10FFFF),
        Value::Str(String::new()),
        Value::Str("a".into()),
        Value::Str("ab".into()),
        Value::Str("b".into()),
        Value::Str("é".into()),
        Value::Str("一".into()),
        // U+FF61 and U+1F600 together make the pair sweep a control for the
        // UTF-16 mistake, which is the one a JVM or Dart implementation makes.
        Value::Str("\u{FF61}".into()),
        Value::Str("\u{1F600}".into()),
        Value::Bytes(vec![]),
        Value::Bytes(vec![0]),
        Value::Bytes(vec![0, 0]),
        Value::Bytes(vec![0xFF]),
        Value::NitriteId(0),
        Value::NitriteId(-1),
        Value::NitriteId(1),
        Value::NitriteId(i64::MAX),
        Value::NitriteId(i64::MIN),
        Value::Uuid([0; 16]),
        Value::Uuid([0xFF; 16]),
        Value::Uuid({
            let mut u = [0u8; 16];
            u[0] = 1;
            u
        }),
        Value::Timestamp(0),
        Value::Timestamp(1000),
        Value::Timestamp(-1),
        Value::TimestampNs(1, 0), // equals Timestamp(1000) -- rule 7
        Value::TimestampNs(0, 1),
        Value::Zoned(1000, "Asia/Kolkata".into()),
        Value::Date(0),
        Value::Date(-1),
        Value::Date(19000),
        Value::Time(0),
        Value::Time(86_399_999_999_999),
        Value::Duration(0, 0),
        Value::Duration(-1, 999_999_999),
        Value::Duration(1, 1),
        Value::Array(vec![]),
        Value::Array(vec![Value::Bool(false)]),
        Value::Array(vec![Value::Bool(true)]),
        Value::Array(vec![Value::Bool(false), Value::Bool(false)]),
    ]);
    out
}

/// Ordered by rule 8, but with no key encoding, so they take no part in the
/// CKE agreement sweep.
fn unencodable_but_ordered() -> Vec<Value> {
    vec![
        Value::Doc(vec![]),
        Value::Doc(vec![("a".into(), Value::Bool(false))]),
        Value::Doc(vec![("a".into(), Value::Bool(true))]),
        Value::Map(vec![]),
        Value::Map(vec![(Value::Str("a".into()), Value::Bool(false))]),
        Value::Map(vec![(Value::Str("a".into()), Value::Bool(true))]),
    ]
}

// ---------------------------------------------------------------------------
// The chapter's reason for existing.
// ---------------------------------------------------------------------------

#[test]
fn cke_byte_order_is_the_section_8_value_order() {
    let keyable: Vec<Value> =
        ordered_corpus().into_iter().filter(cke::is_key_encodable).collect();
    assert!(keyable.len() > 100, "the corpus must be big enough to mean something");
    let keys: Vec<Vec<u8>> =
        keyable.iter().map(|v| cke::encode(v).expect("key-encodable")).collect();

    let mut strict = 0usize;
    for (i, a) in keyable.iter().enumerate() {
        for (j, b) in keyable.iter().enumerate() {
            let want = sign(cmp(a, b));
            let got = sign(keys[i].as_slice().cmp(keys[j].as_slice()));
            if want == 0 {
                // Clause 2 of `03-key-encoding.md` §1: values the order calls
                // equal may still differ in the trailing numeric type code.
                if got != 0 {
                    assert_eq!(
                        keys[i][..keys[i].len() - 1],
                        keys[j][..keys[j].len() - 1],
                        "equal values whose ordering regions differ: {a:?} vs {b:?}"
                    );
                }
                continue;
            }
            strict += 1;
            assert_eq!(
                want, got,
                "CKE order disagrees with §8\n  a = {a:?}\n  b = {b:?}\n  \
                 compare_values says {want}, memcmp says {got}"
            );
        }
    }
    // The bound's job is to catch a corpus that silently shrank -- a sweep
    // over three values also "passes" every assertion above it.
    assert!(strict > 10_000, "only {strict} strict pairs");
}

#[test]
fn the_cross_group_order_is_the_group_tag_order() {
    // Rule 10 says cross-type order "is the group order given in
    // 03-key-encoding.md §2". The first byte of a CKE key is its group tag, so
    // that is directly checkable.
    let keyable: Vec<Value> =
        ordered_corpus().into_iter().filter(cke::is_key_encodable).collect();
    for a in &keyable {
        for b in &keyable {
            let ga = cke::encode(a).unwrap()[0];
            let gb = cke::encode(b).unwrap()[0];
            if ga == gb {
                continue;
            }
            assert_eq!(
                sign(cmp(a, b)),
                sign(ga.cmp(&gb)),
                "cross-group order must follow the group tag: {a:?} (0x{ga:02x}) \
                 vs {b:?} (0x{gb:02x})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// It has to be an order at all. A comparator that is not transitive makes every
// sort in the engine undefined, and no round-trip test can see it.
// ---------------------------------------------------------------------------

#[test]
fn the_order_is_reflexive_antisymmetric_and_total() {
    let mut all = ordered_corpus();
    all.extend(unencodable_but_ordered());
    for a in &all {
        assert_eq!(cmp(a, a), Ordering::Equal, "{a:?} != itself");
        assert!(values_equal(a, a));
        for b in &all {
            assert_eq!(
                sign(cmp(a, b)),
                -sign(cmp(b, a)),
                "not antisymmetric: {a:?} vs {b:?}"
            );
        }
    }
}

#[test]
fn sorting_by_it_produces_a_pairwise_ordered_sequence() {
    // A comparator that is not transitive cannot produce a sequence that is
    // pairwise ordered, so this catches it without the O(n^3) sweep.
    let mut all = ordered_corpus();
    all.extend(unencodable_but_ordered());
    all.sort_by(|a, b| cmp(a, b));
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            assert_ne!(
                cmp(&all[i], &all[j]),
                Ordering::Greater,
                "sort produced an unordered sequence:\n  [{i}] {:?}\n  [{j}] {:?}",
                all[i],
                all[j]
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The ten rules, one test each.
// ---------------------------------------------------------------------------

#[test]
fn rule_1_null_equals_only_null_and_sorts_below_everything() {
    assert_eq!(cmp(&Value::Null, &Value::Null), Ordering::Equal);
    for v in ordered_corpus() {
        if matches!(v, Value::Null) {
            continue;
        }
        assert_eq!(cmp(&Value::Null, &v), Ordering::Less, "vs {v:?}");
    }
}

#[test]
fn rule_2_every_numeric_tag_is_one_domain_compared_exactly() {
    assert_eq!(
        cmp(&Value::int(NumType::I32, 5), &Value::int(NumType::I64, 5)),
        Ordering::Equal
    );
    assert_eq!(
        cmp(&Value::int(NumType::I32, 5), &Value::f64(5.0)),
        Ordering::Equal
    );
    assert_eq!(cmp(&Value::int(NumType::U8, 5), &f32v(5.0)), Ordering::Equal);
    // 2^53+1 against the f64 that 2^53+1 rounds to: a fold through f64 calls
    // these equal.
    assert_eq!(
        cmp(&Value::int(NumType::I64, (1i128 << 53) + 1), &Value::f64(9007199254740992.0)),
        Ordering::Greater
    );
    // 2^100 is about 1.2677e30, so it straddles 1e30 and 1e31. No i64 or f64
    // fold can place it against both.
    let huge = Value::Int { w: NumType::I128, neg: false, mag: 1u128 << 100 };
    assert_eq!(cmp(&huge, &Value::f64(1e30)), Ordering::Greater);
    assert_eq!(cmp(&huge, &Value::f64(1e31)), Ordering::Less);
}

#[test]
fn rule_3_nan_equals_nan_and_sorts_above_every_number() {
    let nan = Value::f64(f64::NAN);
    assert_eq!(cmp(&nan, &nan), Ordering::Equal, "a NaN key must be findable");
    assert_eq!(cmp(&nan, &Value::f64(f64::INFINITY)), Ordering::Greater);
    let i128max = Value::Int { w: NumType::I128, neg: false, mag: (1u128 << 127) - 1 };
    assert_eq!(cmp(&nan, &i128max), Ordering::Greater);
    // Two NaN payloads are one value, which is what makes the key lossy about
    // payload legitimate.
    let other = Value::f64(f64::from_bits(0x7FF8_0000_0000_0001));
    assert_eq!(cmp(&nan, &other), Ordering::Equal);
}

#[test]
fn rule_3_negative_zero_equals_positive_zero() {
    assert_eq!(cmp(&Value::f64(-0.0), &Value::f64(0.0)), Ordering::Equal);
    assert_eq!(cmp(&Value::f64(-0.0), &Value::int(NumType::I32, 0)), Ordering::Equal);
    assert_eq!(cmp(&f32v(-0.0), &Value::f64(0.0)), Ordering::Equal);
}

#[test]
fn rule_4_str_compares_by_utf8_byte_order() {
    // U+FF61 is one UTF-16 code unit (0xFF61); U+10000 is a surrogate pair
    // starting 0xD800 -- lower in UTF-16, higher in code point. A comparator
    // written over UTF-16 units gets this backwards. Rust's own str Ord is
    // already byte order, so this is a regression guard, not a Rust hazard.
    let a = Value::Str("｡".into());
    let b = Value::Str("\u{10000}".into());
    assert_eq!(cmp(&a, &b), Ordering::Less);
    assert_eq!(cmp(&Value::Str("ab".into()), &Value::Str("abc".into())), Ordering::Less);
    assert_eq!(cmp(&Value::Str(String::new()), &Value::Str("a".into())), Ordering::Less);
    // No case folding, no normalization.
    assert_eq!(cmp(&Value::Str("A".into()), &Value::Str("a".into())), Ordering::Less);
    assert_ne!(
        cmp(&Value::Str("é".into()), &Value::Str("e\u{0301}".into())),
        Ordering::Equal,
        "§8 rule 4 forbids normalization in the comparison"
    );
}

#[test]
fn rule_5_bytes_is_lexicographic_shorter_is_smaller_on_a_prefix() {
    assert_eq!(
        cmp(&Value::Bytes(vec![1, 2]), &Value::Bytes(vec![1, 2, 0])),
        Ordering::Less
    );
    assert_eq!(cmp(&Value::Bytes(vec![]), &Value::Bytes(vec![0])), Ordering::Less);
    // Unsigned: 0xFF is above 0x01.
    assert_eq!(
        cmp(&Value::Bytes(vec![0xFF]), &Value::Bytes(vec![0x01])),
        Ordering::Greater
    );
}

#[test]
fn rule_6_char_is_not_a_one_character_str() {
    assert_ne!(cmp(&Value::Char(0x61), &Value::Str("a".into())), Ordering::Equal);
    assert_eq!(cmp(&Value::Char(0x41), &Value::Char(0x61)), Ordering::Less);
}

#[test]
fn rule_7_the_three_instant_tags_compare_as_one_instant() {
    assert_eq!(
        cmp(&Value::Timestamp(1000), &Value::TimestampNs(1, 0)),
        Ordering::Equal
    );
    assert_eq!(
        cmp(&Value::Timestamp(1000), &Value::Zoned(1000, "UTC".into())),
        Ordering::Equal
    );
    assert_eq!(
        cmp(
            &Value::Zoned(1000, "UTC".into()),
            &Value::Zoned(1000, "Asia/Kolkata".into())
        ),
        Ordering::Equal,
        "ZONED denotes an instant; the zone is display, not order"
    );
    assert_eq!(
        cmp(&Value::TimestampNs(1, 0), &Value::TimestampNs(1, 1)),
        Ordering::Less
    );
}

#[test]
fn rule_7_date_time_and_duration_are_not_comparable_to_instants() {
    let ts = Value::Timestamp(0);
    for v in [Value::Date(0), Value::Time(0), Value::Duration(0, 0)] {
        assert_ne!(cmp(&ts, &v), Ordering::Equal, "vs {v:?}");
        assert_eq!(sign(cmp(&ts, &v)), -sign(cmp(&v, &ts)));
    }
}

#[test]
fn rule_8_array_compares_element_wise_then_by_length() {
    assert_eq!(
        cmp(
            &Value::Array(vec![Value::Bool(false)]),
            &Value::Array(vec![Value::Bool(true)])
        ),
        Ordering::Less
    );
    assert_eq!(
        cmp(
            &Value::Array(vec![Value::Bool(false)]),
            &Value::Array(vec![Value::Bool(false), Value::Bool(false)])
        ),
        Ordering::Less,
        "a prefix sorts first"
    );
    // Element-wise beats length.
    assert_eq!(
        cmp(
            &Value::Array(vec![Value::Bool(true)]),
            &Value::Array(vec![Value::Bool(false), Value::Bool(false)])
        ),
        Ordering::Greater
    );
}

#[test]
fn rule_8_doc_and_map_compare_as_their_sorted_key_value_sequences() {
    assert_eq!(
        cmp(
            &Value::Doc(vec![("a".into(), Value::Bool(false))]),
            &Value::Doc(vec![("a".into(), Value::Bool(true))])
        ),
        Ordering::Less
    );
    // Field insertion order must not matter: a DOC is its *sorted* sequence.
    assert_eq!(
        cmp(
            &Value::Doc(vec![
                ("a".into(), Value::Bool(false)),
                ("b".into(), Value::Bool(true)),
            ]),
            &Value::Doc(vec![
                ("b".into(), Value::Bool(true)),
                ("a".into(), Value::Bool(false)),
            ])
        ),
        Ordering::Equal,
        "a DOC is its sorted field sequence, not its literal order"
    );
    assert_eq!(
        cmp(
            &Value::Map(vec![(Value::Str("a".into()), Value::Bool(false))]),
            &Value::Map(vec![(Value::Str("b".into()), Value::Bool(false))])
        ),
        Ordering::Less
    );
}

#[test]
fn rule_8_doc_and_map_are_ordered_but_are_not_keys() {
    for v in unencodable_but_ordered() {
        assert!(is_ordered(&v), "{v:?} is ordered by rule 8");
        assert!(!cke::is_key_encodable(&v), "{v:?} has no key encoding");
    }
}

#[test]
fn rule_9_false_is_below_true() {
    assert_eq!(cmp(&Value::Bool(false), &Value::Bool(true)), Ordering::Less);
    assert_eq!(cmp(&Value::Bool(true), &Value::Bool(true)), Ordering::Equal);
}

// ---------------------------------------------------------------------------
// The refusals. §8's closing paragraph is a MUST, and an implementation that
// quietly returns Equal for two OPAQUE values makes them indexable by accident.
// ---------------------------------------------------------------------------

#[test]
fn rule_10_array_is_below_map_is_below_doc() {
    // §8 rule 10's extension. Not a matter of taste: this is the assertion two
    // implementations failed in *opposite* directions, and it is unobservable
    // from any file because these ranks are never written down. Only a test
    // that names the order holds the implementations together.
    let arr = Value::Array(vec![]);
    let map = Value::Map(vec![]);
    let doc = Value::Doc(vec![]);
    assert_eq!(cmp(&arr, &map), Ordering::Less);
    assert_eq!(cmp(&map, &doc), Ordering::Less);
    assert_eq!(cmp(&arr, &doc), Ordering::Less);
    for v in [&arr, &map, &doc] {
        assert_eq!(cmp(&Value::Str("zzz".into()), v), Ordering::Less, "{v:?}");
    }
}

#[test]
fn comparing_two_unordered_values_is_an_error_not_equal() {
    // Returning Equal is the dangerous answer: it makes two different
    // geometries indistinguishable to a sort, a dedup and values_equal. This
    // crate returned Equal until §8's closing paragraph was made explicit.
    let g1 = Value::Geometry(vec![1, 1, 0, 0, 0]);
    let g2 = Value::Geometry(vec![1, 2, 0, 0, 0]);
    assert!(compare_values(&g1, &g2).is_err(), "two geometries must not compare");
    assert!(compare_values(&g1, &Value::Null).is_err(), "on the left");
    assert!(compare_values(&Value::Null, &g1).is_err(), "on the right");
    assert!(!values_equal(&g1, &g2), "different geometries are not equal");
    assert!(values_equal(&g1, &g1), "and identical ones still are");
}

#[test]
fn dec128_is_refused_rather_than_approximated() {
    // Rule 2 puts DEC128 in the numeric domain, and this crate has no exact
    // decimal arithmetic. Approximating it compared every DEC128 as zero, so
    // DEC128(5) tested equal to INT(0).
    let mut five = [0u8; 16];
    five[0] = 5;
    let mut nine = [0u8; 16];
    nine[0] = 9;
    let d5 = Value::Dec128(five);
    let d9 = Value::Dec128(nine);
    assert!(compare_values(&d5, &d9).is_err());
    assert!(compare_values(&d5, &Value::int(NumType::I32, 0)).is_err());
    assert!(!values_equal(&d5, &Value::int(NumType::I32, 0)));
    assert!(!values_equal(&d5, &d9));
    assert!(values_equal(&d5, &Value::Dec128(five)));
    assert!(!cryptand::cke::is_key_encodable(&d5), "§4.4: no key encoding");
}

#[test]
fn an_unordered_element_never_makes_a_container_comparison_panic() {
    // §8 gives no order for an unordered *element*, but sorting a list of
    // documents has to stay defined. The container comparison ranks such an
    // element deterministically; the containers themselves are still ordered.
    let a = Value::Array(vec![Value::Geometry(vec![1])]);
    let b = Value::Array(vec![Value::Geometry(vec![2])]);
    assert!(compare_values(&a, &b).is_ok(), "the ARRAY itself is ordered");
    assert_eq!(sign(cmp(&a, &b)), -sign(cmp(&b, &a)), "and antisymmetric");
    assert_eq!(cmp(&a, &a), Ordering::Equal);
}

#[test]
fn unordered_types_are_refused_and_have_no_key_encoding() {
    let unordered = [
        Value::Regex("a".into(), String::new()),
        Value::VectorF32(vec![1.0]),
        Value::Geometry(vec![1, 1, 0, 0, 0]),
        Value::Opaque {
            origin: "java".into(),
            type_name: "java.lang.Object".into(),
            data: vec![1],
        },
        Value::Unknown { tag: 0xEE, payload: vec![1] },
    ];
    for v in &unordered {
        assert!(!is_ordered(v), "{v:?} must not be ordered");
        assert!(!cke::is_key_encodable(v), "{v:?} must have no key encoding");
        assert!(compare_values(v, &Value::Null).is_err(), "{v:?} on the left");
        assert!(compare_values(&Value::Null, v).is_err(), "{v:?} on the right");
    }
}

// ---------------------------------------------------------------------------
// compare_numeric on its own -- it is a public function, so it is API.
// ---------------------------------------------------------------------------

#[test]
fn compare_numeric_agrees_with_compare_values_on_every_numeric_pair() {
    let nums = tortured_numbers();
    for a in &nums {
        for b in &nums {
            assert_eq!(
                sign(compare_numeric(a, b)),
                sign(cmp(a, b)),
                "{a:?} vs {b:?}"
            );
        }
    }
}

#[test]
fn compare_numeric_spans_the_whole_128_bit_range_without_a_fold() {
    let i128max = Value::Int { w: NumType::I128, neg: false, mag: (1u128 << 127) - 1 };
    let u128max = Value::Int { w: NumType::U128, neg: false, mag: u128::MAX };
    assert_eq!(compare_numeric(&i128max, &u128max), Ordering::Less);
    assert_eq!(compare_numeric(&u128max, &Value::f64(f64::INFINITY)), Ordering::Less);
    let i128min = Value::Int { w: NumType::I128, neg: true, mag: 1u128 << 127 };
    assert_eq!(
        compare_numeric(&i128min, &Value::f64(f64::NEG_INFINITY)),
        Ordering::Greater
    );
}
