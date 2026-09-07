//! `13-operations.md` §9 — statistics for the query planner.
//!
//! This file exists because `stats.rs` was **dead code**: 180 lines, 0 % line
//! coverage, no caller anywhere in the crate, and a `pub fn _unused()` at the
//! bottom holding it in the build. The Dart implementation wires the same
//! chapter into `analyze` / `statsOf` / `mostSelective`; this crate had the
//! sketch and the histogram and nothing that used them, so §9 was implemented
//! in the sense that the code was present and unimplemented in the sense that
//! no database ever had statistics.
//!
//! §9's own last paragraph is why this can be tested by result rather than by
//! byte: **statistics are advisory.** A planner MUST produce correct results
//! without them, so every test here also checks the without-them path.

use cryptand::database::{Database, Indexing};
use cryptand::index;
use cryptand::stats::{self, HyperLogLog, IndexStats};
use cryptand::value::{NumType, Value};

fn doc(id: i64, city: &str, age: i64) -> Value {
    Value::Doc(vec![
        ("_id".into(), Value::NitriteId(id)),
        ("city".into(), Value::Str(city.into())),
        ("age".into(), Value::int(NumType::I64, age as i128)),
    ])
}

// ---------------------------------------------------------------------------
// The sketch. §9 picks HyperLogLog for one property: it is mergeable and
// fixed-size, so a compaction accumulates it while streaming.
// ---------------------------------------------------------------------------

#[test]
fn the_sketch_estimates_cardinality_within_its_error_bound() {
    let mut h = HyperLogLog::new(10);
    for i in 0..10_000u32 {
        h.add(&i.to_le_bytes());
    }
    let est = h.estimate() as f64;
    // p = 10 gives 1024 registers and a standard error of 1.04/sqrt(m) ~ 3.25 %.
    // Three sigma is ~10 %; the bound here is deliberately loose because the
    // point of the test is that the estimate tracks reality at all, not that it
    // reproduces one particular implementation's rounding.
    assert!(
        (est - 10_000.0).abs() / 10_000.0 < 0.15,
        "estimated {est} for 10 000 distinct keys"
    );
}

#[test]
fn the_sketch_is_mergeable_which_is_why_it_was_chosen() {
    // §9: "two segments' sketches combine by register-wise maximum". Without
    // that, a compaction could not accumulate one while streaming, and an
    // exact distinct count needs memory proportional to cardinality.
    let mut a = HyperLogLog::new(10);
    let mut b = HyperLogLog::new(10);
    let mut whole = HyperLogLog::new(10);
    for i in 0..5_000u32 {
        a.add(&i.to_le_bytes());
        whole.add(&i.to_le_bytes());
    }
    for i in 5_000..10_000u32 {
        b.add(&i.to_le_bytes());
        whole.add(&i.to_le_bytes());
    }
    a.merge(&b);
    assert_eq!(
        a.estimate(),
        whole.estimate(),
        "a merge must give exactly what one pass would have"
    );
}

#[test]
fn the_sketch_counts_duplicates_once() {
    let mut h = HyperLogLog::new(10);
    for _ in 0..1000 {
        h.add(b"the same key");
    }
    assert!(h.estimate() <= 3, "estimated {} for one distinct key", h.estimate());
}

#[test]
fn an_empty_sketch_estimates_zero() {
    assert_eq!(HyperLogLog::new(10).estimate(), 0);
}

// ---------------------------------------------------------------------------
// The descriptor round trip. `params.stats` is a CVE doc inside a catalog
// descriptor, so it has to survive encode and decode without losing a field.
// ---------------------------------------------------------------------------

#[test]
fn stats_round_trip_through_their_value_encoding() {
    let mut b = stats::StatsBuilder::new();
    for i in 0..200u32 {
        b.add(&i.to_be_bytes(), i % 10 == 0);
    }
    let s = b.build(42, 4096);
    let back = IndexStats::from_value(&s.to_value());
    assert_eq!(back.updated_seq, 42);
    assert_eq!(back.entries, s.entries);
    assert_eq!(back.null_count, s.null_count);
    assert_eq!(back.distinct_estimate, s.distinct_estimate);
    assert_eq!(back.min_key, s.min_key);
    assert_eq!(back.max_key, s.max_key);
    assert_eq!(back.histogram.len(), s.histogram.len());
    for (x, y) in back.histogram.iter().zip(s.histogram.iter()) {
        assert_eq!(x.bound, y.bound);
        assert_eq!(x.cumulative, y.cumulative);
    }
}

#[test]
fn an_absent_or_partial_value_decodes_to_zeroes_rather_than_failing() {
    // §9: statistics "may be stale or absent", so the decoder's job is to give
    // a planner something usable, never to refuse.
    let s = IndexStats::from_value(&Value::Doc(vec![]));
    assert_eq!(s.entries, 0);
    assert_eq!(s.histogram.len(), 0);
    assert!(stats::selectivity(&s).is_none(), "no entries means no estimate");
}

// ---------------------------------------------------------------------------
// Defect 37: the histogram is bounded in BYTES, not only in buckets, and the
// byte bound is the binding one. A CKE key runs to kilobytes, and
// `params.stats` is one cell of a copy-on-write B+tree, so it MUST fit a page.
// ---------------------------------------------------------------------------

#[test]
fn the_histogram_is_bounded_in_bytes_not_only_in_buckets() {
    // Long string keys: 64 buckets of these is several kilobytes, which is the
    // measurement that produced defect 37 (4734 B against a 4096 B page).
    let mut b = stats::StatsBuilder::new();
    for i in 0..500u32 {
        let key = format!("{:0>200}", i);
        b.add(key.as_bytes(), false);
    }
    let budget = 2048;
    let s = b.build(1, budget);
    assert!(
        s.encoded_len() <= budget,
        "encoded {} bytes against a {budget} byte budget",
        s.encoded_len()
    );
    assert!(
        s.histogram.len() < stats::MAX_BUCKETS,
        "with keys this long the bucket count MUST have been reduced, got {}",
        s.histogram.len()
    );
    // §9's remedy is to drop *alternate* buckets, so the range is preserved:
    // the last bound still reaches the maximum key.
    assert_eq!(
        s.histogram.last().map(|x| x.bound.clone()),
        Some(s.max_key.clone()),
        "dropping buckets must keep the range, not truncate it"
    );
}

#[test]
fn a_generous_budget_keeps_the_full_bucket_count() {
    // The control for the test above: if the reduction fired regardless of the
    // budget, that test would pass for the wrong reason.
    let mut b = stats::StatsBuilder::new();
    for i in 0..500u32 {
        b.add(&i.to_be_bytes(), false);
    }
    let s = b.build(1, 1 << 20);
    // 500 entries at a quota of ceil(500/64) = 8 gives 63 buckets, not 64:
    // MAX_BUCKETS bounds the count, it does not fix it. Asserting 64 here
    // would be asserting an arithmetic accident.
    assert!(
        s.histogram.len() >= stats::MAX_BUCKETS - 1,
        "a generous budget must keep the full bucket count, got {}",
        s.histogram.len()
    );
}

#[test]
fn the_histogram_is_equi_depth_and_monotone() {
    let mut b = stats::StatsBuilder::new();
    for i in 0..1000u32 {
        b.add(&i.to_be_bytes(), false);
    }
    let s = b.build(1, 1 << 20);
    assert!(!s.histogram.is_empty());
    let mut prev_cum = 0;
    let mut prev_bound: Vec<u8> = Vec::new();
    let mut widths = Vec::new();
    for bkt in &s.histogram {
        assert!(bkt.cumulative > prev_cum, "cumulative must strictly increase");
        assert!(bkt.bound > prev_bound, "bounds must be in key order");
        widths.push(bkt.cumulative - prev_cum);
        prev_cum = bkt.cumulative;
        prev_bound = bkt.bound.clone();
    }
    assert_eq!(prev_cum, s.entries, "the last bucket must cover every entry");
    // Equi-depth: every bucket holds the same count except the last, which
    // takes the remainder.
    let first = widths[0];
    for w in &widths[..widths.len() - 1] {
        assert_eq!(*w, first, "buckets must be equal depth, got {widths:?}");
    }
    assert!(widths[widths.len() - 1] <= first);
}

// ---------------------------------------------------------------------------
// The engine seam: `analyze` writes into `params.stats`, `stats_of` reads it
// back, and `most_selective` decides on it. This is the part that did not
// exist.
// ---------------------------------------------------------------------------

#[test]
fn analyze_writes_statistics_a_reopen_can_read() {
    let mut db = Database::create_in_memory(cryptand::container::Profile::Desktop).unwrap();
    let mut c = db.collection("people").unwrap();
    let by_city = db.create_index(&c, &["city"], "non_unique", false).unwrap();

    for i in 0..300i64 {
        let d = doc(i, if i % 3 == 0 { "delhi" } else { "kolkata" }, 20 + (i % 50));
        let mut d = d;
        c.insert(&mut db.engine, &mut d).unwrap();
        db.index_document(&by_city, &d).unwrap();
    }
    db.commit(cryptand::container::Durability::None).unwrap();

    // §9: absent until something computes them, and that is not an error.
    assert!(db.stats_of(&by_city).unwrap().is_none(), "absent before analyze");

    let s = db.analyze(&by_city).unwrap();
    assert_eq!(s.entries, 300, "one entry per document");
    assert!(s.distinct_estimate > 0);
    assert!(!s.min_key.is_empty() && !s.max_key.is_empty());
    assert!(s.min_key < s.max_key);
    assert!(!s.histogram.is_empty());

    let read_back = db.stats_of(&by_city).unwrap().expect("written to params.stats");
    assert_eq!(read_back.entries, s.entries);
    assert_eq!(read_back.min_key, s.min_key);
    assert_eq!(read_back.histogram.len(), s.histogram.len());
}

#[test]
fn most_selective_picks_on_evidence_and_not_on_uniqueness() {
    // §7.1's complaint about `FindPlan`: it chooses "by whether it is unique
    // and how many fields it covers", so it "routinely picks a unique index on
    // a field the query barely constrains over a non-unique index that would
    // eliminate 99 % of the collection". Here `city` has 2 distinct values over
    // 300 rows and `age` has 50, so the selective index is `age` -- and it is
    // the one a descriptor-only planner has no reason to prefer.
    let mut db = Database::create_in_memory(cryptand::container::Profile::Desktop).unwrap();
    let mut c = db.collection("people").unwrap();
    let by_city = db.create_index(&c, &["city"], "non_unique", false).unwrap();
    let by_age = db.create_index(&c, &["age"], "non_unique", false).unwrap();

    for i in 0..300i64 {
        let mut d = doc(i, if i % 2 == 0 { "delhi" } else { "kolkata" }, 20 + (i % 50));
        c.insert(&mut db.engine, &mut d).unwrap();
        db.index_document(&by_city, &d).unwrap();
        db.index_document(&by_age, &d).unwrap();
    }
    db.commit(cryptand::container::Durability::None).unwrap();

    let candidates = vec![by_city.clone(), by_age.clone()];
    // Before analysis there is no evidence, and §9 says that is "choose some
    // other way", not an error.
    assert!(
        db.most_selective(&candidates).unwrap().is_none(),
        "no statistics means no answer, never a guess"
    );

    db.analyze(&by_city).unwrap();
    db.analyze(&by_age).unwrap();
    let best = db.most_selective(&candidates).unwrap().expect("both analyzed");
    assert_eq!(best.name, by_age.name, "the selective index, not the unique one");

    let city = db.stats_of(&by_city).unwrap().unwrap();
    let age = db.stats_of(&by_age).unwrap().unwrap();
    assert!(
        stats::selectivity(&age).unwrap() < stats::selectivity(&city).unwrap(),
        "age {:?} must be more selective than city {:?}",
        stats::selectivity(&age),
        stats::selectivity(&city)
    );
}

#[test]
fn null_entries_are_counted_and_a_sparse_index_holds_none() {
    let mut db = Database::create_in_memory(cryptand::container::Profile::Desktop).unwrap();
    let mut c = db.collection("people").unwrap();
    // The catalog name is derived from the fields and the index type, so a
    // sparse and a dense index over the *same* field would collide. Two fields
    // carrying the same values keeps the comparison honest.
    let dense = db.create_index(&c, &["nick_d"], "non_unique", false).unwrap();
    let sparse = db.create_index(&c, &["nick_s"], "non_unique", true).unwrap();

    for i in 0..60i64 {
        // Two thirds of the documents have no `nickname` at all.
        let mut d = if i % 3 == 0 {
            Value::Doc(vec![
                ("_id".into(), Value::NitriteId(i)),
                ("nick_d".into(), Value::Str(format!("n{i}"))),
                ("nick_s".into(), Value::Str(format!("n{i}"))),
            ])
        } else {
            Value::Doc(vec![("_id".into(), Value::NitriteId(i))])
        };
        c.insert(&mut db.engine, &mut d).unwrap();
        db.index_document(&dense, &d).unwrap();
        db.index_document(&sparse, &d).unwrap();
    }
    db.commit(cryptand::container::Durability::None).unwrap();

    let d = db.analyze(&dense).unwrap();
    let s = db.analyze(&sparse).unwrap();
    assert_eq!(d.entries, 60, "a dense index holds an entry for every document");
    assert_eq!(d.null_count, 40, "and counts the missing ones as null");
    assert_eq!(s.entries, 20, "a sparse index holds only the present ones");
    assert_eq!(s.null_count, 0, "which is what makes it sparse");
}

#[test]
fn analyze_on_an_empty_index_is_valid_and_says_nothing() {
    let mut db = Database::create_in_memory(cryptand::container::Profile::Desktop).unwrap();
    let c = db.collection("people").unwrap();
    let idx = db.create_index(&c, &["city"], "non_unique", false).unwrap();
    let s = db.analyze(&idx).unwrap();
    assert_eq!(s.entries, 0);
    assert_eq!(s.distinct_estimate, 0);
    assert!(s.histogram.is_empty());
    assert!(stats::selectivity(&s).is_none());
    // And it is still readable back, so a planner sees "no evidence" rather
    // than "no statistics", which are different states.
    assert!(db.stats_of(&idx).unwrap().is_some());
}

#[test]
fn statistics_are_advisory_and_a_stale_one_never_changes_an_answer() {
    // §9's closing MUST: "a planner MUST produce correct results without them".
    // The concrete form of that here is that analysing, and then changing the
    // data without re-analysing, leaves the query answers untouched.
    let mut db = Database::create_in_memory(cryptand::container::Profile::Desktop).unwrap();
    let mut c = db.collection("people").unwrap();
    let idx = db.create_index(&c, &["city"], "non_unique", false).unwrap();
    for i in 0..50i64 {
        let mut d = doc(i, "delhi", 30);
        c.insert(&mut db.engine, &mut d).unwrap();
        db.index_document(&idx, &d).unwrap();
    }
    db.commit(cryptand::container::Durability::None).unwrap();
    db.analyze(&idx).unwrap();

    // An index tree's keys are ARRAY (§2), so equality on the first field is a
    // *prefix* scan; `scan_eq` builds a scalar bound and matches nothing here.
    let scan = index::scan_prefix(&[Value::Str("delhi".into())]).unwrap();
    let before = db.index_scan(&idx, &scan).unwrap();

    for i in 50..100i64 {
        let mut d = doc(i, "delhi", 30);
        c.insert(&mut db.engine, &mut d).unwrap();
        db.index_document(&idx, &d).unwrap();
    }
    db.commit(cryptand::container::Durability::None).unwrap();

    let after = db.index_scan(&idx, &scan).unwrap();
    assert_eq!(before.len(), 50);
    assert_eq!(after.len(), 100, "the answer follows the data, not the statistics");
    let stale = db.stats_of(&idx).unwrap().unwrap();
    assert_eq!(stale.entries, 50, "and the statistics really are stale");
}
