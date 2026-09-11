//! The engine end to end: writes, reads, flush, compaction, recovery.

mod support;
use support::*;

use cryptand::backup::{Backup, BackupMode};
use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::segment::value_kind;
use cryptand::spaceapi::SpaceApi;
use cryptand::value::Value;
use cryptand::verify::{Class, EngineVerify};

const T: u32 = 16;

#[test]
fn put_get_round_trip_through_the_memtable() {
    // Phase 2 of the Dart reference shipped a `get` that never consulted the
    // memtable, and 259 tests missed it because they all compacted first. This
    // one deliberately does not.
    let (_t, mut e) = engine("memtable", Profile::Desktop);
    e.put(T, &Value::NitriteId(1), b"one").unwrap();
    assert_eq!(e.get(T, &Value::NitriteId(1)).unwrap().as_deref(), Some(&b"one"[..]));
    assert_eq!(e.get(T, &Value::NitriteId(2)).unwrap(), None);
}

#[test]
fn newest_version_wins_across_a_flush() {
    let (_t, mut e) = engine("versions", Profile::Desktop);
    e.put(T, &Value::NitriteId(1), b"v1").unwrap();
    e.flush().unwrap();
    e.put(T, &Value::NitriteId(1), b"v2").unwrap();
    e.flush().unwrap();
    assert_eq!(e.get(T, &Value::NitriteId(1)).unwrap().as_deref(), Some(&b"v2"[..]));
    e.remove(T, &Value::NitriteId(1)).unwrap();
    e.flush().unwrap();
    assert_eq!(e.get(T, &Value::NitriteId(1)).unwrap(), None);
}

#[test]
fn values_at_or_above_vlog_min_are_separated() {
    let (_t, mut e) = engine("vlog", Profile::Desktop);
    let big = vec![7u8; 4096];
    e.put(T, &Value::NitriteId(1), &big).unwrap();
    e.flush().unwrap();
    let refs = e.all_refs().unwrap();
    let seg = e.segment(&refs[0]).unwrap();
    let rec = seg.iter().next().unwrap().unwrap();
    assert_eq!(rec.value_kind, value_kind::VLOG, "a 4 KiB value must reach the value log");
    assert_eq!(e.get(T, &Value::NitriteId(1)).unwrap().unwrap(), big);
}

#[test]
fn a_scan_returns_every_live_row_in_key_order() {
    let (_t, mut e) = engine("scan", Profile::Desktop);
    for i in 0..500i64 {
        e.put(T, &Value::NitriteId(i), format!("v{i}").as_bytes()).unwrap();
    }
    e.flush().unwrap();
    for i in (0..500i64).step_by(5) {
        e.remove(T, &Value::NitriteId(i)).unwrap();
    }
    e.flush().unwrap();
    let rows = e.scan_tree(T, None, None, None, true).unwrap();
    assert_eq!(rows.len(), 400);
    let mut prev: Option<Vec<u8>> = None;
    for (k, _) in &rows {
        if let Some(p) = &prev {
            assert!(p < k, "scan is not in key order");
        }
        prev = Some(k.clone());
    }
}

#[test]
fn compaction_preserves_every_answer() {
    let (_t, mut e) = engine("compact", Profile::Desktop);
    e.memtable_entry_limit = 200;
    let mut rng = Rng::new(7);
    let mut want = std::collections::BTreeMap::new();
    for _ in 0..4000 {
        let id = rng.below(800) as i64;
        let v = format!("v{}", rng.next() % 1000);
        e.put(T, &Value::NitriteId(id), v.as_bytes()).unwrap();
        want.insert(id, v);
        if e.memtable_pressure().0 >= 200 {
            e.flush().unwrap();
            e.maybe_compact(Some(u64::MAX)).unwrap();
        }
    }
    e.flush().unwrap();
    e.drain_compaction().unwrap();
    e.commit(Durability::Sync).unwrap();
    for (id, v) in &want {
        assert_eq!(
            e.get(T, &Value::NitriteId(*id)).unwrap().as_deref(),
            Some(v.as_bytes()),
            "id {id} after compaction"
        );
    }
    let r = e.verify().unwrap();
    assert!(r.of(Class::Corruption).is_empty(), "{:?}", r.findings);
}

#[test]
fn reopening_after_a_commit_sees_every_committed_row() {
    let t = TempDb::new("reopen");
    {
        let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
        for i in 0..300i64 {
            e.put(T, &Value::NitriteId(i), format!("v{i}").as_bytes()).unwrap();
        }
        e.close(true).unwrap();
    }
    let mut e = Engine::open(&t.path, None).unwrap();
    for i in 0..300i64 {
        assert_eq!(
            e.get(T, &Value::NitriteId(i)).unwrap().as_deref(),
            Some(format!("v{i}").as_bytes()),
            "id {i} after reopen"
        );
    }
    let r = e.verify().unwrap();
    assert!(r.of(Class::Corruption).is_empty(), "{:?}", r.findings);
}

#[test]
fn a_large_separated_value_survives_a_reopen() {
    let t = TempDb::new("reopen-vlog");
    let big = vec![9u8; 8000];
    {
        let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
        e.put(T, &Value::NitriteId(42), &big).unwrap();
        e.close(true).unwrap();
    }
    let mut e = Engine::open(&t.path, None).unwrap();
    assert_eq!(e.get(T, &Value::NitriteId(42)).unwrap().unwrap(), big);
}

#[test]
fn range_delete_is_one_write_and_hides_the_interval() {
    let (_t, mut e) = engine("rangedelete", Profile::Desktop);
    for i in 0..100i64 {
        e.put(T, &Value::NitriteId(i), b"x").unwrap();
    }
    e.flush().unwrap();
    e.remove_range(T, &Value::NitriteId(20), &Value::NitriteId(40)).unwrap();
    e.flush().unwrap();
    assert!(e.get(T, &Value::NitriteId(19)).unwrap().is_some());
    assert!(e.get(T, &Value::NitriteId(20)).unwrap().is_none());
    assert!(e.get(T, &Value::NitriteId(39)).unwrap().is_none());
    assert!(e.get(T, &Value::NitriteId(40)).unwrap().is_some());
    assert_eq!(e.scan_tree(T, None, None, None, false).unwrap().len(), 80);
}

#[test]
fn a_range_delete_still_in_the_memtable_hides_the_interval() {
    // The test above flushes after `remove_range`, so its range delete is
    // always resolved out of a **segment**. Nothing exercised the other half of
    // `range_deletes_for` — the memtable one — and the gap was invisible until
    // a control asked it to be: with the memtable half disabled outright, the
    // entire suite still passed.
    //
    // §4 resolves a range delete at read time from wherever it currently
    // lives, and between `remove_range` and the next flush that is the
    // memtable. A reader that consults only segments returns deleted data,
    // which is the definition of wrong.
    let (_t, mut e) = engine("rangedelete-mem", Profile::Desktop);
    for i in 0..100i64 {
        e.put(T, &Value::NitriteId(i), b"x").unwrap();
    }
    e.flush().unwrap();

    // No flush after this one: the range delete stays in the memtable.
    e.remove_range(T, &Value::NitriteId(20), &Value::NitriteId(40)).unwrap();

    assert!(e.get(T, &Value::NitriteId(19)).unwrap().is_some(), "19 is outside the interval");
    assert!(e.get(T, &Value::NitriteId(20)).unwrap().is_none(), "an unflushed range delete did not hide its start");
    assert!(e.get(T, &Value::NitriteId(30)).unwrap().is_none(), "an unflushed range delete did not hide its middle");
    assert!(e.get(T, &Value::NitriteId(39)).unwrap().is_none(), "an unflushed range delete did not hide its end");
    assert!(e.get(T, &Value::NitriteId(40)).unwrap().is_some(), "the interval is half-open");
    assert_eq!(e.scan_tree(T, None, None, None, false).unwrap().len(), 80, "a scan must honour it too");

    // And it survives the flush, so the memtable path and the segment path
    // agree rather than merely both existing.
    e.flush().unwrap();
    assert!(e.get(T, &Value::NitriteId(30)).unwrap().is_none());
    assert_eq!(e.scan_tree(T, None, None, None, false).unwrap().len(), 80);
}

#[test]
fn the_point_index_answers_exactly_what_the_descent_does() {
    // `Segment::lookup_ref_hashed` is only built after a segment has served
    // one lookup per 32 entries, so no small test ever reaches it. This one
    // reads every key several times over segments that hold superseded
    // versions (pinned by a snapshot), tombstones, and a range delete whose
    // start cell is the newest cell of a live key -- the three cases where a
    // key's first cell is not its answer -- and checks every answer, current
    // and at the snapshot, against a model.
    let (_t, mut e) = engine("point-index", Profile::Desktop);
    let n = 1000i64;
    let key = |i: i64| Value::NitriteId(i);
    for i in 0..n {
        e.put(T, &key(i), format!("a{i}").as_bytes()).unwrap();
    }
    // A flush is what advances `visible_seq`, so it has to precede the
    // snapshot that pins these versions.
    e.flush().unwrap();
    let snap = e.snapshot();
    for i in (0..n).step_by(2) {
        e.put(T, &key(i), format!("b{i}").as_bytes()).unwrap();
    }
    for i in (0..n).step_by(7) {
        e.remove(T, &key(i)).unwrap();
    }
    e.remove_range(T, &key(100), &key(120)).unwrap();
    e.flush().unwrap();
    for i in 500..600 {
        e.put(T, &key(i), format!("c{i}").as_bytes()).unwrap();
    }
    e.flush().unwrap();
    // Merged, so the superseded versions share a segment with their
    // successors, and a key's first cell there is often not its answer.
    e.compact().unwrap();

    let now = |i: i64| -> Option<String> {
        if (500..600).contains(&i) {
            return Some(format!("c{i}"));
        }
        if i >= n || (100..120).contains(&i) || i % 7 == 0 {
            return None;
        }
        Some(if i % 2 == 0 { format!("b{i}") } else { format!("a{i}") })
    };
    let then = |i: i64| (i < n).then(|| format!("a{i}"));
    let s = |v: Option<Vec<u8>>| v.map(|b| String::from_utf8(b).unwrap());
    for pass in 0..3 {
        for i in 0..n + 50 {
            assert_eq!(s(e.get(T, &key(i)).unwrap()), now(i), "key {i}, pass {pass}");
            assert_eq!(s(e.get_at(T, &key(i), Some(&snap)).unwrap()), then(i), "key {i} at the snapshot, pass {pass}");
        }
    }
    let refs = e.all_refs().unwrap();
    assert!(!refs.is_empty());
    for r in &refs {
        assert!(e.segment(r).unwrap().point_indexed(), "segment {} was never read through its index", r.segment_id);
    }
}

#[test]
fn ttl_is_evaluated_at_read_time_and_a_backwards_clock_resurrects() {
    // §9: "an implementation MUST treat a backwards clock jump as resurrecting
    // entries rather than as corruption."
    let (_t, mut e) = engine("ttl", Profile::Desktop);
    e.now_ms = 1000;
    e.put_with_expiry(T, &Value::NitriteId(1), b"x", 2000).unwrap();
    e.flush().unwrap();
    assert!(e.get(T, &Value::NitriteId(1)).unwrap().is_some());
    e.now_ms = 2000;
    assert!(e.get(T, &Value::NitriteId(1)).unwrap().is_none(), "expiry is at-or-before");
    e.now_ms = 1500;
    assert!(e.get(T, &Value::NitriteId(1)).unwrap().is_some(), "a backwards clock resurrects");
}

#[test]
fn shrink_and_backup_round_trip() {
    let t = TempDb::new("backup");
    let dest = TempDb::new("backup-dest");
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    for i in 0..200i64 {
        e.put(T, &Value::NitriteId(i), format!("v{i}").as_bytes()).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let uuid = e.sb.database_uuid;
    e.backup(&dest.path, BackupMode::Plain).unwrap();
    e.shrink().unwrap();
    let mut b = Engine::open(&dest.path, None).unwrap();
    // §2.1: an implementation MUST NOT copy the source's `database_uuid`.
    assert_ne!(b.sb.database_uuid, uuid);
    for i in 0..200i64 {
        assert_eq!(
            b.get(T, &Value::NitriteId(i)).unwrap().as_deref(),
            Some(format!("v{i}").as_bytes())
        );
    }
}

/// A bounded scan must cost the range, not the tree.
///
/// This is a **counter** assertion, and it has to be, for a reason worth
/// stating: a scan that applies `lower`/`upper` to its *result* returns exactly
/// the same rows as one that seeks, and once the segments are in memory it
/// reads exactly the same number of pages. So neither the answers, nor the page
/// counter this project treats as its primary result, nor the cross-language
/// interop gate could tell the two apart. This implementation materialised the
/// whole tree for a one-row index lookup — **7.76 ms, 2 page reads, 1 row** —
/// while the Dart and Java implementations seeked. Only a count of *records
/// examined* separates them, and after the fix the same lookup is 46 µs.
///
/// `04-segments.md` §8 makes cursors mandatory for exactly this.
#[test]
fn a_bounded_scan_examines_the_range_and_not_the_tree() {
    use cryptand::value::Value;

    let (_t, mut e) = engine("bounded-scan", cryptand::container::Profile::Desktop);
    const T: u32 = 16;
    let n = 20_000i64;
    for i in 0..n {
        e.put(T, &Value::NitriteId(i), format!("v{i}").as_bytes()).unwrap();
    }
    e.flush().unwrap();
    e.drain_compaction().unwrap();

    let one = cryptand::cke::encode(&Value::NitriteId(9_000)).unwrap();
    let upper = cryptand::cke::successor(&one).unwrap();

    e.reset_scan_counters();
    let rows = e.scan_tree(T, Some(&one), Some(&upper), None, false).unwrap();
    let examined = e.scan_records_examined();
    assert_eq!(rows.len(), 1, "the range holds exactly one key");

    // The bound is deliberately generous: a seek lands on a leaf and the walk
    // stops at the first key past the range, so the cost is a handful of
    // records per segment, not 20 000. Anything near `n` means the bounds went
    // back to being a post-filter.
    assert!(
        examined < 200,
        "a one-row bounded scan examined {examined} records out of {n}: the \
         bounds are not reaching the segment walk"
    );

    // And the control: an *unbounded* scan of the same tree really does examine
    // the tree, so the assertion above is measuring the bounds and not a
    // counter that never moves.
    e.reset_scan_counters();
    let all = e.scan_tree(T, None, None, None, false).unwrap();
    assert_eq!(all.len(), n as usize);
    assert!(
        e.scan_records_examined() >= n as u64,
        "the unbounded control examined only {} records, so the counter is not \
         measuring what the bounded case claims",
        e.scan_records_examined()
    );
}
