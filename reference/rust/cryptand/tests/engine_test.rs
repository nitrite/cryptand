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
fn a_full_compaction_publishes_so_the_next_flush_reuses_its_inputs() {
    // `01-container.md` §1: a compaction publishes with one superblock, and
    // `10-transactions.md` §5 frees the inputs at that commit. `compact()` did
    // not commit, so the inputs stayed named by the live superblock and the
    // next flush appended past them: 425 pages next to 1 679 free ones on the
    // cross-language CRUD matrix.
    let t = TempDb::new("compact-publishes");
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    let doc = vec![5u8; 600];
    for i in 0..4000i64 {
        e.put(T, &Value::NitriteId(i), &doc).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    let before = e.sb.commit_id;
    e.compact().unwrap();
    assert!(e.sb.commit_id > before, "compact() published nothing");

    let after_compact = e.pager.page_count;
    for i in 0..1000i64 {
        e.put(T, &Value::NitriteId(i), &vec![6u8; 600]).unwrap();
    }
    e.flush().unwrap();
    // The flush is about 80 pages; out of the free list it grows the file by
    // at most tree 1's own page or so.
    assert!(
        e.pager.page_count - after_compact < 8,
        "the flush appended {} pages instead of reusing the compacted inputs",
        e.pager.page_count - after_compact
    );
}

/// The cross-language matrix's shape: a full compaction's output standing on
/// the run its inputs left, part of that run then taken by a later flush.
fn compacted(e: &mut Engine, size: usize) {
    for i in 0..4000i64 {
        e.put(T, &Value::NitriteId(i), &vec![0u8; size]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    e.compact().unwrap();
    for i in 0..1500i64 {
        e.put(T, &Value::NitriteId(i), &vec![1u8; size]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
}

fn expected(i: i64, size: usize) -> Option<Vec<u8>> {
    Some(vec![(i < 1500) as u8; size])
}

fn free_pages(e: &Engine) -> u64 {
    e.pager.free_list().iter().map(|x| x.pages as u64).sum()
}

fn shrink_relocates(mut e: Engine, path: &std::path::Path, key: Option<&[u8]>, size: usize) {
    // `13-operations.md` §5: `shrink()` relocates live extents downward and
    // truncates. It only truncated, and a full compaction leaves the free
    // space *below* the live data, so it reclaimed nothing: 820 of 3 366
    // pages on the cross-language CRUD matrix.
    compacted(&mut e, size);
    let before = e.pager.page_count;
    let free_before = free_pages(&e);
    e.shrink().unwrap();
    println!(
        "shrink: {before} pages ({free_before} free) -> {} ({} free)",
        e.pager.page_count,
        free_pages(&e)
    );
    assert!(free_before > before / 5, "the fixture left no free run to reclaim");
    assert!(free_pages(&e) * 20 < e.pager.page_count, "{} free pages left in {}", free_pages(&e), e.pager.page_count);
    let r = e.verify().unwrap();
    assert!(r.of(Class::Corruption).is_empty() && r.of(Class::Leak).is_empty(), "{:?}", r.findings);
    let pages = e.pager.page_count;
    e.close(false).unwrap();
    assert_eq!(std::fs::metadata(path).unwrap().len(), pages * e.pager.page_size as u64);
    let mut e = Engine::open(path, key).unwrap();
    for i in 0..4000i64 {
        assert_eq!(e.get(T, &Value::NitriteId(i)).unwrap(), expected(i, size), "key {i}");
    }
    assert!(e.verify().unwrap().of(Class::Corruption).is_empty());
}

#[test]
fn shrink_moves_live_extents_down_and_ends_the_file_at_them() {
    let t = TempDb::new("shrink-relocates");
    let e = Engine::create(&t.path, Profile::Desktop).unwrap();
    shrink_relocates(e, &t.path, None, 600);
}

#[test]
fn shrink_hops_a_segment_that_stands_on_a_hole_too_small_for_it() {
    // Inline values, so the whole last level is one segment, and no hole below
    // it fits it: it goes to the end and comes back down.
    let t = TempDb::new("shrink-hops");
    let e = Engine::create(&t.path, Profile::Desktop).unwrap();
    shrink_relocates(e, &t.path, None, 200);
}

#[test]
fn shrink_reseals_what_it_moves_in_an_encrypted_file() {
    // A key-index page's nonce binds its page id (`14-security.md` §5.2), so a
    // moved page is sealed again under a fresh nonce; a value-log record's
    // binds its segment id and offset, so it moves as it is.
    let t = TempDb::new("shrink-encrypted");
    let key = [7u8; 32];
    let e = Engine::create_encrypted(&t.path, Profile::Desktop, &key, 0, 0, 0, 0).unwrap();
    shrink_relocates(e, &t.path, Some(&key), 600);
}

#[test]
fn a_closed_file_ends_at_page_count() {
    // `Pager::grow` preallocates in chunks; the tail past `page_count` is
    // debris to every reader, and a closed file has no use for it.
    let t = TempDb::new("close-trims");
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    for i in 0..300i64 {
        e.put(T, &Value::NitriteId(i), &vec![1u8; 600]).unwrap();
    }
    e.close(true).unwrap();
    let pages = e.sb.page_count;
    let len = std::fs::metadata(&t.path).unwrap().len();
    assert_eq!(len, pages * e.pager.page_size as u64);
}

#[test]
fn verify_right_after_an_open_that_sealed_a_segment_finds_no_leak() {
    // §2.1 step 8 seals every unsealed value-log segment on open, which edits
    // tree 7; the page that edit orphans is free at the next commit. `verify`
    // counted only the persisted free list, so it called that page a leak on
    // every file whose writer left a segment open -- every Dart save.
    let t = TempDb::new("open-seals");
    {
        let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
        e.put(T, &Value::NitriteId(1), &vec![9u8; 8000]).unwrap();
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        // Dropped without `close`, so the segment is still unsealed on disk.
    }
    let mut e = Engine::open(&t.path, None).unwrap();
    let r = e.verify().unwrap();
    assert!(r.of(Class::Leak).is_empty(), "{:?}", r.findings);
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

/// F-018. A last-level compaction dropped the range tombstone (its seq was
/// below every snapshot) but kept the point records it covered, which have
/// different user keys and so were never shadowed: the rows came back. Found
/// by `oplog_check` (M1.2), seed 1, minimized to put, range_del, commit, compact.
#[test]
fn compaction_does_not_resurrect_rows_hidden_by_a_range_delete() {
    let (_t, mut e) = engine("rangedelete-compact", Profile::Desktop);
    for i in 0..100i64 {
        e.put(T, &Value::NitriteId(i), b"x").unwrap();
    }
    e.flush().unwrap();
    e.remove_range(T, &Value::NitriteId(20), &Value::NitriteId(40)).unwrap();
    e.flush().unwrap();
    e.compact().unwrap();
    assert!(e.get(T, &Value::NitriteId(25)).unwrap().is_none(), "a deleted row came back");
    assert_eq!(e.scan_tree(T, None, None, None, false).unwrap().len(), 80);
    // and once more, now that everything is in the last level
    e.put(T, &Value::NitriteId(1000), b"y").unwrap();
    e.flush().unwrap();
    e.compact().unwrap();
    assert_eq!(e.scan_tree(T, None, None, None, false).unwrap().len(), 81);
}

/// F-018, second shape: the tombstone's range reaches past every point key of
/// the compaction's inputs into a last-level segment the inputs do not
/// overlap. That segment must join the compaction, or the tombstone is dropped
/// while the rows it hides survive next to it.
#[test]
fn a_range_delete_reaching_past_its_inputs_still_hides_the_rows_it_covers() {
    let (_t, mut e) = engine("rangedelete-reach", Profile::Desktop);
    for i in 500..600i64 {
        e.put(T, &Value::NitriteId(i), b"far").unwrap();
    }
    e.flush().unwrap();
    e.compact().unwrap(); // 500..600 now sits alone in the last level
    e.put(T, &Value::NitriteId(1), b"near").unwrap();
    e.remove_range(T, &Value::NitriteId(2), &Value::NitriteId(10_000)).unwrap();
    e.flush().unwrap();
    // A partial compaction: only the new L0 segment, straight into the last
    // level. (`compact()` takes everything and would hide the defect.)
    let last = e.policy.last_level();
    let l0 = e.refs_at(0).unwrap();
    assert_eq!(l0.len(), 1);
    let mut job = e.begin_compaction(l0, last).unwrap().unwrap();
    while e.step_compaction(&mut job, Some(u64::MAX)).unwrap() {}
    e.finish_compaction(job).unwrap();
    assert!(e.get(T, &Value::NitriteId(550)).unwrap().is_none(), "a deleted row came back");
    assert_eq!(e.scan_tree(T, None, None, None, false).unwrap().len(), 1);
}

/// F-019. Value-log collection decided a record was live with point lookups
/// that ignore range deletes, then re-wrote it as a fresh PUT -- at a seq
/// above the range delete that hid it. A live snapshot is what keeps the old
/// version in the tree for collection to find. `oplog_check` seed 1, shrunk
/// from 2019 lines to 7.
#[test]
fn value_log_collection_does_not_resurrect_a_range_deleted_row() {
    let (_t, mut e) = engine("collect-rangedelete", Profile::Desktop);
    let big = vec![7u8; 6000]; // past every profile's vlog_min
    e.put(T + 1, &Value::NitriteId(1), &big).unwrap();
    e.compact().unwrap();
    e.put(T, &Value::NitriteId(5), &big).unwrap();
    let s = e.snapshot();
    e.remove_range(T, &Value::NitriteId(0), &Value::NitriteId(10)).unwrap();
    e.compact().unwrap();
    assert!(e.get(T, &Value::NitriteId(5)).unwrap().is_none(), "a deleted row came back");
    assert!(e.get_at(T, &Value::NitriteId(5), Some(&s)).unwrap().is_none(), "and the snapshot never saw it");
    assert!(e.scan_tree(T, None, None, None, false).unwrap().is_empty());
}

/// F-020. Collection re-wrote a relocated value with no expiry, so a TTL
/// value that the collector moved never expired.
#[test]
fn value_log_collection_keeps_a_values_expiry() {
    let (_t, mut e) = engine("collect-expiry", Profile::Desktop);
    let big = vec![7u8; 6000];
    e.put(T + 1, &Value::NitriteId(1), &big).unwrap();
    e.compact().unwrap();
    e.put_with_expiry(T, &Value::NitriteId(5), &big, 1_000).unwrap();
    let _s = e.snapshot();
    e.put(T + 1, &Value::NitriteId(2), &big).unwrap();
    e.compact().unwrap();
    e.now_ms = 2_000;
    assert!(e.get(T, &Value::NitriteId(5)).unwrap().is_none(), "an expired value is still readable");
}

/// F-021. A last-level compaction dropped a tombstone that every snapshot
/// sees, but kept the version beneath it because the key's *newest* version
/// was newer than the oldest snapshot. That snapshot then read the deleted
/// value. `oplog_check` seed 1.
#[test]
fn compaction_does_not_resurrect_a_deleted_version_under_a_snapshot() {
    let (_t, mut e) = engine("compact-snapshot-tombstone", Profile::Desktop);
    e.put(T, &Value::NitriteId(1), b"v1").unwrap();
    e.remove(T, &Value::NitriteId(1)).unwrap();
    e.flush().unwrap();
    let s = e.snapshot();
    e.put(T, &Value::NitriteId(1), b"v2").unwrap();
    e.flush().unwrap();
    e.compact().unwrap();
    assert!(e.get_at(T, &Value::NitriteId(1), Some(&s)).unwrap().is_none(), "the snapshot read a deleted value");
    assert!(e.scan_tree(T, None, None, Some(&s), false).unwrap().is_empty());
    assert_eq!(e.get(T, &Value::NitriteId(1)).unwrap().as_deref(), Some(&b"v2"[..]));
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

/// F-080: tree 1 is rebuilt into end-of-file pages every commit; the pages it
/// leaves behind must come back, or a file grows with its commit count.
#[test]
fn a_thousand_tiny_sync_commits_keep_the_file_bounded() {
    let (_t, mut e) = engine("f080", Profile::Desktop);
    for i in 0..1000i64 {
        e.put(T, &Value::NitriteId(i), format!("v{i}").as_bytes()).unwrap();
        e.flush().unwrap();
        if i % 100 == 99 {
            e.compact().unwrap();
        }
        e.commit(Durability::Sync).unwrap();
    }
    let pages = e.sb.page_count;
    eprintln!("F-080 rust pages={pages}");
    assert!(pages < 1000, "1000 commits of ~10 bytes made {pages} pages");
}
