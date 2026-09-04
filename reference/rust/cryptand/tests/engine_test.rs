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
