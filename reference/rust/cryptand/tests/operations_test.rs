//! `10-transactions.md` §3 and §6, and the whole operational surface of
//! `13-operations.md`: checkpoints, backup, repair, metrics, the change feed
//! and multi-process readers.

mod support;
use support::*;

use cryptand::backup::{restore, Backup, BackupMode};
use cryptand::changefeed::ChangeFeed;
use cryptand::checkpoint::Checkpoints;
use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::metrics::{Metric, Metrics};
use cryptand::multiproc::{attach, ReaderMode, Sidecar, VolatileReason};
use cryptand::repair::EngineRepair;
use cryptand::spaceapi::{SpaceApi, Step};
use cryptand::txn::{bounds_of, Backpressure, Bound, Isolation, Transaction, MAX_DELAY_MS};
use cryptand::value::Value;
use cryptand::verify::{Class, EngineVerify};

const T: u32 = 16;

#[test]
fn a_snapshot_transaction_commits_and_a_conflicting_one_aborts() {
    let (_t, mut e) = engine("txn", Profile::Desktop);
    e.put(T, &Value::NitriteId(1), b"base").unwrap();
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();

    let mut a = Transaction::begin(&mut e, Isolation::Snapshot);
    a.put(T, Value::NitriteId(1), b"from-a".to_vec()).unwrap();
    e.put(T, &Value::NitriteId(1), b"interloper").unwrap();
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let err = a.commit(&mut e, Durability::Sync).unwrap_err();
    assert!(matches!(err, cryptand::Error::Conflict(_)), "{err}");
    assert_eq!(e.get(T, &Value::NitriteId(1)).unwrap().as_deref(), Some(&b"interloper"[..]));
}

#[test]
fn rollback_is_free_and_leaves_no_trace() {
    // §3 — "Nothing durable is written before sequencing, so rollback is free
    // and leaves no trace — unlike the undo-log approach all three SDKs use
    // today, which writes and then reverses."
    let (_t, mut e) = engine("rollback", Profile::Desktop);
    let before = e.pager.page_writes;
    let mut tx = Transaction::begin(&mut e, Isolation::Snapshot);
    for i in 0..100i64 {
        tx.put(T, Value::NitriteId(i), b"x".to_vec()).unwrap();
    }
    tx.rollback(&mut e);
    assert_eq!(e.pager.page_writes, before, "a rolled-back transaction wrote pages");
    assert!(e.get(T, &Value::NitriteId(0)).unwrap().is_none());
}

#[test]
fn savepoints_discard_buffered_entries_after_a_mark() {
    let (_t, mut e) = engine("savepoint", Profile::Desktop);
    let mut tx = Transaction::begin(&mut e, Isolation::Snapshot);
    tx.put(T, Value::NitriteId(1), b"keep".to_vec()).unwrap();
    let mark = tx.savepoint();
    tx.put(T, Value::NitriteId(2), b"drop".to_vec()).unwrap();
    tx.rollback_to(mark);
    tx.commit(&mut e, Durability::Sync).unwrap();
    assert!(e.get(T, &Value::NitriteId(1)).unwrap().is_some());
    assert!(e.get(T, &Value::NitriteId(2)).unwrap().is_none());
}

#[test]
fn a_read_only_transaction_cannot_write_and_never_conflicts() {
    let (_t, mut e) = engine("readonly", Profile::Desktop);
    e.put(T, &Value::NitriteId(1), b"v").unwrap();
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let mut tx = Transaction::begin(&mut e, Isolation::ReadOnly);
    assert!(tx.put(T, Value::NitriteId(2), b"x".to_vec()).is_err());
    e.put(T, &Value::NitriteId(1), b"changed").unwrap();
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    assert!(tx.commit(&mut e, Durability::Sync).is_ok(), "a read-only txn never conflicts");
}

#[test]
fn the_backpressure_curve_is_quadratic_and_has_no_cliff() {
    let at = |cur: f64| {
        Backpressure::compute(&[Bound { name: "l0_segments", current: cur, soft: 4.0, hard: 16.0 }])
            .delay_ms
    };
    assert_eq!(at(4.0), 0.0, "at the soft bound the delay is zero");
    assert!((at(16.0) - MAX_DELAY_MS).abs() < 1e-9, "at the hard bound it is max_delay_ms");
    // Quadratic: halfway is a quarter, not a half.
    assert!((at(10.0) - MAX_DELAY_MS * 0.25).abs() < 1e-9);
    let mut prev = 0.0;
    for i in 0..=12 {
        let d = at(4.0 + i as f64);
        assert!(d >= prev, "the curve must be monotone: no cliff before the hard threshold");
        prev = d;
    }
    let bp =
        Backpressure::compute(&[Bound { name: "locality_debt", current: 40.0, soft: 20.0, hard: 40.0 }]);
    assert_eq!(bp.cause, Some("locality_debt"), "the bound that caused it MUST be exposed");
}

#[test]
fn every_bound_of_section_6_is_reported() {
    let (_t, mut e) = engine("bounds", Profile::Desktop);
    let names: Vec<&str> = bounds_of(&mut e).unwrap().iter().map(|b| b.name).collect();
    for want in ["l0_segments", "tier_segments", "memtable_bytes", "vlog_space", "locality_debt"] {
        assert!(names.contains(&want), "bound {want} is not reported");
    }
}

#[test]
fn a_checkpoint_restores_roots_and_never_rolls_a_counter_back() {
    let (_t, mut e) = engine("checkpoint", Profile::Desktop);
    for i in 0..100i64 {
        e.put(T, &Value::NitriteId(i), b"before").unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    e.create_checkpoint("v1", None).unwrap();
    let before = (e.next_seq, e.sb.next_segment_id, e.sb.next_vlog_segment_id, e.sb.next_nonce);

    for i in 100..200i64 {
        e.put(T, &Value::NitriteId(i), b"after").unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    assert!(e.get(T, &Value::NitriteId(150)).unwrap().is_some());

    e.restore_checkpoint("v1").unwrap();
    assert!(e.get(T, &Value::NitriteId(150)).unwrap().is_none(), "restore did not roll roots back");
    assert!(e.get(T, &Value::NitriteId(50)).unwrap().is_some());
    let after = (e.next_seq, e.sb.next_segment_id, e.sb.next_vlog_segment_id, e.sb.next_nonce);
    assert!(after.0 >= before.0 && after.1 >= before.1 && after.2 >= before.2);
    assert!(after.3 >= before.3, "next_nonce was rolled back");
    // A restore keeps the *current* `checkpoint_root`, so it does not delete
    // the other checkpoints.
    assert!(e.checkpoint("v1").unwrap().is_some());
}

#[test]
fn an_expired_checkpoint_is_dropped_automatically() {
    let (_t, mut e) = engine("expiry", Profile::Desktop);
    e.create_checkpoint("soon", Some(1000)).unwrap();
    e.create_checkpoint("later", Some(9999)).unwrap();
    assert_eq!(e.drop_expired_checkpoints(2000).unwrap(), vec!["soon".to_string()]);
    assert!(e.checkpoint("later").unwrap().is_some());
}

#[test]
fn an_incremental_backup_copies_only_what_changed() {
    let (_t, mut e) = engine("incr", Profile::Desktop);
    e.memtable_entry_limit = 100;
    for i in 0..600i64 {
        e.put(T, &Value::NitriteId(i), b"v").unwrap();
        if e.memtable_pressure().0 >= 100 {
            e.flush().unwrap();
        }
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();

    let dest = TempDb::new("incr-dest");
    let full = e.backup_incremental(&dest.path, &[]).unwrap();
    assert!(full.segments_copied > 1);
    let have = e.segment_ids().unwrap();
    // A re-backup with nothing changed copies **zero** segments.
    assert_eq!(e.backup_incremental(&dest.path, &have).unwrap().segments_copied, 0);

    for i in 0..20i64 {
        e.put(T, &Value::NitriteId(i), b"touched").unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let delta = e.backup_incremental(&dest.path, &have).unwrap();
    assert!(delta.segments_copied >= 1);
    assert!(delta.segments_copied < full.segments_copied, "the delta was not smaller");
}

#[test]
fn a_restore_verifies_before_reporting_success() {
    let t = TempDb::new("restore-source");
    {
        let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
        for i in 0..100i64 {
            e.put(T, &Value::NitriteId(i), b"v").unwrap();
        }
        e.close(true).unwrap();
    }
    let src = TempDb::new("restore-copy");
    let dst = TempDb::new("restore-dst");
    let mut e = Engine::open(&t.path, None).unwrap();
    e.backup(&src.path, BackupMode::Plain).unwrap();
    let r = restore(&src.path, &dst.path, None).unwrap();
    assert!(r.of(Class::Corruption).is_empty(), "{:?}", r.findings);
    let mut restored = Engine::open(&dst.path, None).unwrap();
    assert!(restored.get(T, &Value::NitriteId(7)).unwrap().is_some());
}

#[test]
fn a_lost_manifest_is_rebuilt_from_the_segment_headers() {
    // §3 — "every field the manifest holds is duplicated in the segment header
    // for exactly this reason", and `group` is there for no other reason.
    let (_t, mut e) = engine("repair", Profile::Desktop);
    e.memtable_entry_limit = 100;
    for i in 0..600i64 {
        e.put(T, &Value::NitriteId(i), b"v").unwrap();
        if e.memtable_pressure().0 >= 100 {
            e.flush().unwrap();
            e.maybe_compact(Some(u64::MAX)).unwrap();
        }
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let mut before: Vec<(u64, u8, u8)> =
        e.all_refs().unwrap().iter().map(|r| (r.segment_id, r.level, r.group)).collect();
    before.sort_unstable();
    assert!(!before.is_empty());

    e.manifest.tree.root = 0;
    assert!(e.all_refs().unwrap().is_empty());
    let rep = e.rebuild_manifest().unwrap();
    assert_eq!(rep.segments_recovered as usize, before.len());
    let mut after: Vec<(u64, u8, u8)> =
        e.all_refs().unwrap().iter().map(|r| (r.segment_id, r.level, r.group)).collect();
    after.sort_unstable();
    assert_eq!(after, before, "level and group must survive the rebuild");
    for i in 0..600i64 {
        assert!(e.get(T, &Value::NitriteId(i)).unwrap().is_some(), "id {i} lost by the repair");
    }
}

#[test]
fn a_lost_value_log_stats_entry_is_rebuilt_by_scanning_the_records() {
    let (_t, mut e) = engine("repair-vlog", Profile::Desktop);
    for i in 0..50i64 {
        e.put(T, &Value::NitriteId(i), &vec![1u8; 700]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let want: Vec<(u64, u64)> = e.vlog_stats.iter().map(|(id, s)| (*id, s.bytes)).collect();
    assert!(!want.is_empty());
    e.vlog_stats.clear();
    let rep = e.rebuild_vlog_stats().unwrap();
    assert_eq!(rep.vlog_entries_rebuilt as usize, want.len());
    for (id, bytes) in want {
        assert_eq!(e.vlog_stats[&id].bytes, bytes, "watermark for value-log segment {id}");
        // §4.3 of `14-security.md` forbids appending to a segment this session
        // did not open, and a repair is by definition a new session.
        assert!(e.vlog_stats[&id].sealed);
    }
    for i in 0..50i64 {
        assert_eq!(e.get(T, &Value::NitriteId(i)).unwrap().unwrap(), vec![1u8; 700]);
    }
}

#[test]
fn every_maintenance_operation_is_incremental_and_resumable() {
    let (_t, mut e) = engine("spaceapi", Profile::Mobile);
    e.memtable_entry_limit = 100;
    for i in 0..1500i64 {
        e.put(T, &Value::NitriteId(i), b"v").unwrap();
        if e.memtable_pressure().0 >= 100 {
            e.flush().unwrap();
        }
    }
    e.flush().unwrap();
    let mut steps = 0;
    while e.compact_step().unwrap() == Step::More && steps < 2000 {
        steps += 1;
    }
    assert!(steps > 0, "compaction finished in zero bounded steps");
    assert_eq!(e.collect_pass().unwrap(), Step::Done);
    assert_eq!(e.cluster_pass().unwrap(), Step::Done);
    let freed = e.shrink().unwrap();
    println!("compaction took {steps} bounded steps; shrink released {freed} pages");
    assert!(e.verify().unwrap().of(Class::Corruption).is_empty());
}

#[test]
fn a_metric_that_cannot_be_computed_is_reported_unavailable_by_name() {
    // §6 — "A fabricated answer defeats this section more thoroughly than a
    // missing one, because a caller cannot tell the two apart."
    let (_t, mut e) = engine("metrics", Profile::Desktop);
    let m = e.metrics().unwrap();
    assert!(matches!(m["value_reads_per_scanned_row"], Metric::Unavailable(_)));
    assert!(matches!(m["filter_false_positive_rate"], Metric::Unavailable(_)));

    for i in 0..200i64 {
        e.put(T, &Value::NitriteId(i), &vec![7u8; 700]).unwrap();
    }
    e.flush().unwrap();
    e.scan_tree(T, None, None, None, true).unwrap();
    for i in 0..200i64 {
        e.get(T, &Value::NitriteId(i)).unwrap();
    }
    let m = e.metrics().unwrap();
    for name in [
        "bytes_written_logical",
        "bytes_written_device",
        "write_amp_value",
        "write_amp_key_index",
        "write_amp_gc",
        "backpressure_delay_ms",
        "stall_events",
        "live_bytes",
        "allocated_bytes",
        "vlog_live_bytes",
        "vlog_allocated_bytes",
        "locality_debt",
        "vlog_live_runs",
        "vlog_ideal_runs",
        "pinned_by_snapshots",
        "pinned_by_checkpoints",
        "unencrypted_pages",
        "nonces_allocated",
        "nonce_floor",
        "page_cache_hit_rate",
        "segments_probed_per_lookup_p50",
        "segments_probed_per_lookup_p99",
        "filter_false_positive_rate",
        "value_reads_per_scanned_row",
        "oldest_snapshot_age_ms",
        "compaction_backlog_bytes",
        "unavailable_ranges",
    ] {
        assert!(m.contains_key(name), "required metric {name} is missing");
    }
    assert!(!matches!(m["value_reads_per_scanned_row"], Metric::Unavailable(_)));
    assert_eq!(m["unavailable_ranges"], Metric::Count(0), "0 is the normal state");
}

#[test]
fn the_change_feed_is_exactly_consistent_with_the_data() {
    let (_t, mut e) = engine("feed", Profile::Desktop);
    e.enable_change_feed(T);
    for i in 0..20i64 {
        e.put(T, &Value::NitriteId(i), b"v").unwrap();
    }
    e.remove(T, &Value::NitriteId(3)).unwrap();
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let changes = e.read_changes(T, 0).unwrap();
    assert_eq!(changes.len(), 21);
    assert_eq!(changes.last().unwrap().op, "delete");
    for w in changes.windows(2) {
        assert!(w[0].seq < w[1].seq, "the feed is a sequential range scan");
    }
    let cut = changes[10].seq;
    assert_eq!(e.trim_change_feed(T, cut).unwrap(), 10);
    assert_eq!(e.read_changes(T, 0).unwrap().len(), 11);
}

#[test]
fn a_stale_slot_is_a_free_slot_to_a_claimer() {
    // §8's rule 1, and the reason it is normative rather than an optimization:
    // when the writing process dies -- or was never there, as for two
    // `dbinspect` sessions against a file no application has open -- nothing
    // reclaims stale slots. They accumulate, and after `slot_count` reader
    // opens every subsequent reader falls to volatile mode, for a reason it
    // cannot see, against a database where volatile mode is not even necessary.
    let t = TempDb::new("sidecar");
    let path = cryptand::multiproc::sidecar_path(&t.path);
    let side = Sidecar::create(&path, 2, 2000).unwrap();
    assert!(matches!(attach(&side, 10, 1_000_000).unwrap(), ReaderMode::Slotted(_)));
    assert!(matches!(attach(&side, 11, 1_000_000).unwrap(), ReaderMode::Slotted(_)));
    // Both slots held by live readers: §8 rule 4 requires the implementation to
    // report **which** of its two causes it hit.
    match attach(&side, 12, 1_000_000).unwrap() {
        ReaderMode::Volatile(VolatileReason::SidecarFull) => {}
        other => panic!("expected SidecarFull, got {other:?}"),
    }
    // Time passes; both heartbeats go stale, so a *claimer* recycles one —
    // which is rule 1's clause, and the fix for the accumulation above.
    let later = 1_000_000 + 10 * 2000;
    assert!(matches!(attach(&side, 13, later).unwrap(), ReaderMode::Slotted(_)));
}

#[test]
fn a_dead_writer_is_visible_to_a_reader() {
    // §8 rule 5 — a reader MUST treat a `writer_pid` of 0, or a writer
    // heartbeat older than `3 x reader_heartbeat_ms`, as **no live writer**:
    // nothing will reclaim extents, so its own pin protects nothing.
    let t = TempDb::new("nowriter");
    let path = cryptand::multiproc::sidecar_path(&t.path);
    let side = Sidecar::create(&path, 4, 2000).unwrap();
    let now = cryptand::multiproc::now_ms();
    assert!(side.writer_alive(now).unwrap(), "create publishes the writer's own identity");
    assert!(!side.writer_alive(now + 10_000).unwrap(), "a stale heartbeat is no live writer");
    side.refresh_writer(now + 10_000).unwrap();
    assert!(side.writer_alive(now + 10_000).unwrap());
}

#[test]
fn a_reader_slot_pins_min_retained_commit() {
    // §8 rule 2 — the writer computes `min_retained_commit` as the minimum over
    // its own snapshots **and** every live slot; a stale slot does not pin.
    let t = TempDb::new("pin");
    let path = cryptand::multiproc::sidecar_path(&t.path);
    let side = Sidecar::create(&path, 4, 2000).unwrap();
    let now = 5_000_000u64;
    let slot = side.claim(42, now).unwrap().unwrap();
    assert_eq!(side.min_retained_commit(100, now).unwrap(), 42);
    let stale = now + 10 * 2000;
    assert_eq!(side.min_retained_commit(100, stale).unwrap(), 100, "a stale slot does not pin");
    side.release(&slot).unwrap();
    assert_eq!(side.min_retained_commit(100, now).unwrap(), 100);
}
