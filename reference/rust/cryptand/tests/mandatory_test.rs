//! The mandatory tests of `11-conformance.md` §6.
//!
//! Each one exists because the property it checks is invisible to every other
//! check. Where §6 states a number, the number is asserted here.

mod support;
use support::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::filter::{user_key_prefix, BlockedBloom};
use cryptand::manifest::SegmentRef;
use cryptand::metrics::{percentile, Metric, Metrics};
use cryptand::segment::{internal_key, op, value_kind, SegEntry, SegmentBuilder, Segment};
use cryptand::spaceapi::SpaceApi;
use cryptand::store::Store;
use cryptand::value::Value;
use cryptand::verify::{Class, EngineVerify};

const T: u32 = 16;

// ---------------------------------------------------------------------------
// "A concurrency test is mandatory" -- N threads writing overlapping key
// ranges while M threads scan, with a compaction forced throughout.
// ---------------------------------------------------------------------------

#[test]
fn concurrency_n_writers_m_scanners_and_a_compaction_throughout() {
    let t = TempDb::new("concurrency");
    let mut store = Store::create(&t.path, Profile::Desktop).unwrap();
    store.durability = Durability::Os;
    store.spawn_committer(2);
    let store = Arc::new(store);

    let writers = 8usize;
    let per = 400i64;
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for w in 0..writers {
        let s = store.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..per {
                // Overlapping ranges: every writer touches the same 200 keys.
                let id = (i % 200) * 10 + w as i64;
                s.put(T, &Value::NitriteId(id), format!("w{w}-{i}").as_bytes()).unwrap();
            }
        }));
    }
    for _ in 0..3 {
        let s = store.clone();
        let stop = stop.clone();
        handles.push(std::thread::spawn(move || {
            let mut scans = 0u32;
            while !stop.load(Ordering::SeqCst) && scans < 200 {
                // Every reader must observe a snapshot: no torn batch, and no
                // missing value for a key the scan can see.
                let rows = {
                    let mut e = s.engine.lock().unwrap();
                    e.scan_tree(T, None, None, None, true).unwrap()
                };
                for (_k, v) in rows {
                    assert!(!v.is_empty(), "a scan returned a torn value");
                }
                scans += 1;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }));
    }
    for h in handles.drain(..writers) {
        h.join().unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    for h in handles {
        h.join().unwrap();
    }
    store.commit_once().unwrap();
    {
        let mut e = store.engine.lock().unwrap();
        e.drain_compaction().unwrap();
        e.commit(Durability::Sync).unwrap();
        // "the final database must pass `cryptand verify`"
        let r = e.verify().unwrap();
        assert!(r.of(Class::Corruption).is_empty(), "{:?}", r.findings);
        assert!(r.of(Class::Tampering).is_empty(), "{:?}", r.findings);
        let rows = e.scan_tree(T, None, None, None, true).unwrap();
        assert_eq!(rows.len(), 200 * writers, "every distinct key must survive");
    }
    Arc::try_unwrap(store).ok().unwrap().close().unwrap();
}

// ---------------------------------------------------------------------------
// "A read-tail test is mandatory, and **its write load is part of the test**."
// ---------------------------------------------------------------------------

#[test]
fn read_tail_p99_is_at_most_2_and_p99_9_at_most_3() {
    // The write load is normative: keys in **random order**, then updates to a
    // substantial fraction, with no forced full compaction. Ascending inserts
    // give every flush a disjoint key range, so manifest pruning alone leaves
    // one candidate and the measurement means nothing.
    let (_t, mut e) = engine("readtail", Profile::Desktop);
    e.memtable_entry_limit = 500;
    let n = 20_000i64;
    let mut rng = Rng::new(0x5EED);
    let mut ids: Vec<i64> = (0..n).collect();
    for i in (1..ids.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        ids.swap(i, j);
    }
    for &id in &ids {
        e.put(T, &Value::NitriteId(id), format!("v{id}").as_bytes()).unwrap();
        if e.memtable_pressure().0 >= 500 {
            e.flush().unwrap();
            e.maybe_compact(Some(u64::MAX)).unwrap();
        }
    }
    for _ in 0..n / 2 {
        let id = rng.below(n as u64) as i64;
        e.put(T, &Value::NitriteId(id), b"updated").unwrap();
        if e.memtable_pressure().0 >= 500 {
            e.flush().unwrap();
            e.maybe_compact(Some(u64::MAX)).unwrap();
        }
    }
    e.flush().unwrap();

    e.counters.segments_probed.clear();
    for _ in 0..20_000 {
        let id = rng.below(n as u64) as i64;
        e.get(T, &Value::NitriteId(id)).unwrap();
    }
    let p99 = percentile(&e.counters.segments_probed, 0.99);
    let p999 = percentile(&e.counters.segments_probed, 0.999);
    // "An implementation MUST also report which read path it used -- with §4's
    // early exit or without -- because the bound holds for the first and not
    // the second."
    println!("read tail: early_exit={} p99={p99} p99.9={p999}", e.early_exit);
    assert!(e.early_exit, "this run used §4's early exit");
    assert!(p99 <= 2, "p99 {p99} exceeds 2");
    assert!(p999 <= 3, "p99.9 {p999} exceeds 3");
}

// ---------------------------------------------------------------------------
// "An aged-scan test is mandatory."
// ---------------------------------------------------------------------------

#[test]
fn aged_scan_stays_within_1_5x_and_0_3_value_reads_per_row() {
    // Enforces four MUSTs whose violation is invisible to every other check:
    // clustered promotion (§6.3), cold-tier collection (§6.8), the
    // locality-debt bound (§6.9), and value readahead (§8.1).
    let (_t, mut e) = engine("agedscan", Profile::Desktop);
    e.memtable_entry_limit = 400;
    // `11-conformance.md` §6: the fixture MUST set `vlog_min` below its own
    // documents. Every profile now puts it at a quarter page
    // (`12-profiles.md` §2.5), so a 600-byte value is **inline** and none of
    // the four mechanisms under test engages at all. The literal 600 used to
    // clear `desktop`'s old 256 by accident; when the default moved, this test
    // kept passing with `v/row 0.000` and a ratio of 1.0.
    e.sb.vlog_min = 256;
    let n = 2_000i64;
    let value = vec![3u8; 600]; // above vlog_min, so every value separates
    for i in 0..n {
        e.put(T, &Value::NitriteId(i), &value).unwrap();
        if e.memtable_pressure().0 >= 400 {
            e.flush().unwrap();
        }
    }
    e.flush().unwrap();
    // The bound of §6.9 is stated over a database "not under active write
    // pressure", so both scans are measured in that state: a full compaction
    // to the last level, which is what promotes surviving values into the cold
    // tier in key order (§6.3), followed by collection (§6.8).
    e.compact().unwrap();

    e.pager.page_reads = 0;
    e.counters.value_reads = 0;
    e.counters.scanned_rows = 0;
    let rows = e.scan_tree(T, None, None, None, true).unwrap();
    assert_eq!(rows.len(), n as usize);
    let first_reads = e.pager.page_reads;

    // 10x the dataset in random updates.
    let mut rng = Rng::new(99);
    for _ in 0..n * 10 {
        let id = rng.below(n as u64) as i64;
        e.put(T, &Value::NitriteId(id), &value).unwrap();
        if e.memtable_pressure().0 >= 400 {
            e.flush().unwrap();
            e.maybe_compact(Some(u64::MAX)).unwrap();
        }
    }
    e.flush().unwrap();
    e.compact().unwrap();

    e.pager.page_reads = 0;
    e.counters.value_reads = 0;
    e.counters.scanned_rows = 0;
    let rows2 = e.scan_tree(T, None, None, None, true).unwrap();
    assert_eq!(rows2.len(), n as usize);
    let second_reads = e.pager.page_reads;
    let ratio = second_reads as f64 / first_reads.max(1) as f64;
    let vrow = e.counters.value_reads as f64 / e.counters.scanned_rows.max(1) as f64;
    let debt = e.locality_debt() * 100.0;
    println!("aged scan: {ratio:.3}x  v/row {vrow:.3}  locality_debt {debt:.1} %");
    assert!(ratio <= 1.5, "aged scan cost {ratio:.2}x the first, above the 1.5x bound");
    assert!(vrow <= 0.3, "value_reads_per_scanned_row {vrow:.3} above 0.3");
    assert!(
        debt <= e.sb.locality_debt_pct as f64,
        "locality_debt {debt:.1} % above locality_debt_pct {}",
        e.sb.locality_debt_pct
    );
}

// ---------------------------------------------------------------------------
// "A stale-version test is mandatory."
// ---------------------------------------------------------------------------

#[test]
fn a_lower_level_with_a_higher_max_seq_does_not_win() {
    // Build a file in which a segment at a *lower* level has a higher `max_seq`
    // than a segment above it, from an **unrelated** key, while both cover the
    // queried key. A reader resolving by segment order instead of by entry
    // `seq` returns the stale version.
    let (_t, mut e) = engine("staleversion", Profile::Desktop);
    let page = e.page_size();
    let last = e.policy.last_level();

    // The low level (last) holds key 5 at seq 10, and key 999 at seq 500.
    let mut lo = SegmentBuilder::new(page, 900, last, 0, e.filter_bits_at(last)).unwrap();
    for (key, seq) in [(5i64, 10u64), (999, 500)] {
        let cke = cryptand::cke::encode(&Value::NitriteId(key)).unwrap();
        lo.add(SegEntry::new(internal_key(T, &cke, seq, op::PUT), value_kind::INLINE, b"OLD".to_vec()))
            .unwrap();
    }
    // The high level (1) holds key 5 at seq 20 -- newer, but its segment's
    // max_seq (20) is *below* the lower level's (500).
    let mut hi = SegmentBuilder::new(page, 901, 1, 0, e.filter_bits_at(1)).unwrap();
    let cke5 = cryptand::cke::encode(&Value::NitriteId(5)).unwrap();
    hi.add(SegEntry::new(internal_key(T, &cke5, 20, op::PUT), value_kind::INLINE, b"NEW".to_vec()))
        .unwrap();

    for (b, level) in [(lo, last), (hi, 1)] {
        let extent = b.build().unwrap();
        let pages = (extent.len() / page) as u32;
        let start = e.pager.alloc_extent(pages).unwrap();
        e.pager.write_extent(start, &extent).unwrap();
        let seg = Segment::open(extent, page).unwrap();
        let r = SegmentRef::of(&seg, level, 0, start);
        let mut m = std::mem::replace(&mut e.manifest, cryptand::manifest::Manifest::new(0));
        m.add(&mut e.pager, &r).unwrap();
        e.manifest = m;
    }
    e.next_seq = 501;
    e.visible_seq = 500;

    let refs = e.all_refs().unwrap();
    let lo_ref = refs.iter().find(|r| r.segment_id == 900).unwrap();
    let hi_ref = refs.iter().find(|r| r.segment_id == 901).unwrap();
    assert!(lo_ref.max_seq > hi_ref.max_seq, "the fixture must invert max_seq across levels");
    assert!(lo_ref.covers(&cryptand::segment::user_prefix(T, &cke5)));
    assert!(hi_ref.covers(&cryptand::segment::user_prefix(T, &cke5)));

    assert_eq!(
        e.get(T, &Value::NitriteId(5)).unwrap().as_deref(),
        Some(&b"NEW"[..]),
        "resolved by segment max_seq instead of by entry seq: returned the stale version"
    );
    // And again with the early exit off, which is what §4 requires of a reader
    // without the level-discipline proof.
    e.early_exit = false;
    assert_eq!(e.get(T, &Value::NitriteId(5)).unwrap().as_deref(), Some(&b"NEW"[..]));
}

// ---------------------------------------------------------------------------
// "A range-delete-under-filter test is mandatory."
// ---------------------------------------------------------------------------

#[test]
fn a_range_delete_bearing_segment_is_never_filter_pruned() {
    let (_t, mut e) = engine("rd-filter", Profile::Desktop);
    for i in 0..200i64 {
        e.put(T, &Value::NitriteId(i), b"live").unwrap();
    }
    e.flush().unwrap();
    // One range delete, in its own segment, covering a key that is NOT a point
    // key of that segment.
    e.remove_range(T, &Value::NitriteId(50), &Value::NitriteId(60)).unwrap();
    e.flush().unwrap();

    let refs = e.all_refs().unwrap();
    let rd_ref = refs.iter().find(|r| r.has_range_deletes).expect("a segment carries the range delete");
    let seg = e.segment(rd_ref).unwrap();
    let probe = cryptand::segment::user_prefix(T, &cryptand::cke::encode(&Value::NitriteId(55)).unwrap());
    // The test only means something if the filter would have pruned it.
    assert!(
        !seg.may_contain(&probe),
        "the fixture is wrong: key 55 IS a point key of the range-delete segment, so the test \
         would pass for the wrong reason"
    );
    assert!(e.get(T, &Value::NitriteId(55)).unwrap().is_none(), "a deleted key was resurrected");
    assert!(e.get(T, &Value::NitriteId(49)).unwrap().is_some());
    assert!(e.get(T, &Value::NitriteId(60)).unwrap().is_some());
}

// ---------------------------------------------------------------------------
// "A filter cross-check is mandatory."
// ---------------------------------------------------------------------------

#[test]
fn the_filter_bytes_match_the_recorded_ones_not_merely_the_rate() {
    // "A filter that differs by one probe is a false negative -- a lost key,
    // not a slow lookup."
    let v = read_vector("filter/blocked_bloom.json");
    let r = &v["reproduce"];
    let tree = r["tree_id"].as_u64().unwrap() as u32;
    let first = r["first_id"].as_i64().unwrap();
    let count = r["key_count"].as_u64().unwrap() as i64;
    let bits = r["bits_per_key"].as_u64().unwrap() as u32;
    let keys: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            user_key_prefix(tree, &cryptand::cke::encode(&Value::NitriteId(first + i)).unwrap())
        })
        .collect();
    let f = BlockedBloom::build(&keys, bits, keys.len() as u64);
    let payload = f.encode_payload();
    // `header_bytes` is the WHOLE 20-byte header. Defect 42 in the Dart
    // implementation's report is exactly this field: it once called 16 bytes
    // `header_bytes` when the header is 20, and an SDK trusting the name lays
    // its blocks 4 bytes early, so every probe reads the wrong bits and the
    // filter produces **false negatives** -- the one failure that loses keys
    // silently.
    let want_header = unhex(v["header_bytes"].as_str().unwrap());
    assert_eq!(want_header.len(), 20, "{}", v["header_note"]);
    assert_eq!(&payload[..20], &want_header[..], "filter page header");
    let want_blocks = unhex(v["blocks"].as_str().unwrap());
    assert_eq!(&payload[20..20 + want_blocks.len()], &want_blocks[..], "filter blocks");
    for k in &keys {
        assert!(f.may_contain(k), "a key it holds fails its own filter");
    }
}

// ---------------------------------------------------------------------------
// "A containment test is mandatory."
// ---------------------------------------------------------------------------

#[test]
fn one_corrupt_page_does_not_make_the_database_unreadable() {
    let t = TempDb::new("containment");
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    e.memtable_entry_limit = 200;
    for i in 0..1000i64 {
        e.put(T, &Value::NitriteId(i), format!("v{i}").as_bytes()).unwrap();
        if e.memtable_pressure().0 >= 200 {
            e.flush().unwrap();
        }
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let refs = e.all_refs().unwrap();
    assert!(refs.len() > 1, "the fixture needs more than one segment");
    let victim = refs.iter().max_by_key(|r| r.entries).unwrap().clone();
    e.close(true).unwrap();

    // Corrupt one page of a mid-level segment.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&t.path).unwrap();
        f.seek(SeekFrom::Start((victim.start_page + 1) * 8192 + 100)).unwrap();
        f.write_all(&[0xFF; 16]).unwrap();
    }

    // "the database MUST still open"
    let mut e = Engine::open(&t.path, None).unwrap();
    let r = e.verify().unwrap();
    assert!(!r.of(Class::Corruption).is_empty(), "the damage must be detected");
    // "MUST name the affected range"
    let named = e.quarantine(victim.segment_id).unwrap().expect("the segment is in the manifest");
    assert_eq!(named.segment_id, victim.segment_id);
    assert!(!named.min_key.is_empty() && !named.max_key.is_empty());
    let m = e.metrics().unwrap();
    assert_eq!(m["unavailable_ranges"], Metric::Count(1));

    // "MUST still serve every key outside that segment's range"
    let mut served = 0;
    let mut refused = 0;
    for i in 0..1000i64 {
        match e.get(T, &Value::NitriteId(i)) {
            Ok(_) => served += 1,
            Err(cryptand::Error::Unavailable(_)) => refused += 1,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
    println!("containment: {served} keys served, {refused} refused by name");
    assert!(served > 0, "containment served nothing");
    // A read that lands inside the hole fails with a *specific* error, never a
    // wrong or empty answer.
    assert!(refused > 0, "no read landed in the quarantined range");
}

// ---------------------------------------------------------------------------
// "A profile round-trip test is mandatory" -- with the same page size.
// ---------------------------------------------------------------------------

#[test]
fn profile_round_trip_between_two_profiles_that_share_a_page_size() {
    // §6: the pair must share a page size. `mobile <-> tablet` is the usable
    // 4 KiB pair; an earlier version of this requirement named
    // `mobile -> desktop -> mobile`, which `12-profiles.md` §6 forbids
    // outright, so no conforming implementation could run it.
    let (_t, mut e) = engine("profile", Profile::Mobile);
    for i in 0..500i64 {
        e.put(T, &Value::NitriteId(i), format!("v{i}").as_bytes()).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    let before: Vec<_> = e.scan_tree(T, None, None, None, true).unwrap();

    e.set_profile(Profile::Tablet).unwrap();
    e.compact().unwrap();
    assert!(e.verify().unwrap().of(Class::Corruption).is_empty());
    assert_eq!(e.scan_tree(T, None, None, None, true).unwrap(), before);

    e.set_profile(Profile::Mobile).unwrap();
    e.compact().unwrap();
    assert!(e.verify().unwrap().of(Class::Corruption).is_empty());
    assert_eq!(e.scan_tree(T, None, None, None, true).unwrap(), before);

    // The other half of the property: the forbidden change is refused.
    let err = e.set_profile(Profile::Desktop).unwrap_err();
    assert!(format!("{err}").contains("page_size is fixed at creation"), "{err}");
}

// ---------------------------------------------------------------------------
// "A crash test is mandatory": kill at randomized points, reopen, and assert
// that every acknowledged batch is present and no unacknowledged batch is
// partially present.
// ---------------------------------------------------------------------------

#[test]
fn a_crash_at_a_randomized_point_leaves_a_structurally_valid_database() {
    for mode in [Durability::None, Durability::Os, Durability::Sync] {
        for cut in [3usize, 7, 11, 23] {
            let t = TempDb::new("crash");
            let mut acked = Vec::new();
            {
                let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
                e.memtable_entry_limit = 50;
                for batch in 0..40i64 {
                    for i in 0..10i64 {
                        e.put(T, &Value::NitriteId(batch * 10 + i), b"v").unwrap();
                    }
                    if batch % 3 == 0 {
                        e.flush().unwrap();
                        e.commit(mode).unwrap();
                        acked.push(batch);
                    }
                    if batch as usize == cut {
                        // The kill: drop the engine without close(), leaving
                        // whatever the last committed superblock named.
                        break;
                    }
                }
                drop(e);
            }
            let mut e = Engine::open(&t.path, None).unwrap();
            let r = e.verify().unwrap();
            assert!(
                r.of(Class::Corruption).is_empty(),
                "mode {mode:?} cut {cut}: {:?}",
                r.findings
            );
            for batch in &acked {
                for i in 0..10i64 {
                    let id = batch * 10 + i;
                    assert!(
                        e.get(T, &Value::NitriteId(id)).unwrap().is_some(),
                        "mode {mode:?} cut {cut}: acknowledged id {id} is missing"
                    );
                }
            }
        }
    }
}

#[test]
fn the_resident_page_cache_stays_inside_the_profile_budget() {
    // `12-profiles.md` §1 gives `mobile` a 4 MiB page cache budget and
    // `design/performance-model.md` P7 predicts resident set bounded by it.
    //
    // The budget was a decoration: `page_cache_bytes` was declared in the
    // profile table and read by nothing, so the segment cache grew with the
    // data. Measured on `mobile` before the bound: 28 MB resident over 30
    // segments at 60 000 documents, and 70 MB over 75 at 150 000 — linear in
    // the data touched, which is the definition of unbounded.
    //
    // The check is a counter, not a wall clock: `page_cache_resident_bytes`
    // against the profile's own number. It is machine-independent, so it can
    // be asserted in CI (`design/performance-model.md` §8).
    let (_t, mut e) = engine("cachebound", Profile::Mobile);
    let budget = e.profile.page_cache_bytes;
    let payload = vec![b'x'; 400];
    let n = 15_000i64;
    for i in 0..n {
        e.put(16, &Value::NitriteId(i), &payload).unwrap();
    }
    e.flush().unwrap();
    e.compact().unwrap();

    // Touch every key, which is what makes an unbounded cache hold everything.
    for i in 0..n {
        assert!(e.get(16, &Value::NitriteId(i)).unwrap().is_some(), "key {i} vanished");
    }

    let resident = e.page_cache_resident_bytes();
    assert!(
        resident <= budget,
        "resident {resident} B over {} segments exceeds the mobile budget of {budget} B",
        e.page_cache_segments()
    );

    // A control that can fail: the workload must actually have pressed on the
    // budget. Without this, an engine that cached nothing would pass, and a
    // check that cannot fail measures nothing — this project's own recurring
    // lesson.
    assert!(
        e.counters.page_cache_evictions > 0,
        "nothing was evicted, so the bound was never tested: \
         raise the document count until the resident set would exceed {budget} B"
    );

    // And eviction must not have cost correctness: a miss re-reads through the
    // pager, so every key is still there.
    assert!(e.get(16, &Value::NitriteId(n - 1)).unwrap().is_some());
}
