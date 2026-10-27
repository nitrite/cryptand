//! F-150: dead value-log space must come back (04 §6.8).

mod support;
use support::*;

use cryptand::container::{Durability, Profile};
use cryptand::database::Database;
use cryptand::value::Value;

#[test]
fn f150_overwriting_the_same_values_does_not_grow_the_file() {
    // 100 x (open, overwrite 256 x 4 KiB, commit, close). Before the fix
    // the file grew ~1.9 MB a cycle (56 MB at 30); it plateaued near
    // 30 MB with tiered levels keeping every version; since §5 drops a
    // superseded version at any level (F-150), ~13 MB.
    let (t, mut e) = engine("f150", Profile::Desktop);
    e.close(true).unwrap();
    let path = t.path.clone();
    let mut at_50 = 0;
    for cycle in 0..100u8 {
        let mut d = Database::open(&path, None).unwrap();
        for i in 0..256i64 {
            d.engine.put(16, &Value::NitriteId(i), &vec![cycle; 4096]).unwrap();
        }
        d.commit(Durability::Sync).unwrap();
        d.close().unwrap();
        if cycle == 50 {
            at_50 = std::fs::metadata(&path).unwrap().len();
        }
    }
    let len = std::fs::metadata(&path).unwrap().len();
    let mut d = Database::open(&path, None).unwrap();
    for i in 0..256i64 {
        assert_eq!(d.engine.get(16, &Value::NitriteId(i)).unwrap().unwrap(), vec![99u8; 4096]);
    }
    assert!(len <= at_50 + at_50 / 10, "still growing: {at_50} at cycle 50, {len} at 100");
    assert!(len < 16 << 20, "file {len} bytes for 1 MiB live");
}

#[test]
fn f151_a_cold_point_read_reads_pages_not_the_segment() {
    // Before the fix a page-cache miss read, decrypted and decoded the whole
    // segment extent: 609 pages for one `get` here. Now the head, the
    // filter (~7 pages), the manifest and one descent.
    let (t, mut e) = engine("f151", Profile::Desktop);
    e.close(true).unwrap();
    let path = t.path.clone();
    let mut d = Database::open(&path, None).unwrap();
    for i in 0..20_000i64 {
        d.engine.put(16, &Value::NitriteId(i), &vec![(i % 251) as u8; 100]).unwrap();
    }
    d.commit(Durability::Sync).unwrap();
    d.close().unwrap();
    let mut d = Database::open(&path, None).unwrap();
    for i in [7i64, 12_345, 19_999] {
        let p0 = d.engine.pager.reads();
        assert_eq!(d.engine.get(16, &Value::NitriteId(i)).unwrap().unwrap(), vec![(i % 251) as u8; 100]);
        let n = d.engine.pager.reads() - p0;
        assert!(n <= 32, "a cold get of {i} read {n} pages");
    }
}

#[cfg(unix)]
#[test]
fn f160_reading_many_segments_holds_one_descriptor() {
    // Before the fix each lazily read segment opened its own descriptor:
    // 10^8 documents ran out at open (EMFILE, macOS limit 256).
    let (t, mut e) = engine("f160", Profile::Desktop);
    e.close(true).unwrap();
    let path = t.path.clone();
    let mut d = Database::open(&path, None).unwrap();
    for i in 0..40_000i64 {
        d.engine.put(16, &Value::NitriteId(i * 7919 % 40_000), &vec![(i % 251) as u8; 100]).unwrap();
        if i % 1_000 == 999 {
            d.commit(Durability::Sync).unwrap();
        }
    }
    d.close().unwrap();
    let fds = || std::fs::read_dir("/dev/fd").unwrap().count();
    let mut d = Database::open(&path, None).unwrap();
    let before = fds();
    for i in (0..40_000i64).step_by(97) {
        assert!(d.engine.get(16, &Value::NitriteId(i)).unwrap().is_some());
    }
    let grew = fds() - before;
    assert!(grew <= 1, "{grew} descriptors opened by reads");
}

#[test]
fn f170_a_scan_streams_in_bounded_memory() {
    // `scan_tree` collected every version in range before returning: O(range).
    // The cursor holds one readahead window plus one batch per segment, and
    // the memtable's part of the range (bounded by `memtable_entry_limit`).
    let (_t, mut e) = engine("f170", Profile::Desktop);
    for i in 0..20_000i64 {
        e.put(16, &Value::NitriteId(i), &vec![(i % 251) as u8; 100]).unwrap();
        if i % 5_000 == 4_999 {
            e.flush().unwrap();
        }
    }
    for i in (0..20_000i64).step_by(7) {
        e.put(16, &Value::NitriteId(i), b"new").unwrap(); // newer versions over older segments
    }
    e.flush().unwrap();
    for i in 0..7i64 {
        e.put(16, &Value::NitriteId(i * 1_000 + 7), b"new").unwrap(); // the memtable, copied whole
    }
    e.remove_range(16, &Value::NitriteId(100), &Value::NitriteId(200)).unwrap();
    let all = e.scan_tree(16, None, None, None, true).unwrap();
    assert_eq!(all.len(), 20_000 - 100);
    assert_eq!(all.iter().filter(|(_, v)| v == b"new").count(), 2_858 - 14 + 6); // newest wins (key 7 was already new)
    let mut c = e.scan_cursor(16, None, None, None, true).unwrap();
    let (mut n, mut most) = (0, 0);
    while let Some((k, v)) = c.next(&mut e).unwrap() {
        assert_eq!((&k, &v), (&all[n].0, &all[n].1));
        most = most.max(c.held());
        n += 1;
    }
    assert_eq!(n, all.len());
    assert!(most < 1_000, "the cursor held {most} rows of {n}");
}

#[test]
fn f171_an_unbounded_scan_opens_only_its_own_trees_segments() {
    // `Database::collection` scans its name dictionary unbounded; that opened
    // every segment of the file (228 MB at 10^8), the data tree's included.
    let (_t, mut e) = engine("f171", Profile::Desktop);
    for i in 0..5i64 {
        e.put(16, &Value::NitriteId(i), b"name").unwrap();
    }
    e.flush().unwrap();
    for s in 0..10i64 {
        for i in 0..500i64 {
            e.put(17, &Value::NitriteId(s * 1_000 + i), &[1u8; 100]).unwrap();
        }
        e.flush().unwrap();
    }
    let opens = |e: &cryptand::engine::Engine| e.counters.page_cache_hits + e.counters.page_cache_misses;
    let before = opens(&e);
    assert_eq!(e.scan_tree(16, None, None, None, true).unwrap().len(), 5);
    let n = opens(&e) - before;
    assert!(n <= 2, "an unbounded scan of tree 16 opened {n} segments");
}

#[test]
fn f172_page_writes_alone_widen_the_nonce_window() {
    // 10^8 encrypted rung died at 5x10^6 docs: `ensure_nonces` read the
    // engine's cursor, which only value-log records advance, so inline-only
    // writes never re-published and the pager ran out at 2^20 pages. Headroom
    // = the whole gap: any page written since the open publish must make the
    // next `arm` publish a new floor.
    use cryptand::engine::Engine;
    let t = TempDb::new("f172");
    let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &[7u8; 32], 0, 0, 0, 0).unwrap();
    e.nonce_headroom = cryptand::security::NONCE_GAP;
    let floor = e.sb.next_nonce;
    for i in 0..2_000i64 {
        e.put(1, &Value::NitriteId(i), &[b'v'; 100]).unwrap();
    }
    e.flush().unwrap();
    e.flush().unwrap(); // arms again, after the first flush wrote pages
    assert!(e.sb.next_nonce > floor, "floor never re-published: {floor}");
    e.close(true).unwrap();
}

#[test]
fn f173_compact_and_shrink_rearm_per_extent() {
    // 10^8 encrypted settle died: `compact()` ran its whole merge as one
    // unbounded step and `relocate_down` never armed, so one window had to
    // cover every page of the file. Scaled down: 64 KiB segments, a 64-page
    // headroom, and the window drained to exactly that before each pass.
    use cryptand::engine::Engine;
    use cryptand::spaceapi::SpaceApi;
    let t = TempDb::new("f173");
    let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &[7u8; 32], 0, 0, 0, 0).unwrap();
    e.profile.segment_target_bytes = 64 << 10;
    e.nonce_headroom = 64;
    let drain = |e: &mut Engine| {
        e.allocate_nonce().unwrap();
        while e.pager.crypto.as_ref().map(|c| c.limit - c.next).unwrap() > 64 {
            e.allocate_nonce().unwrap();
        }
    };
    for i in 0..20_000i64 {
        e.put(1, &Value::NitriteId(i), &[b'v'; 100]).unwrap();
        if i % 2_000 == 1_999 {
            e.flush().unwrap();
        }
    }
    drain(&mut e);
    e.compact().unwrap();
    drain(&mut e);
    e.shrink().unwrap();
    e.close(true).unwrap();
    let mut e = Engine::open(&t.path, Some(&[7u8; 32])).unwrap();
    assert_eq!(e.scan_tree(1, None, None, None, true).unwrap().len(), 20_000);
}

#[test]
fn f182_a_commit_inside_a_compaction_job_leaks_no_pages() {
    // A paced job places each output as it fills (F-147) but the manifest
    // names them only when it publishes. A commit between the two persisted a
    // free list without them: unreachable and not free, for good on a crash.
    use cryptand::verify::{Class, EngineVerify};
    let (t, mut e) = engine("f182", Profile::Desktop);
    e.profile.segment_target_bytes = 64 << 10;
    e.memtable_entry_limit = 2_000;
    let (mut mid_job, mut leaks) = (0, 0);
    for i in 0..100_000i64 {
        e.put(16, &Value::NitriteId(i), &[7u8; 256]).unwrap();
        if e.unpublished_outputs() && mid_job < 20 && i % 500 == 0 {
            mid_job += 1;
            e.commit(Durability::Sync).unwrap();
            leaks += e.verify().unwrap().of(Class::Leak).len();
        }
    }
    e.close(true).unwrap();
    let mut d = Database::open(&t.path, None).unwrap();
    leaks += d.engine.verify().unwrap().of(Class::Leak).len();
    assert!(mid_job > 0, "no commit landed inside a job");
    assert_eq!(leaks, 0, "pages neither reachable nor free");
}
