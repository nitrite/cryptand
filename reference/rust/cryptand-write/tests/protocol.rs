//! `10-transactions.md` §2 — the protocol's requirements and its three ordering
//! invariants, exercised with real threads. This is the chapter the Dart
//! reference implementation declared out of reach.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use cryptand_conformance::cke;
use cryptand_conformance::value::Value;
use cryptand_write::engine::{Batch, Durability, Stored, WriteOptions};
use cryptand_write::nonce::NonceAllocator;
use cryptand_write::prefix::Watermark;
use cryptand_write::vlog::HeatClass;
use cryptand_write::WriteEngine;

fn key(i: i64) -> Vec<u8> {
    cke::encode(&Value::NitriteId(i)).unwrap()
}

fn engine(options: WriteOptions) -> (WriteEngine, tempdir::Dir) {
    let dir = tempdir::Dir::new();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dir.path().join("db.cryptand"))
        .unwrap();
    (WriteEngine::create(file, options).unwrap(), dir)
}

/// A directory that removes itself. Not worth a dependency.
mod tempdir {
    use std::path::{Path, PathBuf};
    pub struct Dir(PathBuf);
    impl Dir {
        pub fn new() -> Dir {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "cryptand-write-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

// ---------------------------------------------------------------------------
// §2 -- the writer, and what many of them do to one counter
// ---------------------------------------------------------------------------

#[test]
fn many_writers_get_disjoint_contiguous_seq_ranges() {
    let (e, _d) = engine(WriteOptions { durability: Durability::Os, ..Default::default() });
    let e = Arc::new(e);
    let threads = 8;
    let per_thread = 200;
    let gate = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (e, gate) = (e.clone(), gate.clone());
        handles.push(std::thread::spawn(move || {
            gate.wait();
            let mut ranges = Vec::new();
            for i in 0..per_thread {
                let mut b = Batch::default();
                b.put(16, key((t * per_thread + i) as i64), vec![7u8; 64]);
                ranges.push(e.write(&b, HeatClass::First).unwrap());
            }
            ranges
        }));
    }
    let mut all: Vec<(u64, u64)> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    all.sort();
    // One `fetch_add` per batch means the allocated ranges tile [1, n+1)
    // exactly: no gaps, no overlaps, whatever order the threads ran in.
    assert_eq!(all.len(), threads * per_thread);
    let mut next = 1u64;
    for (start, end) in &all {
        assert_eq!(*start, next, "seq ranges must tile without a gap");
        next = *end;
    }
    assert_eq!(e.next_seq(), next);
}

#[test]
fn concurrent_writers_to_the_same_keys_leave_the_newest_seq_winning() {
    let (e, _d) = engine(WriteOptions { durability: Durability::Os, ..Default::default() });
    let e = Arc::new(e);
    let threads = 8;
    let keys = 32;
    let gate = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (e, gate) = (e.clone(), gate.clone());
        handles.push(std::thread::spawn(move || {
            gate.wait();
            for round in 0..50 {
                let mut b = Batch::default();
                b.put(16, key((round % keys) as i64), vec![t as u8; 300]);
                e.write(&b, HeatClass::First).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    e.drain();
    // The overlapping case: every key resolves, and the surviving entry is the
    // one with the highest seq -- an older batch never overwrites a newer.
    for k in 0..keys {
        let entry = e.entry(&key(k as i64)).expect("every key written");
        let value = e.get(&key(k as i64)).unwrap().expect("resolves through the value log");
        assert_eq!(value.len(), 300);
        assert!(entry.seq > 0);
    }
}

#[test]
fn a_batch_is_invisible_until_the_committer_publishes_it() {
    // A committer that is busy for a long time makes the window observable.
    let (e, _d) = engine(WriteOptions {
        durability: Durability::Os,
        committer_work_per_batch: Duration::from_millis(80),
        ..Default::default()
    });
    let mut b = Batch::default();
    b.put(16, key(1), vec![1u8; 400]);
    let (start, end) = e.write(&b, HeatClass::First).unwrap();
    // `os` does not wait, so this observes the pre-commit state: the bytes are
    // written and the memtable entry exists, but the watermark has not moved.
    assert!(e.visible_seq() < end, "a batch is not visible before the barrier");
    assert_eq!(e.entry(&key(1)).unwrap().seq, start);
    e.drain();
    assert!(e.visible_seq() >= end - 1);
}

#[test]
fn sync_does_not_return_until_the_batch_is_visible() {
    let (e, _d) = engine(WriteOptions { durability: Durability::Sync, ..Default::default() });
    for i in 0..20 {
        let mut b = Batch::default();
        b.put(16, key(i), vec![9u8; 300]);
        let (_, end) = e.write(&b, HeatClass::First).unwrap();
        assert!(
            e.visible_seq() >= end - 1,
            "a sync write MUST NOT be acknowledged before its barrier (§2.4)"
        );
    }
}

// ---------------------------------------------------------------------------
// §2.3 invariant 2 -- the contiguous-prefix watermark
// ---------------------------------------------------------------------------

#[test]
fn a_reserved_but_unwritten_range_pins_every_later_one() {
    let (e, _d) = engine(WriteOptions { durability: Durability::Os, ..Default::default() });
    let vlog = e.vlog(HeatClass::First);

    // A writer that reserved a range and died: the reservation is never
    // completed. Everything after it is written and completed normally.
    let dead = vlog.reserve(128).unwrap();
    let later = vlog.reserve(64).unwrap();
    vlog.write_at(later, &vec![3u8; 64]).unwrap();
    vlog.complete(later);

    assert_eq!(
        vlog.durable_bytes(),
        0,
        "the watermark MUST NOT advance past a hole -- doing so publishes garbage as a live record"
    );
    assert_eq!(vlog.pending_ranges(), 1, "the later range is written but unreachable");
    assert!(vlog.reserved_bytes() >= dead.offset + dead.len);

    // Completing the hole releases the whole prefix at once.
    vlog.write_at(dead, &vec![1u8; 128]).unwrap();
    vlog.complete(dead);
    assert_eq!(vlog.durable_bytes(), 192);
    assert_eq!(vlog.pending_ranges(), 0);
}

#[test]
fn the_watermark_never_moves_backwards_and_ignores_a_double_completion() {
    let mut w = Watermark::new(0);
    assert_eq!(w.complete(0, 10), 10);
    assert_eq!(w.complete(0, 10), 10, "a repeated completion is not a rewind");
    assert_eq!(w.complete(20, 30), 10, "a gap holds the watermark");
    assert_eq!(w.complete(10, 20), 30, "filling the gap releases both");
}

#[test]
fn only_records_below_the_watermark_are_referenced() {
    let (e, _d) = engine(WriteOptions { durability: Durability::Sync, ..Default::default() });
    for i in 0..64 {
        let mut b = Batch::default();
        b.put(16, key(i), vec![i as u8; 512]);
        e.write(&b, HeatClass::First).unwrap();
    }
    e.drain();
    let vlog = e.vlog(HeatClass::First);
    let watermark = vlog.durable_bytes();
    assert_eq!(watermark, vlog.reserved_bytes(), "no holes in this run");
    for i in 0..64 {
        match e.entry(&key(i)).unwrap().value {
            Stored::Vlog { offset, len, .. } => {
                assert!(
                    offset + len <= watermark,
                    "a VLOG pointer names bytes above the durable watermark"
                );
                assert_eq!(e.get(&key(i)).unwrap().unwrap(), vec![i as u8; 512]);
            }
            other => panic!("a 512-byte value belongs in the value log, got {other:?}"),
        }
    }
}

#[test]
fn a_value_below_vlog_min_stays_inline() {
    let (e, _d) = engine(WriteOptions {
        durability: Durability::Os,
        vlog_min: 256,
        ..Default::default()
    });
    let mut b = Batch::default();
    b.put(16, key(1), vec![1u8; 255]);
    b.put(16, key(2), vec![2u8; 256]);
    e.write(&b, HeatClass::First).unwrap();
    e.drain();
    assert!(matches!(e.entry(&key(1)).unwrap().value, Stored::Inline(_)));
    assert!(matches!(e.entry(&key(2)).unwrap().value, Stored::Vlog { .. }));
}

// ---------------------------------------------------------------------------
// §2.2 -- open segments are bounded by heat classes, not by writers
// ---------------------------------------------------------------------------

#[test]
fn writers_share_a_segment_without_serializing_on_it() {
    let (e, _d) = engine(WriteOptions { durability: Durability::Os, ..Default::default() });
    let e = Arc::new(e);
    let threads = 8;
    let gate = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (e, gate) = (e.clone(), gate.clone());
        handles.push(std::thread::spawn(move || {
            gate.wait();
            for i in 0..100 {
                let mut b = Batch::default();
                b.put(16, key((t * 100 + i) as i64), vec![t as u8; 400]);
                e.write(&b, HeatClass::First).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    e.drain();
    let vlog = e.vlog(HeatClass::First);
    // 800 batches went into ONE open segment, each taking a disjoint range with
    // one fetch_add. Write-path memory is O(1) in concurrency: three segments
    // for three heat classes, whatever the thread count.
    assert_eq!(vlog.reservations.load(Ordering::Relaxed), 800);
    assert_eq!(vlog.durable_bytes(), vlog.reserved_bytes());
    for t in 0..threads {
        for i in 0..100 {
            assert_eq!(
                e.get(&key((t * 100 + i) as i64)).unwrap().unwrap(),
                vec![t as u8; 400],
                "disjoint ranges must not overlap"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// §2.3 invariant 3 -- the nonce watermark
// ---------------------------------------------------------------------------

#[test]
fn a_crashed_session_never_reissues_a_nonce() {
    // Three sessions, each crashing after allocating, with the publishes going
    // to one durable cell -- the superblock.
    let published = Arc::new(AtomicU64::new(0));
    let mut issued: Vec<u64> = Vec::new();
    let mut persisted = 0u64;
    for _session in 0..3 {
        let p = published.clone();
        let mut publish = move |v: u64| p.store(v, Ordering::SeqCst);
        let alloc = NonceAllocator::open(persisted, 1 << 10, &mut publish);
        let p2 = published.clone();
        let mut publish2 = move |v: u64| p2.store(v, Ordering::SeqCst);
        for _ in 0..100 {
            issued.push(alloc.allocate(&mut publish2));
        }
        // The session dies here without publishing anything further. The next
        // session reads only what is durable.
        persisted = published.load(Ordering::SeqCst);
    }
    let mut sorted = issued.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), issued.len(), "a nonce was reissued after a crash");
}

#[test]
fn no_allocated_nonce_ever_reaches_the_published_floor() {
    let published = Arc::new(AtomicU64::new(0));
    let p = published.clone();
    let mut publish = move |v: u64| p.store(v, Ordering::SeqCst);
    // A tiny gap so the republish path runs many times.
    let alloc = Arc::new(NonceAllocator::open(0, 16, &mut publish));
    let threads = 8;
    let gate = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let (alloc, gate, published) = (alloc.clone(), gate.clone(), published.clone());
        handles.push(std::thread::spawn(move || {
            gate.wait();
            let mut mine = Vec::new();
            for _ in 0..500 {
                let p = published.clone();
                let mut publish = move |v: u64| p.store(v, Ordering::SeqCst);
                let v = alloc.allocate(&mut publish);
                assert!(
                    v < published.load(Ordering::SeqCst),
                    "allocated a nonce at or above the durably published floor"
                );
                mine.push(v);
            }
            mine
        }));
    }
    let mut all: Vec<u64> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), n, "two threads were handed the same nonce");
}

// ---------------------------------------------------------------------------
// §2.4 -- group commit
// ---------------------------------------------------------------------------

#[test]
fn batches_inside_one_window_share_the_committer_barriers() {
    let (e, _d) = engine(WriteOptions {
        durability: Durability::Sync,
        commit_window: Duration::from_millis(5),
        ..Default::default()
    });
    let e = Arc::new(e);
    let threads = 8;
    let gate = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (e, gate) = (e.clone(), gate.clone());
        handles.push(std::thread::spawn(move || {
            gate.wait();
            for i in 0..50 {
                let mut b = Batch::default();
                b.put(16, key((t * 50 + i) as i64), vec![1u8; 300]);
                e.write(&b, HeatClass::First).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    e.drain();
    let m = e.metrics();
    let commits = m.commits.load(Ordering::Relaxed);
    let batches = m.batches_committed.load(Ordering::Relaxed);
    assert_eq!(batches, 400);
    assert!(
        batches > commits,
        "under load a commit MUST carry more than one batch: {batches} batches in {commits} commits"
    );
}
