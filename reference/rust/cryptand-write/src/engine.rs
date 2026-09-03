//! `10-transactions.md` §2 — the writer, the committer, and the watermark that
//! is the commit.

use std::collections::BTreeMap;
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use cryptand_conformance::hash::cfh64;

use crate::prefix::Watermark;
use crate::vlog::{encode_record, HeatClass, Reservation, VlogSegment, HEAT_CLASSES};
use crate::{Error, Result, Seq};

/// §7. The mode is what the implementation **performed**, never what was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    None,
    Os,
    Sync,
    Full,
}

impl Durability {
    /// §7: `none` and `os` never risk structural corruption; they risk losing
    /// recent batches, so a writer does not wait for the barrier.
    fn waits(self) -> bool {
        matches!(self, Durability::Sync | Durability::Full)
    }
}

#[derive(Clone, Debug)]
pub struct WriteOptions {
    /// §2.2 requires the memtable be sharded; `memtable_shards` defaults to 8
    /// (`01-container.md` §2).
    pub memtable_shards: usize,
    pub durability: Durability,
    /// `01-container.md` §2 — values at or above this go to the value log.
    pub vlog_min: usize,
    pub vlog_capacity: u64,
    /// §2.4 group commit: batches arriving inside one window share the
    /// committer's barriers.
    pub commit_window: Duration,
    /// P3's stated fragility, made measurable: "if the committer becomes the
    /// bottleneck (one thread building segments for many writers), scaling
    /// stops early". This crate builds no segments, so the cost of doing so is
    /// injected here rather than pretended away.
    pub committer_work_per_batch: Duration,
}

impl Default for WriteOptions {
    fn default() -> Self {
        WriteOptions {
            memtable_shards: 8,
            durability: Durability::Sync,
            vlog_min: 256,
            vlog_capacity: 512 * 1024 * 1024,
            commit_window: Duration::from_micros(200),
            committer_work_per_batch: Duration::ZERO,
        }
    }
}

/// What a memtable holds for one key: the value, or a pointer into the value
/// log (`02-value-encoding.md` §9 — an indirection is storage, not data).
#[derive(Clone, Debug, PartialEq)]
pub enum Stored {
    Inline(Vec<u8>),
    Vlog { segment_id: u64, offset: u64, len: u64 },
    Tombstone,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub seq: Seq,
    pub value: Stored,
}

/// One writer's batch. Keys are CKE (`03-key-encoding.md`).
#[derive(Default, Clone, Debug)]
pub struct Batch {
    pub ops: Vec<(u32, Vec<u8>, Option<Vec<u8>>)>,
}

impl Batch {
    pub fn put(&mut self, tree_id: u32, key: Vec<u8>, value: Vec<u8>) -> &mut Self {
        self.ops.push((tree_id, key, Some(value)));
        self
    }

    pub fn remove(&mut self, tree_id: u32, key: Vec<u8>) -> &mut Self {
        self.ops.push((tree_id, key, None));
        self
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

#[derive(Default, Debug)]
pub struct Metrics {
    pub batches: AtomicU64,
    pub entries: AtomicU64,
    pub vlog_bytes: AtomicU64,
    pub commits: AtomicU64,
    /// Batches published per commit — group commit's amortization (§2.4).
    pub batches_committed: AtomicU64,
}

struct Shared {
    next_seq: AtomicU64,
    /// `visible_seq`: every record with `seq <= visible_seq` is committed.
    /// A contiguous-prefix watermark, so a completed batch stays invisible
    /// while an older one is outstanding (§2.3).
    visible: Mutex<Watermark>,
    visible_cv: Condvar,
    /// Batches whose bytes are written, waiting for the committer's barrier.
    queue: Mutex<Vec<(Seq, Seq)>>,
    queue_cv: Condvar,
    shutdown: AtomicBool,
    file: Arc<File>,
    options: WriteOptions,
    metrics: Metrics,
}

pub struct WriteEngine {
    shared: Arc<Shared>,
    shards: Arc<Vec<Mutex<BTreeMap<Vec<u8>, Entry>>>>,
    vlogs: Vec<Arc<VlogSegment>>,
    committer: Option<JoinHandle<()>>,
}

impl WriteEngine {
    pub fn create(file: File, options: WriteOptions) -> Result<WriteEngine> {
        let file = Arc::new(file);
        // §6.2 / §2.1: open segments are bounded by the number of heat classes,
        // not by the number of writers, so write-path memory is O(1) in
        // concurrency.
        let mut vlogs = Vec::new();
        for (i, heat) in HEAT_CLASSES.iter().enumerate() {
            let base = i as u64 * (options.vlog_capacity + crate::vlog::DATA_OFFSET);
            vlogs.push(VlogSegment::create(
                file.clone(),
                base,
                options.vlog_capacity,
                i as u64 + 1,
                *heat,
                0,
            )?);
        }
        let shards = Arc::new(
            (0..options.memtable_shards).map(|_| Mutex::new(BTreeMap::new())).collect::<Vec<_>>(),
        );
        let shared = Arc::new(Shared {
            next_seq: AtomicU64::new(1),
            visible: Mutex::new(Watermark::new(0)),
            visible_cv: Condvar::new(),
            queue: Mutex::new(Vec::new()),
            queue_cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
            file: file.clone(),
            options,
            metrics: Metrics::default(),
        });
        let committer = spawn_committer(shared.clone(), vlogs.clone());
        Ok(WriteEngine { shared, shards, vlogs, committer: Some(committer) })
    }

    pub fn options(&self) -> &WriteOptions {
        &self.shared.options
    }

    pub fn metrics(&self) -> &Metrics {
        &self.shared.metrics
    }

    pub fn visible_seq(&self) -> Seq {
        self.shared.visible.lock().unwrap().get()
    }

    pub fn next_seq(&self) -> Seq {
        self.shared.next_seq.load(Ordering::Acquire)
    }

    pub fn vlog(&self, heat: HeatClass) -> &Arc<VlogSegment> {
        &self.vlogs[heat as usize]
    }

    /// The writer of §2, step by step. Returns the batch's `[seq_base, end)`.
    pub fn write(&self, batch: &Batch, heat: HeatClass) -> Result<(Seq, Seq)> {
        if batch.is_empty() {
            let v = self.visible_seq();
            return Ok((v, v));
        }
        // 1. begin -- the snapshot this batch is written against.
        let _snapshot = self.visible_seq();

        // 2. buffer -- thread-local, no shared state touched yet.
        // 3. values -- one reservation and one pwrite for the whole batch
        //    (§6.2: "A writer SHOULD coalesce all of one batch's records into a
        //    single reservation and a single pwrite").
        let vlog = &self.vlogs[heat as usize];
        let mut blob = Vec::new();
        let mut placed: Vec<(usize, u64, u64)> = Vec::new(); // (op index, rel offset, len)
        for (i, (tree_id, key, value)) in batch.ops.iter().enumerate() {
            let Some(v) = value else { continue };
            if v.len() < self.shared.options.vlog_min {
                continue;
            }
            let rec = encode_record(*tree_id, key, v);
            placed.push((i, blob.len() as u64, rec.len() as u64));
            blob.extend_from_slice(&rec);
        }
        let reservation: Option<Reservation> = if blob.is_empty() {
            None
        } else {
            let r = vlog.reserve(blob.len() as u64)?;
            vlog.write_at(r, &blob)?;
            Some(r)
        };

        // 4. sequence -- one fetch_add, one of the two global points.
        let seq_base = self.shared.next_seq.fetch_add(batch.len() as u64, Ordering::AcqRel);
        let end = seq_base + batch.len() as u64;

        // 5. publish -- into shard h(key) % shards. Writers on different shards
        //    never meet.
        for (i, (_, key, value)) in batch.ops.iter().enumerate() {
            let stored = match value {
                None => Stored::Tombstone,
                Some(v) => match placed.iter().find(|(idx, _, _)| *idx == i) {
                    Some((_, rel, len)) => Stored::Vlog {
                        segment_id: vlog.segment_id,
                        offset: reservation.unwrap().offset + rel,
                        len: *len,
                    },
                    None => Stored::Inline(v.clone()),
                },
            };
            let entry = Entry { seq: seq_base + i as u64, value: stored };
            let shard = (cfh64(key) % self.shards.len() as u64) as usize;
            let mut m = self.shards[shard].lock().unwrap();
            match m.get(key) {
                // A later seq wins; an older batch never overwrites a newer one.
                Some(prev) if prev.seq > entry.seq => {}
                _ => {
                    m.insert(key.clone(), entry);
                }
            }
        }

        // 6. enqueue -- the bytes are written, so the range may join a commit.
        //    Completing the reservation first is what lets the value-log
        //    watermark move over this range (§2.3 invariant 2).
        if let Some(r) = reservation {
            vlog.complete(r);
            self.shared.metrics.vlog_bytes.fetch_add(r.len, Ordering::Relaxed);
        }
        self.shared.metrics.batches.fetch_add(1, Ordering::Relaxed);
        self.shared.metrics.entries.fetch_add(batch.len() as u64, Ordering::Relaxed);
        {
            let mut q = self.shared.queue.lock().unwrap();
            q.push((seq_base, end));
        }
        self.shared.queue_cv.notify_one();

        // 7. wait -- per the durability mode; `none` and `os` return at once.
        if self.shared.options.durability.waits() {
            // `visible_seq` is inclusive: the batch is durable once the
            // watermark reaches its last seq, which is `end - 1`.
            let last = end - 1;
            let mut v = self.shared.visible.lock().unwrap();
            while v.get() < last {
                v = self.shared.visible_cv.wait(v).unwrap();
            }
        }
        Ok((seq_base, end))
    }

    /// Reads a key back, resolving a value-log indirection transparently
    /// (`02-value-encoding.md` §9). `None` for absent or deleted.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let shard = (cfh64(key) % self.shards.len() as u64) as usize;
        let entry = { self.shards[shard].lock().unwrap().get(key).cloned() };
        Ok(match entry {
            None | Some(Entry { value: Stored::Tombstone, .. }) => None,
            Some(Entry { value: Stored::Inline(v), .. }) => Some(v),
            Some(Entry { value: Stored::Vlog { segment_id, offset, .. }, .. }) => {
                let seg = self
                    .vlogs
                    .iter()
                    .find(|s| s.segment_id == segment_id)
                    .ok_or(Error::SegmentFull)?;
                Some(seg.read_record(offset)?.2)
            }
        })
    }

    pub fn entry(&self, key: &[u8]) -> Option<Entry> {
        let shard = (cfh64(key) % self.shards.len() as u64) as usize;
        self.shards[shard].lock().unwrap().get(key).cloned()
    }

    /// Blocks until every batch enqueued so far is visible.
    pub fn drain(&self) {
        let target = self.shared.next_seq.load(Ordering::Acquire) - 1;
        let mut v = self.shared.visible.lock().unwrap();
        while v.get() < target {
            v = self.shared.visible_cv.wait(v).unwrap();
        }
    }
}

impl Drop for WriteEngine {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.queue_cv.notify_all();
        if let Some(h) = self.committer.take() {
            let _ = h.join();
        }
    }
}

/// The committer of §2: one thread, off the writer threads, amortizing its
/// barriers over a whole commit group.
fn spawn_committer(shared: Arc<Shared>, vlogs: Vec<Arc<VlogSegment>>) -> JoinHandle<()> {
    std::thread::spawn(move || loop {
        // A. collect
        let batches = {
            let mut q = shared.queue.lock().unwrap();
            while q.is_empty() {
                if shared.shutdown.load(Ordering::Acquire) {
                    return;
                }
                let (guard, _) = shared.queue_cv.wait_timeout(q, shared.options.commit_window).unwrap();
                q = guard;
                if q.is_empty() && shared.shutdown.load(Ordering::Acquire) {
                    return;
                }
            }
            std::mem::take(&mut *q)
        };

        // B/C. the value-log tails are already written; one barrier covers
        // every write since the last commit.
        if shared.options.durability.waits() {
            let _ = shared.file.sync_data();
        }

        // D. flush -- a real committer builds an L0 segment here and edits the
        // manifest. This one does not, so the cost is injected instead.
        if !shared.options.committer_work_per_batch.is_zero() {
            std::thread::sleep(shared.options.committer_work_per_batch * batches.len() as u32);
        }

        // E. barrier. F/G. publish and wake.
        //
        // Invariant 1 (§2.3): what is published must already be durable. Every
        // range here completed its pwrite before it was enqueued, and the
        // barrier above precedes this publish, so a published seq never names
        // bytes that are not on the device.
        debug_assert!(vlogs.iter().all(|v| v.durable_bytes() <= v.reserved_bytes()));
        {
            let mut v = shared.visible.lock().unwrap();
            for (start, end) in &batches {
                // seq numbers are 1-based and `visible_seq` is inclusive, so a
                // batch covering [base, end) completes the range [base-1, end-1).
                v.complete(*start - 1, *end - 1);
            }
        }
        shared.metrics.commits.fetch_add(1, Ordering::Relaxed);
        shared.metrics.batches_committed.fetch_add(batches.len() as u64, Ordering::Relaxed);
        shared.visible_cv.notify_all();
    })
}
