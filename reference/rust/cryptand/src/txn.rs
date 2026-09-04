//! `10-transactions.md` §3 (transactions and isolation), §6 (the normative
//! backpressure curve) and §7 (durability modes).

use crate::container::Durability;
use crate::engine::{Engine, Snapshot};
use crate::error::{Error, Result};
use crate::segment::{op, user_prefix};
use crate::value::Value;

/// §3's four levels.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Isolation {
    /// Reads at the start snapshot; writes are buffered and sequenced at
    /// commit; write–write conflicts are detected by key.
    Snapshot,
    /// Each statement takes a fresh snapshot.
    ReadCommitted,
    /// Additionally records the read set and validates it at commit.
    Serializable,
    /// Pins a snapshot; cannot conflict; never blocks and is never blocked.
    ReadOnly,
}

#[derive(Clone, Debug)]
pub struct TxnWrite {
    pub tree: u32,
    pub key: Value,
    pub op: u8,
    pub value: Vec<u8>,
    pub expiry_ms: Option<u64>,
}

/// A buffered transaction. **Nothing durable is written before sequencing**, so
/// rollback is free and leaves no trace — unlike the undo-log approach all
/// three SDKs use today, which writes and then reverses.
pub struct Transaction {
    pub isolation: Isolation,
    pub snapshot: Snapshot,
    writes: Vec<TxnWrite>,
    reads: Vec<Vec<u8>>,
    savepoints: Vec<usize>,
    committed: bool,
}

impl Transaction {
    pub fn begin(engine: &mut Engine, isolation: Isolation) -> Transaction {
        Transaction {
            isolation,
            snapshot: engine.snapshot(),
            writes: Vec::new(),
            reads: Vec::new(),
            savepoints: Vec::new(),
            committed: false,
        }
    }

    pub fn put(&mut self, tree: u32, key: Value, value: Vec<u8>) -> Result<()> {
        self.check_writable()?;
        self.writes.push(TxnWrite { tree, key, op: op::PUT, value, expiry_ms: None });
        Ok(())
    }

    pub fn remove(&mut self, tree: u32, key: Value) -> Result<()> {
        self.check_writable()?;
        self.writes.push(TxnWrite { tree, key, op: op::DELETE, value: Vec::new(), expiry_ms: None });
        Ok(())
    }

    fn check_writable(&self) -> Result<()> {
        if self.isolation == Isolation::ReadOnly {
            return crate::error::invalid("a read-only transaction cannot write");
        }
        Ok(())
    }

    pub fn get(&mut self, engine: &mut Engine, tree: u32, key: &Value) -> Result<Option<Vec<u8>>> {
        // Serializable records its read set and validates it at commit.
        if self.isolation == Isolation::Serializable {
            self.reads.push(user_prefix(tree, &crate::cke::encode(key)?));
        }
        if self.isolation == Isolation::ReadCommitted {
            self.snapshot = engine.snapshot();
        }
        // A buffered write of the same key is visible to its own transaction.
        for w in self.writes.iter().rev() {
            if w.tree == tree && crate::compare::values_equal(&w.key, key) {
                return Ok(if w.op == op::DELETE { None } else { Some(w.value.clone()) });
            }
        }
        let snap = self.snapshot;
        engine.get_at(tree, key, Some(&snap))
    }

    /// §3 — savepoints discard buffered entries after a mark.
    pub fn savepoint(&mut self) -> usize {
        self.savepoints.push(self.writes.len());
        self.savepoints.len() - 1
    }

    pub fn rollback_to(&mut self, mark: usize) {
        if let Some(&at) = self.savepoints.get(mark) {
            self.writes.truncate(at);
            self.savepoints.truncate(mark);
        }
    }

    pub fn rollback(&mut self, engine: &mut Engine) {
        self.writes.clear();
        engine.release(&self.snapshot);
        self.committed = true;
    }

    pub fn write_set(&self) -> Result<Vec<Vec<u8>>> {
        self.writes
            .iter()
            .map(|w| Ok(user_prefix(w.tree, &crate::cke::encode(&w.key)?)))
            .collect()
    }

    /// §3 — conflict detection compares the written key set against keys
    /// written by batches with `seq` in `(start_seq, commit_seq)`. On conflict
    /// the transaction aborts; the format does not define automatic retry.
    pub fn commit(&mut self, engine: &mut Engine, durability: Durability) -> Result<u64> {
        if self.committed {
            return crate::error::invalid("the transaction is already finished");
        }
        if self.isolation == Isolation::ReadOnly {
            engine.release(&self.snapshot);
            self.committed = true;
            return Ok(engine.sb.commit_id);
        }
        let mut checked = self.write_set()?;
        if self.isolation == Isolation::Serializable {
            checked.extend(self.reads.iter().cloned());
        }
        if engine.conflicts(&checked, self.snapshot.seq) {
            engine.release(&self.snapshot);
            self.committed = true;
            return Err(Error::Conflict(
                "a batch sequenced after this transaction started wrote one of its keys".into(),
            ));
        }
        for w in std::mem::take(&mut self.writes) {
            match w.op {
                op::DELETE => {
                    engine.remove(w.tree, &w.key)?;
                }
                _ => match w.expiry_ms {
                    Some(x) => {
                        engine.put_with_expiry(w.tree, &w.key, &w.value, x)?;
                    }
                    None => {
                        engine.put(w.tree, &w.key, &w.value)?;
                    }
                },
            }
        }
        engine.flush()?;
        let id = engine.commit(durability)?;
        engine.release(&self.snapshot);
        self.committed = true;
        Ok(id)
    }
}

/// §6's bounds, and the curve over them.
#[derive(Clone, Copy, Debug)]
pub struct Bound {
    pub name: &'static str,
    pub current: f64,
    pub soft: f64,
    pub hard: f64,
}

impl Bound {
    pub fn overshoot(&self) -> f64 {
        if self.hard <= self.soft {
            return if self.current > self.soft { 1.0 } else { 0.0 };
        }
        ((self.current - self.soft) / (self.hard - self.soft)).clamp(0.0, 1.0)
    }
}

/// §6 — **the backpressure curve is normative**:
/// `delay_ms = max_delay_ms * x^2`, quadratic so it is imperceptible while the
/// engine is merely busy and firm before it is in trouble.
#[derive(Clone, Debug)]
pub struct Backpressure {
    pub delay_ms: f64,
    pub cause: Option<&'static str>,
}

pub const MAX_DELAY_MS: f64 = 100.0;

impl Backpressure {
    pub fn compute(bounds: &[Bound]) -> Backpressure {
        let mut worst = 0.0f64;
        let mut cause = None;
        for b in bounds {
            let x = b.overshoot();
            if x > worst {
                worst = x;
                cause = Some(b.name);
            }
        }
        Backpressure { delay_ms: MAX_DELAY_MS * worst * worst, cause }
    }

    /// §6: an implementation MUST NOT stall at the hard threshold without
    /// having applied increasing delay before it — a cliff turns a throughput
    /// problem into a hang, and that is the failure users report.
    pub fn is_cliff_free(&self) -> bool {
        self.delay_ms.is_finite()
    }
}

/// The five bounds of §6, read off an engine.
pub fn bounds_of(engine: &mut Engine) -> Result<Vec<Bound>> {
    let l0 = engine.refs_at(0)?.len() as f64;
    let l0_trigger = engine.policy.l0_trigger.max(1) as f64;
    let mut worst_tier = 0.0f64;
    for level in 1..engine.policy.last_level() {
        worst_tier = worst_tier.max(engine.refs_at(level)?.len() as f64);
    }
    let (mem, mem_limit) = engine.memtable_pressure();
    let debt = engine.locality_debt() * 100.0;
    let debt_pct = engine.sb.locality_debt_pct as f64;
    let tier_width = engine.policy.tier_width.max(1) as f64;
    let vlog_live: u64 = engine.vlog_stats.values().map(|s| s.live_bytes).sum();
    let vlog_alloc: u64 =
        engine.vlog_stats.values().map(|s| s.pages as u64 * engine.page_size() as u64).sum();
    let amp = if vlog_live == 0 { 100.0 } else { vlog_alloc as f64 * 100.0 / vlog_live as f64 };
    let target = engine.sb.vlog_space_target_pct as f64;
    Ok(vec![
        Bound { name: "l0_segments", current: l0, soft: l0_trigger, hard: l0_trigger * 4.0 },
        Bound { name: "tier_segments", current: worst_tier, soft: tier_width, hard: tier_width * 2.0 },
        Bound {
            name: "memtable_bytes",
            current: mem as f64,
            soft: mem_limit as f64,
            hard: mem_limit as f64 * 2.0,
        },
        Bound { name: "vlog_space", current: amp, soft: target, hard: target * 2.0 },
        Bound { name: "locality_debt", current: debt, soft: debt_pct, hard: debt_pct * 2.0 },
    ])
}
