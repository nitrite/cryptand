//! `13-operations.md` §9 — planner statistics, maintained at compaction and
//! stored in each index tree's catalog descriptor under `params.stats`.
//!
//! **Statistics are advisory.** They may be stale or absent; a planner MUST
//! produce correct results without them, and MUST NOT refuse to run because
//! they are missing. That is the one reason §9's byte bound is safe: a coarser
//! histogram is a worse estimate and never a wrong answer.

use crate::cve;
use crate::value::{NumType, Value};

/// A mergeable, fixed-size distinct-count sketch. Chosen for exactly that
/// property: a compaction accumulates it in a few hundred bytes while
/// streaming, and two segments' sketches combine by register-wise maximum.
#[derive(Clone, Debug)]
pub struct HyperLogLog {
    pub registers: Vec<u8>,
    pub p: u32,
}

impl HyperLogLog {
    pub fn new(p: u32) -> HyperLogLog {
        HyperLogLog { registers: vec![0u8; 1 << p], p }
    }

    pub fn add(&mut self, key: &[u8]) {
        let h = crate::hash::cfh64(key);
        let idx = (h >> (64 - self.p)) as usize;
        let w = (h << self.p) | (1 << (self.p - 1));
        let rank = w.leading_zeros() as u8 + 1;
        if rank > self.registers[idx] {
            self.registers[idx] = rank;
        }
    }

    pub fn merge(&mut self, other: &HyperLogLog) {
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            *a = (*a).max(*b);
        }
    }

    pub fn estimate(&self) -> u64 {
        let m = self.registers.len() as f64;
        let alpha = match self.registers.len() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let sum: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let raw = alpha * m * m / sum;
        if raw <= 2.5 * m {
            let zeros = self.registers.iter().filter(|&&r| r == 0).count() as f64;
            if zeros > 0.0 {
                return (m * (m / zeros).ln()).round() as u64;
            }
        }
        raw.round() as u64
    }
}

#[derive(Clone, Debug)]
pub struct HistogramBucket {
    pub bound: Vec<u8>,
    pub cumulative: u64,
}

#[derive(Clone, Debug, Default)]
pub struct IndexStats {
    pub updated_seq: u64,
    pub entries: u64,
    pub distinct_estimate: u64,
    pub null_count: u64,
    pub min_key: Vec<u8>,
    pub max_key: Vec<u8>,
    pub histogram: Vec<HistogramBucket>,
}

/// §9's maximum. **64 buckets is a maximum, not a target**, and the *byte*
/// bound is the binding one.
pub const MAX_BUCKETS: usize = 64;

impl IndexStats {
    pub fn to_value(&self) -> Value {
        let u = |v: u64| Value::Int { w: NumType::U64, neg: false, mag: v as u128 };
        Value::Doc(vec![
            ("updated_seq".into(), u(self.updated_seq)),
            ("entries".into(), u(self.entries)),
            ("distinct_estimate".into(), u(self.distinct_estimate)),
            ("null_count".into(), u(self.null_count)),
            ("min_key".into(), Value::Bytes(self.min_key.clone())),
            ("max_key".into(), Value::Bytes(self.max_key.clone())),
            (
                "histogram".into(),
                Value::Array(
                    self.histogram
                        .iter()
                        .map(|b| {
                            Value::Doc(vec![
                                ("bound".into(), Value::Bytes(b.bound.clone())),
                                ("cumulative".into(), u(b.cumulative)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn from_value(v: &Value) -> IndexStats {
        let u = |f: &str| -> u64 {
            match v.field(f) {
                Some(Value::Int { mag, .. }) => *mag as u64,
                _ => 0,
            }
        };
        let by = |f: &str| -> Vec<u8> {
            match v.field(f) {
                Some(Value::Bytes(b)) => b.clone(),
                _ => Vec::new(),
            }
        };
        IndexStats {
            updated_seq: u("updated_seq"),
            entries: u("entries"),
            distinct_estimate: u("distinct_estimate"),
            null_count: u("null_count"),
            min_key: by("min_key"),
            max_key: by("max_key"),
            histogram: match v.field("histogram") {
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|b| HistogramBucket {
                        bound: match b.field("bound") {
                            Some(Value::Bytes(x)) => x.clone(),
                            _ => Vec::new(),
                        },
                        cumulative: match b.field("cumulative") {
                            Some(Value::Int { mag, .. }) => *mag as u64,
                            _ => 0,
                        },
                    })
                    .collect(),
                _ => Vec::new(),
            },
        }
    }

    /// §9 — a writer MUST reduce the bucket count until the encoded
    /// `params.stats` fits the descriptor's page budget, and SHOULD do so by
    /// **dropping alternate buckets**, which keeps the histogram equi-depth at
    /// twice the width rather than truncating its range.
    ///
    /// The bound is in bytes, not buckets: a CKE key runs to kilobytes, so a
    /// bucket *count* does not bound the size at all — 64 bounds over 300
    /// string keys measured 4734 B against a 4096 B page.
    pub fn fit_to(&mut self, budget_bytes: usize) {
        while self.encoded_len() > budget_bytes && self.histogram.len() > 1 {
            let mut kept = Vec::with_capacity(self.histogram.len().div_ceil(2));
            for (i, b) in self.histogram.iter().enumerate() {
                if i % 2 == 1 || i + 1 == self.histogram.len() {
                    kept.push(b.clone());
                }
            }
            if kept.len() == self.histogram.len() {
                kept.pop();
            }
            self.histogram = kept;
        }
        if self.encoded_len() > budget_bytes {
            self.histogram.clear();
        }
    }

    pub fn encoded_len(&self) -> usize {
        cve::encode(&self.to_value()).len()
    }
}

/// Accumulates statistics while a compaction streams — free, because that
/// compaction already touches every key.
pub struct StatsBuilder {
    pub hll: HyperLogLog,
    pub entries: u64,
    pub null_count: u64,
    pub min_key: Option<Vec<u8>>,
    pub max_key: Option<Vec<u8>>,
    samples: Vec<Vec<u8>>,
}

impl Default for StatsBuilder {
    fn default() -> Self {
        StatsBuilder::new()
    }
}

impl StatsBuilder {
    pub fn new() -> StatsBuilder {
        StatsBuilder {
            hll: HyperLogLog::new(10),
            entries: 0,
            null_count: 0,
            min_key: None,
            max_key: None,
            samples: Vec::new(),
        }
    }

    pub fn add(&mut self, key: &[u8], is_null: bool) {
        self.hll.add(key);
        self.entries += 1;
        if is_null {
            self.null_count += 1;
        }
        if self.min_key.is_none() {
            self.min_key = Some(key.to_vec());
        }
        self.max_key = Some(key.to_vec());
        self.samples.push(key.to_vec());
    }

    pub fn build(&self, updated_seq: u64, budget_bytes: usize) -> IndexStats {
        let mut hist = Vec::new();
        if !self.samples.is_empty() {
            let n = self.samples.len();
            let buckets = MAX_BUCKETS.min(n);
            let step = n.div_ceil(buckets);
            let mut cumulative = 0u64;
            let mut i = 0usize;
            while i < n {
                let end = (i + step).min(n);
                cumulative += (end - i) as u64;
                hist.push(HistogramBucket { bound: self.samples[end - 1].clone(), cumulative });
                i = end;
            }
        }
        let mut s = IndexStats {
            updated_seq,
            entries: self.entries,
            distinct_estimate: self.hll.estimate(),
            null_count: self.null_count,
            min_key: self.min_key.clone().unwrap_or_default(),
            max_key: self.max_key.clone().unwrap_or_default(),
            histogram: hist,
        };
        s.fit_to(budget_bytes);
        s
    }
}

/// §7.1 of `06-indexes.md` — choose the *selective* index rather than the
/// *unique-looking* one. `None` when no statistics are available, which a
/// planner must handle without refusing to run.
pub fn selectivity(stats: &IndexStats) -> Option<f64> {
    if stats.entries == 0 || stats.distinct_estimate == 0 {
        return None;
    }
    Some(1.0 / stats.distinct_estimate as f64)
}

pub fn most_selective<'a>(candidates: &'a [(String, IndexStats)]) -> Option<&'a str> {
    candidates
        .iter()
        .filter_map(|(n, s)| selectivity(s).map(|v| (n.as_str(), v)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(n, _)| n)
}
