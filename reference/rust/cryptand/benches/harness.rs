//! Shared bench scaffolding. `design/performance-model.md` §8: performance
//! assertions go on plan shape or a store counter (page reads, bytes written);
//! wall time is recorded and charted, not gated.

#![allow(dead_code)]

use std::path::PathBuf;

pub struct Bench {
    pub path: PathBuf,
}

impl Bench {
    pub fn new(tag: &str) -> Bench {
        let mut p = std::env::temp_dir();
        p.push(format!("cryptand-bench-{tag}-{}.cryptand", std::process::id()));
        let _ = std::fs::remove_file(&p);
        Bench { path: p }
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

pub fn arg(i: usize, default: u64) -> u64 {
    std::env::args().nth(i + 1).and_then(|s| s.parse().ok()).unwrap_or(default)
}

pub fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

pub fn percentile(samples: &[u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    s[(((s.len() - 1) as f64) * p).round() as usize]
}

pub fn row(name: &str, value: impl std::fmt::Display) {
    println!("{name:<44} {value}");
}
