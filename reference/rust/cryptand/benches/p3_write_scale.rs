//! **P3 — concurrent write scaling.** `10-transactions.md` §2.1's first
//! consequence is a property of the format and holds everywhere: a commit group
//! costs **one barrier over *n* batches**, however many threads produced them,
//! because there is no journal to serialize on and no leader to elect.
//!
//! The second — that *N* writers thereby drive *N* independent append streams
//! into the device — is a property of the **host write path**, and
//! `00-conventions.md` §1.1 forbids stating it as a bare fact. This bench
//! reports which was observed.
//!
//! Run: `cargo run --release --bin p3_write_scale [rows_per_thread]`

#[path = "harness.rs"]
mod harness;
use harness::*;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use cryptand::container::{Durability, Profile};
use cryptand::store::Store;
use cryptand::value::Value;

fn run(threads: usize, rows: usize, durability: Durability, disjoint: bool) -> (f64, u64) {
    let b = Bench::new(&format!("p3-{threads}-{durability:?}"));
    let mut store = Store::create(&b.path, Profile::Server).unwrap();
    store.durability = durability;
    store.spawn_committer(1);
    let store = Arc::new(store);
    let t0 = Instant::now();
    let mut handles = Vec::new();
    for w in 0..threads {
        let s = store.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..rows {
                // Disjoint: each writer owns a key range. Overlapping: every
                // writer touches the same range, so the commit group merges.
                let id = if disjoint {
                    (w * rows + i) as i64
                } else {
                    (i % 5000) as i64 * 64 + w as i64
                };
                s.put(16, &Value::NitriteId(id), b"0123456789abcdef0123456789abcdef").unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    store.commit_once().unwrap();
    let secs = t0.elapsed().as_secs_f64();
    let commits = store.shared.commits.load(Ordering::SeqCst);
    let total = (threads * rows) as f64;
    Arc::try_unwrap(store).ok().unwrap().close().unwrap();
    (total / secs, commits)
}

fn main() {
    let rows = arg(0, 20_000) as usize;
    println!("P3 — {rows} rows per thread, 32-byte values, server profile\n");
    for durability in [Durability::Os, Durability::Sync] {
        for disjoint in [true, false] {
            println!(
                "--- durability {:?}, {} key ranges",
                durability,
                if disjoint { "disjoint" } else { "overlapping" }
            );
            let mut base = 0.0;
            for threads in [1usize, 2, 4, 8, 16, 32] {
                let (rate, commits) = run(threads, rows, durability, disjoint);
                if threads == 1 {
                    base = rate;
                }
                let per_commit = (threads * rows) as f64 / commits.max(1) as f64;
                row(
                    &format!("  {threads:>2} writers"),
                    format!(
                        "{rate:>12.0} rows/s   {:.2}x   {commits} commit groups \
                         ({per_commit:.0} rows per barrier)",
                        rate / base
                    ),
                );
            }
            println!();
        }
    }
    println!(
        "§2.1's first consequence is the one to read here: rows per barrier rising with\n\
         thread count IS group commit. The throughput column is the host's write path,\n\
         which §1.1 forbids this document from claiming in advance."
    );
}
