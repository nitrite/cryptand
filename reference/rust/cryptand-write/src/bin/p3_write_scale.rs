//! **P3** — `design/performance-model.md` §4: "Insert throughput scales
//! near-linearly with writer threads up to the device's useful queue depth
//! (8–16 on NVMe), then becomes device-bound."
//!
//!     cargo run --release --bin p3_write_scale [total_batches]
//!
//! Reports, per `design/performance-model.md` §4's *Measure* line: 1…32 writer
//! threads inserting disjoint and overlapping key ranges, with throughput and
//! p50/p99 latency. The engine-comparison half of P3 (≥2× RocksDB, ≥3× Fjall,
//! ≥5× MVStore) is a separate benchmark against those engines and is not this.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use cryptand_conformance::cke;
use cryptand_conformance::value::Value;
use cryptand_write::engine::{Batch, Durability, WriteOptions};
use cryptand_write::vlog::HeatClass;
use cryptand_write::WriteEngine;

const VALUE_BYTES: usize = 512;

fn key(i: i64) -> Vec<u8> {
    cke::encode(&Value::NitriteId(i)).unwrap()
}

struct Run {
    ops_per_sec: f64,
    p50_us: f64,
    p99_us: f64,
}

fn run(threads: usize, total: usize, overlapping: bool, options: WriteOptions) -> Run {
    let dir = std::env::temp_dir().join(format!("cryptand-p3-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("t{threads}.cryptand"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let e = Arc::new(WriteEngine::create(file, options).unwrap());
    let per_thread = total / threads;
    let gate = Arc::new(Barrier::new(threads + 1));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (e, gate) = (e.clone(), gate.clone());
        handles.push(std::thread::spawn(move || {
            let mut lat = Vec::with_capacity(per_thread);
            let value = vec![0xA5u8; VALUE_BYTES];
            gate.wait();
            for i in 0..per_thread {
                // Disjoint: each thread owns a key range. Overlapping: every
                // thread writes the same small range, so memtable shards and
                // the same keys collide.
                let k = if overlapping {
                    (i % 1024) as i64
                } else {
                    (t * per_thread + i) as i64
                };
                let mut b = Batch::default();
                b.put(16, key(k), value.clone());
                let at = Instant::now();
                e.write(&b, HeatClass::First).unwrap();
                lat.push(at.elapsed());
            }
            lat
        }));
    }
    gate.wait();
    let started = Instant::now();
    let mut lat: Vec<Duration> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    e.drain();
    let elapsed = started.elapsed();
    let _ = std::fs::remove_file(&path);
    lat.sort();
    let pick = |q: f64| lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)].as_secs_f64() * 1e6;
    Run {
        ops_per_sec: lat.len() as f64 / elapsed.as_secs_f64(),
        p50_us: pick(0.50),
        p99_us: pick(0.99),
    }
}

/// §2.1's own claim: "one `fetch_add`; ~20 ns even at 64 threads".
fn counter_cost(threads: usize, per_thread: usize) -> f64 {
    let c = Arc::new(AtomicU64::new(0));
    let gate = Arc::new(Barrier::new(threads + 1));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let (c, gate) = (c.clone(), gate.clone());
        handles.push(std::thread::spawn(move || {
            gate.wait();
            for _ in 0..per_thread {
                std::hint::black_box(c.fetch_add(1, Ordering::AcqRel));
            }
        }));
    }
    gate.wait();
    let at = Instant::now();
    for h in handles {
        h.join().unwrap();
    }
    let e = at.elapsed();
    e.as_secs_f64() * 1e9 / (threads * per_thread) as f64
}

fn main() {
    let total: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let widths = [1usize, 2, 4, 8, 16, 32];

    println!("P3 -- write concurrency. {total} batches of one {VALUE_BYTES}-byte value each.");
    println!("Host: {} logical cores.\n", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0));

    println!("spec/10-transactions.md section 2.1 -- the cost of the one global fetch_add");
    println!("{:>8} {:>12}", "threads", "ns/op");
    for t in [1usize, 2, 4, 8, 16, 32, 64] {
        println!("{t:>8} {:>12.1}", counter_cost(t, 200_000));
    }

    // `sync` waits for a real barrier per commit group, and at one writer that
    // is one fsync per batch, so it runs a smaller count rather than a
    // differently-shaped workload.
    let sync_total = (total / 20).max(2_000);
    for (label, durability, count) in [
        ("os -- the protocol, no barrier", Durability::Os, total),
        ("sync -- with the barrier", Durability::Sync, sync_total),
    ] {
        for overlapping in [false, true] {
            println!(
                "\n{label}, {} keys, {count} batches",
                if overlapping { "overlapping" } else { "disjoint" }
            );
            println!("{:>8} {:>14} {:>10} {:>10} {:>8}", "threads", "batches/s", "p50 us", "p99 us", "scale");
            let mut base = 0.0;
            for w in widths {
                let r = run(
                    w,
                    count,
                    overlapping,
                    WriteOptions { durability, ..Default::default() },
                );
                if w == 1 {
                    base = r.ops_per_sec;
                }
                println!(
                    "{w:>8} {:>14.0} {:>10.1} {:>10.1} {:>7.2}x",
                    r.ops_per_sec,
                    r.p50_us,
                    r.p99_us,
                    r.ops_per_sec / base
                );
            }
        }
    }

    // P3's stated fragility: "if the committer becomes the bottleneck (one
    // thread building segments for many writers), scaling stops early."
    //
    // Swept in `sync`, deliberately: `os` does not scale in the first place, so
    // sweeping the knob there would be a control that cannot fail.
    println!("\nP3's fragility -- one committer, with per-batch work injected (sync, {} batches)", sync_total / 4);
    println!("{:>10} {:>12} {:>12} {:>8}", "us/batch", "1 writer", "16 writers", "scale");
    for us in [0u64, 25, 100, 400] {
        let opts = || WriteOptions {
            durability: Durability::Sync,
            committer_work_per_batch: Duration::from_micros(us),
            ..Default::default()
        };
        let one = run(1, sync_total / 4, false, opts());
        let many = run(16, sync_total / 4, false, opts());
        println!(
            "{us:>10} {:>12.0} {:>12.0} {:>7.2}x",
            one.ops_per_sec,
            many.ops_per_sec,
            many.ops_per_sec / one.ops_per_sec
        );
    }
}
