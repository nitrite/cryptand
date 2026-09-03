//! Where does P3's scaling actually stop?
//!
//! `design/performance-model.md` §4 names two candidates — the one `fetch_add`
//! and the committer — and `10-transactions.md` §2.1 asserts the value-log path
//! is free of contention because "concurrent writers never touch the same
//! bytes, buffer, or cache line". That last claim is about *writers*; it says
//! nothing about the file, and `00-conventions.md` §2 requires a database to be
//! **one file**.
//!
//! So this measures the three shared things in isolation, with no engine
//! around them:
//!
//!   1. `pwrite` at disjoint offsets in ONE file — the format's actual shape
//!   2. `pwrite` at disjoint offsets in N files — the same bytes, no shared inode
//!   3. one mutex-guarded queue with a condvar notify — the committer handoff
//!
//!     cargo run --release --bin p3_bottleneck

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::time::Instant;

const RECORD: usize = 512;
const PER_THREAD: usize = 20_000;

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cryptand-p3b-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.join(name)
}

fn new_file(name: &str) -> File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(temp(name))
        .unwrap()
}

fn scale(label: &str, widths: &[usize], f: impl Fn(usize) -> f64) {
    println!("\n{label}");
    println!("{:>8} {:>14} {:>8}", "threads", "ops/s", "scale");
    let mut base = 0.0;
    for &w in widths {
        let ops = f(w);
        if base == 0.0 {
            base = ops;
        }
        println!("{w:>8} {ops:>14.0} {:>7.2}x", ops / base);
    }
}

fn run<T: Send + Sync + 'static>(threads: usize, state: Arc<T>, body: fn(&T, usize, usize)) -> f64 {
    let gate = Arc::new(Barrier::new(threads + 1));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (state, gate) = (state.clone(), gate.clone());
        handles.push(std::thread::spawn(move || {
            gate.wait();
            body(&state, t, PER_THREAD);
        }));
    }
    gate.wait();
    let at = Instant::now();
    for h in handles {
        h.join().unwrap();
    }
    (threads * PER_THREAD) as f64 / at.elapsed().as_secs_f64()
}

struct OneFile {
    file: File,
    tail: AtomicU64,
}

struct ManyFiles {
    files: Vec<File>,
    tail: AtomicU64,
}

struct Queue {
    q: Mutex<Vec<(u64, u64)>>,
    cv: Condvar,
}

fn main() {
    let widths = [1usize, 2, 4, 8, 16, 32];
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    println!("P3 bottleneck decomposition. {PER_THREAD} ops per thread, {RECORD}-byte records, {cores} cores.");

    scale("1. reserve + pwrite, disjoint offsets, ONE file (the format's shape)", &widths, |w| {
        let s = Arc::new(OneFile { file: new_file("one"), tail: AtomicU64::new(0) });
        run(w, s, |s, _t, n| {
            let buf = [0xA5u8; RECORD];
            for _ in 0..n {
                let off = s.tail.fetch_add(RECORD as u64, Ordering::AcqRel);
                s.file.write_all_at(&buf, off).unwrap();
            }
        })
    });

    scale("2. the same writes spread over ONE FILE PER THREAD", &widths, |w| {
        let files = (0..w).map(|i| new_file(&format!("many{i}"))).collect();
        let s = Arc::new(ManyFiles { files, tail: AtomicU64::new(0) });
        run(w, s, |s, t, n| {
            let buf = [0xA5u8; RECORD];
            for _ in 0..n {
                let off = s.tail.fetch_add(RECORD as u64, Ordering::AcqRel);
                s.files[t].write_all_at(&buf, off).unwrap();
            }
        })
    });

    scale("3. the committer handoff: one mutex-guarded queue plus a notify", &widths, |w| {
        let s = Arc::new(Queue { q: Mutex::new(Vec::new()), cv: Condvar::new() });
        let drain = s.clone();
        let stop = Arc::new(AtomicU64::new(0));
        let stop2 = stop.clone();
        let drainer = std::thread::spawn(move || {
            while stop2.load(Ordering::Acquire) == 0 {
                let mut q = drain.q.lock().unwrap();
                if q.is_empty() {
                    let (g, _) = drain
                        .cv
                        .wait_timeout(q, std::time::Duration::from_micros(200))
                        .unwrap();
                    q = g;
                }
                q.clear();
            }
        });
        let ops = run(w, s, |s, _t, n| {
            for i in 0..n {
                s.q.lock().unwrap().push((i as u64, i as u64 + 1));
                s.cv.notify_one();
            }
        });
        stop.store(1, Ordering::Release);
        drainer.join().unwrap();
        ops
    });

    let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("cryptand-p3b-{}", std::process::id())));
}
