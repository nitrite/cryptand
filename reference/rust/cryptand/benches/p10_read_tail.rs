//! **P10 — the bounded read tail.** `04-segments.md` §4.1, and the measurement
//! lesson `11-conformance.md` §6 turned into a normative write load: keys in
//! **random order**, then updates to a substantial fraction. Ascending inserts
//! give every flush a disjoint key range, so manifest pruning alone leaves one
//! candidate and every shape — including the controls — reads p99 = 1.
//!
//! Run: `cargo run --release --bin p10_read_tail [documents]`

#[path = "harness.rs"]
mod harness;
use harness::*;

use cryptand::container::Profile;
use cryptand::engine::Engine;
use cryptand::value::Value;

struct Shape {
    name: &'static str,
    filters: bool,
    early_exit: bool,
    plain_tiered: bool,
}

fn measure(n: i64, shape: &Shape) -> (f64, u64, u64, u64) {
    let b = Bench::new("p10");
    let mut e = Engine::create(&b.path, Profile::Desktop).unwrap();
    e.memtable_entry_limit = 2_000;
    e.filters = shape.filters;
    e.early_exit = shape.early_exit;
    if shape.plain_tiered {
        // §3.1: "Plain tiering is this policy with `overlap_bound =
        // tier_width`", and nothing else changes — the control is one
        // superblock field.
        e.policy = e.policy.plain_tiered();
        e.sb.overlap_bound = e.policy.overlap_bound;
    }
    let mut rng = Rng::new(0xC0FFEE);
    let mut ids: Vec<i64> = (0..n).collect();
    for i in (1..ids.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        ids.swap(i, j);
    }
    let push = |e: &mut Engine, id: i64, v: &[u8]| {
        e.put(16, &Value::NitriteId(id), v).unwrap();
        if e.memtable_pressure().0 >= 2_000 {
            e.flush().unwrap();
            e.maybe_compact(Some(u64::MAX)).unwrap();
        }
    };
    for &id in &ids {
        push(&mut e, id, b"v");
    }
    for _ in 0..n / 2 {
        let id = rng.below(n as u64) as i64;
        push(&mut e, id, b"updated");
    }
    e.flush().unwrap();

    e.counters.segments_probed.clear();
    let probes = 20_000;
    for _ in 0..probes {
        let id = rng.below(n as u64) as i64;
        e.get(16, &Value::NitriteId(id)).unwrap();
    }
    let s: Vec<u64> = e.counters.segments_probed.iter().map(|&x| x as u64).collect();
    let mean = s.iter().sum::<u64>() as f64 / s.len() as f64;
    (mean, percentile(&s, 0.99), percentile(&s, 0.999), *s.iter().max().unwrap())
}

fn main() {
    let n = arg(0, 200_000) as i64;
    println!("P10 — {n} documents, random-order writes plus {} updates\n", n / 2);
    println!("{:<44} {:>6} {:>5} {:>7} {:>5}", "shape", "mean", "p99", "p99.9", "max");
    for shape in [
        Shape { name: "range-partitioned, filter on, early exit", filters: true, early_exit: true, plain_tiered: false },
        Shape { name: "  control: filter off", filters: false, early_exit: true, plain_tiered: false },
        Shape { name: "  control: plain tiered (overlap = tier)", filters: true, early_exit: true, plain_tiered: true },
        Shape { name: "  control: plain tiered, filter off", filters: false, early_exit: true, plain_tiered: true },
        Shape { name: "  control: no early exit (§4's default)", filters: true, early_exit: false, plain_tiered: false },
    ] {
        let (mean, p99, p999, max) = measure(n, &shape);
        println!("{:<44} {mean:>6.2} {p99:>5} {p999:>7} {max:>5}", shape.name);
    }
    println!(
        "\n§6's bound is p99 <= 2 and p99.9 <= 3, and it belongs to the early exit:\n\
         the arithmetic in §4.1 counts filter false positives and nothing else."
    );
}
