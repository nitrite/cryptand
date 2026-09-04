//! **P8 — scan locality as a database ages.** `04-segments.md` §6.9 states the
//! bound as an *outcome* because that is what can be measured, tested and
//! enforced: "a format whose scan performance silently decays is not
//! acceptable."
//!
//! The four MUSTs this measures — clustered promotion (§6.3), cold-tier
//! collection (§6.8), the locality-debt bound (§6.9) and value readahead
//! (§8.1) — are each invisible to every other check.
//!
//! Run: `cargo run --release --bin p8_aged_scan [documents] [--only-on]`

#[path = "harness.rs"]
mod harness;
use harness::*;

use cryptand::container::Profile;
use cryptand::engine::Engine;
use cryptand::value::Value;
use cryptand::vlog;

struct Shape {
    name: &'static str,
    promote: bool,
    collect: bool,
    readahead: bool,
}

fn measure(n: i64, value_bytes: usize, shape: &Shape) -> (f64, f64, f64, u64) {
    let b = Bench::new("p8");
    let mut e = Engine::create(&b.path, Profile::Desktop).unwrap();
    e.memtable_entry_limit = 4_000;
    // The control has to be able to fail: `compact()` collects when it
    // finishes, so a "no collection" shape that still called it would measure
    // the collected database and report that collection changes nothing.
    e.auto_collect = shape.collect;
    if !shape.readahead {
        // The floor case: a window of one is no window at all.
        e.sb.readahead_window = 1;
    }
    let value = vec![7u8; value_bytes];
    let load = |e: &mut Engine, id: i64| {
        e.put(16, &Value::NitriteId(id), &value).unwrap();
        if e.memtable_pressure().0 >= 4_000 {
            e.flush().unwrap();
            e.maybe_compact(Some(u64::MAX)).unwrap();
        }
    };
    for i in 0..n {
        load(&mut e, i);
    }
    e.flush().unwrap();
    if shape.promote {
        e.compact().unwrap();
    } else {
        e.drain_compaction().unwrap();
    }

    e.pager.page_reads = 0;
    e.counters.value_reads = 0;
    e.counters.scanned_rows = 0;
    let rows = e.scan_tree(16, None, None, None, true).unwrap();
    assert_eq!(rows.len(), n as usize);
    let first = e.pager.page_reads;

    let mut rng = Rng::new(0xA6ED);
    for _ in 0..n * 10 {
        let id = rng.below(n as u64) as i64;
        load(&mut e, id);
    }
    e.flush().unwrap();
    if shape.promote {
        e.compact().unwrap();
    } else {
        e.drain_compaction().unwrap();
    }
    if shape.collect {
        e.collect_while_over_debt(8).unwrap();
    }

    e.pager.page_reads = 0;
    e.counters.value_reads = 0;
    e.counters.scanned_rows = 0;
    let rows = e.scan_tree(16, None, None, None, true).unwrap();
    assert_eq!(rows.len(), n as usize);
    let second = e.pager.page_reads;
    let stats: Vec<_> = e.vlog_stats.values().cloned().collect();
    (
        second as f64 / first.max(1) as f64,
        e.counters.value_reads as f64 / e.counters.scanned_rows.max(1) as f64,
        e.locality_debt() * 100.0,
        vlog::live_runs(&stats),
    )
}

fn main() {
    let n = arg(0, 20_000) as i64;
    let only_on = flag("--only-on");
    println!("P8 — {n} documents of 600 B, aged by {}x in random updates\n", 10);
    println!("{:<48} {:>8} {:>8} {:>8} {:>6}", "shape", "scan", "v/row", "debt %", "runs");
    let shapes = if only_on {
        vec![Shape { name: "all four MUSTs in force", promote: true, collect: true, readahead: true }]
    } else {
        vec![
            Shape { name: "all four MUSTs in force", promote: true, collect: true, readahead: true },
            Shape { name: "  control: promotion but no collection", promote: true, collect: false, readahead: true },
            Shape { name: "  control: no readahead window", promote: true, collect: true, readahead: false },
            Shape { name: "  floor: no promotion, no collection", promote: false, collect: false, readahead: false },
        ]
    };
    for s in &shapes {
        let (scan, vrow, debt, runs) = measure(n, 600, s);
        println!("{:<48} {scan:>7.2}x {vrow:>8.3} {debt:>8.1} {runs:>6}", s.name);
    }
    println!(
        "\n§6 of `11-conformance.md` bounds the first column at 1.5x and the second at 0.3,\n\
         and requires `locality_debt` to be within `locality_debt_pct` (20 %) at the end."
    );
}
