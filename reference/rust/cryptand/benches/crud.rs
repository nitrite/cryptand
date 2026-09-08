//! The CRUD-under-load matrix — see `reference/bench/README.md`.
//!
//! `benches/ops.rs` beside this one measures **C** and **R**: a bulk insert, a
//! point read, a scan, an index lookup. It has no **U** and no **D**, and every
//! phase of it runs against a database that has just been compacted and is
//! otherwise idle. That is the best case, and it is not the case a person
//! choosing a database is asking about when they say "under load".
//!
//! This one measures all four operations, and it measures them twice: once each
//! in isolation, and once in a sustained mixed workload where compaction and
//! value-log GC are running underneath. The difference between the two is the
//! point of the benchmark.
//!
//! ## What "under load" means here, and what it does not
//!
//! It means a **sustained mixed workload against a database larger than the
//! page cache**, with background maintenance running. It does **not** mean
//! concurrency. `reference/bench/README.md` explains why the cross-language
//! suite has no concurrency row: Dart has no shared-memory threads, so a
//! multi-writer number would not mean the same thing in each of the three, and
//! `10-transactions.md` §2's scaling has its own single-language harness in
//! `benches/p3_write_scale.rs`. Load here is the shape of the work, not the
//! number of threads, and that is a definition all three can honour.
//!
//! ## The rules, from `design/performance-model.md` §8
//!
//! - **A counter is the primary result; wall time is an observation.** Page
//!   reads per operation and bytes to device are comparable across machines and
//!   languages. Microseconds are not, and are labelled.
//! - **The median, not the mean**, and a p99 beside it, because the tail is
//!   what an interactive application feels.
//! - **Measure after a compaction.** A phase that reads what it just wrote
//!   measures the memtable.
//! - Every row compares an implementation **to itself** across a change. See
//!   `reference/bench/README.md` for the rows that are not comparable between
//!   implementations and why.

mod harness;

use std::time::Instant;

use cryptand::container::{Durability, Profile};
use cryptand::database::Database;
use cryptand::value::{NumType, Value};

/// Snowflake-shaped ids: a long shared prefix, as `performance-model.md` §1
/// assumes. The same function as `benches/ops.rs`, so the two are the same
/// workload.
fn snowflake(i: u64) -> i64 {
    (1_767_225_600_000i64 * 4_194_304) + (i as i64) * 4096 + 1
}

/// §1's document shape: 20 fields, names averaging 12 B, values averaging 20 B.
/// `rev` changes the value bytes without changing the shape, so an update is a
/// real rewrite rather than a no-op the engine could elide.
fn doc(i: u64, rev: u64) -> Value {
    let pad = format!("{i:0>6}");
    let v = |p: &str| {
        let mut s = format!("{p}-{pad}-{}", rev % 10);
        while s.len() < 19 {
            s.push('y');
        }
        Value::Str(s)
    };
    Value::Doc(vec![
        ("_id".into(), Value::NitriteId(snowflake(i))),
        ("custAddr1_ln".into(), v("addr1")),
        ("custAddr2_ln".into(), v("addr2")),
        ("custCityName".into(), v("city")),
        ("custPostCode".into(), v("post")),
        ("custCountryX".into(), v("ctry")),
        ("custEmailAdr".into(), v("mail")),
        ("custPhoneNum".into(), v("phon")),
        ("ordReference".into(), v("ordr")),
        ("ordStatusTxt".into(), v("stat")),
        ("ordCurrencyC".into(), v("curr")),
        ("ordNotesText".into(), v("note")),
        ("whseLocation".into(), v("whse")),
        ("carrierName_".into(), v("carr")),
        ("trackingNumb".into(), v("trak")),
        ("ordTotMinorU".into(), Value::int(NumType::IntVar, 1299 + i as i128)),
        ("ordTaxMinorU".into(), Value::int(NumType::IntVar, 216)),
        ("ordShipMinor".into(), Value::int(NumType::IntVar, 499)),
        ("placedAtUtcM".into(), Value::Timestamp(1_767_225_000_000)),
        ("dispatchUtcM".into(), Value::Timestamp(1_767_225_600_000)),
    ])
}

fn row(name: &str, value: String, unit: &str, primary: bool) {
    let kind = if primary { "counter" } else { "observation" };
    println!("{name}={value} unit={unit} kind={kind}");
}

fn us(d: std::time::Duration) -> u64 {
    d.as_nanos() as u64 / 1000
}

/// p50 and p99 of a latency sample, in microseconds, plus the mean cost in
/// page reads — the counter that does not move with the machine.
struct Phase {
    lat: Vec<u64>,
    page_reads: u64,
    device: u64,
    ops: u64,
    secs: f64,
}

impl Phase {
    fn report(&mut self, name: &str) {
        row(
            &format!("{name}_ops_per_s"),
            format!("{:.0}", self.ops as f64 / self.secs.max(1e-9)),
            "ops/s",
            false,
        );
        row(&format!("{name}_us_p50"), harness::percentile(&self.lat, 0.50).to_string(), "us", false);
        row(&format!("{name}_us_p99"), harness::percentile(&self.lat, 0.99).to_string(), "us", false);
        row(&format!("{name}_us_p999"), harness::percentile(&self.lat, 0.999).to_string(), "us", false);
        row(
            &format!("{name}_page_reads_per_op"),
            format!("{:.3}", self.page_reads as f64 / self.ops.max(1) as f64),
            "pages/op",
            true,
        );
        row(
            &format!("{name}_bytes_device_per_op"),
            format!("{:.1}", self.device as f64 / self.ops.max(1) as f64),
            "bytes/op",
            true,
        );
    }
}

fn main() {
    let n = harness::arg(0, 20_000);
    // The mixed phase runs this many operations. Kept independent of `n` so the
    // steady-state cost is measured over a fixed amount of work whatever the
    // dataset size.
    let mixed_ops = harness::arg(1, 20_000);

    println!("# cryptand crud-under-load matrix -- rust");
    println!("# implementation=rust documents={n} mixed_ops={mixed_ops} profile=desktop durability=os");

    let b = harness::Bench::new("crud");
    let mut db = Database::create(&b.path, Profile::Desktop).unwrap();

    // ------------------------------------------------------------------
    // C — create. The bulk load, which is also the fixture for everything
    // below.
    // ------------------------------------------------------------------
    let mut c = db.collection("orders").unwrap();
    let mut logical = 0u64;
    let d0 = db.engine.pager.bytes_written_device;
    let t0 = Instant::now();
    let mut lat = Vec::with_capacity(n as usize);
    for i in 0..n {
        let mut d = doc(i, 0);
        logical += cryptand::cve::encode(&d).len() as u64;
        let t = Instant::now();
        c.insert(&mut db.engine, &mut d).unwrap();
        lat.push(us(t.elapsed()));
    }
    db.commit(Durability::Os).unwrap();
    let mut create = Phase {
        lat,
        page_reads: 0,
        device: db.engine.pager.bytes_written_device - d0,
        ops: n,
        secs: t0.elapsed().as_secs_f64(),
    };
    create.report("create");
    row("create_logical_bytes", logical.to_string(), "bytes", true);
    row(
        "create_write_amplification",
        format!("{:.3}", create.device as f64 / logical.max(1) as f64),
        "ratio",
        true,
    );

    // Drain compaction before every measured phase below: a phase that reads
    // what it just wrote measures the memtable, not the engine.
    db.engine.drain_compaction().unwrap();
    db.commit(Durability::Os).unwrap();

    // ------------------------------------------------------------------
    // R — read. Random point reads over the whole key space.
    // ------------------------------------------------------------------
    let mut rng = harness::Rng::new(0x51ED_C0DE);
    // Warm the path: the first reads pay for a cold cache, and on a JIT for
    // compilation. Neither is what this row is about.
    for _ in 0..200 {
        let _ = c.get(&mut db.engine, snowflake(rng.below(n))).unwrap();
    }
    let reads = n.min(5_000);
    let p0 = db.engine.pager.page_reads;
    let t0 = Instant::now();
    let mut lat = Vec::with_capacity(reads as usize);
    for _ in 0..reads {
        let id = snowflake(rng.below(n));
        let t = Instant::now();
        let got = c.get(&mut db.engine, id).unwrap();
        lat.push(us(t.elapsed()));
        assert!(got.is_some(), "the fixture must hold every id it reads");
    }
    Phase {
        lat,
        page_reads: db.engine.pager.page_reads - p0,
        device: 0,
        ops: reads,
        secs: t0.elapsed().as_secs_f64(),
    }
    .report("read");

    // ------------------------------------------------------------------
    // U — update. An overwrite of an existing document, which in this format
    // is a `put` at the same key: a new version, not an edit in place. The
    // interesting counter is bytes to device per update, because that is the
    // write amplification of the operation an application performs most after
    // read.
    // ------------------------------------------------------------------
    let updates = n.min(5_000);
    let p0 = db.engine.pager.page_reads;
    let d0 = db.engine.pager.bytes_written_device;
    let t0 = Instant::now();
    let mut lat = Vec::with_capacity(updates as usize);
    for k in 0..updates {
        let mut d = doc(rng.below(n), k + 1);
        let t = Instant::now();
        c.insert(&mut db.engine, &mut d).unwrap();
        lat.push(us(t.elapsed()));
    }
    db.commit(Durability::Os).unwrap();
    Phase {
        lat,
        page_reads: db.engine.pager.page_reads - p0,
        device: db.engine.pager.bytes_written_device - d0,
        ops: updates,
        secs: t0.elapsed().as_secs_f64(),
    }
    .report("update");

    db.engine.drain_compaction().unwrap();
    db.commit(Durability::Os).unwrap();

    // ------------------------------------------------------------------
    // D — delete. A tombstone, so it is a write and not a reclaim; the space
    // comes back at the next compaction that spans the key.
    // ------------------------------------------------------------------
    let deletes = n.min(5_000);
    let p0 = db.engine.pager.page_reads;
    let d0 = db.engine.pager.bytes_written_device;
    let t0 = Instant::now();
    let mut lat = Vec::with_capacity(deletes as usize);
    for k in 0..deletes {
        // Delete a disjoint band so every one hits a live document.
        let id = snowflake(k % n);
        let t = Instant::now();
        c.remove(&mut db.engine, id).unwrap();
        lat.push(us(t.elapsed()));
    }
    db.commit(Durability::Os).unwrap();
    Phase {
        lat,
        page_reads: db.engine.pager.page_reads - p0,
        device: db.engine.pager.bytes_written_device - d0,
        ops: deletes,
        secs: t0.elapsed().as_secs_f64(),
    }
    .report("delete");

    // A delete must actually have deleted. A benchmark of an operation that
    // did nothing is the easiest way to publish a fast number.
    assert!(c.get(&mut db.engine, snowflake(0)).unwrap().is_none(), "the delete phase deleted nothing");

    db.engine.drain_compaction().unwrap();
    db.commit(Durability::Os).unwrap();

    // ------------------------------------------------------------------
    // The mixed phase — the one this benchmark exists for.
    //
    // 70 % read, 20 % update, 5 % insert, 5 % delete, interleaved, with
    // compaction and value-log GC running underneath rather than drained
    // first. The mix is the shape of an interactive application's steady
    // state; the isolated phases above are each one operation's best case, and
    // the difference between the two columns is the cost of everything the
    // best case leaves out.
    // ------------------------------------------------------------------
    let p0 = db.engine.pager.page_reads;
    let d0 = db.engine.pager.bytes_written_device;
    let mut next_new = n;
    let mut lat_read = Vec::new();
    let mut lat_update = Vec::new();
    let mut lat_insert = Vec::new();
    let mut lat_delete = Vec::new();
    let t0 = Instant::now();
    for k in 0..mixed_ops {
        let roll = rng.below(100);
        let t = Instant::now();
        if roll < 70 {
            let _ = c.get(&mut db.engine, snowflake(rng.below(n))).unwrap();
            lat_read.push(us(t.elapsed()));
        } else if roll < 90 {
            let mut d = doc(rng.below(n), k + 2);
            c.insert(&mut db.engine, &mut d).unwrap();
            lat_update.push(us(t.elapsed()));
        } else if roll < 95 {
            let mut d = doc(next_new, 1);
            next_new += 1;
            c.insert(&mut db.engine, &mut d).unwrap();
            lat_insert.push(us(t.elapsed()));
        } else {
            c.remove(&mut db.engine, snowflake(rng.below(n))).unwrap();
            lat_delete.push(us(t.elapsed()));
        }
        // Background maintenance, paced as `12-profiles.md` §4 requires rather
        // than drained: this is the load the phase is named for.
        if k % 64 == 0 {
            db.engine.maybe_compact(None).unwrap();
        }
    }
    db.commit(Durability::Os).unwrap();
    let secs = t0.elapsed().as_secs_f64();

    row("mixed_ops_per_s", format!("{:.0}", mixed_ops as f64 / secs.max(1e-9)), "ops/s", false);
    row(
        "mixed_page_reads_per_op",
        format!("{:.3}", (db.engine.pager.page_reads - p0) as f64 / mixed_ops.max(1) as f64),
        "pages/op",
        true,
    );
    row(
        "mixed_bytes_device_per_op",
        format!("{:.1}", (db.engine.pager.bytes_written_device - d0) as f64 / mixed_ops.max(1) as f64),
        "bytes/op",
        true,
    );
    for (name, v) in [
        ("mixed_read", &mut lat_read),
        ("mixed_update", &mut lat_update),
        ("mixed_insert", &mut lat_insert),
        ("mixed_delete", &mut lat_delete),
    ] {
        row(&format!("{name}_us_p50"), harness::percentile(v, 0.50).to_string(), "us", false);
        row(&format!("{name}_us_p99"), harness::percentile(v, 0.99).to_string(), "us", false);
        row(&format!("{name}_count"), v.len().to_string(), "ops", true);
    }

    // The resident set the mix ran against, so the latency rows above can be
    // read against the cache that produced them (`12-profiles.md` §1).
    row("page_cache_resident_bytes", db.engine.page_cache_resident_bytes().to_string(), "bytes", true);
    row("page_cache_budget_bytes", db.engine.profile.page_cache_bytes.to_string(), "bytes", true);
    row("page_cache_evictions", db.engine.counters.page_cache_evictions.to_string(), "count", true);

    println!("# done");
}
