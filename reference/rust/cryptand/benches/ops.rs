//! The cross-language operational benchmark — see `reference/bench/README.md`.
//!
//! The `p*` benchmarks beside this one measure the *design*: whether a bound
//! holds, whether a mechanism is the one doing the work. This one measures what
//! the phrase "performance claim" usually means to a person choosing a
//! database: what the implementation does per second, and what it costs on the
//! device. The same workload runs in all three languages and prints the same
//! rows, so the numbers can be put next to each other.
//!
//! `design/performance-model.md` §8's rule governs the output: **a counter is
//! the primary result and wall time is an observation.** Page reads per lookup
//! is comparable across machines and across languages; microseconds are not,
//! and are labelled.

mod harness;

use std::path::Path;
use std::time::Instant;

use cryptand::codec;
use cryptand::container::{Durability, Profile};
use cryptand::database::{Database, Indexing};
use cryptand::engine::Engine;
use cryptand::value::{NumType, Value};

/// Snowflake-shaped ids: a long shared prefix, as §1 assumes.
fn snowflake(i: u64) -> i64 {
    (1_767_225_600_000i64 * 4_194_304) + (i as i64) * 4096 + 1
}

/// §1's document shape: 20 fields, names averaging 12 B, values averaging 20 B,
/// giving a ~516 B logical record. Built to that shape deliberately — every
/// density figure in §6 is costed against it.
fn doc(i: u64) -> Value {
    let pad = format!("{i:0>6}");
    let v = |p: &str| {
        let mut s = format!("{p}-{pad}-x");
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
    // `counter` and `observation` are the two words the other two
    // implementations print too, so a comparison script can filter on them
    // rather than on a hand-maintained list of row names.
    let kind = if primary { "counter" } else { "observation" };
    println!("{name}={value} unit={unit} kind={kind}");
}

fn percentile(v: &mut Vec<u64>, p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[((v.len() - 1) as f64 * p).round() as usize]
}

/// Fills a database and returns `(logical bytes, elapsed seconds, the index)`.
fn fill(
    db: &mut Database,
    n: u64,
    with_index: bool,
) -> (u64, f64, Option<cryptand::database::IndexDescriptor>) {
    let mut c = db.collection("orders").unwrap();
    let idx = if with_index {
        Some(db.create_index(&c, &["ordStatusTxt"], "non_unique", false).unwrap())
    } else {
        None
    };
    let mut logical = 0u64;
    let t0 = Instant::now();
    for i in 0..n {
        let mut d = doc(i);
        logical += cryptand::cve::encode(&d).len() as u64;
        c.insert(&mut db.engine, &mut d).unwrap();
        if let Some(ix) = &idx {
            db.index_document(ix, &d).unwrap();
        }
    }
    db.commit(Durability::Os).unwrap();
    (logical, t0.elapsed().as_secs_f64(), idx)
}

fn file_bytes(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn main() {
    let n = harness::arg(0, 20_000);
    println!("# cryptand ops bench -- rust");
    println!("# implementation=rust documents={n} profile=desktop durability=os");

    // ------------------------------------------------------------------
    // insert
    // ------------------------------------------------------------------
    let b = harness::Bench::new("ops");
    let mut db = Database::create(&b.path, Profile::Desktop).unwrap();
    let (logical, secs, index) = fill(&mut db, n, true);
    // `13-operations.md` §6's own required metrics, not the file length: the
    // file is grown in large chunks, so its size is preallocated space.
    let device = db.engine.pager.bytes_written_device;
    db.engine.drain_compaction().unwrap();
    db.commit(Durability::Os).unwrap();
    let device_after_compaction = db.engine.pager.bytes_written_device;

    row("insert_docs_per_s", format!("{:.0}", n as f64 / secs), "docs/s", false);
    row("insert_bytes_device", device.to_string(), "bytes", true);
    row("insert_logical_bytes", logical.to_string(), "bytes", true);
    row(
        "write_amplification",
        format!("{:.3}", device as f64 / logical.max(1) as f64),
        "ratio",
        true,
    );
    row(
        "write_amplification_compacted",
        format!("{:.3}", device_after_compaction as f64 / logical.max(1) as f64),
        "ratio",
        true,
    );

    // ------------------------------------------------------------------
    // point read -- after a compaction, so it measures the engine and not the
    // memtable. A benchmark that reads what it just wrote measures neither.
    // ------------------------------------------------------------------
    let c = db.collection("orders").unwrap();
    let mut rng = harness::Rng::new(0x51ED_C0DE);
    // Warm the path: the first read pays for a cold page cache and, on a
    // managed runtime, for compilation.
    for _ in 0..200 {
        let _ = c.get(&mut db.engine, snowflake(rng.below(n)));
    }
    db.engine.pager.page_reads = 0;
    let mut samples = Vec::with_capacity(5000);
    let reads = 5000.min(n as usize);
    for _ in 0..reads {
        let id = snowflake(rng.below(n));
        let t = Instant::now();
        let got = c.get(&mut db.engine, id).unwrap();
        samples.push(t.elapsed().as_nanos() as u64);
        assert!(got.is_some(), "the fixture must hold every id it reads");
    }
    let page_reads = db.engine.pager.page_reads;
    row("point_read_us_p50", format!("{:.2}", percentile(&mut samples, 0.50) as f64 / 1000.0), "us", false);
    row("point_read_us_p99", format!("{:.2}", percentile(&mut samples, 0.99) as f64 / 1000.0), "us", false);
    row(
        "point_read_page_reads",
        format!("{:.3}", page_reads as f64 / reads as f64),
        "pages/lookup",
        true,
    );

    // ------------------------------------------------------------------
    // scan
    // ------------------------------------------------------------------
    db.engine.pager.page_reads = 0;
    let t = Instant::now();
    let rows = c.scan(&mut db.engine).unwrap();
    let scan_secs = t.elapsed().as_secs_f64();
    let scan_pages = db.engine.pager.page_reads;
    assert_eq!(rows.len() as u64, n, "the scan must return every document");
    row("scan_rows_per_s", format!("{:.0}", rows.len() as f64 / scan_secs), "rows/s", false);
    row(
        "scan_page_reads_per_row",
        format!("{:.4}", scan_pages as f64 / rows.len() as f64),
        "pages/row",
        true,
    );

    // ------------------------------------------------------------------
    // index lookup
    // ------------------------------------------------------------------
    // The index the fill already created. Creating a second one here returned
    // an error and the row was skipped **silently**, which is how a benchmark
    // reports nothing and still looks like it ran.
    if let Some(ix) = &index {
        let mut samples = Vec::with_capacity(2000);
        for i in 0..2000.min(n) {
            let pad = format!("{i:0>6}");
            let mut s = format!("stat-{pad}-x");
            while s.len() < 19 {
                s.push('y');
            }
            let scan = cryptand::index::scan_prefix(&[Value::Str(s)]).unwrap();
            let t = Instant::now();
            let _ = db.index_scan(ix, &scan).unwrap();
            samples.push(t.elapsed().as_nanos() as u64);
        }
        row(
            "index_lookup_us_p50",
            format!("{:.2}", percentile(&mut samples, 0.50) as f64 / 1000.0),
            "us",
            false,
        );
    }
    let on_disk = file_bytes(&b.path);
    db.close().unwrap();
    drop(b);

    // ------------------------------------------------------------------
    // the codec -- and the row is here because it measured ZERO, which is why
    // `page_codec` is 0 in every profile now. `01-container.md` §7 carries the
    // reasoning: a page is a fixed-size slot, so a compressed page occupies
    // the same slot and is written with the same page_size-byte write. The row
    // stays in the suite so that a container shape which *does* make it pay
    // shows up here rather than in an argument.
    // ------------------------------------------------------------------
    let bytes_off = device_after_compaction;
    let b2 = harness::Bench::new("ops-codec");
    let mut db2 = Database::create(&b2.path, Profile::Desktop).unwrap();
    db2.engine.pager.page_codec = codec::LZ4;
    db2.engine.sb.page_codec = codec::LZ4;
    let (_, _, _) = fill(&mut db2, n, true);
    db2.engine.drain_compaction().unwrap();
    db2.commit(Durability::Os).unwrap();
    let device_on = db2.engine.pager.bytes_written_device;
    let bytes_on = device_on;
    db2.close().unwrap();
    drop(b2);
    row("codec_bytes_on", bytes_on.to_string(), "bytes", true);
    row("codec_bytes_off", bytes_off.to_string(), "bytes", true);
    row("codec_bytes_device_on", device_on.to_string(), "bytes", true);
    row(
        "codec_saving",
        format!("{:.4}", 1.0 - bytes_on as f64 / bytes_off.max(1) as f64),
        "ratio",
        true,
    );

    // ------------------------------------------------------------------
    // the cipher, on the write path -- P11
    // ------------------------------------------------------------------
    let b3 = harness::Bench::new("ops-enc");
    let key = [7u8; 32];
    let mut db3 = Database {
        engine: Engine::create_encrypted(&b3.path, Profile::Desktop, &key, 0, 0, 0, 0).unwrap(),
    };
    let (_, enc_secs, _) = fill(&mut db3, n, true);
    db3.close().unwrap();
    drop(b3);
    row(
        "cipher_write_ratio",
        format!("{:.3}", enc_secs / secs.max(1e-9)),
        "ratio",
        false,
    );
    println!("# done");
}
