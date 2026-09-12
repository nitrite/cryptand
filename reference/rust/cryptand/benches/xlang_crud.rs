//! The CRUD matrix at the **engine** level, in the one shape all three
//! implementations can run — the like-for-like cross-language number that
//! `benches/crud.rs` does not give, because that one drives a `Collection` and
//! builds and encodes a document inside the timed loop.
//!
//! Java's `org.dizitart.cryptand.bench.XlangCrudBench` carries the full
//! statement of what is and is not held identical; the short version is that
//! the document, the key, the profile, the durability, the phase sizes and the
//! pseudo-random sequence are the same bit for bit, and the **storage model is
//! not**. This one is `file-backed, segments resident`: a real file with
//! incremental extent writes, but whole segment extents held in memory under an
//! LRU, so a read rarely reaches the file. That difference is the largest term
//! in any gap between these numbers and another language's, and it is printed
//! as `storage_model` so it cannot be read past.

mod harness;

use std::time::Instant;

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::spaceapi::SpaceApi;
use cryptand::value::{NumType, Value};

const TREE: u32 = 16;

fn snowflake(i: u64) -> i64 {
    (1_767_225_600_000i64 * 4_194_304) + (i as i64) * 4096 + 1
}

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

/// xorshift64, and a reduction chosen so that a signed `%` and an unsigned one
/// cannot disagree. Identical in Java, Rust and Dart.
fn next(mut s: u64) -> u64 {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    s
}

fn below(seed: u64, n: u64) -> usize {
    ((seed >> 32) % n) as usize
}

static mut MEASURING: bool = true;

fn measuring() -> bool {
    unsafe { MEASURING }
}

fn row(name: &str, value: String, unit: &str) {
    if measuring() {
        println!("{name}={value} unit={unit}");
    }
}

fn ops(phase: &str, count: u64, secs: f64) {
    row(&format!("{phase}_ops_per_s"), format!("{:.0}", count as f64 / secs.max(1e-9)), "ops/s");
}

fn pass(n: u64, mixed_ops: u64, v0: &[Vec<u8>], v1: &[Vec<u8>]) {
    let b = harness::Bench::new("xlang-crud");
    let mut e = Engine::create(&b.path, Profile::Desktop).unwrap();
    let key = |i: usize| Value::NitriteId(snowflake(i as u64));

    let t0 = Instant::now();
    for i in 0..n as usize {
        e.put(TREE, &key(i), &v0[i]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    ops("create", n, t0.elapsed().as_secs_f64());

    e.compact().unwrap();

    let mut seed = 0x51ED_C0DEu64;
    for _ in 0..2000 {
        seed = next(seed);
        e.get(TREE, &key(below(seed, n))).unwrap();
    }
    let reads = n.min(5000);
    let t0 = Instant::now();
    for _ in 0..reads {
        seed = next(seed);
        e.get(TREE, &key(below(seed, n))).unwrap();
    }
    ops("read", reads, t0.elapsed().as_secs_f64());

    let updates = n.min(5000);
    let t0 = Instant::now();
    for _ in 0..updates {
        seed = next(seed);
        let i = below(seed, n);
        e.put(TREE, &key(i), &v1[i]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    ops("update", updates, t0.elapsed().as_secs_f64());

    let deletes = n.min(5000);
    let t0 = Instant::now();
    for k in 0..deletes as usize {
        e.remove(TREE, &key(k % n as usize)).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    ops("delete", deletes, t0.elapsed().as_secs_f64());

    let t0 = Instant::now();
    for _ in 0..mixed_ops {
        seed = next(seed);
        let roll = below(seed, 100);
        seed = next(seed);
        let i = below(seed, n);
        if roll < 70 {
            e.get(TREE, &key(i)).unwrap();
        } else if roll < 95 {
            e.put(TREE, &key(i), &v1[i]).unwrap();
        } else {
            e.remove(TREE, &key(i)).unwrap();
        }
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    ops("mixed", mixed_ops, t0.elapsed().as_secs_f64());

    let p0 = Instant::now();
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    let persist = p0.elapsed();
    // `13-operations.md` §5: move the live extents down over the space the
    // compaction freed and end the file at them. Dart has nothing to do here:
    // it places segments only when it saves.
    let s0 = Instant::now();
    e.shrink().unwrap();
    let shrink = s0.elapsed();
    e.close(true).unwrap();

    row("persist_ms", format!("{:.1}", persist.as_secs_f64() * 1e3), "ms");
    row("shrink_ms", format!("{:.1}", shrink.as_secs_f64() * 1e3), "ms");
    row("file_bytes", std::fs::metadata(&b.path).map(|m| m.len()).unwrap_or(0).to_string(), "bytes");
    row("storage_model", "file-backed, segments resident".into(), "text");
}

fn main() {
    let n = harness::arg(0, 20_000);
    let mixed_ops = harness::arg(1, 20_000);

    println!("# cryptand cross-language CRUD matrix -- rust");
    println!("# implementation=rust documents={n} mixed_ops={mixed_ops} profile=desktop durability=os");
    println!("# the first pass is discarded; see the module docs for what is and is not held identical");

    let v0: Vec<Vec<u8>> = (0..n).map(|i| cryptand::cve::encode(&doc(i, 0))).collect();
    let v1: Vec<Vec<u8>> = (0..n).map(|i| cryptand::cve::encode(&doc(i, 1))).collect();

    for p in 0..2 {
        unsafe { MEASURING = p == 1 };
        pass(n, mixed_ops, &v0, &v1);
    }
    println!("# done");
}
