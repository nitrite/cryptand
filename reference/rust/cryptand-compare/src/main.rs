//! Cryptand against `fjall`, `redb` and `sled` — the Rust comparison table.
//!
//! `reference/java/.../bench/CompareBench.java` does this for Java against
//! MVStore, RocksDB and PalDB. This is its Rust counterpart, and it follows the
//! same rules, which are the ones `reference/bench/README.md` sets out:
//!
//! * **The same bytes.** Every engine is handed the same already-encoded
//!   document under the same key bytes, so neither encoding nor key layout is
//!   the variable. The values are built before the clock starts.
//! * **The same phase shape.** Create *n*, read, update and delete a fixed
//!   slice, then a sustained 70/25/5 read/update/delete mix — the same phases,
//!   in the same order, from the same pseudo-random sequence.
//! * **One durability barrier per phase.** This is the part that has to be
//!   stated rather than assumed. Cryptand buffers a phase's writes in its
//!   memtable and makes them durable at `commit(Os)`; fjall buffers in its own
//!   memtable and journal and persists at `PersistMode::Buffer`; redb takes one
//!   write transaction for the phase and commits it at the end; sled writes
//!   through its own buffer and `flush()`es at the end. All four therefore pay
//!   one barrier per phase and none per operation. A per-operation barrier
//!   would measure `fsync` in all four and nothing else.
//! * **A read returns a handle, in all four.** `redb`'s `get` returns an
//!   `AccessGuard` over its mapped page, `fjall`'s and `sled`'s return
//!   reference-counted slices of their block caches, and none of the three
//!   copies the value out. Cryptand's `get` does copy -- it returns an owned
//!   `Vec<u8>` -- so this table calls `get_ref`, which is the same resolution
//!   returning a borrow of the resident segment extent. Calling `get` here
//!   would be measuring a whole-document `memcpy` that the other three are not
//!   being asked to do.
//! * **The read phase is `n` operations, not a sample.** It is the row this
//!   comparison turns on and a 5 000-operation phase moved several per cent
//!   between runs of the same binary. Update and delete stay at 5 000 because
//!   updating or deleting every key changes what the next phase is measuring.
//! * **The first pass is discarded.** A cold process measures the process.
//! * **Medians, not means**, taken by the runner.
//!
//! What is *not* equal, and cannot be made equal, is what each engine does for
//! the money. Cryptand maintains a manifest, per-segment filters, liveness
//! statistics and a value-log GC, verifies a CRC-32C per page, and writes a
//! file three other language runtimes can open. redb is a copy-on-write B-tree
//! with full ACID transactions and no background compaction at all. sled and
//! fjall are LSM engines closer in shape to Cryptand. The `on_disk` row is
//! printed for the same reason: an engine that writes less is doing less.

use std::time::Instant;

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::value::{NumType, Value};

const TREE: u32 = 16;
const TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("bench");

fn snowflake(i: u64) -> i64 {
    (1_767_225_600_000i64 * 4_194_304) + (i as i64) * 4096 + 1
}

/// The suite's document: 20 fields, names averaging 12 B, values averaging
/// 20 B. `design/performance-model.md` §1's shape, and the one every density
/// figure in §6 is costed against.
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

/// xorshift64. Identical in the Java, Rust and Dart benchmarks so the operation
/// order is the same sequence everywhere.
fn next(mut s: u64) -> u64 {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    s
}

fn below(seed: u64, n: u64) -> usize {
    ((seed >> 32) % n) as usize
}

#[derive(Default, Clone)]
struct Row {
    create: f64,
    read: f64,
    update: f64,
    delete: f64,
    mixed: f64,
    bytes: u64,
}

fn rate(count: u64, secs: f64) -> f64 {
    count as f64 / secs.max(1e-9)
}

/// Bytes under `path`, whether the engine writes one file or a directory.
fn on_disk(path: &std::path::Path) -> u64 {
    let Ok(md) = std::fs::metadata(path) else { return 0 };
    if md.is_file() {
        return md.len();
    }
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            total += on_disk(&e.path());
        }
    }
    total
}

struct Dir(std::path::PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir()
            .join(format!("cryptand-compare-{tag}-{}-{:?}", std::process::id(), Instant::now()));
        let _ = std::fs::remove_dir_all(&p);
        Dir(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------------------------------------------------------------------------

fn bench_cryptand(n: u64, mixed_ops: u64, keys: &[Vec<u8>], v0: &[Vec<u8>], v1: &[Vec<u8>]) -> Row {
    let d = Dir::new("cryptand");
    std::fs::create_dir_all(&d.0).unwrap();
    let file = d.0.join("db.cff");
    let mut e = Engine::create(&file, Profile::Desktop).unwrap();
    // The engine's key API takes a `Value`; the bytes it produces are exactly
    // the `keys` the other three are handed, so no engine gets a shorter key.
    let key = |i: usize| Value::NitriteId(snowflake(i as u64));
    let _ = keys;
    let mut r = Row::default();

    let t = Instant::now();
    for i in 0..n as usize {
        e.put(TREE, &key(i), &v0[i]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    r.create = rate(n, t.elapsed().as_secs_f64());
    e.compact().unwrap();

    let mut seed = 0x51ED_C0DEu64;
    for _ in 0..2000 {
        seed = next(seed);
        e.get_ref(TREE, &key(below(seed, n))).unwrap();
    }
    let reads = n;
    let t = Instant::now();
    for _ in 0..reads {
        seed = next(seed);
        e.get_ref(TREE, &key(below(seed, n))).unwrap();
    }
    r.read = rate(reads, t.elapsed().as_secs_f64());

    let updates = n.min(5000);
    let t = Instant::now();
    for _ in 0..updates {
        seed = next(seed);
        let i = below(seed, n);
        e.put(TREE, &key(i), &v1[i]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    r.update = rate(updates, t.elapsed().as_secs_f64());

    let deletes = n.min(5000);
    let t = Instant::now();
    for k in 0..deletes as usize {
        e.remove(TREE, &key(k % n as usize)).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    r.delete = rate(deletes, t.elapsed().as_secs_f64());

    let t = Instant::now();
    for _ in 0..mixed_ops {
        seed = next(seed);
        let roll = below(seed, 100);
        seed = next(seed);
        let i = below(seed, n);
        if roll < 70 {
            e.get_ref(TREE, &key(i)).unwrap();
        } else if roll < 95 {
            e.put(TREE, &key(i), &v1[i]).unwrap();
        } else {
            e.remove(TREE, &key(i)).unwrap();
        }
    }
    e.flush().unwrap();
    e.commit(Durability::Os).unwrap();
    r.mixed = rate(mixed_ops, t.elapsed().as_secs_f64());

    e.close(true).unwrap();
    r.bytes = on_disk(&d.0);
    r
}

fn bench_fjall(n: u64, mixed_ops: u64, keys: &[Vec<u8>], v0: &[Vec<u8>], v1: &[Vec<u8>]) -> Row {
    use fjall::{Config, Database, KeyspaceCreateOptions, PersistMode};
    let d = Dir::new("fjall");
    let db = Database::open(Config::new(&d.0)).unwrap();
    let ks = db.keyspace("bench", KeyspaceCreateOptions::default).unwrap();
    let mut r = Row::default();

    let t = Instant::now();
    for i in 0..n as usize {
        ks.insert(&keys[i][..], &v0[i][..]).unwrap();
    }
    db.persist(PersistMode::Buffer).unwrap();
    r.create = rate(n, t.elapsed().as_secs_f64());

    let mut seed = 0x51ED_C0DEu64;
    for _ in 0..2000 {
        seed = next(seed);
        ks.get(&keys[below(seed, n)][..]).unwrap();
    }
    let reads = n;
    let t = Instant::now();
    for _ in 0..reads {
        seed = next(seed);
        ks.get(&keys[below(seed, n)][..]).unwrap();
    }
    r.read = rate(reads, t.elapsed().as_secs_f64());

    let updates = n.min(5000);
    let t = Instant::now();
    for _ in 0..updates {
        seed = next(seed);
        let i = below(seed, n);
        ks.insert(&keys[i][..], &v1[i][..]).unwrap();
    }
    db.persist(PersistMode::Buffer).unwrap();
    r.update = rate(updates, t.elapsed().as_secs_f64());

    let deletes = n.min(5000);
    let t = Instant::now();
    for k in 0..deletes as usize {
        ks.remove(&keys[k % n as usize][..]).unwrap();
    }
    db.persist(PersistMode::Buffer).unwrap();
    r.delete = rate(deletes, t.elapsed().as_secs_f64());

    let t = Instant::now();
    for _ in 0..mixed_ops {
        seed = next(seed);
        let roll = below(seed, 100);
        seed = next(seed);
        let i = below(seed, n);
        if roll < 70 {
            ks.get(&keys[i][..]).unwrap();
        } else if roll < 95 {
            ks.insert(&keys[i][..], &v1[i][..]).unwrap();
        } else {
            ks.remove(&keys[i][..]).unwrap();
        }
    }
    db.persist(PersistMode::Buffer).unwrap();
    r.mixed = rate(mixed_ops, t.elapsed().as_secs_f64());

    drop(ks);
    drop(db);
    r.bytes = on_disk(&d.0);
    r
}

fn bench_redb(n: u64, mixed_ops: u64, keys: &[Vec<u8>], v0: &[Vec<u8>], v1: &[Vec<u8>]) -> Row {
    use redb::{Database, Durability as RDur, ReadableDatabase, ReadableTable};
    let d = Dir::new("redb");
    std::fs::create_dir_all(&d.0).unwrap();
    let file = d.0.join("db.redb");
    let db = Database::create(&file).unwrap();
    let mut r = Row::default();

    // One write transaction per phase, committed at the end: redb's analogue of
    // the memtable-plus-one-barrier shape the other three run in. `None` is the
    // durability level that does not `fsync`, which is what `Durability::Os`
    // and `PersistMode::Buffer` are on the others.
    let phase_write = |f: &mut dyn FnMut(&mut redb::Table<&[u8], &[u8]>)| {
        let mut txn = db.begin_write().unwrap();
        txn.set_durability(RDur::None).unwrap();
        {
            let mut tb = txn.open_table(TABLE).unwrap();
            f(&mut tb);
        }
        txn.commit().unwrap();
    };

    let t = Instant::now();
    phase_write(&mut |tb| {
        for i in 0..n as usize {
            tb.insert(&keys[i][..], &v0[i][..]).unwrap();
        }
    });
    r.create = rate(n, t.elapsed().as_secs_f64());

    let mut seed = 0x51ED_C0DEu64;
    {
        let txn = db.begin_read().unwrap();
        let tb = txn.open_table(TABLE).unwrap();
        for _ in 0..2000 {
            seed = next(seed);
            tb.get(&keys[below(seed, n)][..]).unwrap();
        }
    }
    let reads = n;
    let t = Instant::now();
    {
        let txn = db.begin_read().unwrap();
        let tb = txn.open_table(TABLE).unwrap();
        for _ in 0..reads {
            seed = next(seed);
            tb.get(&keys[below(seed, n)][..]).unwrap();
        }
    }
    r.read = rate(reads, t.elapsed().as_secs_f64());

    let updates = n.min(5000);
    let mut s = seed;
    let t = Instant::now();
    phase_write(&mut |tb| {
        for _ in 0..updates {
            s = next(s);
            let i = below(s, n);
            tb.insert(&keys[i][..], &v1[i][..]).unwrap();
        }
    });
    r.update = rate(updates, t.elapsed().as_secs_f64());
    seed = s;

    let deletes = n.min(5000);
    let t = Instant::now();
    phase_write(&mut |tb| {
        for k in 0..deletes as usize {
            tb.remove(&keys[k % n as usize][..]).unwrap();
        }
    });
    r.delete = rate(deletes, t.elapsed().as_secs_f64());

    let mut s = seed;
    let t = Instant::now();
    phase_write(&mut |tb| {
        for _ in 0..mixed_ops {
            s = next(s);
            let roll = below(s, 100);
            s = next(s);
            let i = below(s, n);
            if roll < 70 {
                tb.get(&keys[i][..]).unwrap();
            } else if roll < 95 {
                tb.insert(&keys[i][..], &v1[i][..]).unwrap();
            } else {
                tb.remove(&keys[i][..]).unwrap();
            }
        }
    });
    r.mixed = rate(mixed_ops, t.elapsed().as_secs_f64());

    drop(db);
    r.bytes = on_disk(&d.0);
    r
}

fn bench_sled(n: u64, mixed_ops: u64, keys: &[Vec<u8>], v0: &[Vec<u8>], v1: &[Vec<u8>]) -> Row {
    let d = Dir::new("sled");
    let db = sled::Config::new().path(&d.0).open().unwrap();
    let mut r = Row::default();

    let t = Instant::now();
    for i in 0..n as usize {
        db.insert(&keys[i][..], &v0[i][..]).unwrap();
    }
    db.flush().unwrap();
    r.create = rate(n, t.elapsed().as_secs_f64());

    let mut seed = 0x51ED_C0DEu64;
    for _ in 0..2000 {
        seed = next(seed);
        db.get(&keys[below(seed, n)][..]).unwrap();
    }
    let reads = n;
    let t = Instant::now();
    for _ in 0..reads {
        seed = next(seed);
        db.get(&keys[below(seed, n)][..]).unwrap();
    }
    r.read = rate(reads, t.elapsed().as_secs_f64());

    let updates = n.min(5000);
    let t = Instant::now();
    for _ in 0..updates {
        seed = next(seed);
        let i = below(seed, n);
        db.insert(&keys[i][..], &v1[i][..]).unwrap();
    }
    db.flush().unwrap();
    r.update = rate(updates, t.elapsed().as_secs_f64());

    let deletes = n.min(5000);
    let t = Instant::now();
    for k in 0..deletes as usize {
        db.remove(&keys[k % n as usize][..]).unwrap();
    }
    db.flush().unwrap();
    r.delete = rate(deletes, t.elapsed().as_secs_f64());

    let t = Instant::now();
    for _ in 0..mixed_ops {
        seed = next(seed);
        let roll = below(seed, 100);
        seed = next(seed);
        let i = below(seed, n);
        if roll < 70 {
            db.get(&keys[i][..]).unwrap();
        } else if roll < 95 {
            db.insert(&keys[i][..], &v1[i][..]).unwrap();
        } else {
            db.remove(&keys[i][..]).unwrap();
        }
    }
    db.flush().unwrap();
    r.mixed = rate(mixed_ops, t.elapsed().as_secs_f64());

    drop(db);
    r.bytes = on_disk(&d.0);
    r
}

fn main() {
    let arg = |i: usize, d: u64| {
        std::env::args().nth(i + 1).and_then(|s| s.parse().ok()).unwrap_or(d)
    };
    let n = arg(0, 20_000);
    let mixed_ops = arg(1, 20_000);

    println!("# cryptand against fjall, redb and sled -- rust");
    println!("# documents={n} mixed_ops={mixed_ops} profile=desktop durability=no-fsync, one barrier per phase");

    let keys: Vec<Vec<u8>> =
        (0..n).map(|i| cryptand::cke::encode(&Value::NitriteId(snowflake(i))).unwrap()).collect();
    let v0: Vec<Vec<u8>> = (0..n).map(|i| cryptand::cve::encode(&doc(i, 0))).collect();
    let v1: Vec<Vec<u8>> = (0..n).map(|i| cryptand::cve::encode(&doc(i, 1))).collect();

    type B = fn(u64, u64, &[Vec<u8>], &[Vec<u8>], &[Vec<u8>]) -> Row;
    let engines: [(&str, B); 4] = [
        ("cryptand", bench_cryptand),
        ("fjall", bench_fjall),
        ("redb", bench_redb),
        ("sled", bench_sled),
    ];

    for (name, f) in engines {
        // Discarded: a cold process measures the process.
        let _ = f(n, mixed_ops, &keys, &v0, &v1);
        let r = f(n, mixed_ops, &keys, &v0, &v1);
        println!("{name}_create={:.0} unit=ops/s", r.create);
        println!("{name}_read={:.0} unit=ops/s", r.read);
        println!("{name}_update={:.0} unit=ops/s", r.update);
        println!("{name}_delete={:.0} unit=ops/s", r.delete);
        println!("{name}_mixed={:.0} unit=ops/s", r.mixed);
        println!("{name}_on_disk={} unit=bytes", r.bytes);
    }
    println!("# done");
}
