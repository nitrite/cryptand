//! PLAN 6.8 / performance-model P2: sustained uniform-random overwrites over a
//! dataset much larger than RAM; device bytes written per logical byte.
//!
//! `p2 ENGINE PATH N VALUE_BYTES MULT` loads N keys, then N*MULT uniform-random
//! overwrites, one barrier (no fsync) every 100k ops. Device bytes come from
//! the kernel's per-process counter (Darwin `ri_diskio_byteswritten`, Linux
//! `/proc/self/io` write_bytes), not the file size. ENGINE: cryptand|fjall|rocksdb.

use std::time::Instant;

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::value::Value;

const TREE: u32 = 16;
const BARRIER: u64 = 100_000;

#[cfg(target_os = "macos")]
fn device_written() -> u64 {
    let mut ri: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: `ri` is a valid, writable rusage_info_v2 and RUSAGE_INFO_V2 names that layout.
    let rc = unsafe {
        libc::proc_pid_rusage(
            std::process::id() as i32,
            libc::RUSAGE_INFO_V2,
            &mut ri as *mut _ as *mut libc::rusage_info_t,
        )
    };
    assert_eq!(rc, 0, "proc_pid_rusage");
    ri.ri_diskio_byteswritten
}

#[cfg(not(target_os = "macos"))]
fn device_written() -> u64 {
    let s = std::fs::read_to_string("/proc/self/io").unwrap();
    s.lines().find_map(|l| l.strip_prefix("write_bytes: ")).unwrap().trim().parse().unwrap()
}

fn next(mut s: u64) -> u64 {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    s
}

fn key(i: u64) -> Vec<u8> {
    cryptand::cke::encode(&Value::NitriteId((1_767_225_600_000i64 * 4_194_304) + (i as i64) * 4096 + 1)).unwrap()
}

/// Incompressible bytes, different per (key, revision).
fn value(i: u64, rev: u64, len: usize, buf: &mut Vec<u8>) {
    buf.clear();
    let mut s = (i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ rev.wrapping_mul(0xD1B5_4A32_D192_ED03)) | 1;
    while buf.len() < len {
        s = next(s);
        buf.extend_from_slice(&s.to_le_bytes());
    }
    buf.truncate(len);
}

trait Kv {
    fn put(&mut self, k: &[u8], i: u64, v: &[u8]);
    fn barrier(&mut self);
}

struct C(Engine);
impl Kv for C {
    fn put(&mut self, _k: &[u8], i: u64, v: &[u8]) {
        let k = Value::NitriteId((1_767_225_600_000i64 * 4_194_304) + (i as i64) * 4096 + 1);
        self.0.put(TREE, &k, v).unwrap();
    }
    fn barrier(&mut self) {
        self.0.flush().unwrap();
        self.0.commit(Durability::Os).unwrap();
    }
}

struct F(fjall::Database, fjall::Keyspace);
impl Kv for F {
    fn put(&mut self, k: &[u8], _i: u64, v: &[u8]) {
        self.1.insert(k, v).unwrap();
    }
    fn barrier(&mut self) {
        self.0.persist(fjall::PersistMode::Buffer).unwrap();
    }
}

struct R(rocksdb::DB);
impl Kv for R {
    fn put(&mut self, k: &[u8], _i: u64, v: &[u8]) {
        self.0.put(k, v).unwrap();
    }
    fn barrier(&mut self) {
        self.0.flush_wal(false).unwrap();
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (engine, path) = (a[1].as_str(), std::path::Path::new(&a[2]));
    let n: u64 = a[3].parse().unwrap();
    let vlen: usize = a[4].parse().unwrap();
    let mult: u64 = a[5].parse().unwrap();

    let mut db: Box<dyn Kv> = match engine {
        "cryptand" => {
            std::fs::create_dir_all(path).unwrap();
            Box::new(C(Engine::create(&path.join("db.cff"), Profile::Desktop).unwrap()))
        }
        "fjall" => {
            let db = fjall::Database::open(fjall::Config::new(path)).unwrap();
            let ks = db.keyspace("p2", fjall::KeyspaceCreateOptions::default).unwrap();
            Box::new(F(db, ks))
        }
        "rocksdb" => {
            let mut o = rocksdb::Options::default();
            o.create_if_missing(true);
            Box::new(R(rocksdb::DB::open(&o, path).unwrap()))
        }
        e => panic!("unknown engine {e}"),
    };

    println!("# p2 engine={engine} n={n} value_bytes={vlen} overwrites={}", n * mult);
    let dev0 = device_written();
    let t = Instant::now();
    let mut buf = Vec::with_capacity(vlen);
    let mut logical = 0u64;
    let report = |phase: &str, ops: u64, logical: u64, t: &Instant| {
        let dev = device_written() - dev0;
        println!(
            "phase={phase} ops={ops} logical={logical} device={dev} wa={:.3} secs={:.0}",
            dev as f64 / logical.max(1) as f64,
            t.elapsed().as_secs_f64()
        );
    };

    for i in 0..n {
        let k = key(i);
        value(i, 0, vlen, &mut buf);
        db.put(&k, i, &buf);
        logical += (k.len() + vlen) as u64;
        if (i + 1) % BARRIER == 0 {
            db.barrier();
        }
        if (i + 1) % (n / 20).max(1) == 0 {
            report("load", i + 1, logical, &t);
        }
    }
    db.barrier();
    report("load", n, logical, &t);
    let load_logical = logical;
    let load_dev = device_written() - dev0;

    let total = n * mult;
    let mut seed = 0x51ED_C0DEu64;
    for op in 0..total {
        seed = next(seed);
        let i = (seed >> 32) % n;
        let k = key(i);
        value(i, op + 1, vlen, &mut buf);
        db.put(&k, i, &buf);
        logical += (k.len() + vlen) as u64;
        if (op + 1) % BARRIER == 0 {
            db.barrier();
        }
        if (op + 1) % (total / 60).max(1) == 0 {
            report("overwrite", op + 1, logical, &t);
        }
    }
    db.barrier();
    drop(db);
    report("final", n + total, logical, &t);
    let dev = device_written() - dev0;
    println!(
        "{engine}_wa_steady={:.3} unit=ratio",
        (dev - load_dev) as f64 / (logical - load_logical).max(1) as f64
    );
    println!("# done");
}
