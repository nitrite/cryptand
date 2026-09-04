//! Shared fixtures. Not a test module of its own.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use cryptand::container::Profile;
use cryptand::database::Database;
use cryptand::engine::Engine;
use cryptand::value::{NumType, Value};

pub fn vectors_dir() -> PathBuf {
    // tests/ -> cryptand/ -> rust/ -> reference/
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("conformance")
}

pub fn read_vector(rel: &str) -> serde_json::Value {
    let p = vectors_dir().join("vectors").join(rel);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_str(&s).unwrap()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub struct TempDb {
    pub path: PathBuf,
}

impl TempDb {
    pub fn new(tag: &str) -> TempDb {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "cryptand-test-{tag}-{}-{}.cryptand",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&p);
        TempDb { path: p }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let mut lock = self.path.as_os_str().to_os_string();
        lock.push("-lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

/// An engine over a real file, at the profile given.
pub fn engine(tag: &str, profile: Profile) -> (TempDb, Engine) {
    let t = TempDb::new(tag);
    let e = Engine::create(&t.path, profile).unwrap();
    (t, e)
}

pub fn db(tag: &str, profile: Profile) -> (TempDb, Database) {
    let t = TempDb::new(tag);
    let d = Database::create(&t.path, profile).unwrap();
    (t, d)
}

pub fn doc(id: i64, fields: Vec<(&str, Value)>) -> Value {
    let mut f: Vec<(String, Value)> = vec![("_id".into(), Value::NitriteId(id))];
    for (k, v) in fields {
        f.push((k.to_string(), v));
    }
    Value::Doc(f)
}

pub fn i32v(v: i32) -> Value {
    Value::int(NumType::I32, v as i128)
}

pub fn str_value(s: &str) -> Value {
    Value::Str(s.to_string())
}

/// A deterministic PRNG, so a failing test is reproducible.
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A padded value of roughly `n` bytes, so the value-log threshold can be
/// crossed deliberately.
pub fn payload(n: usize, seed: u8) -> Vec<u8> {
    cryptand::cve::encode(&Value::Bytes(vec![seed; n]))
}
