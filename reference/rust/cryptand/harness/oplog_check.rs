//! Model checker (PLAN M1.2): replays an op-log (`reference/conformance/oplog/`)
//! against `Engine` and a `BTreeMap` model, comparing every read and the
//! full-scan digest at the end and after every `reopen`.
//!
//! oplog_check FILE.jsonl                      replay one log
//! oplog_check --seeds A..B [gen knobs...]     generate + replay seeds A..B-1
//! oplog_check --shrink FILE.jsonl             print a minimal still-failing log
//! Exit 1 on the first divergence, with the line number and both answers.
use cryptand::cke;
use cryptand::container::{Durability, Profile};
use cryptand::engine::{Engine, Snapshot};
use cryptand::txn::{Isolation, Transaction};
use cryptand::Value;
use serde_json::Value as J;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[allow(dead_code)] // its `main` and knobs; we use the generator and `value_bytes`
#[path = "oplog_gen.rs"]
mod gen;

/// tree → key → (value, expiry)
type Model = BTreeMap<u32, BTreeMap<Vec<u8>, (Vec<u8>, Option<u64>)>>;
const KEY: [u8; 32] = [7; 32];
/// A log that breaks the format's own rules (only a shrinker makes these).
const INVALID: &str = "invalid log";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}
fn cke_bytes(b: &[u8]) -> Vec<u8> {
    cke::encode(&Value::Bytes(b.to_vec())).expect("cke")
}
fn from_cke(k: &[u8]) -> Vec<u8> {
    match cke::decode_all(k).expect("decode key") {
        Value::Bytes(b) => b,
        v => panic!("non-bytes key {v:?}"),
    }
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn short(v: &Option<Vec<u8>>) -> String {
    match v {
        None => "absent".into(),
        Some(b) => format!("{} bytes {}…", b.len(), hexs(&b[..b.len().min(8)])),
    }
}

struct Run {
    path: PathBuf,
    encrypted: bool,
    e: Engine,
    model: Model,
    /// The model as of the last time `visible_seq` reached the newest write:
    /// what a new snapshot sees (`spec/10` §1: a reader takes `visible_seq`).
    committed: Model,
    snaps: HashMap<u64, (Snapshot, Model)>,
    clock: u64,
    trees: u32,
    seen_visible: u64,
}

impl Run {
    fn visible(&self, m: &Model, t: u32, k: &[u8]) -> Option<Vec<u8>> {
        m.get(&t)?.get(k).filter(|(_, x)| x.is_none_or(|x| x > self.clock)).map(|(v, _)| v.clone())
    }

    fn model_scan(&self, m: &Model, t: u32, lo: Option<&[u8]>, hi: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let Some(tree) = m.get(&t) else { return vec![] };
        tree.iter()
            .filter(|(k, _)| lo.is_none_or(|l| k.as_slice() >= l) && hi.is_none_or(|h| k.as_slice() < h))
            .filter(|(_, (_, x))| x.is_none_or(|x| x > self.clock))
            .map(|(k, (v, _))| (k.clone(), v.clone()))
            .collect()
    }

    fn engine_scan(&mut self, t: u32, lo: Option<&[u8]>, hi: Option<&[u8]>, at: Option<&Snapshot>) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let (lo, hi) = (lo.map(cke_bytes), hi.map(cke_bytes));
        let rows = self.e.scan_tree(t, lo.as_deref(), hi.as_deref(), at, true).map_err(|e| format!("scan: {e}"))?;
        Ok(rows.into_iter().map(|(k, v)| (from_cke(&k), v)).collect())
    }

    fn digest_check(&mut self) -> Result<String, String> {
        let (mut de, mut dm) = (Sha256::new(), Sha256::new());
        for t in 1..=self.trees {
            let got = self.engine_scan(t, None, None, None)?;
            let want = self.model_scan(&self.model, t, None, None);
            if got != want {
                return Err(diff_scan(t, &want, &got));
            }
            for (h, rows) in [(&mut de, &got), (&mut dm, &want)] {
                for (k, v) in rows {
                    h.update(t.to_be_bytes());
                    h.update((k.len() as u32).to_be_bytes());
                    h.update(k);
                    h.update((v.len() as u32).to_be_bytes());
                    h.update(v);
                }
            }
        }
        Ok(hexs(&de.finalize()))
    }

    fn apply_write(&mut self, w: &J, txn: Option<&mut Transaction>) -> Result<(), String> {
        let t = w["t"].as_u64().unwrap() as u32;
        let k = unhex(w["k"].as_str().unwrap());
        let key = Value::Bytes(k.clone());
        let tree = self.model.entry(t).or_default();
        match (w["op"].as_str().unwrap(), txn) {
            ("put", txn) => {
                let v = gen::value_bytes(w["v"]["n"].as_u64().unwrap() as usize, w["v"]["s"].as_u64().unwrap());
                let x = w["x"].as_u64();
                tree.insert(k, (v.clone(), x));
                let r = match (txn, x) {
                    (Some(tx), _) => tx.put(t, key, v),
                    (None, Some(x)) => self.e.put_with_expiry(t, &key, &v, x).map(drop),
                    (None, None) => self.e.put(t, &key, &v).map(drop),
                };
                r.map_err(|e| format!("put: {e}"))
            }
            ("del", txn) => {
                tree.remove(&k);
                match txn {
                    Some(tx) => tx.remove(t, key),
                    None => self.e.remove(t, &key).map(drop),
                }
                .map_err(|e| format!("del: {e}"))
            }
            (op, _) => Err(format!("{op} not allowed here")),
        }
    }

    fn step(&mut self, j: &J) -> Result<(), String> {
        let at = |s: &Self| j["at"].as_u64().map(|id| s.snaps.get(&id).cloned().ok_or(INVALID));
        let bound = |f: &str| j[f].as_str().map(unhex);
        match j["op"].as_str().ok_or("no op")? {
            "put" | "del" => self.apply_write(j, None)?,
            "range_del" => {
                let t = j["t"].as_u64().unwrap() as u32;
                let (lo, hi) = (bound("lo").unwrap(), bound("hi").unwrap());
                self.model.entry(t).or_default().retain(|k, _| !(k >= &lo && k < &hi));
                self.e
                    .remove_range(t, &Value::Bytes(lo), &Value::Bytes(hi))
                    .map_err(|e| format!("range_del: {e}"))?;
            }
            "batch" => {
                let mut tx = Transaction::begin(&mut self.e, Isolation::Snapshot);
                for w in j["ops"].as_array().unwrap() {
                    self.apply_write(w, Some(&mut tx))?;
                }
                tx.commit(&mut self.e, Durability::None).map_err(|e| format!("batch commit: {e}"))?;
            }
            "get" => {
                let t = j["t"].as_u64().unwrap() as u32;
                let k = bound("k").unwrap();
                let (want, got) = match at(self).transpose()? {
                    Some((s, m)) => (self.visible(&m, t, &k), self.e.get_at(t, &Value::Bytes(k.clone()), Some(&s))),
                    None => (self.visible(&self.model, t, &k), self.e.get(t, &Value::Bytes(k.clone()))),
                };
                let got = got.map_err(|e| format!("get: {e}"))?;
                if got != want {
                    return Err(format!("get t={t} k={}: model {} engine {}", hexs(&k), short(&want), short(&got)));
                }
            }
            "scan" => {
                let t = j["t"].as_u64().unwrap() as u32;
                let (lo, hi) = (bound("lo"), bound("hi"));
                let (snap, m) = match at(self).transpose()? {
                    Some((s, m)) => (Some(s), m),
                    None => (None, self.model.clone()), // ponytail: clone per scan, fine at test sizes
                };
                let want = self.model_scan(&m, t, lo.as_deref(), hi.as_deref());
                let got = self.engine_scan(t, lo.as_deref(), hi.as_deref(), snap.as_ref())?;
                if got != want {
                    return Err(diff_scan(t, &want, &got));
                }
            }
            "snapshot" => {
                if self.snaps.contains_key(&j["id"].as_u64().unwrap()) {
                    return Err(INVALID.into());
                }
                let s = self.e.snapshot();
                self.snaps.insert(j["id"].as_u64().unwrap(), (s, self.committed.clone()));
            }
            "release" => {
                let (s, _) = self.snaps.remove(&j["id"].as_u64().unwrap()).ok_or(INVALID)?;
                self.e.release(&s);
            }
            "commit" => {
                let d = match j["d"].as_str().unwrap() {
                    "none" => Durability::None,
                    "os" => Durability::Os,
                    "sync" => Durability::Sync,
                    _ => Durability::Full,
                };
                self.e.flush().map_err(|e| format!("flush: {e}"))?;
                self.e.commit(d).map_err(|e| format!("commit: {e}"))?;
            }
            "checkpoint" => {
                self.e.flush().map_err(|e| format!("flush: {e}"))?;
                self.e.commit(Durability::Full).map_err(|e| format!("checkpoint: {e}"))?;
            }
            "compact" => self.e.compact().map_err(|e| format!("compact: {e}"))?,
            "shrink" => drop(self.e.relocate_and_truncate().map_err(|e| format!("shrink: {e}"))?),
            "ttl_advance" => {
                self.clock += j["ms"].as_u64().unwrap();
                self.e.now_ms = self.clock;
            }
            "reopen" => {
                if !self.snaps.is_empty() {
                    return Err(INVALID.into());
                }
                self.e.flush().map_err(|e| format!("reopen flush: {e}"))?;
                self.e.commit(Durability::Sync).map_err(|e| format!("reopen commit: {e}"))?;
                self.e.close(true).map_err(|e| format!("close: {e}"))?;
                let key = self.encrypted.then_some(&KEY[..]);
                self.e = Engine::open(&self.path, key).map_err(|e| format!("open: {e}"))?;
                self.e.now_ms = self.clock;
                self.digest_check()?;
            }
            op => return Err(format!("unknown op {op}")),
        }
        // A flush (explicit, or the memtable filling) publishes every write so far.
        let tip = self.e.next_seq.saturating_sub(1);
        if self.e.visible_seq != self.seen_visible {
            if self.e.visible_seq != tip {
                return Err(format!("visible_seq moved to {} but the newest seq is {tip}", self.e.visible_seq));
            }
            self.seen_visible = self.e.visible_seq;
            self.committed = self.model.clone();
        }
        Ok(())
    }
}

fn diff_scan(t: u32, want: &[(Vec<u8>, Vec<u8>)], got: &[(Vec<u8>, Vec<u8>)]) -> String {
    let i = want.iter().zip(got).position(|(a, b)| a != b).unwrap_or(want.len().min(got.len()));
    let show = |r: Option<&(Vec<u8>, Vec<u8>)>| r.map_or("end".into(), |(k, v)| format!("k={} {}", hexs(k), short(&Some(v.clone()))));
    format!(
        "scan t={t}: model {} rows, engine {} rows; first difference at row {i}: model {} engine {}",
        want.len(),
        got.len(),
        show(want.get(i)),
        show(got.get(i))
    )
}

/// Replays one log. Ok(digest) or Err("line N: …").
fn replay(log: &str, dir: &Path) -> Result<String, String> {
    let mut lines = log.lines();
    let h: J = serde_json::from_str(lines.next().ok_or("empty log")?).map_err(|e| format!("line 1: {e}"))?;
    if h["oplog"] != 1 {
        return Err("line 1: not an oplog v1".into());
    }
    let profile = match h["profile"].as_str().unwrap_or("desktop") {
        "mobile" => Profile::Mobile,
        "tablet" => Profile::Tablet,
        "server" => Profile::Server,
        _ => Profile::Desktop,
    };
    let encrypted = h["encrypted"] == true;
    let path = dir.join(format!("oplog-{}.cff", h["seed"]));
    let _ = std::fs::remove_file(&path);
    let e = if encrypted {
        Engine::create_encrypted(&path, profile, &KEY, 0, 0, 0, 0)
    } else {
        Engine::create(&path, profile)
    }
    .map_err(|e| format!("create: {e}"))?;
    let trees = h["trees"].as_u64().unwrap_or(1) as u32;
    let seen_visible = e.visible_seq;
    let mut r = Run { path: path.clone(), encrypted, e, model: Model::new(), committed: Model::new(), snaps: HashMap::new(), clock: 0, trees, seen_visible };
    let out = (|| {
        for (n, l) in lines.enumerate() {
            let j: J = serde_json::from_str(l).map_err(|e| format!("line {}: {e}", n + 2))?;
            r.step(&j).map_err(|e| format!("line {}: {} — {e}", n + 2, j["op"]))?;
        }
        r.digest_check().map_err(|e| format!("end: {e}"))
    })();
    let _ = r.e.close(true);
    let _ = std::fs::remove_file(&path);
    out
}

/// Greedy delta debugging over the op lines: drop chunks while the log still
/// fails (an invalid log does not count), halving the chunk when none drops;
/// then drop each snapshot id's lines together, and shrink inside batches.
/// Repeats until a whole round removes nothing.
fn shrink(log: &str, dir: &Path) -> String {
    let fails = |ls: &[String]| matches!(replay(&ls.join("\n"), dir), Err(e) if !e.contains(INVALID));
    let mut lines: Vec<String> = log.lines().map(String::from).collect();
    assert!(fails(&lines), "the log does not fail; nothing to shrink");
    loop {
        let start = lines.len() + lines.iter().map(String::len).sum::<usize>();
        let mut chunk = (lines.len() - 1) / 2;
        while chunk >= 1 {
            let mut i = 1;
            let mut dropped = false;
            while i < lines.len() {
                let end = (i + chunk).min(lines.len());
                let trial: Vec<String> = lines[..i].iter().chain(&lines[end..]).cloned().collect();
                if fails(&trial) {
                    lines = trial;
                    dropped = true;
                } else {
                    i = end;
                }
            }
            if !dropped {
                chunk /= 2;
            }
        }
        // A snapshot goes with its release and every read at it.
        let ids: Vec<u64> = lines.iter().filter_map(|l| serde_json::from_str::<J>(l).ok()?["id"].as_u64()).collect();
        for id in ids {
            let uses = |l: &String| {
                let j: J = serde_json::from_str(l).unwrap_or(J::Null);
                j["id"].as_u64() == Some(id) || j["at"].as_u64() == Some(id)
            };
            let trial: Vec<String> = lines.iter().filter(|l| !uses(l)).cloned().collect();
            if trial.len() < lines.len() && fails(&trial) {
                lines = trial;
            }
        }
        // One write at a time out of each batch.
        for i in 1..lines.len() {
            let mut j: J = serde_json::from_str(&lines[i]).unwrap();
            if j["op"] != "batch" {
                continue;
            }
            let mut k = 0;
            while k < j["ops"].as_array().unwrap().len() && j["ops"].as_array().unwrap().len() > 1 {
                let mut t = j.clone();
                t["ops"].as_array_mut().unwrap().remove(k);
                let mut trial = lines.clone();
                trial[i] = t.to_string();
                if fails(&trial) {
                    lines = trial;
                    j = t;
                } else {
                    k += 1;
                }
            }
        }
        if lines.len() + lines.iter().map(String::len).sum::<usize>() == start {
            break;
        }
    }
    lines.join("\n") + "\n"
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = std::env::temp_dir().join(format!("oplog_check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let code = if args.first().map(String::as_str) == Some("--shrink") {
        let log = std::fs::read_to_string(&args[1]).expect("read log");
        let small = shrink(&log, &dir);
        print!("{small}");
        eprintln!("{} → {} lines; {}", log.lines().count(), small.lines().count(), replay(&small, &dir).unwrap_err());
        0
    } else if args.first().map(String::as_str) == Some("--seeds") {
        let (a, b) = args.get(1).and_then(|s| s.split_once("..")).expect("--seeds A..B");
        let (a, b): (u64, u64) = (a.parse().unwrap(), b.parse().unwrap());
        let mut code = 0;
        for seed in a..b {
            let mut knobs = vec!["--seed".to_string(), seed.to_string()];
            knobs.extend_from_slice(&args[2..]);
            let log = gen::generate(&knobs).unwrap_or_else(|e| panic!("{e}"));
            if let Err(e) = replay(&log, &dir) {
                println!("seed {seed} FAIL {e}\n  reproduce: oplog_gen {}", knobs.join(" "));
                code = 1;
                break;
            }
        }
        if code == 0 {
            println!("seeds {a}..{b}: 0 divergences");
        }
        code
    } else {
        let mut code = 0;
        for f in &args {
            match replay(&std::fs::read_to_string(f).expect("read log"), &dir) {
                Ok(d) => println!("{f}: ok digest {d}"),
                Err(e) => {
                    println!("{f}: FAIL {e}");
                    code = 1;
                }
            }
        }
        code
    };
    let _ = std::fs::remove_dir_all(&dir);
    std::process::exit(code);
}
