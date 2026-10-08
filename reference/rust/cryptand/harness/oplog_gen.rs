//! Seeded op-log generator, format in `reference/conformance/oplog/README.md`.
//!
//! cargo run -p cryptand --features harness --bin oplog_gen -- --seed 7 --ops 10000
//! Knobs: --profile desktop|mobile|... --encrypted --trees N --keys N
//!        --skew 0..1 (0 uniform) --big 0..1 (value-log fraction) --prefix N (shared key prefix bytes)
//!        --mix put=40,del=8,range_del=1,batch=4,get=25,scan=6,snapshot=2,release=2,commit=3,
//!              reopen=1,compact=1,shrink=1,checkpoint=1,ttl_advance=2
//!        --maint W   weight W for each maintenance op (gc, encrypt, decrypt,
//!                    rotate, backup, erase; 0 by default, so seeds are unchanged)
use std::fmt::Write as _;
use std::io::Write as _;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1) // ponytail: modulo bias, irrelevant at these ranges
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Bytes of a value as the format defines them; checkers in other languages must match.
#[allow(dead_code)]
pub fn value_bytes(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed);
    let mut v = Vec::with_capacity(n + 8);
    while v.len() < n {
        v.extend_from_slice(&r.next().to_le_bytes());
    }
    v.truncate(n);
    v
}

const OPS: [&str; 20] = [
    "put", "del", "range_del", "batch", "get", "scan", "snapshot", "release", "commit", "reopen",
    "compact", "shrink", "checkpoint", "ttl_advance", "gc", "encrypt", "decrypt", "rotate", "backup", "erase",
];
// The maintenance ops (M2.2) come last at weight 0: a pick over these weights
// is the pick over the first 14, so every existing seed generates as before.
const MIX: [u32; 20] = [40, 8, 1, 4, 25, 6, 2, 2, 3, 1, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0];

struct Cfg {
    seed: u64,
    ops: usize,
    profile: String,
    encrypted: bool,
    trees: u32,
    keys: u64,
    skew: f64,
    big: f64,
    prefix: usize,
    mix: [u32; 20],
}

struct Gen {
    c: Cfg,
    r: Rng,
    clock: u64,
    live: Vec<u32>,
    next_snap: u32,
}

impl Gen {
    fn new(c: Cfg) -> Gen {
        Gen { r: Rng(c.seed), c, clock: 0, live: Vec::new(), next_snap: 1 }
    }

    /// Variable-length decimal keys after a shared prefix, so "1" < "10" < "2"
    /// and one key is a prefix of another. ponytail: power-law skew, not true zipf.
    fn key(&mut self) -> String {
        let u = self.r.unit().powf(1.0 + 8.0 * self.c.skew);
        let idx = ((u * self.c.keys as f64) as u64).min(self.c.keys - 1);
        let mut k = vec![0xABu8; self.c.prefix];
        k.extend_from_slice(idx.to_string().as_bytes());
        hex(&k)
    }

    fn value(&mut self) -> String {
        let p = self.r.unit();
        let n = if p < self.c.big / 50.0 {
            300 * 1024 + self.r.below(1024) // past every profile's blob_threshold
        } else if p < self.c.big {
            4096 + self.r.below(4096) // past every profile's vlog_min
        } else {
            self.r.below(257) // includes the empty value
        };
        // < 2^53: exact as a JSON number in every parser (Dart, JS, Jackson doubles)
        format!(r#"{{"n":{},"s":{}}}"#, n, self.r.next() >> 11)
    }

    fn tree(&mut self) -> u32 {
        1 + self.r.below(self.c.trees as u64) as u32
    }

    fn put(&mut self, ttl: bool) -> String {
        let (t, k, v) = (self.tree(), self.key(), self.value());
        if ttl && self.r.below(10) == 0 {
            let x = self.clock + 1 + self.r.below(5000);
            format!(r#"{{"op":"put","t":{t},"k":"{k}","v":{v},"x":{x}}}"#)
        } else {
            format!(r#"{{"op":"put","t":{t},"k":"{k}","v":{v}}}"#)
        }
    }

    fn del(&mut self) -> String {
        let (t, k) = (self.tree(), self.key());
        format!(r#"{{"op":"del","t":{t},"k":"{k}"}}"#)
    }

    fn at(&mut self) -> String {
        if !self.live.is_empty() && self.r.below(3) == 0 {
            let id = self.live[self.r.below(self.live.len() as u64) as usize];
            format!(r#","at":{id}"#)
        } else {
            String::new()
        }
    }

    /// Two distinct keys, ordered.
    fn bounds(&mut self) -> Option<(String, String)> {
        let (a, b) = (self.key(), self.key());
        // hex of bytes compares like the bytes: same alphabet order, two chars per byte
        match a.cmp(&b) {
            std::cmp::Ordering::Less => Some((a, b)),
            std::cmp::Ordering::Greater => Some((b, a)),
            std::cmp::Ordering::Equal => None,
        }
    }

    fn line(&mut self) -> String {
        let total: u32 = self.c.mix.iter().sum();
        let mut pick = self.r.below(total as u64) as u32;
        let mut i = 0;
        while pick >= self.c.mix[i] {
            pick -= self.c.mix[i];
            i += 1;
        }
        match OPS[i] {
            "put" => self.put(true),
            "del" => self.del(),
            "range_del" => match self.bounds() {
                Some((lo, hi)) => {
                    let t = self.tree();
                    format!(r#"{{"op":"range_del","t":{t},"lo":"{lo}","hi":"{hi}"}}"#)
                }
                None => self.del(),
            },
            "batch" => {
                let n = 1 + self.r.below(16);
                let ops: Vec<String> = (0..n)
                    .map(|_| if self.r.below(4) == 0 { self.del() } else { self.put(false) })
                    .collect();
                format!(r#"{{"op":"batch","ops":[{}]}}"#, ops.join(","))
            }
            "get" => {
                let (t, k, at) = (self.tree(), self.key(), self.at());
                format!(r#"{{"op":"get","t":{t},"k":"{k}"{at}}}"#)
            }
            "scan" => {
                let t = self.tree();
                let mut s = format!(r#"{{"op":"scan","t":{t}"#);
                if let Some((lo, hi)) = self.bounds() {
                    match self.r.below(4) {
                        0 => write!(s, r#","lo":"{lo}""#).unwrap(),
                        1 => write!(s, r#","hi":"{hi}""#).unwrap(),
                        2 => write!(s, r#","lo":"{lo}","hi":"{hi}""#).unwrap(),
                        _ => {} // full scan
                    }
                }
                s + &self.at() + "}"
            }
            "snapshot" if self.live.len() < 4 => {
                let id = self.next_snap;
                self.next_snap += 1;
                self.live.push(id);
                format!(r#"{{"op":"snapshot","id":{id}}}"#)
            }
            "release" if !self.live.is_empty() => {
                let id = self.live.swap_remove(self.r.below(self.live.len() as u64) as usize);
                format!(r#"{{"op":"release","id":{id}}}"#)
            }
            "snapshot" | "release" => self.put(true),
            "commit" => {
                let d = ["none", "os", "sync", "full"][self.r.below(4) as usize];
                format!(r#"{{"op":"commit","d":"{d}"}}"#)
            }
            "reopen" => {
                // A snapshot does not survive close: release them first.
                let mut s: String = self
                    .live
                    .drain(..)
                    .map(|id| format!("{{\"op\":\"release\",\"id\":{id}}}\n"))
                    .collect();
                s.push_str(r#"{"op":"reopen"}"#);
                s
            }
            "ttl_advance" => {
                let ms = 1 + self.r.below(2000);
                self.clock += ms;
                format!(r#"{{"op":"ttl_advance","ms":{ms}}}"#)
            }
            op => format!(r#"{{"op":"{op}"}}"#), // compact, shrink, checkpoint, maintenance
        }
    }

    fn write(&mut self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        let c = &self.c;
        writeln!(
            out,
            r#"{{"oplog":1,"seed":{},"profile":"{}","encrypted":{},"trees":{},"keys":{},"skew":{},"big":{},"prefix":{}}}"#,
            c.seed, c.profile, c.encrypted, c.trees, c.keys, c.skew, c.big, c.prefix
        )?;
        for _ in 0..self.c.ops {
            let l = self.line();
            writeln!(out, "{l}")?;
        }
        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse(args: &[String]) -> Result<Cfg, String> {
    let mut c = Cfg {
        seed: 1,
        ops: 1000,
        profile: "desktop".into(),
        encrypted: false,
        trees: 2,
        keys: 1000,
        skew: 0.5,
        big: 0.05,
        prefix: 0,
        mix: MIX,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        let bad = |e: &dyn std::fmt::Display| format!("{a}: {e}");
        match a.as_str() {
            "--seed" => c.seed = val()?.parse().map_err(|e| bad(&e))?,
            "--ops" => c.ops = val()?.parse().map_err(|e| bad(&e))?,
            "--profile" => c.profile = val()?,
            "--encrypted" => c.encrypted = true,
            "--trees" => c.trees = val()?.parse().map_err(|e| bad(&e))?,
            "--keys" => c.keys = val()?.parse().map_err(|e| bad(&e))?,
            "--skew" => c.skew = val()?.parse().map_err(|e| bad(&e))?,
            "--big" => c.big = val()?.parse().map_err(|e| bad(&e))?,
            "--prefix" => c.prefix = val()?.parse().map_err(|e| bad(&e))?,
            "--maint" => {
                let w = val()?.parse().map_err(|e| bad(&e))?;
                c.mix[14..].fill(w);
            }
            "--mix" => {
                c.mix = [0; 20];
                for kv in val()?.split(',') {
                    let (k, w) = kv.split_once('=').ok_or(bad(&"want op=weight"))?;
                    let i = OPS.iter().position(|o| *o == k).ok_or(bad(&format!("unknown op {k}")))?;
                    c.mix[i] = w.parse().map_err(|e| bad(&e))?;
                }
            }
            _ => return Err(format!("unknown argument {a}")),
        }
    }
    if c.trees == 0 || c.keys == 0 || c.mix.iter().sum::<u32>() == 0 {
        return Err("--trees, --keys and the mix total must be > 0".into());
    }
    if !(0.0..=1.0).contains(&c.skew) || !(0.0..=1.0).contains(&c.big) {
        return Err("--skew and --big are in 0..=1".into());
    }
    Ok(c)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let c = parse(&args).unwrap_or_else(|e| {
        eprintln!("oplog_gen: {e}");
        std::process::exit(2)
    });
    let out = std::io::stdout();
    let mut w = std::io::BufWriter::new(out.lock());
    Gen::new(c).write(&mut w).and_then(|_| w.flush()).expect("write stdout");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen(args: &str) -> String {
        let a: Vec<String> = args.split_whitespace().map(String::from).collect();
        let mut out = Vec::new();
        Gen::new(parse(&a).unwrap()).write(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn deterministic_and_seed_sensitive() {
        assert_eq!(gen("--seed 9 --ops 500"), gen("--seed 9 --ops 500"));
        assert_ne!(gen("--seed 9 --ops 500"), gen("--seed 10 --ops 500"));
    }

    #[test]
    fn every_op_appears_and_lines_are_well_formed() {
        let log = gen("--seed 3 --ops 20000 --big 0.2 --prefix 3 --maint 1");
        let mut lines = log.lines();
        let h: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(h["oplog"], 1);
        let mut seen = std::collections::HashSet::new();
        let (mut live, mut clock) = (std::collections::HashSet::new(), 0u64);
        for l in lines {
            let j: serde_json::Value = serde_json::from_str(l).unwrap();
            let op = j["op"].as_str().unwrap().to_string();
            match op.as_str() {
                "range_del" => assert!(j["lo"].as_str() < j["hi"].as_str()),
                "scan" => {
                    if let (Some(lo), Some(hi)) = (j["lo"].as_str(), j["hi"].as_str()) {
                        assert!(lo < hi);
                    }
                }
                "snapshot" => assert!(live.insert(j["id"].as_u64().unwrap())),
                "release" => assert!(live.remove(&j["id"].as_u64().unwrap())),
                "reopen" => assert!(live.is_empty(), "reopen with a live snapshot"),
                "ttl_advance" => clock += j["ms"].as_u64().unwrap(),
                "batch" => assert!(j["ops"].as_array().unwrap().iter().all(|w| w.get("x").is_none())),
                "put" => {
                    if let Some(x) = j["x"].as_u64() {
                        assert!(x > clock, "expiry already in the past");
                    }
                    assert!(j["k"].as_str().unwrap().starts_with("ababab"));
                    assert!(j["v"]["s"].as_u64().unwrap() < 1 << 53, "seed not exact in JSON");
                }
                _ => {}
            }
            if let Some(at) = j["at"].as_u64() {
                assert!(live.contains(&at), "read at a released snapshot");
            }
            seen.insert(op);
        }
        for op in OPS {
            assert!(seen.contains(op), "{op} never generated");
        }
    }

    #[test]
    fn value_bytes_are_the_specified_stream() {
        // SplitMix64(0) first output, little-endian.
        assert_eq!(value_bytes(8, 0), 0xE220_A839_7B1D_CDAFu64.to_le_bytes());
        assert_eq!(value_bytes(3, 0), [0xAF, 0xCD, 0x1D]);
        assert!(value_bytes(0, 5).is_empty());
    }

    #[test]
    fn rejects_bad_knobs() {
        for a in ["--skew 2", "--trees 0", "--mix put=0", "--mix nope=1", "--seed"] {
            let a: Vec<String> = a.split_whitespace().map(String::from).collect();
            assert!(parse(&a).is_err(), "{a:?}");
        }
    }
}

/// One log as a string, from command-line style knobs (used by `oplog_check --seeds`).
pub fn generate(args: &[String]) -> Result<String, String> {
    let mut out = Vec::new();
    Gen::new(parse(args)?).write(&mut out).map_err(|e| e.to_string())?;
    Ok(String::from_utf8(out).expect("utf8"))
}
