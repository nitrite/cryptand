//! M1.5 query differential: an index scan built by `06-indexes.md` §7's
//! helpers against a brute-force model over the same documents, using
//! `02-value-encoding.md` §8's logical order. `QUERY_SEEDS=N` for a sweep.

mod support;
use support::*;

use std::cmp::Ordering;

use cryptand::compare::compare_values;
use cryptand::container::Profile;
use cryptand::index::{self, Cmp};
use cryptand::catalog::index_type;
use cryptand::database::Indexing;
use cryptand::value::{NumType, Value};

const WIDTHS: [NumType; 6] = [NumType::I8, NumType::I32, NumType::I64, NumType::U64, NumType::F64, NumType::F32];
const WORDS: [&str; 6] = ["", "a", "ab", "abc", "b", "ba"];

fn scalar(r: &mut Rng) -> Value {
    match r.below(10) {
        0 => Value::Null,
        1 => Value::Bool(r.below(2) == 1),
        2 | 3 => Value::Str(WORDS[r.below(6) as usize].into()),
        _ => {
            let n = r.below(11) as i128 - 3; // -3..7: small, so values collide across types
            let w = WIDTHS[r.below(6) as usize];
            match w {
                NumType::U64 => Value::int(w, n.abs()),
                NumType::F64 | NumType::F32 => {
                    Value::Float { w, v: n as f64 + if r.below(3) == 0 { 0.5 } else { 0.0 } }
                }
                _ => Value::int(w, n),
            }
        }
    }
}

fn field(r: &mut Rng) -> Option<Value> {
    match r.below(8) {
        0 => None,
        1 => Some(Value::Array((0..r.below(4)).map(|_| scalar(r)).collect())),
        _ => Some(scalar(r)),
    }
}

/// §3/§5 as a model: the values a document is indexed under.
fn values_of(d: &Value) -> Vec<Value> {
    index::resolve(d, &["v".to_string()]).unwrap_or_else(|| vec![Value::Null])
}

fn run_seed(seed: u64) {
    let mut r = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xC0FFEE);
    let (_t, mut db) = db(&format!("qdiff{seed}"), Profile::Desktop);
    let mut c = db.collection("q").unwrap();
    let idx = db.create_index(&c, &["v"], index_type::NON_UNIQUE, false).unwrap();
    let mut live: Vec<Value> = Vec::new();
    for id in 1..=(20 + r.below(60) as i64) {
        let d = doc(id, field(&mut r).map(|v| vec![("v", v)]).unwrap_or_default());
        c.insert(&mut db.engine, &d).unwrap();
        db.index_document(&idx, &d).unwrap();
        live.push(d);
        if r.below(6) == 0 {
            let gone = live.remove(r.below(live.len() as u64) as usize);
            let gid = match &gone { Value::Doc(f) => match f[0].1 { Value::NitriteId(i) => i, _ => unreachable!() }, _ => unreachable!() };
            db.unindex_document(&idx, &gone).unwrap();
            c.remove(&mut db.engine, gid).unwrap();
        }
    }
    db.engine.flush().unwrap();
    let id_of = |d: &Value| match d { Value::Doc(f) => match f[0].1 { Value::NitriteId(i) => i, _ => 0 }, _ => 0 };

    for q in 0..40 {
        let b = scalar(&mut r);
        let (label, scan, pred): (String, _, Box<dyn Fn(&Value) -> bool>) = match r.below(7) {
            0 if matches!(b, Value::Str(_)) => {
                let Value::Str(s) = &b else { unreachable!() };
                let s = s.clone();
                (format!("starts_with {s:?}"), index::scan_starts_with(&[], &s),
                 Box::new(move |x: &Value| matches!(x, Value::Str(y) if y.starts_with(&s))))
            }
            0 | 1 => {
                let b2 = b.clone();
                let s = if cryptand::compare::is_numeric(&b) { index::scan_prefix_numeric(&[b.clone()]) } else { index::scan_prefix(&[b.clone()]) };
                (format!("eq {b:?}"), s, Box::new(move |x: &Value| compare_values(x, &b2).ok() == Some(Ordering::Equal)))
            }
            k => {
                let op = [Cmp::Gt, Cmp::Ge, Cmp::Lt, Cmp::Le][(k - 2) as usize % 4];
                let b2 = b.clone();
                (format!("{op:?} {b:?}"), index::scan_range(&[], op, &b), Box::new(move |x: &Value| {
                    let o = compare_values(x, &b2).unwrap();
                    match op { Cmp::Gt => o.is_gt(), Cmp::Ge => o.is_ge(), Cmp::Lt => o.is_lt(), Cmp::Le => o.is_le() }
                }))
            }
        };
        let mut got = db.index_scan(&idx, &scan.unwrap()).unwrap();
        got.sort();
        got.dedup();
        let want: Vec<i64> = live.iter().filter(|d| values_of(d).iter().any(|x| pred(x))).map(id_of).collect();
        assert_eq!(got, want, "seed {seed} query {q}: {label}");
    }
}

#[test]
fn an_index_scan_answers_what_a_full_scan_answers() {
    let n: u64 = std::env::var("QUERY_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(50);
    for seed in 0..n {
        run_seed(seed);
    }
}
