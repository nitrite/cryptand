#![no_main]
use cryptand::{cke, compare};
use std::cmp::Ordering;

fn canon(b: &[u8]) -> Option<(cryptand::Value, Vec<u8>)> {
    let v = cke::decode_all(b).ok()?;
    let e = cke::encode(&v).ok()?;
    let v2 = cke::decode_all(&e).expect("re-encoded key decodes");
    assert_eq!(cke::encode(&v2).unwrap(), e, "CKE decode∘encode is not the identity");
    Some((v2, e))
}

/// 03's opening clauses: §8 order, clause-2 ties broken by type code (the CKE
/// bytes), recursively inside arrays (clause 3). `None` where §8 is unordered.
fn refined(a: &cryptand::Value, b: &cryptand::Value) -> Option<Ordering> {
    use cryptand::Value::Array;
    if let (Array(x), Array(y)) = (a, b) {
        for (p, q) in x.iter().zip(y) {
            match refined(p, q)? {
                Ordering::Equal => continue,
                o => return Some(o),
            }
        }
        return Some(x.len().cmp(&y.len()));
    }
    match compare::compare_values(a, b).ok()? {
        Ordering::Equal => Some(cke::encode(a).ok()?.cmp(&cke::encode(b).ok()?)),
        o => Some(o),
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mid = data.first().map_or(0, |&m| m as usize % data.len().max(1));
    let (a, b) = data.split_at(mid);
    let (Some((va, ea)), Some((vb, eb))) = (canon(a), canon(b)) else { return };
    // F-120: memcmp order is exactly 03's refined order, not §8's alone.
    if let Some(o) = refined(&va, &vb) {
        assert_eq!(ea.cmp(&eb), o, "memcmp order disagrees with 03 §1: {va:?} vs {vb:?}");
    }
});
