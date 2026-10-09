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

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mid = data.first().map_or(0, |&m| m as usize % data.len().max(1));
    let (a, b) = data.split_at(mid);
    let (Some((va, ea)), Some((vb, eb))) = (canon(a), canon(b)) else { return };
    // memcmp order equals the logical order wherever the logical order is strict.
    if let Ok(o @ (Ordering::Less | Ordering::Greater)) = compare::compare_values(&va, &vb) {
        assert_eq!(ea.cmp(&eb), o, "memcmp order disagrees with §8: {va:?} vs {vb:?}");
    }
});
