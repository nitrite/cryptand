//! **The blocked-Bloom false-positive rate**, measured rather than predicted.
//!
//! `04-segments.md` §2.4 records the correction this bench exists to check: an
//! earlier draft printed the *classic* Bloom figures for the same bits per key,
//! and blocking costs roughly 7x that. "Raising `filter_bits_per_key` recovers
//! less than it looks like it should — because `k` is clamped at 16 and a
//! fuller block hurts more than more probes help."
//!
//! Run: `cargo run --release --bin filter_fpr [keys]`

#[path = "harness.rs"]
mod harness;
use harness::*;

use cryptand::cke;
use cryptand::filter::{block_count_for, probes_for, user_key_prefix, BlockedBloom};
use cryptand::hash::{cfh64, crc32c};
use cryptand::value::Value;

fn keys_of(shape: &str, n: u64, present: bool) -> Vec<Vec<u8>> {
    let base: i64 = if present { 0 } else { 1 << 40 };
    let mut rng = Rng::new(if present { 1 } else { 2 });
    (0..n)
        .map(|i| {
            let v = match shape {
                // Snowflake ids: a timestamp prefix and a sequence suffix.
                "snowflake" => Value::NitriteId(base + 1_700_000_000_000 * 4096 + i as i64),
                "dense" => Value::NitriteId(base + i as i64),
                "sparse" => Value::NitriteId(base + rng.next() as i64),
                "prefixed" => Value::Str(format!("org.dizitart.no2.entity.Employee#{}", base + i as i64)),
                _ => Value::Array(vec![
                    Value::Str(format!("country-{}", i % 200)),
                    Value::NitriteId(base + i as i64),
                ]),
            };
            user_key_prefix(17, &cke::encode(&v).unwrap())
        })
        .collect()
}

/// The negative control §2.4.1 argues for: CRC-32C is affine, so **any pair of
/// evaluations over the same key carries 32 bits of entropy, not 64**.
fn crc_pair(key: &[u8]) -> u64 {
    let a = crc32c(key) as u64;
    let mut salted = vec![0x5Au8];
    salted.extend_from_slice(key);
    let b = crc32c(&salted) as u64;
    (a << 32) | b
}

fn main() {
    let n = arg(0, 200_000);
    let probes = n * 10;

    println!("Measured false-positive rate, {n} keys, {probes} absent probes\n");
    println!("{:<16} {:>8} {:>8} {:>8} {:>8}", "shape", "10 bits", "12 bits", "16 bits", "24 bits");
    for shape in ["snowflake", "dense", "sparse", "prefixed", "compound"] {
        let present = keys_of(shape, n, true);
        let absent = keys_of(shape, probes, false);
        let mut cells = Vec::new();
        for bits in [10u32, 12, 16, 24] {
            let f = BlockedBloom::build(&present, bits, present.len() as u64);
            let hits = absent.iter().filter(|k| f.may_contain(k)).count();
            cells.push(format!("{:.3} %", hits as f64 * 100.0 / absent.len() as f64));
        }
        println!("{shape:<16} {:>8} {:>8} {:>8} {:>8}", cells[0], cells[1], cells[2], cells[3]);
    }

    println!("\n§2.4's defaults: 16 bits above the last level (~0.33 %), 10 at it (~1.7 %).");
    println!("Derived probes: 10 bits -> {}, 12 -> {}, 14 -> {}, 16 -> {}",
        probes_for(10), probes_for(12), probes_for(14), probes_for(16));
    println!("block_count: 32 keys at 16 bits -> {}, 33 -> {}, 1000 -> {}",
        block_count_for(32, 16), block_count_for(33, 16), block_count_for(1000, 16));

    // Blocking is the cause of the rate, not hash quality. §2.4 isolates it by
    // running the same keys through a classic Bloom filter with the same hash:
    // "classic landed at 0.051 % against a 0.046 % prediction, blocked at
    // 0.331 %."
    {
        let present = keys_of("dense", n, true);
        let absent = keys_of("dense", probes, false);
        for bits in [10u32, 16] {
            let m = (n * bits as u64).max(1);
            let k = probes_for(bits);
            let mut classic = vec![0u8; (m / 8 + 1) as usize];
            let set = |f: &mut Vec<u8>, key: &[u8]| {
                let h = cfh64(key);
                let (h1, h2) = ((h & 0xFFFF_FFFF) as u64, ((h >> 32) | 1) as u64);
                for i in 0..k as u64 {
                    let bit = h1.wrapping_add(i.wrapping_mul(h2)) % m;
                    f[(bit / 8) as usize] |= 1 << (bit % 8);
                }
            };
            let test = |f: &[u8], key: &[u8]| {
                let h = cfh64(key);
                let (h1, h2) = ((h & 0xFFFF_FFFF) as u64, ((h >> 32) | 1) as u64);
                (0..k as u64).all(|i| {
                    let bit = h1.wrapping_add(i.wrapping_mul(h2)) % m;
                    f[(bit / 8) as usize] & (1 << (bit % 8)) != 0
                })
            };
            for key in &present {
                set(&mut classic, key);
            }
            let hits = absent.iter().filter(|key| test(&classic, key)).count();
            let blocked = BlockedBloom::build(&present, bits, present.len() as u64);
            let bhits = absent.iter().filter(|key| blocked.may_contain(key)).count();
            let predicted = (1.0 - (-(k as f64) / bits as f64).exp()).powi(k as i32) * 100.0;
            row(
                &format!("{bits} bits, same hash and same k = {k}"),
                format!(
                    "classic {:.3} % (predicts {predicted:.3} %), blocked {:.3} % ({:.1}x)",
                    hits as f64 * 100.0 / absent.len() as f64,
                    bhits as f64 * 100.0 / absent.len() as f64,
                    bhits as f64 / hits.max(1) as f64
                ),
            );
        }
    }

    // §2.4.1's argument for replacing CRC-32C, reproduced.
    //
    // **The key set is part of this control.** Sequential ids differ in ~22
    // bits, which is inside the burst length CRC-32 is designed to detect, so
    // they produce zero collisions for *either* function and the control cannot
    // fail. Random 64-bit ids spread the differences over the whole width,
    // which is where CRC's affinity — "any pair of CRC-32C evaluations over the
    // same key therefore carries 32 bits of entropy, not 64" — shows up.
    let n64 = 4_000_000u64;
    let mut crc_seen = std::collections::HashSet::with_capacity(n64 as usize);
    let mut cfh_seen = std::collections::HashSet::with_capacity(n64 as usize);
    let mut crc_collisions = 0u64;
    let mut cfh_collisions = 0u64;
    let mut rng = Rng::new(0xBEEF);
    for _ in 0..n64 {
        let k = user_key_prefix(17, &cke::encode(&Value::NitriteId(rng.next() as i64)).unwrap());
        if !crc_seen.insert(crc_pair(&k)) {
            crc_collisions += 1;
        }
        if !cfh_seen.insert(cfh64(&k)) {
            cfh_collisions += 1;
        }
    }
    let predicted = (n64 as f64).powi(2) / 2f64.powi(33);
    println!(
        "\n§2.4.1's negative control over {n64} random keys:\n  \
         CRC-32C pair: {crc_collisions} collisions (n^2 / 2^33 predicts {predicted:.0})\n  \
         CFH-64:       {cfh_collisions} collisions"
    );
}
