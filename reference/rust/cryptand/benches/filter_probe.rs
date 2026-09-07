//! What `04-segments.md` §2.4's filter probe costs, with the payload decoded
//! once per segment against once per probe.
//!
//! `12-profiles.md` §12 costs a probe as "exactly one 64-byte block". Decoding
//! the whole filter payload on every probe is not that, and it is what the Rust
//! implementation did until the `Segment::filter_cache` existed — while Dart
//! and Java both already cached it.
//!
//! The end-to-end `ops_bench` at 20 000 documents shows the fix as roughly 5 %
//! on `point_read_us_p50`, which understates it badly: at that size a segment's
//! filter is two or three 64-byte blocks, so the copy being removed is a couple
//! of hundred bytes. The cost is O(filter size), so this measures it across
//! sizes, which is the shape of the claim rather than one number from it.
//!
//! `cargo run --release --bin filter_probe`

use cryptand::cke;
use cryptand::filter::user_key_prefix;
use cryptand::segment::{internal_key, op, value_kind, SegEntry, Segment, SegmentBuilder};
use cryptand::value::Value;
use std::time::Instant;

const T: u32 = 16;
const PAGE: usize = 4096;
const PROBES: usize = 200_000;

fn segment_with(n: i64) -> Segment {
    let mut b = SegmentBuilder::new(PAGE, 1, 0, 0, 10).unwrap();
    for i in 0..n {
        let c = cke::encode(&Value::NitriteId(i)).unwrap();
        b.add(SegEntry::new(
            internal_key(T, &c, i as u64 + 1, op::PUT),
            value_kind::INLINE,
            b"v".to_vec(),
        ))
        .unwrap();
    }
    Segment::open(b.build().unwrap(), PAGE).unwrap()
}

fn main() {
    println!(
        "# §2.4 filter probe, {PROBES} probes per row. `decoded_per_probe` is the\n\
         # counter; the two µs columns are observations of this machine."
    );
    println!(
        "{:>9} | {:>12} | {:>14} | {:>14} | {:>8}",
        "keys", "filter bytes", "per probe (ns)", "cached (ns)", "ratio"
    );
    println!("{}", "-".repeat(72));

    for &n in &[1_000i64, 10_000, 100_000, 500_000] {
        let seg = segment_with(n);
        let f = seg.filter().unwrap().expect("the segment has a filter");
        let bytes = f.blocks.len();
        let keys: Vec<Vec<u8>> = (0..1000i64)
            .map(|i| user_key_prefix(T, &cke::encode(&Value::NitriteId(i)).unwrap()))
            .collect();

        // Uncached: decode the payload on every probe, as the engine did.
        let t0 = Instant::now();
        let mut sink = 0u64;
        for i in 0..PROBES {
            let k = &keys[i % keys.len()];
            if let Ok(Some(f)) = seg.filter() {
                sink += f.may_contain(k) as u64;
            }
        }
        let uncached = t0.elapsed().as_nanos() as f64 / PROBES as f64;

        // Cached: `may_contain`, which decodes once.
        let seg2 = segment_with(n);
        let t1 = Instant::now();
        for i in 0..PROBES {
            sink += seg2.may_contain(&keys[i % keys.len()]) as u64;
        }
        let cached = t1.elapsed().as_nanos() as f64 / PROBES as f64;
        let parses = seg2.filter_parses.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(parses, 1, "the cached path decoded {parses} times");
        std::hint::black_box(sink);

        println!(
            "{:>9} | {:>12} | {:>14.1} | {:>14.1} | {:>7.1}x",
            n,
            bytes,
            uncached,
            cached,
            uncached / cached
        );
    }
    println!(
        "\n`decoded_per_probe` is 1 for every cached row and is asserted, not printed:\n\
         the ratio is a property of this machine, the parse count is a property of\n\
         the code (`design/performance-model.md` §8)."
    );
}
