#![no_main]
use cryptand::segment::Segment;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut b = data.to_vec();
    b.resize(b.len().div_ceil(4096).max(1) * 4096, 0);
    let Ok(seg) = Segment::open(b, 4096) else { return };
    let _ = seg.verify_checksums();
    let _ = seg.filter();
    let _ = seg.range_deletes();
    for r in seg.iter().take(10_000) {
        if r.is_err() {
            break;
        }
    }
    let _ = seg.lookup(b"k", None);
    let _ = seg.seek(b"k");
});
