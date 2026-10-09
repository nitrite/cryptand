#![no_main]
use cryptand::container::PageHeader;
use cryptand::segment::Segment;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut b = data.to_vec();
    b.resize(b.len().div_ceil(4096).max(1) * 4096, 0);
    // An attacker recomputes CRCs (14 §9.4), so the decoders meet the bytes.
    for page in b.chunks_mut(4096) {
        if let Ok(h) = PageHeader::parse(page) {
            let end = PageHeader::checksum_range_end(page, &h);
            if end > 4 && end <= page.len() {
                let crc = cryptand::hash::crc32c(&page[4..end]);
                page[..4].copy_from_slice(&crc.to_le_bytes());
            }
        }
    }
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
