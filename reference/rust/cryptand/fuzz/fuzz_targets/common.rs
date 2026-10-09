//! Shared by `open_file` and `open_encrypted`: an attacker who edits a page
//! recomputes its CRC (14 §9.4), so the input's page checksums are repaired
//! first and the decoders, not the CRC, meet the bytes.

use cryptand::container::{PageHeader, Superblock};
use cryptand::engine::Engine;
use cryptand::verify::EngineVerify;

pub fn repair_crcs(b: &mut [u8]) {
    let ps = b.get(..4096).and_then(|s| Superblock::parse(s).ok()).map_or(4096, |sb| sb.page_size());
    if ps < 512 || ps > 65536 {
        return;
    }
    for p in 2..b.len() / ps {
        let page = &mut b[p * ps..(p + 1) * ps];
        if let Ok(h) = PageHeader::parse(page) {
            let end = PageHeader::checksum_range_end(page, &h);
            if end > 4 && end <= ps {
                let crc = cryptand::hash::crc32c(&page[4..end]);
                page[..4].copy_from_slice(&crc.to_le_bytes());
            }
        }
    }
}

/// Opens read-only, verifies, scans every tree and point-reads a few keys.
/// Any typed error is a pass; a panic, abort, OOM or hang is a crash.
pub fn exercise(data: &[u8], key: Option<&[u8]>) {
    let mut b = data.to_vec();
    repair_crcs(&mut b);
    let path = std::env::temp_dir().join(format!("cryptand-fuzz-{}.cryptand", std::process::id()));
    std::fs::write(&path, &b).unwrap();
    let Ok(mut e) = Engine::open_read_only(&path, key) else { return };
    let _ = e.verify();
    let cat = std::mem::replace(&mut e.catalog, cryptand::catalog::Catalog::new(0, 0, 16));
    let all = cat.all(&mut e.pager);
    e.catalog = cat;
    for (_, d) in all.unwrap_or_default() {
        let rows = e.scan_tree(d.tree_id(), None, None, None, true);
        for (k, _) in rows.unwrap_or_default().iter().take(8) {
            if let Ok(v) = cryptand::cke::decode_all(k) {
                let _ = e.get(d.tree_id(), &v);
            }
        }
    }
}
