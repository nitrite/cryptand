//! F-150: dead value-log space must come back (04 §6.8).

mod support;
use support::*;

use cryptand::container::{Durability, Profile};
use cryptand::database::Database;
use cryptand::value::Value;

#[test]
fn f150_overwriting_the_same_values_does_not_grow_the_file() {
    // 100 x (open, overwrite 256 x 4 KiB, commit, close). Before the fix
    // the file grew ~1.9 MB a cycle (56 MB at 30); it plateaued near
    // 30 MB with tiered levels keeping every version; since §5 drops a
    // superseded version at any level (F-150), ~13 MB.
    let (t, mut e) = engine("f150", Profile::Desktop);
    e.close(true).unwrap();
    let path = t.path.clone();
    let mut at_50 = 0;
    for cycle in 0..100u8 {
        let mut d = Database::open(&path, None).unwrap();
        for i in 0..256i64 {
            d.engine.put(16, &Value::NitriteId(i), &vec![cycle; 4096]).unwrap();
        }
        d.commit(Durability::Sync).unwrap();
        d.close().unwrap();
        if cycle == 50 {
            at_50 = std::fs::metadata(&path).unwrap().len();
        }
    }
    let len = std::fs::metadata(&path).unwrap().len();
    let mut d = Database::open(&path, None).unwrap();
    for i in 0..256i64 {
        assert_eq!(d.engine.get(16, &Value::NitriteId(i)).unwrap().unwrap(), vec![99u8; 4096]);
    }
    assert!(len <= at_50 + at_50 / 10, "still growing: {at_50} at cycle 50, {len} at 100");
    assert!(len < 16 << 20, "file {len} bytes for 1 MiB live");
}

#[test]
fn f151_a_cold_point_read_reads_pages_not_the_segment() {
    // Before the fix a page-cache miss read, decrypted and decoded the whole
    // segment extent: 609 pages for one `get` here. Now the head, the
    // filter (~7 pages), the manifest and one descent.
    let (t, mut e) = engine("f151", Profile::Desktop);
    e.close(true).unwrap();
    let path = t.path.clone();
    let mut d = Database::open(&path, None).unwrap();
    for i in 0..20_000i64 {
        d.engine.put(16, &Value::NitriteId(i), &vec![(i % 251) as u8; 100]).unwrap();
    }
    d.commit(Durability::Sync).unwrap();
    d.close().unwrap();
    let mut d = Database::open(&path, None).unwrap();
    for i in [7i64, 12_345, 19_999] {
        let p0 = d.engine.pager.reads();
        assert_eq!(d.engine.get(16, &Value::NitriteId(i)).unwrap().unwrap(), vec![(i % 251) as u8; 100]);
        let n = d.engine.pager.reads() - p0;
        assert!(n <= 32, "a cold get of {i} read {n} pages");
    }
}
