//! Temporary: a long read loop, for sampling the point-read path.
mod harness;
use std::time::Instant;
use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::value::{NumType, Value};
const TREE: u32 = 16;
fn snowflake(i: u64) -> i64 { (1_767_225_600_000i64 * 4_194_304) + (i as i64) * 4096 + 1 }
fn doc(i: u64, rev: u64) -> Value {
    let pad = format!("{i:0>6}");
    let v = |p: &str| { let mut s = format!("{p}-{pad}-{}", rev % 10); while s.len() < 19 { s.push('y'); } Value::Str(s) };
    Value::Doc(vec![
        ("_id".into(), Value::NitriteId(snowflake(i))),
        ("custAddr1_ln".into(), v("addr1")), ("custAddr2_ln".into(), v("addr2")),
        ("custCityName".into(), v("city")), ("custPostCode".into(), v("post")),
        ("custCountryX".into(), v("ctry")), ("custEmailAdr".into(), v("mail")),
        ("custPhoneNum".into(), v("phon")), ("ordReference".into(), v("ordr")),
        ("ordStatusTxt".into(), v("stat")), ("ordCurrencyC".into(), v("curr")),
        ("ordNotesText".into(), v("note")), ("whseLocation".into(), v("whse")),
        ("carrierName_".into(), v("carr")), ("trackingNumb".into(), v("trak")),
        ("ordTotMinorU".into(), Value::int(NumType::IntVar, 1299 + i as i128)),
        ("ordTaxMinorU".into(), Value::int(NumType::IntVar, 216)),
        ("ordShipMinor".into(), Value::int(NumType::IntVar, 499)),
        ("placedAtUtcM".into(), Value::Timestamp(1_767_225_000_000)),
        ("dispatchUtcM".into(), Value::Timestamp(1_767_225_600_000)),
    ])
}
fn next(mut s: u64) -> u64 { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s }
fn below(seed: u64, n: u64) -> usize { ((seed >> 32) % n) as usize }
fn main() {
    let n: u64 = harness::arg(0, 20_000);
    let secs: u64 = harness::arg(1, 10);
    let b = harness::Bench::new("readprof");
    let mut e = Engine::create(&b.path, Profile::Desktop).unwrap();
    let key = |i: usize| Value::NitriteId(snowflake(i as u64));
    let v0: Vec<Vec<u8>> = (0..n).map(|i| cryptand::cve::encode(&doc(i, 0))).collect();
    for i in 0..n as usize { e.put(TREE, &key(i), &v0[i]).unwrap(); }
    e.flush().unwrap(); e.commit(Durability::Os).unwrap(); e.compact().unwrap();
    if std::env::var("CFF_SHAPE").is_ok() {
        for r in e.all_refs().unwrap() {
            let seg = e.segment(&r).unwrap();
            let mut page = seg.header.root_page;
            let mut h = 0;
            let mut fan = Vec::new();
            loop {
                let node = seg.node(page).unwrap();
                fan.push(node.cell_count);
                h += 1;
                if node.is_leaf { break }
                page = node.child_at(node.cell_count / 2).unwrap().0;
            }
            eprintln!("seg {} level {} pages {} entries {} height {h} fanout {fan:?}",
                r.segment_id, r.level, r.pages, seg.header.entry_count);
        }
    }
    let phase = std::env::args().nth(3).unwrap_or_else(|| "read".into());
    let mut seed = 0x51ED_C0DEu64;
    let t0 = Instant::now(); let mut count = 0u64;
    while t0.elapsed().as_secs() < secs {
        for _ in 0..10_000 {
            seed = next(seed);
            let i = below(seed, n);
            match phase.as_str() {
                "update" => { e.put(TREE, &key(i), &v0[i]).unwrap(); }
                "mixed" => {
                    let roll = below(next(seed), 100);
                    if roll < 70 { e.get(TREE, &key(i)).unwrap(); }
                    else if roll < 95 { e.put(TREE, &key(i), &v0[i]).unwrap(); }
                    else { e.remove(TREE, &key(i)).unwrap(); }
                }
                _ => { e.get_ref(TREE, &key(i)).unwrap(); }
            }
            count += 1;
        }
    }
    println!("{phase}_ops_per_s={:.0}", count as f64 / t0.elapsed().as_secs_f64());
}
