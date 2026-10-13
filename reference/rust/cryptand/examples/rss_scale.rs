//! F-147: writer RSS while building an N-document file, the Rust twin of
//! Dart `tool/rss_scale.dart build` (same document shape, commit per 100k).
//!
//!     cargo run --release --example rss_scale PATH N
//!
//! Run under `/usr/bin/time -l` for max RSS.

use cryptand::container::{Durability, Profile};
use cryptand::database::Database;
use cryptand::engine::Engine;
use cryptand::value::{NumType, Value};

fn doc(i: i64) -> Value {
    let pad = format!("{i:06}");
    let v = |p: &str| Value::Str(format!("{:y<19}", format!("{p}-{pad}-x")));
    let mut f: Vec<(String, Value)> = vec![("_id".into(), Value::NitriteId(1767225600000 * 4194304 + i * 4096 + 1))];
    for (name, p) in [
        ("custAddr1_ln", "addr1"), ("custAddr2_ln", "addr2"), ("custCityName", "city"),
        ("custPostCode", "post"), ("custCountryX", "ctry"), ("custEmailAdr", "mail"),
        ("custPhoneNum", "phon"), ("ordReference", "ordr"), ("ordStatusTxt", "stat"),
        ("ordCurrencyC", "curr"), ("ordNotesText", "note"), ("whseLocation", "whse"),
        ("carrierName_", "carr"), ("trackingNumb", "trak"),
    ] {
        f.push((name.into(), v(p)));
    }
    f.push(("ordTotMinorU".into(), Value::int(NumType::I64, 1299 + i as i128)));
    f.push(("ordTaxMinorU".into(), Value::int(NumType::I64, 216)));
    f.push(("ordShipMinor".into(), Value::int(NumType::I64, 499)));
    f.push(("placedAtUtcM".into(), Value::Timestamp(1767225000000)));
    f.push(("dispatchUtcM".into(), Value::Timestamp(1767225600000)));
    Value::Doc(f)
}

fn main() -> cryptand::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let path = std::path::Path::new(&a[1]);
    let n: i64 = a[2].parse().unwrap();
    let _ = std::fs::remove_file(path);
    let mut db = Database { engine: Engine::create(path, Profile::Desktop)? };
    let mut c = db.collection("c")?;
    for i in 0..n {
        c.insert(&mut db.engine, &doc(i))?;
        if (i + 1) % 100_000 == 0 {
            db.commit(Durability::Sync)?;
            println!("{}", i + 1);
        }
    }
    db.close()?;
    println!("built {n} bytes={}", std::fs::metadata(path)?.len());
    Ok(())
}
