//! F-147: writer RSS while building an N-document file, the Rust twin of
//! Dart `tool/rss_scale.dart build` (same document shape, commit per 100k).
//!
//!     cargo run --release --example rss_scale PATH N
//!     cargo run --release --example rss_scale PATH N read   # 10k uniform gets
//!
//!     cargo run --release --example rss_scale PATH N settle # compact+commit+shrink (F-154)
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
    if a.get(3).map(String::as_str) == Some("read") {
        let t = std::time::Instant::now();
        let mut db = Database { engine: Engine::open(path, None)? };
        let open_ms = t.elapsed().as_millis();
        let c = db.collection("c")?;
        let (mut s, mut us) = (0x51ED_C0DEu64, Vec::with_capacity(10_000));
        for _ in 0..10_000 {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let t = std::time::Instant::now();
            let id = 1767225600000 * 4194304 + ((s >> 33) as i64 % n) * 4096 + 1;
            assert!(c.get(&mut db.engine, id)?.is_some());
            us.push(t.elapsed().as_micros());
        }
        us.sort_unstable();
        println!("open_ms={open_ms} get_uniform_us p50={} p99={} p999={}", us[5000], us[9900], us[9990]);
        return Ok(());
    }
    if a.get(3).map(String::as_str) == Some("settle") {
        use cryptand::spaceapi::SpaceApi;
        let mut db = Database { engine: Engine::open(path, None)? };
        db.engine.compact()?;
        db.commit(Durability::Sync)?;
        db.engine.shrink()?;
        db.close()?;
        let b = std::fs::metadata(path)?.len();
        println!("settled bytes={b} space_amp={:.2}", b as f64 / (n as f64 * 516.0));
        return Ok(());
    }
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
