//! F-147: writer RSS while building an N-document file, the Rust twin of
//! Dart `tool/rss_scale.dart build` (same document shape, commit per 100k).
//!
//!     cargo run --release --example rss_scale PATH N
//!     cargo run --release --example rss_scale PATH N read   # 10k uniform + 10k zipf gets, 100k scan, verify
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
        let id = |k: i64| 1767225600000 * 4194304 + k * 4096 + 1;
        let mut s = 0x51ED_C0DEu64;
        let mut rnd = || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            s >> 11
        };
        let mut line = format!("open_ms={open_ms}");
        // Current RSS after each step, from `ps` (std has no getrusage).
        let mark = |step: &str| {
            let pid = std::process::id().to_string();
            let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid]).output();
            let kb = out.ok().and_then(|o| String::from_utf8(o.stdout).ok()?.trim().parse::<u64>().ok()).unwrap_or(0);
            eprintln!("rss_{step}_mb={}", kb >> 10);
        };
        mark("open");
        // Same picks as Dart `tool/scale.dart`: uniform, then zipf by inverse
        // power (ponytail: s~1.2 skew, not an exact Zipf(0.99)).
        for name in ["uniform", "zipf"] {
            let mut us = Vec::with_capacity(10_000);
            for _ in 0..10_000 {
                let u = rnd() as f64 / (1u64 << 53) as f64;
                let k = if name == "zipf" { (n as f64 * u.powi(6)) as i64 % n } else { (u * n as f64) as i64 };
                let t = std::time::Instant::now();
                assert!(c.get(&mut db.engine, id(k))?.is_some());
                us.push(t.elapsed().as_micros());
            }
            us.sort_unstable();
            mark(name);
            line += &format!(" get_{name}_us p50={} p99={} p999={}", us[5000], us[9900], us[9990]);
        }
        let lo = (rnd() % (n.max(100_001) - 100_000) as u64) as i64;
        let enc = |k| cryptand::cke::encode(&Value::NitriteId(id(k)));
        let t = std::time::Instant::now();
        let mut cur = db.engine.scan_cursor(c.tree, Some(&enc(lo)?), Some(&enc(lo + 100_000)?), None, true)?;
        let mut rows = 0;
        while cur.next(&mut db.engine)?.is_some() {
            rows += 1;
        }
        line += &format!(" scan_rows={rows} scan_rows_per_s={:.0}", rows as f64 / t.elapsed().as_secs_f64());
        mark("scan");
        use cryptand::verify::EngineVerify;
        let t = std::time::Instant::now();
        let report = db.engine.verify()?;
        mark("verify");
        println!("{line} verify_ms={} verify_sound={}", t.elapsed().as_millis(), report.ok());
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
