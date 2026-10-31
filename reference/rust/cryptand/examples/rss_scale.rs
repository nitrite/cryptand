//! F-147: writer RSS while building an N-document file, the Rust twin of
//! Dart `tool/rss_scale.dart build` (same document shape, commit per 100k).
//!
//!     cargo run --release --example rss_scale PATH N
//!     cargo run --release --example rss_scale PATH N read   # 10k uniform + 10k zipf gets, 100k scan, verify
//!
//!     cargo run --release --example rss_scale PATH N settle # compact+commit+shrink (F-154)
//!     cargo run --release --example rss_scale PATH N settle compact|shrink  # one phase (F-174)
//!
//!     cargo run --release --example rss_scale PATH N index  # 6.5: unique + compound index build, probes, analyze, verify
//!     cargo run --release --example rss_scale PATH N spatial  # 6.5: R-tree build, near/nearestK vs brute force, verify
//!     cargo run --release --example rss_scale PATH N vector   # 6.5: 128-d Vamana build, recall@10 vs brute force, verify
//!     cargo run --release --example rss_scale PATH N patho [WORKLOAD]  # 6.6: pathological workloads, one file each
//!
//! Run under `/usr/bin/time -l` for max RSS. `CRYPTAND_ENC=1` makes every
//! mode use an encrypted file (fixed raw key, kdf 0: Argon2id excluded).

/// F-202: `CRYPTAND_HWM=1` counts live heap bytes and prints a backtrace each
/// time the high-water mark passes another 16 MB, naming a burst that heap
/// snapshots minutes apart miss. Off, it is one relaxed load per allocation.
mod hwm {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering::Relaxed};
    pub static ON: AtomicBool = AtomicBool::new(false);
    // Signed: memory allocated before `ON` may be freed after it.
    static LIVE: AtomicIsize = AtomicIsize::new(0);
    static MARK: AtomicIsize = AtomicIsize::new(0);
    thread_local!(static IN: Cell<bool> = const { Cell::new(false) });
    pub struct Counting;
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            if ON.load(Relaxed) {
                let live = LIVE.fetch_add(l.size() as isize, Relaxed) + l.size() as isize;
                if live > MARK.load(Relaxed) + (16 << 20) && !IN.with(|f| f.replace(true)) {
                    MARK.store(live, Relaxed);
                    eprintln!("HWM {} MB\n{}", live >> 20, std::backtrace::Backtrace::force_capture());
                    IN.with(|f| f.set(false));
                }
            }
            unsafe { System.alloc(l) }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            if ON.load(Relaxed) {
                LIVE.fetch_sub(l.size() as isize, Relaxed);
            }
            unsafe { System.dealloc(p, l) }
        }
    }
}
#[global_allocator]
static ALLOC: hwm::Counting = hwm::Counting;

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
    hwm::ON.store(std::env::var_os("CRYPTAND_HWM").is_some(), std::sync::atomic::Ordering::Relaxed);
    let path = std::path::Path::new(&a[1]);
    let n: i64 = a[2].parse().unwrap();
    // ponytail: fixed bench key, never a real secret.
    let key = std::env::var_os("CRYPTAND_ENC").map(|_| [7u8; 32]);
    let key = key.as_ref().map(|k| &k[..]);
    if a.get(3).map(String::as_str) == Some("read") {
        let t = std::time::Instant::now();
        let mut db = Database { engine: Engine::open(path, key)? };
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
        // `settle compact` / `settle shrink`: one phase, so `time -l` peaks per phase.
        let only = a.get(4).map(String::as_str);
        let mut db = Database { engine: Engine::open(path, key)? };
        if only != Some("shrink") {
            db.engine.compact()?;
            db.commit(Durability::Sync)?;
        }
        if only != Some("compact") {
            db.engine.shrink()?;
        }
        db.close()?;
        let b = std::fs::metadata(path)?.len();
        println!("settled bytes={b} space_amp={:.2}", b as f64 / (n as f64 * 516.0));
        return Ok(());
    }
    if a.get(3).map(String::as_str) == Some("index") {
        return index_rung(path, n);
    }
    if a.get(3).map(String::as_str) == Some("spatial") {
        return spatial_rung(path, n);
    }
    if a.get(3).map(String::as_str) == Some("vector") {
        return vector_rung(path, n);
    }
    if a.get(3).map(String::as_str) == Some("patho") {
        return patho_rung(path, n, a.get(4).map(String::as_str));
    }
    let _ = std::fs::remove_file(path);
    // CRYPTAND_PROFILE=mobile: the profile the file is created with; reads
    // take it from the file.
    let profile = match std::env::var("CRYPTAND_PROFILE").as_deref() {
        Ok("mobile") => Profile::Mobile,
        _ => Profile::Desktop,
    };
    let mut db = Database { engine: match key {
        Some(k) => Engine::create_encrypted(path, profile, k, 0, 0, 0, 0)?,
        None => Engine::create(path, profile)?,
    } };
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

/// PLAN 6.5: a unique index on `ordReference` and a compound one on
/// (`custCityName`, `ordTotMinorU`) with 1000 cities, maintained per insert.
fn index_rung(path: &std::path::Path, n: i64) -> cryptand::Result<()> {
    use cryptand::catalog::index_type;
    use cryptand::database::Indexing;
    use cryptand::index;
    let rss = || {
        let pid = std::process::id().to_string();
        let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid]).output();
        out.ok().and_then(|o| String::from_utf8(o.stdout).ok()?.trim().parse::<u64>().ok()).unwrap_or(0) >> 10
    };
    let city = |i: i64| Value::Str(format!("city-{:03}", i % 1000));
    let _ = std::fs::remove_file(path);
    let mut db = Database { engine: Engine::create(path, Profile::Desktop)? };
    let mut c = db.collection("c")?;
    let uq = db.create_index(&c, &["ordReference"], index_type::UNIQUE, false)?;
    let cx = db.create_index(&c, &["custCityName", "ordTotMinorU"], index_type::NON_UNIQUE, false)?;
    let t = std::time::Instant::now();
    for i in 0..n {
        let Value::Doc(mut f) = doc(i) else { unreachable!() };
        f.iter_mut().find(|(k, _)| k == "custCityName").unwrap().1 = city(i);
        let d = Value::Doc(f);
        c.insert(&mut db.engine, &d)?;
        db.index_document(&uq, &d)?;
        db.index_document(&cx, &d)?;
        if (i + 1) % 100_000 == 0 {
            // F-184: timestamps and events per commit, to line up with 1 s RSS samples.
            let (t0, r0) = (t.elapsed().as_secs_f64(), rss());
            db.engine.events.clear();
            db.commit(Durability::Sync)?;
            let (mut fl, mut cp, mut cb) = (0, 0, 0u64);
            for e in &db.engine.events {
                match e {
                    cryptand::engine::StoreEvent::Flushed { .. } => fl += 1,
                    cryptand::engine::StoreEvent::Compacted { bytes, .. } => (cp, cb) = (cp + 1, cb + bytes),
                    _ => {}
                }
            }
            eprintln!(
                "{} t={t0:.1} commit_ms={} rss_before={r0} rss_mb={} cache_mb={} flushes={fl} compactions={cp} compacted_mb={}",
                i + 1,
                ((t.elapsed().as_secs_f64() - t0) * 1000.0) as u64,
                rss(),
                db.engine.page_cache_resident_bytes() >> 20,
                cb >> 20
            );
        }
    }
    db.commit(Durability::Sync)?;
    let mut line = format!("built={n} build_s={} bytes={} rss_build_mb={}", t.elapsed().as_secs(), std::fs::metadata(path)?.len(), rss());
    // F-186: CRYPTAND_DRAIN=1 runs the compaction backlog out before probing (Java's background thread does).
    if std::env::var("CRYPTAND_DRAIN").is_ok() {
        db.engine.drain_compaction()?;
        db.commit(Durability::Sync)?;
    }
    let mut s = 0x51ED_C0DEu64;
    let mut us = Vec::with_capacity(10_000);
    let segs0 = cryptand::engine::SCAN_SEGMENTS.load(std::sync::atomic::Ordering::Relaxed);
    for _ in 0..10_000 {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let k = ((s >> 11) % n as u64) as i64;
        let Some(v) = doc(k).field("ordReference").cloned() else { unreachable!() };
        let t = std::time::Instant::now();
        assert_eq!(db.index_scan(&uq, &index::scan_prefix(&[v])?)?.len(), 1);
        us.push(t.elapsed().as_micros());
    }
    // CRYPTAND_PROBE_SECS: keep probing that long so `sample PID` can attach.
    if let Some(secs) = std::env::var("CRYPTAND_PROBE_SECS").ok().and_then(|v| v.parse::<u64>().ok()) {
        eprintln!("probing pid={}", std::process::id());
        let t = std::time::Instant::now();
        while t.elapsed().as_secs() < secs {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let Some(v) = doc(((s >> 11) % n as u64) as i64).field("ordReference").cloned() else { unreachable!() };
            assert_eq!(db.index_scan(&uq, &index::scan_prefix(&[v])?)?.len(), 1);
        }
    }
    // F-186: segments that can hold a key of the unique tree, by level / group / trees spanned.
    {
        let tr = |k: &[u8]| if k.len() >= 4 { u32::from_be_bytes([k[0], k[1], k[2], k[3]]) } else { 0 };
        let mut m = std::collections::BTreeMap::new();
        for r in db.engine.all_refs()? {
            if tr(&r.max_key) < uq.tree || tr(&r.min_key) > uq.tree { continue; }
            let e = m.entry((r.level, r.group, tr(&r.min_key), tr(&r.max_key))).or_insert((0u32, 0u64));
            e.0 += 1;
            e.1 += r.entries;
        }
        for ((l, g, a, b), (c, e)) in m { eprintln!("segs level={l} group={g} trees={a}..{b} count={c} entries={e}"); }
    }
    us.sort_unstable();
    let segs = cryptand::engine::SCAN_SEGMENTS.load(std::sync::atomic::Ordering::Relaxed) - segs0;
    line += &format!(" unique_us p50={} p99={} segs_per_probe={}", us[5000], us[9900], segs as f64 / 10_000.0);
    let t = std::time::Instant::now();
    let hits = db.index_scan(&cx, &index::scan_prefix(&[city(7)])?)?.len();
    line += &format!(" compound_rows={hits} compound_ms={} rss_probe_mb={}", t.elapsed().as_millis(), rss());
    let t = std::time::Instant::now();
    let st = db.analyze(&cx)?;
    line += &format!(" analyze_ms={} rss_analyze_mb={} entries={} distinct={} nulls={} buckets={}", t.elapsed().as_millis(), rss(), st.entries, st.distinct_estimate, st.null_count, st.histogram.len());
    use cryptand::verify::EngineVerify;
    let t = std::time::Instant::now();
    let rep = db.engine.verify()?;
    let ok = rep.ok();
    for f in rep.findings.iter().take(5) {
        eprintln!("verify {:?}: {}", f.class, f.what);
    }
    println!("{line} verify_ms={} verify_sound={ok} rss_verify_mb={}", t.elapsed().as_millis(), rss());
    db.close()
}

fn rss_mb() -> u64 {
    let pid = std::process::id().to_string();
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid]).output();
    out.ok().and_then(|o| String::from_utf8(o.stdout).ok()?.trim().parse::<u64>().ok()).unwrap_or(0) >> 10
}

/// PLAN 6.5 spatial, as Java `RssScale.xy`: point of document i in [0, 1000)^2.
fn xy(i: i64) -> (f64, f64) {
    let mut z = (i as u64).wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0x51EDC0DE);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    ((z >> 40) as f64 * 1000.0 / (1u64 << 24) as f64, (z & 0xFFFFFF) as f64 * 1000.0 / (1u64 << 24) as f64)
}

fn point(x: f64, y: f64) -> Vec<u8> {
    cryptand::wkb::encode(&cryptand::wkb::Geometry::Point(Some(cryptand::wkb::Coord::xy(x, y)))).unwrap()
}

/// PLAN 6.5, as Java `spatialRung`: a spatial index on point field `loc`;
/// near and nearestK checked against brute force.
fn spatial_rung(path: &std::path::Path, n: i64) -> cryptand::Result<()> {
    let _ = std::fs::remove_file(path);
    let mut db = Database::create(path, Profile::Desktop)?;
    let mut c = db.collection("c")?;
    let sp = db.create_spatial_index(&c, "loc", 2, None)?;
    let t = std::time::Instant::now();
    for i in 0..n {
        let Value::Doc(mut f) = doc(i) else { unreachable!() };
        let (x, y) = xy(i);
        f.push(("loc".into(), Value::Geometry(point(x, y))));
        c.insert(&mut db.engine, &Value::Doc(f))?;
        if (i + 1) % 100_000 == 0 {
            db.commit(Durability::Os)?;
            eprintln!("{} t={} rss_mb={}", i + 1, t.elapsed().as_secs(), rss_mb());
        }
    }
    db.commit(Durability::Os)?;
    let mut line = format!("built={n} build_s={} bytes={} rss_build_mb={}", t.elapsed().as_secs(), std::fs::metadata(path)?.len(), rss_mb());
    let mut s = 0x51ED_C0DEu64;
    let (mut us, mut kus, mut rows) = (Vec::new(), Vec::new(), 0usize);
    for k in 0..1000 {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let (x, y) = xy(((s >> 11) % n as u64) as i64);
        let g = std::time::Instant::now();
        let hits = db.with_spatial(&sp, |ix, e| ix.near(e, &c, x, y, 1.0))?.len();
        us.push(g.elapsed().as_micros());
        assert!(hits >= 1, "near probe {k}");
        rows += hits;
        let g = std::time::Instant::now();
        assert_eq!(db.with_spatial(&sp, |ix, e| ix.nearest_k(e, &c, x, y, 10))?.len(), 10.min(n as usize), "knn probe {k}");
        kus.push(g.elapsed().as_micros());
    }
    us.sort_unstable();
    kus.sort_unstable();
    line += &format!(" near_us p50={} p99={} near_rows={rows} knn10_us p50={} p99={}", us[500], us[990], kus[500], kus[990]);
    let (qx, qy) = (500.5, 499.5);
    let mut brute = 0;
    let mut best = vec![f64::MAX; 10];
    for i in 0..n {
        let (x, y) = xy(i);
        let d = (x - qx).hypot(y - qy);
        if d <= 1.0 {
            brute += 1;
        }
        if d < best[9] {
            best[9] = d;
            best.sort_by(f64::total_cmp);
        }
    }
    let got = db.with_spatial(&sp, |ix, e| ix.near(e, &c, qx, qy, 1.0))?.len();
    let knn = db.with_spatial(&sp, |ix, e| ix.nearest_k(e, &c, qx, qy, 10))?;
    let kth = best[(10.min(n as usize)) - 1];
    let ring = db.with_spatial(&sp, |ix, e| ix.near(e, &c, qx, qy, kth))?;
    let knn_ok = knn.len() == 10.min(n as usize) && knn.iter().all(|id| ring.contains(id));
    line += &format!(" near_rows_q={got} brute_near={brute} knn_ok={knn_ok} rss_probe_mb={}", rss_mb());
    assert!(got == brute && knn_ok, "brute force");
    let g = std::time::Instant::now();
    use cryptand::verify::EngineVerify;
    let sound = db.engine.verify()?.findings.is_empty();
    println!("{line} verify_ms={} verify_sound={sound} rss_verify_mb={}", g.elapsed().as_millis(), rss_mb());
    db.close()
}

fn unit(x: u64) -> f64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
}

/// PLAN 6.5 vectors, as Java `RssScale.vec`: 128-d around one of 1000 centres.
fn vec128(i: i64) -> Vec<f32> {
    let c = (i % 1000) as u64;
    (0..128u64)
        .map(|k| (unit(c * 128 + k) + 0.15 * (unit(((i + 1) as u64).wrapping_mul(0x2545F4914F6CDD1D).wrapping_add(k)) - 0.5)) as f32)
        .collect()
}

/// PLAN 6.5, as Java `vectorRung`: a 128-d l2 vector index; 100 searches,
/// recall@10 against brute force.
fn vector_rung(path: &std::path::Path, n: i64) -> cryptand::Result<()> {
    let _ = std::fs::remove_file(path);
    let mut db = Database::create(path, Profile::Desktop)?;
    let mut c = db.collection("c")?;
    let vx = db.create_vector_index(&c, "emb", 128, "l2", 1024)?;
    let t = std::time::Instant::now();
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        let Value::Doc(mut f) = doc(i) else { unreachable!() };
        if let Some(Value::NitriteId(id)) = f.iter().find(|(k, _)| k == "_id").map(|(_, v)| v) {
            ids.push(*id);
        }
        f.push(("emb".into(), Value::VectorF32(vec128(i))));
        c.insert(&mut db.engine, &Value::Doc(f))?;
        if (i + 1) % 100_000 == 0 {
            db.commit(Durability::Os)?;
            eprintln!("{} t={} rss_mb={}", i + 1, t.elapsed().as_secs(), rss_mb());
        } else if (i + 1) % 10_000 == 0 {
            eprintln!("{} t={}", i + 1, t.elapsed().as_secs());
        }
    }
    db.commit(Durability::Os)?;
    let mut line = format!("built={n} build_s={} bytes={} rss_build_mb={}", t.elapsed().as_secs(), std::fs::metadata(path)?.len(), rss_mb());
    let queries = 100usize;
    let q: Vec<Vec<f32>> = (0..queries).map(|k| vec128(n + 7919 * k as i64)).collect();
    let mut us = Vec::new();
    let mut got = Vec::new();
    for qk in &q {
        let g = std::time::Instant::now();
        let hits = db.with_vector(&vx, |ix, e| ix.search(e, qk, 10, None))?;
        us.push(g.elapsed().as_micros());
        got.push(hits.into_iter().map(|h| h.0).collect::<std::collections::HashSet<i64>>());
    }
    us.sort_unstable();
    let mut best: Vec<Vec<(f64, i64)>> = vec![Vec::new(); queries];
    for i in 0..n {
        let v = vec128(i);
        for k in 0..queries {
            let d = cryptand::vector::distance_f64(cryptand::vector::Metric::L2, &q[k], &v);
            let b = &mut best[k];
            if b.len() < 10 || d < b[9].0 {
                b.push((d, ids[i as usize]));
                b.sort_by(|x, y| x.0.total_cmp(&y.0));
                b.truncate(10);
            }
        }
    }
    let hit: usize = (0..queries).map(|k| best[k].iter().filter(|(_, id)| got[k].contains(id)).count()).sum();
    let fallbacks = db.with_vector(&vx, |ix, _| Ok(ix.fallbacks))?;
    line += &format!(
        " search_us p50={} p99={} recall10={:.3} fallbacks={fallbacks} rss_probe_mb={}",
        us[queries / 2],
        us[queries * 99 / 100],
        hit as f64 / (queries * 10) as f64,
        rss_mb()
    );
    let g = std::time::Instant::now();
    use cryptand::verify::EngineVerify;
    let sound = db.engine.verify()?.findings.is_empty();
    println!("{line} verify_ms={} verify_sound={sound} rss_verify_mb={}", g.elapsed().as_millis(), rss_mb());
    db.close()
}

/// PLAN 6.6: each workload builds its own file `PATH.<name>`, checks what it
/// wrote after a reopen, verifies, and prints one line. N scales the key
/// workloads; the shape ones use the PLAN's fixed counts.
fn patho_rung(path: &std::path::Path, n: i64, only: Option<&str>) -> cryptand::Result<()> {
    use cryptand::verify::EngineVerify;
    const T: u32 = 16;
    let id = |i: i64| Value::NitriteId(i);
    let pre = |i: i64| Value::Str(format!("{}{i:012}", "shared/prefix/".repeat(16)));
    let val = |i: i64| vec![(i % 251) as u8; 100];
    let all = ["mono", "prefix", "bigdoc", "fields", "colls", "tombstone", "rangedel", "ttl"];
    for w in all.iter().filter(|w| only.is_none_or(|o| o == **w)) {
        let p = path.with_extension(w);
        let _ = std::fs::remove_file(&p);
        let mut db = Database::create(&p, Profile::Desktop)?;
        let t = std::time::Instant::now();
        let commit_every = |db: &mut Database, i: i64| -> cryptand::Result<()> {
            if (i + 1) % 100_000 == 0 { db.commit(Durability::Sync)?; }
            Ok(())
        };
        let mut extra = String::new();
        match *w {
            "mono" | "tombstone" => {
                for i in 0..n { db.engine.put(T, &id(i), &val(i))?; commit_every(&mut db, i)?; }
                if *w == "tombstone" {
                    for i in 0..n { db.engine.remove(T, &id(i))?; commit_every(&mut db, i)?; }
                    db.commit(Durability::Sync)?;
                    extra += &format!(" bytes_deleted={}", std::fs::metadata(&p)?.len());
                    for i in 0..n { db.engine.put(T, &id(i), &val(i + 1))?; commit_every(&mut db, i)?; }
                }
            }
            "prefix" => for i in 0..n { db.engine.put(T, &pre(i), &val(i))?; commit_every(&mut db, i)?; },
            // 64 x 16 MB: value log, not segments.
            "bigdoc" => for i in 0..64 { db.engine.put(T, &id(i), &vec![(i % 251) as u8; 16 << 20])?; db.commit(Durability::Sync)?; },
            // 10^6 distinct names, 10 new ones per document.
            "fields" => {
                let mut c = db.collection("c")?;
                for i in 0..100_000i64 {
                    let mut f = vec![("_id".to_string(), id(i + 1))];
                    f.extend((0..10).map(|k| (format!("f{}", i * 10 + k), Value::int(NumType::I64, i as i128))));
                    c.insert(&mut db.engine, &Value::Doc(f))?;
                    if (i + 1) % 10_000 == 0 { db.commit(Durability::Sync)?; }
                }
            }
            "colls" => for i in 0..100_000i64 {
                let mut c = db.collection(&format!("c{i}"))?;
                c.insert(&mut db.engine, &Value::Doc(vec![("_id".into(), id(i + 1))]))?;
                if (i + 1) % 10_000 == 0 { db.commit(Durability::Sync)?; }
            },
            // Every 100-key span deleted as a range, in a shuffled order.
            "rangedel" => {
                for i in 0..n { db.engine.put(T, &id(i), &val(i))?; commit_every(&mut db, i)?; }
                db.commit(Durability::Sync)?;
                let spans = n / 100;
                for j in 0..spans {
                    let s = (j * 7919) % spans;
                    db.engine.remove_range(T, &id(s * 100), &id(s * 100 + 100))?;
                    if (j + 1) % 1000 == 0 { db.commit(Durability::Sync)?; }
                }
            }
            // All expire 2 s after the write; read after they have.
            "ttl" => {
                let at = cryptand::engine::now_millis() as u64 + 2000;
                for i in 0..n { db.engine.put_with_expiry(T, &id(i), &val(i), at)?; commit_every(&mut db, i)?; }
                db.commit(Durability::Sync)?;
                let now = cryptand::engine::now_millis() as u64;
                if now < at + 100 { std::thread::sleep(std::time::Duration::from_millis(at + 100 - now)); }
            }
            _ => unreachable!(),
        }
        db.commit(Durability::Sync)?;
        let build_s = t.elapsed().as_secs_f64();
        db.engine.drain_compaction()?;
        db.commit(Durability::Sync)?;
        db.close()?;
        let mut db = Database::open(&p, None)?;
        // Every check probes 1000 spread keys (all for the shape workloads).
        let probe = |k: i64| (0..1000).map(move |j| j * (k / 1000).max(1)).filter(move |j| *j < k);
        let bad = match *w {
            "mono" => probe(n).filter(|&i| db.engine.get(T, &id(i)).ok().flatten() != Some(val(i))).count(),
            "tombstone" => probe(n).filter(|&i| db.engine.get(T, &id(i)).ok().flatten() != Some(val(i + 1))).count(),
            "prefix" => probe(n).filter(|&i| db.engine.get(T, &pre(i)).ok().flatten() != Some(val(i))).count(),
            "bigdoc" => (0..64).filter(|&i| db.engine.get(T, &id(i)).ok().flatten().map(|v| v.len() == 16 << 20 && v[0] == (i % 251) as u8) != Some(true)).count(),
            "fields" => {
                let c = db.collection("c")?;
                probe(100_000).filter(|&i| c.get(&mut db.engine, i + 1).ok().flatten().and_then(|d| d.field(&format!("f{}", i * 10 + 9)).cloned()) != Some(Value::int(NumType::I64, i as i128))).count()
            }
            "colls" => {
                let names = db.collections()?.len();
                extra += &format!(" collections={names}");
                usize::from(names != 100_000)
            }
            "rangedel" | "ttl" => {
                extra += &format!(" scan_rows={}", db.engine.scan_tree(T, None, None, None, false)?.len());
                probe(n).filter(|&i| db.engine.get(T, &id(i)).ok().flatten().is_some()).count()
            }
            _ => unreachable!(),
        };
        let open_rss = rss_mb();
        let rep = db.engine.verify()?;
        for f in rep.findings.iter().take(5) {
            eprintln!("{w} verify {:?}: {}", f.class, f.what);
        }
        println!(
            "workload={w} n={n} build_s={build_s:.1} bytes={} bad={bad} verify_sound={} rss_mb={open_rss}{extra}",
            std::fs::metadata(&p)?.len(), rep.ok()
        );
        db.close()?;
        let _ = std::fs::remove_file(&p);
    }
    Ok(())
}
