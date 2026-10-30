//! F-195 / F-196 (ports of Java's `RTreeIncrementalTest` and `VectorGraphTest`):
//! the copy-on-write R-tree and the incremental Vamana graph answer as brute
//! force does through writes, early write-backs and a reopen.

mod support;
use support::*;

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::Ordering;

use cryptand::container::{Durability, Profile};
use cryptand::database::Database;
use cryptand::value::Value;
use cryptand::verify::EngineVerify;
use cryptand::wkb::{self, Coord, Geometry};

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn at(id: i64, x: f64, y: f64) -> Value {
    doc(id, vec![("loc", Value::Geometry(wkb::encode(&Geometry::Point(Some(Coord::xy(x, y)))).unwrap()))])
}

fn rect(x0: f64, y0: f64, x1: f64, y1: f64) -> Vec<u8> {
    let ring = vec![Coord::xy(x0, y0), Coord::xy(x1, y0), Coord::xy(x1, y1), Coord::xy(x0, y1), Coord::xy(x0, y0)];
    wkb::encode(&Geometry::Polygon(vec![ring])).unwrap()
}

fn brute(live: &HashMap<i64, (f64, f64)>, x0: f64, y0: f64, x1: f64, y1: f64) -> BTreeSet<i64> {
    live.iter().filter(|(_, p)| p.0 >= x0 && p.0 <= x1 && p.1 >= y0 && p.1 <= y1).map(|(id, _)| *id).collect()
}

fn sound(db: &mut Database) {
    let r = db.engine.verify().unwrap();
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

#[test]
fn random_writes_with_early_write_backs_match_brute_force_before_and_after_reopen() {
    let saved = cryptand::rtree::DIRTY_BUDGET.swap(8, Ordering::Relaxed);
    let (t, mut db) = db("rtree-cow", Profile::Desktop);
    db.engine.memtable_entry_limit = 256;
    let mut rnd = Rng(195);
    let mut live: HashMap<i64, (f64, f64)> = HashMap::new();
    let mut ids: Vec<i64> = Vec::new();
    let mut next_id = 1i64;
    let mut c = db.collection("c").unwrap();
    let ix = db.create_spatial_index(&c, "loc", 2, None).unwrap();
    for step in 0..20_000 {
        let op = rnd.below(10);
        let (x, y) = (rnd.f64() * 100.0, rnd.f64() * 100.0);
        if op < 6 || ids.is_empty() {
            let id = next_id;
            next_id += 1;
            c.insert(&mut db.engine, &at(id, x, y)).unwrap();
            ids.push(id);
            live.insert(id, (x, y));
        } else if op < 8 {
            let id = ids[rnd.below(ids.len())];
            if live.contains_key(&id) {
                c.insert(&mut db.engine, &at(id, x, y)).unwrap();
                live.insert(id, (x, y));
            }
        } else {
            let id = ids[rnd.below(ids.len())];
            c.remove(&mut db.engine, id).unwrap();
            live.remove(&id);
        }
        if step % 2_000 == 1_999 {
            db.commit(Durability::Os).unwrap();
        }
        if step % 500 == 0 {
            let (qx, qy) = (rnd.f64() * 90.0, rnd.f64() * 90.0);
            let q = rect(qx, qy, qx + 10.0, qy + 10.0);
            let got: BTreeSet<i64> = db.with_spatial(&ix, |s, e| s.intersects(e, &c, &q)).unwrap().into_iter().collect();
            assert_eq!(brute(&live, qx, qy, qx + 10.0, qy + 10.0), got, "step {step}");
        }
    }
    let all = rect(-1.0, -1.0, 101.0, 101.0);
    assert_eq!(live.len(), db.with_spatial(&ix, |s, e| s.intersects(e, &c, &all)).unwrap().len());
    assert_eq!(live.len() as u64, db.with_spatial(&ix, |s, _| Ok(s.len())).unwrap());
    db.commit(Durability::Os).unwrap();
    sound(&mut db);
    db.close().unwrap();
    drop(db);

    let mut db = Database::open(&t.path, None).unwrap();
    let c = db.collection("c").unwrap();
    assert_eq!(live.len() as u64, db.with_spatial(&ix, |s, _| Ok(s.len())).unwrap());
    let got: BTreeSet<i64> = db.with_spatial(&ix, |s, e| s.intersects(e, &c, &all)).unwrap().into_iter().collect();
    assert_eq!(live.keys().copied().collect::<BTreeSet<_>>(), got);
    // nearest_k: the 10 returned are among the 10 nearest by brute force.
    let knn = db.with_spatial(&ix, |s, e| s.nearest_k(e, &c, 50.0, 50.0, 10)).unwrap();
    assert_eq!(10, knn.len());
    let mut d: Vec<f64> = live.values().map(|p| (p.0 - 50.0).hypot(p.1 - 50.0)).collect();
    d.sort_by(f64::total_cmp);
    for id in knn {
        let p = live[&id];
        assert!((p.0 - 50.0).hypot(p.1 - 50.0) <= d[9], "knn {id}");
    }
    sound(&mut db);
    cryptand::rtree::DIRTY_BUDGET.store(saved, Ordering::Relaxed);
}

fn l2(a: &[f32], b: &[f32]) -> f64 {
    a.iter().zip(b).map(|(x, y)| (*x as f64 - *y as f64).powi(2)).sum::<f64>().sqrt()
}

fn recall(db: &mut Database, ix: &str, live: &HashMap<i64, Vec<f32>>, rnd: &mut Rng, dim: usize) -> (f64, u64) {
    let mut found = 0;
    let queries = 50;
    for _ in 0..queries {
        let q: Vec<f32> = (0..dim).map(|_| rnd.f64() as f32).collect();
        let mut all: Vec<(i64, f64)> = live.iter().map(|(id, v)| (*id, l2(&q, v))).collect();
        all.sort_by(|a, b| a.1.total_cmp(&b.1));
        let truth: BTreeSet<i64> = all[..10].iter().map(|h| h.0).collect();
        let hits = db.with_vector(ix, |v, e| v.search(e, &q, 10, None)).unwrap();
        assert_eq!(10, hits.len());
        for (id, d) in hits {
            let v = live.get(&id).expect("deleted document returned");
            assert!((l2(&q, v) - d).abs() < 1e-9);
            if truth.contains(&id) {
                found += 1;
            }
        }
    }
    let fallbacks = db.with_vector(ix, |v, _| Ok(v.fallbacks)).unwrap();
    (found as f64 / (queries * 10) as f64, fallbacks)
}

#[test]
fn recall_at_10_against_brute_force_stays_high_through_deletes_and_a_reopen() {
    let saved = cryptand::vector::ADJACENCY_DIRTY_BUDGET.swap(8, Ordering::Relaxed);
    let (t, mut db) = db("vector-graph", Profile::Desktop);
    db.engine.memtable_entry_limit = 256;
    let dim = 16;
    let mut rnd = Rng(196);
    let mut live: HashMap<i64, Vec<f32>> = HashMap::new();
    let mut ids = Vec::new();
    let mut c = db.collection("c").unwrap();
    let ix = db.create_vector_index(&c, "emb", dim as u32, "l2", 16).unwrap();
    for i in 0..4000i64 {
        let v: Vec<f32> = (0..dim).map(|_| rnd.f64() as f32).collect();
        c.insert(&mut db.engine, &doc(i + 1, vec![("emb", Value::VectorF32(v.clone()))])).unwrap();
        ids.push(i + 1);
        live.insert(i + 1, v);
        if i % 1000 == 999 {
            db.commit(Durability::Os).unwrap();
        }
    }
    for _ in 0..400 {
        let id = ids[rnd.below(ids.len())];
        c.remove(&mut db.engine, id).unwrap();
        live.remove(&id);
    }
    let (r, fallbacks) = recall(&mut db, &ix, &live, &mut rnd, dim);
    assert!(r >= 0.95, "recall {r}");
    assert_eq!(0, fallbacks, "searches answered by the scan, not the graph");
    db.commit(Durability::Os).unwrap();
    sound(&mut db);
    db.close().unwrap();
    drop(db);

    let mut db = Database::open(&t.path, None).unwrap();
    db.collection("c").unwrap();
    assert_eq!(live.len() as u64, db.with_vector(&ix, |v, _| Ok(v.len())).unwrap());
    let (r, fallbacks) = recall(&mut db, &ix, &live, &mut rnd, dim);
    assert!(r >= 0.95, "recall after reopen {r}");
    assert_eq!(0, fallbacks);
    sound(&mut db);
    cryptand::vector::ADJACENCY_DIRTY_BUDGET.store(saved, Ordering::Relaxed);
}

#[test]
fn clearing_an_indexed_collection_empties_its_spatial_and_vector_indexes() {
    // F-198: a vector search returns slots, so a clear that left them named
    // documents that are gone.
    let (_t, mut db) = db("index-clear", Profile::Desktop);
    let mut c = db.collection("c").unwrap();
    let sp = db.create_spatial_index(&c, "loc", 2, None).unwrap();
    let vx = db.create_vector_index(&c, "emb", 2, "l2", 4).unwrap();
    for i in 1..=50i64 {
        let d = doc(i, vec![
            ("loc", Value::Geometry(wkb::encode(&Geometry::Point(Some(Coord::xy(i as f64, 0.0)))).unwrap())),
            ("emb", Value::VectorF32(vec![i as f32, 0.0])),
        ]);
        c.insert(&mut db.engine, &d).unwrap();
    }
    c.clear(&mut db.engine).unwrap();
    assert_eq!(0, db.with_spatial(&sp, |s, _| Ok(s.len())).unwrap());
    assert!(db.with_vector(&vx, |v, e| v.search(e, &[1.0, 0.0], 5, None)).unwrap().is_empty());
    db.commit(Durability::Os).unwrap();
    sound(&mut db);
}

#[test]
#[cfg_attr(debug_assertions, ignore = "3500 x 128-d builds; the release gate runs it")]
fn a_clustered_index_is_navigable_beyond_the_entry_points_cluster() {
    // F-201: K tight clusters of P in D dims (env CL_K/CL_P/CL_D override).
    // Each cluster outgrows m = 32, and without the far slots every list
    // filled with its own cluster and a search never left the entry point's:
    // recall 0.025 here (64-d does not show it; high dimensions do).
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (k, p, dim) = (env("CL_K", 50), env("CL_P", 70), env("CL_D", 128));
    let (_t, mut db) = db("vector-clusters", Profile::Desktop);
    let mut rnd = Rng(201);
    let centres: Vec<Vec<f32>> = (0..k).map(|_| (0..dim).map(|_| rnd.f64() as f32).collect()).collect();
    let mut c = db.collection("c").unwrap();
    let ix = db.create_vector_index(&c, "emb", dim as u32, "l2", 64).unwrap();
    let mut live: HashMap<i64, Vec<f32>> = HashMap::new();
    for i in 0..(k * p) as i64 {
        let ctr = &centres[i as usize % k];
        let v: Vec<f32> = ctr.iter().map(|x| x + 0.15 * (rnd.f64() as f32 - 0.5)).collect();
        c.insert(&mut db.engine, &doc(i + 1, vec![("emb", Value::VectorF32(v.clone()))])).unwrap();
        live.insert(i + 1, v);
    }
    let mut found = 0;
    for q in 0..40usize {
        let q = q * k / 40;
        let query: Vec<f32> = centres[q].iter().map(|x| x + 0.15 * (rnd.f64() as f32 - 0.5)).collect();
        let mut all: Vec<(i64, f64)> = live.iter().map(|(id, v)| (*id, l2(&query, v))).collect();
        all.sort_by(|a, b| a.1.total_cmp(&b.1));
        let truth: BTreeSet<i64> = all[..10].iter().map(|h| h.0).collect();
        for (id, _) in db.with_vector(&ix, |v, e| v.search(e, &query, 10, None)).unwrap() {
            found += truth.contains(&id) as usize;
        }
    }
    let r = found as f64 / 400.0;
    assert!(r >= 0.9, "recall {r}");
}
