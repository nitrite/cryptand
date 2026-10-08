//! PLAN M2.1 — crash consistency under injected faults. Each seed runs a
//! random workload of batches (puts and removes, `flush`, `commit(Sync)`,
//! sometimes a compaction), loses power at a random write, keeps a random
//! subset of the un-fsynced writes (some torn), and reopens. On reopen:
//!
//! - the file opens (a typed error is not enough: only un-fsynced writes were
//!   lost, so the last durable commit is intact) and never panics;
//! - `verify` is clean;
//! - the state is the last acknowledged batch, or that batch plus the one in
//!   flight, never anything in between;
//! - an encrypted file's next nonce is above every nonce used before the cut.
//!
//! `CRYPTAND_FAULT_SEEDS=a..b` widens the run (default 0..40).

mod support;
use support::*;

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::fault::{self, splitmix, Plan};
use cryptand::value::Value;
use cryptand::verify::{Class, EngineVerify};

const T: u32 = 16;
const KEY: [u8; 32] = [7u8; 32];

type Model = BTreeMap<i64, Vec<u8>>;

fn seeds() -> std::ops::Range<u64> {
    std::env::var("CRYPTAND_FAULT_SEEDS")
        .ok()
        .and_then(|s| {
            let (a, b) = s.split_once("..")?;
            Some(a.parse().ok()?..b.parse().ok()?)
        })
        .unwrap_or(0..40)
}

fn create(path: &Path, encrypted: bool) -> Engine {
    if encrypted {
        Engine::create_encrypted(path, Profile::Desktop, &KEY, 0, 0, 0, 0).unwrap()
    } else {
        Engine::create(path, Profile::Desktop).unwrap()
    }
}

fn next_nonce(e: &Engine) -> u64 {
    e.pager.crypto.as_ref().map_or(0, |c| c.next)
}

struct Run {
    acked: Model,
    inflight: Model,
    max_nonce: u64,
}

/// The workload. Stops at the first error, which is the injected fault.
fn workload(e: &mut Engine, seed: u64) -> Run {
    workload_with(e, seed, false)
}

/// `convert`: plaintext files are encrypted in place at batch 4, and every
/// later batch is followed by a conversion step (F-072).
fn workload_with(e: &mut Engine, seed: u64, convert: bool) -> Run {
    let mut rng = seed;
    let mut model = Model::new();
    let mut run = Run { acked: Model::new(), inflight: Model::new(), max_nonce: 0 };
    for _batch in 0..12 {
        for _ in 0..(1 + splitmix(&mut rng) % 40) {
            let r = splitmix(&mut rng);
            let k = (r % 200) as i64;
            if r % 5 == 0 {
                model.remove(&k);
                if e.remove(T, &Value::NitriteId(k)).is_err() {
                    return run;
                }
            } else {
                // Some values cross the value-log threshold.
                let len = if r % 7 == 0 { 3000 } else { 1 + (r >> 20) as usize % 60 };
                let v = vec![(r >> 8) as u8; len];
                model.insert(k, v.clone());
                if e.put(T, &Value::NitriteId(k), &v).is_err() {
                    return run;
                }
            }
        }
        run.inflight = model.clone();
        let r = splitmix(&mut rng);
        let ok = e.flush().is_ok()
            && (r % 4 != 0 || e.compact().is_ok())
            && e.commit(Durability::Sync).is_ok()
            && (!convert || e.sb.cipher != 0 && e.keys.is_none() || {
                use cryptand::convert::ConvertApi;
                if e.sb.cipher == 0 && _batch == 4 {
                    e.encrypt(&KEY, 0, 0, 0, 0).is_ok()
                } else if e.sb.cipher != 0 {
                    e.convert_step().is_ok()
                } else {
                    true
                }
            });
        run.max_nonce = run.max_nonce.max(next_nonce(e));
        if !ok {
            return run;
        }
        run.acked = model.clone();
    }
    run
}

fn state(e: &mut Engine) -> Model {
    let mut m = Model::new();
    for k in 0..200i64 {
        if let Some(v) = e.get(T, &Value::NitriteId(k)).unwrap() {
            m.insert(k, v);
        }
    }
    m
}

fn one(name: &str, seed: u64, plan_of: impl Fn(u64, u64, &mut u64) -> Plan) -> Result<(), String> {
    one_with(name, seed, false, plan_of)
}

fn one_with(name: &str, seed: u64, convert: bool, plan_of: impl Fn(u64, u64, &mut u64) -> Plan) -> Result<(), String> {
    let encrypted = seed % 2 == 1 && !convert;
    let mut rng = seed.wrapping_mul(31) + 1;

    // Dry run: how many writes and syncs does this seed's workload issue?
    let t = TempDb::new(&format!("fault-dry-{name}-{seed}"));
    let mut e = create(&t.path, encrypted);
    fault::arm(&t.path, Plan::default());
    workload_with(&mut e, seed, convert);
    let (writes, syncs) = fault::counts(&t.path);
    fault::disarm(&t.path);
    drop(e);

    let t = TempDb::new(&format!("fault-{name}-{seed}"));
    let mut e = create(&t.path, encrypted);
    let plan = plan_of(writes, syncs, &mut rng);
    fault::arm(&t.path, plan);
    let run = workload_with(&mut e, seed, convert);
    // The process dies here: no close, no flush. Drop must not panic either.
    catch_unwind(AssertUnwindSafe(|| drop(e))).map_err(|_| format!("seed {seed}: drop panicked"))?;
    let dropped = fault::crash(&t.path, splitmix(&mut rng)).unwrap();
    let ctx = format!("seed {seed} enc={encrypted} {plan:?} writes={writes} dropped={dropped}");

    // A converting file may or may not have reached `cipher = 1`.
    let key = (encrypted || convert).then_some(&KEY[..]);
    let mut e = match catch_unwind(AssertUnwindSafe(|| {
        Engine::open(&t.path, key).or_else(|err| if convert { Engine::open(&t.path, None) } else { Err(err) })
    })) {
        Err(_) => return Err(format!("{ctx}: open panicked")),
        Ok(Err(err)) => return Err(format!("{ctx}: open refused: {err}")),
        Ok(Ok(e)) => e,
    };
    let report = e.verify().map_err(|err| format!("{ctx}: verify error: {err}"))?;
    // A torn fallback slot is a Warning (F-070); anything else is a failure.
    if report.findings.iter().any(|f| f.class != Class::Warning) {
        return Err(format!("{ctx}: verify: {report:?}"));
    }
    let got = state(&mut e);
    if got != run.acked && got != run.inflight {
        return Err(format!(
            "{ctx}: state is neither the acked batch ({} keys) nor the in-flight one ({} keys): {} keys",
            run.acked.len(),
            run.inflight.len(),
            got.len()
        ));
    }
    if encrypted || (convert && e.sb.cipher != 0) {
        let n = e.allocate_nonce().map_err(|err| format!("{ctx}: nonce: {err}"))?;
        if n < run.max_nonce {
            return Err(format!("{ctx}: nonce {n} reissued (used up to {})", run.max_nonce));
        }
    }
    e.close(true).map_err(|err| format!("{ctx}: close after recovery: {err}"))?;
    Ok(())
}

fn sweep(name: &str, plan_of: impl Fn(u64, u64, &mut u64) -> Plan + Copy) {
    let failures: Vec<String> = seeds().filter_map(|s| one(name, s, plan_of).err()).collect();
    assert!(failures.is_empty(), "{name}: {} failures:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn power_cut_at_a_random_write() {
    sweep("crash", |w, _, rng| Plan { crash_at_write: Some(splitmix(rng) % w.max(1)), ..Plan::default() });
}

#[test]
fn fsync_eio_then_power_cut() {
    sweep("eio", |_, s, rng| Plan { eio_at_sync: Some(splitmix(rng) % s.max(1)), ..Plan::default() });
}

#[test]
fn enospc_at_a_random_write_then_power_cut() {
    sweep("enospc", |w, _, rng| Plan { enospc_at_write: Some(splitmix(rng) % w.max(1)), ..Plan::default() });
}

#[test]
fn power_cut_during_in_place_encryption() {
    let failures: Vec<String> = seeds()
        .filter_map(|s| {
            one_with("convert", s, true, |w, _, rng| Plan { crash_at_write: Some(splitmix(rng) % w.max(1)), ..Plan::default() })
                .err()
        })
        .collect();
    assert!(failures.is_empty(), "convert: {} failures:\n{}", failures.len(), failures.join("\n"));
}

/// The control (PLAN rule 5): when `fsync` lies, acknowledged batches are
/// lost, and the checks above must say so.
#[test]
fn control_a_lying_fsync_is_caught() {
    let failures = (0..20)
        .filter(|&s| {
            one("control", s, |w, _, rng| Plan { crash_at_write: Some(w - 1 - splitmix(rng) % (w / 4).max(1)), sync_lies: true, ..Plan::default() })
                .is_err()
        })
        .count();
    assert!(failures > 0, "a lying fsync went unnoticed in 20 seeds");
}

/// F-069: `create` publishes slot B only, so until the first close slot A is
/// zeros. A reader that guessed 4096 for the page size could not find slot B
/// of an 8 KiB file, and a crash before the first close lost the database.
#[test]
fn crash_before_the_first_close_reopens() {
    for encrypted in [false, true] {
        let t = TempDb::new("f069");
        let mut e = create(&t.path, encrypted);
        assert_ne!(e.pager.page_size, 4096, "the case needs a non-4 KiB page");
        e.put(T, &Value::NitriteId(1), b"x").unwrap();
        drop(e);
        let mut e = Engine::open(&t.path, encrypted.then_some(&KEY[..])).unwrap();
        assert!(e.verify().unwrap().ok());
    }
}

/// F-095: a commit whose superblock write fails must not keep its number.
/// Slots alternate by `commit_id`, so the retry, numbered one too high,
/// overwrote the last durable superblock; and an unpublished nonce floor
/// left allocation running above what a crash would reissue.
#[test]
fn a_failed_publish_keeps_its_commit_id_and_nonce_floor() {
    for encrypted in [false, true] {
        let t = TempDb::new("f095");
        let mut e = create(&t.path, encrypted);
        e.put(T, &Value::NitriteId(1), b"x").unwrap();
        e.commit(Durability::Sync).unwrap();
        let (before, floor) = (e.sb.commit_id, e.sb.next_nonce);
        // The first sync of a commit is the barrier in front of the superblock,
        // after the commit is numbered.
        fault::arm(&t.path, Plan { eio_at_sync: Some(0), ..Plan::default() });
        e.put(T, &Value::NitriteId(2), b"y").unwrap();
        assert!(e.commit(Durability::Sync).is_err());
        fault::disarm(&t.path);
        assert_eq!(e.sb.commit_id, before, "encrypted={encrypted}");
        assert_eq!(e.sb.next_nonce, floor, "encrypted={encrypted}");
        e.commit(Durability::Sync).unwrap();
        assert_eq!(e.sb.commit_id, before + 1, "encrypted={encrypted}");
        if encrypted {
            // A failed floor publish leaves the limit where the durable floor is.
            let durable_floor = e.sb.next_nonce;
            fault::arm(&t.path, Plan { eio_at_sync: Some(0), ..Plan::default() });
            let r = e.ensure_nonces(u64::MAX / 4);
            fault::disarm(&t.path);
            assert!(r.is_err());
            assert_eq!(e.sb.next_nonce, durable_floor);
            assert!(e.pager.crypto.as_ref().unwrap().limit <= durable_floor, "limit above the durable floor");
        }
    }
}
