//! M2.3: disk full. Needs a small volume: `tools/enospc.sh` mounts a 200 MB
//! image and sets `CRYPTAND_ENOSPC_DIR`; without it the test does nothing.

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::error::Error;
use cryptand::value::Value;
use cryptand::verify::{Class, EngineVerify};

const T: u32 = 16;
const KEY: [u8; 32] = [9u8; 32];

fn value(i: i64) -> Vec<u8> {
    let mut v = format!("value-{i}-").into_bytes();
    v.resize(if i % 5 == 0 { 9000 } else { 700 }, b'x');
    v
}

fn clean(e: &mut Engine, acked: i64, what: &str) {
    for i in 0..acked {
        let got = e.get(T, &Value::NitriteId(i)).unwrap_or_else(|x| panic!("{what}: acked key {i}: {x}"));
        assert_eq!(got, Some(value(i)), "{what}: acked key {i} lost");
    }
    let r = e.verify().unwrap();
    let bad: Vec<_> = r.findings.iter().filter(|f| f.class != Class::Warning).collect();
    assert!(bad.is_empty(), "{what}: {bad:?}");
}

fn run(dir: &std::path::Path, encrypted: bool) {
    let key: Option<&[u8]> = encrypted.then_some(&KEY[..]);
    let path = dir.join(if encrypted { "rust-enc.cff" } else { "rust.cff" });
    let ballast = dir.join("rust.ballast");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&ballast, vec![0u8; 100 << 20]).unwrap(); // freed later
    let mut e = match key {
        Some(k) => Engine::create_encrypted(&path, Profile::Mobile, k, 0, 0, 0, 0),
        None => Engine::create(&path, Profile::Mobile),
    }
    .unwrap();
    // Fill until the device refuses. Every 50 puts is one durable commit;
    // `acked` counts the puts a successful commit made durable.
    let (mut i, mut acked) = (0i64, 0i64);
    let err = loop {
        let r = e.put(T, &Value::NitriteId(i), &value(i)).and_then(|_| {
            if i % 50 == 49 { e.flush()?; e.commit(Durability::Sync)?; }
            Ok(())
        });
        match r {
            Ok(()) => { i += 1; if i % 50 == 0 { acked = i; } }
            Err(x) => break x,
        }
        assert!(i < 10_000_000, "the device never filled");
    };
    assert!(matches!(err, Error::Io(_)), "a full device is an I/O error, not {err:?}");
    eprintln!("rust{}: full after {i} puts ({acked} acked): {err}", if encrypted { " enc" } else { "" });
    // Further work fails cleanly too, never a panic.
    for j in 0..20 {
        let _ = e.put(T, &Value::NitriteId(i + j), &value(i + j)).and_then(|_| e.commit(Durability::Sync));
    }
    let _ = e.close(true);
    drop(e);
    // Still full: the file opens and nothing acknowledged is lost.
    let mut e = Engine::open(&path, key).expect("a full device must not stop the file opening");
    clean(&mut e, acked, "reopened while full");
    drop(e);
    // Space freed: work resumes.
    std::fs::remove_file(&ballast).unwrap();
    let mut e = Engine::open(&path, key).unwrap();
    let base = 1_000_000_000i64;
    for j in 0..2000 {
        e.put(T, &Value::NitriteId(base + j), &value(j)).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
    // A full compaction rewrites the data beside itself and may still not fit
    // (a fresh value-log segment preallocates its extent); it fails cleanly.
    match e.compact() {
        Ok(()) | Err(Error::Io(_)) => {}
        Err(x) => panic!("compaction on a near-full device: {x:?}"),
    }
    clean(&mut e, acked, "resumed");
    e.close(true).unwrap();
    drop(e);
    let mut e = Engine::open(&path, key).unwrap();
    clean(&mut e, acked, "resumed, reopened");
    for j in 0..2000 {
        assert_eq!(e.get(T, &Value::NitriteId(base + j)).unwrap(), Some(value(j)));
    }
    drop(e);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_full_device_fails_cleanly_and_recovers() {
    let Some(dir) = std::env::var_os("CRYPTAND_ENOSPC_DIR") else { return };
    let dir = std::path::PathBuf::from(dir);
    run(&dir, false);
    run(&dir, true);
}
