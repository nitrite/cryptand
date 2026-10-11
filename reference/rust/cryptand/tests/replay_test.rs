//! F-128, 14 §5.5: an older authentic page copied back over its own position
//! is tampering, because every parent records its child's nonce.

mod support;
use support::*;

use cryptand::container::{Durability, Profile, PAGE_HEADER_BYTES};
use cryptand::convert::ConvertApi;
use cryptand::engine::Engine;
use cryptand::error::Error;
use cryptand::spaceapi::Step;
use cryptand::value::Value;

const T: u32 = 16;
const KEY: [u8; 32] = [7u8; 32];

fn read_all(path: &std::path::Path, n: i64) -> Result<Vec<Option<Vec<u8>>>, Error> {
    let mut e = Engine::open(path, Some(&KEY))?;
    (0..n).map(|i| e.get(T, &Value::NitriteId(i))).collect()
}

#[test]
fn an_older_page_replayed_at_its_own_position_is_tampering() {
    let t = TempDb::new("replay");
    let n = 400;
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    e.encrypt(&KEY, 0, 0, 0, 0).unwrap();
    while e.convert_step().unwrap() == Step::More {}
    for i in 0..n {
        e.put(T, &Value::NitriteId(i), format!("v-{i}").as_bytes()).unwrap();
    }
    // Small commits: each rewrites the copy-on-write trees' paths, and the
    // pages they free are reused a few commits later.
    let small = |e: &mut Engine, rounds: std::ops::Range<i64>| {
        for r in rounds {
            for i in (r * 7..r * 7 + 5).map(|i| i % n) {
                e.put(T, &Value::NitriteId(i), format!("r{r}-{i}").as_bytes()).unwrap();
            }
            e.flush().unwrap();
            e.commit(Durability::Sync).unwrap();
        }
    };
    small(&mut e, 0..30);
    e.close(true).unwrap();
    drop(e);
    let older = std::fs::read(&t.path).unwrap();
    let mut e = Engine::open(&t.path, Some(&KEY)).unwrap();
    small(&mut e, 30..60);
    e.close(true).unwrap();
    drop(e);
    let base = std::fs::read(&t.path).unwrap();
    let want = read_all(&t.path, n).unwrap();

    let ps = 1usize << base[14]; // page_size_log2
    let (mut tamper, mut tried, mut bad) = (0, 0, Vec::new());
    for p in 2..(base.len().min(older.len()) / ps) {
        let (o, b) = (&older[p * ps..(p + 1) * ps], &base[p * ps..(p + 1) * ps]);
        // Both sealed pages (flags.ENCRYPTED, bit 1), and not the same write.
        if o == b || o[5] & 2 == 0 || b[5] & 2 == 0 || o[..PAGE_HEADER_BYTES] == b[..PAGE_HEADER_BYTES] {
            continue;
        }
        tried += 1;
        let mut f = base.clone();
        f[p * ps..(p + 1) * ps].copy_from_slice(o);
        std::fs::write(&t.path, &f).unwrap();
        match read_all(&t.path, n) {
            Err(Error::Tamper(_)) => tamper += 1,
            Ok(got) if got == want => {}
            Ok(_) => bad.push(format!("page {p}: an older page was read as current")),
            Err(e) => bad.push(format!("page {p}: reported as {e}, not tampering")),
        }
    }
    assert!(bad.is_empty(), "{} of {tried} replays not caught: {bad:#?}", bad.len());
    assert!(tried > 0, "no page position was reused; the test proves nothing");
    assert!(tamper > 0, "{tried} replays, none caught");
    println!("{tried} replays, {tamper} caught as tampering");
}

/// Writes `conformance/files/v1.0-security-replay.cryptand` (F-128): the
/// encrypted golden file after a few more commits, with one page put back to
/// what it held before them -- authentic bytes at their own position, which
/// only the parent's recorded nonce tells apart. Run by hand:
/// `cargo test -p cryptand --test replay_test -- --ignored make_replay_vector`.
#[test]
#[ignore]
fn make_replay_vector() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/files");
    let out = dir.join("v1.0-security-replay.cryptand");
    let key: Vec<u8> = (1..=32).collect(); // the manifest's corpus key
    std::fs::copy(dir.join("v1.0-encrypted.cryptand"), &out).unwrap();
    Engine::open(&out, Some(&key)).unwrap().close(true).unwrap();
    let older = std::fs::read(&out).unwrap();
    let mut e = Engine::open(&out, Some(&key)).unwrap();
    for r in 0..12i64 {
        // A tree no descriptor names: the documents stay as they were.
        e.put(999, &Value::NitriteId(r), b"replay").unwrap();
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
    }
    e.close(true).unwrap();
    drop(e);
    let base = std::fs::read(&out).unwrap();
    let ps = 1usize << base[14];
    for p in 2..base.len().min(older.len()) / ps {
        let (o, b) = (&older[p * ps..(p + 1) * ps], &base[p * ps..(p + 1) * ps]);
        if o == b || o[5] & 2 == 0 || b[5] & 2 == 0 || o[..PAGE_HEADER_BYTES] == b[..PAGE_HEADER_BYTES] {
            continue;
        }
        let mut f = base.clone();
        f[p * ps..(p + 1) * ps].copy_from_slice(o);
        std::fs::write(&out, &f).unwrap();
        if matches!(Engine::open(&out, Some(&key)).map(|_| ()), Err(Error::Tamper(_))) {
            std::fs::write(&out, &f).unwrap(); // the open above may have published a floor
            println!("page {p} replayed");
            return;
        }
    }
    panic!("no replay of a page open reads");
}
