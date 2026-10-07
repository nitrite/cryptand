//! F-072: 13 §5 `encrypt()` and 14 §8.3/§8.4's in-place conversion.

mod support;
use support::*;

use cryptand::container::{Durability, Profile};
use cryptand::convert::ConvertApi;
use cryptand::engine::Engine;
use cryptand::spaceapi::Step;
use cryptand::value::Value;
use cryptand::verify::{Class, EngineVerify};

const T: u32 = 16;
const KEY: [u8; 32] = [9u8; 32];

fn value(i: i64) -> Vec<u8> {
    // Every seventh crosses `vlog_min`, so the value log has records too.
    let len = if i % 7 == 0 { 3000 } else { 40 };
    let mut v = format!("value-{i}-").into_bytes();
    v.resize(len, b'x');
    v
}

fn check(e: &mut Engine, n: i64, what: &str) {
    for i in 0..n {
        assert_eq!(e.get(T, &Value::NitriteId(i)).unwrap(), Some(value(i)), "{what}: key {i}");
    }
    let r = e.verify().unwrap();
    let bad: Vec<_> = r.findings.iter().filter(|f| f.class != Class::Warning).collect();
    assert!(bad.is_empty(), "{what}: {bad:?}");
}

#[test]
fn encrypt_in_place_converts_everything_and_survives_reopen_midway() {
    let t = TempDb::new("encrypt");
    let n = 600;
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    for i in 0..n {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
        if i % 150 == 149 {
            e.flush().unwrap();
        }
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();

    e.encrypt(&KEY, 0, 0, 0, 0).unwrap();
    let c = e.conversion().unwrap();
    assert!(c.remaining > 0, "nothing to convert? {c:?}");
    assert!(!e.fully_encrypted().unwrap(), "14 §8.3: not encrypted while plaintext remains");
    // Writes after the switch, interleaved with the conversion.
    e.put(T, &Value::NitriteId(n), &value(n)).unwrap();
    e.close(true).unwrap();
    drop(e);

    // A half-converted file is a valid file (14 §8.4), and needs the key now.
    assert!(Engine::open(&t.path, None).is_err());
    let mut e = Engine::open(&t.path, Some(&KEY)).unwrap();
    check(&mut e, n + 1, "half-converted");

    let mut steps = 0;
    while e.convert_step().unwrap() == Step::More {
        steps += 1;
        assert!(steps < 20, "conversion does not converge: {:?}", e.conversion().unwrap());
    }
    assert!(e.conversion().unwrap().done());
    assert!(e.fully_encrypted().unwrap());
    check(&mut e, n + 1, "converted");
    e.close(true).unwrap();
    drop(e);

    let mut e = Engine::open(&t.path, Some(&KEY)).unwrap();
    assert!(e.fully_encrypted().unwrap());
    check(&mut e, n + 1, "reopened");
}

#[test]
fn encrypt_refuses_an_encrypted_file() {
    let t = TempDb::new("encrypt-twice");
    let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &KEY, 0, 0, 0, 0).unwrap();
    assert!(e.encrypt(&KEY, 0, 0, 0, 0).is_err());
}

#[test]
fn decrypt_needs_confirmation_resumes_after_reopen_and_leaves_no_keyslots() {
    use cryptand::convert::ConfirmDecrypt;
    let t = TempDb::new("decrypt");
    let n = 600;
    let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &KEY, 0, 0, 0, 0).unwrap();
    for i in 0..n {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
        if i % 150 == 149 {
            e.flush().unwrap();
        }
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();

    assert!(e.decrypt(ConfirmDecrypt::No).is_err(), "14 §8.3: decrypt MUST be confirmed");
    e.decrypt(ConfirmDecrypt::RemoveEncryption).unwrap();
    assert_eq!(e.convert_step().unwrap(), Step::More);
    e.close(true).unwrap();
    drop(e);

    // Half-decrypted: still `cipher = 1`, still needs the key, reads whole.
    assert!(Engine::open(&t.path, None).is_err());
    let mut e = Engine::open(&t.path, Some(&KEY)).unwrap();
    check(&mut e, n, "half-decrypted");
    e.decrypt(ConfirmDecrypt::RemoveEncryption).unwrap();
    let mut steps = 0;
    while e.convert_step().unwrap() == Step::More {
        steps += 1;
        assert!(steps < 20, "decrypt does not converge: {:?}", e.conversion().unwrap());
    }
    assert!(!e.fully_encrypted().unwrap());
    e.close(true).unwrap();
    drop(e);

    let mut e = Engine::open(&t.path, None).unwrap();
    assert_eq!(e.sb.cipher, 0);
    check(&mut e, n, "decrypted");
    drop(e);
    let bytes = std::fs::read(&t.path).unwrap();
    for slot in [0usize, 8192] {
        assert!(bytes[slot + 3512..slot + 3512 + 576].iter().all(|&b| b == 0), "keyslots left in slot at {slot}");
        // 14 §6.2: with `cipher = 0`, `sb_mac` is written as zero.
        assert!(bytes[slot + 296..slot + 328].iter().all(|&b| b == 0), "sb_mac left in slot at {slot}");
    }
}

#[test]
fn rotate_master_key_rekeys_everything_and_drops_the_old_keys() {
    use cryptand::keyapi::KeyApi;
    use cryptand::rotate::rotate_master_key;
    let (k1, k2, k3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let t = TempDb::new("rotate");
    let n = 600;
    let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &k1, 0, 0, 0, 0).unwrap();
    for i in 0..n {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
        if i % 150 == 149 {
            e.flush().unwrap();
        }
    }
    e.add_key(&k2, 0, 0, 0, 0, "second").unwrap();
    let before = *e.keys.as_ref().unwrap().master_key();
    let mut e = rotate_master_key(e, &k3, 0, 0, 0, 0).unwrap();
    assert_ne!(*e.keys.as_ref().unwrap().master_key(), before, "the master key did not change");
    check(&mut e, n, "rotated");
    e.put(T, &Value::NitriteId(n), &value(n)).unwrap();
    e.close(true).unwrap();
    drop(e);
    for old in [k1, k2] {
        assert!(matches!(Engine::open(&t.path, Some(&old)), Err(cryptand::Error::CannotUnlock)));
    }
    let mut e = Engine::open(&t.path, Some(&k3)).unwrap();
    check(&mut e, n + 1, "reopened after rotation");
}

#[test]
fn rotate_a_half_encrypted_file() {
    use cryptand::rotate::rotate_master_key;
    let t = TempDb::new("rotate-half");
    let n = 300;
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    for i in 0..n {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
    }
    e.flush().unwrap();
    e.encrypt(&KEY, 0, 0, 0, 0).unwrap();
    for i in n..2 * n {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
    }
    let mut e = rotate_master_key(e, &[4u8; 32], 0, 0, 0, 0).unwrap();
    check(&mut e, 2 * n, "half-encrypted, rotated");
    while e.convert_step().unwrap() == Step::More {}
    check(&mut e, 2 * n, "then converted");
}

/// F-072 g: a vector region is found through its descriptor, re-laid by
/// conversion both ways and re-sealed by rotation.
#[test]
fn vector_regions_convert_and_rotate() {
    use cryptand::catalog::TreeDescriptor;
    use cryptand::convert::ConfirmDecrypt;
    use cryptand::rotate::rotate_master_key;
    use cryptand::value::NumType;
    use cryptand::vector::{DType, Region};
    let t = TempDb::new("region-convert");
    let slots = 3000u64; // > 170 chunks at 4 KiB: the chunked layout needs more pages
    let vec_of = |s: u64| vec![s as f32, -(s as f32), 0.5, 1.0];
    let region_of = |e: &mut Engine| {
        let d = e.catalog.get(&mut e.pager, "idx:c:v:vector").unwrap().unwrap();
        Region::open(&mut e.pager, d.param_u64("vector_region").unwrap()).unwrap()
    };
    let read_all = |e: &mut Engine, what: &str, encrypted: bool| {
        let r = region_of(e);
        assert_eq!(r.encrypted, encrypted, "{what}");
        for s in (1..slots).step_by(7) {
            assert_eq!(r.read_slot(&mut e.pager, s).unwrap(), vec_of(s), "{what}: slot {s}");
        }
    };
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    for i in 0..100 {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
    }
    let mut r = Region::create(&mut e.pager, 4, DType::F32, slots).unwrap();
    for s in (1..slots).step_by(7) {
        r.write_slot(&mut e.pager, s, &vec_of(s)).unwrap();
    }
    let params = vec![("vector_region".to_string(), Value::int(NumType::U64, r.start_page as i128))];
    let d = TreeDescriptor::create(T + 1, "index", Some("c"), None, None, 0, params, 0);
    e.catalog.put(&mut e.pager, "idx:c:v:vector", &d).unwrap();
    e.commit(Durability::Sync).unwrap();

    e.encrypt(&KEY, 0, 0, 0, 0).unwrap();
    assert!(e.conversion().unwrap().remaining > 0);
    while e.convert_step().unwrap() == Step::More {}
    assert!(e.fully_encrypted().unwrap(), "{:?}", e.conversion().unwrap());
    read_all(&mut e, "encrypted", true);

    let mut e = rotate_master_key(e, &[5u8; 32], 0, 0, 0, 0).unwrap();
    read_all(&mut e, "rotated", true);

    e.decrypt(ConfirmDecrypt::RemoveEncryption).unwrap();
    while e.convert_step().unwrap() == Step::More {}
    read_all(&mut e, "decrypted", false);
    check(&mut e, 100, "decrypted");
}

/// F-081: values whose pointers are still in the memtable (no flush before
/// `encrypt()`) survive the conversion, a rotation and a decrypt. The value-log
/// rewrite judged liveness from segments alone and retired their segment.
#[test]
fn memtable_held_values_survive_encrypt_rotate_decrypt() {
    use cryptand::convert::ConfirmDecrypt;
    use cryptand::rotate::rotate_master_key;
    let t = TempDb::new("memtable-convert");
    let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
    for i in 0..100 {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
    }
    e.commit(Durability::Sync).unwrap();
    e.encrypt(&KEY, 0, 0, 0, 0).unwrap();
    while e.convert_step().unwrap() == Step::More {}
    // More writes reuse the space a wrongly retired segment gave back.
    for i in 100..200 {
        e.put(T, &Value::NitriteId(i), &value(i)).unwrap();
    }
    e.flush().unwrap();
    check(&mut e, 200, "encrypted");
    let mut e = rotate_master_key(e, &[5u8; 32], 0, 0, 0, 0).unwrap();
    check(&mut e, 200, "rotated");
    e.decrypt(ConfirmDecrypt::RemoveEncryption).unwrap();
    while e.convert_step().unwrap() == Step::More {}
    check(&mut e, 200, "decrypted");
}
