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
