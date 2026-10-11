//! PLAN M4.2: the primitive KATs in `conformance/vectors/kat`, shared with
//! the Java and Dart suites. Rust calls crates, but through the same entry
//! points the format uses where cryptand wraps them.

use blake2::digest::{Mac, Update, VariableOutput};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use cryptand::security::{argon2id, hkdf_sha256, hmac_sha256};
use serde_json::Value;

fn rows(name: &str) -> Vec<Value> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/vectors/kat/").to_string() + name;
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let rows = v.as_array().unwrap().clone();
    assert!(!rows.is_empty(), "{p} is empty");
    rows
}

fn hex(r: &Value, k: &str) -> Vec<u8> {
    let s = r[k].as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn aead<C: KeyInit + Aead>(file: &str) {
    for (i, r) in rows(file).iter().enumerate() {
        let (key, nonce, aad, msg, ct) = (hex(r, "key"), hex(r, "nonce"), hex(r, "aad"), hex(r, "msg"), hex(r, "ct"));
        let valid = hex(r, "valid") == [1];
        let c = C::new_from_slice(&key).unwrap();
        let n = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce);
        let got = c.decrypt(n, Payload { msg: &ct, aad: &aad });
        if valid {
            assert_eq!(got.as_deref(), Ok(&msg[..]), "{file} row {i} decrypt");
            assert_eq!(c.encrypt(n, Payload { msg: &msg, aad: &aad }).unwrap(), ct, "{file} row {i} encrypt");
        } else {
            assert!(got.is_err(), "{file} row {i}: invalid vector accepted");
        }
    }
}

#[test]
fn chacha20_poly1305_wycheproof() {
    aead::<ChaCha20Poly1305>("chacha20_poly1305.json");
}

#[test]
fn xchacha20_poly1305_wycheproof() {
    aead::<XChaCha20Poly1305>("xchacha20_poly1305.json");
}

#[test]
fn hkdf_sha256_wycheproof() {
    for (i, r) in rows("hkdf_sha256.json").iter().enumerate() {
        let okm = hex(r, "okm");
        assert_eq!(hkdf_sha256(&hex(r, "salt"), &hex(r, "ikm"), &hex(r, "info"), okm.len()), okm, "row {i}");
    }
}

#[test]
fn hmac_sha256_wycheproof() {
    for (i, r) in rows("hmac_sha256.json").iter().enumerate() {
        let tag = hex(r, "tag");
        assert_eq!(&hmac_sha256(&hex(r, "key"), &hex(r, "msg"))[..tag.len()], &tag[..], "row {i}");
    }
}

#[test]
fn blake2b_reference_keyed() {
    for (i, r) in rows("blake2b_keyed.json").iter().enumerate() {
        let mut m = <blake2::Blake2bMac512 as Mac>::new_from_slice(&hex(r, "key")).unwrap();
        Mac::update(&mut m, &hex(r, "msg"));
        assert_eq!(m.finalize().into_bytes().to_vec(), hex(r, "tag"), "row {i}");
    }
    // Unkeyed, variable output: the path Argon2's H' takes.
    for (i, r) in rows("blake2b_unkeyed.json").iter().enumerate() {
        let d = hex(r, "digest");
        let mut h = blake2::Blake2bVar::new(d.len()).unwrap();
        h.update(&hex(r, "msg"));
        let mut out = vec![0u8; d.len()];
        h.finalize_variable(&mut out).unwrap();
        assert_eq!(out, d, "unkeyed row {i}");
    }
}

#[test]
fn argon2id_rfc9106_and_reference() {
    for (i, r) in rows("argon2id.json").iter().enumerate() {
        let n = |k: &str| r[k].as_u64().unwrap() as u32;
        let tag = hex(r, "tag");
        let got = argon2id(&hex(r, "password"), &hex(r, "salt"), &hex(r, "secret"), &hex(r, "ad"),
                           n("t"), n("m"), n("p"), tag.len()).unwrap();
        assert_eq!(got, tag, "row {i} ({})", r["source"]);
    }
}
