//! `14-security.md` §3.3, §3.4 and §4.2 — subkey derivation, the nonce
//! construction and the keyslot layout. Four primitives only, all named to the
//! parameter by `00-conventions.md` §1.1, so they come from published crates
//! rather than from this file.

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{corrupt, Result};

pub const INFO_PREFIX: &str = "cryptand/v1/";

/// HKDF-SHA256, exposed raw so the RFC 5869 test vector can be checked against
/// the same code path the subkeys use.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("HKDF output length within 255 * 32");
    out
}

/// §3.4 — never use the master key directly. `database_uuid` as the salt is
/// what makes two files with the same password have different content keys.
pub fn subkey(master_key: &[u8], database_uuid: &[u8; 16], purpose: &str) -> [u8; 32] {
    let mut info = INFO_PREFIX.as_bytes().to_vec();
    info.extend_from_slice(purpose.as_bytes());
    let out = hkdf_sha256(database_uuid, master_key, &info, 32);
    out.try_into().unwrap()
}

/// §4.2 — 24 bytes, little-endian: domain, counter, object_id, and a 56-bit
/// offset.
pub fn nonce(domain: u8, counter: u64, object_id: u64, offset: u64) -> Result<[u8; 24]> {
    if offset >= 1u64 << 56 {
        return corrupt("nonce offset does not fit 56 bits");
    }
    let mut n = [0u8; 24];
    n[0] = domain;
    n[1..9].copy_from_slice(&counter.to_le_bytes());
    n[9..17].copy_from_slice(&object_id.to_le_bytes());
    n[17..24].copy_from_slice(&offset.to_le_bytes()[..7]);
    Ok(n)
}

/// §4.1 — the reservation watermark. A writer publishes `persisted + GAP`
/// durably before allocating anything, and never reaches the published value.
pub const NONCE_GAP: u64 = 1 << 20;

/// §3.3 — the keyslot, 4 x 144 bytes at superblock offset 3512.
pub mod keyslot {
    pub const SIZE: usize = 144;
    pub const COUNT: usize = 4;
    pub const OFFSET_IN_SUPERBLOCK: usize = 3512;

    pub const STATE: usize = 0;
    pub const KDF: usize = 1;
    pub const LABEL_LEN: usize = 2;
    pub const T_COST: usize = 4;
    pub const M_COST_KIB: usize = 8;
    pub const PARALLELISM: usize = 12;
    pub const SALT: usize = 16;
    pub const WRAP_NONCE: usize = 48;
    pub const WRAPPED_KEY: usize = 72;
    pub const WRAP_TAG: usize = 104;
    pub const LABEL: usize = 120;
}

/// Argon2id (RFC 9106) with the optional secret and associated data, which the
/// keyslot's AAD path needs.
#[allow(clippy::too_many_arguments)]
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
    tag_len: usize,
) -> Result<Vec<u8>> {
    let mut b = ParamsBuilder::new();
    b.m_cost(m_cost_kib).t_cost(t_cost).p_cost(parallelism).output_len(tag_len);
    if !ad.is_empty() {
        let data = argon2::AssociatedData::new(ad)
            .map_err(|e| crate::Corrupt(format!("argon2 associated data: {e}")))?;
        b.data(data);
    }
    let params = b.build().map_err(|e| crate::Corrupt(format!("argon2 params: {e}")))?;
    let a = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|e| crate::Corrupt(format!("argon2 secret: {e}")))?
    };
    let mut out = vec![0u8; tag_len];
    a.hash_password_into(password, salt, &mut out)
        .map_err(|e| crate::Corrupt(format!("argon2: {e}")))?;
    Ok(out)
}

/// RFC 9106 §3.2 step 1's `H_0`, the 64-byte prehash. Computed here so the
/// vector's intermediate can be checked and not only its tag -- a wrong `H_0`
/// and a wrong tag are different mistakes.
#[allow(clippy::too_many_arguments)]
pub fn argon2_h0(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
    tag_len: u32,
) -> [u8; 64] {
    let mut h = Blake2bVar::new(64).unwrap();
    let mut put = |v: u32| h.update(&v.to_le_bytes());
    put(parallelism);
    put(tag_len);
    put(m_cost_kib);
    put(t_cost);
    put(0x13); // version
    put(2); // Argon2id
    for field in [password, salt, secret, ad] {
        h.update(&(field.len() as u32).to_le_bytes());
        h.update(field);
    }
    let mut out = [0u8; 64];
    h.finalize_variable(&mut out).unwrap();
    out
}
