//! `14-security.md` §3.3, §3.4 and §4.2 — subkey derivation, the nonce
//! construction and the keyslot layout. Four primitives only, all named to the
//! parameter by `00-conventions.md` §1.1, so they come from published crates
//! rather than from this file.

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use blake2::digest::{Update, VariableOutput};
#[allow(unused_imports)]
use hmac::digest::Update as _;
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

/// The Poly1305 tag XChaCha20-Poly1305 appends (`14-security.md` §5.2).
pub const AEAD_TAG_BYTES: usize = 16;

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
            .map_err(|e| crate::Error::Corrupt(format!("argon2 associated data: {e}")))?;
        b.data(data);
    }
    let params = b.build().map_err(|e| crate::Error::Corrupt(format!("argon2 params: {e}")))?;
    let a = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|e| crate::Error::Corrupt(format!("argon2 secret: {e}")))?
    };
    let mut out = vec![0u8; tag_len];
    a.hash_password_into(password, salt, &mut out)
        .map_err(|e| crate::Error::Corrupt(format!("argon2: {e}")))?;
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

// ---------------------------------------------------------------------------
// The rest of `14-security.md`: keyslots, the superblock MAC, AEAD over page
// payloads and value-log records, and the key ring that holds the subkeys.
// ---------------------------------------------------------------------------

use crate::container::{sb as sboff, Superblock, PAGE_HEADER_BYTES};
use crate::error::Error;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hmac::{Mac, SimpleHmac};

/// §4.2's domains.
pub mod domain {
    pub const PAGE: u8 = 1;
    pub const VLOG: u8 = 2;
    pub const KEY_WRAP: u8 = 3;
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    // The OS CSPRNG, via the AEAD stack's own `OsRng`.
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut b = [0u8; N];
    chacha20poly1305::aead::OsRng.fill_bytes(&mut b);
    b
}

/// §2 — a constant-time tag comparison. A byte-by-byte early-exit compare on a
/// Poly1305 or HMAC tag is a forgery oracle.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <SimpleHmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC key any length");
    Mac::update(&mut m, msg);
    m.finalize().into_bytes().into()
}

/// §3.3 — one keyslot.
#[derive(Clone, Debug)]
pub struct Keyslot {
    pub occupied: bool,
    pub kdf: u8,
    pub t_cost: u32,
    pub m_cost_kib: u32,
    pub parallelism: u32,
    pub salt: [u8; 32],
    pub wrap_nonce: [u8; 24],
    pub wrapped_key: [u8; 32],
    pub wrap_tag: [u8; 16],
    pub label: String,
}

impl Keyslot {
    pub fn parse(b: &[u8]) -> Result<Keyslot> {
        use keyslot as k;
        let state = b[k::STATE];
        if state > 1 {
            return corrupt(format!("keyslot state {state} is neither 0 nor 1"));
        }
        let label_len = (b[k::LABEL_LEN] as usize).min(16);
        Ok(Keyslot {
            occupied: state == 1,
            kdf: b[k::KDF],
            t_cost: u32::from_le_bytes(b[k::T_COST..k::T_COST + 4].try_into().unwrap()),
            m_cost_kib: u32::from_le_bytes(b[k::M_COST_KIB..k::M_COST_KIB + 4].try_into().unwrap()),
            parallelism: u32::from_le_bytes(
                b[k::PARALLELISM..k::PARALLELISM + 4].try_into().unwrap(),
            ),
            salt: b[k::SALT..k::SALT + 32].try_into().unwrap(),
            wrap_nonce: b[k::WRAP_NONCE..k::WRAP_NONCE + 24].try_into().unwrap(),
            wrapped_key: b[k::WRAPPED_KEY..k::WRAPPED_KEY + 32].try_into().unwrap(),
            wrap_tag: b[k::WRAP_TAG..k::WRAP_TAG + 16].try_into().unwrap(),
            label: String::from_utf8_lossy(&b[k::LABEL..k::LABEL + label_len]).to_string(),
        })
    }

    pub fn encode(&self) -> [u8; keyslot::SIZE] {
        use keyslot as k;
        let mut b = [0u8; keyslot::SIZE];
        b[k::STATE] = u8::from(self.occupied);
        b[k::KDF] = self.kdf;
        let label = self.label.as_bytes();
        let n = label.len().min(16);
        b[k::LABEL_LEN] = n as u8;
        b[k::T_COST..k::T_COST + 4].copy_from_slice(&self.t_cost.to_le_bytes());
        b[k::M_COST_KIB..k::M_COST_KIB + 4].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        b[k::PARALLELISM..k::PARALLELISM + 4].copy_from_slice(&self.parallelism.to_le_bytes());
        b[k::SALT..k::SALT + 32].copy_from_slice(&self.salt);
        b[k::WRAP_NONCE..k::WRAP_NONCE + 24].copy_from_slice(&self.wrap_nonce);
        b[k::WRAPPED_KEY..k::WRAPPED_KEY + 32].copy_from_slice(&self.wrapped_key);
        b[k::WRAP_TAG..k::WRAP_TAG + 16].copy_from_slice(&self.wrap_tag);
        b[k::LABEL..k::LABEL + n].copy_from_slice(&label[..n]);
        b
    }
}

/// §3.2 — a writer MUST reject these when *creating* a keyslot. On *open* it
/// MUST use whatever the slot says; the superblock MAC is what prevents an
/// attacker weakening them.
pub fn check_kdf_params(t_cost: u32, m_cost_kib: u32, parallelism: u32) -> Result<()> {
    if t_cost < 2 || m_cost_kib < 16384 || parallelism < 1 {
        return crate::error::invalid(
            "Argon2id parameters below the floor of t_cost 2 / m_cost 16384 KiB / parallelism 1",
        );
    }
    Ok(())
}

/// §3.1 — the KEK derives from the password; the master key is random and is
/// only ever wrapped by it, so a password change rewrites 32 bytes rather than
/// the database.
pub fn derive_kek(password: &[u8], slot: &Keyslot) -> Result<[u8; 32]> {
    if slot.kdf == 0 {
        // A key the host already holds: the 32 supplied bytes *are* the KEK.
        if password.len() != 32 {
            return crate::error::invalid("a raw (kdf = 0) keyslot takes exactly 32 key bytes");
        }
        return Ok(password.try_into().unwrap());
    }
    let out = argon2id(
        password,
        &slot.salt,
        &[],
        &[],
        slot.t_cost,
        slot.m_cost_kib,
        slot.parallelism,
        32,
    )?;
    Ok(out.try_into().unwrap())
}

/// §3.3 — AAD for the wrap is `database_uuid || slot_index`, which binds a slot
/// to its file: a keyslot lifted from another database does not unwrap here.
pub fn wrap_aad(database_uuid: &[u8; 16], slot_index: u8) -> Vec<u8> {
    let mut v = database_uuid.to_vec();
    v.push(slot_index);
    v
}

pub fn wrap_master_key(
    master_key: &[u8; 32],
    kek: &[u8; 32],
    database_uuid: &[u8; 16],
    slot_index: u8,
) -> Result<([u8; 24], [u8; 32], [u8; 16])> {
    let nonce = random_bytes::<24>();
    let c = XChaCha20Poly1305::new(kek.into());
    let out = c
        .encrypt(
            &nonce.into(),
            Payload { msg: master_key, aad: &wrap_aad(database_uuid, slot_index) },
        )
        .map_err(|_| Error::Corrupt("key wrap failed".into()))?;
    Ok((nonce, out[..32].try_into().unwrap(), out[32..].try_into().unwrap()))
}

pub fn unwrap_master_key(
    slot: &Keyslot,
    kek: &[u8; 32],
    database_uuid: &[u8; 16],
    slot_index: u8,
) -> Option<[u8; 32]> {
    let mut ct = slot.wrapped_key.to_vec();
    ct.extend_from_slice(&slot.wrap_tag);
    let c = XChaCha20Poly1305::new(kek.into());
    let plain = c
        .decrypt(
            &slot.wrap_nonce.into(),
            Payload { msg: &ct, aad: &wrap_aad(database_uuid, slot_index) },
        )
        .ok();
    // §11 — the AEAD hands back the master key in a fresh heap buffer. Copying
    // it into the array and letting the `Vec` drop returns that allocation to
    // the allocator with the key still in it.
    plain.and_then(|mut v| {
        let out: Option<[u8; 32]> = v.as_slice().try_into().ok();
        secure_zero(&mut v);
        out
    })
}

/// §6.2's message: the superblock with `sb_mac` itself zeroed.
pub fn superblock_mac_message(image: &[u8]) -> Vec<u8> {
    let mut m = image[..4092].to_vec();
    m[sboff::SB_MAC..sboff::SB_MAC + 32].fill(0);
    m
}

/// Overwrites `b` with zeros in a way the optimizer is not free to remove.
///
/// `14-security.md` §11 makes zeroing a MUST, and a plain `fill(0)` on a buffer
/// that is about to be dropped is a *dead store*: nothing reads it afterwards,
/// so the compiler is entitled to delete the writes entirely and the key stays
/// in the freed page. `black_box` makes the buffer opaque to the optimizer —
/// it must assume the zeros are observed — and the fence stops the writes being
/// sunk past the end of the scope.
///
/// The `zeroize` crate does this with `write_volatile`. That needs `unsafe`,
/// and this crate has none; `black_box` is the safe approximation and is a
/// hint rather than a guarantee, which is the honest description of what any
/// zeroing achieves on a runtime that may have already copied the bytes.
pub fn secure_zero(b: &mut [u8]) {
    b.fill(0);
    std::hint::black_box(&*b);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// The unlocked key material for one file.
///
/// `Clone` because the page cipher lives in the pager (`14-security.md` §5.2 —
/// the copy-on-write trees write pages without an engine in scope) while the
/// value-log cipher lives in the engine. Both copies are zeroized by
/// [`crate::engine::Engine::close`].
#[derive(Clone)]
pub struct KeyRing {
    master_key: [u8; 32],
    page_key: [u8; 32],
    vlog_key: [u8; 32],
    sbmac_key: [u8; 32],
    pub database_uuid: [u8; 16],
    pub slot_index: u8,
}

impl KeyRing {
    pub fn from_master(master_key: [u8; 32], database_uuid: [u8; 16], slot_index: u8) -> KeyRing {
        KeyRing {
            page_key: subkey(&master_key, &database_uuid, "page"),
            vlog_key: subkey(&master_key, &database_uuid, "vlog"),
            sbmac_key: subkey(&master_key, &database_uuid, "sbmac"),
            master_key,
            database_uuid,
            slot_index,
        }
    }

    /// §3.3 — unwrapping tries each occupied slot in order and stops at the
    /// first whose tag verifies. A failure across all slots is "wrong key",
    /// and an implementation MUST NOT distinguish "no such slot" from "bad
    /// password" in what it reports.
    pub fn unlock(sb: &Superblock, password: &[u8]) -> Result<KeyRing> {
        for i in 0..keyslot::COUNT {
            let raw = &sb.keyslots[i * keyslot::SIZE..(i + 1) * keyslot::SIZE];
            let slot = Keyslot::parse(raw)?;
            if !slot.occupied {
                continue;
            }
            let Ok(mut kek) = derive_kek(password, &slot) else { continue };
            let unwrapped = unwrap_master_key(&slot, &kek, &sb.database_uuid, i as u8);
            // §11 — the KEK is key material in its own right and outlives its
            // use by the length of this loop body unless it is cleared here.
            secure_zero(&mut kek);
            if let Some(mut mk) = unwrapped {
                let ring = KeyRing::from_master(mk, sb.database_uuid, i as u8);
                secure_zero(&mut mk);
                return Ok(ring);
            }
        }
        Err(Error::CannotUnlock)
    }

    pub fn master_key(&self) -> &[u8; 32] {
        &self.master_key
    }

    /// §6.2 — a writer holding the key writes `sb_mac` on **every** superblock
    /// write, before the CRC.
    pub fn seal_superblock(&self, image: &mut [u8; crate::container::SUPERBLOCK_BYTES]) {
        image[sboff::SB_MAC..sboff::SB_MAC + 32].fill(0);
        let mac = hmac_sha256(&self.sbmac_key, &superblock_mac_message(image));
        image[sboff::SB_MAC..sboff::SB_MAC + 32].copy_from_slice(&mac);
        let crc = crate::hash::crc32c(&image[0..sboff::CHECKSUM]);
        image[sboff::CHECKSUM..sboff::CHECKSUM + 4].copy_from_slice(&crc.to_le_bytes());
    }

    /// §6.2 — verified immediately after choosing a slot and **before acting
    /// on any other superblock field**, in constant time. A mismatch is
    /// tampering, reported distinctly from a CRC failure.
    pub fn verify_superblock(&self, sb: &Superblock) -> Result<()> {
        let mut image = sb.encode();
        image[sboff::SB_MAC..sboff::SB_MAC + 32].copy_from_slice(&sb.sb_mac);
        let want = hmac_sha256(&self.sbmac_key, &superblock_mac_message(&image));
        if !constant_time_eq(&want, &sb.sb_mac) {
            return Err(Error::Tamper("superblock MAC mismatch".into()));
        }
        Ok(())
    }

    /// §5.2 — AAD is the 40-byte page header with `checksum` zeroed, so
    /// `page_type`, `flags`, `tree_id`, `commit_id`, `extent_pages`,
    /// `payload_len` and `nonce` cannot be edited without detection.
    pub fn page_aad(header: &[u8]) -> Vec<u8> {
        let mut a = header[..PAGE_HEADER_BYTES].to_vec();
        a[0..4].fill(0);
        a
    }

    pub fn encrypt_page(&self, page_id: u64, counter: u64, header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = nonce(domain::PAGE, counter, page_id, 0)?;
        XChaCha20Poly1305::new(&self.page_key.into())
            .encrypt(&n.into(), Payload { msg: plaintext, aad: &KeyRing::page_aad(header) })
            .map_err(|_| Error::Corrupt("page encryption failed".into()))
    }

    pub fn decrypt_page(&self, page_id: u64, counter: u64, header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let n = nonce(domain::PAGE, counter, page_id, 0)?;
        XChaCha20Poly1305::new(&self.page_key.into())
            .decrypt(&n.into(), Payload { msg: ciphertext, aad: &KeyRing::page_aad(header) })
            .map_err(|_| Error::Tamper(format!("page {page_id} AEAD tag mismatch")))
    }

    /// §5.3 — `aad = u64le(vlog_segment_id) || u64le(record_offset) ||
    /// u32le(tree_id)`, plaintext `key_len || key || value_len || value`.
    pub fn vlog_aad(segment_id: u64, record_offset: u64, tree_id: u32) -> Vec<u8> {
        let mut a = Vec::with_capacity(20);
        a.extend_from_slice(&segment_id.to_le_bytes());
        a.extend_from_slice(&record_offset.to_le_bytes());
        a.extend_from_slice(&tree_id.to_le_bytes());
        a
    }

    pub fn encrypt_vlog(
        &self,
        segment_id: u64,
        record_offset: u64,
        tree_id: u32,
        counter: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<Vec<u8>> {
        let mut pt = Vec::with_capacity(key.len() + value.len() + 10);
        crate::varint::put_uvar(&mut pt, key.len() as u64);
        pt.extend_from_slice(key);
        crate::varint::put_uvar(&mut pt, value.len() as u64);
        pt.extend_from_slice(value);
        let n = nonce(domain::VLOG, counter, segment_id, record_offset)?;
        XChaCha20Poly1305::new(&self.vlog_key.into())
            .encrypt(
                &n.into(),
                Payload { msg: &pt, aad: &KeyRing::vlog_aad(segment_id, record_offset, tree_id) },
            )
            .map_err(|_| Error::Corrupt("value-log record encryption failed".into()))
    }

    /// Decrypts one record given the whole stored record bytes.
    pub fn decrypt_vlog(
        &self,
        segment_id: u64,
        record_offset: u64,
        tree_id: u32,
        counter: u64,
        stored: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (len, n) = crate::varint::get_uvar(stored)?;
        let body = &stored[n..n + len as usize];
        // `nonce` (8) then `tree_id` (4) are in the clear; the trailing 4 are
        // the CRC over the stored bytes.
        let ct = &body[12..body.len() - 4];
        let nn = nonce(domain::VLOG, counter, segment_id, record_offset)?;
        let pt = XChaCha20Poly1305::new(&self.vlog_key.into())
            .decrypt(
                &nn.into(),
                Payload { msg: ct, aad: &KeyRing::vlog_aad(segment_id, record_offset, tree_id) },
            )
            .map_err(|_| Error::Tamper("value-log record AEAD tag mismatch".into()))?;
        let (klen, kn) = crate::varint::get_uvar(&pt)?;
        let ks = kn;
        let ke = ks + klen as usize;
        let (vlen, vn) = crate::varint::get_uvar(&pt[ke..])?;
        let vs = ke + vn;
        Ok((pt[ks..ke].to_vec(), pt[vs..vs + vlen as usize].to_vec()))
    }

    /// §5.4 — blobs and vector regions run raw payload across interior pages,
    /// so each is encrypted per page-sized chunk rather than as one stream.
    pub fn chunk_nonce(&self, head_page_id: u64, counter: u64, index: u64) -> Result<[u8; 24]> {
        nonce(domain::PAGE, counter, head_page_id, index)
    }

    pub fn encrypt_chunk(&self, head_page_id: u64, counter: u64, index: u64, pt: &[u8]) -> Result<Vec<u8>> {
        let n = self.chunk_nonce(head_page_id, counter, index)?;
        let mut aad = head_page_id.to_le_bytes().to_vec();
        aad.extend_from_slice(&index.to_le_bytes());
        XChaCha20Poly1305::new(&self.page_key.into())
            .encrypt(&n.into(), Payload { msg: pt, aad: &aad })
            .map_err(|_| Error::Corrupt("extent chunk encryption failed".into()))
    }

    pub fn decrypt_chunk(&self, head_page_id: u64, counter: u64, index: u64, ct: &[u8]) -> Result<Vec<u8>> {
        let n = self.chunk_nonce(head_page_id, counter, index)?;
        let mut aad = head_page_id.to_le_bytes().to_vec();
        aad.extend_from_slice(&index.to_le_bytes());
        XChaCha20Poly1305::new(&self.page_key.into())
            .decrypt(&n.into(), Payload { msg: ct, aad: &aad })
            .map_err(|_| Error::Tamper("extent chunk AEAD tag mismatch".into()))
    }

    /// §11 — zero the master key and every subkey on `close()`.
    pub fn zeroize(&mut self) {
        secure_zero(&mut self.master_key);
        secure_zero(&mut self.page_key);
        secure_zero(&mut self.vlog_key);
        secure_zero(&mut self.sbmac_key);
    }
}

/// §11 — "a runtime with deterministic destruction SHOULD bind key material to
/// a type that zeroes on release".
///
/// `Engine::close` zeroes the two rings it knows about: the engine's and the
/// pager's. It is not the only way a ring dies. An `Engine` dropped without
/// `close` — a `?` on any error between `open` and `close`, a panic unwinding
/// through the caller, a test that just lets the value fall out of scope — took
/// its keys to the allocator intact, and so did every `clone` made anywhere
/// else. Zeroing on drop covers those without the caller having to know.
impl Drop for KeyRing {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Builds the four keyslots for a fresh encrypted file, §3.3.
pub fn make_keyslot(
    master_key: &[u8; 32],
    database_uuid: &[u8; 16],
    slot_index: u8,
    password: &[u8],
    kdf: u8,
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
    label: &str,
) -> Result<Keyslot> {
    if kdf == 1 {
        check_kdf_params(t_cost, m_cost_kib, parallelism)?;
    }
    let mut slot = Keyslot {
        occupied: true,
        kdf,
        // §3.3: for `kdf = 0` the cost fields MUST be written as zero.
        t_cost: if kdf == 0 { 0 } else { t_cost },
        m_cost_kib: if kdf == 0 { 0 } else { m_cost_kib },
        parallelism: if kdf == 0 { 0 } else { parallelism },
        salt: if kdf == 0 { [0u8; 32] } else { random_bytes::<32>() },
        wrap_nonce: [0u8; 24],
        wrapped_key: [0u8; 32],
        wrap_tag: [0u8; 16],
        label: label.to_string(),
    };
    let mut kek = derive_kek(password, &slot)?;
    let wrapped_result = wrap_master_key(master_key, &kek, database_uuid, slot_index);
    secure_zero(&mut kek);
    let (nonce, wrapped, tag) = wrapped_result?;
    slot.wrap_nonce = nonce;
    slot.wrapped_key = wrapped;
    slot.wrap_tag = tag;
    Ok(slot)
}
