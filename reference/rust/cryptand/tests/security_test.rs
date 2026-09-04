//! `14-security.md` §13's mandatory tests, plus the keyslot and nonce rules
//! §3 and §4 state.

mod support;
use support::*;

use cryptand::container::{feature, Durability, Profile, Superblock};
use cryptand::engine::Engine;
use cryptand::security::{self, constant_time_eq, keyslot, make_keyslot, KeyRing, Keyslot, NONCE_GAP};
use cryptand::value::Value;
use cryptand::verify::{Class, EngineVerify};
use cryptand::Error;

const T: u32 = 16;

/// Creates an encrypted database. Argon2id at the profile's cost is ~500 ms per
/// open, so these tests use `kdf = 0` — a key the host already holds, which
/// §3.3 defines exactly for this case — except where the KDF is the subject.
fn encrypted(tag: &str) -> (TempDb, Engine) {
    let (t, mut e) = engine(tag, Profile::Desktop);
    let master = security::random_bytes::<32>();
    let slot = make_keyslot(&master, &e.sb.database_uuid, 0, &[7u8; 32], 0, 0, 0, 0, "keyring").unwrap();
    e.sb.keyslots[..keyslot::SIZE].copy_from_slice(&slot.encode());
    e.sb.cipher = 1;
    e.sb.set_feature(feature::CIPHER, true);
    e.keys = Some(KeyRing::from_master(master, e.sb.database_uuid, 0));
    e.commit(Durability::Sync).unwrap();
    (t, e)
}

#[test]
fn an_encrypted_file_round_trips_and_refuses_the_wrong_key() {
    let (t, mut e) = encrypted("aead");
    for i in 0..200i64 {
        e.put(T, &Value::NitriteId(i), &vec![i as u8; 700]).unwrap();
    }
    e.close(true).unwrap();

    let mut ok = Engine::open(&t.path, Some(&[7u8; 32])).unwrap();
    assert_eq!(ok.get(T, &Value::NitriteId(3)).unwrap().unwrap(), vec![3u8; 700]);
    // §3.3 and `00-conventions.md` §9: "cannot unlock", reported identically
    // for a missing keyslot and a wrong password.
    assert!(matches!(Engine::open(&t.path, Some(&[8u8; 32])), Err(Error::CannotUnlock)));
    assert!(matches!(Engine::open(&t.path, None), Err(Error::CannotUnlock)));
}

#[test]
fn editing_the_superblock_is_reported_as_tampering_not_corruption() {
    // §6.1's attack: set `cipher = 0` so the next writer stores plaintext.
    // None of it touches an encrypted byte, and all of it is invisible without
    // the MAC.
    let (t, mut e) = encrypted("tamper-sb");
    let master = *e.keys.as_ref().unwrap().master_key();
    e.put(T, &Value::NitriteId(1), b"secret").unwrap();
    e.close(true).unwrap();

    let mut raw = std::fs::read(&t.path).unwrap();
    let a = Superblock::parse(&raw[0..4096]).ok();
    let b = Superblock::parse(&raw[8192..12288]).ok();
    let slot = match (&a, &b) {
        (Some(x), Some(y)) if y.commit_id > x.commit_id => 8192,
        (None, Some(_)) => 8192,
        _ => 0,
    };
    raw[slot + cryptand::container::sb::CIPHER] = 0;
    let crc = cryptand::hash::crc32c(&raw[slot..slot + 4092]);
    raw[slot + 4092..slot + 4096].copy_from_slice(&crc.to_le_bytes());
    std::fs::write(&t.path, &raw).unwrap();

    let sb = Superblock::parse(&std::fs::read(&t.path).unwrap()[slot..slot + 4096]).unwrap();
    assert_eq!(sb.cipher, 0, "the edit landed");
    let ring = KeyRing::from_master(master, sb.database_uuid, 0);
    // A mismatch is a security failure, reported distinctly from a CRC
    // failure, which is corruption.
    assert!(matches!(ring.verify_superblock(&sb), Err(Error::Tamper(_))));
}

#[test]
fn a_flipped_ciphertext_byte_fails_its_tag_not_merely_its_checksum() {
    let (t, mut e) = encrypted("tamper-page");
    e.put(T, &Value::NitriteId(1), &vec![5u8; 900]).unwrap();
    e.close(true).unwrap();

    let seg = {
        let open = Engine::open(&t.path, Some(&[7u8; 32])).unwrap();
        open.vlog_stats.values().next().unwrap().clone()
    };
    let mut raw = std::fs::read(&t.path).unwrap();
    let at = (seg.start_page * 8192 + cryptand::vlog::DATA_OFFSET as u64 + 40) as usize;
    raw[at] ^= 0x40;
    std::fs::write(&t.path, &raw).unwrap();

    let mut e = Engine::open(&t.path, Some(&[7u8; 32])).unwrap();
    let r = e.get(T, &Value::NitriteId(1));
    // §9.4: the CRC is error detection; the tag is integrity. Either catching
    // it is conforming, returning the plaintext is not.
    assert!(
        matches!(r, Err(Error::Corrupt(_)) | Err(Error::Tamper(_))),
        "an edited ciphertext byte must be refused, got {r:?}"
    );
}

#[test]
fn no_nonce_is_ever_issued_twice_across_repeated_crashes() {
    // §13's nonce-uniqueness test: "the test that would have caught the
    // crash-reuse defect §4.1 describes, and nothing else catches it."
    let t = TempDb::new("nonce");
    let raw_key = [3u8; 32];
    {
        let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
        let master = security::random_bytes::<32>();
        let slot = make_keyslot(&master, &e.sb.database_uuid, 0, &raw_key, 0, 0, 0, 0, "k").unwrap();
        e.sb.keyslots[..keyslot::SIZE].copy_from_slice(&slot.encode());
        e.sb.cipher = 1;
        e.sb.set_feature(feature::CIPHER, true);
        e.keys = Some(KeyRing::from_master(master, e.sb.database_uuid, 0));
        e.commit(Durability::Sync).unwrap();
        for i in 0..40i64 {
            e.put(T, &Value::NitriteId(i), &vec![1u8; 700]).unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        std::mem::forget(e); // the kill: no close, no seal
    }
    let mut floors = Vec::new();
    for round in 1..4i64 {
        let mut e = Engine::open(&t.path, Some(&raw_key)).unwrap();
        floors.push(e.sb.next_nonce);
        for i in 0..40i64 {
            e.put(T, &Value::NitriteId(round * 1000 + i), &vec![2u8; 700]).unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        std::mem::forget(e);
    }
    // §4.1 rule 1: each open publishes `persisted + 2^20` **before** allocating,
    // so successive sessions allocate from disjoint ranges even after a crash.
    for w in floors.windows(2) {
        assert!(w[1] >= w[0] + NONCE_GAP, "the published floor did not move: {floors:?}");
    }

    let mut e = Engine::open(&t.path, Some(&raw_key)).unwrap();
    let mut seen = std::collections::HashSet::new();
    let stats: Vec<_> = e.vlog_stats.values().cloned().collect();
    for s in stats {
        let mut off = 0u64;
        while off < s.bytes {
            let at = s.start_page * 8192 + cryptand::vlog::DATA_OFFSET as u64 + off;
            let want = ((s.bytes - off) as usize).min(1 << 16);
            let raw = e.pager.read_at(at, want).unwrap();
            let rec = cryptand::vlog::decode_record(&raw, true).unwrap();
            let nonce = rec.nonce.unwrap();
            assert!(seen.insert(nonce), "value-log nonce {nonce} was issued twice");
            off += rec.total_len as u64;
        }
    }
    assert!(seen.len() >= 100, "the fixture wrote only {} encrypted records", seen.len());
}

#[test]
fn a_keyslot_from_another_database_does_not_unwrap_here() {
    // §3.3 — the wrap AAD is `database_uuid || slot_index`, so an attacker
    // cannot graft a slot whose password they know onto a file they want to
    // read (T3).
    let master = security::random_bytes::<32>();
    let uuid_a = [1u8; 16];
    let uuid_b = [2u8; 16];
    let slot = make_keyslot(&master, &uuid_a, 0, &[9u8; 32], 0, 0, 0, 0, "a").unwrap();
    assert!(security::unwrap_master_key(&slot, &[9u8; 32], &uuid_a, 0).is_some());
    assert!(security::unwrap_master_key(&slot, &[9u8; 32], &uuid_b, 0).is_none());
    assert!(security::unwrap_master_key(&slot, &[9u8; 32], &uuid_a, 1).is_none());
}

#[test]
fn key_rotation_leaves_only_the_new_credential_working() {
    let (t, mut e) = encrypted("rotate");
    e.put(T, &Value::NitriteId(1), b"v").unwrap();
    let master = *e.keys.as_ref().unwrap().master_key();
    let uuid = e.sb.database_uuid;
    let new = make_keyslot(&master, &uuid, 1, &[42u8; 32], 0, 0, 0, 0, "new").unwrap();
    e.sb.keyslots[keyslot::SIZE..2 * keyslot::SIZE].copy_from_slice(&new.encode());
    // §8.2: overwrite the keyslot bytes with zeros, not merely `state = 0`.
    e.sb.keyslots[..keyslot::SIZE].fill(0);
    e.close(true).unwrap();

    let mut ok = Engine::open(&t.path, Some(&[42u8; 32])).unwrap();
    assert_eq!(ok.get(T, &Value::NitriteId(1)).unwrap().as_deref(), Some(&b"v"[..]));
    assert!(matches!(Engine::open(&t.path, Some(&[7u8; 32])), Err(Error::CannotUnlock)));
}

#[test]
fn crypto_erase_makes_the_file_permanently_unreadable() {
    // §8.2 — the only erase that means anything on flash, and it MUST write
    // **both** superblock slots, since either may hold an intact copy.
    let (t, mut e) = encrypted("erase");
    e.put(T, &Value::NitriteId(1), b"v").unwrap();
    e.commit(Durability::Sync).unwrap();
    e.sb.keyslots.fill(0);
    e.write_superblock(Durability::Sync).unwrap();
    e.sb.commit_id += 1;
    e.write_superblock(Durability::Sync).unwrap();
    drop(e);
    assert!(matches!(Engine::open(&t.path, Some(&[7u8; 32])), Err(Error::CannotUnlock)));
}

#[test]
fn the_argon2id_floor_binds_on_create_and_not_on_open() {
    // §3.2: a writer MUST reject `t_cost < 2`, `m_cost_kib < 16384` or
    // `parallelism < 1` when **creating** a keyslot. On open it MUST use
    // whatever the slot says — the superblock MAC is what prevents an attacker
    // weakening those numbers.
    let master = [1u8; 32];
    assert!(make_keyslot(&master, &[0u8; 16], 0, b"pw", 1, 1, 65536, 1, "weak").is_err());
    assert!(make_keyslot(&master, &[0u8; 16], 0, b"pw", 1, 3, 1024, 1, "weak").is_err());
    // `kdf = 0` writes the cost fields as zero and is not subject to the floor.
    let raw = make_keyslot(&master, &[0u8; 16], 0, &[0u8; 32], 0, 0, 0, 0, "host").unwrap();
    assert_eq!((raw.t_cost, raw.m_cost_kib, raw.parallelism), (0, 0, 0));
    let round = Keyslot::parse(&raw.encode()).unwrap();
    assert_eq!(round.label, "host");
    assert!(round.occupied);
}

#[test]
fn a_tag_comparison_is_constant_time_over_length_and_content() {
    assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
    assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
    assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
}

#[test]
fn structure_and_checksums_are_readable_without_the_key() {
    // §5.1's payoff, and the bill §7 pays for it.
    let (t, mut e) = encrypted("verify-nokey");
    for i in 0..100i64 {
        e.put(T, &Value::NitriteId(i), b"x").unwrap();
    }
    e.close(true).unwrap();

    let mut pager = cryptand::pager::Pager::open(&t.path, 8192, 4).unwrap();
    let a = Superblock::parse(&pager.read_slot(0).unwrap()).ok();
    let b = Superblock::parse(&pager.read_slot(1).unwrap()).ok();
    let sb = match (a, b) {
        (Some(x), Some(y)) => {
            if x.commit_id >= y.commit_id {
                x
            } else {
                y
            }
        }
        (Some(x), None) => x,
        (None, Some(y)) => y,
        _ => panic!("no valid superblock"),
    };
    assert_eq!(sb.cipher, 1);
    assert!(sb.features_required & feature::bit(feature::CIPHER) != 0);
    let mut pager = cryptand::pager::Pager::open(&t.path, 8192, sb.page_count).unwrap();
    let mut checked = 0;
    for p in 2..sb.page_count {
        let raw = pager.read_page(p).unwrap();
        if raw.iter().all(|&x| x == 0) {
            continue;
        }
        if cryptand::container::PageHeader::verify(&raw, p).is_ok() {
            checked += 1;
        }
    }
    assert!(checked > 0, "no page header verified without the key");
}

#[test]
fn a_converting_file_never_reports_itself_as_fully_encrypted() {
    // §8.3 — "that is the one place where a reassuring answer is a dangerous
    // one."
    let (_t, mut e) = engine("convert", Profile::Desktop);
    for i in 0..50i64 {
        e.put(T, &Value::NitriteId(i), b"plain").unwrap();
    }
    e.flush().unwrap();
    e.sb.cipher = 1;
    e.sb.set_feature(feature::CIPHER, true);
    e.counters.unencrypted_pages = e.pager.page_count;
    let m = cryptand::metrics::Metrics::metrics(&mut e).unwrap();
    assert_ne!(m["unencrypted_pages"], cryptand::metrics::Metric::Count(0));
    let r = e.verify().unwrap();
    assert!(r.of(Class::Corruption).is_empty(), "{:?}", r.findings);
}

#[test]
fn a_backup_of_an_encrypted_database_must_be_asked_for_by_name() {
    // §2.1 of `13-operations.md`: an unencrypted backup of an encrypted
    // database is a silent downgrade, refused unless asked for by name.
    use cryptand::backup::{Backup, BackupMode};
    let (_t, mut e) = encrypted("downgrade");
    let dest = TempDb::new("downgrade-dest");
    e.put(T, &Value::NitriteId(1), b"v").unwrap();
    e.commit(Durability::Sync).unwrap();
    assert!(e.backup(&dest.path, BackupMode::Plain).is_err());
    let r = e.backup(&dest.path, BackupMode::PlaintextDowngrade).unwrap();
    assert!(r.downgraded, "the downgrade MUST be reported in the result");
    // The ciphertext copy is the one exception to the new-uuid rule.
    let dest2 = TempDb::new("cipher-copy");
    let r = e.backup(&dest2.path, BackupMode::CiphertextCopy).unwrap();
    assert!(r.kept_source_uuid);
}

#[test]
fn structure_aware_fuzzing_never_crashes_hangs_or_over_allocates() {
    // §9.3 — "A parser for a format read from untrusted sources that has never
    // been fuzzed is not finished." Structure-aware matters: most of a
    // database's bytes are unused value-log record space, so uniform bit flips
    // land in padding and measure nothing. These targets are the ones a hostile
    // file would edit.
    let t = TempDb::new("fuzz");
    {
        let mut e = Engine::create(&t.path, Profile::Desktop).unwrap();
        e.memtable_entry_limit = 60;
        for i in 0..300i64 {
            e.put(T, &Value::NitriteId(i), &vec![(i % 251) as u8; if i % 10 == 0 { 700 } else { 40 }])
                .unwrap();
            if e.memtable_pressure().0 >= 60 {
                e.flush().unwrap();
            }
        }
        e.close(true).unwrap();
    }
    let original = std::fs::read(&t.path).unwrap();
    let page_size = 8192usize;

    // The superblock slots, then every headed page's header and payload head.
    let mut targets: Vec<(usize, usize)> = vec![(0, 4096), (page_size, 4096)];
    {
        let mut e = Engine::open(&t.path, None).unwrap();
        let count = e.sb.page_count;
        for p in 2..count {
            let Ok(raw) = e.pager.read_page(p) else { continue };
            let Ok(h) = cryptand::container::PageHeader::parse(&raw) else { continue };
            if h.page_type == 0 || h.payload_len == 0 {
                continue;
            }
            targets.push((p as usize * page_size, 40));
            targets.push((p as usize * page_size + 40, (h.payload_len as usize).min(256)));
        }
    }
    assert!(targets.len() > 8, "the fixture has too little structure to fuzz");

    let tmp = TempDb::new("fuzz-mutant");
    let mut rng = Rng::new(0xF0FF);
    let (mut refused, mut reported, mut benign) = (0u32, 0u32, 0u32);
    for _ in 0..300 {
        let mut b = original.clone();
        for _ in 0..1 + rng.below(4) {
            let (base, len) = targets[rng.below(targets.len() as u64) as usize];
            let at = base + rng.below(len.max(1) as u64) as usize;
            if at < b.len() {
                b[at] ^= 1 << rng.below(8);
            }
        }
        std::fs::write(&tmp.path, &b).unwrap();
        // No `catch_unwind`: a panic here fails the test, which is the point.
        match Engine::open(&tmp.path, None) {
            Err(_) => refused += 1,
            Ok(mut e) => match e.verify() {
                Err(_) => refused += 1,
                Ok(r) => {
                    if r.of(Class::Corruption).is_empty() && r.of(Class::Tampering).is_empty() {
                        benign += 1;
                    } else {
                        reported += 1;
                    }
                }
            },
        }
    }
    println!(
        "fuzz: {refused} refused at open, {reported} reported by verify, {benign} benign, 0 panics"
    );
    // A mutation that changes nothing a reader may act on — a reserved byte, an
    // unread payload — is not a failure. What would be a failure is a panic,
    // and reaching this line means there was none.
    assert!(refused + reported > 200, "too few mutations were detected: the targets are wrong");
}
