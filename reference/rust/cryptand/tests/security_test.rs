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
    // Closed first: this is about the key, not the writer lock, and on Windows
    // a still-open writer makes the next open's first read fail as Locked.
    ok.close(true).unwrap();
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
    // Above `vlog_min`, so the value is a value-log record and the tag under
    // test is the record's. Sized off the superblock rather than off a literal
    // — the cut-off is a quarter page now (`12-profiles.md` §2.5).
    let big = vec![5u8; e.sb.vlog_min as usize + 512];
    e.put(T, &Value::NitriteId(1), &big).unwrap();
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
        // Above `vlog_min` — see the note in `operations_test`.
        let big = vec![1u8; e.sb.vlog_min as usize + 512];
        for i in 0..40i64 {
            e.put(T, &Value::NitriteId(i), &big).unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        // The kill: no close and no seal, but the file descriptor goes,
        // which is what a dying process does — and `01-container.md` §10's
        // writer lock goes with it. `mem::forget` would leak both.
        drop(e);
    }
    let mut floors = Vec::new();
    for round in 1..4i64 {
        let mut e = Engine::open(&t.path, Some(&raw_key)).unwrap();
        floors.push(e.sb.next_nonce);
        let big = vec![2u8; e.sb.vlog_min as usize + 512];
        for i in 0..40i64 {
            e.put(T, &Value::NitriteId(round * 1000 + i), &big).unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        drop(e);
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
    ok.close(true).unwrap();
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

    let mut pager = cryptand::pager::Pager::open_shared(&t.path, 8192, 4).unwrap();
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
    let mut pager = cryptand::pager::Pager::open_shared(&t.path, 8192, sb.page_count).unwrap();
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
    // been fuzzed is not finished." Three things make it find anything:
    //
    //  * **Structure-aware.** Most of a database's bytes are unused value-log
    //    record space, so uniform bit flips land in padding and measure
    //    nothing. These targets are the ones a hostile file would edit.
    //
    //  * **The checksum is repaired after the mutation.** This test did not do
    //    that, and that is the more interesting half. §3's `checksum` verifies
    //    "before decompression and before decryption", so a mutant with a stale
    //    checksum dies at the container gate and *no decoder sees a byte* — the
    //    run measures CRC-32C and calls it a pass. Measured: the repair moves
    //    the population from 43 mutants reaching the reader in 400 to 233.
    //    §9.4 is the same point from the other side — a CRC "is trivially
    //    recomputed by anyone who edits the file", so an attacker's file always
    //    has a valid one, and a fuzzer that assumes otherwise is not modelling
    //    the attacker §9 describes.
    //
    //  * **It reads, it does not only verify.** `verify()` walks structure and
    //    checksums; the decoders that turn bytes into values only run when
    //    something reads. The Dart port of this test found four untyped
    //    failures on its first runs and three were behind a read.
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
        let mut touched: Vec<usize> = Vec::new();
        for _ in 0..1 + rng.below(4) {
            let (base, len) = targets[rng.below(targets.len() as u64) as usize];
            let at = base + rng.below(len.max(1) as u64) as usize;
            if at >= b.len() {
                continue;
            }
            // A run of 0xFF has to be one of the mutations on its own: a length
            // field only becomes an allocation bomb when *all* its bytes are
            // set, and one flipped bit almost never does that.
            match rng.below(4) {
                0 => b[at] ^= 1 << rng.below(8),
                1 => b[at] = 0x00,
                2 => b[at] = 0xFF,
                _ => {
                    let w = 1 + rng.below(8) as usize;
                    for k in 0..w {
                        if at + k < b.len() {
                            b[at + k] = 0xFF;
                        }
                    }
                }
            }
            touched.push(at / page_size);
        }
        for pg in touched {
            // Pages 0 and 1 are the superblock slots, which have their own
            // rule; a mutation there is meant to be caught, and is.
            if pg < 2 {
                continue;
            }
            let off = pg * page_size;
            if off + page_size > b.len() {
                continue;
            }
            let page = &b[off..off + page_size];
            let Ok(h) = cryptand::container::PageHeader::parse(page) else { continue };
            // `checksum_range_end`, not `page_size`: a value-log head page
            // checksums only its immutable header region, because records are
            // appended into its tail for the life of the segment. A repair over
            // the whole page writes a checksum that is wrong the moment it is
            // written, and the mutation is then "caught" by the repair rather
            // than by the reader — a fuzzer silently measuring itself.
            let end = cryptand::container::PageHeader::checksum_range_end(page, &h);
            let crc = cryptand::hash::crc32c(&b[off + 4..off + end]);
            b[off..off + 4].copy_from_slice(&crc.to_le_bytes());
        }
        std::fs::write(&tmp.path, &b).unwrap();
        // No `catch_unwind`: a panic here fails the test, which is the point.
        match Engine::open(&tmp.path, None) {
            Err(_) => refused += 1,
            Ok(mut e) => {
                let v = e.verify();
                // Read, whatever the verifier said. `verify` walks structure and
                // checksums; the decoders live behind a read.
                for i in 0..300i64 {
                    let _ = e.get(T, &Value::NitriteId(i));
                }
                let _ = e.scan_tree(T, None, None, None, true);
                match v {
                    Err(_) => refused += 1,
                    Ok(r) => {
                        if r.of(Class::Corruption).is_empty() && r.of(Class::Tampering).is_empty() {
                            benign += 1;
                        } else {
                            reported += 1;
                        }
                    }
                }
            }
        }
    }
    println!(
        "fuzz: {refused} refused at open, {reported} reported by verify, {benign} benign, 0 panics"
    );
    // A mutation that changes nothing a reader may act on — a reserved byte, an
    // unread payload — is not a failure. What would be a failure is a panic,
    // and reaching this line means there was none.
    // With the checksum repaired, most mutants now *reach* the reader instead
    // of dying at the container gate, so the assertion that means something is
    // the one about reach — a run where everything is refused has measured the
    // CRC and nothing else.
    assert!(
        benign + reported > 100,
        "too few mutants reached the reader ({benign} benign, {reported} reported): \
         the checksum repair or the targets are wrong"
    );
}

// ---------------------------------------------------------------------------
// §5.1 — what is encrypted. These exist because "the file is encrypted" was
// true of its superblock and its value log and of nothing else: every inline
// value, every key, every index entry and every B+tree page sat in the clear
// under a `cipher = 1` superblock, and no test looked. The failure is silent by
// construction — the database opens, reads and verifies perfectly.
// ---------------------------------------------------------------------------

#[test]
fn no_inline_value_or_key_survives_in_the_clear() {
    let (t, mut e) = encrypted("cleartext");
    // Below `vlog_min` (256 B on desktop), so these never reach the value log:
    // they live in a segment leaf cell, which is page payload.
    for i in 0..80i64 {
        e.put(T, &Value::Str(format!("KEYNEEDLE-{i:04}")), b"VALUENEEDLE").unwrap();
    }
    e.flush().unwrap();
    e.close(true).unwrap();

    let raw = std::fs::read(&t.path).unwrap();
    for needle in [&b"VALUENEEDLE"[..], &b"KEYNEEDLE-0007"[..]] {
        let hits = raw.windows(needle.len()).filter(|w| *w == needle).count();
        assert_eq!(
            hits,
            0,
            "{} occurrences of {:?} in an encrypted file",
            hits,
            String::from_utf8_lossy(needle)
        );
    }
    // And it is still readable with the key, which is the other half.
    let mut e = Engine::open(&t.path, Some(&[7u8; 32])).unwrap();
    assert_eq!(e.get(T, &Value::Str("KEYNEEDLE-0007".into())).unwrap().unwrap(), b"VALUENEEDLE");
}

#[test]
fn every_data_page_carries_the_encrypted_flag_and_a_distinct_nonce() {
    // §5.2: "`flags.ENCRYPTED` MUST be set. A reader MUST NOT infer encryption
    // from `cipher` alone." And §4: a repeated nonce is the whole failure.
    use cryptand::container::{page_flags, page_type, PageHeader};
    // Encrypted from page 2 on, not converted: §8.3's mixture is a different
    // property with its own test.
    let t = TempDb::new("flags");
    let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &[7u8; 32], 0, 0, 0, 0).unwrap();
    for i in 0..120i64 {
        e.put(T, &Value::NitriteId(i), b"payload").unwrap();
    }
    e.close(true).unwrap();

    let raw = std::fs::read(&t.path).unwrap();
    let ps = 8192usize;
    let mut seen = std::collections::HashSet::new();
    let mut encrypted_pages = 0;
    for p in 2..raw.len() / ps {
        let page = &raw[p * ps..(p + 1) * ps];
        if page.iter().all(|&b| b == 0) {
            continue;
        }
        let Ok(h) = PageHeader::parse(page) else { continue };
        // §5.1's one clear page kind.
        if h.page_type == page_type::VLOG_SEGMENT || h.page_type == page_type::FREE {
            continue;
        }
        if PageHeader::verify(page, p as u64).is_err() {
            continue;
        }
        assert!(
            h.flags & page_flags::ENCRYPTED != 0,
            "page {p} (type {}) is stored in the clear in an encrypted database",
            h.page_type
        );
        assert!(seen.insert(h.nonce), "nonce {} is used by two pages", h.nonce);
        encrypted_pages += 1;
    }
    assert!(encrypted_pages > 4, "only {encrypted_pages} encrypted pages; the probe found nothing");
}

#[test]
fn a_vector_region_slot_is_not_stored_in_the_clear() {
    // §5.4 — "a vector region's payload: encrypted, as an extent". A region is
    // written slot by slot, so its chunks are rewritten; each write takes a
    // fresh counter, stored in the clear at the head of the chunk, because a
    // fixed per-extent counter would re-encrypt a chunk under a nonce it has
    // already used.
    use cryptand::vector::{DType, Region};
    let (t, mut e) = encrypted("region");
    let mut r = Region::create(&mut e.pager, 4, DType::F32, 64).unwrap();
    let v: Vec<f32> = vec![1.5, -2.5, 3.25, 4.125];
    r.write_slot(&mut e.pager, 1, &v).unwrap();
    r.write_slot(&mut e.pager, 2, &[9.0, 9.0, 9.0, 9.0]).unwrap();
    assert_eq!(r.read_slot(&mut e.pager, 1).unwrap(), v);
    assert_eq!(r.read_slot(&mut e.pager, 2).unwrap(), vec![9.0f32; 4]);
    e.commit(Durability::Sync).unwrap();
    e.close(false).unwrap();

    let raw = std::fs::read(&t.path).unwrap();
    let needle: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    let hits = raw.windows(needle.len()).filter(|w| *w == needle.as_slice()).count();
    assert_eq!(hits, 0, "a vector's f32 bytes are on disk in the clear");
}

// ---------------------------------------------------------------------------
// §11 — key material in memory
// ---------------------------------------------------------------------------

/// §11: "a runtime with deterministic destruction SHOULD bind key material to a
/// type that zeroes on release".
///
/// This is a type-level assertion rather than a memory one, because safe Rust
/// cannot read a freed allocation to check it. It is still a control that can
/// fail: every field of `KeyRing` is a `Copy` array, so the type has no drop
/// glue of its own and `needs_drop` is **false** unless a `Drop` impl puts it
/// there. Deleting that impl fails this test.
///
/// It matters because `Engine::close` only zeroes the two rings it knows about.
/// An engine dropped without `close` — an early `?`, a panic unwinding through
/// the caller, a test letting the value fall out of scope — took its keys to
/// the allocator intact before the impl existed.
#[test]
fn a_key_ring_zeroes_itself_on_drop_and_not_only_on_close() {
    assert!(
        std::mem::needs_drop::<KeyRing>(),
        "KeyRing has no drop glue, so a ring that `close` never sees is never zeroed"
    );

    // And the zeroing it performs actually clears, rather than being a method
    // that exists and does nothing — this project has shipped that shape before.
    let mut ring = KeyRing::from_master([0xA5u8; 32], [1u8; 16], 0);
    assert_eq!(ring.master_key(), &[0xA5u8; 32]);
    ring.zeroize();
    assert_eq!(ring.master_key(), &[0u8; 32], "the master key survived zeroize");
}

/// §11's zeroing is only meaningful if the writes survive optimization. A plain
/// `fill(0)` before a drop is a dead store the compiler may delete outright, so
/// the helper is asserted here to actually clear a buffer under `--release`,
/// which is the profile where that deletion happens.
#[test]
fn secure_zero_clears_under_release_optimization() {
    let mut secret = vec![0x5Au8; 4096];
    cryptand::security::secure_zero(&mut secret);
    assert!(secret.iter().all(|&b| b == 0), "secure_zero left bytes behind");
}

#[test]
fn a_read_only_handle_writes_nothing_at_open_and_refuses_writes_after() {
    // `11-conformance.md` §3's reader matrix requires this mode: a file whose
    // `write_version_minor` exceeds what the implementation supports MUST open
    // read-only rather than be refused. It is also what any reader of a file it
    // does not own needs.
    //
    // Both halves are asserted, because either alone is satisfiable by
    // accident: a handle that writes nothing at open but accepts a `put` is
    // not read-only, and one that refuses writes while still publishing a
    // nonce floor has already modified the file it promised not to touch.
    let t = TempDb::new("readonly");
    let key = [9u8; 32];
    {
        let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &key, 0, 0, 0, 0).unwrap();
        for i in 0..200i64 {
            e.put(16, &Value::NitriteId(i), b"payload").unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        e.close(true).unwrap();
    }

    let digest = |p: &std::path::Path| -> u64 {
        std::fs::read(p)
            .unwrap()
            .iter()
            .fold(1469598103934665603u64, |a, x| (a ^ *x as u64).wrapping_mul(1099511628211))
    };
    let before = digest(&t.path);

    let mut e = Engine::open_read_only(&t.path, Some(&key)).unwrap();

    // Half one: opening changed nothing. On an encrypted database the ordinary
    // open publishes a nonce floor (`14-security.md` §4.1) with a synchronous
    // superblock write, so this is the half that actually used to fail.
    assert_eq!(digest(&t.path), before, "opening read-only modified the file");

    // And it is a real handle, not an inert one: the data reads back.
    assert_eq!(e.get(16, &Value::NitriteId(7)).unwrap().as_deref(), Some(&b"payload"[..]));
    assert_eq!(e.scan_tree(16, None, None, None, false).unwrap().len(), 200);

    // Half two: every write path refuses. They all pass through `arm`, so this
    // is a sample of the paths rather than a list of them.
    assert!(e.put(16, &Value::NitriteId(1), b"nope").is_err(), "put succeeded on a read-only handle");
    assert!(e.remove(16, &Value::NitriteId(1)).is_err(), "remove succeeded on a read-only handle");
    assert!(e.flush().is_err(), "flush succeeded on a read-only handle");

    assert_eq!(digest(&t.path), before, "a refused write still changed the file");
}

/// F-072: 13 §5's keyslot operations.
#[test]
fn add_key_remove_key_and_crypto_erase() {
    use cryptand::keyapi::KeyApi;
    let t = TempDb::new("keyapi");
    let (k1, k2) = ([1u8; 32], [2u8; 32]);
    let mut e = Engine::create_encrypted(&t.path, Profile::Desktop, &k1, 0, 0, 0, 0).unwrap();
    e.put(16, &Value::NitriteId(1), b"secret").unwrap();
    e.flush().unwrap();
    assert_eq!(e.add_key(&k2, 0, 0, 0, 0, "second").unwrap(), 1);
    e.close(true).unwrap();
    drop(e);

    let mut e = Engine::open(&t.path, Some(&k2)).unwrap();
    assert_eq!(e.get(16, &Value::NitriteId(1)).unwrap().as_deref(), Some(&b"secret"[..]));
    e.remove_key(0).unwrap();
    assert!(e.remove_key(1).is_err(), "the last keyslot is crypto-erase, by name only");
    e.close(true).unwrap();
    drop(e);
    assert!(matches!(Engine::open(&t.path, Some(&k1)), Err(cryptand::Error::CannotUnlock)));

    let mut e = Engine::open(&t.path, Some(&k2)).unwrap();
    e.crypto_erase().unwrap();
    drop(e);
    assert!(matches!(Engine::open(&t.path, Some(&k2)), Err(cryptand::Error::CannotUnlock)));
    let bytes = std::fs::read(&t.path).unwrap();
    let ps = 8192;
    for slot in [0usize, ps] {
        let area = &bytes[slot + 3512..slot + 3512 + 576];
        assert!(area.iter().all(|&b| b == 0), "keyslot bytes left at offset {slot}");
    }
}
