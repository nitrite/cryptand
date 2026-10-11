# Security review — spec 14 traceability (PLAN M4)

Attacker: whoever holds the file (`spec/14-security.md` §1). One row per
MUST / MUST NOT of spec 14 → the test that proves it, per implementation.
`R` = `rust/cryptand/tests/`, `J` = `java/src/test/.../cryptand/`, `D` =
`dart/cryptand/test/`. `—` = no test (a finding), `M5` = Dart rewrite,
`doc` = a documentation requirement, checked by reading.
Status 2026-10-11: M4.1 first pass. Rows marked `?` still need a test located.

| # | § | requirement | R | J | D |
|---|---|---|---|---|---|
| 1 | 2 | refuse an encrypted file if any primitive is missing | n/a (all four built in) | n/a | n/a |
| 2 | 2 | constant-time tag compare | `security_test::a_tag_comparison_is_constant_time_over_length_and_content` | `SecurityConformanceTest.constantTimeEquals` | `security_test` "constant-time compare is length-safe…" |
| 3 | 3.2 | Argon2id exactly per RFC 9106; fail rather than derive differently | `conformance_test` argon2 vectors | `CryptoPrimitivesTest.argon2idRfc9106` | `argon2_test` |
| 4 | 3.2 | reject below-floor cost on create, honour slot on open | `the_argon2id_floor_binds_on_create_and_not_on_open` | `CryptoPrimitivesTest.argon2CreateFloors` | "a below-floor Argon2id cost is refused at creation" |
| 5 | 3.3 | raw-key slot writes kdf params as zero | ? | `SecurityConformanceTest.rawKeyslotZeroesKdfParameters` | ? |
| 6 | 3.3 | "no such slot" indistinguishable from "bad password" | `an_encrypted_file_round_trips_and_refuses_the_wrong_key` (`CannotUnlock`) | `EncryptionTest.wrongKey` | "unlock tries every slot and reports one failure" |
| 7 | 3.3 | refuse removing the last slot; crypto-erase by name | `add_key_remove_key_and_crypto_erase` | `ConvertTest.lastKeyslotAndCryptoEraseAreRefusedUnlessByName` (F-122) | `backup_feed_test` "remove_key refuses…" |
| 8 | 3.4 | wrap AAD binds slot to file and index | `a_keyslot_from_another_database_does_not_unwrap_here` | `EncryptionTest.foreignSlot`, `SecurityConformanceTest.wrapAadBindsSlotToFile` | "the wrap AAD binds a slot…", "…threat T3" |
| 9 | 4.1 | publish floor before allocating; never pass it; publish then continue | `no_nonce_is_ever_issued_twice_across_repeated_crashes`, `the_nonce_floor_publish_never_rewrites_the_live_slot` | `EncryptionTest.nonceUniqueness`, `SecurityConformanceTest.nonceGap` | "a crashed session never has its counters reissued", "allocation stops at the watermark…", "open publishes before it returns" |
| 10 | 4.3 | never append to a value-log segment not opened this session | `conformance_test` (seal_unsealed) | ? | M5 |
| 11 | 5.2 | `flags.ENCRYPTED` set; reader never infers encryption | `every_data_page_carries_the_encrypted_flag_and_a_distinct_nonce` | ? | M5 |
| 12 | 5.2 | header is AAD; splice and relabel fail | corpus `security-tamper-header`, `security-splice` | `CorpusTest` same | `encryption_test` "a page moved…", "relabelling…" |
| 13 | 5.4 | extent sized for the 16-byte tags | `a_vector_region_slot_is_not_stored_in_the_clear` | ? | M5 |
| 14 | 6.2 | sb_mac over superblock + keyslots; tampering ≠ CRC failure | `editing_the_superblock_is_reported_as_tampering_not_corruption`, corpus `tamper-sb`, `downgrade-kdf` | `EncryptionTest.tamperedSuperblock`, `CorpusTest` | `security_test` "catches cipher forced to 0…", "catches a weakened Argon2id cost…" |
| 15 | 6.2 | no tree read before sb_mac verifies | corpus `at_open_or_read: true` rows | same | same |
| 16 | 7 | `compression = none` offered while encrypted | `compression_test` | `CompressionTest` | `compression_test` |
| 17 | 8.1 | a forced erase path (`compact()` + shrink) exists | `operations_test::every_maintenance_operation_is_incremental_and_resumable` | `OperationsTest.shrink` | M5 |
| 18 | 8.2 | crypto-erase zeroes both superblock slots | `crypto_erase_makes_the_file_permanently_unreadable` | `OplogCheckTest` (erase op) | "crypto_erase zeroes every slot" |
| 19 | 8.2 | no crypto-erase on an unencrypted file | `add_key_remove_key_and_crypto_erase` (F-122) | `ConvertTest.lastKeyslot…` (F-122) | **bug**, M5 (F-122) |
| 20 | 8.3 | decrypt needs explicit confirmation | `convert_test::decrypt_needs_confirmation…` | `ConvertTest.decryptNeedsConfirmation…` | M5 |
| 21 | 8.3 | mixed page flags read per page; fraction exposed; never "encrypted" while plaintext pages remain | `a_converting_file_never_reports_itself_as_fully_encrypted`, `rotate_a_half_encrypted_file` | `ConvertTest.rotateAHalfEncryptedFile`, metric `unencrypted_pages` | M5 |
| 22 | 9.1 | bounds before allocating; depth 100; typed corruption error | `hostile_test`, cargo-fuzz (M3) | `HostileTest`, Jazzer (M3) | `hostile_test`, `fuzz_test` |
| 23 | 9.2 | no dispatch on file content | by construction (no reflection / class lookup) — M4.6 confirms | same | same |
| 24 | 9.3 | negative tests run in CI | `tools/gate.sh` | same | same |
| 25 | 9.4 | docs never call checksums integrity | doc | doc | doc |
| 26 | 10 | credentials: Argon2id, per-record salt, hash only, constant-time verify | ? | `HostileUserRecordTest`, `SecurityConformanceTest` | `aead_test` ? |
| 27 | 10 | user password not reused as keyslot password | ? | ? | ? |
| 28 | 11 | master key and subkeys zeroed on close / drop | `a_key_ring_zeroes_itself_on_drop_and_not_only_on_close`, `secure_zero_clears_under_release_optimization` | ? (M4.5) | "destroy zeroes every key" |
| 29 | 11 | no password parameter of an immutable string type | n/a (`&[u8]`) | API takes `byte[]` (`Database.addUser`) | M4.5 |
| 30 | 11 | document best-effort zeroing under a moving GC | n/a | doc ? | doc ? |
| 31 | 11 | metadata carries no user name / device id | ? | ? | ? |
| 32 | 11 | mlock is optional; never fail open without it | n/a (no mlock used) | n/a | n/a |
| 33 | 12 | Argon2id cost never lowered for latency | row 4 | row 4 | row 4 |
| 34 | 13 | tamper test over every `security-*` vector | corpus, `error_class: tampering` | `CorpusTest` | `corpus_test` |
| 35 | 13 | `v1.0-security-converting` vector (F-123) | corpus | `CorpusTest` | `corpus_test` |
| 36 | 13 | nonce uniqueness across crashes | row 9 | row 9 (+ M2.2 kills) | row 9 |
| 37 | 13 | key rotation | `key_rotation_leaves_only_the_new_credential_working` | `EncryptionTest.keyRotation` | M5 |
| 38 | 13 | conversion round trip | `convert_test::encrypt_in_place…`, `decrypt_needs…` | `ConvertTest` | M5 |
| 39 | 13 | cross-SDK encrypted round trip | `conformance/interop/run.sh` (encrypted, 12/12) | same | same |
