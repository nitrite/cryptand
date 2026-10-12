# HANDOFF — Cryptand 1.0 release

## State (2026-10-12, IST)

- Branch `packaging/v1.0.0`. Manifests 1.0.0, nothing published, no tags.
- Done: M0, M1.1, M1.2 (Rust, Java), M2.1–2.3 (Rust, Java), M3 (8 cargo-fuzz
  targets x 4 h, 7 Jazzer targets x 2 h under JDK 21: clean), M4.1, M4.2.
  Dart halves wait for M5. Details: git log and PLAN status table.
- Jazzer: remote clone `~/Documents/codebase/cryptand-fuzz`, run under
  `JAVA_HOME=/opt/homebrew/opt/openjdk@21` (JDK 24 silently voids the run):
  `JAZZER_FUZZ=1 mvn -B surefire:test -Dtest=JazzerTest#<t>` in `reference/java`.
- M4.1/M4.2 left for M4.5: Java wiping the caller's password array (review
  row 29), the never-log marker test (row 40).
- **Format changes approved 10-12, both in all three, corpus regenerated:**
  F-127: optional bit 16 `CONVERTING` (14 §8.3); F-128: parent-recorded
  nonces (14 §5.5: superblock `root_nonces` at 328, descriptor `root_nonce`,
  CoW cell and R-tree entry `child_nonce`, manifest `nonce`, checkpoint
  `root_nonces`, segment pages carry the head's `commit_id`). Vector regions
  are unbound (documented); overflow chains unchecked (no writer makes one,
  ponytail in Java `resolveValue`). **M5's Dart rewrite must carry both.**
- Corpus regeneration order: `dart run tool/generate_corpus.dart`, then Rust
  `convert_test make_converting_vector` and `replay_test make_replay_vector`
  (both `--ignored`): `v1.0-encrypted` is not deterministic.
- M4.3 done: `tools/security_attack.py` 3 writers x 3 readers, 1479 runs,
  0 failures, value-log records and segment heads included (interop `write`
  now sets `vlog_min` 256 in all three). Blob chunks: no writer exists (F-103);
  vector regions unbound by design. Value-log head CRC spans 40+64 bytes only.
- M4.4 done: F-133 (all three: nonce floor overflow near 2^64, Java/Dart
  wrapped to 0) and F-134 (Java vlog `nonce_base` not allocated) fixed.
  Concurrency: Java 32-thread test; Rust cursor behind `&mut Engine`; Dart
  one isolate. Crash reuse: existing row 9 tests + M2.2 kills.
  **M5's Dart rewrite must keep `_cmpU64`/`_addSaturating` semantics.**
- F-132 (Dart, fixed): converting files mix plaintext/encrypted vlog records;
  Dart probes per record (ponytail) until M5 writes byte 39 (F-076).
- Fuzz crash to regress file: CRC-repair with `JazzerTest.repairCrcs` into
  `reference/conformance/files/fuzz-regress/fNNN-*.cryptand`
  (`CRYPTAND_FUZZ_DUMP` keeps only the last input replayed). Replaying
  Jazzer inputs needs `process-test-resources`: `surefire:test` reads `target/test-classes`.
- Remote gate clone `cryptand-gate` (rsync the tree; Dart SDK `~/dart-sdk/bin`).
- Open outside M5: none. M5 (Dart): F-035, F-038, F-072,
  M2.2 Dart, Dart checks of F-079, F-081, F-084, F-087, F-088, F-094..F-121
  (`?`/`M5` in FINDINGS), Dart corpus replay (M3.4).
- Traps: corpus test without `--features harness` reuses a stale `interop`
  binary (the gate passes the feature); Rust `stall_test` fails while another job fsyncs on /Volumes/External;
  never build Java in a clone where a hop, torture or Jazzer runs; rebuilding
  classes under a running Jazzer breaks it.

## Decisions in force (human)

- Scope = the three engine packages. Dart storage rewrite (M5) on
  `dart-storage`; go/no-go Fri 10-23, else Dart ships `1.0.0-rc.1`. Freeze
  Tue 10-27, tags Fri 10-30.
- Java `--release 11`, built on JDK 17, as nitrite-java.
- F-072: all of 13 §5 in all three for 1.0 (Dart's in M5). Rotation is
  copy-and-swap; no format change.
- F-103: value log, no put-time BLOBs.
- Push every commit; one finding per commit unless files are shared.
- CPU-heavy work (fuzz, torture, soak, bench, M1.2) runs on the remote Mac
  (`anindya@207.254.39.186`), one clone per job, never here.

## Open questions for the human

- None.

## Next action

M4.5 (key material): zeroize on every exit path; Java wipes the caller's
`char[]`/`byte[]` (review row 29); marker-password grep of every error
message (row 40); document Dart's best-effort limit.

## Log

- 2026-10-10 — Jazzer was under JDK 24 (void); openjdk@21 installed; F-119 fixed; Java M1.2 encrypted seed 9334 diverges, not reproduced locally. Earlier sessions: git history.
- 2026-10-11 — F-120 fixed in spec (option a); F-121 (Java verify horizon mix) found via seed 9334 and fixed; final Java M1.2 encrypted run started.
- 2026-10-11 — Jazzer openFile/openEncrypted/cveDecode/analyzer 2 h clean under 21; last 3 targets started.
- 2026-10-11 — M1.2 Java encrypted 0..10000 clean; last 3 Jazzer targets clean, M3 Rust/Java done.
- 2026-10-11 — M4 started: SECURITY-REVIEW.md first pass; F-122 fixed (R+J tests), F-123 converting vector added after approval.
- 2026-10-11 — spec 14 §13 reworded for security-converting; M4.1 done (F-124 tests, F-125 docs).
- 2026-10-11 — M4.2 KATs in all three; F-126 Argon2id (J+D) found and fixed.
- 2026-10-11 — interop password leg; M4.3 harness (1197 runs); F-129, F-130 fixed; F-127/F-128 to the human.
- 2026-10-12 — F-127 (CONVERTING bit) and F-128 (parent-recorded nonces, option b) fixed in R+J+D after the human's decisions; corpus regenerated, `v1.0-security-replay` added; F-131 (Java segment commit race) found by interop and fixed; gate quick green.
- 2026-10-12 — M4.3 done: vlog record/head attacks (1479 runs clean); interop fixture now separates values in all three, exposing F-132 (Dart converting-file vlog read), fixed; gate quick green.
- 2026-10-12 — M4.4 done: F-133 nonce exhaustion wrap (R+J+D), F-134 (J nonce_base); gate quick green.
