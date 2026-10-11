# HANDOFF — Cryptand 1.0 release

## State (2026-10-11, evening IST)

- Branch `packaging/v1.0.0`. Manifests 1.0.0, nothing published, no tags.
  `tools/gate.sh quick` green at d057be4.
- Done: M0, M2.1, M2.2 (Rust, Java), M2.3. Dart halves wait for M5.
- M1.2: Rust 10 000 plain + encrypted clean. Java plain 10 000/0. Java
  encrypted seed 9334 was F-121 (verify false positive, fixed d057be4; 1000
  remote replays clean after, it failed within 473 before). Final Java
  `--encrypted` 0..10000 at d057be4: 0 divergences (log
  `m12-java-enc.log` in the remote `cryptand` clone; F-115 debug
  instrumentation sits in its `git stash`).
- M3: Rust 8 cargo-fuzz targets x 4 h clean. Jazzer (7 targets) in remote
  clone `~/Documents/codebase/cryptand-fuzz`, logs
  `reference/bench/runs/fuzz/jz-*.log`, 2 h each, 4 at a time. Every run
  before 10-10 23:30 IST was under JDK 24, where instrumentation fails
  (`class file major version 68`) yet the run reports a pass: void.
  Under 21: openFile found F-119 (fixed 420d2d2); ckeRoundtrip found F-120
  (spec, fixed 3d93fec, option a). openFile, openEncrypted, cveDecode,
  analyzer 2 h each at 6f701f5: clean (BUILD SUCCESS, 0 failures, no
  JDK-68 errors). wkb, superblockKeyslot, ckeRoundtrip 2 h at 5da815b:
  clean too, so all 7 Jazzer targets are clean under 21. Old logs in `fuzz/old/`.
  Launch: `JAZZER_FUZZ=1 mvn -B surefire:test -Dtest=JazzerTest#<t>` in
  `reference/java` (maxDuration 2h in the annotation). Old crash inputs in `~/fuzz-crashes`.
- M4.1 done: `reference/SECURITY-REVIEW.md`, 40 rows, no `?` left. F-122..F-125
  fixed (missing tests and docs; each new test shown failing with its guard
  removed). F-123 added `v1.0-security-converting`; spec 14 §13 reworded so it
  must read, not fail (human, 1c28a0c). Left for M4.5: Java wiping the
  caller's password array (row 29), the never-log marker test (row 40).
- M4.2 done: shared KATs in `reference/conformance/vectors/kat` (Wycheproof
  AEAD/HKDF/HMAC extracted from local RustCrypto crate test data with
  `blb2json.py`, BLAKE2 reference keyed KAT, CPython unkeyed edges, Argon2id
  RFC 9106 + phc test.c + 2 RustCrypto rows). Tests: R `kat_test.rs`, J
  `KatTest`, D `kat_test.dart`. Found F-126 (S0): Java and Dart Argon2id were
  not RFC 9106 past segment length 2; fixed. Interop gate is raw-key only:
  a password-slot leg is the follow-up (task chip offered).
- Remote JDKs: `openjdk@18` links to 24.0.1. Jazzer: `JAVA_HOME=/opt/homebrew/opt/openjdk@21`.
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

M4.3: file-attacker harness (`security_attack`), per PLAN. Before it, or in
parallel: the interop password-slot leg (F-126 follow-up).

## Log

- 2026-10-10 — Jazzer was under JDK 24 (void); openjdk@21 installed; F-119 fixed; Java M1.2 encrypted seed 9334 diverges, not reproduced locally. Earlier sessions: git history.
- 2026-10-11 — F-120 fixed in spec (option a); F-121 (Java verify horizon mix) found via seed 9334 and fixed; final Java M1.2 encrypted run started.
- 2026-10-11 — Jazzer openFile/openEncrypted/cveDecode/analyzer 2 h clean under 21; last 3 targets started.
- 2026-10-11 — M1.2 Java encrypted 0..10000 clean; last 3 Jazzer targets clean, M3 Rust/Java done.
- 2026-10-11 — M4 started: SECURITY-REVIEW.md first pass; F-122 fixed (R+J tests), F-123 converting vector added after approval.
- 2026-10-11 — spec 14 §13 reworded for security-converting; M4.1 done (F-124 tests, F-125 docs).
- 2026-10-11 — M4.2 KATs in all three; F-126 Argon2id (J+D) found and fixed.
