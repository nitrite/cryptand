# HANDOFF — Cryptand 1.0 release

## State (2026-10-11, 10:35 IST)

- Branch `packaging/v1.0.0`. Manifests 1.0.0, nothing published, no tags.
  `tools/gate.sh quick` green at 420d2d2.
- Done: M0, M2.1, M2.2 (Rust, Java), M2.3. Dart halves wait for M5.
- M1.2: Rust 10 000 plain + encrypted clean. Java plain 10 000/0; Java
  `--encrypted` 1/10 000 diverged at 5101229, seed 9334: end-of-log verify says
  `VLOG pointer in segment 77: value-log segment 13 has no entry in tree 7`
  (a value-log segment collected while an on-disk segment still points into
  it; F-093/F-100/F-102/F-115 class). Does not reproduce locally: 40x alone
  and 3x seeds 9234..9334 in one JVM, at 5101229 and at HEAD (JDK 25, Mac
  here). Likely timing; the failing run was the remote M1 under JDK 24. No F
  number yet. Remote loop at 5101229, JDK 24 (`/tmp/s9334.sh`, log
  `reference/bench/runs/s9334.log`): 5 rounds of 200x seed 9334 + seeds
  9000..9334; round 1 (200x alone) passed. Log: remote `~/Documents/codebase/cryptand/reference/bench/runs/m12-java.log`.
  Seeds: `tools/oplog_java.sh A B --encrypted`. That clone has F-115 debug
  instrumentation in `git stash`.
- M3: Rust 8 cargo-fuzz targets x 4 h clean. Jazzer (7 targets) in remote
  clone `~/Documents/codebase/cryptand-fuzz`, logs
  `reference/bench/runs/fuzz/jz-*.log`, 2 h each, 4 at a time. Every run
  before 10-10 23:30 IST was under JDK 24, where instrumentation fails
  (`class file major version 68`) yet the run reports a pass: void.
  Under 21: openFile found F-119 (fixed 420d2d2); ckeRoundtrip found F-120
  (spec contradiction, open for the human). Running since 10:30 IST at
  6f701f5: openFile, openEncrypted, cveDecode, analyzer (end ~12:30); old
  logs in `fuzz/old/`. Still to run: wkb, superblockKeyslot, then ckeRoundtrip
  once F-120 is decided. Crash inputs moved out of the tree to `~/fuzz-crashes`.
- Remote JDKs: `openjdk@18` links to 24.0.1. Jazzer: `JAVA_HOME=/opt/homebrew/opt/openjdk@21`.
- Fuzz crash to regress file: CRC-repair with `JazzerTest.repairCrcs` into
  `reference/conformance/files/fuzz-regress/fNNN-*.cryptand`
  (`CRYPTAND_FUZZ_DUMP` keeps only the last input replayed). Replaying
  Jazzer inputs needs `process-test-resources`: `surefire:test` reads `target/test-classes`.
- Remote gate clone `cryptand-gate` (rsync the tree; Dart SDK `~/dart-sdk/bin`).
- Open outside M5: Java M1.2 seed 9334. M5 (Dart): F-035, F-038, F-072,
  M2.2 Dart, Dart checks of F-079, F-081, F-084, F-087, F-088, F-094..F-119
  (`?`/`M5` in FINDINGS), Dart corpus replay (M3.4).
- Traps: Rust `stall_test` fails while another job fsyncs on /Volumes/External;
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

- F-120: 02 §8 claims CKE order refines §8 order; false for ARRAYs holding
  §8-equal numerics of different types (`I32(5)`/`I64(5)`, NaN f64/f32), in
  Rust and Java alike. Options: (a) fix the spec claim (refinement holds per
  scalar and for type-exact arrays) and narrow the fuzz assertion, no byte
  change; (b) change ARRAY/NUMBER encoding (format change, breaks CFF v1.0).

## Next action

Watch the remote seed 9334 loop; when it fails, shrink (`OplogCheckTest
--shrink`) and find the race; if all 5 rounds pass, try the run's exact
conditions (full 10 000 in one JVM). At ~12:30 triage the 4 Jazzer logs, then
run wkb and superblockKeyslot. F-120 waits for the human.

## Log

- 2026-10-10 — Jazzer was under JDK 24 (void); openjdk@21 installed; F-119 fixed; Java M1.2 encrypted seed 9334 diverges, not reproduced locally. Earlier sessions: git history.
- 2026-10-11 — F-120 found (ckeRoundtrip, spec-level); 4 Jazzer targets rerunning under JDK 21; seed 9334 looping on the remote.
