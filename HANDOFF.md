# HANDOFF — Cryptand 1.0 release

## State (2026-10-11, 11:20 IST)

- Branch `packaging/v1.0.0`. Manifests 1.0.0, nothing published, no tags.
  `tools/gate.sh quick` green at d057be4.
- Done: M0, M2.1, M2.2 (Rust, Java), M2.3. Dart halves wait for M5.
- M1.2: Rust 10 000 plain + encrypted clean. Java plain 10 000/0. Java
  encrypted seed 9334 was F-121 (verify false positive, fixed d057be4; 1000
  remote replays clean after, it failed within 473 before). Final Java
  `--encrypted` 0..10000 running on the remote at d057be4 since 11:19 IST
  (~4 h): `~/Documents/codebase/cryptand/reference/bench/runs/m12-java-enc.log`.
  That clone has F-115 debug instrumentation in `git stash`; its working tree
  is clean.
- M3: Rust 8 cargo-fuzz targets x 4 h clean. Jazzer (7 targets) in remote
  clone `~/Documents/codebase/cryptand-fuzz`, logs
  `reference/bench/runs/fuzz/jz-*.log`, 2 h each, 4 at a time. Every run
  before 10-10 23:30 IST was under JDK 24, where instrumentation fails
  (`class file major version 68`) yet the run reports a pass: void.
  Under 21: openFile found F-119 (fixed 420d2d2); ckeRoundtrip found F-120
  (spec, fixed 3d93fec, option a). Running since 10:30 IST at 6f701f5:
  openFile, openEncrypted, cveDecode, analyzer (end ~12:30, no findings at
  11:20); old logs in `fuzz/old/`. Still to run: wkb, superblockKeyslot,
  ckeRoundtrip (pull 3d93fec first). Old crash inputs in `~/fuzz-crashes`.
- Remote JDKs: `openjdk@18` links to 24.0.1. Jazzer: `JAVA_HOME=/opt/homebrew/opt/openjdk@21`.
- Fuzz crash to regress file: CRC-repair with `JazzerTest.repairCrcs` into
  `reference/conformance/files/fuzz-regress/fNNN-*.cryptand`
  (`CRYPTAND_FUZZ_DUMP` keeps only the last input replayed). Replaying
  Jazzer inputs needs `process-test-resources`: `surefire:test` reads `target/test-classes`.
- Remote gate clone `cryptand-gate` (rsync the tree; Dart SDK `~/dart-sdk/bin`).
- Open outside M5: none (Java M1.2 final run pending). M5 (Dart): F-035, F-038, F-072,
  M2.2 Dart, Dart checks of F-079, F-081, F-084, F-087, F-088, F-094..F-121
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

- None.

## Next action

At ~12:30 triage the 4 Jazzer logs; then in `cryptand-fuzz` pull to d057be4,
recompile under openjdk@21 and run wkb, superblockKeyslot, ckeRoundtrip. At
~15:30 check `m12-java-enc.log` for `0 divergences`; if so tick M1.2 in PLAN.

## Log

- 2026-10-10 — Jazzer was under JDK 24 (void); openjdk@21 installed; F-119 fixed; Java M1.2 encrypted seed 9334 diverges, not reproduced locally. Earlier sessions: git history.
- 2026-10-11 — F-120 fixed in spec (option a); F-121 (Java verify horizon mix) found via seed 9334 and fixed; final Java M1.2 encrypted run started.
