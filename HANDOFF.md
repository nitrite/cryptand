# HANDOFF — Cryptand 1.0 release

## State (2026-10-10, session 12)

- Branch `packaging/v1.0.0`. Manifests at 1.0.0, nothing published, no tags.
  Java targets Java 11 (built on JDK 17). Java `mvn verify` green at 5101229
  (F-115); Rust `cargo test --workspace` green 10-08.
- M0 done. M2.1, M2.2 (Rust, Java), M2.3 done. Dart after M5.
- M1.2: Rust 10 000 seeds plain + encrypted, 0 divergences. Java at 5101229
  (remote `~/Documents/codebase/cryptand/reference/bench/runs/m12-java.log`):
  plain 10 000/0; `--encrypted` 1/10 000 diverged, seed 9334: verify says
  `CORRUPTION VLOG pointer in segment 77: value-log segment 13 has no entry
  in tree 7`. Not triaged, no F number yet. M1.2 not done.
  Remote debug instrumentation from the F-115 hunt is in `git stash` there.
- Remote JDKs: `openjdk@18` is a link to 24.0.1 (not 18). Jazzer needs
  `JAVA_HOME=/opt/homebrew/opt/openjdk@21` (installed 10-10); under 24 its
  instrumentation fails (`class file major version 68`) yet the run still
  reports a clean pass.
- M3 Rust: 8 cargo-fuzz targets x 4 h done 10-10, 0 crashes. Coverage:
  open_file 4758, open_encrypted 3846, cve_decode 1333, analyzer 1228,
  segment 764, cke_roundtrip 675, wkb 367, superblock_keyslot 152 (shallow).
- M3 Jazzer runs on the remote Mac in a separate clone
  `~/Documents/codebase/cryptand-fuzz` (all CPU-heavy work goes there, human
  10-10), 4 targets at a time, 2 h each, logs `reference/bench/runs/fuzz/jz-*.log`
  there. Every 10-10 Jazzer run before 23:30 IST ran under JDK 24 and proves
  nothing; all 7 targets need a JDK 21 rerun. ckeRoundtrip is running under
  21 since 23:37 (ends ~01:40, no findings at 23:55). openFile under 21 found
  F-119 (fixed, 420d2d2); rerun it after ckeRoundtrip ends (rebuilding classes
  under a running fuzzer breaks it). Gate runs on the remote too: clone
  `cryptand-gate` (rsync the tree; Dart 3.12.2 SDK in `~/dart-sdk/bin`, put it on PATH; interop green there at da1cd1d).
  Crash files go to `reference/conformance/files/fuzz-regress/` CRC-repaired
  (call `JazzerTest.repairCrcs`; `CRYPTAND_FUZZ_DUMP` keeps only the last
  input replayed). Replaying inputs needs `process-test-resources`, since
  `surefire:test` reads `target/test-classes`. Fixed so far: F-105..F-119.
- Open S1/S0 outside M5: none. M5: F-035, F-038, Dart halves of F-072,
  F-080, F-084 check, M2.2 Dart, F-075, F-079, F-081, F-087, F-088,
  F-094..F-115 (Dart check), Dart corpus replay (M3.4).
- Rust `stall_test` fails whenever another job fsyncs on /Volumes/External;
  never build Java while a hop, Java torture or Jazzer runs.
- Debug recipe that worked: loop one seed (`one()` from `tools/torture.py`),
  then halt the child at op boundaries to tell op-boundary bugs from mid-op ones.

## Decisions already made (human)

- 10-06: scope = the three engine packages; Dart storage rewrite (M5) on
  `dart-storage`, go/no-go Fri 10-23 else Dart ships `1.0.0-rc.1`; freeze
  Tue 10-27, tags Fri 10-30.
- 10-06: F-042 — range-delete `end_key` is `CKE(end)`, no `tree_id`.
- 10-07: Java matches nitrite-java (`--release 11`, built on JDK 17); Java
  ships its own Unicode 15.1 tables; F-058/F-059 get conformance vectors.
- 10-07: F-067 approved — writer lock = one byte at 2^62, in spec 01 §10.
- 10-07: push every commit. Soak (M6.7) runs on the remote Mac
  (`anindya@207.254.39.186`) when it is free, never here. It was busy 10-07
  (llama-server at 96 % CPU) and has no Dart SDK; Rust and Java soak only.
- 10-07: F-072 — implement all of 13 §5 (encrypt/decrypt, rotate_master_key,
  add/remove_key, crypto_erase, cluster) in all three for 1.0; Dart's in M5.
  Rotation = copy-and-swap (fresh master into a sibling file, rename over);
  no format change; spec 14 §8.3/§8.4 get a note.
- 10-07: F-069 approved — spec 01 §2.1 step 1 probes slot B at every legal page size.

- 10-09: bundled multi-finding commits stay (pushed); one finding per commit
  from now unless files are shared.
- 10-09: port F-094 cold sizing to Rust; F-096 hot segments grow
  geometrically (256 KiB doubling to `vlog_segment_bytes`) in all three.

## Open questions for the human

- None.

## Next action

Triage Java M1.2 encrypted seed 9334 (VLOG pointer with no entry in tree 7;
replay that one seed). When ckeRoundtrip ends (~01:40), pull 420d2d2 into
`cryptand-fuzz`, delete the untracked `crash-0580…`/`crash-0d3a…` in
`JazzerTestInputs/openFile`, then rerun all 7 targets under openjdk@21, 4 at a time.

## Log

- 2026-10-06 — Survey, scope, M0.2 gate, M1.1–M1.3 (F-018…F-042). Details in git.
- 2026-10-07 — Hop sweeps, CI 26/26, F-043…F-077; M0 done; M2.1 fault seams; F-072 Rust + Java encrypt/decrypt. Details in git.
- 2026-10-08 — Java rotate; F-072 g in Rust+Java + interop step 12; F-075, F-077, F-078, F-079 (S0), F-081 (S0) fixed; F-080 found.
- 2026-10-08 — F-080 (S1) fixed in Rust + Java; gate quick green.
- 2026-10-08 — F-080 follow-up (Rust Database compaction), F-082/F-083/F-084 (S0) fixed; M2.2 harness; 5000-kill runs started.
- 2026-10-08 — CI fix (F-088); Java converts under snapshots (F-087); F-085, F-086 from M2.2; M2.3 harness: F-089–F-092 fixed, F-093 open.
- 2026-10-08 — F-093 (GC vs in-flight batch), F-094 (cold extent sizing), F-095 (failed publish numbering, Rust nonce limit); M2.3 green in Rust and Java.
- 2026-10-09 — Decisions on F-094 parity, profile floor, bundled commits; F-096 (hot extents, harness `.bak` leak filled the disk) fixed in Rust + Java; F-097 (Java double rollover orphaned a segment) fixed.
- 2026-10-09 — M2.3 green on F-096; M2.2 Rust 5000/0; Java F-098 (decrypt vs memtable blob), F-099 (compact no flush), F-100 (liveness understated), F-101 (extent mid-publish), F-102 (GC vs unflushed overwrite) fixed; F-103 open for the human.
- 2026-10-09 — F-103 fixed (human chose a: value log, no put-time BLOBs); final Java M2.2 run started.
- 2026-10-09 — Java M2.2 4999/5000; F-104 (rotate OOM on a free page) fixed; M1.2 10k and M2.2 rerun started on the remote Mac.
- 2026-10-09 — M2.2 Java done (5000/0). M3 started: cargo-fuzz (8) + Jazzer (7) targets; F-105..F-112 fixed (Rust, Java, Dart); collectionReclaimsSpace flake fixed.
- 2026-10-10 — Rust fuzz 8x4 h clean; M1.2 Rust 10k clean; F-115 (Java liveness vs visibleSeq) fixed; Java M1.2 and Jazzer rerun.
- 2026-10-10 — CPU work moved to the remote Mac; F-116 (TIME signed order), F-117 (vlog stats shape) fixed in Java + Dart; F-118 (wrong-shape records) fixed in all three.
- 2026-10-10 — Jazzer was under JDK 24 (no instrumentation); openjdk@21 installed; F-119 (Java Verify.walk recursion) fixed; Java M1.2 encrypted seed 9334 diverges.
