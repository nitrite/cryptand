# HANDOFF — Cryptand 1.0 release

## State (2026-10-09, session 11)

- Branch `packaging/v1.0.0`. Manifests at 1.0.0, nothing published, no tags.
  Java targets Java 11 (built on JDK 17). Java `mvn verify` green after F-102;
  Rust `cargo test --workspace` (debug) green 10-08, `--release` rebuilt for M2.2.
- M0 done. M1: hop 0..1000 plain and 0..300 encrypted clean; 10 000-seed
  M1.2 runs still pending. M2.1: fault sweeps 1000 seeds clean (Rust, Java).
- M2.3 `tools/enospc.sh` green on the F-096 build, Rust + Java, plain + encrypted.
- M2.2 done for Rust and Java: 5000 kills, 0 failures each (Java seeds
  101000..103500 rerun on the remote Mac after F-104). Dart after M5.
- M1.2 10 000-seed runs still running on the remote Mac
  (`~/Documents/codebase/cryptand`, pre-F-104 checkout):
  `reference/bench/runs/m12-rust.log` (prints only at the end; plain then
  `--encrypted`), `m12-java.log` (`tools/oplog_java.sh`, plain then encrypted).
  Remote Java: `JAVA_HOME=/opt/homebrew/opt/openjdk@18` (system Java is 11).
- M3 (this Mac): 8 cargo-fuzz targets in `reference/rust/cryptand/fuzz/`
  (`seed.py` seeds `corpus/`), 4 h each from 10-09 ~20:00, logs
  `reference/bench/runs/fuzz/m3-*.log` (`cke_roundtrip` restarted ~20:10).
  Jazzer: `JazzerTest.java` (7 targets); fuzz one with `JAZZER_FUZZ=1 mvn
  surefire:test -Dtest=JazzerTest#openFile` (corpus `.cifuzz-corpus/`,
  git-ignored, seeded from the Rust corpora; `mvn verify` replays ~11.8k).
  Crash files go to `reference/conformance/files/fuzz-regress/` CRC-repaired
  (`CRYPTAND_FUZZ_DUMP=path` while replaying one), replayed by the hostile
  tests in all three. Fixed so far: F-105..F-110.
- `segment` (cov 254) and `superblock_keyslot` (cov 152) targets are shallow:
  `segment`'s seeds are single pages, not segment extents.
- Java `EngineTest.collectionReclaimsSpace` failed once under fuzz load
  ("fixture wrote too little"), green on rerun: a load-sensitive flake.
- F-098..F-103 fixed in Java (Rust checked: not affected; Dart unchecked, M5).
- Open S1/S0 outside M5: none. M5: F-035, F-038, Dart halves of F-072,
  F-080, F-084 check, M2.2 Dart, F-075, F-079, F-081, F-087, F-088, F-094..F-110 (Dart check), Dart corpus replay (M3.4).
- Rust `stall_test` fails whenever another job fsyncs on /Volumes/External;
  never build Java while a hop or Java torture runs, nor edit sources
  while `tools/gate.sh` runs (its interop stage rebuilds Java).
- Debug recipe that worked: loop one seed (`one()` from `tools/torture.py`),
  then halt the child at op boundaries (temporary `Runtime.halt` at the end of
  `tortureChild`) to tell op-boundary bugs from mid-op ones.

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

When the Rust fuzz campaign ends (~10-10 00:10), triage `m3-*.log` (crash files
under `fuzz/artifacts/`), then give `segment` real segment-extent seeds and run
the Jazzer campaign (2 h per target, one `mvn surefire:test` per target). Check
the remote `m12-*.log` (want `0 divergences`; then tick M1.2 for Rust + Java).

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
- 2026-10-09 — M2.2 Java done (5000/0). M3 started: cargo-fuzz (8) + Jazzer (7) targets; F-105..F-110 fixed (Rust, Java, Dart).
