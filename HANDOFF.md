# HANDOFF — Cryptand 1.0 release

## State (2026-10-09, session 11)

- Branch `packaging/v1.0.0`. Manifests at 1.0.0, nothing published, no tags.
  Java targets Java 11 (built on JDK 17). Java `mvn verify` green after F-102;
  Rust `cargo test --workspace` (debug) green 10-08, `--release` rebuilt for M2.2.
- M0 done. M1: hop 0..1000 plain and 0..300 encrypted clean; 10 000-seed
  M1.2 runs still pending. M2.1: fault sweeps 1000 seeds clean (Rust, Java).
- M2.3 `tools/enospc.sh` green on the F-096 build, Rust + Java, plain + encrypted.
- M2.2 (this Mac, `/Volumes/External`): **Rust 5000 kills, 0 failures**
  (seeds 1000..6000, half encrypted). Java 5000 kills: 25 failures → 9 (after
  F-098, F-099) → 6 (after F-100, F-101). F-102 then fixed the corruption class;
  the only failures left are F-103 leaks (104067 8/10, 103891 2/10). A final
  Java 5000-kill run on the F-102 build has **not** been run.
- F-098..F-103 fixed in Java (Rust checked: not affected; Dart unchecked, M5).
- Open S1/S0 outside M5: none. M5: F-035, F-038, Dart halves of F-072,
  F-080, F-084 check, M2.2 Dart, F-075, F-079, F-081, F-087, F-088, F-094..F-103 (Dart check).
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

Read the tail of `reference/bench/runs/m22-java4.log` (two lines, `… kills, N failures`).
0 failures: tick M2.2 for Java. Otherwise debug the failing seed with the recipe above.
Then M1.2 10 000-seed runs, M3 fuzzing.

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
