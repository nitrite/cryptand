# HANDOFF — Cryptand 1.0 release

## State (2026-10-09, end of session 9)

- Branch `packaging/v1.0.0`. Manifests at 1.0.0, nothing published, no tags.
  Java targets Java 11 (built on JDK 17). Java `mvn verify` 360 green, Rust
  `cargo test --workspace` (debug) green 10-08; Rust `--release` not re-run
  (it would replace the binary the running M2.2 job uses).
- M0 done. M1: hop 0..1000 plain and 0..300 encrypted clean; 10 000-seed
  M1.2 runs still pending. M2.1: fault sweeps 1000 seeds clean (Rust, Java).
- M2.3 `tools/enospc.sh`: **Rust and Java green, plain + encrypted** (Java 3/3)
  after F-093 (GC freed a batch mid-commit), F-094 (cold segments sized to
  content; open tolerates a full device), F-095 (failed publish skipped a
  commit id; Rust also kept an unpublished nonce limit). Dart halves are M5.
- M2.2: Rust run on the pre-F-093 build: seeds 1000..4356 0 engine failures,
  then 11 ENOSPC FAILs and a crash (host disk full from leaked `.bak`s,
  F-096). Java run not yet started.
- F-096 (S1): hot value-log segments grow geometrically from 256 KiB (Rust +
  Java); F-094's cold sizing ported to Rust. `torture.py` cleans `.bak`.
- Open S1/S0 outside M5: none. M5: F-035, F-038, Dart halves of F-072,
  F-080, F-084 check, M2.2 Dart, F-075, F-079, F-081, F-087, F-088, F-094, F-095, F-096, F-097 (Dart check).
- Rust `stall_test` fails whenever another job fsyncs on /Volumes/External;
  never build Java while a hop or Java torture runs, nor edit sources
  while `tools/gate.sh` runs (its interop stage rebuilds Java).

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

- none.

## Next action

Rerun `tools/enospc.sh` (F-096 changes sizing), restart Rust M2.2 on the new
build (`tools/torture.py rust 1000 3500 --ops 400 --maint 1`, then encrypted
3500..6000), then Java:
`nohup sh -c 'tools/torture.py java 101000 103500 --ops 400 --maint 1; tools/torture.py java 103500 106000 --ops 400 --maint 1 --encrypted' > reference/bench/runs/m22-java.log 2>&1 &`
Shrink any failure, record numbers. Then M1.2 10 000-seed runs, M3 fuzzing.

## Log

- 2026-10-06 — Survey, scope, M0.2 gate, M1.1–M1.3 (F-018…F-042). Details in git.
- 2026-10-07 — Hop sweeps, CI 26/26, F-043…F-077; M0 done; M2.1 fault seams; F-072 Rust + Java encrypt/decrypt. Details in git.
- 2026-10-08 — Java rotate; F-072 g in Rust+Java + interop step 12; F-075, F-077, F-078, F-079 (S0), F-081 (S0) fixed; F-080 found.
- 2026-10-08 — F-080 (S1) fixed in Rust + Java; gate quick green.
- 2026-10-08 — F-080 follow-up (Rust Database compaction), F-082/F-083/F-084 (S0) fixed; M2.2 harness; 5000-kill runs started.
- 2026-10-08 — CI fix (F-088); Java converts under snapshots (F-087); F-085, F-086 from M2.2; M2.3 harness: F-089–F-092 fixed, F-093 open.
- 2026-10-08 — F-093 (GC vs in-flight batch), F-094 (cold extent sizing), F-095 (failed publish numbering, Rust nonce limit); M2.3 green in Rust and Java.
- 2026-10-09 — Decisions on F-094 parity, profile floor, bundled commits; F-096 (hot extents, harness `.bak` leak filled the disk) fixed in Rust + Java; F-097 (Java double rollover orphaned a segment) fixed.
