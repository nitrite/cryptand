# HANDOFF — Cryptand 1.0 release

## State (2026-10-07, end of session 5)

- Branch `packaging/v1.0.0`, every commit pushed (human 10-07). Manifests at
  1.0.0, nothing published, no tags. Java targets Java 11 (built on JDK 17).
  CI 26/26 green as of M0 (run 37597698770); not re-run since.
- M0 done. M1: hop 0..1000 plain and 0..300 encrypted clean; index
  differential in all three; the 10 000-seed M1.2 runs still pending.
- **M2.1** fault layers: Rust `src/fault.rs` (feature `faults`, tests only),
  Java `PageFile.Hook` + test-tree `container.Faults`. Sweeps: power cut,
  fsync EIO, ENOSPC, lying-fsync control; Rust also a power cut during
  in-place encryption. 1000 seeds × 3 clean in both (Rust ~10 min, Java ~15).
  Dart waits for M5. Found F-069 (S0, all three, slot B lookup; spec 01 §2.1
  amended), F-070, F-071 (S0, Java barrier; Dart's whole-file save → M5).
- **F-072** (13 §5 MUSTs): Rust complete — `keyapi.rs`, `convert.rs`
  (encrypt, decrypt with confirmation, resumable `convert_step`, fraction),
  `rotate.rs` (copy-and-swap, synchronous, refused while checkpoints exist).
  Interop steps 7–9 green in all three. Java: key ops only. Dart: M5.
- **F-073** (readers inferred encryption from `cipher`): Rust fixed; Java and
  Dart read Rust's converted files fine (blobs untested until Java converts).
- Open S1/S0 outside M5: F-072 (Java, Dart). M5: F-035, F-038.
- Rust `stall_test` fails whenever another job fsyncs on /Volumes/External;
  never build Java while a hop or Java fault sweep runs.

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

## Open questions for the human

(none)

## Next action

Check `reference/bench/runs/fault_rust_convert_0_1000.log` (1000-seed Rust
sweeps incl. conversion). Then F-072 for Java: port `convert.rs` (encrypt,
decrypt, convert_step, conversion) and `rotate.rs`; Java already has the key
ops. Java-written blobs give Rust's blob reader its first mixed-file test.
Then M2.2 kill -9 torture.

## Log

- 2026-10-06 — Survey, baseline, scope; M0.2 gate; M1.1 op-log; M1.2 Rust (F-018…F-022).
- 2026-10-06 — M1.2 Java checker; F-026…F-029.
- 2026-10-06 — Java clean (F-030/31/34/36/37/40), Dart checker (F-032/33/39), F-041, M1.3 hop → F-042.
- 2026-10-07 — Hop sweeps: F-043…F-051 across all three; hop 50 plain + 20 enc clean; gate green.
- 2026-10-07 — Final-code sweeps; F-052 (suspect), F-053 (F-029 in Rust/Dart), F-054, F-055; hop 0..150 plain + 0..40 enc clean.
- 2026-10-07 — F-052 root-caused and fixed (S0, Java seal during recount); F-056 (Dart live_records < 0) from hop seed 151.
- 2026-10-07 — Pushed; M0.5 CI matrix (F-061…F-064); M1.5 index differential (F-057…F-059); F-060 from hop seed 289.
- 2026-10-07 — Own Unicode tables in Java, Java 11 target, F-058/F-059 vectors; F-062…F-064 fixed; F-065 from hop seed 451.
- 2026-10-07 — CI 26/26 green (F-066, F-068 on the way); hop 0..1000 plain clean; M0 done.
- 2026-10-07 — F-067: one writer-lock byte (2^62) in all three + spec 01 §10; interop lock step.
- 2026-10-07 — Hop 0..300 enc clean; M2.1 Rust fault seam, 3000 fault seeds clean; F-069 (S0, all three), F-070.
- 2026-10-07 — Spec 01 §2.1 (F-069 approved); M2.1 Java fault seam, 3000 seeds clean; F-071 (S0, Java barrier; Dart → M5).
- 2026-10-07 — F-072 (S1) found scoping M2.2: 13 §5 MUSTs missing; human: implement all; Rust key ops done; design in PLAN.
- 2026-10-07 — F-072 Rust: encrypt/decrypt/convert/rotate + interop 7–9; F-073 (Rust readers); conversion crash sweep.
