# HANDOFF — Cryptand 1.0 release

## State (2026-10-08, end of session 6)

- Branch `packaging/v1.0.0`. Manifests at 1.0.0, nothing published, no tags.
  Java targets Java 11 (built on JDK 17). Gate quick green 10-08 (see Log).
- M0 done. M1: hop 0..1000 plain and 0..300 encrypted clean; 10 000-seed
  M1.2 runs still pending. M2.1: fault sweeps 1000 seeds clean (Rust, Java).
- **F-072 done in Rust and Java** (Dart: M5): encrypt/decrypt/convertStep,
  key ops, and rotate (Java `Engine.rotateMasterKey`, port of `rotate.rs`).
  Vector regions and descriptor-rooted index trees (R-tree, vector graph) are
  re-laid by conversion and re-sealed by rotation (PLAN F-072 g). Java live
  indexes convert their own structures via `Engine.registerOwner`. Interop:
  steps 7–9 and the new step 12 (indexed Java file; Rust and Java each
  encrypt, rotate and decrypt it; Java queries both indexes; both verify).
- Fixed this session: F-075 (encrypted vector-region layout, Rust + Java),
  F-077 (flaky containment test: 11/400 under load → 0/400), F-078 (Java
  vector-index deadlocks under `sync`), F-079 (S0: index structures read as
  leaks by verify, so `repair` freed them; skipped by rotate/convert), F-081
  (S0, Rust: in-place conversion retired value-log segments the memtable
  still pointed into; plus three false positives in Rust verify).
- F-080 fixed in Rust + Java (S1, both had it): tree 1 written fresh at EOF
  every commit + never-coalesced 1-page extents → 1000 tiny sync commits made
  684 MB (Java) / 114 431 pages (Rust). Now coalesced and placed in the lowest
  reclaimable extent; 76 / 516 pages. Java also extends the file to
  `page_count` at publish (a free tail left it short; Dart sizes its store
  from the file length). Dart halves → M5.
- Open S1/S0 outside M5: none new. M5: F-035, F-038, Dart halves of F-072,
  F-080 (fresh tree 1; `fromBytes` page count), F-075 (no region storage), F-079, F-081.
- Rust `stall_test` fails whenever another job fsyncs on /Volumes/External;
  never build Java while a hop or Java fault sweep runs, nor edit sources
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

## Open questions for the human

(none)

## Next action

M2.2 kill -9 torture (Rust + Java). Optional first: re-measure the 10-08
vector-index case (3000 one-doc inserts, was 2.3 GB) to confirm F-080 covers it.

## Log

- 2026-10-06 — Survey, scope, M0.2 gate, M1.1–M1.3 (F-018…F-042). Details in git.
- 2026-10-07 — Hop sweeps, CI 26/26, F-043…F-077; M0 done; M2.1 fault seams; F-072 Rust + Java encrypt/decrypt. Details in git.
- 2026-10-08 — Java rotate; F-072 g in Rust+Java + interop step 12; F-075, F-077, F-078, F-079 (S0), F-081 (S0) fixed; F-080 found.
- 2026-10-08 — F-080 (S1) fixed in Rust + Java; gate quick green.
