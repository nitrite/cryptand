# HANDOFF — Cryptand 1.0 release

## State (2026-10-07)

- Branch `packaging/v1.0.0`, tracking `origin` (github.com/nitrite/cryptand).
  Commits after the 10-06 morning push are **not pushed** (open question 1).
- Three engines, Level 4 + encryption, in `reference/`; manifests at 1.0.0,
  nothing published, no tags. `tools/gate.sh quick` **green** (~4–6 min, M2
  Pro): suites, interop, oplog regress in all three, 3-language hop vectors.
- **M1.2 checkers in all three** (Rust `oplog_check`, Java `OplogCheckTest`
  with `Verify` after every reopen, Dart `test/oplog_check_test.dart`), each
  with a shrinker. Last clean sweeps (before F-043…F-051 landed): Rust 300
  plain + 100 enc; Java 0..600 plain + 100 enc; Dart 200 plain + 24 enc.
  Re-runs on the final code were running at session end:
  `reference/bench/runs/{rust_0_300,rust_enc_0_100,oplog_java_0_300,oplog_java_enc_0_50,hop_50_150}.log`.
- **M1.3 hop built and clean:** `--hop` legs in all three; `tools/oplog_hop.sh A B`
  rotates writers Rust→Java→Dart on one file at `reopen` lines, all three must
  agree on the final digest, and Rust's `cryptand verify` must find nothing
  (leaks included). Clean: seeds 0..50 plain, 0..20 encrypted (`--ops 400`,
  reopen-heavy mix). `--logs` replays `oplog/hop/*.jsonl` in every rotation (gate).
- Fixed 10-06/07 (each with a control shown failing, except the racy F-047/F-051,
  which have a rate): F-030…F-034, F-036, F-037, F-039…F-051. On-disk/cross-language
  ones: F-042 range-delete `end_key` (**human: CKE-only**, spec 04 §2.5),
  F-043 collected segments left in tree 7, F-044 Rust/Dart could not read
  Java's BLOBs, F-046 Rust rewrote encrypted records keyless, F-048 Rust
  `repair` destroyed blobs, F-050 no one freed dropped blobs.
- Open for M5 (Dart rewrite): F-035 writer lock not held (spec 01 §10 MUST),
  F-038 Dart file grows ~4× live data per open→save (makes Dart replays
  minutes per log and hop files GBs). F-048 Dart verify reports blobs as
  leaks (S3).

## Decisions already made (human)

- 10-06: scope = the three engine packages; Dart storage rewrite (M5) on
  `dart-storage`, go/no-go Fri 10-23 else Dart ships `1.0.0-rc.1`; freeze
  Tue 10-27, tags Fri 10-30.
- 10-06: F-042 — range-delete `end_key` is `CKE(end)`, no `tree_id`.

## Open questions for the human

1. OK to push `packaging/v1.0.0`? (M0.5 CI needs it on GitHub.)
2. **[H] M8.2:** crates.io, Maven Central `org.dizitart`, pub.dev publisher
   available? pub.dev needs a hand publish of `1.0.0-rc.1` once.
3. A 24 h soak per engine (M6.7) on this machine, tying up the External SSD?

## Next action

Read the five run logs above; shrink and fix any divergence (Java: replay
with `IDLE=false`, then `-Doplog.maintain=true`; hop: rebuild the chain leg by
leg and run Java `--hop … N N` as a verifier after each). Then M1.5 (query
differential) and the 10 000-seed runs of 1.2/1.3 as `nohup` jobs; Dart's
share waits on F-038 or runs on the no-reopen mix only.

## Log

- 2026-10-06 — Survey, baseline, scope; M0.2 gate; M1.1 op-log; M1.2 Rust (F-018…F-022).
- 2026-10-06 — M1.2 Java checker; F-026…F-029.
- 2026-10-06 — Java clean (F-030/31/34/36/37/40), Dart checker (F-032/33/39), F-041, M1.3 hop → F-042.
- 2026-10-07 — Hop sweeps: F-043…F-051 across all three; hop 50 plain + 20 enc clean; gate green.
