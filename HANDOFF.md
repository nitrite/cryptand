# HANDOFF — Cryptand 1.0 release

## State (2026-10-07, end of session)

- Branch `packaging/v1.0.0`, tracking `origin` (github.com/nitrite/cryptand).
  Commits after the 10-06 morning push are **not pushed** (open question 1).
- Three engines, Level 4 + encryption, in `reference/`; manifests at 1.0.0,
  nothing published, no tags. `tools/gate.sh quick` **green** (~7 min, M2
  Pro): suites, interop, oplog regress in all three, 7 hop vectors × 3 rotations.
- **M1.2 checkers in all three** (Rust `oplog_check`, Java `OplogCheckTest`
  with `Verify` after every reopen, Dart `test/oplog_check_test.dart`), each
  with a shrinker. Final-code sweeps (2000 ops): Rust 300 plain + 100 enc clean;
  Java 300 plain (1 divergence = F-052 suspect) + 50 enc clean; Dart last ran
  200 plain + 24 enc before F-053/F-055 (slow: F-038).
- **M1.3 hop:** `tools/oplog_hop.sh` (writers rotate Rust→Java→Dart on one file
  at `reopen` lines; all three agree on the digest; Rust `cryptand verify` finds
  nothing, leaks included). Clean, `--ops 400` reopen-heavy mix: seeds 0..150
  plain and 0..40 encrypted (the later ones on the final code).
- Fixed 10-06/07: F-030…F-034, F-036, F-037, F-039…F-051, F-053…F-055 (each with
  a control shown failing, except the racy F-047/F-051, which have a rate).
  Cross-language and on-disk: F-042 range-delete `end_key` (**human: CKE-only**,
  spec 04 §2.5), F-043, F-044/F-050 BLOBs (Rust/Dart could not read Java's;
  nobody freed dropped ones), F-046, F-048 (Rust repair), F-053 (F-029 in
  Rust/Dart), F-054 (Rust shrink cut a blob), F-055 (Dart freed live segments).
- Open: **F-052** (S1 suspect, Java `live_bytes` understated once in 300
  seeds under heavy load, not reproduced); for M5: F-035 (Dart writer lock,
  spec 01 §10 MUST), F-038 (Dart file growth), F-048's Dart verify leak report (S3).

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

Chase F-052: run `tools/oplog_java.sh 0 300 --ops 2000` with the machine
loaded (e.g. alongside a hop sweep) until it recurs, keep the failing
`-Doplog.trace` output, and compare `recomputeLiveness` with the
publish/seal paths. Then M1.5 (query differential) and the 10 000-seed
runs of 1.2/1.3 as `nohup` jobs.

## Log

- 2026-10-06 — Survey, baseline, scope; M0.2 gate; M1.1 op-log; M1.2 Rust (F-018…F-022).
- 2026-10-06 — M1.2 Java checker; F-026…F-029.
- 2026-10-06 — Java clean (F-030/31/34/36/37/40), Dart checker (F-032/33/39), F-041, M1.3 hop → F-042.
- 2026-10-07 — Hop sweeps: F-043…F-051 across all three; hop 50 plain + 20 enc clean; gate green.
- 2026-10-07 — Final-code sweeps; F-052 (suspect), F-053 (F-029 in Rust/Dart), F-054, F-055; hop 0..150 plain + 0..40 enc clean.
