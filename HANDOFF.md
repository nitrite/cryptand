# HANDOFF — Cryptand 1.0 release

## State (2026-10-07, end of session 3)

- Branch `packaging/v1.0.0`, pushed to `origin` (github.com/nitrite/cryptand).
  Human 10-07: always push after committing. Registries (crates.io, Maven
  Central `org.dizitart`, pub.dev) are set up; nitrite already publishes there.
- Three engines, Level 4 + encryption, in `reference/`; manifests at 1.0.0,
  nothing published, no tags. `tools/gate.sh quick` green (now builds Rust
  with `--features cryptand/harness`, so the conformance test never runs a
  stale `interop` binary).
- **CI (M0.5)** `.github/workflows/ci.yml`: ubuntu/macos/windows × Rust
  stable+1.89, JDK 17/21/25, Dart 3.5+stable, interop ×3, cargo-deny; actions
  pinned by SHA; runs on `packaging/**` pushes. First run found F-061 (fixed),
  F-062, F-063, F-064 (open), plus JaCoCo 0.8.13 for JDK 25 and cargo-deny
  private crates (fixed).
- **M1.5** `query_diff_test` in all three (index eq / eq-numeric / range /
  starts_with vs a brute-force model): 2000 seeds each clean after F-057
  (Java had no range helper), F-058 (Dart empty array → NULL), F-059 (Java
  unresolved traversal → no entry). Controls shown failing.
- **F-052 verified:** Java oplog 0..300 × 2000 ops clean. **Hop 152..289**
  clean; seed 289 found **F-060** (S0, Rust GC freed an expired entry's value:
  F-049 had been marked "Rust ok"). Fixed, vector `oplog/hop/f060-*`.
- Open for M5: F-035 (Dart writer lock), F-038 (Dart file growth), F-048's Dart
  verify leak report (S3). Open S1: F-062, F-063.

## Decisions already made (human)

- 10-06: scope = the three engine packages; Dart storage rewrite (M5) on
  `dart-storage`, go/no-go Fri 10-23 else Dart ships `1.0.0-rc.1`; freeze
  Tue 10-27, tags Fri 10-30.
- 10-06: F-042 — range-delete `end_key` is `CKE(end)`, no `tree_id`.
- 10-07: push every commit. Soak (M6.7) runs on the remote Mac
  (`anindya@207.254.39.186`) when it is free, never here. It was busy 10-07
  (llama-server at 96 % CPU) and has no Dart SDK; Rust and Java soak only.

## Open questions for the human

1. **F-062:** Java 17's normalizer is Unicode 13, so full-text terms differ.
   Raise Java's minimum to **JDK 21**, or ship our own normalization tables
   in Java (bigger, keeps 17)?
2. F-058/F-059 change which index entries Dart/Java write for `[]` and for
   a path no array element resolves, to match the spec's literal reading
   (and Rust). Bytes for those documents change; no spec text changes. Add
   conformance vectors for both cases? (Vectors need your approval.)

## Next action

Hop seeds 290..1000 plain and 0..300 encrypted on the F-060 code
(`nohup tools/oplog_hop.sh 290 1000 --ops 400`), then the 10 000-seed
runs of 1.2. In parallel: F-063 (Rust positional I/O + `multiproc` on Windows).

## Log

- 2026-10-06 — Survey, baseline, scope; M0.2 gate; M1.1 op-log; M1.2 Rust (F-018…F-022).
- 2026-10-06 — M1.2 Java checker; F-026…F-029.
- 2026-10-06 — Java clean (F-030/31/34/36/37/40), Dart checker (F-032/33/39), F-041, M1.3 hop → F-042.
- 2026-10-07 — Hop sweeps: F-043…F-051 across all three; hop 50 plain + 20 enc clean; gate green.
- 2026-10-07 — Final-code sweeps; F-052 (suspect), F-053 (F-029 in Rust/Dart), F-054, F-055; hop 0..150 plain + 0..40 enc clean.
- 2026-10-07 — F-052 root-caused and fixed (S0, Java seal during recount); F-056 (Dart live_records < 0) from hop seed 151.
- 2026-10-07 — Pushed; M0.5 CI matrix (F-061…F-064); M1.5 index differential (F-057…F-059); F-060 from hop seed 289.
