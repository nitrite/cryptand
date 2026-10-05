# HANDOFF — Cryptand 1.0 release

## State (2026-10-06)

- Branch `packaging/v1.0.0`; `main` exists locally. **No git remote**, and
  `nitrite/cryptand` does not exist on GitHub yet (F-016).
- Three engines, each Level 4 + encryption, ~30k / 36k / 37k LOC
  (Rust / Java / Dart), in `reference/`. Packages are at version 1.0.0 in their
  manifests; nothing is published and there are no tags.
- Baseline on this M2 Pro, all **green**: `cargo test --workspace --release`;
  `mvn test` 325/325; `dart analyze` clean and `dart test` 655/655;
  `reference/conformance/interop/run.sh` passes 12 directions, plaintext and
  encrypted.
- Not green as a gate: `cargo fmt --check` (863 hunks, deliberately not
  gated) and clippy (~35 style warnings, gate only correctness/suspicious).
- Plan, ledger and rules are written: `PLAN.md` (M0–M8, Verify per step,
  calendar), `FINDINGS.md` (F-001…F-017 seeded: 3 confirmed Dart storage
  defects, 4 suspects, and the known gaps from HARDENING and the REPORTs).
- Nothing has been executed beyond the baseline. M0.1 and M0.3 are done.

## Decisions already made (human, 10-06)

- Scope: **the three engine packages only**. Nitrite adapters come next month.
- Dart: **do the storage rewrite (M5)**, on branch `dart-storage`. Go/no-go
  **Fri 10-23**; if it misses, Dart ships `1.0.0-rc.1` from the in-memory
  engine and Rust/Java ship 1.0.0.
- Final tags Fri 10-30; code freeze Tue 10-27.

## Open questions for the human

1. **[H] M0.4:** create `github.com/nitrite/cryptand` (public?) and add it as
   `origin`. CI, the OS matrix and releases are all blocked on it.
2. **[H] M8.2:** are crates.io, Maven Central `org.dizitart` and a pub.dev
   publisher available to you? pub.dev needs you to publish `1.0.0-rc.1` by
   hand once.
3. Is a 24 h soak per engine (M6.7) acceptable on this machine, given that it
   ties up the External SSD?

## Next action

**M0.2:** write `tools/gate.sh quick|full` exactly as specified in PLAN.md
M0.2. Run `quick`, prove it fails on a flipped assertion, and commit.
Then start M1.1 (the op-log generator) on track A.

Parallel sessions, if wanted: track B starts M5.1 in a worktree on
`dart-storage`; track C starts M6.1 (the workload binary) in a worktree on
`scale`.

## Log

- 2026-10-06 — Surveyed the repo, ran the full baseline (green), got the scope
  and Dart decisions, wrote PLAN/HANDOFF/FINDINGS/CLAUDE.md.
