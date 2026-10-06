# HANDOFF — Cryptand 1.0 release

## State (2026-10-06)

- Branch `packaging/v1.0.0`; `main` exists locally. `origin` =
  github.com/nitrite/cryptand (public, created by the human 10-06, still
  **empty — nothing pushed yet**, awaiting the human's go).
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
- M0.1–M0.3 done. `tools/gate.sh quick` is green (190 s, M2 Pro) and proven
  to fail. Its later stages print `PENDING` until M1.4/M2.2/M3/M6 build them.
  Clippy correctness/suspicious had 2 hits, both intentional, now `#[allow]`ed
  with a reason (`container.rs` `writable`, `multiproc.rs` perms restore).
- M1.1 done: op-log format `reference/conformance/oplog/README.md`, generator
  `cargo run -p cryptand --features harness --bin oplog_gen -- --seed N`.
  Unverified assumptions for M1.2: engine trees 1..N need no creation step;
  `Value::Bytes` CKE order = memcmp of the raw bytes.

## Decisions already made (human, 10-06)

- Scope: **the three engine packages only**. Nitrite adapters come next month.
- Dart: **do the storage rewrite (M5)**, on branch `dart-storage`. Go/no-go
  **Fri 10-23**; if it misses, Dart ships `1.0.0-rc.1` from the in-memory
  engine and Rust/Java ship 1.0.0.
- Final tags Fri 10-30; code freeze Tue 10-27.

## Open questions for the human

1. **[H] M0.4:** OK to push `main` and `packaging/v1.0.0` to `origin`? Then M0.5 (CI).
2. **[H] M8.2:** are crates.io, Maven Central `org.dizitart` and a pub.dev
   publisher available to you? pub.dev needs you to publish `1.0.0-rc.1` by
   hand once.
3. Is a 24 h soak per engine (M6.7) acceptable on this machine, given that it
   ties up the External SSD?

## Next action

**M1.2:** Rust model checker (harness bin `oplog_check`): replay a log against
`Engine` and a `BTreeMap`, compare every read and the digest. Then Java, Dart.

Parallel sessions, if wanted: track B starts M5.1 in a worktree on
`dart-storage`; track C starts M6.1 (the workload binary) in a worktree on
`scale`.

## Log

- 2026-10-06 — Surveyed the repo, ran the full baseline (green), got the scope
  and Dart decisions, wrote PLAN/HANDOFF/FINDINGS/CLAUDE.md.
- 2026-10-06 — M0.2: `tools/gate.sh` written, quick green, flip test fails it.
- 2026-10-06 — M1.1: op-log format + seeded generator; origin added, not pushed.
