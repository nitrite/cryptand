# HANDOFF — Cryptand 1.0 release

## State (2026-10-06)

- Branch `packaging/v1.0.0`, tracking `origin` = github.com/nitrite/cryptand
  (public). `main` and `packaging/v1.0.0` pushed 10-06; later commits not yet.
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
- M1.1 done. M1.2 Rust done: `oplog_check` (replay, `--seeds A..B`,
  `--shrink`), 300 seeds × 2000 ops clean after fixing F-018…F-022 (commit
  edbd6cd). F-022's two filters still need the M2.5 ownership audit as control.
- Model semantics: a snapshot sees only *committed* writes (`visible_seq`);
  op-log `commit` = flush + commit.
- **M1.2 Java in progress (10-06).** `OplogCheckTest` (lsm package) replays
  `regress/` (in the gate) and `-Doplog.dir` logs; `tools/oplog_java.sh A B
  [knobs]` feeds it Rust `oplog_gen` output. `main --shrink FILE` minimizes
  (any-of-5 replays, since Java's committer/compactor threads make some bugs
  racy). Fixed in Java: F-026 scan read-ahead past EOF, F-027 GC rewrites a
  snapshot-only version over newer data, F-028 scan misses acknowledged
  writes, F-029 lookup early exit wrong across range-partition groups. F-025
  (cursor upper bound inclusive) noted only. Regress logs f027, f029 added;
  Rust replays them with identical digests.
- **Java still red at scale:** mix without compact/reopen/shrink is clean
  (100 seeds × 2000 ops); `+compact` ~65/100 and `+reopen` ~25/100 seeds
  diverge (stale/absent gets, "value-log segment N has no entry in tree 7").
  Racy: a 55-line shrink passed 20/20 replays. Unproven suspect: GC
  check-then-rewrite races a concurrent user put (writers skip `structure`).

## Decisions already made (human, 10-06)

- Scope: **the three engine packages only**. Nitrite adapters come next month.
- Dart: **do the storage rewrite (M5)**, on branch `dart-storage`. Go/no-go
  **Fri 10-23**; if it misses, Dart ships `1.0.0-rc.1` from the in-memory
  engine and Rust/Java ship 1.0.0.
- Final tags Fri 10-30; code freeze Tue 10-27.

## Open questions for the human

1. OK to push the new commits on `packaging/v1.0.0`? (M0.5 CI needs them on GitHub.)
2. **[H] M8.2:** are crates.io, Maven Central `org.dizitart` and a pub.dev
   publisher available to you? pub.dev needs you to publish `1.0.0-rc.1` by
   hand once.
3. Is a 24 h soak per engine (M6.7) acceptable on this machine, given that it
   ties up the External SSD?

## Next action

Make the Java `+compact` divergence deterministic: replay with the background
compactor idle (or call `maintain()` only from op-log `compact`) to tell an
engine race from a sequential bug; then shrink, fix, add `regress/`, repeat for
`+reopen`. Target: `tools/oplog_java.sh 0 300 --ops 2000` → 0 divergences.
Then Dart.

## Log

- 2026-10-06 — Surveyed the repo, ran the full baseline (green), got the scope
  and Dart decisions, wrote PLAN/HANDOFF/FINDINGS/CLAUDE.md.
- 2026-10-06 — M0.2: `tools/gate.sh` written, quick green, flip test fails it.
- 2026-10-06 — M1.1: op-log format + seeded generator; origin added, not pushed.
- 2026-10-06 — Pushed to origin. M1.2 Rust checker + shrinker; fixed F-018…F-022 (4×S0, 1×S1); gate green.
- 2026-10-06 — M1.2 Java checker; fixed F-026…F-029 in Java (2×S0, 2×S1); compact/reopen mixes still diverge.
