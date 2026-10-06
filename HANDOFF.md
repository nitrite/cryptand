# HANDOFF — Cryptand 1.0 release

## State (2026-10-06, evening)

- Branch `packaging/v1.0.0`, tracking `origin` (github.com/nitrite/cryptand).
  Commits after 10-06 morning are **not pushed** (open question 1).
- Three engines, Level 4 + encryption, in `reference/`; manifests at 1.0.0,
  nothing published, no tags. `tools/gate.sh quick` **green** (247 s, M2 Pro),
  now with oplog regress replayed by all three and the 3-language hop stage.
- **M1.2 model checkers in all three** (Rust `oplog_check`, Java
  `OplogCheckTest`, Dart `test/oplog_check_test.dart`), each with a shrinker.
  Clean: Rust 300 plain + 100 encrypted seeds; Java 0..600 plain + 100
  encrypted (full default mix, background compactor on); Dart 200 plain + 24
  encrypted. 10 000 seeds × 3 (the 1.2 Verify) not run yet.
- **M1.3 hop built:** `--hop` legs in all three, `tools/oplog_hop.sh A B` (one
  file, writers rotate at `reopen` lines, all three must agree on the final
  digest) and `--logs` for committed logs (`oplog/hop/`, in the gate). Sweep of
  50 plain + 20 encrypted seeds was running at session end:
  `reference/bench/runs/hop_*.log`.
- Fixed this session (all with a control shown failing): Java F-030 F-031
  F-034 F-036 F-037 F-040, Dart F-032 F-033 F-039, all three F-041, Rust F-042
  (on-disk range-delete `end_key`; **human approved CKE-only**, spec 04 §2.5
  clarified). Java harness: `Options.backgroundCompaction`, `-Doplog.idle`,
  `-Doplog.maintain` (deterministic `maintain()` per op), `-Doplog.trace`.
- Open, assigned to M5 (Dart storage rewrite): F-035 Dart does not hold the
  writer lock for the session (spec 01 §10 MUST); F-038 Dart file grows ~4× the
  live data per open→write→save. Both are why Dart op-log replays are slow.
- Model semantics: a snapshot sees only committed writes; op-log `commit` =
  flush + commit.

## Decisions already made (human, 10-06)

- Scope: the three engine packages only. Dart storage rewrite (M5) on branch
  `dart-storage`, go/no-go Fri 10-23, else Dart ships `1.0.0-rc.1`.
- Final tags Fri 10-30; code freeze Tue 10-27.
- F-042: range-delete `end_key` is `CKE(end)` without `tree_id`.

## Open questions for the human

1. OK to push `packaging/v1.0.0`? (M0.5 CI needs it on GitHub.)
2. **[H] M8.2:** crates.io, Maven Central `org.dizitart`, pub.dev publisher
   available? pub.dev needs a hand publish of `1.0.0-rc.1` once.
3. A 24 h soak per engine (M6.7) on this machine, tying up the External SSD?

## Next action

Read `reference/bench/runs/hop_0_50.log` and `hop_enc_0_20.log`; shrink and
fix any divergence (start with a single-language `--hop` chain to see which
writer/reader pair disagrees). Then M1.5 (query differential), and the 10 000
seed runs of 1.2/1.3 as `nohup` background jobs.

## Log

- 2026-10-06 — Surveyed, baseline green, scope/Dart decisions, PLAN/HANDOFF/FINDINGS.
- 2026-10-06 — M0.2 gate; M1.1 op-log format + generator; pushed.
- 2026-10-06 — M1.2 Rust checker; F-018…F-022 fixed.
- 2026-10-06 — M1.2 Java checker; F-026…F-029 fixed.
- 2026-10-06 — Java clean (F-030/31/34/36/37/40), Dart checker + F-032/33/39,
  F-041 ×3, M1.3 hop → F-042 (human: CKE-only). F-035, F-038 logged for M5.
