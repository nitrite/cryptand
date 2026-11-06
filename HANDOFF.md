# HANDOFF — Cryptand 1.0 release

## State (2026-10-31)

- Branch `dart-storage` (pushed). Manifests 1.0.0, nothing published, no tags.
  Done: M0, M4; M1–M3, M5 per PLAN status table. M6 6.5 rungs (index,
  full-text, spatial, vector) PASS R+J+D at 10^6 (10^7 for index/text/spatial).
- Vector 10^6 (v6, pre-F-205, ef 100), bar 448 MB, all sound, recall 0.824:
  R build 5339 s, 2.52 GB, peak 172 MB; J 4841 s, 2.33 GB, 370 MB;
  D 7421 s, 2.88 GB, 405 MB. F-205 (per-search beam) committed after.
- 6.6 PASS (11-01, remote, 72e7823): patho at 10^6, 8 workloads x R+J+D, all
  verify sound, bad=0. Wall: R 106 s, J 95 s, D 807 s. bigdoc R 1.71 / J 2.35 /
  D 2.10 GB; colls R 47 s / J 2.4 s / D 112 s. J process peak 4.4 GB (one JVM
  for all 8; per-workload RSS not split). Logs: remote bench/runs/p66.
  Rungs: Rust `rss_scale PATH N patho [W]`, Java `RssScale PATH N patho [W]`,
  Dart `scale patho PATH N [W]`.

- 6.7 Rust soak PASS (11-03 run, remote `reference/bench/runs/soak-11-03/`): 69 cycles at 10^8,
  all sound, RSS 1312 -> 1262 MB, fds 8, bytes flat 90.2 GB. Not yet in RESULTS.md.
- 6.7 Java soak RELAUNCHED 11-06 at 0150b00 (F-213: the 11-03 run acked 0 writes after cycle 1,
  writer hung on reopen). Remote `~/soak67j.sh`, log `~/soak67j.log`: gate quick -> J 10^8 build
  -> 24 h soak. Outputs in remote `reference/bench/runs/soak/` (`java.out`, `java/cycles.csv`, `done`).
  Check the `acked` column is non-zero every cycle, not just PASS.

## Must-keep (any Dart rewrite or refactor)

F-127/F-128 format bits; `_cmpU64`/`_addSaturating`; F-135/F-136 zeroing;
F-137 key-on-plaintext refusal; F-138 `uvar() < 0 ||` checks; `_writeOwnerOnly`
(0600); code that moves an extent keeping its segment id MUST evict it (F-156).

## Remote and traps

- Remote `anindya@207.254.39.186`: ONE clone `~/Documents/codebase/cryptand`
  (consolidated 11-01 at the human's request; old dirty diffs saved in
  `~/cryptand-patches`). Jazzer needs JDK 21. Databases go in `~/soakdb`.
- Corpus regen: `dart run tool/generate_corpus.dart`, then Rust
  `convert_test make_converting_vector` and `replay_test make_replay_vector` (`--ignored`).
- Corpus test needs `--features harness`; Rust `stall_test` fails while
  another job fsyncs; never build Java in a clone where a long job runs.
- Rungs: Rust `rss_scale PATH N <mode>`, Java `RssScale PATH N <mode>`,
  Dart `scale <mode> PATH N`; modes read/index/text/spatial/vector.

## Decisions in force (human)

- Scope = three engine packages; Dart ships 1.0.0 (go 10-27). Freeze/tag dates
  (10-27/10-30) passed; schedule for 6.6–6.8, M7, M8 to be set by the human.
- Java `--release 11` on JDK 17. F-072 all of 13 §5 in all three. F-103 value
  log, no put-time BLOBs. Spec 05/09: vector_graph is a CoW B+tree.
- Push every commit; one finding per commit. CPU-heavy work on remote only.

## Open questions for the human

- None. Schedule (human, 11-01): 6.7, 6.8, M7, M8 sequentially, ASAP.

## Next action

When remote `reference/bench/runs/soak/done` exists: read `java.out` (+ `soak-11-03/rust.out`),
record them in RESULTS.md (Scale table) and tick 6.7; file a finding for any
GREW/unsound. Then 6.8 (P2 vs fjall/RocksDB).

## Log
- 11-06: F-213 (Java reopen hang after kill) fixed; Java soak relaunched on remote.

- 10-27 — Dart go; 6.5 index rung, F-182/F-183 fixed.
- 10-28 — F-184..F-188 (index footprint, probes, L0 backlog, segment commit_id).
- 10-29 — F-184 Dart fixed; F-189 compaction bound; full-text rung, F-190/F-191.
- 10-30 — F-192..F-204: spatial/vector on pages R+J+D, Vamana prune, F-202 closed.
- 10-31 — F-203 fixed (R 865 -> 172 MB), F-205 beam width; v6 vector 10^6 PASS
  R+J+D; F-204 closed at 1.4x; space_test fd flake fixed; handoff trimmed (294 -> ~60 lines).
- 10-31 — 6.6 rungs R+J+D; F-206..F-208 fixed; F-209, F-210 open.
- 10-31 — F-206..F-208 committed (gate green); F-210 J fixed; f160 fd bound 4.
- 10-31 — F-210 R (eager free of unpublished catalog pages) + D (owner map) fixed.
- 11-01 — F-210 10^5 rerun PASS R+J+D; F-209 debt-loop guard R+D (partial).
- 11-01 — F-209 closed: spec §6.9 run_capacity (human go), R+J+D.
- 11-01 — 6.6 PASS at 10^6 R+J+D.
- 11-01 — F-211 R colls 46.6 -> 10.4 s (CoW node cache); write-back and D open.
- 11-01 — remote consolidated to one clone (114 GB free); soak harness; 6.7 launched.
- 11-03 — F-212 (J aged scan, stale liveness gate) fixed; soak 6.7 relaunched.
