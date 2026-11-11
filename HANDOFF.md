# HANDOFF — Cryptand 1.0 release

## State (2026-11-11)

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
- 6.7 Java soak 11-09 FAILED on harness, not engine: 65 cycles all sound, but the Java
  soak fsynced every op (~20 ops/s vs Rust's 1000-op commits), an uncapped JVM heap read as
  RSS growth, and the deadline cut the last cycle (acked 0). Fixed in 4991082 (Java batches
  1000 ops, -Xms=-Xmx 3g, no truncated cycle) + Dart soak mode (human 11-11: Dart soaks too).
  Smoke at 2e4: R ~140k, J ~100k, D ~80k ops/s. Old run: remote `runs/soak-11-09-java-fail`.
- RERUN launched 11-11 00:50 IST: remote `~/soak67jd.sh`, outputs `runs/soak2/`: gate ->
  Java 24 h on existing j.cff (`java-done`) -> rm j.cff -> Dart 10^8 build -> Dart 24 h (`done`).
  Check acked non-zero every cycle and min RSS flat, not just PASS.

- Audit 11-11 (PLAN A1): F-215 (blob read, R+D), F-216 (Dart postings `first_doc`, human go),
  F-217 (postings decode, R+J) fixed, each with a test that fails reverted. F-218: CI had not
  run since 10-12 (trigger lacked `dart-storage`) and was red on Windows; test fixed, branch
  added, **first run not yet read**.
- F-219 (A1.5) wired 11-11 in R+J+D: writer sidecar + heartbeat + slots in each commit's floor,
  reader claim/re-pin/heartbeat/release, volatile with reason. Spec 13 §8 now names magic
  "CLK1", the claim lock (1 byte at 2^40) and a reader creating a missing sidecar (human 11-11).
  Gate stage `multiproc (3x3)` = `reference/conformance/interop/multiproc.py`. Readers now leave
  `*.cryptand-lock` beside files they open (gitignored; corpus digests skip them).
  Dart beats on its own ops only (a Dart timer kept never-closed handles' processes alive): an
  idle Dart reader >6 s is reclaimed and its next read says reopen; R/J beat on a thread.
  F-220 (open): a read of reused pages hangs (R) or returns 0 rows (J, D) instead of failing.

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

1. `gh run list --branch dart-storage`: read the first CI run since 10-12 (now also runs the
   multiproc tests on Windows); fix what Linux and Windows show (A1.3). 2. Soak: when remote
   `reference/bench/runs/soak2/java-done` exists, read `java.out`; at `done`, `dart.out` (+
   `soak-11-03/rust.out`); record in RESULTS.md, tick 6.7. 3. A1.4's interop full-text step. Then 6.8.

## Log
- 11-11: F-219 multi-process readers wired R+J+D, spec 13 §8 pinned (magic, lock byte, no-sidecar), 3x3 gate stage; F-220 filed.
- 11-11: audit A1: F-215..F-219 filed; F-215/216/217 fixed, F-218 CI trigger + Windows test, F-219 approved to wire.
- 11-11: 6.7 Java soak FAIL traced to harness (per-op fsync, uncapped heap, cut cycle); fixed 4991082, Dart soak added, J+D rerun launched.
