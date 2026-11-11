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
- RERUN launched 11-11 00:50 IST (`~/soak67jd.sh`) DIED: remote disk full, Java soak hit ENOSPC
  (`runs/soak2/java.out`). 11-11 cleanup deleted `~/soakdb/j.cff`, all Ollama models and sheaflet
  GGUFs; remote now ~146 GB free. Rerun needs a fresh Java 10^8 build before the 24 h soak.

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
  F-220 fixed 11-11 R+J+D: a reader rejects pages newer than its snapshot, segment pages off
  their head's commit, a segment head naming another `segment_id`, a CoW page of another tree.
  F-221 fixed 11-11 R+D (human go): CoW pages carry their commit (R catalog/attributes had 0 too);
  Dart hostile_test no longer rewrites the fuzz-regress corpus in place.
- F-211 fixed 11-11 R+D: catalog/tree 3/attributes held in memory, flushed before any page/root read
  (J's design; R `snapshot()` and `Transaction::begin` now return Result). colls 10^5 R 5.7 s, D 6.5 s,
  J 2.4; costs file +20-40% and R RSS 321 -> 614 MB.
- Review 11-12 of F-205..F-221 (committed, gate quick green on remote):
  F-223 (S0, R+D): F-211's `flush` dropped held catalog edits before writing them, so a commit
  retried after ENOSPC/EIO lost new collections; fixed, tests fail reverted. F-222 (S2, R+J+D):
  a reader claim could land between the writer's slot read and its superblock; the writer now
  holds the claim lock across both. F-212 re-fixed (reset was conditional). F-218: first CI runs
  read, 7/26 red: Dart Windows `_close` re-lock (product bug), Windows test teardown, two 3.5.0
  lints, F-220 test race, F-212; all fixed locally, **Windows unverified until CI runs**.
- Remote has Dart at `~/dart-sdk/bin` (not on the default PATH; the gate needs it). The gate now
  raises `ulimit -n`: at 256 the Dart runner died of EMFILE in the 65-reader test and hung.
  F-222's MUST is in 13 §8 (human 11-12).

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

- 13 §8 rules 1 and 5 ask for a heartbeat every `reader_heartbeat_ms`; Dart beats on its own
  operations only (idle reader reclaimed after 6 s, idle writer reads as "no live writer").
  Relax the spec for single-threaded runtimes, or give Dart an isolate-backed beat?
- Schedule (human, 11-01): 6.7, 6.8, M7, M8 sequentially, ASAP.

## Next action

1. `gh run list --branch dart-storage`: read the run for the 11-12 commits (gate quick green on
   remote, 1050 s); fix what Windows still shows (A1.3). 2. Soak: when remote
   `reference/bench/runs/soak2/java-done` exists, read `java.out`; at `done`, `dart.out` (+
   `soak-11-03/rust.out`); record in RESULTS.md, tick 6.7. 3. A1.4's interop full-text step. Then 6.8.

## Log
- 11-12: review of F-205..F-221: F-222 (claim/floor race) and F-223 (failed commit lost catalog edits) found and fixed; F-212 re-fixed; CI failures read and fixed locally.
- 11-11: F-211 redesign R+D (deferred reserved trees) + F-221 in R; F-221 fixed (D); F-211 Dart 4x; soak2 found dead (ENOSPC).
- 11-11: F-220 fixed R+J+D (reader page checks, no format change); F-221 filed (Dart CoW commit_id 0).
