# HANDOFF — Cryptand 1.0 release

## State (2026-10-31)

- Branch `dart-storage` (pushed). Manifests 1.0.0, nothing published, no tags.
  Done: M0, M4; M1–M3, M5 per PLAN status table. M6 6.5 rungs (index,
  full-text, spatial, vector) PASS R+J+D at 10^6 (10^7 for index/text/spatial).
- Vector 10^6 (v6, pre-F-205, ef 100), bar 448 MB, all sound, recall 0.824:
  R build 5339 s, 2.52 GB, peak 172 MB; J 4841 s, 2.33 GB, 370 MB;
  D 7421 s, 2.88 GB, 405 MB. F-205 (per-search beam) committed after.
- 6.6 rung (10-31): Rust `rss_scale PATH N patho [W]`, Java `RssScale PATH N
  patho [W]`, Dart `scale patho PATH N [W]`; W = mono prefix bigdoc fields colls
  tombstone rangedel ttl, one file each, reopen + checks + verify. Local 10^5
  run found F-206 (R verify), F-207 (S1 R+J+D tree_span split), F-208 (S1 R+D
  TTL never expired): fixed, tests R+J+D, gate quick at `~/g207.log`.
  Open: F-209 (D bigdoc 4.65 GB vs R 1.71), F-210 (J colls quadratic, D slow,
  R 1.36 GB for 10^5 one-doc collections; fixed R+J+D, not yet rerun at 10^5). All other workloads pass R+J+D.

## Must-keep (any Dart rewrite or refactor)

F-127/F-128 format bits; `_cmpU64`/`_addSaturating`; F-135/F-136 zeroing;
F-137 key-on-plaintext refusal; F-138 `uvar() < 0 ||` checks; `_writeOwnerOnly`
(0600); code that moves an extent keeping its segment id MUST evict it (F-156).

## Remote and traps

- Remote `anindya@207.254.39.186`, one clone per job (gate `cryptand-gate`,
  bench `cryptand-f184`, Jazzer `cryptand-fuzz` under JDK 21 only).
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

- New schedule for 6.6–6.8, M7, M8 (the PLAN dates have passed).

## Next action

Rerun patho colls at 10^5 on remote, R+J+D, to confirm F-210 in time and
size; then F-209 (Dart bigdoc 4.65 GB), then the 6.6 rungs at 10^6 on remote.

## Log

- 10-27 — Dart go; 6.5 index rung, F-182/F-183 fixed.
- 10-28 — F-184..F-188 (index footprint, probes, L0 backlog, segment commit_id).
- 10-29 — F-184 Dart fixed; F-189 compaction bound; full-text rung, F-190/F-191.
- 10-30 — F-192..F-204: spatial/vector on pages R+J+D, Vamana prune, F-202 closed.
- 10-31 — F-203 fixed (R 865 -> 172 MB), F-205 beam width; v6 vector 10^6 PASS
  R+J+D; F-204 closed at 1.4x; space_test fd flake fixed; handoff trimmed (294 -> ~60 lines).
- 10-31 — 6.6 rungs R+J+D; F-206..F-208 fixed; F-209, F-210 open.
- 10-31 — F-206..F-208 committed (gate green); F-210 J fixed; f160 fd bound 4.
- 10-31 — F-210 R (eager free of unpublished catalog pages) + D (owner map) fixed.
