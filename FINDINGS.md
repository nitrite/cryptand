# Release 1.0 findings ledger

One row per issue found during the 1.0 release pass (PLAN.md). Older defects
1–102 are in `reference/HARDENING.md` and the REPORTs; this ledger starts at
F-001 so the numbers never collide.

**Status:** `suspect` (a hypothesis, not yet reproduced) → `open` (reproduced,
with a repro named) → `fixed` (commit hash) | `waived` (human, with date) |
`closed` (disproved, with the number that disproved it).
**R / J / D:** what this finding means in Rust / Java / Dart: `bug`, `ok`
(checked, not affected), `?` (not yet checked), `n/a`.
Severity per PLAN.md. Keep each row to one line; put details in the commit
message or a test comment, not here.

| id | sev | status | R | J | D | title | repro / evidence | fix |
|---|---|---|---|---|---|---|---|---|
| F-001 | S1 | open | ok | ok | bug | Dart open reads every segment and value-log extent into memory, so RSS = database size | `lib/src/file.dart:571-592`, REPORT.md §6 | M5 |
| F-002 | S0 | open | ok | ok | bug | Dart writes reach disk only at `save()`; a crash loses everything since the last save (`durabilityAchieved = none`) | `lib/src/engine.dart:382` | M5 |
| F-003 | S1 | open | ? | ? | bug | Dart ignores the `12-profiles.md` §1 page-cache budget | REPORT.md §6 | M5 |
| F-004 | S0 | suspect | ? | bug? | ? | Extent double-allocation: merging Java flush shards gave "segment head magic is 0300190003000100" (one extent, two owners) in 2/8 interop runs; reverted without a root cause | HARDENING.md "The fix works, and it is not shipped" | M2.5 |
| F-005 | S2 | open | ok | bug | n/a | Java `Vlog.reserve` holds the monitor across fetch_add, nonce allocation and bookkeeping, so §2.2 "writers do not contend" is not literally true | HARDENING.md "What is still serialized" | M2 |
| F-006 | S2 | open | ok | bug | ? | Java flush drains the memtable one skip-list `remove` at a time, O(n log n), 10.6 % of the create profile | HARDENING.md "Two things deliberately not done" | M6 |
| F-007 | S1 | suspect | bug? | ? | ? | Rust `PointIndex` (16 B/key per segment) may sit outside the page-cache budget; at 10⁹ keys that is ~16 GB | `cryptand/src/segment.rs:1336-1360` | M6.4 |
| F-008 | S1 | suspect | bug? | ? | ? | `Segment::open(extent: Vec<u8>)` holds a whole segment extent in memory; check segment size bounds at 10⁹ | `cryptand/src/segment.rs:1380` | M6.4 |
| F-009 | S1 | suspect | ? | bug? | ? | Java `int` casts on file-supplied lengths (`BtreePage.java:241,245` `(int) r.uvar()`, +5 sites) can overflow on hostile input or at scale | grep in PLAN M4.6 | M4.6 |
| F-010 | S2 | open | ? | ? | ? | Value-log collection policy differs: an all-value-log workload ends at different file sizes in the three | RESULTS.md §4 | M6 |
| F-011 | S2 | open | n/a | n/a | bug | P11 open-time missed in pure Dart: Argon2id 405 ms `mobile`, 2183 ms `desktop` (target 250–500 ms) | Dart REPORT §0.1 | M7.2, document |
| F-012 | S1 | open | ? | ? | ? | P2 (write amplification vs fjall/RocksDB, data ≫ RAM) never measured; nothing has run above 10⁶ documents | README "Still unmeasured" | M6 |
| F-013 | S2 | open | n/a | bug | n/a | No `module-info.java` / `Automatic-Module-Name`; every internal package is public API | `reference/java/src/main/java` | M7.3 |
| F-014 | S1 | open | ? | ? | ? | Fuzzing is 600 seeded mutants plus one sweep; no coverage-guided fuzzing anywhere | `Fuzz.java`, `harness/fuzz.dart` | M3 |
| F-015 | S1 | open | ? | ? | ? | CI is Linux-only; locking, paths and fsync are untested on macOS and Windows | `.github/workflows/ci.yml` | M0.5 |
| F-016 | S1 | fixed | n/a | n/a | n/a | No GitHub repo / git remote; release workflows have never run | repo created by the human 10-06, both branches pushed | M0.4 |
| F-017 | S3 | open | bug | n/a | n/a | ~35 clippy style warnings, 863 rustfmt hunks (not gated; see PLAN) | `cargo clippy` 10-06 | optional |
| F-018 | S0 | fixed | bug | ? | ? | Last-level compaction drops a range tombstone but keeps the rows it covers (different user keys), and picks last-level overlap by `max_key`, not the tombstone's `end`: deleted rows come back | `engine_test` `compaction_does_not_resurrect_rows_hidden_by_a_range_delete`, `a_range_delete_reaching_past…` | M1.2 |
| F-019 | S0 | fixed | bug | ? | ? | Value-log GC (`collect`) tests liveness with point lookups that ignore range deletes, then rewrites the value as a fresh PUT above the tombstone: deleted row comes back | `engine_test` `value_log_collection_does_not_resurrect…`; `oplog/regress/f019-*` | M1.2 |
| F-020 | S1 | fixed | bug | ? | ? | GC rewrites a relocated value with no expiry: a TTL value moved by GC never expires | `engine_test` `value_log_collection_keeps_a_values_expiry` | M1.2 |
| F-021 | S0 | fixed | bug | ? | ? | Compaction drops a tombstone visible to every snapshot but keeps the version beneath it when the key's newest version is newer than the oldest snapshot: that snapshot reads deleted data | `engine_test` `compaction_does_not_resurrect_a_deleted_version_under_a_snapshot`; `oplog/regress/f021-*` | M1.2 |
| F-022 | S0 | fixed | bug | ? | ? | `vlog_stats` keeps collected segments forever; `shrink` relocates and re-frees their already-freed extents → one extent, two owners, live value-log data overwritten ("record shorter than its CRC"). Likely related to F-004 | `oplog/regress/f022-*` (seed 6, 2015→13 lines) | M1.2 |
| F-023 | S2 | open | bug | ? | ? | `Engine::commit(Full)` does not flush the memtable, so a write before it is lost on crash; `Database`/`Store` flush first, but `Engine` is `pub` | crash probe 10-06 | M7.3 API review |
| F-024 | S2 | open | bug | ? | ? | Space metrics (`metrics.rs`, `checkpoint.rs`, `txn.rs`) count collected value-log segments' pages as allocated | code read 10-06 | M6 |
