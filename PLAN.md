# Cryptand 1.0 — production release plan

**Ship:** `cryptand` 1.0.0 for Rust (crates.io), Java (`org.dizitart:cryptand`,
Maven Central), Dart (pub.dev). **Tags Fri 2026-10-30**, Sat 10-31 is buffer.
**Scope:** the three engine packages only. Nitrite SDK adapters are next month.
**Dart:** gets the storage rewrite (M5); go/no-go **Fri 10-23**, else Dart ships
`1.0.0-rc.1` and Rust/Java ship `1.0.0` alone.

Decided by the human on 2026-10-06. Baseline the same day, all green on this
machine (M2 Pro, 10 cores, 16 GB, `/Volumes/External` 298 GB free): Rust
workspace debug+release, Java `mvn test` 325, Dart 655 + `dart analyze` clean,
interop gate 12/12 directions plaintext+encrypted.

## Status

| | milestone | track | due | status |
|---|---|---|---|---|
| M0 | Execution infra, gates, CI matrix | all | 10-07 | **done** (0.5: 26/26 jobs green, run 37597698770) |
| M1 | Differential + model testing | A | 10-14 | in progress (1.1 done; 1.2 checkers in all three; 1.3 hop built; 1.4 regress + hop in the gate; 1.5 index differential in all three, 2000 seeds clean) |
| M2 | Crash consistency + concurrency | A | 10-16 | in progress (2.1 Rust+Java: 3000 fault seeds each clean, Dart after M5; F-069, F-071) |
| M3 | Coverage-guided fuzzing | A | 10-16 | todo |
| M4 | Security review + pentest | A | 10-21 | todo |
| M5 | Dart storage rewrite | B | 10-23 gate | todo |
| M6 | Scale 10⁶→10⁹, soak, P2 | C | 10-24 | todo |
| M7 | Platforms, Flutter on device, API freeze, dry runs | all | 10-26 | todo |
| M8 | Freeze 10-27 → RC → final tags 10-30 | all | 10-30 | todo |

Tracks can run as parallel sessions, each in its own git worktree on its own
branch, merged into `packaging/v1.0.0`: **A** correctness+security
(Rust/Java first, Dart replays), **B** Dart rewrite, **C** long-running scale
runs (mostly background jobs, little attention).

---

## Execution rules (every session)

1. Read `HANDOFF.md`, this file, then the open S0/S1 rows of `FINDINGS.md`.
2. Do the **Next action**. For a defect: **reproduce first** (a failing test,
   fuzz input, or op-log), then fix, then re-run the step's Verify.
3. **Same bug, three languages.** The three implementations repeatedly carried
   the *same* defect (`reference/HARDENING.md` "the three had the same four
   defects"). Every finding is checked in Rust, Java and Dart, and the ledger
   records the result for each.
4. **The format is frozen at CFF v1.0.** A fix that changes bytes on disk, a
   spec MUST, or a conformance vector is **escalated to the human** before
   it is written. If approved: regenerate vectors, run all three suites and
   the interop gate.
5. **A control that cannot fail measures nothing** (project rule). Every new
   test must be shown failing with the fix reverted, or against a seeded fault.
6. One finding per commit: `fix(F-012, rust+java): …`. Run the gate for the
   languages touched before committing. Never commit red.
7. Long jobs (fuzz, scale, soak, torture) run with `nohup … &` and log to
   `reference/bench/runs/` (git-ignored). Results go into `RESULTS.md` or
   `FINDINGS.md` as numbers, labelled with the machine and device.
8. No claim without a number. Never mark a milestone done without its Verify.
9. Session end: rewrite HANDOFF State + Next action, add a Log line, tick the
   status table, commit.

### Severity and the release gate

| | meaning | release |
|---|---|---|
| **S0** | data loss or corruption; panic/abort/OOM/hang on any input file; crypto break; nonce reuse; acknowledged write lost | must fix |
| **S1** | wrong query result; memory or open time O(n) in database size; >10× perf cliff; a spec MUST violated; unsafe default | must fix, or a written waiver from the human |
| **S2** | performance, ergonomics, a SHOULD | fix if time, else listed in release notes |
| **S3** | docs, style | optional |

**Release gate:** 0 open S0, 0 un-waived S1, `tools/gate.sh full` green on
macOS locally and CI green on Linux/macOS/Windows, M6 scale table filled in.

---

## M0 — Execution infrastructure (10-06 → 10-07)

- [x] **0.1** PLAN.md, HANDOFF.md, FINDINGS.md, CLAUDE.md written and committed.
- [x] **0.2** `tools/gate.sh quick|full` at the repo root. `quick`: rust
  `cargo test --workspace` (debug and `--release`) +
  `cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious`;
  java `mvn -B verify`; dart `dart analyze --fatal-infos` + `dart test`;
  `reference/conformance/interop/run.sh`; regress corpora (M1.4, M3.5).
  `full` adds: 60 s per fuzz target, the 10⁶ scale rung, 200 kill-9 rounds per impl.
  Prints the time per stage; exits non-zero on the first failure.
  *Not gated:* `cargo fmt` (863 hunks, the code is hand-formatted on purpose)
  and clippy style lints (~35, none correctness).
  **Verify:** `tools/gate.sh quick` exits 0; flip one assertion and it exits 1.
  *Done 10-06:* quick green in 190 s; a flipped `multiproc.rs` assert → exit 1.
  Stages not built yet print `PENDING` (regress replays, fuzz, scale, kill -9).
- [x] **0.3** `FINDINGS.md` ledger, seeded with the suspects found on 10-06.
- [x] **0.4 [H]** Create GitHub repo `nitrite/cryptand` (it does not exist; this
  checkout has **no remote**), push `main` and `packaging/v1.0.0`.
  **Verify:** `gh repo view nitrite/cryptand` works and the existing CI runs.
- [x] **0.5** (10-07: 26/26 green on run 37597698770; matrix, cargo-deny, SHA pins landed; runs on `packaging/**` pushes. F-062/F-063/F-064 fixed 10-07; Java targets `--release 11` (nitrite-java's level), built on JDK 17, with a Java 11 runtime job) CI matrix in `.github/workflows/ci.yml`: `ubuntu`, `macos`,
  `windows` × Rust stable + MSRV 1.89, JDK 17/21/25 (+ Java 11 runtime), Dart 3.5 + stable;
  interop on all three OSes. Add a `cargo-deny` job. Pin every action by SHA,
  `permissions: contents: read`.
  **Verify:** every job green on GitHub (needs 0.4).

## M1 — Differential and model testing (track A, 10-07 → 10-14)

Target: wrong answers, not crashes. The current suites are example-based; no
test compares the engine against a model on random histories.

- [x] **1.1** Op-log format `reference/conformance/oplog/` (JSON lines: `put`,
  `del`, `range_del`, `batch`, `get`, `scan`, `snapshot`, `reopen`,
  `compact`, `shrink`, `checkpoint`, `ttl_advance`) plus a seeded generator
  (Rust, `harness` feature) with knobs for key skew, value size (inline vs
  value log), and op mix.
  *Done 10-06:* format in `oplog/README.md` (+ `release`, `commit`; values as
  SplitMix64 `{n,s}`); `oplog_gen` bin, 4 tests in the gate, shown failing.
- [ ] **1.2** (10-06: checkers in all three. Rust 300 seeds × 2000 clean after
  F-018…F-022; Java 0..300 full mix clean after F-026…F-031, F-034, F-036,
  F-037, F-040 (0..600 plain + 100 encrypted, 0 divergences); Dart 200 plain +
  24 encrypted clean after F-032, F-033, F-039. Dart replays are minutes per
  log because of F-038; 10 000 seeds still to run) Model checker per implementation: replay an op-log against the
  engine **and** a sorted in-memory map; compare every read, and a full-scan
  digest at the end and after every `reopen`. Rust harness bin, Java test
  class, Dart test.
- [ ] **1.3** (10-07: `--hop` legs in all three, `tools/oplog_hop.sh`; seeds 0..1000 plain clean after F-060 (289) and F-065 (451); 0..40 encrypted; 300 encrypted to run)
  Cross-language hop: Rust plays ops 0..k, Java k..m, Dart m..n on
  the same file, then all three compute the digest. Plaintext and encrypted.
- [ ] **1.4** (started: shrinkers in all three; 8 logs in `regress/`, replayed by all three
  in the gate) Shrink every failure to a minimal op-log, commit it under
  `oplog/regress/`, and replay the whole directory in `gate.sh quick`.
- [ ] **1.5** (10-07: index eq / eq-numeric / range / starts_with vs a brute-force model, `query_diff_test` in all three, 2000 seeds each clean → F-057/58/59. The engines have no filter language, and vector search is brute force only (spec 09 §8 fallback), so text / spatial / kNN differentials remain) Query differential: random documents + random filters (eq, range,
  in, compound, text, spatial within/intersects, vector kNN) — the index answer
  against a brute-force scan; for HNSW, recall@10 against exact search.
  **Verify:** 10 000 seeds × 3 impls and 1 000 hop seeds with 0 divergences;
  query differential 0 mismatches at Levels 1–3, HNSW recall at or above the
  spec 09 target; the regress directory is green in all three.

## M2 — Crash consistency and concurrency (track A, 10-09 → 10-16)

- [ ] **2.1** Fault-injecting file layer in each implementation's test tree:
  drop un-fsynced writes, tear the last write at a 512 B boundary, fail `fsync`
  (EIO), and fail a random write with ENOSPC. Add the smallest I/O seam the
  pager needs (Rust: a trait behind `cfg(test)` or the `harness` feature).
  Invariants on reopen: opens, or refuses with a typed error and never a panic;
  `verify` is clean; every write acknowledged under a durable mode is present;
  a batch is all-or-nothing; the nonce floor is above every nonce used.
- [ ] **2.2** Real kill -9 torture: a child process runs random ops including
  compaction, value-log GC, `shrink`, `encrypt()`, `rotate_master_key`,
  `crypto_erase` and backup; the parent kills it at a random time, then
  reopens and runs `verify` plus the model check of M1.
- [ ] **2.3** Disk full: a 200 MB `hdiutil` image. Filling it must give a clean
  error, the file must still open, and work must resume once space is freed.
- [ ] **2.4** Rust: ThreadSanitizer (nightly `-Zsanitizer=thread`) over
  `cryptand` and `cryptand-write` tests; Miri over `compare.rs`, `hash.rs`,
  `security.rs` and the codec unit tests. Java: the `CrudBench` mixed phase
  (the old tree-7 reproducer) 200× at 1k/5k/20k documents.
- [ ] **2.5** **Extent ownership audit** — the latent bug. HARDENING records
  that merging Java's flush shards made "two structures handed the same
  extent" in 2/8 interop runs, and the change was reverted without a root
  cause. The allocator bug may still be reachable another way. Add a test-only
  audit (every extent owned by exactly one structure, checked at each commit)
  to all three. Re-apply the shard merge on a branch, reproduce, root-cause,
  fix. Then ship the merge (it measured +1.8× mixed, p99.9 1284→831 µs).
- [ ] **2.6** Multi-process: one writer and N readers in separate processes;
  lock-sidecar semantics; a stale lock after kill -9 is recoverable; on all
  three OSes through CI.
  **Verify:** 5 000 kills each for Rust and Java (1 000 for Dart after M5) and
  1 000 fault-injection seeds per impl, all with 0 invariant failures; TSan and
  Miri clean; Java mixed phase 200/200; the ownership audit is on in test
  builds and green; ENOSPC recovers.

## F-072 — 13 §5 maintenance MUSTs (human 10-07: all of them, all three)

- [x] **a** Rust `add_key`/`remove_key`/`crypto_erase` (`keyapi.rs`); Java had them.
- [~] **b** In-place `encrypt()` (Rust done 10-07; Java next). Set `cipher`, keyslot 0,
  seal the open value-log segments, commit; new pages and new value-log
  segments are encrypted (head byte 39). Then a resumable `convert_step()`
  until nothing plaintext remains: full compaction (segments re-laid with the
  tag reserved), every copy-on-write tree rebuilt, every value-log segment
  rewritten by GC, every blob/vector extent re-chunked. A plaintext page can be
  full to `page_size − 40`, so pages are re-laid, never just re-sealed.
  Expose the fraction converted; never report "encrypted" while plaintext
  remains (14 §8.3).
- [~] **c** (Rust fixed, J/D ok on Rust-written files; blobs untested) Readers decide per page (`flags.ENCRYPTED`), per value-log segment
  (head byte 39) and per extent, never from `cipher` (14 §5.2). Known suspect:
  Rust `read_vlog_record` and `verify` use `sb.cipher` / `false`. Driven by a
  half-converted file in all three readers and through interop.
- [~] **d** (Rust done 10-07) `decrypt()`: the mirror. Requires explicit confirmation; `cipher`
  stays 1 and the keyslots stay until no encrypted page or record remains,
  then one superblock clears both (no 14 §6.1 downgrade window).
- [~] **e** (Rust done 10-07, synchronous; refused while checkpoints exist) `rotate_master_key()`: copy-and-swap. Stream into a sibling file
  under a fresh master in bounded steps, catch up concurrent writes, fsync,
  rename over. Crash leaves the old file intact. Spec 14 §8.3/§8.4 note.
- [ ] **f** Dart: all of the above inside M5.
  **Verify:** each op has a crash test (M2.1 fault sweep over a conversion,
  1000 seeds) and an interop step (a half-converted Rust file read by Java and
  Dart and vice versa); `verify` clean after each; 14 §8.3's fraction reported.

## M3 — Coverage-guided fuzzing (track A, 10-08 → 10-16, mostly background)

Today's fuzzing is 600 seeded mutants plus the field-boundary sweep. That is
too small to support a production claim.

- [ ] **3.1** `cargo-fuzz` targets (nightly) in `reference/rust/cryptand/fuzz/`:
  `open_file` (arbitrary bytes → read-only open + `verify` + full scan),
  `open_encrypted` (known key), `cve_decode`, `cke_roundtrip` (decode∘encode is
  the identity, and `memcmp` order equals the logical order), `wkb`,
  `analyzer` (no panic, normalization idempotent), `segment`,
  `superblock_keyslot`. Seed from `reference/conformance/files` and the vectors.
  Run with `-rss_limit_mb=2048 -timeout=10` so OOMs and hangs count as crashes.
- [ ] **3.2** Structure-aware mutation: extend the field-boundary sweep to every
  page type (value log, blob, vector, R-tree, catalog, keyslot area).
- [ ] **3.3** Java: Jazzer (`com.code-intelligence:jazzer-junit`, test scope) on
  the same targets.
- [ ] **3.4** Dart has no coverage-guided fuzzer, so it gets **corpus replay**:
  every Rust and Java corpus entry and crash goes through the Dart reader (and
  the Java one) in a test. The Dart mutational fuzz runs at 10⁶ mutants in the
  background.
- [ ] **3.5** Triage every crash into FINDINGS; add the minimized input to
  `reference/conformance/files/fuzz-regress/`, replayed by all three in
  `gate.sh quick`.
  **Verify:** at least 4 CPU-hours per Rust target and 2 per Java target, then
  a final 1 CPU-hour run per target that finds nothing new; the regress corpus
  is green in 3/3.

## M4 — Security review and pentest (track A, 10-12 → 10-21)

Attacker model per `spec/14-security.md`: whoever holds **the file**.
Deliverable: `reference/SECURITY-REVIEW.md`, one row per MUST in spec 14 →
the test that proves it → result.

- [ ] **4.1** Traceability: walk every MUST/MUST NOT of spec 14 (and spec 01 §
  encryption) and map it to a test. A missing test is a finding.
- [ ] **4.2** Primitive KATs in all three: Wycheproof `chacha20_poly1305`,
  `xchacha20_poly1305`, `hkdf_sha256`, `hmac_sha256`; RFC 9106 Argon2id,
  including parallelism > 1; RFC 7693 and reference BLAKE2b KATs; empty and
  maximum lengths. Java and Dart hand-roll Argon2id, BLAKE2b and HChaCha20, so
  this is where a silent mismatch would hide.
- [ ] **4.3** File-attacker harness (`security_attack`): attack × location ×
  implementation. Attacks: flip, zero, or truncate each byte class (cleartext
  page header, ciphertext, tag, nonce, superblock, keyslot); splice pages
  across files and across positions; replay an older authentic page within
  one file; downgrade `cipher` or KDF cost; swap keyslots; extend the file.
  Each must give a named security error, no plaintext, and no crash.
  Rollback of a whole file is out of scope per spec 14; the docs must say so.
- [ ] **4.4** Nonces: concurrent writers never share a nonce (record every
  nonce in a test build and assert uniqueness across 32 threads and across
  kill -9 from M2.2); the floor is published before use; counter exhaustion is
  handled.
- [ ] **4.5** Key material: zeroized on every exit path (close, error, drop,
  panic unwind); no secret in `toString`, `Debug`, logs, or exception text (a
  test sets a marker password and greps every error message for it); Java
  takes `char[]`/`byte[]` and wipes it; Dart's best-effort limit is documented.
- [ ] **4.6** Length arithmetic sweep (the defect 101 class): list every
  `count × size`, `offset + len`, and `(int)` / `as usize` / `toInt()` on a file
  value in all three, and prove each is checked. Java has 5 `(int)` casts on
  file values plus `int n = (int) r.uvar()` in `BtreePage`. Also cover the
  maximum decompressed size, nesting depth, and varint length.
- [ ] **4.7** Filesystem: created files, the lock sidecar, backups and temp
  files are `0600`; no symlink following on the sidecar; Windows share modes;
  temp files never hold plaintext of an encrypted database.
- [ ] **4.8** Supply chain and pipeline: `cargo deny` (advisories, licenses,
  bans) and `cargo audit` clean; release workflows pinned by SHA with minimal
  permissions; pub.dev through OIDC; SBOMs (`cargo cyclonedx`,
  `cyclonedx-maven-plugin`) attached to the GitHub release; a `SECURITY.md`
  disclosure policy at the repo root.
- [ ] **4.9** Rust `unsafe`: 3 files (`compare.rs`, `hash.rs`, `security.rs`).
  Add a `// SAFETY:` justification at each site and
  `#![deny(unsafe_op_in_unsafe_fn)]`; Miri from M2.4.
  **Verify:** every SECURITY-REVIEW row has a passing test; 0 open S0/S1 with
  tag `sec`; `cargo deny check` clean; KATs green in 3/3.

## M5 — Dart storage rewrite (track B, 10-07 → **go/no-go 10-23**)

Today `DatabaseFile.open` reads **every segment and value-log extent into
memory**, writes happen only at `save()` (`durabilityAchieved = none`), and all
I/O is synchronous. RSS = database size, and an app crash loses everything
since the last save. `REPORT.md` §6 records this as known.

- [ ] **5.1** A one-page design in `reference/dart/cryptand/REPORT.md` that
  mirrors Rust's path: extents addressed through `PageStore`, read on demand,
  with a bounded page cache that honours `12-profiles.md` §1 (this also closes
  the cache-budget gap the REPORT records).
- [ ] **5.2** Segments open lazily (header + filter + pages on demand), not
  through `readExtent` of the whole extent.
- [ ] **5.3** The value log and segments are appended to the file as they are
  written; a durable commit is fsync of data, then the superblock flip, as in
  `spec/10-transactions.md`. `durabilityAchieved` reports the real mode.
- [ ] **5.4** Flush, compaction, GC and `shrink` write through the file;
  `save()` becomes a checkpoint, kept for API compatibility.
- [ ] **5.5** Keep the API synchronous. Document running the engine on a
  background isolate in Flutter (an async facade is out of scope).
  **Verify:** all existing Dart tests green; interop gate green; M2.2 kill -9
  1 000/1 000 for Dart, with no acknowledged write lost; open a 10⁷-document
  file with RSS ≤ profile cache budget + 64 MB; the M6 Dart rungs pass.
  **10-23:** if Verify is not met, Dart releases `1.0.0-rc.1` from the
  pre-rewrite (in-memory) engine, so do the rewrite on its own branch
  (`dart-storage`), with the limits stated at the top of its README. The human
  confirms the call.

## M6 — Scale and stress (track C, 10-08 → 10-24, mostly background)

Nothing has run above 10⁶ documents. The target is 10⁹ for Rust and Java, and
10⁷ for Dart (10⁸ stretch, after M5).

- [ ] **6.1** A workload binary per implementation from one seeded generator:
  16-byte hashed keys; ~100 B CVE documents; 5 % at 2 KiB, so the value log is
  exercised; batched multi-thread writers for Rust and Java. Each rung emits
  one JSON metrics line.
- [ ] **6.2** Ladder 10⁶ → 10⁷ → 10⁸ → 10⁹, `desktop` and `mobile` profiles,
  plaintext and encrypted at 10⁸. Record per rung: load rate; point-read
  p50/p99/p99.9 (uniform and zipfian); range-scan rows/s; mixed
  update/delete; peak RSS; cold open time (after `purge`); file size and space
  amplification; device bytes written (P2); `verify`, `shrink` and `backup`
  times; compaction debt.
- [ ] **6.3** Pass bars per rung (a miss is a finding): RSS ≤ profile budget +
  memtables + 256 MB, so nothing O(n) in memory; cold open ≤ 2 s at 10⁹,
  excluding Argon2id; point-read p99 at 10⁹ ≤ 3× p99 at 10⁶; load rate at 10⁹ ≥
  0.4× the rate at 10⁶; space amplification ≤ 1.6 on `desktop` once compaction
  settles; `verify` completes; no 32-bit overflow anywhere.
- [ ] **6.4** Suspects to probe first. They are in FINDINGS as `suspect`;
  promote each to a finding or close it with the number.
- [ ] **6.5** Indexes at scale: unique and compound indexes at 10⁸; full text
  at 10⁷ documents; spatial at 10⁷; HNSW at 10⁶ × 128-d, recall@10 against
  brute force; planner stats sane.
- [ ] **6.6** Pathological workloads: monotonically increasing keys;
  shared-prefix keys; 16 MB documents; 10⁶ distinct field names (dictionary
  growth); 10⁵ collections; delete-all then reinsert (tombstone storm);
  range-delete storm; TTL expiry storm.
- [ ] **6.7** Soak: 24 h mixed at a 10⁸ base, for Rust and for Java, with a
  kill -9 every 10–30 min, `verify` after each reopen, and RSS, fd count and
  file size sampled. Nothing may grow monotonically.
- [ ] **6.8** Measure P2 (write amplification, sustained random writes ≫ RAM:
  a 64 GB dataset against 16 GB RAM) against fjall and RocksDB, the one
  prediction still unmeasured. Update `RESULTS.md` and the README table.
  **Disk:** 298 GB free. One 10⁹ dataset at a time; delete it once the numbers
  are recorded.
  **Verify:** a Scale table in `reference/bench/RESULTS.md` filled for every
  rung × impl; every bar met or a finding filed; the soak ends with 0 verify
  failures.

## M7 — Platforms, API, packaging (all, 10-20 → 10-26)

- [ ] **7.1** The CI OS matrix from M0.5 is green, including Windows paths
  (long, non-ASCII) and locking.
- [ ] **7.2** Flutter on device: a `reference/dart/cryptand_flutter_smoke/`
  `integration_test` app creates an encrypted database, writes 10⁵ docs on a
  background isolate, is killed, reopens, and verifies. Run it on the iOS
  simulator and the Android emulator. Measure Argon2id open time (P11 missed:
  405 ms `mobile`, 2183 ms `desktop` in pure Dart) and frame jank. The miss is
  documented, not lowered (spec 14 §3.2 forbids weakening the cost).
- [ ] **7.3** API freeze: Rust — snapshot the public API (`cargo public-api`)
  and review every `pub` item; Java — add `module-info.java` (or at least
  `Automatic-Module-Name`) so internal packages are not public API; Dart —
  `lib/cryptand.dart` exports only the intended surface. `dart doc`,
  `cargo doc` and `javadoc` produce no warnings.
- [ ] **7.4** Docs: each package README has a quickstart that is compiled in a
  test, an honest limits section (Dart: single writer, no web), and a
  finalized `CHANGELOG` 1.0.0.
- [ ] **7.5** Dry runs: `cargo publish --dry-run -p cryptand` plus a
  `cargo package --list` review; `mvn -B -P release verify -Dgpg.skip`;
  `dart pub publish --dry-run`, with a pana score of at least 140.
  **Verify:** all dry runs pass; the smoke app is green on both simulators.

## M8 — Release (10-27 → 10-30)

- [ ] **8.1** Tue 10-27 code freeze: only S0/S1 fixes after this.
- [ ] **8.2 [H]** Secrets and accounts: `CARGO_REGISTRY_TOKEN`; `MAVEN_USERNAME`,
  `MAVEN_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`; Maven Central namespace
  `org.dizitart` verified; a pub.dev publisher. pub.dev requires the **first**
  version to be published by hand, so the human publishes `1.0.0-rc.1` with
  `dart pub publish` and then enables automated publishing for
  `dart-v{{version}}`.
- [ ] **8.3** Set the manifests to `1.0.0-rc.1` and push the three rc tags in
  **one push of at most three tags** (rollout.md §4). The workflows publish.
- [ ] **8.4** RC validation: in fresh projects in each ecosystem, install the rc
  from the registry, run the quickstart, and open the interop files written by
  the other two.
- [ ] **8.5** Fri 10-30: bump to `1.0.0`, tag, and publish. Write the GitHub
  release notes with SBOMs, the SECURITY-REVIEW summary, and every open S2.
  Update the README Status table.
  **Verify:** each registry serves 1.0.0, and the 8.4 checks pass against
  1.0.0.

---

## Calendar

| dates | A: correctness + security | B: Dart | C: scale |
|---|---|---|---|
| 10-06 – 10-07 | M0 | — | — |
| 10-07 – 10-14 | M1, M3 (fuzzers running) | M5.1–5.3 | M6.1, 10⁶–10⁸ |
| 10-14 – 10-21 | M2, M4 | M5.3–5.5 | 10⁹ Rust/Java, M6.5–6.6 |
| 10-21 – 10-24 | M4 finish, fix backlog | **10-23 go/no-go** | M6.7 soak, M6.8 P2 |
| 10-20 – 10-26 | M7 | M7.2 Flutter | Dart rungs |
| 10-27 – 10-30 | M8 | M8 | — |

## Human-only steps [H]

0.4 create the repo and push · 8.2 registry secrets, namespaces, the first
pub.dev publish · every S1 waiver · approving any format change (rule 4) · the
Dart call on 10-23.

## Out of scope for 1.0

- Nitrite adapters (`nitrite-cryptand-adapter` in all three SDKs) and the
  rollout.md §6 definition-of-done test — next milestone.
- rollout.md Phase 0 (SDK semantic fixes) and `cryptand import` migration.
- A Dart async API facade; `dart2js`/Flutter web (`int` is a double there).
- An FFI fast path for Argon2id in Dart.
- Any CFF format change, unless an S0 forces one (rule 4).
- `cargo fmt` reformatting and clippy style lints.
