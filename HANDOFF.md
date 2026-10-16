# HANDOFF — Cryptand 1.0 release

## State (2026-10-13, IST)

- Branch `packaging/v1.0.0`. Manifests 1.0.0, nothing published, no tags.
- Done: M0, M1.1, M1.2 (Rust, Java), M2.1–2.3 (Rust, Java), M3 (8 cargo-fuzz
  targets x 4 h, 7 Jazzer targets x 2 h under JDK 21: clean), M4.1, M4.2.
  Dart halves wait for M5. Details: git log and PLAN status table.
- Jazzer: remote clone `~/Documents/codebase/cryptand-fuzz`, run under
  `JAVA_HOME=/opt/homebrew/opt/openjdk@21` (JDK 24 silently voids the run):
  `JAZZER_FUZZ=1 mvn -B surefire:test -Dtest=JazzerTest#<t>` in `reference/java`.
- **Format changes approved 10-12, both in all three, corpus regenerated:**
  F-127: optional bit 16 `CONVERTING` (14 §8.3); F-128: parent-recorded
  nonces (14 §5.5: superblock `root_nonces` at 328, descriptor `root_nonce`,
  CoW cell and R-tree entry `child_nonce`, manifest `nonce`, checkpoint
  `root_nonces`, segment pages carry the head's `commit_id`). Vector regions
  are unbound (documented); overflow chains unchecked (no writer makes one,
  ponytail in Java `resolveValue`). **M5's Dart rewrite must carry both.**
- Corpus regeneration order: `dart run tool/generate_corpus.dart`, then Rust
  `convert_test make_converting_vector` and `replay_test make_replay_vector`
  (both `--ignored`): `v1.0-encrypted` is not deterministic.
- M4.3 done: `tools/security_attack.py` 3 writers x 3 readers, 1479 runs,
  0 failures, value-log records and segment heads included (interop `write`
  now sets `vlog_min` 256 in all three). Blob chunks: no writer exists (F-103);
  vector regions unbound by design. Value-log head CRC spans 40+64 bytes only.
- M4.4 done: F-133 (all three: nonce floor overflow near 2^64, Java/Dart
  wrapped to 0) and F-134 (Java vlog `nonce_base` not allocated) fixed.
  Concurrency: Java 32-thread test; Rust cursor behind `&mut Engine`; Dart
  one isolate. Crash reuse: existing row 9 tests + M2.2 kills.
  **M5's Dart rewrite must keep `_cmpU64`/`_addSaturating` semantics.**
- M4.5 done: passwords zeroed by every Java/Dart entry point (F-135; raw
  keys left to the host: zeroing them broke every reusing caller); failed
  opens zero the cipher/ring (F-136); marker tests R+J+D. **M5 keeps both.**
- F-137 fixed (human 10-12): 14 §6.1 MUST refuse a key on a plaintext file;
  R+D now refuse like Java. F-135 API kept: passwords zeroed, raw keys are
  the host's (14 §11 note). **M5 keeps the F-137 refusal.**
- F-132 (Dart, fixed): converting files mix plaintext/encrypted vlog records;
  Dart probes per record (ponytail) until M5 writes byte 39 (F-076).
- M4.6 done: F-138 (all three: value-log `record_len` / Dart cell suffix
  used before checked; Rust rotate aborted). Dart `uvar()` returns >= 2^63
  as negative: every length check needs `< 0 ||`. **M5 keeps both.**
- M4.7 done: F-139 (all three): created db, sidecar, rotation temp and
  restore target `0600`; sidecar `O_NOFOLLOW`. Dart sets the mode by libc
  `chmod` over FFI (`_writeOwnerOnly`). F-140 (Dart default `vlogMin` 2048
  unsaveable at 4096 pages) open for M5. **M5 keeps `_writeOwnerOnly`.**
- M4.8 done: `cargo deny check` + `cargo audit` clean on remote (tools in
  remote `~/.cargo/bin`); release workflows pinned like CI; Rust/Java attach
  CycloneDX SBOMs to the tag's GitHub release (`gh release create` if absent);
  Dart has no SBOM step (no tool in PLAN). `SECURITY.md` uses GitHub private
  reporting: **[H] enable it in repo settings.**
- M4.9 done: `pager.rs` also has 3 FFI `unsafe` blocks (the plan missed them),
  `security.rs` has none; README/CHANGELOG no longer say "no `unsafe`".
- Fuzz crash to regress file: CRC-repair with `JazzerTest.repairCrcs` into
  `reference/conformance/files/fuzz-regress/fNNN-*.cryptand`
  (`CRYPTAND_FUZZ_DUMP` keeps only the last input replayed). Replaying
  Jazzer inputs needs `process-test-resources`: `surefire:test` reads `target/test-classes`.
- Remote gate clone `cryptand-gate` (rsync the tree; Dart SDK `~/dart-sdk/bin`).
- F-150 fixed (R+D; Java not affected): `space_test` in all three. Residue: tiered
  levels keep superseded versions until the last level (§5 condition 3), so 1 MB
  live sits in ~30 MB (Rust desktop) / ~80 MB (Dart `Engine()` default). Residue fixed 10-13 (human approved
  04 §5 change: superseded non-RANGE_DELETE versions drop at any level, R+J+D): ~13 / ~26 MB.
  Dart FINDINGS cells done 10-13 (`test/findings_test.dart` ports the R/J repros); F-079 was a Dart
  verify false-leak bug, fixed (`Database.indexClaims`). Left `?`: F-007/008/010/012 (M6 scale).
- F-151 fixed 10-13 (R+D): page-granular segment reads. 10^6 remote: Rust get p50 3 us, Dart 28 us.
- F-152 fixed 10-14 (R+D): compaction paced per put (one bounded step per
  `step / pace` bytes, pace 4..64 by §6 x²); L0 was 46 (Dart), Rust L1 tier at hard.
  The M6 RSS bar is PLAN 6.3's (cache + memtables + 256 MB); `scale.dart` checked
  M5.5's +64 MB open bar: Dart 10^6 read 206 MB now PASS (320).
- F-153 fixed 10-14 (Rust): `write` flushes at `memtable_entry_limit` (as Dart, Java per
  shard). Rust 10^6: file 652 MB, writer 467 MB, levels 3/2/3/5, backpressure none.
  Mandatory read-tail test sets the limit to 501 so its own flush+drain still runs.
- F-156 (S0, Rust, regression from F-151) fixed 10-14: `relocate_down` left a moved
  segment cached; its lazy loader read the old place. Any new code that moves an
  extent keeping its segment id MUST evict it. Hop flake = layout varies with Java timing.
- F-154 fixed 10-14 (D): Dart `shrink()` was a stub; now ports Rust relocate+truncate. Settled
  10^6 (`scale settle` / `rss_scale PATH N settle`): Rust 495 MB (1.14x live), Dart 688 MB (1.58x,
  bar 1.6: thin margin; Dart segments run ~40% larger than Rust's for the same data, unexplained).
  F-155 profiled 10-14: live heap 25 MB; max RSS is shared `__LINKEDIT` + freed-dirty malloc;
  peak footprint 304 MB < 352. Human 10-14: 6.3 bar is peak footprint (PLAN edited).
- Dart fault seam: `fileHook` in `cow.dart` (`fileWrite`/`fileSync`); `test/fault_test.dart`
  (`CRYPTAND_FAULT_SEEDS=a..b`). Corpus replay: `test/corpus_replay_test.dart`, skipped unless
  `CRYPTAND_CORPUS_DIRS` (remote: `cryptand-gate/.../fuzz/{corpus,artifacts}` + `cryptand-kill-plain/reference/java/.cifuzz-corpus/...JazzerTest`).
- Traps: corpus test without `--features harness` reuses a stale `interop`
  binary (the gate passes the feature); Rust `stall_test` fails while another job fsyncs on /Volumes/External;
  never build Java in a clone where a hop, torture or Jazzer runs; rebuilding
  classes under a running Jazzer breaks it.

## Decisions in force (human)

- Scope = the three engine packages. Dart storage rewrite (M5) on
  `dart-storage`; go/no-go Fri 10-23, else Dart ships `1.0.0-rc.1`. Freeze
  Tue 10-27, tags Fri 10-30.
- Java `--release 11`, built on JDK 17, as nitrite-java.
- F-072: all of 13 §5 in all three for 1.0 (Dart's in M5). Rotation is
  copy-and-swap; no format change.
- F-103: value log, no put-time BLOBs.
- Push every commit; one finding per commit unless files are shared.
- CPU-heavy work (fuzz, torture, soak, bench, M1.2) runs on the remote Mac
  (`anindya@207.254.39.186`), one clone per job, never here.

## Open questions for the human

- Enable GitHub private vulnerability reporting on nitrite/cryptand (SECURITY.md points there).

## Next action

10^8 Dart AOT (10-16, remote): build 223 MB footprint PASS, settle 113 MB PASS, **read 637 MB FAIL**
(bar 320): F-165 opened, profile Dart read open/verify memory next. Java 10^8 run 10-16 failed:
`/tmp/j1e8.db` vanished at 1189 s of build (NoSuchFileException; cause unknown, macOS /tmp?).
Rerun running (10-16 21:48): `cryptand-1e8/reference/bench/runs/j-1e8.sh` -> `j-1e8.log`, db and
per-rung full output in remote `~/j1e8/`. Then: fill RESULTS, close F-161.

## Log

- 2026-10-10 — Jazzer was under JDK 24 (void); openjdk@21 installed; F-119 fixed; Java M1.2 encrypted seed 9334 diverges, not reproduced locally. Earlier sessions: git history.
- 2026-10-11 — F-120 fixed in spec (option a); F-121 (Java verify horizon mix) found via seed 9334 and fixed; final Java M1.2 encrypted run started.
- 2026-10-11 — Jazzer openFile/openEncrypted/cveDecode/analyzer 2 h clean under 21; last 3 targets started.
- 2026-10-11 — M1.2 Java encrypted 0..10000 clean; last 3 Jazzer targets clean, M3 Rust/Java done.
- 2026-10-11 — M4 started: SECURITY-REVIEW.md first pass; F-122 fixed (R+J tests), F-123 converting vector added after approval.
- 2026-10-11 — spec 14 §13 reworded for security-converting; M4.1 done (F-124 tests, F-125 docs).
- 2026-10-11 — M4.2 KATs in all three; F-126 Argon2id (J+D) found and fixed.
- 2026-10-11 — interop password leg; M4.3 harness (1197 runs); F-129, F-130 fixed; F-127/F-128 to the human.
- 2026-10-12 — F-127 (CONVERTING bit) and F-128 (parent-recorded nonces, option b) fixed in R+J+D after the human's decisions; corpus regenerated, `v1.0-security-replay` added; F-131 (Java segment commit race) found by interop and fixed; gate quick green.
- 2026-10-12 — M4.3 done: vlog record/head attacks (1479 runs clean); interop fixture now separates values in all three, exposing F-132 (Dart converting-file vlog read), fixed; gate quick green.
- 2026-10-12 — M4.4 done: F-133 nonce exhaustion wrap (R+J+D), F-134 (J nonce_base); gate quick green.
- 2026-10-12 — M4.5 done: F-135/F-136 (J+D), marker tests R+J+D; F-137 to the human; gate quick green.
- 2026-10-12 — F-137 fixed R+D + spec MUST after the human's decision; F-135 raw-key ownership noted in 14 §11; gate quick green.
- 2026-10-12 — M4.6 done: F-138 length checks (R+J+D), tests fail reverted; gate quick green.
- 2026-10-12 — M4.7 done: F-139 file modes 0600 + sidecar no-follow (R+J+D), tests fail reverted; F-140 (Dart) for M5; gate quick green.
- 2026-10-12 — M4.8 done: deny/audit clean, release workflows pinned, SBOMs, SECURITY.md.
- 2026-10-12 — M4.9 done (SAFETY comments + lints, bench unsafe removed); M4 done R+J; gate quick green.
- 2026-10-12 — M5 started: branch `dart-storage`, 5.1 design (mirror Rust: segment LRU, vlog positioned writes, commit = Rust commit).
- 2026-10-12 — M5 step 2: segment LRU + place-on-publish; 694 Dart tests, interop gate green.
- 2026-10-12 — M5 step 1: open on `onFile`; rebuildManifest scans pages; 694 Dart tests, interop gate green.
- 2026-10-12 — M5 step 3: value log on positioned I/O; 694 Dart tests, interop gate green.
- 2026-10-12 — M5 step 5 core: save on the open file commits in place, slots alternate; 695 Dart tests, interop gate green.
- 2026-10-12 — M5 steps 4+5 done: Engine.commit publishes in place, lock held for the session, create on file; 698 Dart tests, interop gate green.
- 2026-10-13 — lock/created parity with R/J; F-141; M2.2 Dart 1 000 kills 0 failures (fault control caught); 699 Dart tests, interop green.
- 2026-10-13 — F-140, F-142 fixed; F-072 Dart done (keyslots, rotate, encrypt/decrypt), gate steps 7–9 with Dart; 10⁷ open RSS 58 MB PASS; 704 Dart tests, interop green.
- 2026-10-13 — Dart kill mix with maint ops: F-143..F-146 (F-146 S0) and F-094/F-096 Dart fixed; M2.2 Dart 1000 kills 0 failures; 709 Dart tests, gate green.
- 2026-10-13 — remote cleaned (21 -> 37 GB free); F-147 Dart compaction streams inputs/outputs: 10^7 build 2.36 GB -> 201 MB RSS, 1000 kills clean; R+J open.
- 2026-10-13 — F-147 Rust fixed (streamed merge, 1980 -> 348 MB at 10^7), Java not affected; gate quick green.
- 2026-10-13 — M2.1 Dart done (3000 seeds x crash/EIO/ENOSPC, F-095 D); M3.4 Dart corpus replay (47730 inputs) found F-148 (R+D) and F-149 (D); F-076 D; F-150 (R+D space) opened; gate green.
- 2026-10-13 — F-150 fixed: Rust level trigger + space-target GC + cold extent sizing, Dart close finishes job + free-list coalesce; Java measured unaffected; space_test R+J+D; gate quick green.
- 2026-10-13 — F-150 residue: 04 §5 superseded versions drop at any level (approved), R+J+D; Rust 30->13 MB, Dart 80->26 MB.
- 2026-10-13 — Dart FINDINGS cells: 34 resolved (13 ported tests in `findings_test`), F-079 Dart verify fixed, interop step 12 verifies with Dart.
- 2026-10-13 — committed F-150 residue + Dart FINDINGS (gate quick green); SECURITY-REVIEW Dart rows done (F-124, F-122 Dart tests).
- 2026-10-13 — M6 started: `tool/scale.dart` (Dart rung, JSON line) and Rust `rss_scale read`; 10^6 rung: F-151 (whole-segment reads per cache miss, R+D) Dart get p50 36 ms, Rust 7.6 ms.
- 2026-10-13 — F-151 fixed R+D (page-granular segment reads); 10^6 rung: Rust p50 7.6 ms -> 5 us, Dart 36 ms -> 29 us, Dart read RSS 153 MB (budget 128) open; gate quick green.
- 2026-10-14 — Dart read RSS was the wrong bar (M5.5 +64 vs 6.3 +256): 206 MB PASS; F-152 (R+D compaction pacing, L0 46 -> 2) fixed; F-153, F-154 opened; gate quick green.
- 2026-10-14 — F-153 (Rust memtable unbounded between commits) fixed; F-155 opened (Rust build RSS 467 > 352); F-156 S0 (Rust shrink + lazy cache) found by the hop, fixed.
- 2026-10-14 — F-154: settle measured (Rust 495 MB passes); Dart `shrink()` stub replaced by a relocate+truncate port, 1487 -> 688 MB; 734 Dart tests.
- 2026-10-14 — F-155 profiled: Rust live heap 25 MB, footprint 304 MB (pass), RSS is shared/freed pages; metric question to the human.
- 2026-10-14 — 6.3 bar = peak footprint (human); 10^7 rung R+D: F-157 (R settle 923 MB), F-158 (D build 381 MB), F-159 (D get 1 ms) opened.
- 2026-10-14 — F-157 fixed (R: streamed compaction runs + sliced segment moves; D: page-by-page move): Rust 10^7 settle 923 -> 251 MB; gate quick green.
- 2026-10-14 — F-159 closed as a harness bug (Dart rung ran 4 MB cache): p50 1058 -> 29 us; F-158 now 603 MB build at Desktop pages.
- 2026-10-14 — Engine() default 8 KB page (human); F-158 fixed (D: outputs not admitted, builder single-hold, uncached compaction/verify streams): 10^7 AOT build 343 MB, read 270.
- 2026-10-14 — F-158 R: `SegmentBuilder::build` drains pages; Rust 10^7 build footprint 291 -> 282 MB; 40 Rust test binaries green.
- 2026-10-14 — Java 10^7 column: build footprint 301 MB at -Xmx128m (PASS), get p50 86 us, settled amp 1.37; F-158 J bounded; 10^8 blocked on remote disk.
- 2026-10-15 — 10^8: Rust build 736 s / 281 MB, read p50 226 us (after F-160 EMFILE fix), settle 408 MB FAIL; Java OOM at ~2x10^7: F-161 to the human.
- 2026-10-15 — F-161 option B (04 §3.1 writer rule: byte-capped outputs, run trigger, small-neighbour absorb) R+J+D; F-163 Dart tree-1 placement; F-162 filed.
- 2026-10-15 — 10^8 rerun: Rust PASS (settle 315 MB); Java compactor OOM (F-164, F-161 regression), writer stalled 10.7 h; F-162 widened to dead-compactor liveness.
- 2026-10-15 — F-162 fixed (J+R: dead background thread fails the next write), F-164 fixed (J: chunked extent write); Java 5x10^6 at 128m PASS.
- 2026-10-16 — Java + Dart AOT 10^8 rung launched on remote (`cryptand-1e8`, jd-1e8.sh).
- 2026-10-16 — 10^8 Dart: build/settle PASS, read 637 MB FAIL (F-165); Java db vanished from /tmp, rerun under ~/j1e8.
