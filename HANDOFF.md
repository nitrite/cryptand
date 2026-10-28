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
  `dart-storage`: **go (human 10-27), Dart ships 1.0.0.** Freeze Tue 10-27,
  tags Fri 10-30. Human 10-27: keep doing M6.5 as written; schedule
  (6.6-6.8, M7 unstarted) decided later.
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

M6.5 in progress (session 10-27). Harness: `rss_scale PATH N index` (Rust example):
unique idx `ordReference` + compound (`custCityName` 1000 cities, `ordTotMinorU`),
probes, `analyze`, `verify`. Remote clone `cryptand-m6`, logs `reference/bench/runs/ix-r-N.{out,err}`.
- 10^7 (pre-fix): build 460 s, file 6.16 GB, unique p50 31 us, compound 10k rows 6 ms,
  analyze RSS 303 -> 1502 MB (F-183), peak footprint 1.95 GB, verify unsound (F-182).
- F-182 committed 79a63a1 (R+D; J not affected), gate quick green on remote.
- F-183 (R+J+D `analyze` streams two passes) committed, gate quick green.
- 10^6 post-fix (ix2-r-1000000): verify sound, analyze RSS flat (398 -> 398 MB), unique p50 7 us;
  peak footprint 375 MB: PASS against the indexed bar 416 (64 cache + 3 trees x 32 memtable + 256; PLAN 6.3 now says one memtable per tree).
- 10^7 post-fix: verify sound, analyze flat, unique p50 30 us; peak footprint 499 then 368 MB on a rerun
  (bar 416): F-184 open, the peak varies by run. F-185 (J: short scans merged the rest of the tree,
  index probe 1.3 ms -> 3 us) fixed, gate quick green. J (`RssScale PATH N index`) + D (`scale index`) rungs exist.
1. ix4 done (10-28), all verify_sound: Rust 10^7 356/356 MB PASS, Java 10^6 233 / 10^7 220 PASS,
   Dart 10^6 312 PASS, Dart 10^7 509 MB FAIL (bar 416). F-184 now mostly Dart. `~/ix5.sh` running:
   Dart 10^7 with 1 s RSS/footprint samples in `runs/ix5-d-1e7.samples` (`ix5.done` when finished,
   ~1.7 h); build_s ~5000 locates build vs analyze/verify phases.
2. Profile the Dart spike from the samples (`footprint` sampled every 10 s missed it; try 1 s or MallocStackLogging).
   Then 10^8 Rust index (~62 GB; remote ~100 GB free).
3. Rest of 6.5: full text 10^7, spatial 10^7, HNSW 10^6 x 128-d recall@10.

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
- 2026-10-17 — Java 10^8 build PASS, read OOM (F-166 filters unbounded, R+J+D), settle OOM (F-167); F-165 Dart verify extent sweep.
- 2026-10-17 — F-165 R+J, F-166 R+J+D fixed (human chose extent sweep + page-cache filters); 10^8 rerun launched.
- 2026-10-17 — rerun: Java read PASS (F-166), settle OOM F-167 fixed R+J+D; Dart 10^8 read FAIL 467 MB / verify 8.4 h (F-168); Java rerun launched.
- 2026-10-17 — F-167 fixed R+J+D; Java 10^8 all PASS; F-168 (D verify filter per entry, F-166 regression) fixed.
- 2026-10-18 — Dart 10^8 read 466 MB: per-step RSS put it on scan; F-169 (D scan opened every segment) fixed, read 246 MB PASS, verify 510 s; 10^8 PASS R+J+D.
- 2026-10-18 — R/J read rungs gain zipf, scan, verify; 10^8 Java PASS, Rust read 382 MB FAIL: F-170 (Rust scan materializes, no cursor) to the human.
- 2026-10-18 — F-170 fixed (human: for 1.0): Rust `scan_cursor` (04 §8), pages released on long scans; Rust 10^8 read 305 MB PASS; gate quick green.
- 2026-10-18 — F-171 (R+D: unbounded scan unpruned; Rust `collection` opened every segment): Rust 10^8 open 230 -> 3 MB, read 180 MB.
- 2026-10-18 — 10^9 deferred past 1.0 (human, disk); PLAN M6 row updated; remote r1e8.db freed (108 GB free).
- 2026-10-18 — rss_scale `CRYPTAND_ENC=1`; encrypted 10^8 Rust rung launched on remote.
- 2026-10-19 — F-172 (S1, R+D: encrypted writes never re-published the nonce floor, died after 2^20 pages) fixed; gate quick green; encrypted 10^8 Rust rung relaunched.
- 2026-10-19 — enc 10^8 Rust build+read PASS; settle hit F-173 (R: compact/shrink never re-armed the nonce window; J+D unaffected), fixed, gate quick green; settle rerun launched.
- 2026-10-19 — F-174 (R: encrypted `write_extent` sealed a whole 32 MiB extent into a 2nd buffer; 10^7 compact 161 -> 131 MB) fixed, gate quick green; J/D harnesses take CRYPTAND_ENC; enc 10^8 R/J/D chain launched.
- 2026-10-19 — enc 10^8 Rust PASS (settle 288 MB); Java run void (RssScale never set `encrypt`), fixed and requeued after Dart.
- 2026-10-20 — Dart enc 10^8 stopped (61 GiB, disk near full); 10^6: size not from encryption, enc load 4.8x slower; Java enc 10^8 running.
- 2026-10-20 — Java enc 10^8 build+read PASS; settle void (empty output, disk suspected), rerun with disk log.
- 2026-10-20 — Dart enc 10^8 rerun queued after Java (frees ~26 GB dbs + Rust targets, gated on 125 GB).
- 2026-10-20 — Java enc 10^8 settle died on full disk again; cleanup gives 118 GB, Dart rerun gated out.
- 2026-10-20 — Java enc 10^8 PASS (settle 200 MB) after disk cleanup; Dart enc 10^8 rerun running.
- 2026-10-21 — Dart enc 10^8 PASS memory (settle 113 MB); slow reads folded into F-175; enc rows in RESULTS.
- 2026-10-21 — F-175 profiled: Dart put walks the catalog twice per doc (2M decrypts at 10^6); Java caches, Rust never reads it.
- 2026-10-21 — F-175 fixed (D): catalog cache; 10^6 enc load 2660 -> 10136 docs/s, plain 12658 -> 30913.
- 2026-10-21 — Dart enc 10^8 after F-175: build 3.8 h (was 11.9), PASS; enc reads unchanged, F-176 opened.
- 2026-10-21 — F-176 profiled: each Dart enc read decrypts its page in pure-Dart AEAD (no decrypted cache); fix options to the human.
- 2026-10-21 — F-176 partial (D): AEAD 129 -> 265 MB/s, KATs green; enc get 259 -> 214 us; rest of the gap unlocated.
- 2026-10-21 — F-176 profiled via VM service: enc page read runs crc32c ~4x (35% of a get) besides decrypt (40%).
- 2026-10-21 — F-176 CRC: Dart verifies each page checksum once (2.92 -> 1.08 per read); warm 10^6 enc get p50 74 us (plain 26).
- 2026-10-22 — Dart enc 10^8 after F-176: get p50 2262 -> 1263 us, verify 2826 -> 1336 s, build 3.8 -> 2.6 h; PASS.
- 2026-10-22 — harnesses take CRYPTAND_PROFILE (R+J+D); mobile plaintext ladder 10^6..10^8 launched on remote.
- 2026-10-24 — mobile 10^8: Rust done; Java build 69% (~17 h left), Dart queued.
- 2026-10-25 — Java mobile 10^8 root-caused: F-177 (J perf) and F-178 (J S1 visible_seq regression) fixed; rerun launched.
- 2026-10-26 — mobile 10^8 done R+J+D, memory PASS, rows in RESULTS; F-179 (Rust settle doubles file) opened.
- 2026-10-26 — F-179 10^7 split repro: compact 4.8 -> 9.4 GB, shrink -> 4.7; 10^8 failure is in shrink.
- 2026-10-26 — F-179 fixed (R): free tree written at the cut point blocked `cut_tail`; mobile 10^8 settle 93.2 -> 46.8 GB; gate quick green (remote).
- 2026-10-27 — 6.4: F-007 point index charged to the cache (R+D) / capped at the budget (J); F-008 closed.
- 2026-10-27 — F-180 fixed (J: clustering liveness scan due-gated); Java single writer default, spec serialized publish; torture 5000 kills 1 failure = F-181 (pre-existing); gate quick green; merged into dart-storage.
- 2026-10-27 — F-181 bisected to ee3a58b (exposer only): after-kill checker read states at a rewound clock; checker fixed R+J+D; torture J 500 / R 300 / D 300 clean, gate quick green (remote); merged into dart-storage.
- 2026-10-27 — Dart go (human). 6.5 index rung: F-182 (R+D commit mid-job leaked placed outputs) fixed, gate green; F-183 (R+J+D analyze held every key, +1.2 GB at 10^7) fixed, gate green.
- 2026-10-27 — F-183 committed (gate green); 10^6 index rung post-fix: verify sound, analyze flat, footprint 375 MB; 10^7 running.
- 2026-10-28 — 10^7 index footprint 499/368 MB (F-184 open); F-185 Java scan bound fixed; J+D index rungs; ix4 chain running.
- 2026-10-28 — ix4: R/J index rungs PASS (Rust 10^7 356 x2), Dart 10^7 509 MB FAIL; ix5 sampling run launched.
- 2026-10-27 — 6.3 bar for indexed builds counts one memtable per tree (desktop 3 trees: 416 MB); 10^6 index 375 MB PASS; 10^7 at 6.7M rows, RSS ~200-290 MB.
