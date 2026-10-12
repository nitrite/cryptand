# HANDOFF — Cryptand 1.0 release

## State (2026-10-12, IST)

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
- Open outside M5: none. M5 (Dart): F-035, F-038, F-072,
  M2.2 Dart, Dart checks of F-079, F-081, F-084, F-087, F-088, F-094..F-121
  (`?`/`M5` in FINDINGS), Dart corpus replay (M3.4).
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

M5 on branch `dart-storage`; design = top of `reference/dart/cryptand/REPORT.md`.
Steps (2), (1), (3) done, and (5)'s core: `DatabaseFile.save` on the
file the store is open on syncs, writes the superblock to the slot of
`commit_id` parity only, syncs (no whole-image rewrite). Still open in (4)+(5):
`Engine.commit(durability)` writing that superblock itself (its `_barrier`
still records `none`), tree 7 / free tree written incrementally, writer lock
held on the store's handle (01 §10). Next: move the in-place block from
`save` into `Engine.commit`, then M2.2's 1 000 kills.

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
