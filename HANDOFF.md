# HANDOFF — Cryptand 1.0 release

## State (2026-10-11, night IST)

- Branch `packaging/v1.0.0`. Manifests 1.0.0, nothing published, no tags.
  `tools/gate.sh quick` green at the M4.3 commit.
- Done: M0, M1.1, M1.2 (Rust, Java), M2.1–2.3 (Rust, Java), M3 (8 cargo-fuzz
  targets x 4 h, 7 Jazzer targets x 2 h under JDK 21: clean), M4.1, M4.2.
  Dart halves wait for M5. Details: git log and PLAN status table.
- Jazzer: remote clone `~/Documents/codebase/cryptand-fuzz`, run under
  `JAVA_HOME=/opt/homebrew/opt/openjdk@21` (JDK 24 silently voids the run):
  `JAZZER_FUZZ=1 mvn -B surefire:test -Dtest=JazzerTest#<t>` in `reference/java`.
- M4.1/M4.2 left for M4.5: Java wiping the caller's password array (review
  row 29), the never-log marker test (row 40). KATs in
  `reference/conformance/vectors/kat`; F-126 Argon2id J+D fixed; interop has a
  password-slot leg (5b).
- M4.3 in progress: `tools/security_attack.py` (stdlib Python, no shared code):
  CRC-repaired attacks on live pages, superblock, keyslots, file length; 3
  writers x 3 readers, 1197 runs, ~100 s, in `gate.sh full`. Green except two
  spec gaps it reports as GAP: F-127 (forged plaintext page accepted, S0) and
  F-128 (older page replayed in place). Found and fixed F-129 (Java slot choice
  on unknown feature), F-130 (Rust typed errors). Rollback documented in the
  three READMEs. Not yet attacked: value-log records and blob/vector chunks
  (the interop files have none) — extend before ticking 4.3.
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

- None open. F-127 fixed (957bde6). F-128 (b) approved 10-12, design below.

## F-128 design (approved: full A–G for 1.0)

Encrypted files only (cipher = 0: fields written 0, never checked). A reader
in a strict file (F-127) MUST report tampering when a child's header `nonce`
differs from the nonce its parent recorded.
A superblock: 7 root nonces at 328..383 (catalog, freelist, attributes,
manifest, vlog_stats, checkpoint, changefeed), under `sb_mac`.
B catalog descriptor `root_nonce` U64 (and `vector_region_nonce`).
C CoW B+tree internal cell: `u64 child_nonce` after `child_subtree_entries`
(CoW trees only; segment cells unchanged).
D R-tree internal entry: `u64 child_nonce` (entry 16·d + 24 bytes).
E manifest entry `"nonce": U64` = segment head page nonce.
F every headed page inside a segment extent carries the head's `commit_id`.
G overflow pages carry the pointing leaf's `commit_id` (no layout change).
Spec text: 14 §5.5 (normative), 01 §2/§5, 04 §2.1/§2.2/§3.2, 05 §3, 08 §2.1, 09.
Residual, documented: vector-region chunks (rewritten in place, rebuildable);
blob replay is caught by the pointer's crc32c as corruption.

## Next action

F-128 in Rust: pager records the nonce it sealed/opened; CowTree child_nonce
(A, C) and roots; catalog `root_nonce` (B); rtree (D); manifest `nonce` (E);
segment commit rule (F). Then Java, Dart, regenerate corpus, harness expects
tamper for "replayed older version". Then extend the harness to value-log
records and blob/vector chunks.

## Log

- 2026-10-10 — Jazzer was under JDK 24 (void); openjdk@21 installed; F-119 fixed; Java M1.2 encrypted seed 9334 diverges, not reproduced locally. Earlier sessions: git history.
- 2026-10-11 — F-120 fixed in spec (option a); F-121 (Java verify horizon mix) found via seed 9334 and fixed; final Java M1.2 encrypted run started.
- 2026-10-11 — Jazzer openFile/openEncrypted/cveDecode/analyzer 2 h clean under 21; last 3 targets started.
- 2026-10-11 — M1.2 Java encrypted 0..10000 clean; last 3 Jazzer targets clean, M3 Rust/Java done.
- 2026-10-11 — M4 started: SECURITY-REVIEW.md first pass; F-122 fixed (R+J tests), F-123 converting vector added after approval.
- 2026-10-11 — spec 14 §13 reworded for security-converting; M4.1 done (F-124 tests, F-125 docs).
- 2026-10-11 — M4.2 KATs in all three; F-126 Argon2id (J+D) found and fixed.
- 2026-10-11 — interop password leg; M4.3 harness (1197 runs); F-129, F-130 fixed; F-127/F-128 to the human.
