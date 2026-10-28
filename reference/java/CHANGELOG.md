# Changelog

All notable changes to the Java implementation of the Cryptand File Format are
documented here. The format's normative source is
[`spec/`](https://github.com/nitrite/cryptand/tree/main/spec) (CFF v1.0); where
this code and the spec disagree, the spec wins.

## 1.0.0

First stable release. Complete implementation of CFF v1.0: every specification
chapter (`00` to `14`), **Level 4** conformance, full write profile, no runtime
dependencies.

- Engine: key-separated, lazily-levelled LSM with a two-tier value log, no
  write-ahead log, a sharded memtable and an off-thread committer (ch. 01, 04, 10).
- Catalog, indexes, full text, spatial and vector (ch. 05 to 09).
- Operations: checkpoints, backup, repair, containment, metrics, change feed,
  multi-process readers, planner statistics, and the whole §5 space API,
  `shrink()` relocating live extents downward (ch. 13).
- Security: Argon2id, BLAKE2b, HKDF, XChaCha20-Poly1305, keyslots, page and
  record encryption, superblock authentication (ch. 14).
- Files round-trip with the Rust and Dart implementations in every direction,
  plaintext and encrypted (`reference/conformance/interop/run.sh`).

### Hardening before release

Found and fixed during the 1.0 release work; each has a row in
[`FINDINGS.md`](https://github.com/nitrite/cryptand/blob/main/FINDINGS.md).
Format byte changes, all approved, all in three implementations, corpus
regenerated, format still CFF v1.0:

- `CONVERTING` superblock flag, authenticated (F-127, 14 §8.3).
- Child pages bound to the nonce recorded in their parent (F-128, 14 §5.5).
- Every encrypted segment page carries its head's `commit_id` (F-188, 04 §2.1).

Also: Java short scans stop at the range bound (F-185); crash, fault and kill campaigns; fuzzing; nonce-floor overflow (F-133);
key material zeroed on close and failed open (F-135, F-136); files created 0600
(F-139); bounded index `analyze` memory (F-183); commit drains the L0 compaction
backlog scale rungs to 10⁸ documents.
