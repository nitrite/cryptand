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
