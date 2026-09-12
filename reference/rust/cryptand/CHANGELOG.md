# Changelog

All notable changes to the Rust reference implementation of the Cryptand File
Format are documented here. The format's normative source is
[`spec/`](https://github.com/nitrite/cryptand/tree/main/spec) (CFF v1.0); where
this code and the spec disagree, the spec wins.

## 1.0.0

First stable release. Complete implementation of CFF v1.0 — every specification
chapter (`00`–`14`), **Level 4** conformance, full write profile, no `unsafe`.

### Storage engine

- Order-preserving key encoding (**CKE**, ch. 03) and self-describing value
  encoding (**CVE**, ch. 02), byte-exact against the shared conformance vectors.
- Container format (ch. 01): superblock, page headers, four device profiles,
  copy-on-write B+trees, free tree, the pager.
- Key-separated, lazily-levelled, immutable-segment LSM with no write-ahead log
  (ch. 04): two-tier value log with liveness GC, blocked-Bloom + CFH-64 filters,
  mandatory cursors, range deletes, TTL, stepwise interruptible compaction.
- Catalog (ch. 05) and secondary indexes (ch. 06).
- Transactions (ch. 10): snapshots, group commit, four isolation levels,
  conflict detection, savepoints, the normative backpressure curve, retention
  watermarks. Concurrent write path with a sharded memtable and off-thread
  committer.

### Query surfaces

- Full-text search (ch. 07): the `cryptand.std.v1` analyzer from the Unicode
  15.1 UCD — NFKC, UAX #29, `Simple_Lowercase_Mapping` — verified against
  `NormalizationTest` (19 074 cases), `WordBreakTest` (1 826 cases) and the
  Snowball vocabulary (42 649 stems), all reproduced first run.
- Spatial (ch. 08): ISO WKB, exact geometry predicates, in-container R-tree.
- Vector (ch. 09): flat regions, adjacency graph, brute-force fallback.

### Security (ch. 14)

- XChaCha20-Poly1305 over page payloads (in the pager, so every B+tree page,
  inline value, key and index entry is encrypted under `cipher = 1`) and value-
  log records.
- Argon2id, BLAKE2b, HKDF-SHA256, HMAC-SHA256 superblock MAC (RustCrypto).
- Random master key wrapped in four keyslots; §4.1 nonce discipline with a
  durably published, non-derived floor; `Engine::create_encrypted` for a
  database encrypted from its first page.
- Structure-aware reader fuzzing (§9.3): 1 500 mutations, 0 panics.

### Operations (ch. 13)

- Verification, repair, corruption containment, checkpoints, full and
  incremental backup, change feed, planner statistics, the required metrics,
  the resumable maintenance API, and multi-process readers (real processes, a
  host-local lock sidecar).

### Binaries

- `cryptand` — `verify` / `dump` / `stats` / `repair` / `backup` / `fuzz` /
  `create`.
- `interop` — the Rust half of the cross-language round-trip gate.

### Cross-language

- `.cryptand` files written by this crate are read, verified, mutated and
  rewritten by the Dart reference implementation and back — plaintext and
  encrypted, both directions — with the wrong key refused by both.

### Testing

- 254 tests in the crate, 319 across the workspace, green in **both** the debug
  and release profiles (they test different arithmetic — an overflow that
  panics in debug silently wraps in release).
