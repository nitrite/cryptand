# Changelog

All notable changes to the Dart reference implementation of the Cryptand File
Format are documented here. The format's normative source is
[`spec/`](https://github.com/nitrite/cryptand/tree/main/spec) (CFF v1.0); where
this code and the spec disagree, the spec wins.

## 1.0.0

First stable release. Complete implementation of CFF v1.0 — every specification
chapter (`00`–`14`), **Level 4** conformance, full write profile.

### Storage engine

- Order-preserving key encoding (**CKE**, ch. 03) and self-describing value
  encoding (**CVE**, ch. 02), byte-exact against the shared conformance vectors.
- Container format (ch. 01): superblock, page headers, four device profiles
  (`mobile`/`tablet`/`desktop`/`server`), copy-on-write B+trees, free tree.
- Key-separated, lazily-levelled, immutable-segment LSM with no write-ahead log
  (ch. 04): value log with hot/cold tiers and liveness GC, blocked-Bloom + CFH-64
  filters, mandatory cursors, range deletes, TTL, stepwise interruptible
  compaction.
- Catalog (ch. 05) and secondary indexes (ch. 06): unique, non-unique and
  compound indexes maintained in the same commit as the document write.
- Transactions (ch. 10): snapshots, group commit, four isolation levels,
  conflict detection, savepoints, the normative backpressure curve, retention
  watermarks. Declares `Level 0 (single-writer)` — a single Dart isolate has no
  shared-memory threads — and still produces byte-identical files.

### Query surfaces

- Full-text search (ch. 07): the `cryptand.std.v1` analyzer implemented from the
  Unicode 15.1 UCD — NFKC, UAX #29 word segmentation, `Simple_Lowercase_Mapping`
  — verified against Unicode's own `NormalizationTest` (19 074 cases) and
  `WordBreakTest` (1 826 cases), plus the Porter2 stemmer against the Snowball
  vocabulary.
- Spatial (ch. 08): ISO WKB, exact geometry predicates, in-container R-tree.
- Vector (ch. 09): flat regions, adjacency graph, brute-force fallback.

### Security (ch. 14)

- XChaCha20-Poly1305 over page payloads and value-log records; page encryption
  lives in the pager, so every B+tree page, inline value, key and index entry is
  encrypted under `cipher = 1`.
- Argon2id (RFC 9106) and BLAKE2b (RFC 7693) in pure Dart, no dependency;
  HKDF-SHA256; HMAC-SHA256 superblock MAC.
- Random master key wrapped in four keyslots; §4.1 nonce discipline with a
  durably published floor; `DatabaseFile.create` for a database encrypted from
  its first page.

### Operations (ch. 13)

- Verification, repair (manifest rebuild from segment headers), corruption
  containment, checkpoints, full and incremental backup, change feed, planner
  statistics (HyperLogLog + equi-depth histogram), the required metrics with
  unavailable-means-unavailable reporting, and the resumable maintenance API.

### Cross-language

- `.cryptand` files written by this implementation are read, verified, mutated
  and rewritten by the Rust reference implementation and back — plaintext and
  encrypted, both directions — with the wrong key refused by both.

### Known limitations

- Parallel compaction (`04 §5.1`) is single-threaded here by runtime constraint;
  files remain byte-identical.
- The free tree lags its own page frees by one commit (~8 pages at close);
  `repair` reclaims them. This is a property of the format shared by every
  implementation.

### Hardening before release

Found and fixed during the 1.0 release work; each has a row in
[`FINDINGS.md`](https://github.com/nitrite/cryptand/blob/main/FINDINGS.md).
Format byte changes, all approved, all in three implementations, corpus
regenerated, format still CFF v1.0:

- `CONVERTING` superblock flag, authenticated (F-127, 14 §8.3).
- Child pages bound to the nonce recorded in their parent (F-128, 14 §5.5).
- Every encrypted segment page carries its head's `commit_id` (F-188, 04 §2.1).

Also: crash, fault and kill campaigns; fuzzing; nonce-floor overflow (F-133);
key material zeroed on close and failed open (F-135, F-136); files created 0600
(F-139); bounded index `analyze` memory (F-183); commit drains the L0 compaction
backlog (F-187); storage layer rewritten (write-through, commit in place, session lock); whole-tree scans read uncached (F-184); scale rungs to 10⁸ documents.
