# Cryptand — Dart reference implementation (phase 14)

Pure Dart implementation of the Cryptand File Format, CFF v1.0.

**The spec is normative.** `../../spec/` is the contract; where this code and
the spec disagree, the spec wins and this code is wrong
(`spec/11-conformance.md` §7).

Read **[REPORT.md](REPORT.md)** first: it states what is implemented, the
thirty-three spec defects this work has found across fourteen phases, and every place a
measurement differs from a claim in `../../design/`.

## Quick start

```bash
dart pub get && dart test
```

## Layout

| | |
|---|---|
| `lib/src/bytes.dart` | primitives, varints, bounds-checked reader/writer (`spec/00`) |
| `lib/src/u128.dart` | 128-bit integer as two halves — proves CKE needs no bignum |
| `lib/src/crc32c.dart` | CRC-32C, verified against RFC 3720 |
| `lib/src/value.dart` | the value model, one class per CVE tag |
| `lib/src/cke.dart` | **CKE** — the order-preserving key encoding (`spec/03`) |
| `lib/src/cve.dart` | **CVE** — values, documents, name dictionary, lazy `DocView` (`spec/02`) |
| `lib/src/compare.dart` | logical value order (`spec/02` §8), which CKE must agree with |
| `lib/src/container.dart` | superblock, page header, open procedure, profiles (`spec/01`) |
| `lib/src/segment.dart` | internal keys, bulk builder, B+tree pages, cursor (`spec/04`) |
| `lib/src/filter.dart` | blocked Bloom (`spec/04` §2.4) — see REPORT.md on the hash |
| `lib/src/security.dart` | SHA-256, HMAC, HKDF, subkeys, nonces, keyslots, superblock MAC, the password path (`spec/14`) |
| `lib/src/blake2b.dart` | **BLAKE2b** (RFC 7693) — present only because Argon2id is defined over it |
| `lib/src/argon2.dart` | **Argon2id** (RFC 9106), pure Dart, no dependency (`spec/14` §2, §3.2) |
| `lib/src/vlog.dart` | the two-tier value log, promotion and collection (`spec/04` §6) |
| `lib/src/cow.dart` | **copy-on-write B+trees** — the reserved trees (`spec/04` §3.3, `spec/05` §2) |
| `lib/src/manifest.dart` | **tree 6**, the segment index the read path prunes with (`spec/04` §3.2) |
| `lib/src/engine.dart` | the LSM engine: levels, compaction, the `spec/04` §4 read path, commit and retention |
| `lib/src/txn.dart` | **snapshots, transactions, backpressure, durability, events** (`spec/10`) |
| `lib/src/metrics.dart` | the required observability surface (`spec/13` §6) |
| `lib/src/checkpoint.dart` | **named retained snapshots** (`spec/13` §1) |
| `lib/src/stats.dart` | **planner statistics** — HyperLogLog and the histogram (`spec/13` §9) |
| `lib/src/verify.dart` | **the verification pass** (`spec/04` §11, `spec/01` §9) |
| `lib/src/repair.dart` | **repair** — the manifest rebuilt from segment headers (`spec/13` §3) |
| `lib/src/profile.dart` | **device profiles**, host hints, the stall budget (`spec/12`) |
| `lib/src/backup.dart` | **backup** — full, incremental, and the uuid rules (`spec/13` §2) |
| `lib/src/changefeed.dart` | **the change feed** (`spec/13` §7) |
| `lib/src/spaceapi.dart` | **the space and key-management API** (`spec/13` §5) |
| `lib/src/unicode.dart` | **NFKC, UAX #29 and simple case mapping** at Unicode 15.1 (`spec/07` §2.2) |
| `lib/src/analyzer.dart` | **`cryptand.std.v1`** — the eight-step pipeline (`spec/07` §2) |
| `lib/src/fulltext.dart` | **postings blocks and the term dictionary** (`spec/07` §1, §4) |
| `lib/src/porter2.dart` | **the Snowball English stemmer**, version-pinned (`spec/07` §2.4) |
| `lib/src/wkb.dart` | **ISO WKB geometry**, with EWKB refused (`spec/08` §1) |
| `lib/src/geometry_ops.dart` | **the exact predicates** — §4's second phase (`spec/08` §4) |
| `lib/src/rtree.dart` | **the in-container R-tree** (`spec/08` §2) |
| `lib/src/vector.dart` | **the vector region, adjacency and search contract** (`spec/09`) |
| `lib/src/catalog.dart` | **the catalog** — descriptors, reserved trees, attributes (`spec/05`) |
| `lib/src/index.dart` | **secondary indexes** — entry derivation and the §7 scans (`spec/06`) |
| `lib/src/database.dart` | collections and repositories over the engine |

`bench/` holds the benchmarks that test the `design/` predictions,
`tool/generate_vectors.dart` produces `../../conformance/vectors/`, and
`tool/experiments/` keeps the one-off scripts REPORT.md cites as evidence.

## The four tests that matter most

- `test/cke_test.dart` — asserts CKE's ordering invariant over the full cross
  product of the numeric torture set, against an **independent** exact
  comparator written with `BigInt` that shares no code with the encoder.
- `test/conformance_test.dart` — reads the generated vectors back and checks
  every assertion. It touches only JSON and the public encode/decode paths,
  which is what makes it the first thing to port to Rust and Java.

- `test/fulltext_test.dart` — the strongest form of the same answer. Dart has
  no NFKC, no UAX #29 and no `Simple_Lowercase_Mapping`, and all three are
  reproduced against Unicode's own suites: **19 074 normalization cases and
  1 826 word-break cases, zero failures**.

- `test/argon2_test.dart` and `test/blake2b_test.dart` — the answer to "isn't
  naming an algorithm a language dependency?". They reproduce RFC 9106 §5.3 and
  RFC 7693 Appendix A from published bytes, which is what lets any SDK arrive at
  the same keys without consulting this code. See REPORT.md §0.1.

- `test/engine_test.dart` — the two mandatory tests of `spec/11-conformance.md`
  §6 that this SDK can run: the **aged scan** (§6's four MUSTs, and the size at
  which they stop holding — see REPORT.md §3.1) and the **read tail**, whose
  write load is as normative as its read load and for a reason REPORT.md §1.4
  spells out.
