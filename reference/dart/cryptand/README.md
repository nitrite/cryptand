# Cryptand — Dart reference implementation (phase 1)

Pure Dart implementation of the Cryptand File Format, CFF v1.0.

**The spec is normative.** `../../spec/` is the contract; where this code and
the spec disagree, the spec wins and this code is wrong
(`spec/11-conformance.md` §7).

Read **[REPORT.md](REPORT.md)** first: it states what is implemented, the nine
spec defects this work found, and every place a measurement differs from a claim
in `../../design/`.

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
| `lib/src/security.dart` | SHA-256, HMAC, HKDF, subkeys, nonces, keyslots, superblock MAC (`spec/14`) |

`bench/` holds the benchmarks that test the `design/` predictions,
`tool/generate_vectors.dart` produces `../../conformance/vectors/`, and
`tool/experiments/` keeps the one-off scripts REPORT.md cites as evidence.

## The two tests that matter most

- `test/cke_test.dart` — asserts CKE's ordering invariant over the full cross
  product of the numeric torture set, against an **independent** exact
  comparator written with `BigInt` that shares no code with the encoder.
- `test/conformance_test.dart` — reads the generated vectors back and checks
  every assertion. It touches only JSON and the public encode/decode paths,
  which is what makes it the first thing to port to Rust and Java.
