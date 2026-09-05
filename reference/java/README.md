# Cryptand — Java reference implementation

Java implementation of the **Cryptand File Format** (CFF v1.0).

**The spec is normative.** `../../spec/` is the contract; where this code and
the spec disagree, the spec wins and this code is wrong
(`spec/11-conformance.md` §7).

## Status: byte layer complete, engine not started

This is **in progress**. It is not yet a conforming implementation and does not
yet declare a level.

| chapter | state |
|---|---|
| `00` conventions — varints, strict UTF-8, CRC-32C, limits, error taxonomy | **done** |
| `01` container — superblock, page header, profiles, feature bits | **done** |
| `02` CVE — the value model, documents, name dictionary | **done** |
| `03` CKE — the order-preserving key encoding and the range helpers | **done** |
| `04` segments — §2.4 filter and CFH-64 only | **partial** |
| `05` catalog — tree descriptors, reserved trees, naming | **done** |
| `06` indexes — entry derivation, field paths, the §7 scan contract | **done** |
| `12` profiles — the four profiles and every constant | **done** |
| `14` security — HKDF, subkeys, nonces, keyslot layout | **partial** |
| `04` the engine — segments, value log, CoW trees, manifest, compaction | not started |
| `07` full text, `08` spatial, `09` vector | not started |
| `10` transactions, `13` operations | not started |
| `14` — Argon2id, BLAKE2b, XChaCha20-Poly1305, page/record encryption | not started |

**91 tests, green**, run against the shared conformance vectors in
`../conformance/vectors` — the same JSON the Dart implementation generates and
the Rust one consumes. Nothing here reads the Dart or Rust source.

**Nine of the ten vector groups are consumed.** The tenth, `analyzer`, needs the
Unicode 15.1 tables and Porter2 and is its own phase.

What is actually verified today:

- **CKE and CVE** — every case in `cke/values.json` (30) and `cve/values.json`
  (17), byte-exact both directions; the **170-value numeric torture set** in its
  published sort order; §1's ordering invariant over **all 170 × 170 pairs**,
  checked against an independent exact comparator built on `BigDecimal` that
  shares no code with the encoder; the three documented lossy decodings; and the
  document vectors **with and without the name dictionary**.
- **Container** — the published superblock decoded, re-encoded, and **built from
  scratch byte-for-byte**; every field offset; the page header; the checksum
  scopes; an unknown required feature bit refusing the file and an unknown
  optional one not; and a `vlog_min` above a quarter page treated as corruption.
- **Filter** — CFH-64's six published values, and the **whole 1000-key filter
  reproduced byte-for-byte**, header and blocks. The header is 20 bytes, not the
  16 an earlier vector labelled.
- **Catalog** — every published tree descriptor re-encoded byte-for-byte,
  including `"orders|2026+eu"` needing no escaping anywhere, and an unknown
  descriptor field surviving a decode-and-rewrite.
- **Indexes** — all nine entry-derivation cases byte-exact, the field-path
  escapes, the 1024-entry cap, and §8.2's numeric-bound failure reproduced as a
  test rather than trusted.
- **Security** — RFC 5869's HKDF test case 1, the three subkeys, the 24-byte
  nonce construction, and the keyslot layout at its published offsets.
- **Rejects** — every published one: unknown group tags, truncated bodies,
  non-canonical escapes and varints, lengths past the buffer, unpaired
  surrogates on write, ill-formed UTF-8 on read, `DEC128` as a key, a bad
  keyslot state, and a damaged page or superblock checksum.

Two of the tests are about the tests. `VectorCoverageTest` asserts how many
cases each vector file holds, because every other test here is a loop over a
vector file and a loop over an empty list passes — this project has produced
five controls that could not fail. And each encoder has been checked with a real
negative control: shifting the CKE exponent bias by one fails four tests, and
changing CFH-64's second rotate from 27 to 26 fails two.

The bar for "conforming" is not this. It is `spec/11-conformance.md` §6's
mandatory tests plus the cross-language round-trip gate in
`../conformance/interop/` — a real `.cryptand` file written here, read, verified
and mutated by Dart and Rust, and back. Until that passes in all four
directions, this stays `1.0.0-SNAPSHOT`.

## Build

```bash
mvn test
```

Java 17 or newer. The library itself has **no runtime dependencies**; JUnit and
Jackson are test scope only, Jackson purely to read the vector JSON.

Java 17 has records, sealed interfaces and pattern matching for `instanceof`,
which is what the value model needs. Pattern matching in `switch` is 21, so the
encoders dispatch through `instanceof` chains and the compiler does **not** check
them for exhaustiveness — each chain ends in a throw naming the type it did not
handle. Worth knowing when adding a CVE type: the build will not tell you where
to go, the tests will.

## Layout

| | |
|---|---|
| `ByteReader` / `ByteWriter` | little-endian primitives, varints, and the big-endian writers CKE needs (`spec/00` §3, §4) |
| `Utf8` | strict UTF-8 — the JDK's convenient calls substitute silently, which the spec forbids |
| `Crc32c` | `spec/00` §6, delegating to the JDK's `CRC32C` |
| `U128` | 128-bit integer as two `long` halves — CKE needs no bignum, and this is the demonstration |
| `Value` | the value model, one sealed variant per CVE tag (`spec/02` §1) |
| `Tag` / `NumType` | the three different numberings, each in exactly one place |
| `Cve` | values, documents, the name dictionary (`spec/02`) |
| `Cke` | the order-preserving key encoding and §8's range helpers (`spec/03`) |
| `NameDict` | a data tree's field-name dictionary (`spec/02` §5.3) |
| `Superblock` / `PageHeader` | the container (`spec/01` §2, §3) |
| `Profile` / `Feature` / `TreeId` | the device profiles, the feature bits, the reserved trees |
| `Cfh64` / `BlockedBloom` | the segment filter and its hash (`spec/04` §2.4) |
| `TreeDescriptor` | a typed *view* over the catalog's CVE document (`spec/05` §3) |
| `IndexKeys` | index entry derivation and the §7 scan contract (`spec/06`) |
| `Security` / `Keyslot` | HKDF, subkeys, nonces, keyslots (`spec/14` §3, §4) |

## License

Apache License 2.0 — see [LICENSE](LICENSE).
