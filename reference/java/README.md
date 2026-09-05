# Cryptand — Java reference implementation

Java implementation of the **Cryptand File Format** (CFF v1.0).

**The spec is normative.** `../../spec/` is the contract; where this code and
the spec disagree, the spec wins and this code is wrong
(`spec/11-conformance.md` §7).

## Status: byte layer only

This is **in progress**. It is not yet a conforming implementation and does not
yet declare a level.

| chapter | state |
|---|---|
| `00` conventions — varints, strict UTF-8, CRC-32C, limits, error taxonomy | **done** |
| `02` CVE — the value model, documents, name dictionary | **done** |
| `03` CKE — the order-preserving key encoding | **done** |
| `01` container, `04` segments, `05` catalog, `06` indexes | not started |
| `07` full text, `08` spatial, `09` vector | not started |
| `10` transactions, `12` profiles, `13` operations, `14` security | not started |

**33 tests, green**, run against the shared conformance vectors in
`../conformance/vectors` — the same JSON the Dart implementation generates and
the Rust one consumes. Nothing here reads the Dart or Rust source.

What is actually verified today:

- every case in `cke/values.json` (30) and `cve/values.json` (17), byte-exact,
  both directions;
- the **170-value numeric torture set**, byte-exact, in the published sort
  order, and §1's ordering invariant over **all 170 × 170 pairs** — checked
  against an independent exact comparator built on `BigDecimal` that shares no
  code with the encoder;
- the three documented lossy decodings (`-0.0`, a NaN payload, and every
  instant-valued tag collapsing to `TIMESTAMP_NS`);
- the document vectors **with and without the name dictionary**, including the
  field table sorted by resolved name bytes with dictionary and inline names
  mixed;
- every published reject: unknown group tags, truncated bodies, non-canonical
  escapes, lengths past the buffer, unpaired surrogates on write, ill-formed
  UTF-8 on read, and a `DEC128` used as a key.

The bar for "conforming" is not this. It is `spec/11-conformance.md` §6's
mandatory tests plus the cross-language round-trip gate in
`../conformance/interop/` — a real `.cryptand` file written here, read,
verified and mutated by Dart and Rust, and back. Until that passes in all four
directions, this stays `1.0.0-SNAPSHOT`.

## Build

```bash
mvn test
```

Java 21 or newer. The library itself has **no runtime dependencies**; JUnit and
Jackson are test scope only, Jackson purely to read the vector JSON.

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

## License

Apache License 2.0 — see [LICENSE](LICENSE).
