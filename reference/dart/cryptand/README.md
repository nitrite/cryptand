# cryptand

Reference implementation of the **Cryptand File Format** (CFF v1.0) in pure
Dart — a cross-language, encrypted storage engine and on-disk format for
[Nitrite](https://nitrite.dizitart.com).

A `.cryptand` file written by this package can be opened, queried, mutated and
closed by the Rust reference implementation and back, with no export step, no
conversion, and no loss. Any SDK in any language reaches the same file by
implementing one document: the [spec](https://nitrite.dizitart.com/cryptand).

**The spec is normative.** Where this code and the spec disagree, the spec wins
and this code is wrong (`spec/11-conformance.md` §7).

## What it is

A key-separated, lazily-levelled, immutable-segment LSM store with no
write-ahead log:

- **Values are written once** to an append-only value log; the tree holds a
  16-byte pointer. Compaction rewrites ~6% of the data, not 100%.
- **No write-ahead log** — the value-log record is the durability record.
- **Everything is immutable** — segments are bulk-built and written once, so no
  crash at any durability setting produces an unopenable file.
- **Four device profiles** (`mobile`/`tablet`/`desktop`/`server`) change how a
  writer behaves and nothing about how a file is read.
- **Encryption is thorough** — XChaCha20-Poly1305 over every page and value-log
  record, Argon2id key derivation, a random master key wrapped in keyslots.
  Headers stay in the clear so verify/repair/backup run with no key.

This package is **Level 4** (core + collections + full-text + spatial + vector)
and declares `Level 0 (single-writer)` — a single Dart isolate has no
shared-memory threads, so it produces byte-identical files without concurrent
writers.

## Usage

```dart
import 'dart:io';
import 'package:cryptand/cryptand.dart';

void main() {
  final key = List<int>.generate(32, (i) => i);

  final db = DatabaseFile.create('people.cryptand',
      credential: key, kdf: Keyslot.kdfRaw);
  final people = db.createCollection('people');
  people.put(const CNitriteId(1),
      CDoc({'name': CStr('Ada'), 'age': CInt.i32(36)}));
  db.engine.flush();
  DatabaseFile.save(db, 'people.cryptand');

  final reopened = DatabaseFile.open('people.cryptand', key: key);
  final doc = reopened.collection('people')!.get(const CNitriteId(1))!;
  print(doc['name']); // 'Ada'
}
```

See [`example/`](example/) for the full round-trip, and
[`CHANGELOG.md`](CHANGELOG.md) for what each release covers.

## Package layout

| area | files |
|---|---|
| Primitives (`spec/00`) | `bytes`, `u128`, `crc32c` |
| Value & key encoding (`02`, `03`) | `value`, `cve`, `cke`, `compare` |
| Container (`01`) | `container`, `cow` |
| LSM engine (`04`) | `segment`, `filter`, `vlog`, `manifest`, `engine` |
| Catalog & indexes (`05`, `06`) | `catalog`, `index`, `database` |
| Full text (`07`) | `unicode`, `unicode_tables`, `analyzer`, `porter2`, `fulltext` |
| Spatial (`08`) | `wkb`, `geometry_ops`, `rtree` |
| Vector (`09`) | `vector` |
| Transactions (`10`) | `txn` |
| Profiles (`12`) | `profile` |
| Operations (`13`) | `verify`, `repair`, `checkpoint`, `backup`, `changefeed`, `spaceapi`, `stats`, `metrics` |
| Security (`14`) | `security`, `aead`, `argon2`, `blake2b` |
| File layer (`01` §1) | `file` |

## Development

```bash
dart pub get
dart test          # 655 tests
dart analyze
```

`bench/` holds the benchmarks that test the `design/` predictions;
`tool/generate_vectors.dart` produces the shared conformance vectors;
`REPORT.md` records every spec defect this implementation has found.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
