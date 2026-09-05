# cryptand

Reference implementation of the **Cryptand File Format** (CFF v1.0) — a
cross-language, encrypted storage engine and on-disk format for
[Nitrite](https://nitrite.dizitart.com).

A `.cryptand` file written by this crate can be opened, queried, mutated and
closed by the Dart reference implementation and back, with no export step, no
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

This crate is **Level 4** (core + collections + full-text + spatial + vector),
full write profile, no `unsafe`.

## Usage

```rust
use std::path::Path;
use cryptand::container::{Durability, Profile};
use cryptand::database::Database;
use cryptand::value::{NumType, Value};

let mut db = Database::create(Path::new("people.cryptand"), Profile::Desktop)?;
let mut people = db.collection("people")?;
people.insert(&mut db.engine, &Value::Doc(vec![
    ("_id".into(),  Value::NitriteId(1)),
    ("name".into(), Value::Str("Ada".into())),
    ("age".into(),  Value::int(NumType::I32, 36)),
]))?;
db.commit(Durability::Sync)?;
db.close()?;

let mut reopened = Database::open(Path::new("people.cryptand"), None)?;
let doc = reopened.collection("people")?.get(&mut reopened.engine, 1)?;
```

For an encrypted database, open the engine directly with
`Engine::create_encrypted(path, profile, &key, 0, 0, 0, 0)` and pass the key to
`Database::open(path, Some(&key))`. See [`examples/roundtrip.rs`](examples/roundtrip.rs)
and the `interop` binary for complete flows.

## Binaries

- `cryptand` — `verify` / `dump` / `stats` / `repair` / `backup` / `fuzz` /
  `create`.
- `interop` — the Rust half of the cross-language round-trip gate
  (`reference/conformance/interop/`).

## Development

```bash
cargo test              # 147 tests in this crate, 212 across the workspace
cargo test --release    # run BOTH profiles — they test different arithmetic
```

`benches/` holds the plain-binary benchmarks that test the `design/`
predictions; `REPORT.md` records every spec defect this implementation has
found.

## License

Apache License 2.0.
