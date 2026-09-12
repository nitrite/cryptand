# cryptand (Java)

Java implementation of the **Cryptand File Format** (CFF v1.0), a
cross-language, encrypted storage engine and on-disk format for
[Nitrite](https://nitrite.dizitart.com).

A `.cryptand` file written here is opened, verified, mutated and written back by
the Rust and Dart implementations, and theirs by this one, plaintext and
encrypted, with no export step and no conversion.

**The spec is normative.** `../../spec/` is the contract; where this code and
the spec disagree, the spec wins and this code is wrong
(`spec/11-conformance.md` §7).

## Install

```xml
<dependency>
    <groupId>org.dizitart</groupId>
    <artifactId>cryptand</artifactId>
    <version>1.0.0</version>
</dependency>
```

Java 17 or newer. **No runtime dependencies**: Argon2id, BLAKE2b and
XChaCha20-Poly1305 are implemented here, because none is in the JDK.

## Usage

```java
import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Value;

Engine.Options options = new Engine.Options();
long id;
try (Database db = Database.create(Path.of("people.cryptand"), options)) {
    Collection people = db.collection("people");
    id = people.insert(Value.Doc.of(Map.of("name", new Value.Str("Ada"))));
    db.commit();
}
try (Database db = Database.open(Path.of("people.cryptand"), options)) {
    Value.Doc ada = db.collection("people").get(id);
}
```

For an encrypted file set `options.encrypt = true` and `options.password` (or
`options.rawKey`) when creating, and the same credential when opening.

## What it is

A key-separated, lazily-levelled, immutable-segment LSM store with no
write-ahead log: values written once to a value log, a concurrent write path
with a sharded memtable and an off-thread committer, four device profiles, and
authenticated encryption over every page and record. **Level 4** conformance:
core, collections, full text, spatial and vector.

The maintenance API of `spec/13-operations.md` §5 is complete, including
`shrink()`, which relocates live extents downward and truncates.

## Build

```bash
mvn verify         # 325 tests, coverage ratchet, sources and javadoc jars
```

The cross-language gate is `../conformance/interop/run.sh`. Benchmarks, the
interop harness and the fuzzer live under `src/test`, so none of them reach the
published jar.

## License

Apache License 2.0, see [LICENSE](LICENSE).
