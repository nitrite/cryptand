# Nitrite today: a survey of the three SDKs

Everything below was read out of the working trees at
`/Volumes/External/codebase/nitrite` on 2026-09-01. File and line references are
to those trees.

---

## 1. The shape of the three SDKs

| | Java (+ Kotlin) | Flutter / Dart | Rust |
|---|---|---|---|
| Repo | `nitrite-java` | `nitrite-flutter` | `nitrite-rust` |
| Core | `nitrite/` | `packages/nitrite` | `nitrite/` |
| Persistent engines | MVStore (H2 2.4.240), RocksDB (10.2.1) | Hive 2.2.3 | Fjall 3.1.10 |
| Volatile engine | `InMemoryStore` (`ConcurrentSkipListMap`) | in-memory map | `InMemoryStore` (DashMap) |
| Spatial | `nitrite-spatial` (JTS 1.20) | `nitrite_spatial` | `nitrite-spatial` (own disk R-tree) |
| Full text | in-core `TextIndex` + `TextTokenizer` | in-core `TextIndex` | in-core `text_index` **and** `nitrite-tantivy-fts` |
| Vector | — | — | `nitrite-vector` (HNSW + DiskANN) |
| Debug bridge | `nitrite-bridge` | `nitrite_bridge` | `nitrite-bridge` |
| Interchange today | `nitrite-support` → JSON | — | — |

The three cores are deliberate ports of one another. The *interfaces* line up
almost perfectly; the *bytes* do not line up at all.

## 2. The storage abstraction — nearly identical in all three

`NitriteStore` (Java `store/NitriteStore.java`, Rust
`store/nitrite_store.rs::NitriteStoreProvider`, Dart `store/nitrite_store.dart`)
is a named-map factory plus lifecycle:

```
open_or_create / is_closed / commit / before_close
has_map / open_map(name) / close_map / remove_map
open_rtree / close_rtree / remove_rtree            (Java + Dart; Rust has none — spatial owns its file)
get_collection_names / get_repository_registry / get_keyed_repository_registry
store_version / store_config / store_catalog
subscribe / unsubscribe
```

Rust adds three that Java and Dart do not have and that matter here:

```rust
fn compact(&self)              -> NitriteResult<()>;
fn supports_atomic(&self)      -> bool;
fn run_atomic(&self, op: &mut dyn FnMut() -> NitriteResult<()>) -> NitriteResult<()>;
```

`run_atomic` is the only place in any SDK where *a write spanning several maps*
is atomic — Fjall's single-writer transaction. Java and Dart have nothing
equivalent, so a document insert that touches the data map plus three index maps
is four independent writes with a window in between.

`NitriteMap` is a sorted map:

```
contains_key / get / put / put_if_absent / remove / clear / size / is_empty
keys / values / entries / reversed_entries
first_key / last_key / higher_key / ceiling_key / lower_key / floor_key
drop / is_dropped / attributes / set_attributes
```

`NitriteRTree` is `add(bbox, id) / remove / find_intersecting_keys /
find_contained_keys / size / clear / drop`.

**This abstraction is the right seam for Cryptand.** A Cryptand adapter implements
exactly these, so no SDK needs a rewrite above the store layer.

Two API-level divergences worth carrying into the design:

- Rust `NitriteMapProvider::put_all(Vec<(Key, Value)>)` and
  `skip_keys_from_start(count)` exist as optional, defaulted methods. Dart has
  `valuesSkipping(int)`. Java expresses the same thing as a capability
  interface (`SkippableIterator`, checked by a downcast in `BoundedStream`).
  Cryptand should make batch-put and cursor-skip *mandatory* rather than
  optional — they are free on a cursor-based engine.
- Dart's whole surface is `Future`/`Stream`. Any Cryptand design that requires
  synchronous mmap or pointer casting is dead on arrival in Flutter.

## 3. What each engine actually writes

### MVStore (Java default)

`NitriteMVStore.openMap` (line 252) builds maps with a bare
`new MVMap.Builder<>()`, i.e. H2's `ObjectDataType`. `ObjectDataType` has fast
paths for boxed primitives, `String`, `UUID`, `Date` and arrays; anything else —
including `Document`, `NitriteId`, `DBValue`, `IndexEntryKey`, `Attributes` —
falls through to `TYPE_SERIALIZED_OBJECT`, which is **Java object
serialization**. (The tag table survives verbatim in the v1 compat shim,
`nitrite-mvstore-adapter/.../compat/v1/NitriteDataType.java`.)

Consequences: the file is unreadable outside a JVM; every document carries a
Java class descriptor; `readObject` on untrusted input is a known hazard; and
document size is roughly 2–4x a compact binary encoding.

Structurally MVStore is a copy-on-write B-tree over 4 KiB blocks grouped into
chunks, with two file headers for safety and a chunk-level garbage collector.
The COW-into-chunks design has a documented weakness: a chunk cannot be reclaimed
until every live page in it has been rewritten elsewhere, so reclaiming space
costs writes proportional to the *live* data, not the dead data.

### RocksDB (Java, optional)

`nitrite-rocksdb-adapter` keeps one column family per Nitrite map and encodes
through `ObjectFormatter` — `KryoObjectFormatter` in practice
(`formatter/KryoObjectFormatter.java`, Kryo 5.6.2), with a separate
`encodeKey`/`decodeKey` path and hand-written key serializers
(`ComparableKeySerializer`, `IndexEntryKeySerializer`,
`DefaultTimeKeySerializers`) whose whole job is to make Kryo output sort
correctly under RocksDB's bytewise comparator.

That hand-written order-preserving key layer is *exactly* the problem Cryptand's
CKE solves once, portably, instead of once per engine.

Costs: a JNI crossing per operation; Kryo registration state that is
Java-specific; and RocksDB's memory footprint (block cache + memtables + index
and filter blocks, all outside the JVM heap and outside the JVM's control).

### Hive (Flutter)

`nitrite_hive_adapter` writes Hive boxes. Keys go through
`store/key_encoder.dart`:

```dart
String encode(dynamic key) {
  var writer = BinaryWriterImpl(_typeRegistry);
  writer.write(key);
  return base64.encode(writer.toBytes());
}
```

**Keys are base64 of Hive's binary encoding.** Base64 of a little-endian binary
frame has no relationship to the logical order of the values, so Hive cannot
serve `higherKey`/`ceilingKey`/range scans from disk order — ordering has to be
recovered in Dart memory.

Hive itself is an append-only log with an in-memory key index. Every box open
reads the whole key index into memory (O(number of keys) RAM even for a lazy
box); updates append and never reclaim until a manual `box.compact()`; values in
a non-lazy box are all resident. Documents are encoded by hand-written
`TypeAdapter`s (`adapters/document_adapter.dart`, `dbvalue_adapter.dart`,
`index_key_adapter.dart`, …) — Dart-specific, and versioned by Hive typeIds.

This is the weakest of the four engines and by a wide margin the easiest to beat.

### Fjall (Rust)

`nitrite-fjall-adapter` is the best-engineered of the four adapters, and it is
where most of Cryptand's key-encoding design comes from.

- Values: `bincode` (legacy config).
- Keys: `ordered_key.rs`, a purpose-built order-preserving codec, written after
  a real bug — an integer `between`/`gte` returned wrong rows because bincode's
  little-endian `I32(255)` sorted *after* `I32(256)`. It tags by type group,
  encodes numbers as `(f64 magnitude, class, exact i128)`, byte strings with a
  `0x00 0x01` escape and a `0x00 0x00` terminator, and arrays with
  `ELEM_CONTINUE`/`ELEM_END` framing so `[a] < [a,b]`.
- Map names are mangled to fit Fjall's partition charset
  (`store.rs::encode_name`: `|` → `_P_`, `+` → `_K_`, with `_X_` escaping).
- Cross-map atomicity via `run_atomic`.

Fjall is an LSM with key–value separation and LZ4, which gives it low write
amplification (~2–3x) and good bulk-write throughput. Its weaknesses for
Nitrite: point reads probe multiple levels, range and reverse scans are N-way
merges, and — the local one — `nitrite-rust`'s map layer navigates by repeated
`higher_key` with no cursor, so a skipped or scanned row costs a fresh descent
from the root.

## 4. What Nitrite stores

Six kinds of data, all of which Cryptand must carry:

1. **Key–value maps.** The primitive. Everything else is built on it.
2. **Documents.** `Document` is an ordered string-keyed map. Reserved fields:
   `_id` (`NitriteId`, a 64-bit snowflake), `_revision`, `_modified`, `_source`
   (Rust adds `_type`). Java `Document` values are `Object` — arbitrary POJOs
   reach the store. Rust `Value` is a closed enum of 24 variants
   (`common/value.rs`). Dart sits in between.
3. **Index data.** Unique, non-unique, compound, full-text — see §5.
4. **Spatial data.** Java stores JTS geometry as **WKT text**
   (`spatial/GeometryUtils.java` uses `WKTReader`) and indexes it in an
   MVStore `MVRTreeMap`. Rust has its own `Geometry` enum
   (`Point`/`Circle`/`Polygon`/`Envelope`) and its own page-based
   `disk_rtree` with a `FileHeader { magic, version, page_size, root_page,
   next_page_id, entry_count, height, free_list_head, checksum_enabled,
   free_page_count }`, an LRU page cache, a free list, per-page checksums and
   V1→V2→V3 migrations. Three different geometry representations, three
   different R-trees.
5. **Vector data.** Rust only. `nitrite-vector` offers HNSW (graph persisted
   into `NitriteMap`s, written as one atomic batch, rebuilt from the collection
   if torn) and DiskANN (Vamana graph plus a memory-mapped flat vector file,
   PQ codes resident, exact re-rank from disk), with F32/F16/I8 precision.
6. **Store metadata.** `$nitrite_catalog`, `$nitrite_meta_map`,
   `$nitrite_store_info`, `$nitrite_users`, plus per-collection
   `$nitrite_index_meta|<collection>`.

## 5. Current index layouts — three SDKs, three answers

Index map name is the same string in all three
(`IndexUtils.deriveIndexMapName` / `index_utils.rs::derive_index_map_name`):

```
$nitrite_index | <collection> | <encoded field names> | <index type>
```

…and that is where the agreement ends.

| | Java | Dart | Rust |
|---|---|---|---|
| Unique, single field | `Map<DBValue, List<NitriteId>>` | `Map<DBValue, List<NitriteId>>` | `Map<Array[value, id], ()>` |
| Non-unique, single field | `Map<IndexEntryKey, TRUE>` in a `…\|composite` map | `Map<IndexKey, true>` in a `…\|composite` map | `Map<Array[value, id], ()>` |
| Compound | `Map<DBValue, NavigableMap<DBValue, ?>>` — **nested sub-maps** | `Map<IndexKey.compound, true>` — flat | `Map<Array[v1..vn, id], ()>` — flat |
| Range sentinel | `IndexEntryKey` `LOWER=-1 / EXACT=0 / UPPER=1` byte | `IndexKey._Bound.lower/exact/upper` | array element framing (`ELEM_END < ELEM_CONTINUE`) |
| Full text | `Map<String token, List<NitriteId>>` | same | same, plus optional Tantivy in a separate directory |

Java's compound index still uses the nested-`NavigableMap` layout that Java and
Dart abandoned for the single-field non-unique case — it is O(n) per write and
O(n²) to bulk-load a low-cardinality field. Cryptand should specify **one**
layout (the flat composite key) and retire the other two.

## 6. Semantic divergences that a byte-portable file would *not* fix

These are the ones that matter most. A shared format with these still in place
would produce files that open everywhere and answer differently everywhere.

**6.1 Index type names disagree.** The string is written into the index map
name and into the index descriptor, so it is on disk.

| | Unique | Non-unique | Full text |
|---|---|---|---|
| Java `IndexType` | `Unique` | `NonUnique` | `Fulltext` |
| Dart `IndexType` | `Unique` | `NonUnique` | `Fulltext` |
| Rust `constants.rs` | `unique` | `non-unique` | `full-text` |

Rust's map names are therefore different strings for the same index.

**6.2 The catalog tag disagrees.** Java and Dart write `collections`
(`TAG_COLLECTIONS`); Rust's `constants.rs` defines `TAG_COLLECTION =
"collection"` — singular.

**6.3 Numeric key normalization disagrees three ways.** Measured 2026-08-31
during the fix for nitrite-java gh-1282:

| SDK | `int 5` stored, `eq(5.0)` queried | ids above 2⁵³ |
|---|---|---|
| Java | matches — `DBValue.normalizeNumber` folds to `Double` where exact | correct only since gh-1282 |
| Rust | matches — integers compared as `u128`, floats separately | always correct |
| Dart | **does not match** — no fold, no cross-type equality | always correct |

Java's fold exists because RocksDB compares the *encoded* key rather than
calling `compareTo`. Before gh-1282 it was unconditional, and above 2⁵³ doubles
step by 128 — snowflake/TSID ids were colliding onto one key, so a unique index
rejected ids it had never seen. Note the gotcha if this is ever touched again:
`(long)(double) v == v` is **not** a sufficient exactness test, because
`Long.MAX_VALUE`'s double rounds up to 2⁶³ and the cast back saturates. The
range guard `normalized >= -0x1p63 && normalized < 0x1p63` is required.

Cryptand removes the whole problem class: CKE orders integers and floats in one
exact numeric domain (`spec/03-key-encoding.md` §4), so cross-type equality is a
prefix scan and no lossy fold is needed anywhere.

**6.4 Map name mangling differs per engine.** Fjall substitutes characters, Hive
base64s the whole key, MVStore takes the name as-is. A file written by one is
not addressable by another even if the bytes inside were compatible.

**6.5 Cross-map atomicity exists only on Fjall.** Everywhere else, a document
insert and its index updates are separate writes.

## 7. Performance facts on record

Measured, not predicted. Kept here because Cryptand has to beat them.

**Paged scan, quadratic `skip` fix** (all three SDKs, merged 2026-08-31; Java
5.1/5.2, `nitrite-rust` PR 24, `nitrite-flutter` PR 62). Metric: cost of a paged
walk over a whole collection relative to one full scan, 20k rows of ~1 KB, 400
per page.

| repo / store | before | after |
|---|---|---|
| Java / MVStore | 10.8x | **0.9x** |
| Flutter / Hive | 27.6x (19.8 s vs 0.7 s) | **1.0x** |
| Flutter / in-memory | 3.9x | 3.9x |
| Rust / default | 68.8x | **40.4x** |

Rust remains at 40.4x because its store navigates by repeated `higher_key` from
the root — there is no cursor in the `NitriteMap` API. **This is a storage-engine
defect, not a query-planner defect, and Cryptand's cursor requirement fixes it.**

Two more recorded traps that a new engine inherits if it is careless:

- Dart's `Iterable.skip()` over Hive keys throws past the last key: Dart's
  `SkipIterator` calls `moveNext` for the whole count without checking the
  result, and Hive's skip-list iterator dereferences a null past the end.
- Wall-clock ratio assertions in Nitrite's CI are flaky; performance guards
  should assert on the *plan* or a store metric, never on a timing ratio.

## 8. What interchange looks like today

`nitrite-support`: `Exporter`/`Importer` over a JSON schema file, Java only. It
is a full dump and reload, it is slow, it flattens types through Jackson, and
there is no Dart or Rust counterpart. `nitrite-bridge` (all three SDKs) is a
*debugging* bridge over a paired local socket to the `dbinspect` desktop
client — it inspects a live database, it is not a format.

So: there is no interchange path between Dart and Rust at all, and the Java path
is a lossy one-shot export.

## 9. What Cryptand must therefore provide

Ranked by how much of the above it removes.

1. One value encoding, one key encoding — kills §3 and §6.3 entirely.
2. Numeric tree ids with a name catalog — kills §6.4.
3. Cross-tree atomic commit as a *format* guarantee — kills §6.5, and makes
   index maintenance correct by construction rather than by adapter luck.
4. Cursors in the map contract — kills the 40.4x in §7.
5. One normative index layout, one set of index type names, one catalog
   schema — kills §5, §6.1, §6.2.
6. Spatial and vector indexes *inside* the container with specified page
   formats — kills §4.4 and §4.5, and lets a Java reader see an index a Rust
   writer built.
7. A feature-flag and unknown-preservation regime, so an SDK that lacks the
   vector module can still safely write documents to a collection that has one.
