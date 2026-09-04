# CFF-06 — Secondary indexes

**Normative.** Assumes `03-key-encoding.md`, `05-catalog.md`.

One layout, for all three index types, in all languages. This replaces the three
different layouts documented in `research/nitrite-survey.md` §5.

---

## 1. The layout

Every index is one tree. Every index key is a CKE `ARRAY`:

```
key   = CKE( Array[ v1, v2, …, vk, NitriteId ] )
value = EMPTY                                     (value_kind 3, zero bytes)
```

where `v1…vk` are the indexed field values in the order the index declares them
(k = 1 for a single-field index), and `NitriteId` is the document's id.

That is the whole design. Consequences worth stating explicitly:

- **Insert and remove are O(1) point operations.** No read-modify-write of a
  growing id list, no nested sub-map. Java's `SingleFieldIndex` unique path
  (`Map<DBValue, List<NitriteId>>`) and `CompoundIndex`
  (`Map<DBValue, NavigableMap<DBValue, ?>>`) are both O(n) per write and O(n²)
  to bulk-load a low-cardinality field; both are retired.
- **A prefix query is a range scan**, using `prefix_of_array` and `successor`
  from `03-key-encoding.md` §8. An index on `(country, city, name)` answers
  queries on `country`, on `(country, city)`, and on all three, with one seek
  each.
- **Entries are self-describing.** A scan yields the indexed values *and* the
  document id by decoding the key; there is no second lookup to learn which
  document matched, and a covering query need never touch the data tree.
- **The `LOWER/EXACT/UPPER` bound byte is gone.** Java's `IndexEntryKey` and
  Dart's `IndexKey._Bound` carry a sentinel byte in every stored key to build
  range boundaries. `successor()` does that outside the key, so every index
  entry is one byte smaller and a sentinel can never be persisted by accident.
- **Uniqueness is enforced, not encoded.** A unique index uses the same layout;
  the SDK checks for an existing entry with the same `v1…vk` prefix before
  inserting. The tree does not need a different shape for it. The check is on
  the *`NitriteId` behind* the matching entries, not on their existence: an
  entry whose id is the id being written is the writer's own and is not a
  violation. A unique index over a multi-valued field reaches the same key twice
  for `["a", "b", "a"]`, and a rebuild or a replayed write reaches keys the
  document already owns; a bare existence test rejects all of these. Java, Dart
  and Rust all shipped that bare test (nitrite/nitrite-java#1295).

## 2. Descriptor

An index tree's catalog descriptor:

```
kind   = "index"
owner  = <name of the data tree it indexes>
params = {
    "index_type":  "unique" | "non_unique",   -- the ONLY record of uniqueness
    "data_tree":   U32,                       -- tree id, authoritative
    "fields":      [ STR, … ],                -- field paths, in order
    "sparse":      BOOL,                      -- optional, default false
    "collation":   STR                        -- optional, default absent
}
```

An earlier draft also carried a `"unique": BOOL` alongside `index_type`. Two
records of one fact drift, and nothing said which wins, so the boolean is gone:
**uniqueness is `index_type == "unique"` and nothing else.** A reader
encountering a stray `unique` field preserves it (`11-conformance.md` §4) and
ignores it.

`fields` are field *paths* into the document, using `.` for nesting and
`[]`-free array traversal (see §5). `data_tree` is the binding that matters;
`owner` is the human-readable mirror.

Index tree names are for people: `idx:<data tree name>:<field1,field2>:<type>`
is the recommended convention, but nothing parses it and a name collision is
resolved by appending a counter, not by escaping.

## 3. Null and missing

| document state | index entry |
|---|---|
| field present with value `null` | `CKE(Array[NULL, id])` — indexed |
| field absent | `CKE(Array[NULL, id])` — indexed, **unless** `sparse` |
| field absent, `sparse = true` | no entry |

`NULL` sorts below every other value (`03-key-encoding.md` §2), so
`field < x` naturally includes nulls and `field > x` naturally excludes them.
This matches all three SDKs' current behaviour (Java's `DBNull`, Rust's
`Value::Null`, Dart's `DBNull`), now written down.

A **unique** index treats every `NULL` as distinct — many documents may lack the
field. This is the SQL convention and the one all three SDKs already follow.
Concretely, the uniqueness check of §1 is **skipped** whenever any of `v1…vk` is
`NULL`; it is not that the check runs and passes.

## 4. Arrays: one entry per element

If an indexed field holds an array, the index records **one entry per element**:

```
document { tags: ["red", "blue"], _id: 7 }
entries   Array["red",  NitriteId(7)]
          Array["blue", NitriteId(7)]
```

Removal removes all of them. A query `tags == "red"` is an ordinary prefix scan
and needs no special case. Duplicate elements produce one entry, not two — the
key is identical, so the second write is a no-op.

For a compound index where more than one field is an array, entries are the
cartesian product. A writer MUST cap this at 1024 entries per document and
report an error beyond it rather than write an unbounded number of index rows.

## 5. Field paths

A field path is a `.`-separated sequence of document field names, resolved left
to right. Traversing an array field applies the remainder of the path to every
element and flattens the results (so `orders.items.sku` indexes every sku in
every item of every order).

A path component that is itself a literal `.` is escaped as `\.`; a literal
backslash is `\\`. This is the only escaping in the format, and it exists only
inside index field paths.

An unresolvable path is treated as an absent field (§3).

## 6. Values that cannot be indexed

`DOC`, `MAP`, `VECTOR`, `GEOMETRY`, `REGEX`, `OPAQUE`, `DEC128`, `BLOB_REF`,
`OVERFLOW_REF` and `VLOG_REF` have no CKE encoding (`03-key-encoding.md` §2).
Attempting to index a field holding one MUST fail with a clear error naming the
field and the type.

`DEC128` is the surprising member of that list — it is a number, and numbers are
otherwise the most indexable thing in the format. `03-key-encoding.md` §4.4 has
the reason: a decimal fraction has no exact binary `m × 2^e` form, so it cannot
join the exact numeric ordering domain without rounding. Storing it is fine;
ordering it is not.

`BYTES` **is** indexable in Cryptand. (Rust's `validate_index_field` currently
rejects it; that restriction is not needed once keys are byte strings and can be
lifted or kept as an SDK-level policy, but the format permits it.)

## 7. Query planning contract

An index tree supports exactly these, and an SDK's planner MUST express every
indexed predicate as one of them:

Every one of these is built from the helpers of `03-key-encoding.md` §8, and
from no others:

| predicate on `(v1…vj)`, j ≤ k | scan |
|---|---|
| equality on a prefix | `[prefix_of_array(v1…vj), successor(…))` |
| equality on a prefix, **last one numeric, type-agnostic** | `[array_prefix_numeric(v1…vj), successor(…))` — the helper that leaves the last element's type code off, so `eq(5)` matches `I32(5)` and `F64(5.0)` alike |
| range on the j-th after equality on `v1…v(j-1)` | `prefix_of_array(v1…v(j-1)) ‖ 0x01` plus the bound of `03-key-encoding.md` §8.1 (non-numeric) or §8.2 (numeric — build from `N(v)`, **never** from `CKE(v)`) |
| `starts_with` on a string in the j-th position | `03-key-encoding.md` §8.3 |
| full scan of the index | `seek_first` … `seek_last` |
| reverse of any of the above | the same bounds, cursor running backwards |

The numeric rows are the ones to get right. A range bound built from the full
`CKE(v)` cuts *between numeric types* rather than between numeric values, which
makes `field >= 5` miss an `I8(5)` and `field > 5` return a `U8(5)`.
`03-key-encoding.md` §8.2 has the worked failure.

### 7.1 Choosing between indexes

An index descriptor carries planner statistics — entry count, distinct-value
estimate, null count, key range and an equi-depth histogram — maintained free of
charge during last-level compaction (`13-operations.md` §9).

Nitrite's `FindPlan` today picks an index from static descriptor properties:
whether it is unique, and how many fields it covers. That routinely picks a
unique index on a field the query barely constrains over a non-unique index that
would eliminate 99 % of the collection. With statistics the planner can estimate
selectivity and choose on evidence, and can decide between an index scan and a
collection scan rather than always preferring the index.

Statistics are **advisory**: they may be stale or absent, and a planner MUST
produce correct results without them.

Sorted output falls out for free when the sort key is an index prefix — the scan
is already in order, so a `sort` over an index prefix MUST NOT materialize. This
is what makes `find().sort().limit()` cheap, and it is the second half of the
paging fix (`04-segments.md` §8 is the first).

## 8. Consistency with the data tree

Index maintenance and the document write go into the **same batch** and therefore
the same commit (`10-transactions.md`). An index can never be transiently out of
step with its collection in a durable state — a guarantee only the Fjall backend
offers Nitrite today, and only because of `run_atomic`.

A verifier MUST be able to check an index against its data tree: every document
produces exactly the entries §3–§5 require, and every entry maps to a live
document. A mismatch is corruption unless the descriptor carries `stale_from`.
