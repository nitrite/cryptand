# CFF-02 — CVE, the Cryptand Value Encoding

**Normative.** Assumes `00-conventions.md`.

CVE encodes everything Nitrite stores *as a value*: scalars, documents, arrays,
maps, vectors and foreign blobs. It is little-endian, self-describing, forward
compatible, and designed so that reading one field of a document costs a binary
search and a slice — not a deserialization.

Keys use CKE (`03-key-encoding.md`), not CVE. The two encodings are separate
because they optimize opposite things: CVE optimizes decode cost and size, CKE
optimizes byte-comparison order.

---

## 1. Value

```
Value := u8 type_tag  ||  payload(type_tag)
```

| tag | type | payload |
|---|---|---|
| `0x00` | `NULL` | — |
| `0x01` | `FALSE` | — |
| `0x02` | `TRUE` | — |
| `0x03` | `I8` | `i8` |
| `0x04` | `I16` | `i16` |
| `0x05` | `I32` | `i32` |
| `0x06` | `I64` | `i64` |
| `0x07` | `I128` | `i128` |
| `0x08` | `U8` | `u8` |
| `0x09` | `U16` | `u16` |
| `0x0A` | `U32` | `u32` |
| `0x0B` | `U64` | `u64` |
| `0x0C` | `U128` | 16 bytes |
| `0x0D` | `INT_VAR` | `ivar` — canonical compact form for any integer that fits `i64` |
| `0x0E` | `F32` | `f32` |
| `0x0F` | `F64` | `f64` |
| `0x10` | `DEC128` | IEEE 754-2008 decimal128, 16 bytes (feature `DEC128`) |
| `0x11` | `CHAR` | `u32` Unicode scalar value |
| `0x12` | `STR` | `uvar len` + UTF-8 |
| `0x13` | `BYTES` | `uvar len` + raw |
| `0x14` | `TIMESTAMP` | `i64` milliseconds since Unix epoch, UTC |
| `0x15` | `TIMESTAMP_NS` | `i64` seconds + `u32` nanos, UTC |
| `0x16` | `ZONED` | `TIMESTAMP` payload + `str` IANA zone id |
| `0x17` | `DATE` | `i32` days since Unix epoch (no time, no zone) |
| `0x18` | `TIME` | `u64` nanoseconds since midnight |
| `0x19` | `DURATION` | `i64` seconds + `u32` nanos |
| `0x1A` | `UUID` | 16 bytes, RFC 4122 big-endian byte order |
| `0x1B` | `NITRITE_ID` | `i64` |
| `0x1C` | `REGEX` | `str` pattern + `str` flags |
| `0x20` | `ARRAY` | §3 |
| `0x21` | `MAP` | §4 — any CKE-encodable `Value` as key |
| `0x22` | `DOC` | §5 |
| `0x23` | `VECTOR` | §6 |
| `0x24` | `GEOMETRY` | `uvar len` + WKB (`08-spatial.md`) |
| `0x30` | `BLOB_REF` | 16-byte blob pointer (`01-container.md` §5) |
| `0x31` | `OVERFLOW_REF` | `uvar inline_len` + inline bytes + `u64 next_page` |
| `0x32` | `VLOG_REF` | 16-byte value-log pointer (`04-segments.md` §6.3) |
| `0x7F` | `OPAQUE` | §7 — foreign, language-specific value |
| `0x80`–`0xBF` | reserved, minor versions | |
| `0xC0`–`0xFF` | implementation-private, must round-trip as `OPAQUE` semantics | |

`0x1D`–`0x1F`, `0x25`–`0x2F` and `0x33`–`0x7E` are reserved.

### 1.1 Every unassigned tag is length-prefixed

**A value whose tag falls in a reserved or implementation-private range MUST be
encoded as `u8 tag || uvar byte_len || bytes(byte_len)`.** That is: every tag in
`0x1D`–`0x1F`, `0x25`–`0x2F`, `0x33`–`0x7E`, `0x80`–`0xBF` and `0xC0`–`0xFF`.

This rule is what makes `11-conformance.md` §4 rule 1 — "an unknown CVE type tag
round-trips byte for byte" — actually implementable, and without it that rule is
a promise no reader can keep. To preserve a value you must first know where it
ends, and for an unknown *scalar* tag there is nothing to derive that from.

A `DOC` alone could get away without it: its field table carries a
`value_offset` per field, so the next field's offset bounds the unknown one. But
an `ARRAY` and a `MAP` store values back to back with no offsets, so an unknown
tag inside either is unskippable, and a reader that meets one has no choice but
to abandon the whole containing value — losing every *known* sibling with it.
That is precisely the silent data loss §4 of `11-conformance.md` exists to
prevent.

A reader MUST therefore surface such a value as an opaque `(tag, bytes)` pair
and MUST write it back unchanged. A reader that encounters an unassigned tag
that is *not* followed by a valid length MUST report corruption rather than
guess a width.

### 1.2 Canonical forms

There are several ways to write the number 5. The format permits all of them on
read and constrains what a writer produces:

- A writer SHOULD emit `INT_VAR` for any integer value that fits in `i64`,
  regardless of the source language's declared width.
- A writer MUST emit the fixed-width tag when the *declared width matters to
  round-tripping* — i.e. when the SDK's type system distinguishes `i32` from
  `i64` and the application will read it back as the narrower type. Rust's
  `Value` enum needs this; Java and Dart mostly do not.
- **The declared width is metadata, never semantics.** Equality and ordering are
  by numeric value across all numeric tags (see `03-key-encoding.md` §4). An
  implementation MUST NOT make `I32(5)` unequal to `I64(5)`.

This is the resolution of the three-way divergence documented in
`research/nitrite-survey.md` §6.3: no lossy fold to `double` anywhere, and
cross-type numeric equality is defined by the format rather than by each SDK.

## 2. Truncation and bounds

Every length in CVE is untrusted input. A decoder MUST verify that a declared
length fits inside the containing buffer **before** allocating, MUST enforce the
depth limit of 100, and MUST fail with a corruption error rather than throw a
native out-of-memory.

## 3. ARRAY

```
0x20  uvar byte_len  uvar count  Value × count
```

`byte_len` counts the bytes after `byte_len` itself, so a decoder can skip an
array without walking it.

## 4. MAP

```
0x21  uvar byte_len  uvar count  ( Value key, Value value ) × count
```

Entries MUST be sorted by `CKE(key)` byte order. Sorting makes maps comparable,
hashable and diffable across languages, and makes a lookup a binary search.
Duplicate keys — two entries whose `CKE(key)` bytes are equal — are corruption.

**A map key MUST be CKE-encodable.** That is: `NULL`, a boolean, any numeric
tag, a temporal tag, `CHAR`, `STR`, `BYTES`, `NITRITE_ID`, `UUID`, or an `ARRAY`
of those. `DOC`, `MAP`, `VECTOR`, `GEOMETRY`, `REGEX`, `OPAQUE` and the three
indirection tags have no CKE encoding (`03-key-encoding.md` §2) and therefore no
defined order, so they cannot be map keys. A writer MUST reject one; a reader
encountering one MUST report corruption. (An application that needs a document
as a key encodes it above the format — as a `STR` or `BYTES` digest, say.)

## 5. DOC — the document

The important one. Layout:

```
0x22
uvar   byte_len                     bytes after this field
uvar   field_count
u8     flags                        bit0 SORTED_BY_NAME_ID (MUST be 1 in v1)
--- field table, field_count entries, each: ---
uvar   name_ref
uvar   value_offset                 from the first byte of the value area
--- name area ---
  for each name_ref with bit0 = 1: uvar len + UTF-8 bytes, in table order
--- value area ---
  Value × field_count, in table order
```

### 5.1 `name_ref`

```
name_ref = (name_id << 1)        when the name is in the tree's name dictionary
name_ref = (index << 1) | 1      when the name is written inline in the name area
```

Inline names are for one-off keys (user-supplied dynamic field names). A writer
SHOULD add any name it sees more than once to the dictionary.

The field table is sorted by `name_ref`'s **resolved name bytes**, not by the
numeric `name_ref` — otherwise dictionary and inline names would interleave
arbitrarily. Concretely: sort by UTF-8 byte order of the field name; store
`SORTED_BY_NAME_ID = 1` to assert it. A reader MAY binary-search on names; it
MUST NOT assume `name_id` order matches name order.

### 5.2 Reading a field

```
resolve(name):
  lo, hi = 0, field_count
  binary search comparing name bytes (dictionary lookup is an array index)
  → value_offset → decode one Value
```

No allocation for unread fields. This is the property the whole design is built
around, and it is what makes Cryptand cheaper than Java serialization, Kryo, Hive
adapters and bincode on every read that does not need the whole document.

### 5.3 The name dictionary

Each data tree has an associated **name dictionary tree** (`05-catalog.md` §4):

```
key   = CKE(U32 name_id)
value = CVE STR name
```

Rules:

- `name_id` is allocated append-only from a counter in the tree descriptor and
  is **never reused**, so a stale cached dictionary is never *wrong*, only
  incomplete.
- A writer MUST write new dictionary entries in the **same commit** as the
  document that first uses them. Atomicity of the batch guarantees this is not a
  window.
- A reader MAY cache the whole dictionary; on encountering an unknown `name_id`
  it MUST re-read the dictionary tree before failing.
- Dictionary entries are never deleted, even when no document uses the name.
  (Reclaiming them would require reusing ids.)

Expected effect: for a 20-field document with an average field-name length of 12
bytes, this removes ~240 bytes of repeated text per document, replacing it with
~20–40 bytes of varints. On document-shaped data this dominates every other
space optimization in the format.

### 5.4 Reserved fields

`_id`, `_revision`, `_modified`, `_source`, `_type` are ordinary fields with
ordinary names, and SHOULD occupy `name_id` 1–5 in every data tree's dictionary
so that they encode in one byte.

`_id` MUST be present in every document stored in a collection data tree, MUST be
`NITRITE_ID`, and MUST equal the tree key of the entry. A reader finding a
mismatch MUST report corruption.

## 6. VECTOR

A first-class type so that embeddings do not pay `ARRAY`-of-`F32` overhead.

```
0x23  u8 dtype  uvar dim  payload
```

| dtype | payload |
|---|---|
| `0` | `f32 × dim` |
| `1` | `f16 × dim` (IEEE 754 binary16) |
| `2` | `i8 × dim`, plus trailing `f32 scale`, `f32 zero_point` |

A 768-dimensional f32 embedding is 3074 bytes here versus 3841 as an array of
tagged `F32`, and decodes as one slice.

## 7. OPAQUE — foreign values

```
0x7F  uvar byte_len  str origin  str type_name  uvar data_len  bytes(data_len)
```

`origin` is the writing SDK's identity (`"java"`, `"dart"`, `"rust"`, …).
`type_name` is that SDK's name for the type (a fully-qualified Java class, a
Rust type path, …).

**This is the escape hatch that makes real interchange survivable.** Java's
`Document` accepts arbitrary `Object` values; an SDK's mapper may not be able to
represent every one of them in the CVE type set. Rather than fail or silently
drop, the writer emits `OPAQUE`.

Rules, all MUST:

- A reader that does not recognize `origin`/`type_name` surfaces the value as an
  opaque handle carrying `origin`, `type_name` and `data`.
- On read-modify-write, an opaque value's bytes are round-tripped **unchanged**.
- An opaque value is not comparable and MUST NOT be used as an index key; an
  attempt is an error, not a silent no-op.
- A writer SHOULD NOT use `OPAQUE` for anything the CVE type set can express.
  Emitting `OPAQUE` for a `java.time.LocalDate` instead of `DATE` is a defect,
  because it makes the field unqueryable from Dart and Rust.

An implementation SHOULD expose a count of opaque values per collection so an
application can see how much of its data is not portable.

## 8. Equality and comparison

Defined here once, for all SDKs, ending the current divergence.

1. `NULL` equals only `NULL`. `NULL` sorts below every other value.
2. All numeric tags (`I8`…`DEC128`) form **one domain**, compared by exact
   numeric value. `I32(5) == I64(5) == F64(5.0) == INT_VAR(5)`. `DEC128`
   participates in *value* comparison, where an implementation compares exactly
   (a decimal against a binary float is compared by their exact rational values,
   never by converting one to the other). It has **no key encoding** and cannot be
   indexed — `03-key-encoding.md` §4.4 explains why.
3. NaN equals NaN (so a NaN key is findable) and sorts above every other number.
   −0.0 equals +0.0 and they sort equal; a writer SHOULD canonicalize −0.0 to
   +0.0. Both facts make the corresponding **key** lossy — a `-0.0` key decodes
   as `+0.0` and a NaN payload is not preserved (`03-key-encoding.md` §7). That
   is forced: a key that distinguished two values the order calls equal would
   place something strictly between them.
4. `STR` compares by UTF-8 byte order — i.e. by Unicode code-point order. No
   locale, no case folding, no normalization. An SDK offering locale collation
   does it above the format with an explicit collation index.
5. `BYTES` compares lexicographically, shorter-is-smaller on a prefix.
6. `CHAR` compares as its scalar value and is **not** equal to a one-character
   `STR`. (This preserves Rust's `Value::Char` round trip; SDKs without a char
   type map it to `STR` on read, which is a widening, not a re-encoding.)
7. `TIMESTAMP`, `TIMESTAMP_NS` and `ZONED` all denote an **instant** and compare
   by that instant across the three tags, at nanosecond resolution — a
   `TIMESTAMP` of 1000 ms and a `TIMESTAMP_NS` of (1 s, 0 ns) are equal.
   `03-key-encoding.md` §5 encodes all three into one key subclass so that the
   byte order agrees. `DATE`, `TIME` and `DURATION` are not comparable to
   instants and sort in their own groups.
8. `ARRAY` compares element-wise, then by length. `MAP` and `DOC` compare as
   their sorted `(key, value)` sequences.
9. `BOOL`: `FALSE < TRUE`.
10. Cross-type order (when two values are not in the same group) is the group
    order given in `03-key-encoding.md` §2. It is stable and total but has no
    semantic meaning; queries SHOULD NOT rely on it.

`OPAQUE`, `GEOMETRY`, `VECTOR` and `REGEX` are **not ordered**. Using them as
index keys is an error. `DOC` and `MAP` *are* ordered (rule 8) but have no key
encoding, so they too cannot be index keys or map keys — the order defined here
is for value comparison only. The set of types that can be a key is exactly the
set `03-key-encoding.md` §2 gives a group tag.

## 9. Indirection tags are storage, not data

`BLOB_REF`, `OVERFLOW_REF` and `VLOG_REF` never appear inside a document. They
are what a *tree cell* holds in place of a value when the value lives elsewhere
(`04-segments.md` §2.2, `value_kind`), and they are given CVE tags only so that
tooling can name and dump them.

An implementation MUST resolve an indirection transparently on read and MUST NOT
surface one to an application. Comparison and equality are defined on the
resolved value.

A compaction MUST copy an indirection through unchanged rather than resolving
and re-inlining it (`04-segments.md` §6.8). Violating this quietly destroys the
write-amplification property the whole design rests on.
