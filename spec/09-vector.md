# CFF-09 — Vector index

**Normative.** Conformance Level 4. Assumes `01-container.md`,
`02-value-encoding.md`, `04-segments.md`.

Nitrite has vector search only in Rust today (`nitrite-vector`: HNSW persisted
into `NitriteMap`s, plus DiskANN over a memory-mapped flat file). Neither is
reachable from Java or Dart. This chapter puts both inside the container so a
Java reader can query an index a Rust writer built.

The design principle: **specify the durable layout, not the algorithm.** A
proximity graph is a flat vector region plus an adjacency list per node. How an
implementation searches or builds that graph is its own business, as long as the
recall it achieves is a quality question and not a correctness one.

---

## 1. Parts

| part | where |
|---|---|
| vectors | one or more `VECTOR_REGION` extents (§2) |
| adjacency | a `vector_graph` tree (§3) |
| quantization codebook | a blob (§4) |
| quantized codes | a `VECTOR_REGION` extent with `dtype` = the code width |
| metadata | the catalog descriptor (§5) |

## 2. Vector region

A contiguous, page-aligned extent, head page type `VECTOR_REGION` (10), with
`flags.EXTENT_HEAD` set.

Region header, immediately after the head page's 40-byte page header:

| off | size | field |
|---|---|---|
| 0 | 8 | `magic` = `43 52 59 5F 56 45 43 1A` (`"CRY_VEC"` + `0x1A`) |
| 8 | 4 | `dim` |
| 12 | 1 | `dtype` — 0 f32, 1 f16, 2 i8, 3 u8 (PQ codes) |
| 13 | 1 | `reserved` |
| 14 | 2 | `stride` — bytes per slot, ≥ the natural size, page-friendly |
| 16 | 8 | `slot_count` — allocated slots |
| 24 | 8 | `live_count` |
| 32 | 8 | `data_offset` — bytes from the extent start to slot 0 |
| 40 | 8 | `next_region` — page id of a continuation region, 0 if last |
| 48 | 16 | reserved |

Slot *i* is at `extent_start_byte + data_offset + i × stride`. Slots are
addressed by a global `slot_id` that spans the region chain.

Three properties, all load-bearing:

- **`data_offset` is page-aligned.** An implementation that can `mmap` maps the
  region once and reads vectors as slices with no copy; DiskANN's whole point is
  that resident memory is then bounded by the OS page cache, so an index larger
  than RAM cannot OOM. **This does not survive encryption.** An encrypted region
  is chunked per page (`14-security.md` §5.4) and cannot be sliced in place, so
  the implementation decrypts into a buffer whose size it must bound itself —
  the OS stops doing that job for it. An encrypted vector index is fully
  supported and materially harder to keep inside a memory budget; say so rather
  than discover it.
- **An implementation that cannot `mmap` reads positionally.** Dart does exactly
  this: `RandomAccessFile.setPosition` + `readInto`. The layout is identical;
  only the access method differs. No part of this format requires mmap.
- **`stride` may exceed the natural vector size** so slots land on 64-byte
  boundaries for SIMD. `stride ≥ dim × sizeof(dtype)`, padding bytes are zero.
  `stride` is a `u16`, so a region's `dim × sizeof(dtype)` MUST be ≤ 65535 —
  16383 dimensions at f32, 32767 at f16 or i8 (`00-conventions.md` §8). A model
  beyond that is served by splitting the vector across two indexes, not by
  widening the field, because a 64 KiB vector is not an embedding a proximity
  graph is the right structure for.

For `dtype = 2` (i8 scalar quantization) each slot is followed inside its stride
by `f32 scale, f32 zero_point`. For `dtype = 3` (PQ codes) a slot holds `m`
subquantizer code bytes where `m` comes from the codebook (§4).

Slot 0 of the first region is reserved and never used, so `slot_id = 0` is a
null pointer.

## 3. Adjacency tree

```
kind   = "vector_graph"
key    = CKE(Array[U8 level, U64 slot_id])
value  = CVE BYTES wrapping an adjacency record
```

The record below is a raw byte layout, wrapped in a CVE `BYTES` value (tag
`0x13`) for the same reason postings are (`07-fulltext.md` §4.2): every INLINE
cell in the format holds a CVE value, with no exceptions, so generic tooling can
dump a tree it does not understand.

Adjacency record:

```
u16   degree
uvar  neighbour_delta × degree     -- zigzag deltas of slot_id, first absolute
```

For **HNSW**, `level` is the graph layer (0 is the base layer, containing every
node). For **DiskANN / Vamana**, there is one layer and `level` is always 0.

Keying by `(level, slot_id)` puts a layer's adjacency contiguously and makes a
layer scan sequential, which is what index construction and repair need.

Deltas are zigzag because neighbour ids are not sorted in graph order — a
proximity graph's neighbour list is ordered by distance, not by id. An
implementation MAY sort the list by id before delta-coding (smaller) at the cost
of losing the distance ordering; the descriptor records which via
`params.neighbours_sorted`.

An adjacency record for a typical degree of 32 is under 100 bytes, so it may sit
either side of `vlog_min`. A writer SHOULD keep adjacency records **inline** —
set the tree's `params.inline_values = true` — because the graph is read
randomly and hot, and an extra value-log indirection per hop is the worst place
in the format to spend one. Vectors themselves are not values in a tree at all;
they live in the flat region (§2).

The entry point(s) for a search are in the descriptor, not in the tree, so a
search starts with zero tree lookups.

## 4. Quantization codebook

A blob (`01-container.md` §5) referenced from the descriptor:

```
u8    version           -- 1
u8    kind              -- 0 none, 1 product quantization, 2 scalar
u16   m                 -- subquantizers (PQ)
u16   k                 -- centroids per subquantizer, typically 256
u16   sub_dim           -- dim / m
f32   centroids[m][k][sub_dim]        -- little-endian
```

`dim = m × sub_dim` MUST hold. Centroids are stored explicitly rather than as a
training seed, because two implementations running the same k-means on the same
data will not produce the same centroids — and if they did not match, an index
written by one would be unreadable by the other.

## 5. Descriptor

```
kind   = "vector_graph"
owner  = <data tree name>
params = {
    "index_type":   "vector",
    "data_tree":    U32,
    "field":        STR,
    "dim":          U32,
    "metric":       "cosine" | "l2" | "dot",
    "algorithm":    "hnsw" | "vamana",
    "precision":    "f32" | "f16" | "i8",
    "vector_region": U64,               -- head page of the region chain
    "code_region":   U64?,              -- PQ codes, if any
    "codebook":      BLOB_REF?,
    "entry_points":  ARRAY[U64],        -- slot ids
    "max_level":     U8,
    "m":             U16,               -- HNSW: neighbours per node
    "ef_construction": U16,
    "neighbours_sorted": BOOL,
    "slot_to_doc":   U32,               -- tree id of the slot → document map
    "doc_to_slot":   U32                -- tree id of the document → slot map
}
```

## 6. Slot ↔ document maps

**Two trees, both `kind = "kv"`, both named in the descriptor.** An earlier draft
had a single `params.id_map` and then said "its inverse is served by a second
tree" without giving that tree a name — which left the inverse unreachable from
the catalog.

```
params.slot_to_doc :  key = CKE(U64 slot_id)     value = CVE NITRITE_ID
params.doc_to_slot :  key = CKE(NITRITE_ID)      value = CVE U64
```

Both directions are needed: search returns slots, filtering needs documents, and
deletion needs to find a document's slot. Both are maintained in the same batch
as the document write, so they cannot disagree in a durable state; a verifier
checks that they are exact inverses.

A deleted document's slot is marked by removing both mappings; the slot itself
stays in the graph until consolidation (§7) repairs the neighbourhoods. A search
MUST skip a slot with no document mapping — this is what makes deletes correct
immediately even though the graph is repaired later, which is the FreshDiskANN
property `nitrite-vector` already implements.

## 7. Consolidation and rebuild

- **Consolidation** removes deleted slots from neighbour lists and reclaims their
  region slots. It is a background sequence of ordinary commits and is
  interruptible.
- **`stale_from`** in the descriptor marks a graph known to be incomplete —
  set when a writer without the `VECTOR` feature mutated the collection
  (`11-conformance.md` §5), or when consolidation is pending.
- **Rebuild from the collection is always possible**, because the vectors also
  live in the documents as CVE `VECTOR` values. An implementation encountering a
  graph it cannot trust MUST be able to rebuild rather than fail. This mirrors
  what `nitrite-vector`'s HNSW backend does today when it detects torn state.

## 8. Search contract

An implementation MUST provide `search(query_vector, k, filter?) → [(NitriteId,
distance)]` with distances in the declared metric, ordered nearest first, and
MUST exclude slots with no live document.

**Recall is not specified.** Two conforming implementations may return different
neighbours for the same query; ANN is approximate by definition. What is
specified: the distances returned are the true distances to the documents
returned (an implementation using PQ codes for traversal MUST re-rank against
the full vectors before returning), and a document that does not exist is never
returned.

### 8.1 The metrics, numerically

§5's descriptor names `"cosine" | "l2" | "dot"` and this chapter said nothing
about what they compute. That is not a small gap. "Ordered nearest first"
requires a value where **smaller means closer**, and a dot product is a
*similarity* — larger means closer — so an implementation that returns it
unchanged sorts every result set backwards while satisfying every other sentence
here. The three reference implementations happened to agree; a fourth had no
written rule to agree with.

For vectors `a` and `b` of equal dimension:

| metric | distance | notes |
|---|---|---|
| `l2` | `sqrt(Σ (aᵢ − bᵢ)²)` | the Euclidean distance, **not** its square. The square orders identically and is cheaper, but §8 requires the *true* distance to be returned, and "true" for `l2` is this. |
| `dot` | `−Σ aᵢbᵢ` | negated, because the dot product is a similarity. The sign convention is the whole reason this section exists. |
| `cosine` | `1 − (Σ aᵢbᵢ) / (‖a‖ ‖b‖)` | the cosine *distance*, in `[0, 2]`. Not the similarity. |

Two edge cases, both MUST:

- **A zero vector has no direction**, so `cosine` against one is defined as
  **`1.0`** — the value an orthogonal pair takes — rather than a division by
  zero, a NaN or an error. An index may legitimately hold a zero vector, and a
  NaN propagating into a neighbour list corrupts the ordering silently.
- **Accumulation is in at least 64-bit floating point**, whatever the region's
  `dtype`. Summing 1536 `f32` products in `f32` loses several bits, so two
  implementations reading the same region and the same query return different
  distances for the same pair and order near-ties differently. The stored
  vectors keep their `dtype`; only the arithmetic widens.

Conformance vectors: `conformance/vectors/vector/metrics.json`.

An implementation MAY refuse to serve a graph built by a different algorithm
(`hnsw` vs `vamana`) — but it MUST then fall back to a brute-force scan of the
vector region, which is always possible and always correct, rather than
returning nothing. Brute force over a flat region is exactly the operation the
region layout is designed to make fast.

## 9. What a Level-0–3 implementation does

An SDK without vector support opens the file, lists the `vector_graph` tree as
opaque, reads and writes documents including their `VECTOR` fields, and follows
§5 of `11-conformance.md` when it mutates a collection that has one. It never
deletes the graph, and the graph's owner repairs it on next open.

That is the specific interchange scenario this whole format exists for: a
Flutter app editing a database whose vector index only the Rust service knows
how to maintain.
