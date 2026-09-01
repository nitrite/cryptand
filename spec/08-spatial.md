# CFF-08 — Spatial index

**Normative.** Conformance Level 3. Assumes `01-container.md`,
`02-value-encoding.md`.

Today the three SDKs have three different geometry representations and two
different R-trees: Java stores JTS geometry as **WKT text** and indexes it in an
MVStore `MVRTreeMap`; Rust has a `Geometry` enum
(`Point`/`Circle`/`Polygon`/`Envelope`) and its own paged `disk_rtree` in a
separate file; Dart has a third. This chapter replaces all of it with one
geometry encoding and one page format inside the container.

---

## 1. Geometry: WKB

A geometry value is CVE tag `0x24`:

```
0x24  uvar len  bytes(len)          -- ISO/OGC Well-Known Binary
```

WKB is chosen because it is the universal geometry interchange form: JTS reads
and writes it natively on the Java side (replacing the `WKTReader` round-trip
that currently costs a text parse per geometry), the `geo`/`wkb` crates cover
Rust, and Dart has several implementations.

Requirements:

- **ISO WKB, and only ISO WKB.** Little-endian byte order marker (`0x01`) — a
  writer MUST emit little-endian; a reader MUST accept both.
- Supported types: `Point`, `LineString`, `Polygon`, `MultiPoint`,
  `MultiLineString`, `MultiPolygon`, `GeometryCollection`.
- `Z`, `M` and `ZM` variants are permitted and are preserved on round trip, and
  they are encoded **the ISO way** — by adding 1000 (Z), 2000 (M) or 3000 (ZM)
  to the base geometry type code. The R-tree indexes the XY envelope only unless
  the index declares `dimensions > 2` (§3).
- **EWKB MUST NOT be written and MUST be rejected on read.** PostGIS's EWKB
  signals Z, M and an embedded SRID by setting high bits (`0x80000000`,
  `0x40000000`, `0x20000000`) of the same type word that ISO uses additively, so
  the two conventions are not distinguishable by a reader that accepts both — a
  `PointZ` is `1001` in ISO and `0x80000001` in EWKB, and a decoder that guesses
  wrong reads coordinates as garbage. A reader MUST reject a type word with any
  of those three bits set. (An earlier draft required ISO WKB and then permitted
  "the EWKB SRID flag", which is exactly the ambiguity this rules out.)
- **SRID is carried in the index descriptor, not in the geometry.**
  `params.srid` declares the one coordinate reference system a spatial index
  works in; a writer MUST reject a geometry whose application-declared SRID
  differs. The format does not reproject, and per-geometry SRIDs would mean an
  R-tree whose bounding boxes are in mixed units — boxes that compare but do not
  mean anything. An application needing several reference systems uses several
  indexes.

**`Circle` has no WKB representation and is not a stored geometry.** In Rust it
is a *query* shape, not data. Circles are expressed at query time as a centre
and radius and are evaluated against candidates from an envelope search; they
are never written to a document. An SDK that currently persists one MUST convert
it to a polygon approximation on migration, with the approximation's segment
count recorded so the conversion is reproducible.

## 2. The R-tree

An R-tree is a tree of `RTREE_INTERNAL` (page type 8) and `RTREE_LEAF` (page
type 9) pages in the same container, rooted from its catalog descriptor.

```
kind   = "rtree"
owner  = <data tree name>
params = {
    "index_type": "spatial",
    "data_tree":  U32,
    "field":      STR,
    "dimensions": U8,            -- 2 (default), 3, or 4; see §3
    "max_entries": U16,          -- node fanout, default derived from page_size
    "srid":       U32?           -- the index's coordinate reference system;
                                 --   absent means "unspecified, planar"
}
```

### 2.1 Page payload

After the 40-byte page header, both node types share:

| off | size | field |
|---|---|---|
| 0 | 2 | `entry_count` |
| 2 | 1 | `dimensions` |
| 3 | 1 | `flags` — bit0 `IS_LEAF` |
| 4 | 4 | reserved |
| 8 | 8 | `subtree_entries` |
| 16 | … | entries |

**Internal entry** (`16 × dimensions + 16` bytes):

```
f64  min[dimensions]
f64  max[dimensions]
u64  child_page
u64  child_subtree_entries
```

**Leaf entry** (`16 × dimensions + 8` bytes):

```
f64  min[dimensions]
f64  max[dimensions]
i64  nitrite_id
```

Fixed-width entries, no varints: a bounding-box comparison is the hot loop of
every spatial query, and a fixed stride lets an implementation scan a node
without decoding it. All `f64` are little-endian (`00-conventions.md` §3 —
R-tree keys are compared numerically in code, never by `memcmp`, so the CKE
big-endian rule does not apply here).

An empty bounding box (a geometry with no coordinates) is encoded as
`min = +Inf, max = -Inf` in every dimension and is never returned by a query.

### 2.2 Structure rules

- All leaves at the same depth.
- Every internal entry's box is the exact union of its child's boxes. A verifier
  checks this; a box that is merely a superset is a defect because it silently
  degrades every query.
- `max_entries` is a writer's choice; a reader MUST handle any node population
  from 1 to what the page holds.
- The split algorithm is **not** specified. R\*-tree, quadratic, linear and
  Hilbert-ordered bulk loading all produce valid trees. This is deliberate —
  split quality is exactly the kind of thing an implementation should be free to
  improve, and it does not affect correctness.

### 2.3 Insertion order and reproducibility

Because the split algorithm is free, two implementations inserting the same
documents will produce different (equally valid) trees. A conformance test
therefore compares **query results**, never tree shape.

## 3. Higher dimensions

The dimension order is fixed: **X, Y, Z, M**, in that order.

| `dimensions` | axes indexed | a geometry lacking an axis |
|---|---|---|
| 2 | X, Y | — |
| 3 | X, Y, **Z** | rejected at write time |
| 4 | X, Y, Z, **M** | rejected at write time |

`dimensions = 3` therefore always means Z, never M — an `XYM` geometry cannot go
into a 3-dimensional index, because silently indexing M in Z's slot would make
two geometries comparable that are not. Index M alone by declaring
`dimensions = 4` and supplying `ZM` geometries, or keep M out of the index and
filter on it above the format.

The entry stride grows with `dimensions`. A reader MUST use the page's own
`dimensions` field and MUST reject a page whose `dimensions` disagrees with the
descriptor.

## 4. Queries

The format supports, and an implementation MUST provide:

| query | evaluation |
|---|---|
| `intersects(g)` | descend on box intersection with `envelope(g)`, then exact WKB predicate on candidates |
| `within(g)` | descend on box intersection, then exact containment on candidates |
| `contains(g)` | descend on boxes containing `envelope(g)`, then exact predicate |
| `near(point, radius)` | descend on the point's box expanded by `radius`, then exact distance |
| `nearest_k(point, k)` | best-first search with a priority queue over node distances |

**The two-phase rule is normative**: the R-tree returns candidates by bounding
box; the exact predicate is evaluated on the geometry. An implementation MUST NOT
return box-level results as if they were exact. This is the difference between
Nitrite's spatial queries meaning the same thing in Java and in Rust.

Distance for `near`/`nearest_k` is planar Euclidean in the coordinate system of
the data by default. Geodesic distance (Nitrite's `GeoNearFilter` /
`GeodesicUtils` on the Java side) is an SDK-level query option; it changes which
candidate box to expand by, not the format.

## 5. Maintenance

Spatial index updates go in the same batch as the document write, so the index is
never durably out of step (`06-indexes.md` §8 applies identically).

An SDK without the `SPATIAL` feature bit that mutates a collection carrying a
spatial index follows `11-conformance.md` §5 — refuse, or repair-log and mark
`stale_from`. It MUST NOT drop the tree.

## 6. What this replaces

| today | in Cryptand |
|---|---|
| Java: WKT strings + `MVRTreeMap` | WKB + in-container R-tree |
| Rust: `Geometry` enum + separate `disk_rtree` file with its own header, cache, free list and V1→V3 migrations | WKB + in-container R-tree; the container already provides the header, checksums, free space and versioning |
| Dart: third representation | same |

The Rust `disk_rtree`'s design is good and much of it survives — page-based
nodes, an LRU cache, lazy loading, per-page checksums. What goes away is its
*private container*: the file header, the free list, the migration manager and
the integrity checker are all duplicates of things `01-container.md` already
specifies for every page in the database.
