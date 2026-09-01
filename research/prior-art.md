# Prior art

What the field already knows, and which parts Cryptand takes.

---

## 1. Cross-language file formats that worked

The question "is a byte-level contract implementable independently in many
languages" is settled. The evidence:

| Format | Independent implementations | What made it work |
|---|---|---|
| **SQLite** | The reference C library plus full independent readers/writers (e.g. `rusqlite` wraps C, but `sqlite3-parser`, `libsql`, and several pure-Go/pure-Java readers parse the file directly) | A short, complete, *frozen* file-format document; a `user_version`/`application_id` regime; and an enormous conformance corpus |
| **Parquet / Arrow** | C++, Java, Rust, Go, Python, JS, C# — all first-class writers | Thrift/flatbuffer-described metadata, explicit logical-vs-physical type mapping, explicit forward-compat rules |
| **Zstandard / LZ4** | Dozens | The frame format is specified separately from the codec, with test vectors |
| **LMDB** | C reference, plus readers in Go/Rust/Java that parse the file | Tiny, fixed, page-based format; copy-on-write means there is no log to replay |

Common denominators, all of which Cryptand adopts:

- The format document is normative and separate from any implementation.
- There is a **reference implementation** plus **golden test vectors**, and
  conformance means passing the vectors, not matching the reference's source.
- **Forward compatibility is designed, not hoped for**: an explicit split
  between "features a reader may ignore" and "features a reader must refuse".
- Nothing in the format depends on host-language types, comparators, or
  allocators.

The corollary is the warning: the formats that *failed* to travel are the ones
that embedded a language's serializer (Java serialization, .NET
`BinaryFormatter`, Python pickle) or a language's collation. Nitrite is in
exactly that trap today.

## 2. The four engines Cryptand has to beat

### MVStore (H2)

Copy-on-write B-tree. 4096-byte blocks; two file headers for safety; data in
**chunks**, each a chunk header plus a run of pages written together; the file
header points at the latest chunk; pages in later chunks reference pages in
earlier ones. Never updates in place.

**Take:** two-header safety, copy-on-write, chunked sequential writing.

**Avoid:** the chunk garbage collector. Because a chunk is only free when *every*
page in it is dead, reclaiming space requires rewriting the still-live pages out
of partially-dead chunks. The published critique is exactly this — a
copy-on-write B+tree in a chunk-based container has poor capacity efficiency due
to write amplification and non-reclaimable partial garbage inside chunks.
Cryptand keeps free space in a **free-extent tree keyed by commit id** instead, so
dead space is reclaimable without touching live pages.

**Avoid:** `ObjectDataType`'s serialization fallback (see the survey).

### RocksDB

Leveled LSM. The reference point for write-heavy throughput and for
industrial-strength compaction, bloom filters, column families and WAL.

**Take:** per-level bloom filters, block-based SST layout with a sparse block
index, and the discipline of a manifest that makes recovery O(1) in the data
size.

**Avoid:** the cost model. Write amplification on a leveled LSM is routinely
10–30x. Memory is the block cache *plus* memtables *plus* resident index and
filter blocks, and on the JVM all of it is off-heap and outside the JVM's
control. Every operation from Java is a JNI crossing. For an embedded document
database on a phone this is the wrong shape.

### Hive (Dart)

Append-only log, in-memory key index, hand-written type adapters.

**Take:** nothing structural. The one lesson is the failure mode: *append-only
without automatic compaction is a space leak*, and *keys in RAM is a memory leak
proportional to the dataset*. Both are documented Hive behaviours — files grow
indefinitely until a manual `box.compact()`, and opening a box (even a lazy one)
reads every key into memory.

**Avoid:** encoding keys in a way that destroys their order (base64 of a
little-endian frame). That single choice removes disk-ordered range scans from
the entire Flutter SDK.

### Fjall

LSM in safe Rust with MVCC snapshot isolation, LZ4, configurable durability,
optimistic and single-writer transaction modes, and — the important one — **key
value separation**: large values are moved into a value log so the tree carries
only keys and pointers. Write amplification lands around 2–3x (WAL, flush,
L1→L2) rather than the 10–30x of a deeply leveled LSM. Partitions are separate
LSM-trees but share one journal, so cross-partition writes are atomic.

**Take:** key–value separation (pushed further, §3); one atomic unit spanning all
partitions so a multi-map write cannot tear; MVCC snapshot isolation.

**Avoid:** the journal — it writes every value a second time and is the single
append stream every writer must serialize on. And avoid the concurrency model
`nitrite-rust` actually uses: `SingleWriterTxDatabase` is exactly one writer.

**Avoid, for this workload:** the read side. A point lookup probes every level's
filter; a range scan is an N-way merge; a reverse scan is worse; and tombstones
survive until a compaction reaches them.

## 3. The structures Cryptand chooses between

### Copy-on-write B+tree (LMDB, redb, MVStore, btrfs)

Writes copy every page from the leaf to the root, then flip a root pointer.

- **Wins:** no WAL needed for tree integrity; recovery is reading a header;
  snapshots are free (an old root is a valid tree); readers never block; no
  torn-page problem, because live data is never overwritten.
- **Loses:** write amplification of *h* pages (tree height, ~3–4) per *commit*.
  Devastating if you commit per key; harmless if you commit per batch.
- redb's summary is the design in one line: "data stored in a collection of
  copy-on-write B-trees" — portable, ACID, pure-Rust, no WAL.

### LSM (RocksDB, Fjall, LevelDB)

Buffer in memory, flush sorted runs, compact in the background.

- **Wins:** sequential writes; write amplification independent of tree height;
  excellent bulk load.
- **Loses:** read amplification across levels; merge-iterator scans; space
  amplification from overlapping levels and tombstones; recovery replays a log.

### Bε-tree (TokuDB, BetrFS)

A B-tree whose internal nodes carry message buffers; updates are inserted at the
root and flushed down in batches.

- **Wins:** asymptotically LSM-class insert cost *and* B-tree-class range scans.
  This is genuinely the structure that has both.
- **Loses:** it is hard. Node splitting with buffered messages, flushing policy,
  and the ε tuning knob are all subtle, and the failure modes are subtle too.
  Specifying it precisely enough for three independent implementations to agree
  byte-for-byte is a much larger risk than the performance it buys.

### Key–value separation (WiscKey, Titan, BlobDB, Fjall)

Store only keys and a fixed-size pointer in the LSM-tree; put values in a
separate append-only value log.

- **Wins:** compaction rewrites keys and pointers instead of records, so write
  amplification drops by the key-to-record ratio. The tree also shrinks, which
  reduces read amplification and helps point lookups.
- **Loses:** a value read is an extra indirection, range scans lose value
  locality, and the value log needs garbage collection — WiscKey's GC scans the
  log, re-queries the tree to test each entry's validity, and rewrites the
  survivors. GC is the new amplification, and it is where designs differ.
- **The known refinement:** lifetime-aware GC. Grouping values by expected
  lifetime makes a segment become garbage all at once, so GC rewrites very
  little to reclaim a lot. DumpKV takes this to a learned lifetime predictor;
  the cheap version is a small set of heat classes.

**Take:** all of it, with two departures.

1. **The threshold is per device, not universal.** Separation buys write
   amplification, which is a server problem; the extra random read it costs is a
   phone problem. `spec/12-profiles.md` sets `vlog_min` from 256 B on a server
   to 4096 B on a phone, where documents stay inline and a point read is one
   I/O. Every published design picks one threshold; picking four is strictly
   better and costs nothing, because `value_kind` is per cell.
2. **Two tiers, and clustering comes free.** The literature treats scan locality
   as a GC problem — Scavenger+ and its relatives reorganise the log in a
   background pass. Cryptand instead promotes surviving values into a cold tier
   **during last-level compaction, which already walks keys in sorted order**
   (`spec/04-segments.md` §6.3). The sort has already been paid for; appending
   values as the merge passes over them makes the cold log key-clustered by
   construction. Locality stops being a background chore and becomes a property
   of the write path — and the format then bounds what is left over with a
   measurable `locality_debt` MUST rather than a hopeful SHOULD.

Heat classes are in the format; the classifier is the implementation's.

### Lazy levelling (Dostoevsky, Dayan & Idreos, SIGMOD 2018)

The observation: merges at every level except the largest buy almost nothing.
They reduce point-lookup cost, long-range-lookup cost and space by a negligible
amount, while dominating the amortized cost of updates. So: **tier every level
except the largest, and level only the largest.**

- **Wins:** update cost close to tiering, with point-lookup, long-range-lookup
  and space bounds close to levelling — because the largest level holds most of
  the data and most of the read cost.
- **Loses:** short-range scans still merge one run per tiered level, and there
  are more runs to probe than in pure levelling (mitigated by filters).

**Take:** the policy, but not as a format requirement. `spec/04-segments.md` §3
records only a segment's level, key range and seq range. Which levels are tiered
and which are levelled is an implementation choice, so a better policy ships
without breaking a single existing file.

### WAL-time separation (BVLSM and relatives)

If a value is already being written durably to the journal, writing it *again*
to the value log at flush time is pure waste. Recent work makes the WAL write
the value's final home.

**Take:** the idea, pushed all the way. Cryptand has **no journal at all**: the
value-log record and the L0 segment entry *are* the durability records, so a
value is written exactly once and a key exactly once before it is queryable.
Recovery is reading a superblock, not replaying a log.

### The choice

Cryptand is the composition of the four above, with copy-on-write kept for the
small internal trees:

```
sharded memtables
   │ values ≥ vlog_min → append-only value log (heat-grouped, liveness-GC'd)
   │ keys+pointers → bulk-built immutable segments
   ▼
L0 overlapping → L1…Ln-1 TIERED → Ln LEVELLED, DISJOINT

catalog / manifest / free space / attributes: copy-on-write B+trees
```

Every piece of it is either immutable or copy-on-write, which is what makes it
specifiable byte-for-byte for three independent implementations — the property
that actually decides this project. There is no in-place page update, no split
algorithm and no rebalancing anywhere in the format.

What this composition gives that the individual pieces do not:

- **No central append stream.** Removing the WAL removes the one file every
  writer must serialize on, so *N* writers drive *N* independent streams.
- **Bounded read cost despite tiering.** A disjoint last level contributes
  exactly one candidate segment, and the tiered levels above it are small.
- **O(1) recovery**, from copy-on-write plus the superblock flip, without the
  copy-on-write write amplification — because the big trees are never updated in
  place at all.

## 4. Encoding prior art

**Order-preserving key encodings.** FoundationDB's tuple layer, CockroachDB's
`encoding` package, and — locally — `nitrite-rust`'s
`nitrite-fjall-adapter/src/ordered_key.rs` all solve the same problem: make
`memcmp` agree with logical order. The shared techniques Cryptand adopts:
type-group tag bytes, big-endian fixed-width numerics with the sign bit flipped,
the monotone float bit transform (flip the sign bit for positives, flip all bits
for negatives), `0x00 → 0x00 0x01` escaping with a `0x00 0x00` terminator so
`"ab" < "abc"`, and element framing where the terminator sorts below the
continuation byte so a shorter tuple sorts first.

The one place Cryptand departs from `ordered_key.rs`: that codec orders numbers
by an f64 *magnitude* prefix and breaks ties by class and exact value, so
ordering is not numerically monotonic above 2⁵³. Cryptand instead normalizes
every integer and float into a shared `(sign, binary exponent, normalized
mantissa)` form using only count-leading-zeros and shifts — exact numeric order
over the whole i128/u128/f64 domain, still with no bignum arithmetic.
(`spec/03-key-encoding.md` §4.)

**Self-describing value encodings.** BSON, CBOR, MessagePack, Ion. All of them
require a linear scan to reach field *n*. Cryptand's CVE instead writes a sorted
`(name_id, offset)` table at the head of every document, so a field read is a
binary search and a slice — no allocation, no decode of unread fields.

**Dictionary-encoded field names.** Parquet, Arrow and Cap'n Proto all separate
schema from data. Nitrite's largest single space waste is repeating
`"firstName"` in every document. A per-tree, append-only name dictionary removes
it, and costs one small cached tree.

**Preserve-unknown round-tripping.** Protobuf's unknown-field retention and
Thrift's equivalent are the model: a reader that does not understand a field
must carry its bytes through a read-modify-write unchanged. Without this rule, a
Dart write to a Java-authored document silently destroys data. Cryptand makes it
a MUST (`spec/11-conformance.md` §4).

**Geometry.** WKB (ISO/OGC well-known binary) is the universal geometry
interchange encoding — JTS reads and writes it natively on the Java side, `geo`
and `wkb` crates on Rust, several packages on Dart. It replaces Java's WKT
strings and Rust's ad-hoc `Geometry` enum with one binary form.

**Vector indexes.** HNSW (Malkov–Yashunin) is a layered proximity graph; DiskANN
/ Vamana is a flat graph with PQ codes resident and full vectors on disk with
exact re-ranking, plus FreshDiskANN-style delete consolidation. `nitrite-vector`
already implements both. Neither is hard to make portable, because the durable
part of each is just *a flat vector region plus an adjacency list per node* —
Cryptand specifies that layout and leaves the search algorithm to the
implementation.

**Full-text postings.** Lucene and Tantivy both use a term dictionary plus
block-compressed postings with skip data. The portable subset is: term
dictionary as a sorted tree, postings as delta-varint blocks of bounded length
keyed by `(term_id, first_doc_id)`. What is *not* portable, and what has to be
specified rather than delegated, is the analyzer — see `spec/07-fulltext.md` §2.

## 5. Things deliberately not taken

| | Why not |
|---|---|
| Bε-tree buffered nodes | The best asymptotics available, and too subtle to specify for three independent implementations. Key–value separation plus lazy levelling reaches a similar place with structures that are trivially specifiable. Revisit only if measurement says otherwise. |
| Learned indexes / perfect hashing | Read-optimized, immutable-leaning, and a research risk in a format that must be frozen. |
| mmap as a *requirement* | Dart has no mmap. Cryptand's structures are all positional-read-able; mmap is an optimization an implementation may take, never an assumption the format makes. |
| Multi-**process** writing in v1 | Multi-*threaded* writing is a Level-0 requirement (`spec/11-conformance.md` §1.1). Multi-process adds lock tables and cross-process coordination to the format for a case embedded Nitrite does not have; reserved as `MULTIPROC`. |
| A write-ahead log | The value-log record and the L0 segment already are durability records. A journal would write every value a second time and would reintroduce the single append stream that limits write concurrency. |
| A learned lifetime predictor for value-log GC | DumpKV shows it works; a fixed set of heat classes captures most of the benefit with none of the model. The format records the class, so a predictor can be added later without a format change. |
| Circular value log (WiscKey's original) | A circular log couples GC to insertion order. Independent sealed segments with per-segment liveness let GC pick victims freely, which is what makes heat grouping pay. |
| A background log-reorganisation pass for scan locality | The standard answer, and a weak one — it is optional, it is easy to skip, and its absence shows up months later. Clustered promotion does the same work inside a compaction that was going to sort the keys anyway. |
| One tuning configuration for all devices | Every engine in §2 ships one shape. A phone and a server disagree by an order of magnitude on what a random read costs and by three on how much is written; one configuration cannot be right for both. Profiles are advisory metadata, so this costs the format nothing. |
| Sibling pointers in leaves | In a copy-on-write tree, updating a leaf forces copying its sibling to fix the pointer. Cursors carry a path stack instead — which is also what fixes Nitrite's re-descent problem. |

---

## Sources

- [Announcing Fjall 2.0](https://fjall-rs.github.io/post/fjall-2/)
- [Announcing Fjall 2.3](https://fjall-rs.github.io/post/fjall-2-3/)
- [fjall — docs.rs](https://docs.rs/brk_fjall/latest/fjall/)
- [H2 MVStore documentation](https://github.com/h2database/h2database/blob/master/h2/src/docsrc/html/mvstore.html)
- [Closing the B-tree vs. LSM-tree Write Amplification Gap on Modern Storage Hardware with Built-in Transparent Compression](https://arxiv.org/pdf/2107.13987)
- [redb — an embedded key-value database in pure Rust](https://github.com/cberner/redb)
- [SQLite (overview)](https://en.wikipedia.org/wiki/SQLite)
- [Embedded Databases in 2026: DuckDB, SQLite, Polars, and chDB](https://kestra.io/blogs/embedded-databases)
- [Hive — lightweight and blazing fast key-value database in pure Dart](https://github.com/isar/hive)
- [What Is Hive in Flutter: How to Use It, Alternatives, Mistakes](https://leancode.co/glossary/hive-in-flutter)
- [Dostoevsky: Better Space-Time Trade-Offs for LSM-Tree Based Key-Value Stores via Adaptive Removal of Superfluous Merging (Dayan & Idreos, SIGMOD 2018)](https://stratos.seas.harvard.edu/publications/dostoevsky-better-space-time-trade-offs-lsm-tree-based-key-value-stores)
- [WiscKey: Separating Keys from Values in SSD-Conscious Storage (summary)](https://codito.in/paper-wisckey-separating-keys-values/)
- [Key-Value Separation in LSM Storage Engines](https://www.skyzh.dev/blog/2023-12-31-lsm-kv-separation-overview/)
- [DumpKV: Learning based lifetime aware garbage collection for key value separation in LSM-tree](https://arxiv.org/pdf/2406.01250)
- [BVLSM: Write-Efficient LSM-Tree Storage via WAL-Time Key-Value Separation](https://arxiv.org/pdf/2506.04678)
- [Scavenger+: Revisiting Space-Time Tradeoffs in Key-Value Separated LSM-trees](https://arxiv.org/pdf/2508.13935)
- [LSM-based Storage Techniques: A Survey](https://arxiv.org/pdf/1812.07527)
