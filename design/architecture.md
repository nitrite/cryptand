# Cryptand — engine architecture

Non-normative. The binding contract is `spec/`. This document explains *why* the
format looks the way it does, and how an implementation is expected to run.

---

## 1. One picture

```
   many application threads, no shared lock on the write path
        │            │            │            │
        ▼            ▼            ▼            ▼
   ┌──────────────────────────────────────────────────┐
   │  memtable shard 0 … shard S-1   (sharded, concurrent)          │
   └──────────────────────────────────────────────────┘
        │                                    │
        │ keys + 16-byte pointers            │ values ≥ vlog_min, written ONCE,
        │                                    │ straight to the device
        ▼ flush: bulk-build a segment        ▼
   L0  [seg][seg][seg][seg]  overlapping   ┌────────────────────────┐
   ───────────────────────────────────     │  VALUE LOG             │
   L1  [seg]…[seg]           TIERED        │  append-only segments  │
   L2  [seg]…[seg]           TIERED        │  grouped by heat class │
   …                                       │  GC'd by liveness      │
   Lmax [seg][seg][seg][seg] LEVELLED,     └────────────────────────┘
                             DISJOINT               ▲
                                                    └── compaction NEVER
                                                        rewrites a value

   internal trees (catalog, manifest, free space, attributes, vlog stats):
   plain copy-on-write B+trees, rooted from the superblock. Small and hot.

   Two superblocks at the front, written alternately. The newest valid one
   is the database. That is the entire recovery procedure.
```

## 2. The seven decisions

### 2.0 One engine, four profiles

The right storage engine for a phone is not the right one for a server, and
pretending otherwise is how embedded databases end up bad at both. A **profile**
(`spec/12-profiles.md`) is a named set of tuning constants recorded in the
superblock. It changes how a writer behaves and **nothing** about how a file is
read — every constant is its own superblock field, so a reader uses values, never
the profile name.

| | `mobile` | `tablet` | `desktop` | `server` |
|---|---|---|---|---|
| `page_size` | 4 KiB | 4 KiB | 8 KiB | 16 KiB |
| `vlog_min` (≤ `page_size`/4) | **1024** | 1024 | 256 | 256 |
| memtable shards | 1 | 2 | 8 | 32 |
| `overlap_bound` | 1 | 2 | 2 | 3 |
| compaction | idle / charging only | idle-preferred | continuous, paced | continuous, paced |
| foreground stall budget | **8 ms** | 8 ms | 25 ms | 100 ms |

The `mobile` choice is the interesting one. Key–value separation buys write
amplification, and write amplification is a server problem: a phone-scale
database writes single-digit megabytes a day. Spending an extra 400 µs of UFS
random read on every document fetch to save traffic nobody notices is the wrong
trade, so on `mobile` `vlog_min` sits at its ceiling — a quarter page, 1024 B at
4 KiB pages — documents stay **inline**, and a point read is one I/O.

A file moves between profiles by ordinary compaction — a Flutter app writes a
`mobile` database, a desktop tool calls `set_profile(desktop)`, and it
reorganises itself for the machine it is now on. No export, no import, no moment
where the data is unreadable.

### 2.1 Values are written once and never re-merged

Every value at or above `vlog_min` goes straight into an append-only **value
log** and the tree stores a 16-byte pointer; compaction merges keys and pointers
only. `vlog_min` is 256 B on `desktop` and `server`, and 1024 B — the largest a
leaf cell can hold at a 4 KiB page — on `mobile` and `tablet`, where the point of
the setting is the opposite one: keep documents *in* the tree so a point read is
one I/O (§2.0).

This is the largest lever on sustained random-write cost, and it is worth being
precise about why. For a 500-byte document, the merged footprint is ~24 bytes of
key and pointer against 524 bytes of logical record — **4.6 %**. Whatever write
amplification the sorted structure has, the value does not pay it. A leveled LSM
that merges values at amplification 20 writes 10 KB to store that document; here
the value is written once, and the key index pays 20 × 24 B = 480 B.

Fjall separates values too, but *above a threshold*, which is tuned for large
blobs. On `desktop` and `server` Cryptand separates far more aggressively —
almost every document — because the point is not to keep big values out of the
tree, it is to keep the merged bytes proportional to the **key** size rather than
the record size. On `mobile` it deliberately does the opposite; §2.0 is where
that argument is made, and the point of putting `vlog_min` in the superblock is
that the same format serves both.

The bill comes due as scan locality and garbage collection, which is what §2.4
is about.

### 2.2 There is no write-ahead log

The value-log record *is* the durability record for the value. The L0 segment
entry *is* the durability record for the key. Both are written once, in their
final location, and are queryable the moment the superblock names them.

Every conventional LSM writes each record twice before it has done any useful
work — once to the journal, once on memtable flush. Fjall's own accounting is
that an item is written three times (WAL, flush, L1→L2). Removing the journal
removes a full 1× of the *logical record size*, which for document workloads is
the dominant term. It also removes the single sequential file that every writer
must serialize on — see §2.5.

Recovery is not log replay. It is: read two superblocks, take the newer valid
one. O(1) in database size.

### 2.3 Lazy levelling

| level | policy | why |
|---|---|---|
| L0 | overlapping | one segment per memtable-shard flush; no merge work at all |
| L1 … Lmax−1 | **tiered** | write amplification proportional to the *number of levels*, not to the fanout |
| Lmax | **levelled, disjoint** | ~90 % of the data lives here; levelling recovers bounded space amplification and a scan that touches one segment per level |

Pure levelling costs ≈ `fanout × levels` in write amplification. Pure tiering
costs ≈ `levels` but wrecks point lookups, scans and space. Lazy levelling —
tiering everywhere except the biggest level — takes tiering's write cost and
levelling's read and space cost, because the biggest level is where both the data
and the read cost actually are.

With `fanout = 8` and four levels: **key-index write amplification ≈ 12**, against
a leveled LSM's 30–40. Multiply by the 4.6 % key ratio from §2.1 and it
contributes ≈ **0.55×** of the logical data. That number is the whole argument.

### 2.4 Two value-log tiers, and clustering for free

Key–value separation has one serious weakness: **scan locality**. Values
adjacent in key order end up scattered on disk, and a full scan degrades as data
ages — silently, over months. Making a background pass "SHOULD re-sort them" is
a weak answer to that.

The value log is therefore built in two tiers:

| tier | written by | ordered by | liveness |
|---|---|---|---|
| **HOT** | the write path, grouped by heat class | insertion | low — most records die or are promoted |
| **COLD** | last-level compaction, bulk writers, cold GC | **key** | high |

**Promotion happens during last-level compaction, which already walks keys in
sorted order.** Appending each surviving value as the merge passes over it
therefore produces a key-clustered cold log **by construction, at no extra
cost** — the sort had to happen anyway. Since the last level holds most of the
data, most scanned bytes are clustered and a scan's value reads are sequential.

Three things make it enforceable rather than hopeful: promotion is a MUST;
`locality_debt` — live bytes in unclustered segments — is a **bounded** MUST
(20 %); and cursors MUST read ahead in pointer order. An aged-scan conformance
test enforces all three.

GC gets cheaper as a side effect. Hot segments die almost entirely and are cheap
to reclaim; cold segments run at high liveness and rarely need collecting at
all. Total value-side cost works out slightly *below* a single mixed log — and
clustered.

### 2.5 Writers do not share an append stream

This is the write-concurrency answer, and it is structural rather than a tuning
knob.

A conventional LSM funnels every writer through one WAL file. Writers contend on
that file's offset and on the group-commit leader, so throughput plateaus a few
threads in and a single append stream cannot saturate a modern NVMe device.

Cryptand has no WAL, so there is nothing central to funnel through:

| shared thing | cost |
|---|---|
| `next_seq` | one `fetch_add`, ~20 ns even at 64 threads |
| the writer's *own* value-log segment tail | one `fetch_add`; different writers, different segments, zero sharing |
| memtable shard | independent per shard, chosen by key hash |
| manifest publish | a microsecond-scale critical section, once per flush or compaction — not per write |

*N* writers therefore drive *N* independent append streams into the device.
Atomicity does not suffer: a batch becomes visible when `visible_seq` in the
superblock passes its sequence range, and the committer advances that watermark
only when every byte of the batch — across every value-log segment and every
memtable shard it touched — is durable. There is no commit record and no
two-phase protocol. The watermark *is* the commit.

Compaction is likewise parallel: jobs on disjoint key ranges run concurrently,
because segments are immutable and outputs are new extents.

### 2.6 Immutability everywhere

Segments are built bottom-up from a sorted stream and written with one sequential
I/O. There is no insertion path into a segment, no split algorithm, no
rebalancing, and no in-place page update anywhere in the format.

Consequences that all fall out of that one property:

- **No page latches.** A reader holding a segment never coordinates with anyone.
- **Free MVCC snapshots.** Every record carries a seq; a snapshot is a number.
- **No torn pages, at any durability setting.** Nothing live is overwritten, so
  the worst a crash can do is lose recent batches — never produce an unopenable
  file.
- **Every device write is sequential**, which is what both flash and the OS
  page cache want.

### 2.7 Nothing blocks a frame

On Flutter the database usually shares an isolate with the UI, so a 16 ms frame
budget is a storage-engine requirement, not an application concern. Every long
operation in the format decomposes into bounded, abandonable steps — because
every long operation writes immutable output, and a partial output is just a
prefix nobody can see.

`max_foreground_stall_ms` (8 ms on `mobile`) binds compaction steps, GC passes,
clustering, `compact()` and segment builds. Backpressure follows a specified
quadratic curve rather than a cliff, compaction I/O is paced against the
foreground write rate, and the host can say `idle`, `charging` or
`thermal_pressure` so that the largest discretionary consumer of battery in an
embedded database is not spent while the user is scrolling.

### 2.8 Security is in the file, not around it

An embedded database's attacker holds the *file*. So the format encrypts and
authenticates every page payload and every value-log record under
XChaCha20-Poly1305, and leaves every **header** in the clear — which is the
whole design in one sentence, because it means `cryptand verify`, repair,
corruption containment and incremental backup all run on an encrypted database
**with no key**. The price is metadata: an attacker learns how many pages each
collection holds and when each changed, never what they contain
(`spec/14-security.md` §7).

Three choices are worth naming, because each one is a common design that this
one deliberately is not:

- **A random master key, wrapped.** The password derives a key-encryption key
  that unwraps 32 random bytes; it never encrypts data itself. Changing a
  password is one superblock write instead of re-encrypting the database, several
  unlock paths (password, keychain, hardware key) can coexist, and destroying
  the keyslots is a **real** erase — which matters because on flash, overwriting
  a block is a story the controller tells you.
- **An authenticated superblock.** It is in the clear so recovery works without
  a key, which also means an attacker can edit it: set `cipher = 0` so the next
  writer stores plaintext, or drop Argon2id's cost so a captured file falls to
  brute force. A keyed MAC over the superblock closes both. It cannot close
  rollback to a genuine older copy of the same file — nothing inside one file
  can — so that is stated as out of scope with the external mitigation that
  works.
- **Nonces from a counter with a published floor.** A stream cipher that reuses
  a nonce discloses both plaintexts and its authentication key, and no checksum
  or tag catches it. Deriving the nonce from `(page_id, commit_id)` looks safe
  under copy-on-write and is not: a crashed commit's `commit_id` is reused by
  the next attempt, which rewrites the same pages with different content. A
  counter that may not cross a durably published floor makes reuse impossible by
  construction, at one extra superblock write per million pages.

And the part that applies with encryption **off**: no host-language deserializer
is ever handed file bytes. MVStore falls through to Java object serialization
for `Document` and `NitriteId`, and `readObject` on untrusted input is a
remote-code-execution primitive. CVE is a tagged encoding with a fixed type set
and no constructor dispatch, so opening a hostile file cannot instantiate a
class. For a format whose entire purpose is opening files other people wrote,
that is the largest security property in the design, and it costs nothing.

## 3. The read path

```
get(tree, key, snapshot_seq):
  prune by key range from the manifest        -- no I/O; a levelled level
                                              --   contributes ≤ 1 candidate
  probe each candidate's filter               -- ~0.33 % survive above the last
                                              --   level, ~1.7 % at it
  descend each survivor's B+tree, newest first
  first live version with seq ≤ snapshot_seq wins
  resolve the value: inline, or one read from the value log
```

Two prunes carry it. Key-range pruning from the manifest removes most segments
with no I/O at all; the filter removes almost all of the rest.

Reads are where key–value separation costs something: a value read is one extra
positional read. Three things pay it back:

- The **key index is tiny** — 4.6 % of the data. A database whose full working
  set would never fit in cache has a *key index* that often does, so the descent
  is usually pure CPU.
- **Key-only reads never touch the value log at all.** Index scans, counts,
  existence checks and covering queries are entirely served from the key index.
  Nitrite does a great deal of exactly this.
- **Projections decode one field, not the document.** The value encoding carries
  a sorted `(name_id, offset)` table, so `doc["price"]` is a binary search and a
  slice — not a deserialization. On a 20-field document where a query needs two
  fields, that is ~10× less decode work than Java serialization, Kryo, Hive
  adapters or bincode, and it applies to every row of every scan.

**Scans use cursors** — a merge heap over one iterator per candidate segment,
each with its own path stack. Because the last level is disjoint, a cold-data
scan merges one segment per level plus L0: a small bounded heap, not an
unbounded N-way merge. Advancing is a pointer bump inside a leaf and a heap
step across segments; there is **no re-descent from the root per row**, which is
precisely the defect that still caps `nitrite-rust`'s paged scan at 40.4×
(`research/nitrite-survey.md` §7).

`skip(n)` uses per-page subtree entry counts to descend past whole subtrees, so
paging is O(log n) rather than O(offset).

## 4. Field names are stored once per tree

A per-tree, append-only name dictionary maps `name_id → "customerAddressLine1"`,
so a document stores varints instead of repeated text. On the assumed 20-field
document that is ~240 bytes of repeated names replaced by ~40 bytes of ids — the
single largest space win available on Nitrite's data, and it costs one small
cached tree.

## 5. Everything is in one file

Data, indexes, catalog, attributes, free space, the manifest, value-log stats,
term dictionaries, postings, R-tree nodes, HNSW adjacency and vector regions are
all trees, segments and extents inside one container, addressed by numeric tree
id.

- A Java reader sees a vector index a Rust writer built — there is no external
  Tantivy directory or private `.rtree` file.
- A multi-tree write is naturally atomic: one batch, one sequence range, one
  watermark. Today only Fjall gives Nitrite that.
- Map names stop being filenames or partition names, so per-engine mangling
  (`|` → `_P_`, base64, …) disappears.

## 6. Memory

| | bounded by |
|---|---|
| page cache | profile budget: 4 MiB mobile, 16 MiB tablet, 64 MiB desktop, 512 MiB server |
| memtables | configured budget; exceeding it triggers a flush, then backpressure |
| segment filters | demand-loaded — a blocked-Bloom probe reads one 64-byte block, so none need be resident |
| value-log write buffers | **none** — writers reserve a byte range and `pwrite` directly, so open segments are bounded by heat class, not by writer count |
| manifest | one small tree, fully cached |
| name dictionaries | per open tree, small |
| cursors | O(levels × height) per cursor |

Nothing scales with the number of keys in the database. That is the structural
win over Hive, which holds every key of every open box in RAM, and over RocksDB,
whose block cache plus memtables plus resident index and filter blocks are large
and, from Java, entirely outside the JVM's control.

## 7. Durability

Four modes (`none` / `os` / `sync` / `full`), with platform specifics made
normative in `spec/10-transactions.md` §7 because getting them wrong is silent.
The one that bites on mobile: on macOS and iOS, `fsync(2)` does **not** flush the
drive write cache — `fcntl(F_FULLFSYNC)` does — and a pure-Dart implementation
cannot reach it without FFI, so it must report `sync` as its ceiling rather than
claim `full`.

Because everything is append-only and copy-on-write, no durability mode can
corrupt structure. At `none` the worst outcome is losing recent batches, never
an unopenable file.

## 8. Where the CPU goes

Removed relative to today: Java object serialization, Kryo, Hive `TypeAdapter`
dispatch, bincode round-trips, JNI crossings, base64 of every key, and the
in-memory re-sorting that Hive's unordered keys force on the Dart SDK.

Added: CRC-32C per page (hardware-accelerated everywhere, and
`java.util.zip.CRC32C` on the JVM), LZ4 on compressed pages, XXH3-64 for filter
probes, and key encoding per operation — cheap integer work that replaces the
comparator calls it displaces.

## 9. Extension points, all inside the container

| | how |
|---|---|
| Secondary indexes | ordinary levelled trees; keys are `CKE(Array[values…, id])`, values `EMPTY`, so they never touch the value log |
| Full text | term dictionary tree + block-postings tree |
| Spatial | R-tree pages + WKB geometry in the document |
| Vector | contiguous page-aligned flat region + adjacency tree; PQ codebook blob |
| Future index types | new page types behind a feature bit; a reader lacking the bit refuses to write the collection, or records a repair-log entry (`spec/11-conformance.md` §5) |
| Future *structures* | the level policy is not in the format (`spec/11-conformance.md` §1.3) — a better compaction picker, a different fanout, buffered internal nodes, all ship without touching a single existing file |
| TTL | per-entry expiry, evaluated at read so it is exact, reclaimed at compaction |
| Change feed | a per-tree opt-in log keyed by `(tree_id, seq)`, appended in the same batch as the mutation |
| Checkpoints, backup | named retained snapshots; incremental backup is a set difference over segment ids |
| Planner statistics | cardinality, histograms and a HyperLogLog distinct estimate, computed free during last-level compaction |

## 10. What this design does not do

Stated here so it is not discovered later.

- **Not distributed.** No replication protocol. Nitrite's replication sits above
  the engine, as it does now.
- **Not an access-control system.** One file, one key, all or nothing. There is
  no per-collection key and no in-file authorization; separate trust domains use
  separate files (`spec/14-security.md` §10).
- **Encryption costs a zero-copy read and a fast filter probe.** An encrypted
  vector region cannot be `mmap`ed and sliced, and a Bloom probe must decrypt a
  whole page to read one 64-byte block. Both are stated in
  `spec/14-security.md` §12 rather than averaged away.
- **Not multi-process in 1.0.** One writing process; unlimited threads inside it.
  `MULTIPROC` is a reserved feature bit.
- **Reads pay one indirection for separated values.** A cold whole-document read
  is ~2 I/Os where an inline-value engine does 1 — on `desktop` and `server`.
  The `mobile` and `tablet` profiles inline documents and pay 1.
- **Scans returning documents depend on value-log locality.** Clustered
  promotion makes that structural rather than scheduled, and a bounded
  `locality_debt` plus a mandatory aged-scan test enforce it — but an
  implementation that ignores all three still ships a database whose scans decay
  with age.
- **Space amplification is higher than a pure B+tree**, bounded at ~1.5× by the
  value-log target.
- **Tail latency is worse on write**: compaction exists. It is paced, bounded by
  a specified backpressure curve and capped by a foreground stall budget, but a
  copy-on-write B+tree has gentler tails and always will.

- **A frozen format constrains future optimization.** Feature bits and the
  policy-free level model are how that price is kept bounded.

The complete accounting — every property the write-path design touched, and the
mis-specifications that writing it down uncovered — is
`design/tradeoff-analysis.md` §8.
