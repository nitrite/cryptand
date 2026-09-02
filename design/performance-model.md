# Performance model

**Every number in this document is a prediction derived from the format's
structure. None of it is measured.** Nothing is implemented yet. Each section
ends with the measurement that would confirm or refute it, and §8 is the
benchmark plan that produces those measurements.

The one thing here that *is* measured is the existing-Nitrite baseline in
`research/nitrite-survey.md` §7.

---

## 1. Parameters

Assumed throughout, all from the spec's defaults.

The `desktop` profile unless stated; `12-profiles.md` gives the others, and
§10 covers how the numbers change on `mobile`.

| | |
|---|---|
| page size | 8192 B; payload 8160 B. §2's leaf arithmetic is quoted at 4096 B so it can be read against the `mobile` profile too; at 8 KiB every fanout below doubles and every height shrinks by one bucket |
| `vlog_min` | 256 B — values at or above this go to the value log |
| `blob_threshold` | 256 KiB |
| `fanout` (T) | 8 |
| levels (L) | 4 at 10⁷ documents |
| `l0_trigger` | 4 |
| `overlap_bound` | 2 |
| filters | **16 bits/key above the last level** (≈0.33 % measured), 10 at the last level (≈1.7 % measured) — blocked-Bloom rates, `spec/04-segments.md` §2.4 |
| `vlog_space_target_pct` | 150 |
| document shape | 20 fields, names averaging 12 B, values averaging 20 B |
| id | snowflake `i64` — ids share a long common prefix |

Two derived quantities drive everything below.

**Logical record** `R` = user key (16 B) + value (500 B) = **516 B**.

**Merged footprint** `K` — what compaction actually rewrites per entry:

```
internal key, prefix-compressed   ~13 B
cell overhead (suffix_len varint,  ~4 B     kind_flags, and the 2-byte
  kind_flags, cell pointer)                 cell pointer (04 §2.2)
value-log pointer                  16 B
                                  ─────
K                                 ~33 B          k = K/R = 6.4 %
```

**Measured: 33.1 B**, from 121.9 entries per leaf at a 4 KiB page
(`reference/dart/cryptand/bench/p1_height.dart`). The model said 32 B and the
first implementation measured **34 B**; `04-segments.md` §2.2 was then changed
to share `value_kind` with the entry flags and to omit `value_len` for the two
kinds whose width is fixed at 16, which recovered two of those bytes. The
remaining 1 B over the model is the prefix-compressed key, which runs ~13 B
rather than 12 on snowflake-shaped ids.

**`k` = 6.4 % is the number the whole write argument rests on.** Compaction
rewrites 6 % of the data, not 100 % of it.

## 2. Fanout and segment height

Leaf cell in a data segment ≈ 33 B → **~122 entries per leaf**. Internal cell
(separator ~5 B + 8 B child + 8 B count + 2 B pointer) ≈ 24 B → **~172 children
per internal page**.

Both are **measured**, not derived — the second column is what
`bench/p1_height.dart` reports at 10⁶ documents, and the first is the model:

| | model | measured |
|---|---|---|
| entries per leaf | ~127 | **121.9** |
| children per internal page | ~169 | **171.9** |

| entries | segment height |
|---|---|
| ≤ 122 | 1 |
| ≤ 21 k | 2 |
| ≤ 3.6 M | 3 |
| ≤ **619 M** | 4 |

Because values are separated, a data segment's leaves hold pointers rather than
documents, so a segment holding 3.6 M documents is 3 levels deep and ~115 MB of
key index — of which the interior is ~1 MB and stays cached permanently.

**Prediction P1 — CONFIRMED.** Segment height ≤ 4 for every collection below
613 M documents at 4 KiB pages, and the interior of the last level's key index
fits in under 2 MiB per 10⁷ documents.

*Measured* (`reference/dart/cryptand/bench/p1_height.dart`, 4 KiB pages,
snowflake ids, the 20-field document below): height 2 at 10⁴, height 3 at 10⁵
and 10⁶, capacity **619 M** at height 4, and an interior of **192 KiB** at 10⁶
documents — **1.88 MiB** extrapolated to 10⁷. The interior is 0.6 % of the
extent at every size measured, which is the property the claim is really about:
the part of the key index that has to stay cached is negligible.

The first implementation measured 548 M and 2.03 MiB, missing both. The gap was
two bytes per leaf cell, and `04-segments.md` §2.2 was changed to recover them
rather than the prediction being relaxed.

## 3. Write amplification — the main claim

Device bytes written per logical byte, at steady state, sustained random writes
over a dataset much larger than RAM.

### 3.1 Cryptand

| component | cost | derivation |
|---|---|---|
| value written once | **0.97×** | 500/516; there is no WAL, so this is the only time the value reaches the device |
| promotion of survivors into the cold log | 0.29× | ~30 % of values reach the last level; the rest die in the hot tier and are never promoted |
| key index: L0 flush | 0.06× | 1 × k |
| key index: tiered levels L1…L3 | 0.19× | (L−1) × k = 3 × 0.064 |
| key index: levelled last level | 0.51× | T × k = 8 × 0.064 |
| value-log GC | 0.15 – 0.35× | the two-tier split collects a *low*-liveness hot log and rarely touches the high-liveness cold one, so the classic `f/(1−f)` term is small at both ends |
| **total** | **2.18 – 2.38×** | the six rows, summed; midpoint **≈ 2.28×** |

The two-tier log costs a promotion write and saves more than that in collection,
so the total is within noise of a single-tier log — and it delivers key
clustering for free, which a single-tier log cannot (§5.2).

Key-index write amplification is **12×** (1 + 3 + 8) — but against the measured
6.4 % of the data, so it contributes 0.77× overall. (At the 6.2 % the model
assumed it would be 0.75×; the difference is inside every other term's
uncertainty.)

### 3.2 Fjall

Fjall separates values above a threshold and quotes ~2–3× write amplification.
Reconstructing it on the same workload with separation active:

| component | cost |
|---|---|
| journal — **the full record**, before anything useful happens | 1.00× |
| flush: value to the value log | 0.97× |
| flush: key to the SST | 0.06× |
| levelled key compaction, T×L ≈ 10 | 0.62× |
| value-log GC | 0.25–1.00× |
| **total** | **2.90 – 3.65×** |

**The difference is almost exactly the journal.** Fjall writes every value
twice before it is queryable — once to the WAL, once to the value log. Cryptand
writes it once, because the value-log record *is* the durability record.

If the value falls below Fjall's separation threshold, it is merged like a key
and the figure goes to 12× or worse. Cryptand's threshold is 256 B on
`desktop`, so almost no document lands in that regime; on `mobile` the threshold
is 1024 B and most documents land in it *deliberately* — §10 is where that trade
is accounted for.

### 3.3 RocksDB, as `nitrite-rocksdb-adapter` uses it

No key–value separation (BlobDB is not enabled), leveled compaction:

| component | cost |
|---|---|
| WAL, full record | 1.00× |
| flush, full record | 1.00× |
| leveled compaction of full records, T×L | 10 – 30× |
| **total** | **12 – 32×** |

With BlobDB enabled it would land near Fjall, around 3×.

### 3.4 MVStore and Hive

MVStore copies the root-to-leaf path per commit and, because a chunk is only
free when every page in it is dead, must rewrite live pages to reclaim space.
Hive appends at 1× and then requires a **full file rewrite** at `compact()` —
its 1× is an accounting artifact, not a property.

### 3.5 The claim

| | write amplification | vs Cryptand |
|---|---|---|
| **Cryptand** | **≈ 2.3×** (§3.1 midpoint 2.26) | — |
| Fjall | ≈ 3.3× (§3.2 midpoint 3.28) | **1.45× more** |
| RocksDB (as used) | ≈ 20× | **9× more** |
| RocksDB + BlobDB | ≈ 3× | 1.3× more |

**Prediction P2.** On sustained uniform-random writes over a dataset 8× the
page-cache budget, under the `desktop` profile, Cryptand writes **1.4–1.6×
fewer bytes to the device than Fjall** and **4–9× fewer than RocksDB as
configured in `nitrite-rocksdb-adapter`**. (The ratio at the two midpoints is
1.45; the range covers both engines' component uncertainty, and it is the same
range quoted in §11, the README and `tradeoff-analysis.md` §9 — if any of them
disagree again, this row is the one that is right, because it is the one with the
arithmetic next to it.) Because that workload is
device-bound, sustained throughput follows the same ratios.

*Measure:* bytes written to the device — `/proc/self/io: write_bytes`,
`fs_usage` on Darwin, or the device counter — not bytes written to the file.
Run for at least 3× the dataset size so compaction and GC reach steady state; a
short run measures the memtable, not the engine.

**The risk has moved from the GC term to the promotion term.** If the fraction
of values surviving to the last level is much higher than ~30 % — a write-once
workload rather than an update-heavy one — promotion costs closer to 0.97× and
the total approaches 3.0×, level with Fjall. The mitigation is in the format: a
sorted bulk writer goes **straight to a clustered cold segment**, skipping the
hot tier and the promotion write entirely (`spec/04-segments.md` §6.3, §10). So
the bad case is the one the format has an explicit path around, and the
benchmark must exercise both.

## 4. Write concurrency

| engine | scaling limit |
|---|---|
| **Cryptand** | one `fetch_add` on `next_seq`; per-writer value-log segments; sharded memtables; off-thread committer. **N writers drive N independent append streams.** |
| Fjall (as used) | `SingleWriterTxDatabase` — **literally one writer**; its optimistic mode still shares one journal |
| RocksDB | concurrent memtable insert, but one WAL file and a group-commit leader; plateaus a few threads in |
| MVStore | one store-wide commit lock |
| Hive | one box, one isolate |

**Prediction P3.** Insert throughput scales near-linearly with writer threads up
to the device's useful queue depth (8–16 on NVMe), then becomes device-bound.
At 16 writer threads: **≥ 2× RocksDB**, **≥ 3× Fjall** as `nitrite-rust`
configures it, **≥ 5× MVStore**.

*Measure:* 1, 2, 4, 8, 16, 32 writer threads inserting disjoint and overlapping
key ranges; report throughput, p50/p99 latency, and CPU seconds per operation.
Report the overlapping case separately — that is where conflict detection and
memtable-shard collisions show up.

**Where P3 is fragile:** if the committer becomes the bottleneck (one thread
building segments for many writers), scaling stops early. The mitigation is in
the format — each memtable shard flushes its **own** L0 segment, so segment
building parallelizes too — but an implementation has to actually do that.

## 5. Read cost

```
point read = manifest key-range prune                          0 I/O
           + filter probes over candidates                     0 I/O (cached)
           + 1 leaf read at the last level (interior cached)    1
           + expected extra descents from filter false          0.026
             positives (range-partitioned tiers cap candidates
             at 9; 16-bit filters above the last level)
           + 1 value-log read at an unrelated offset            1
                                                              ─────
                                                          ≈ 2.0 device I/Os
```

Two, not three. A cold whole-document read is one leaf read plus one value read;
the interior of the key index is small enough to stay resident (§2), and filter
blocks come from the page cache. §9 records this as a deliberate loss against an
engine that inlines values.

**Be careful comparing this to the previous design.** A copy-on-write B+tree
with values inline also cost ~3 *page* reads, but two of those were cached
interior hits and the leaf carried the document — **1 real I/O**. Key–value
separation makes it **2**. Point reads of whole documents roughly double in
I/O count; that is the plain cost of the write path and
`design/tradeoff-analysis.md` §1.1 accounts for it rather than averaging it
away.

| engine | predicted cold point read |
|---|---|
| **Cryptand**, value ≥ `vlog_min` | **2 I/Os + 1 field decode** |
| **Cryptand**, value < `vlog_min` | **1 I/O + 1 field decode** |
| MVStore | 1 I/O + full Java deserialization |
| RocksDB (JNI) | 1–2 I/Os + JNI + full Kryo decode |
| Hive | 1 I/O + full adapter decode, **after** the whole key index is already resident |
| Fjall | bloom probes across levels + 1–2 block reads + a blob read for separated values + full bincode decode |

Key–value separation costs one extra I/O for a separated value. Three things pay
it back:

- **The key index is 6 % of the data**, so its interior stays cached even when
  the database is far larger than RAM. The descent is usually pure CPU.
- **Key-only reads never touch the value log.** Index scans, counts, existence
  checks and covering queries are served entirely from the key index — and
  Nitrite does a great deal of exactly this.
- **Projections decode one field, not the document.** The value encoding's
  sorted `(name_ref, offset)` table makes `doc["price"]` one pass and a slice.
  **Measured at 11× cheaper than a full decode for one field, 6× for two**; the
  table is varint-encoded, so it is a forward scan rather than the binary search
  an earlier draft described (`02-value-encoding.md` §5.2).

**Prediction P4.** Cold point reads of whole documents: at parity with Fjall
(which also separates), and **up to 2× slower than MVStore and Hive**, which
inline everything. Warm, or with a value cache, the gap closes. On projections
touching ≤ 25 % of a document's fields: **≥ 3× MVStore, ≥ 2× Fjall**, because
decode dominates. On key-only index scans: **≥ 5×**, because no value is read at
all. *Measure:* `find(eq(id))` cold and warm, with 1-field, 5-field and
all-field projections, plus a covering index scan.

P4 is deliberately the least flattering prediction in this document. It is the
one an implementation is most tempted to quote selectively.

### 5.1 Scans

Because the last level is disjoint, a scan merges one segment per level plus L0
— a bounded heap of ~5, not an unbounded N-way merge. Advancing is a pointer
bump inside a leaf and a heap step across segments, with **no re-descent from the
root per row**.

**Prediction P5.** A paged walk over a whole collection costs ~1.0–1.2× one full
scan, and `nitrite-rust`'s measured 40.4× collapses to that. *Measure:* the exact
harness from `research/nitrite-survey.md` §7 — 20 k rows of ~1 KB, 400 per page,
paged walk vs full scan.

P5 is the most defensible prediction here: the cause of the 40.4× is known and
named (no cursor, `higher_key` re-descends from the root) and the spec fixes
exactly that.

### 5.2 Scans that return whole documents — the load-bearing one

Everything above assumes values adjacent in key order are adjacent on disk.
Bulk-loaded data has that for free; randomly updated data loses it.

Take an inline-value engine as the baseline: ~8 documents of 500 B per 4 KiB
page, so `N/8` sequential page reads for *N* documents.

| state of the value log | reads for *N* documents | ratio |
|---|---|---|
| key-clustered | `N/127` key + `N/8` value, both sequential | **≈ 1.06×** |
| fully scattered | `N/127` key + up to `N` **random** value reads | **≈ 8×** in read count, and worse in time because the reads are random rather than sequential |

The clustered ratio is `1 + 8/127`. What the aged-scan test actually gates is
the *per-row value read count* — `value_reads_per_scanned_row`, which is `1/8 =
0.125` when clustering holds and approaches `1.0` when it does not
(`spec/13-operations.md` §6). An earlier draft quoted "1.13×", which added that
0.13 to 1 as though it were the ratio; it is not, and the two numbers measure
different things.

Three normative mechanisms close the gap, all MUSTs:

- **Clustered promotion** (`spec/04-segments.md` §6.3) — surviving values are
  promoted into the cold value-log tier *during last-level compaction, which
  already runs in key order*, so the cold log is key-clustered by construction
  at no extra cost. Most data lives at the last level, so most scanned bytes are
  clustered.
- **A bounded locality debt** (§6.9) — live bytes in unclustered segments MUST
  stay under `locality_debt_pct` (20 %), catching the residue that never reaches
  the last level.
- **Pointer-sorted readahead** (§8.1) — a cursor dereferencing values MUST issue
  reads in non-decreasing `(segment, offset)` order over a window of at least
  `readahead_window`, coalescing same-page reads.

**Prediction P8 — CONFIRMED, after a mechanism was added.** On a database aged
by 10× its size in random updates, a full scan returning whole documents costs
**≤ 1.5×** the same scan on a freshly-loaded database, and
`value_reads_per_scanned_row` stays **below 0.3** — with clustered promotion,
cold-tier collection, the locality-debt bound and readahead in force; and
**≥ 6×** with them disabled.

*Measured* (`reference/dart/cryptand/bench/p8_aged_scan.dart`, 20 000 documents
then 200 000 random updates, values in the value log at `vlog_min` 256 B, laid
out over 4 KiB pages and read through a bounded LRU):

| mechanisms | live runs | aged / fresh | `value_reads_per_scanned_row` | value-log space |
|---|---|---|---|---|
| all four on | 2 | **1.00×** | **0.100** | 1.00× |
| promotion but no collection | 19 | 2.14× | 0.224 | 5.82× |
| none | 19 | **9.62×** | 1.038 | 5.82× |

Both halves of the prediction hold — comfortably at the top, and 9.62× against
a predicted "≥ 6×" at the bottom.

**It did not hold on the first attempt, and what was missing is worth stating.**
The design named three mechanisms: promotion, the locality-debt bound, and
readahead. Implementing exactly those produced **2.14×**, a failure. The cause
was that promotion clusters each *generation* of surviving values into its own
run, so ten rounds of compaction left nineteen runs — each perfectly sorted,
which is why the original `locality_debt` (defined over the *clustered flag*)
read 0 % throughout. `spec/04-segments.md` §6.9 now defines the debt over
**surplus runs**, §6.8 makes collection a trigger on it, and §6.3 no longer
claims a value is written "at most twice".

**What it costs.** Holding the debt under 20 % cost **2.12×** value-side write
amplification against **1.76×** with no collection — 20 % more value writes, in
exchange for an aged scan at 1.00× instead of 2.14× and a value log at 1.00× its
live size instead of 5.82×. Collection pays for itself twice over on space
alone.

**Readahead made no measurable difference** in either direction, and that is the
design working: once promotion and collection leave one key-ordered run,
sorting a window of pointers that are already in order is a no-op. §8.1 remains
a MUST because it is what bounds the *unclustered* case, which is exactly when
the other mechanisms have not caught up yet.

**The promotion term of §3.1 is workload-sensitive, as §3.1 itself warns.** That
section costs promotion at 0.29×, assuming ~30 % of values reach the last level,
and adds: "If the fraction of values surviving to the last level is much higher
than ~30 % … promotion costs closer to 0.97×." P8's harness is deliberately that
workload — every compaction promotes every surviving value — and promotion
measured **1.06×**. The caveat was right; the headline number is for a different
workload, and P2 must be measured on its own.

P8 is the failure mode that would otherwise be found by a user a year in,
reported as "the database got slow", and never traced. It is a **mandatory
conformance test** (`spec/11-conformance.md` §6), not merely a benchmark — and
the reason to have written it that way is that it caught a missing mechanism in
the design it was written to defend.

### 5.3 Latency, not just throughput

**Prediction P9.** Under sustained write plus forced compaction: write p99 stays
within **5×** p50 (the quadratic backpressure curve of
`spec/10-transactions.md` §6, plus compaction pacing), and on `mobile` **no
foreground operation exceeds 8 ms** (`spec/12-profiles.md` §4). *Measure:* a
latency histogram under a fixed offered load with compaction forced, on a real
mid-range Android device — not an emulator, whose thermal and scheduling
behaviour resembles nothing.

P9 matters more than any throughput number for the Flutter case: a dropped frame
is visible and a 10 % throughput difference is not.

### 5.4 Read tail

**Prediction P10.** `segments_probed_per_lookup` p99 ≤ 2 and p99.9 ≤ 3, at every
database size. *Measure:* the required metric of `spec/13-operations.md` §6 under
a uniform-random point-read load. This validates range-partitioned tiers and the
per-level filter allocation; if it fails, one of the two is not being
implemented.

P10 survived the filter correction of `spec/04-segments.md` §2.4 with room to
spare: at the measured 0.33 % blocked-Bloom rate the expected extra descents are
0.026, so p99 is 1 and p99.9 is 2.

**Measured, and CONFIRMED — with one condition the prediction did not state.**
`reference/dart/cryptand/bench/p10_read_tail.dart`, 20 000 uniform-random point
reads after random-order inserts plus updates over half the key space, at
`desktop` shape:

| documents | p50 | p99 | p99.9 | max | mean |
|---|---|---|---|---|---|
| 10 000 | 1 | 1 | 1 | 2 | 1.00 |
| 25 000 | 1 | 1 | 2 | 3 | 1.01 |
| 50 000 | 1 | 1 | 2 | 2 | 1.00 |
| 100 000 | 1 | 1 | 2 | 2 | 1.01 |
| 200 000 | 1 | 1 | 2 | 2 | 1.01 |

**The condition is the early exit of `spec/04-segments.md` §4.** This
prediction's arithmetic counts filter false positives and nothing else, which
is the whole story only for a reader that stops at the first candidate holding
the key. A reader that examines every candidate — what §4 *requires* absent a
level-discipline proof — also probes every segment legitimately holding an
older version, and the same databases then measure p99 3 and p99.9 4 at 25 000
documents, outside the bound. P10 is a claim about a reader that takes the
early exit, and §4 now states the ordering that makes the proof available
(descending `segment_id` within a level).

**The sentence that followed was also wrong, and the control is what showed
it:** "it is range partitioning that bounds the tail, and the filter only has to
be good, not excellent." Measured the other way round at 2×10⁵ documents — with
range partitioning intact, removing the filter takes the mean from 1.01 to 3.91;
with the filter intact, removing range partitioning (`overlap_bound = tier_width`)
leaves it at 1.01. Range partitioning is worth 1.64 probes only once the filter
is gone, and one step of tail (p99 1 vs 2) when it is not.

**And the write load decides whether this is measurable at all.** The first
version of the benchmark inserted keys in ascending order and reported p99 = 1
for every shape, controls included — because sequential inserts give each
memtable flush a disjoint key range, so manifest pruning alone leaves one
candidate and there is no tail to bound. `spec/11-conformance.md` §6's
read-tail test therefore specifies the write load, not just the read load.

## 6. Space

**Encoding density**, per the assumed 20-field document, before page compression:

| encoding | estimate | measured |
|---|---|---|
| Java serialization | ~900–1400 B | — |
| bincode (`Value::Document`) | ~820 B | — |
| JSON | ~740 B | **661 B** |
| Hive adapters | ~600–700 B | — |
| Kryo (registered) | ~500–600 B | — |
| **CVE, every name inline** | ~730 B | **639 B** |
| **CVE with a per-tree name dictionary** | **~485 B** | **388 B** |
| **CVE + LZ4** | **~330 B** | not implemented |

The win is that `"customerAddressLine1"` is stored once per *tree*, not once per
*document*: the dictionary alone recovers 251 B of a 639 B document, 39 %.

The measured column is `reference/dart/cryptand/bench/p4_p6_decode.dart` at the
document shape below (realized: 11.6 B names, 17.2 B values). Both absolutes
land ~20 % under the estimate because the realized values are slightly shorter
than the assumed 20 B; the **ratio** is the portable number, and CVE:JSON
measured **1 : 1.70** against a predicted 1 : 1.53. CVE is *relatively* denser
than the model claimed.

**Space amplification** (allocated ÷ live) is the one place Cryptand is
deliberately not best in class:

| engine | predicted |
|---|---|
| RocksDB, leveled | 1.1 – 1.3× |
| **Cryptand, `mobile`** | **~1.2×** — the value log is barely used and the target is 120 % |
| **Cryptand, `desktop`** | **1.4 – 1.6×** — the value log's target is 150 % |
| Fjall | 1.2 – 1.8× |
| MVStore | 1.3 – 2.0× |
| Hive | **unbounded** until `compact()` |

That is the price of the write path, and it is a knob: lowering
`vlog_space_target_pct` toward 120 buys space back with more GC — i.e. it trades
directly against P2.

**Prediction P6.** Absolute file size for 10⁶ documents with 3 indexes:
**≤ 0.6× MVStore, ≤ 0.8× Fjall, ≤ 0.5× Hive after growth** — because the
encoding is 1.5–2.5× denser, which more than covers the higher amplification.
With a Zstd dictionary trained on the collection (`spec/01-container.md` §7),
**≤ 0.35× MVStore**; small structurally-similar documents are exactly the case a
dictionary is for, and exactly the case Nitrite stores.
*Measure:* `du` after load, after 10⁶ random updates, and after an idle period
long enough for compaction and GC to settle.

### 6.1 Encryption

Predictions, like everything else here.

| | effect |
|---|---|
| open latency | **+250 ms** (`mobile`) / **+500 ms** (`desktop`), once, from Argon2id at `spec/12-profiles.md`'s parameters. Dominates opening an encrypted database and is meant to |
| peak RSS at open | **+64 MiB** (`mobile`) / **+256 MiB** (`desktop`), transient. Note this is 16× `mobile`'s entire steady-state page-cache budget — it is the one moment an encrypted phone database is memory-hungry |
| sustained throughput | **~0 %** on any device whose storage is slower than 1–3 GB/s per core, which is every phone and every SATA SSD. On fast NVMe, expect single-digit percent |
| file size | **+0.4 %** from per-page tags; **+24 B** per separated value-log record (16-byte tag + 8-byte clear nonce), so ~5 % on a 500 B separated value and under 1 % where values are inline — i.e. nearly free on `mobile` |
| point read | unchanged in I/O count; one page decrypt added, ~1 µs at 4 KiB |
| filter probe on a cache miss | **a page decrypt instead of a 64-byte read** — the one place encryption changes an algorithmic property rather than adding a constant |
| vector search | zero-copy `mmap` unavailable; resident memory becomes the implementation's to bound (`spec/09-vector.md` §2) |

**Prediction P11.** With encryption enabled, sustained insert and point-read
throughput on a mid-range Android device and on a SATA SSD stay within **5 %** of
the unencrypted figures, and open latency rises by the Argon2id cost and nothing
else. On NVMe the throughput gap is **≤ 15 %**. *Measure:* the full §8 matrix
run twice, `cipher = 0` and `cipher = 1`, reporting open latency separately from
steady-state throughput — averaging them together is how an encryption overhead
number becomes meaningless.

P11 is the prediction most likely to be *pleasantly* confirmed: XChaCha20 is
faster than the storage under it on every device that matters, and the honest
cost of encryption here is a slower open, not a slower database.

**Partially measured — and the open half did not confirm.**
`reference/dart/cryptand/bench/p11_encryption.dart`, Apple M2 Pro, pure Dart,
single-threaded, with Argon2id verified against RFC 9106 §5.3:

| half | measured | against |
|---|---|---|
| open, `mobile` (t 3, m 64 MiB, p 1) | **405 ms** | "~250 ms on a mid-range ARM" |
| open, `desktop` (t 4, m 256 MiB, p 4) | **2183 ms** | "~500 ms" |
| steady state, per 4 KiB page | 53.9 µs encrypt, 53.5 µs decrypt — **73 MiB/s** | — |

The open half is a real miss and `spec/14-security.md` §3.2 now carries it: the
targets were costed against a native implementation with parallel lanes, and
`mobile` — the profile whose whole rationale is a phone UI, and the one most
likely to be running an interpreted or JIT runtime — is `p = 1`, so it has no
lanes to recover with. §3.2 now names the three conforming ways out, of which
using a hardware-backed platform keystore (`kdf = 0`) is the best on a phone and
removes the cost entirely.

The steady-state half is **not** measured against P11's terms and should not be
read as if it were. This implementation has no storage under it — extents are in
memory — so the ratio P11 predicts cannot be formed. 73 MiB/s is the cost of the
*primitive* in the slowest reasonable implementation of it (scalar Dart, no
SIMD); a vectorised ChaCha20 in Rust or Java runs several times faster. The
number's use is as the constant a real-device measurement will divide by, and on
that reading it is a warning: a pure-Dart SDK is cipher-bound rather than
storage-bound, which inverts P11's premise for that SDK specifically.

## 7. Memory

| engine | scales with |
|---|---|
| **Cryptand** | page-cache budget + memtable budget + filters for resident segments + manifest + name dictionaries |
| MVStore | page cache + live Java objects |
| RocksDB | block cache + memtables + resident index/filter blocks, all off-JVM-heap |
| Fjall | block cache + memtables |
| Hive | **every key of every open box**, plus every value in a non-lazy box |

**Prediction P7.** Resident set for a 10⁶-document database with a 16 MiB cache
budget stays within 25 % of that budget; Hive's grows linearly with document
count. *Measure:* RSS after opening and after a full scan, at 10⁴/10⁵/10⁶
documents. This is the prediction most likely to be a landslide, and the one
that matters most on a phone.

## 8. Benchmark plan

Existing harnesses, extended rather than replaced:

| | harness |
|---|---|
| Java | `nitrite-java/nitrite-jmh` |
| Rust | `nitrite-rust/nitrite-bench` (criterion; already covers CRUD, index, spatial, FTS, concurrency, transactions, and comparison against SQLite/redb/sled) |
| Flutter | new; `benchmark_harness` over the same generated dataset |

**Same dataset in all three**, generated from one seed and exported once as a
Cryptand file, so all three SDKs measure identical bytes.

Matrix: `{ MVStore, RocksDB, Hive, Fjall, Cryptand(mobile), Cryptand(desktop),
Cryptand(desktop, encrypted) }
× { 10⁴, 10⁵, 10⁶, 10⁷ docs } × { 0, 1, 3 indexes } × { insert, point read,
range scan, paged scan, update, delete, mixed 80/20 } × { 1, 4, 16 writer
threads }`.

**Run the mobile matrix on a real mid-range Android device and a real iPhone,**
not an emulator or a simulator. Thermal throttling and big.LITTLE scheduling
decide whether the mobile profile is usable, and neither shows up on a desktop.

Two workloads exist specifically to test the claims added for sustained writes:

- **`random-write-8x`** — uniform-random updates over a dataset 8× the cache
  budget, run for 3× the dataset size so compaction and GC reach steady state.
  This is P2, and a short run will not show it.
- **`write-scale`** — 1…32 writer threads at a fixed dataset size. This is P3.
- **`aged-scan`** — load, scan, apply 10× random updates, scan again, with
  clustered promotion / locality-debt enforcement / readahead toggled
  independently. This is P8, and it is also a mandatory conformance test.
- **`latency-under-compaction`** — a fixed offered load with compaction forced,
  reporting a full latency histogram and every foreground stall over 8 ms. This
  is P9.
- **`write-once-bulk`** — a sorted bulk load, to exercise the direct-to-cold
  path that protects P2's promotion term.

Recorded per run: wall time, **bytes written to the device**, peak RSS, final
file size, space amplification, CPU seconds, and — for Cryptand — write
amplification decomposed into value / key-index / GC, because that decomposition
is what says *which* prediction failed.

Two rules taken from prior pain:

- **Never assert on a wall-clock ratio in CI.** Nitrite's timing-ratio guards
  are already flaky. Performance assertions go on plan shape or a store counter
  (page reads, bytes written); wall time is recorded and charted, not gated.
- **Measure on a real phone, not an emulator.** Thermal behaviour and storage
  characteristics on a mid-range Android device decide whether this is usable,
  and no desktop number predicts them.

## 9. Where Cryptand still loses

Shorter than it was, but not empty.

| workload | winner | why |
|---|---|---|
| Cold random reads of whole documents, **`desktop`/`server` profile** | MVStore / Hive | they inline values; Cryptand pays ~2 I/Os to their 1. **Not true on `mobile`/`tablet`**, which inline documents. |
| Space amplification | RocksDB leveled | 1.1–1.3× against Cryptand's 1.5× on desktop (~1.2× on mobile). Absolute size still favours Cryptand (§6), but the ratio does not. |
| Write p99 under sustained load | MVStore | compaction exists; paced and bounded, but a copy-on-write B+tree has gentler tails |
| Multi-process **writing** | RocksDB / SQLite | not in 1.0; multi-process *reading* is supported (`spec/13-operations.md` §8) |
| Raw single-threaded point-get on a hot cache, C++ vs JVM/Dart | RocksDB | language, not format |

## 10. The `mobile` profile changes the answers

Every number above is the `desktop` profile. On `mobile`
(`spec/12-profiles.md`), `vlog_min = 1024` — the maximum a 4 KiB page allows —
inlines documents, and the shape of the engine changes with it:

| | `mobile` | `desktop` |
|---|---|---|
| point read of a document | **1 I/O** | 2 I/Os |
| scan locality | not applicable — values are inline | clustered by promotion |
| write amplification | **~7×** on full records | ~2.3× |
| space amplification | **~1.2×** | ~1.5× |
| read tail (`overlap_bound`) | 1 segment per level | 2 |
| memory | 4 MiB cache, 1 memtable shard, no value-log buffers | 64 MiB, 8 shards |

**The high write amplification is the point, not an oversight.** A phone-scale
Nitrite database writes single-digit megabytes a day; 7× of that is tens of
megabytes, invisible against a 128 GB device's endurance. What a user *does*
notice is 400 µs of UFS random read on every document fetch, and paying one
instead of two is worth far more than the traffic it costs.

If a mobile application is genuinely write-heavy, `vlog_min` is a superblock
field — lower it, and the engine converts by ordinary compaction with no format
change (`spec/12-profiles.md` §6). It cannot be raised above `page_size / 4`
(`spec/00-conventions.md` §8), which is why 1024 and not 4096 is the phone
number; an application that wants a higher ceiling chooses a larger `page_size`
at creation.

The full accounting of what the write-path design cost every other property —
reads, durability, space, memory, latency, complexity — is
`design/tradeoff-analysis.md`. Writing it turned up four mis-specifications,
which are fixed and listed there in §7.

Note what is **no longer** on this list: sustained random writes past RAM, and
write concurrency. Those were the two losses in the earlier design, and §3 and
§4 are the changes that address them — unconditional key–value separation, no
write-ahead log, lazy levelling, and per-writer append streams.

## 11. Summary of predictions

| | claim | confidence |
|---|---|---|
| P1 | segment height ≤ 4 below 613 M docs; key-index interior ≤ 2 MiB per 10⁷ docs | high — arithmetic |
| P2 | **1.4–1.6× fewer device bytes than Fjall, 4–9× fewer than RocksDB, on sustained random writes ≫ RAM** | medium-high — the missing WAL is structural; the GC term is the risk |
| P3 | **≥ 2× RocksDB and ≥ 3× Fjall at 16 writer threads** | medium-high — Fjall as used is single-writer; RocksDB has one WAL |
| P4 | reads at parity on whole documents, ≥ 3× MVStore on projections, ≥ 5× on key-only scans | medium-high |
| P5 | paged scan ~1.0–1.2× full scan; Rust's 40.4× collapses | **high** — cause known, directly fixed |
| P6 | ≤ 0.6× MVStore file size | high — the name dictionary alone accounts for it |
| P7 | RSS bounded by the cache budget; Hive linear in keys | **high** — Hive's behaviour is documented |
| P9 | write p99 within 5× p50; no mobile foreground stall over 8 ms | medium — the mechanisms are specified, the constants are guesses |
| P10 | `segments_probed_per_lookup` p99 ≤ 2 | **CONFIRMED** at p99 1 / p99.9 2, 10⁴–2×10⁵ docs — but only with §4's early exit, and it is the filter rather than range partitioning that delivers it |
| P11 | encryption costs ≤ 5 % throughput on phone/SATA, ≤ 15 % on NVMe; the real cost is a ~250–500 ms open | throughput half still unmeasured (needs real storage); **open half measured and MISSED** — 405 ms `mobile` / 2183 ms `desktop` in pure Dart, because the targets assumed a native KDF with parallel lanes |
| **P8** | **aged full scans ≤ 1.5× fresh, `value_reads_per_scanned_row` < 0.3; ≥ 6× with the mechanisms disabled** | medium-high — clustering is now structural rather than scheduled, so the mechanism runs whether or not anyone remembers to trigger it |
| — | space amplification worse than leveled RocksDB | high, and deliberate |
| — | ~2 I/Os instead of 1 on cold whole-document reads | high, and deliberate |
| — | worse write and read p99 | high, and deliberate |
