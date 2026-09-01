# The full accounting: what every choice costs

The engine was shaped to win on **sustained random writes past RAM** and **write
concurrency**. This document is the complete accounting of what that costs every
other property, what has been done to claw each cost back, and what remains
genuinely worse.

It has been through two rounds. Round one identified the costs; round two
attacked them. Both are recorded, because the fixes only make sense against the
problems they solve.

**Where it stands now.** Two of the three serious regressions are gone —
scan locality is now structural rather than a background chore, and the read
tail is bounded by construction. The point-read cost is gone on phones and
tablets, where it hurt most, and remains on desktop and server, where it is
cheap. Space amplification and implementation complexity remain genuinely worse
and are not going to stop being worse.

**Eight defects were found across the two rounds.** All are fixed; §8 lists
them. A **third round** — an independent review of the written specification
rather than of the design — found fourteen more, this time defects in the
*documents*: an unsound read-resolution order, an under-specified Bloom filter, a
mutable field inside a write-once page, a `vlog_min` above the inline limit, and
a set of chapter-to-chapter contradictions. Those are §8.1. They are the reason
the arithmetic in `performance-model.md` is now written next to its conclusions
rather than only summarized.

---

## 0. The changes under examination

| | change |
|---|---|
| **A** | Key–value separation into an append-only value log |
| **B** | No write-ahead log — the value-log record *is* the durability record |
| **C** | Lazy-levelled immutable segments with range-partitioned tiers |
| **D** | Multi-writer: sharded memtables, per-record sequence numbers, no central append stream |
| **E** | *(round two)* Two-tier value log with clustered promotion |
| **F** | *(round two)* Device profiles — `mobile` / `tablet` / `desktop` / `server` |

---

## 1. Read performance

### 1.1 Point read of a whole document

**Round one's problem.** Separation puts the value at an unrelated offset:

| | I/Os on a cold read |
|---|---|
| A copy-on-write B+tree with values inline | **1** — interior pages are cached, the leaf carries the document |
| Key–value separation | **2** — one leaf read, one value-log read |

This should not be dressed up: it doubles the I/O count on Nitrite's single most
common operation. On NVMe (~80 µs random) it is small. On the UFS/eMMC flash in
a mid-range phone (200–500 µs random) it is felt.

**Round two's fix: the answer is different per device, so make it different per
device.** The whole justification for separation is write amplification — and
write amplification is a *server* problem. A phone-scale Nitrite database writes
single-digit megabytes a day; saving 30 MB/day of device traffic on a 128 GB
phone buys nothing a user can perceive, while spending an extra 400 µs on every
document read buys a visible regression.

So `vlog_min` is now profile-dependent (`spec/12-profiles.md`):

| profile | `page_size` | `vlog_min` | point read | why |
|---|---|---|---|---|
| `mobile` | 4 KiB | **1024** | **1 I/O** | documents stay inline; only genuine attachments separate |
| `tablet` | 4 KiB | 1024 | 1 I/O for most documents | |
| `desktop` | 8 KiB | 256 | 2 I/Os | large datasets, ~80 µs reads, write amplification is the binding constraint |
| `server` | 16 KiB | 256 | 2 I/Os | |

`vlog_min` MUST be ≤ `page_size / 4` (`spec/00-conventions.md` §8), the largest
value a leaf cell can hold. That is why the phone number is 1024 and not the
4096 an earlier draft quoted: 4096 named values that could not be inlined at a
4 KiB page and would have gone to an overflow chain — two I/Os, which is the
cost the whole profile exists to avoid.

**Net: resolved on the devices where it hurt, deliberate where it does not.**
The cost is that the `mobile` profile carries a higher write amplification
(~7× against desktop's ~2.2×) — which is the correct trade at phone write
volumes, and is stated plainly rather than hidden.

Because `value_kind` is per cell and `vlog_min` is a superblock field, a database
moves between these settings by ordinary compaction, with no format change and
no export (`spec/12-profiles.md` §6).

### 1.2 Range scan returning whole documents — round one's worst regression

Scanning *N* documents in key order:

| | reads |
|---|---|
| Values inline | ~*N*/8 leaf reads, sequential |
| Separated, values key-clustered | ~*N*/127 key + ~*N*/8 value ≈ **1.06×** (`design/performance-model.md` §5.2) |
| Separated, values scattered | ~*N*/127 + up to ***N*** random ≈ **8–16×** |

Everything hinges on whether values adjacent in key order are adjacent on disk.
Bulk-loaded data has that for free; random updates destroy it, gradually, so the
symptom appears months later as "the database got slow" and is never traced.

Round one's answer was a *SHOULD* on a background clustering pass. That was a
weak answer to a serious problem — an optional mechanism guarding a mandatory
property.

**Round two's fix: make clustering structural instead of scheduled.** The value
log now has two tiers (`spec/04-segments.md` §6):

- a **HOT** tier written by the write path, where most records die;
- a **COLD** tier that receives **surviving values during last-level
  compaction** — which already walks keys in sorted order.

So the cold log is **key-clustered by construction, at zero extra cost**: the
sort had to happen anyway, and appending values as the merge passes over them is
free. Since the last level holds the large majority of the data, the large
majority of scanned bytes are clustered.

Three supporting changes make it enforceable rather than hopeful:

| | |
|---|---|
| **Promotion is a MUST** (§6.3) | last-level compaction must promote or re-inline every surviving HOT value |
| **Locality debt is a bounded MUST** (§6.9) | `locality_debt` — live value bytes in **surplus runs** — MUST stay under `locality_debt_pct` (20 %). A *measurable outcome*, not a mechanism. The reference implementation had to redefine it: counting segments that merely *lack the clustered flag* reads 0 % on a database whose scans have already degraded 2.1× |
| **Cold-tier collection is a MUST** (§6.8) | promotion clusters each generation of surviving values; only collection merges the generations. Added after the aged-scan test failed at 2.14× with promotion alone |
| **Value readahead is a MUST** (§8.1) | a cursor dereferencing values must issue reads in non-decreasing `(segment, offset)` order over a window of ≥ `readahead_window`, coalescing same-page reads |

And it is now tested: an **aged-scan conformance test is mandatory**
(`spec/11-conformance.md` §6) — load, scan, apply 10× random updates, scan
again; the second scan must cost ≤ 1.5× the first and
`value_reads_per_scanned_row` must stay under 0.3.

**Net: from "potentially catastrophic, mitigated by an optional behaviour" to
"structurally handled, bounded by a MUST, and enforced by a mandatory test".**
On `mobile` the problem does not arise at all, because documents are inline.

### 1.3 Read tail — round one's slightly-worse

| | candidates per point read |
|---|---|
| A tree plus ≤ 8 delta runs | ~9 |
| Round one: L0 + 3 tiered levels × `tier_width` 8 + 1 | up to **29** |
| **Round two** | **9**, and the expected extra descents are ~0.026 (measured filter rate) |

Two fixes:

- **Range-partitioned tiers** (`spec/04-segments.md` §3.1). Plain tiering lets
  every segment at a level overlap a key. Splitting each tiered level into
  `overlap_bound` (default 2, and **1** on `mobile`) groups of mutually disjoint
  segments caps candidates per level at `overlap_bound`, regardless of tier
  width. Cost: a compaction must respect group boundaries, which is cheap for
  bulk-built segments.
- **Per-level filter bits** (§2.4). Upper levels hold little data, so a high bit
  rate there is nearly free: **16 bits** above the last level (**0.33 %** false
  positive, measured — blocked Bloom costs ~7× the classic formula an earlier
  draft quoted, `spec/04-segments.md` §2.4) and 10 at the last level, which
  contributes one candidate anyway.

Worst realistic case is now `l0_trigger (4) + overlap_bound (2) × 2 tiered
levels + 1 disjoint last level` = **9** candidates. The eight above the last
level survive their 16-bit filter at 0.33 % → **expected extra descents ≈
0.026**, and the p99.9 case is one extra descent, not several. (An earlier draft
wrote "3 levels × 2 = 10", counting the disjoint last level as though it were
tiered.)

**Net: better than round one and better than the design it replaced.**

### 1.4 Index-only scans, counts, covering queries — **better**

Index trees store `EMPTY` and never touch the value log. Separation also removes
documents from data-tree leaves, so both index and data leaves hold ~127 entries
against ~8 when documents were inline.

Nitrite does a great deal of exactly this — every indexed `find`, every `count`,
every existence check. **The largest read-side win, and it is untouched by every
trade above.**

Round two adds planner statistics (`spec/13-operations.md` §9): entry counts, a
distinct-value estimate from a HyperLogLog sketch computed free during
last-level compaction, null counts, key range and a 64-bucket equi-depth
histogram. Nitrite's `FindPlan` currently chooses an index from static
properties — uniqueness and field count — which routinely picks a unique index
on a barely-constrained field over a non-unique one that would eliminate 99 % of
the collection.

---

## 2. Durability

**Strength is unchanged and remains the design's best property.** Everything is
append-only or copy-on-write, no live page is ever overwritten, recovery is
reading two superblocks, and no durability mode — including `none` — can produce
a structurally invalid file.

What grew is the number of ways an implementation can get it wrong. Removing the
write-ahead log removed a component whose whole job was making ordering obvious.

| new failure mode | closed by |
|---|---|
| **Torn value-log tail** — concurrent incremental appends, so a crash can leave a partial record | per-record CRC plus a durable `byte_len` watermark; only records below it may be referenced |
| **Reserved-but-unwritten holes** — a writer that reserves a range and dies leaves a gap *below* the tail | `byte_len` MUST advance only over a **contiguous prefix of completed reservations** (`spec/10-transactions.md` §2.3) |
| **Dangling value pointers** — if a key's segment lands durably before its value record, the index points at bytes never written, and **no checksum catches it** | normative MUST: a superblock MUST NOT name a segment whose value-log records are not already durable |
| **GC losing data** — nothing in a B+tree design could lose data through a logic bug; GC can | three explicit MUST invariants (`spec/04-segments.md` §6.8): exact `(segment_id, offset)` match for liveness, no free before the pointer-rewrite commit is durable, `live_bytes` conservative |

### 2.1 Round two: containment and repair

Two additions that make the durability story better than what it replaced, not
merely equal:

**Corruption containment** (`spec/13-operations.md` §4). A single damaged page
MUST NOT make the database unreadable. An implementation must identify the
affected key range, keep serving every key outside it, fail reads inside it with
a specific error, and mark affected trees so a planner does not silently
substitute an incomplete index scan. On a phone — where storage is least
reliable — the alternative behaviour that every backend Nitrite uses today
exhibits is that one bad block turns a user's entire journal into an error
message.

**Repair** (§3). The manifest is deliberately redundant with the segment
headers: every field the manifest holds is duplicated in the segment it
describes. That costs a few dozen bytes per segment and turns the single most
likely catastrophic failure — a damaged manifest root — from a total loss into a
scan-and-rebuild. Every index is derivable from its data tree, so a corrupt index
is dropped and rebuilt rather than mourned.

**Net: guarantee unchanged; implementation burden higher; operational recovery
substantially better.**

---

## 3. File size and space

### 3.1 Space amplification — **still worse, and still deliberate**

| | allocated ÷ live |
|---|---|
| A copy-on-write B+tree with bounded runs | ~1.1 – 1.3× |
| **Cryptand, `mobile`** | **~1.2×** — the value log is barely used, and `vlog_space_target_pct` is 120 |
| **Cryptand, `desktop` / `server`** | **1.4 – 1.6×** |
| RocksDB, leveled | 1.1 – 1.3× |
| Fjall | 1.2 – 1.8× |
| Hive | unbounded until `compact()` |

The value log accumulates garbage between passes, and lazy levelling keeps
superseded versions alive longer. Both are the price of the write win. The
`mobile` profile largely opts out of both, which is the right call where storage
is shared with photos.

Round two improves this in one real way: the **two-tier log runs at higher
average liveness** than a single mixed log. Hot segments die almost entirely and
are cheap to reclaim; cold segments are high-liveness and rarely need collecting
at all. Total value-side write cost works out at ≈1.45× (1.0 initial + ~0.3
promotion + ~0.15 collection) against ≈1.6× for a single-tier log — **slightly
cheaper, and clustered for free**.

### 3.2 Per-record framing

Every separated value costs ~41 bytes: ~26 B of value-log record framing
(including a duplicate key, which GC needs for liveness) plus ~15 B of tree-cell
growth. As a fraction that is 64 % at a 64-byte value and 1 % at 4 KiB — which
is why round one's `vlog_min` of 64 was a mis-specification, and why the
threshold is now profile-scaled from 256 up to `page_size / 4` — 1024 B on a
phone's 4 KiB pages.

### 3.3 Absolute file size — **better than all four incumbents**

Encoding density dominates and is untouched by any of this: CVE with a per-tree
name dictionary is ~485 B for a 20-field document against ~900–1400 B for Java
serialization.

Round two adds **Zstd dictionaries** (`spec/01-container.md` §7) for the case
this format sees most — many small, structurally similar documents, where a
per-page codec has too little context. Typical gain is 2–3× beyond plain Zstd,
which on a phone is the difference between a 200 MB and an 80 MB database.

**Net: amplification ratio worse (much less so on mobile), absolute size
comfortably ahead and now further ahead.**

---

## 4. Memory

| | before | after |
|---|---|---|
| filters | ≤ 8 runs, resident | up to ~10 segments, **demand-loaded** — a blocked-Bloom probe reads one 64-byte block, so nothing need be resident |
| manifest, value-log stats | — | two small trees, resident |
| memtables | one | `memtable_shards` — **1 on `mobile`** |
| open value-log buffers | — | **none** — writers reserve a range and `pwrite` directly, so open segments are bounded by heat classes, not by writer count |
| cursors | 1 path + 8 run positions | a path stack per candidate — now ~10, not ~29 |

Round one specified per-writer open value-log segments, which would have cost
8 writers × 4 buffers × 1 MiB = **32 MiB of write buffers**, scaling with the
very concurrency the design was chasing. (There are three heat classes, not
four — `spec/04-segments.md` §6.6.) The reserve-and-`pwrite` protocol
removes the buffers entirely and is *better* for concurrency as well — writers
never share a buffer or a cache line.

Cursor cost is bounded by the read-tail fix: ~10 candidates × ~4 levels of path
≈ 40 pinned pages ≈ 160 KiB worst case, down from ~480 KiB.

**Net: bounded everywhere, materially better than round one, and nothing scales
with the number of keys** — which remains the structural advantage over Hive.

---

## 5. Latency

Round one's honest position was "throughput was bought with tail latency".
Round two attacks that directly.

| | |
|---|---|
| **Compaction pacing** (`spec/10-transactions.md` §6.1) | compaction and GC I/O MUST be rate-limited to a multiple of the trailing foreground write rate. Unpaced background I/O is the main cause of LSM write-latency spikes — and, on a phone, of unexplained battery drain |
| **A normative backpressure curve** (§6) | `delay = max_delay × x²` over the worst normalized overshoot. Quadratic: imperceptible while merely busy, firm before trouble. An implementation MUST NOT stall at the hard threshold without having applied increasing delay first — a cliff turns a throughput problem into a hang, and that is what users report |
| **Interruptible compaction** (`spec/04-segments.md` §5.2) | a compaction job MUST decompose into steps of ≤ `compaction_step_bytes` (256 KiB on `mobile`). Because output segments are built bottom-up and immutable, a partial output is just a prefix — abandoning it costs only the work done |
| **A foreground stall budget** (`spec/12-profiles.md` §4) | **8 ms on `mobile`** — half a 60 Hz frame — binding on compaction, GC, clustering, `compact()` and flushes. On Flutter the database usually shares an isolate with the UI, and an engine that stalls 120 ms is indistinguishable from a janky app |
| **Host hints** (§5) | `idle`, `charging`, `thermal_pressure`. Non-urgent maintenance defers on mobile. Compaction is the largest discretionary consumer of battery and thermal headroom in an embedded database, and only the host knows when spending it is acceptable |

**Net: write p99 goes from "worse, mitigated by a vague SHOULD" to "bounded by a
specified curve, a paced background, and a frame-budget MUST with a mandatory
conformance test".** Read p99 is improved by §1.3. This is the area round two
changed most.

---

## 5.5 Security

Security was added as a first-class aspect after rounds one and two, so this is
its first accounting.

### 5.5.1 What it buys

| | |
|---|---|
| **Confidentiality against the realistic attacker** | someone holding the file — a lost phone, a leaked backup, a forensic image. Every page payload and every value-log record is AEAD-encrypted (`spec/14-security.md` §5) |
| **Tamper detection** | a modified page fails to open rather than decrypting to plausible garbage, and the superblock is MAC'd so `cipher = 0` and a weakened Argon2id cost cannot be forged in (§6) |
| **A password change that costs 32 bytes** | the two-level key. One level would have made a password change a full-file re-encryption — hours on a phone, non-atomic, and therefore something users are told not to do (§3.1) |
| **Crypto-erase** | the only erase that means anything on flash, where overwriting a block is a lie the controller tells you (§8.2) |
| **A hostile file cannot instantiate a class** | this one applies with encryption *off*, to every file, and it is the biggest security improvement in the format. MVStore feeds `readObject` on file content; CVE has a fixed type set and no dispatch (§1.3, §9.2) |

### 5.5.2 What it costs

| | |
|---|---|
| **~250–500 ms per open** | Argon2id, deliberately, and an implementation MUST NOT lower it to feel faster (§3.2) |
| **64–256 MiB transient at open** | far above `mobile`'s entire 4 MiB steady-state budget. It is the one moment an encrypted phone database is memory-hungry |
| **~0.4 % space per page, ~5 % per small separated value** | 16-byte tag per page and chunk, 24 bytes per value-log record (tag + the clear nonce that lets one record be decrypted alone) |
| **Filter probes stop being cheap** | `04` §2.4's "a probe reads exactly one 64-byte block" needs the page decrypted whole, so demand-loading a filter costs a page decrypt per miss |
| **Zero-copy vector reads are gone** | an encrypted region cannot be `mmap`ed and sliced, so DiskANN's bounded-resident-memory property becomes the implementation's problem rather than the OS's (§5.4) |
| **A length side channel** | compression happens before encryption and `payload_len` is in the clear. Weak here compared to a request-response protocol, real enough to state and to offer `page_codec = 0` against (§7) |
| **Not throughput** | XChaCha20-Poly1305 runs at 1–3 GB/s per core without hardware AES. Every device Nitrite targets has storage slower than that, so on phones and SATA SSDs encryption is free; on fast NVMe it becomes measurable |

### 5.5.3 What it does not defend, and why that is written down

An attacker inside the process; rollback to an authentic earlier copy of the
same file; and per-tree page counts, `commit_id`s and access patterns.

The rollback one is the interesting admission. A single self-contained file has
no anchor to compare itself against, so an attacker who restores an old copy
presents a state that verifies perfectly — because it did. The mitigation that
works is outside the format: pin the last-seen `commit_id` somewhere the
attacker cannot write, which is ten lines and closes it for the mobile case
(`spec/14-security.md` §6.3). Claiming the format handles it would be worse than
saying nothing, so it says this.

**Net: a real security posture, priced honestly, at a cost paid mostly once per
open rather than per operation.**

---

## 6. Complexity and portability

### 6.1 Complexity — **the one cost that only grew**

Three more spec chapters (profiles, operations, security), a two-tier value log,
promotion, locality accounting, checkpoints, backup, repair, containment,
metrics, TTL, statistics — and now four cryptographic primitives, a keyslot
format, a nonce discipline and a conversion path. Three independent
implementations must get all of it right, and the security additions are the
part where "almost right" is indistinguishable from right until it is
catastrophic.

That is the honest reason `spec/14-security.md` §13 makes a **nonce-uniqueness
test mandatory** — write past the published floor twice, kill the process at
random points, then assert no `(key, nonce)` pair occurs twice in the whole
file. It is the only test that catches the defect the chapter's own §4.1
describes, and no amount of code review reliably does.

Three things keep it tractable:

- **No insertion path, no split algorithm, no rebalancing** anywhere in the
  format. Segments are bulk-built and immutable, which removes the category of
  subtlety most likely to produce two implementations that both "work" and
  disagree.
- **Reduced write profiles** (`spec/11-conformance.md` §1.2). An implementation
  may declare `no-vlog`, `no-compaction` or `single-writer` — it reads
  everything and writes a restricted subset. This is safe because `value_kind`
  is per cell and liveness statistics may be stale-conservative, so a
  reduced implementation never corrupts a database it does not fully manage. A
  Dart phone SDK with `vlog_min` at its ceiling implements no value log on the
  write path at all.
- **Most of the operational surface is bookkeeping, not machinery.** Online
  backup, incremental backup and checkpoints are nearly free consequences of
  immutable, uniquely-identified segments — an incremental backup is a set
  difference over segment ids.

**Net: still the largest genuine cost, and honestly the one most likely to cause
trouble.**

### 6.2 Portability — **unaffected, arguably improved**

The encodings (CVE, CKE), catalog, index layouts, full-text, spatial and vector
chapters are untouched by any of this. The interchange claim rests on those.

Profiles are explicitly **advisory**: every tuning constant is its own superblock
field, and a reader uses the values, never the profile name
(`spec/12-profiles.md` §3). A `mobile`-written and a `server`-written database
are the same format and mutually readable.

Immutable bulk-built segments are *easier* to specify byte-exactly than a
mutable tree whose shape depends on a split policy. **The format got harder to
implement and no harder to agree on.**

### 6.3 What Dart pays

No threads, so no concurrency win — declared as `single-writer` rather than
hidden. But round two changes the balance considerably: on the `mobile` profile
Dart writes everything inline, so it implements no value log, no promotion, no
GC and no clustering on the write path. It reads them, because a desktop may
have written them.

---

## 7. Was anything made worse by round two?

Honestly, three things:

1. **Promotion adds a write.** A value that survives to the last level is written
   twice (once hot, once cold) rather than once. Offset by much cheaper GC, and
   avoided entirely by bulk writers that go straight to a clustered cold segment
   (`spec/04-segments.md` §6.3).
2. **Range-partitioned tiers occasionally force a segment split** that pure
   tiering would not. Cheap, since segments are bulk-built, and it buys a bounded
   read tail.
3. **More spec.** Two chapters, several new trees, more conformance tests.

None of these is close to what they bought.

---

## 8. The eight defects, and what changed

| | defect | fix |
|---|---|---|
| ⚠ 1 | `vlog_min = 64 B` gave 64–70 % space overhead at the threshold | profile-scaled: 256 B desktop, **1024 B mobile** — and capped at `page_size / 4`, because the first fix overshot to 4096 B, which a 4 KiB page cannot inline (§8.1, ⚠ 12) |
| ⚠ 2 | Per-writer open value-log segments made write-path memory scale with thread count — 32 MiB at 8 writers | reserve-a-range + direct `pwrite`; **no buffers at all**, open segments bounded by heat class |
| ⚠ 3 | Nothing recovered scan locality; scans would decay 8–16× with age | **clustered promotion during last-level compaction** — free, structural — plus a bounded `locality_debt` MUST and a mandatory aged-scan test |
| ⚠ 4 | The ordering invariant preventing dangling value pointers was implicit in pseudocode | two normative MUSTs plus three GC liveness invariants |
| ⚠ 5 | Tiering let `tier_width` segments overlap one key, so the read tail grew with tier width | **range-partitioned tiers** with `overlap_bound`, and 16-bit filters above the last level |
| ⚠ 6 | Point reads cost 2 I/Os on exactly the device with the slowest random reads | **device profiles**; `mobile` inlines documents and is back to 1 I/O |
| ⚠ 7 | No foreground stall bound — a compaction could block a Flutter UI isolate for 100 ms+ | **interruptible compaction steps** and `max_foreground_stall_ms` = 8 ms on mobile, with a mandatory test |
| ⚠ 8 | One bad page made the whole database unreadable | **corruption containment**: serve every key outside the affected range, name the range, never answer wrongly |

---


### 8.1 Round three — fourteen defects in the specification

Round three read the spec as a reviewer implementing it, not as an author
defending it. Every finding below is a place where the *documents* were wrong or
underdetermined; none of them changes the engine's shape. They are listed in
order of how badly they would have hurt.

Four would have produced **wrong answers**:

| | defect | fix |
|---|---|---|
| ⚠ 9 | `04` §4 resolved a point read by taking the first candidate in `max_seq` order. `max_seq` is a per-*segment* aggregate, so a lower level can outrank a higher one on an unrelated key and return a stale version. | resolve by the winning entry's own `seq`; early exit only under a stated proof (`04` §4) |
| ⚠ 10 | `04` §4 filter-pruned every candidate, including segments holding a `RANGE_DELETE` covering the key. A range delete's keys are not in the filter, so the delete was silently dropped and deleted keys resurrected. | a segment with `HAS_RANGE_DELETES` is never filter-pruned (`04` §4) |
| ⚠ 11 | `03` §8's range table built `<`, `<=`, `>`, `>=` and `between` from the full `CKE(v)`, type code included — so `field >= 5` missed an `I8(5)` and `field > 5` returned a `U8(5)`, defeating the one-numeric-domain rule the chapter exists for. There was also no array-prefix helper that could express type-agnostic numeric equality *on an index*. | numeric bounds are built from `N(v)`; new `array_prefix_numeric` helper (`03` §8.2, §8.3; `06` §7) |
| ⚠ 12 | `12` set `mobile`'s `vlog_min` to 4096 while `00` §8 caps an inline value at `page_size / 4` = 1024 at a 4 KiB page. Values of 1–4 KiB would have gone to overflow chains — two I/Os, the exact cost the profile exists to avoid. | `vlog_min ≤ page_size / 4` is now an invariant; `mobile` is 1024 |

Three were **under-specified in a way that only shows up across languages**:

| | defect | fix |
|---|---|---|
| ⚠ 13 | The blocked-Bloom filter gave a hash and a block selection but never the probe count `k`, the bit-within-block derivation, or how `block_count` is computed. Two implementations would have disagreed, and a filter disagreement is a false negative — a lost key. | fully specified, with `probes` and `block_count` written into the filter page (`04` §2.4) |
| ⚠ 14 | `03` §5 gave millisecond and nanosecond instants two temporal subclasses ordered by subclass byte, so precision decided the order instead of the instant — contradicting `02` §8 rule 7 outright. | one `INSTANT` subclass; every instant-valued tag canonicalizes into it (`03` §5) |
| ⚠ 15 | `DEC128` carried a CKE type code and a size-based rejection rule, but a decimal fraction has no exact binary `m × 2^e` form, so it could not be encoded exactly, decoded back, or ordered against an `f64` without rounding. | `DEC128` is not a key; the type code is reserved for a future exact decimal region (`03` §4.4) |

Two broke the **container's own central rule**:

| | defect | fix |
|---|---|---|
| ⚠ 16 | `04` §6.2 put a mutable `byte_len` in a value-log segment's head page. That page is referenced by a live superblock, so every append violated "no live page is ever overwritten" and left the page's CRC stale between append and rewrite. Three chapters also disagreed about where the watermark lived. | the head page holds immutable identity only; every mutable field moves to tree 7, where advancing it is an ordinary transactional write (`04` §6.2, §6.7; `10` §2.3, §4) |
| ⚠ 17 | `01` §3 required a 32-byte header on every page, but value-log segments, blobs and vector regions all run raw payload across interior pages. | stated as an explicit exception, with each extent's own integrity mechanism named (`01` §3) |

Five were **contradictions between chapters** — the kind that make three SDKs
diverge quietly:

| | defect | fix |
|---|---|---|
| ⚠ 18 | `05` §2 and `04` §3.2 gave the manifest two different keys (`group` present in one, absent in the other); `13` §3 then claimed the manifest was rebuildable from segment headers, which carried no `group` at all. | `group` added to the segment header and to `05`'s key; verifier checks header-against-manifest agreement |
| ⚠ 19 | `10` §2.2 and `11` §1.1 still required "per-writer value-log segments" — the round-two defect ⚠ 2 that the rest of the spec had already removed. | both replaced with the reserve-then-`pwrite` requirement |
| ⚠ 20 | Five per-tree policy fields (`ttl_ms`, `change_feed`, `inline_values`, `zdict`, `stats`) were top-level in `05` §3 and `params.*` everywhere else. | all under `params`, with a stated rule for which side a field belongs on (`05` §3.1) |
| ⚠ 21 | `08` required ISO WKB and then permitted "the EWKB SRID flag" — two incompatible encodings of the same type word, indistinguishable to a reader. `09` required an inverse slot↔document map that no descriptor field named. `07`'s `term_index` kind was missing from `05`'s kind table. `02`'s `MAP` allowed keys that `03` says have no encoding. `04` §10 named a `bulk_threshold` no chapter defined. | each resolved in place |
| ⚠ 22 | `11` §2's feature-bit table said "in `required` when" while the paragraph under it said `TEXT`/`SPATIAL`/`VECTOR` are optional; a vendor row sat orphaned outside the table. Snapshot and checkpoint tuples omitted two of the nine superblock roots. | one stated rule, a corrected table, complete tuples |

And the arithmetic: the round-two read-tail count treated the disjoint last
level as tiered (10 candidates, not 9); the write-amplification total's high end
did not match its own components; P2's range disagreed with its own summary
table; the scan ratio confused `value_reads_per_scanned_row` with a ratio; and
`performance-model.md` quoted a 4 KiB page while calling itself the `desktop`
profile. All corrected, and the components are now printed beside the totals so
the next such slip is visible.

**What round three says about the design, as opposed to the documents.** Nothing
in it required a structural change. Every defect was a statement about the
engine that was wrong, missing, or made twice differently — which is the failure
mode a three-implementation byte contract is most exposed to, and the argument
for the conformance vectors in `spec/11-conformance.md` §6 being written before
any of the three SDKs is.

## 9. Scorecard

Against the copy-on-write B+tree design this replaced, and against the field.

| aspect | direction | note |
|---|---|---|
| Sustained random writes ≫ RAM | **better** | 1.4–1.6× fewer device bytes than Fjall; 4–9× fewer than RocksDB as configured |
| Write concurrency | **better** | no central append stream; ≥ 2× RocksDB, ≥ 3× Fjall at 16 threads |
| Index-only scans, counts, covering queries | **better** | ~5×; leaves ~16× denser |
| Bulk load | **better** | bulk-built segments; sorted batches skip L0 entirely |
| Recovery / open | **better** | O(1) |
| Backup, incremental backup, checkpoints | **better** | nearly free from immutability; nothing Nitrite has today |
| Corruption containment, repair | **better** | partial availability; manifest rebuildable from segment headers |
| Multi-process readers | **better** | one writer, many reader processes |
| Observability | **better** | write-amp decomposition, locality debt, segments-probed — required, not optional |
| Security | **better** | AEAD over pages and records, an authenticated superblock, a wrapped key, crypto-erase, and — encrypted or not — no host deserializer on file bytes. MVStore has none of this; RocksDB and Hive have none of it; Fjall has none of it |
| Open latency, encrypted | **worse** | ~250–500 ms of Argon2id, once, deliberately |
| TTL, change feed, planner statistics | **better** | new capability |
| Mobile behaviour | **better** | frame-budget MUST, idle/charging scheduling, thermal hints, 1-I/O reads |
| Absolute file size | **better** | name dictionary + Zstd dictionaries |
| Read tail | **level** | round two brought it back under the old design |
| Portability | **level** | encodings untouched |
| Durability guarantee | **level** | as strong; harder to implement; better to recover |
| Point read of a whole document | **level on mobile/tablet, worse on desktop/server** | 1 I/O vs 2 |
| Scan returning documents | **level** | clustered by construction; enforced by test |
| Write p99 | **slightly worse** | paced and bounded, but compaction still exists |
| Space amplification | **worse** | ~1.2× mobile, ~1.5× desktop, against ~1.2× |
| Implementation complexity | **much worse** | the real cost, paid three times |

## 10. Is the trade right?

Yes, and round two removed the condition that round one had to attach.

Nitrite's workload is document CRUD with secondary-index maintenance, on a
phone, a tablet or a desktop. Round one's answer was one engine tuned for the
desktop case, with a documented regression on phones and a scan-decay risk
guarded only by a SHOULD. Round two makes the phone case a first-class profile
that avoids the regression entirely, and makes scan locality a structural
property enforced by a mandatory test rather than a background chore.

What remains genuinely worse is **space amplification** — bounded, tunable, and
much smaller on mobile — and **implementation complexity**, which is real and
does not go away.

The escape hatch still stands and is now a supported profile rather than a
fallback: raise `vlog_min` and the engine inlines everything, degrading into a
conventional lazy-levelled LSM with a bounded read tail. That is the `mobile`
profile. **The design can move the whole way along its most aggressive axis
without breaking a single file**, which is what makes it safe to build.
