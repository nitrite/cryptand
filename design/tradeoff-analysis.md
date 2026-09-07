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

### 8.2 Phase 3 of the reference implementation — five more

Phase 3 built the level policy (`04` §3.1), the manifest as a copy-on-write tree
(§3.2, §3.3), the per-level segment filters (§2.4), the catalog (`05`) and the
secondary indexes (`06`), and measured prediction **P10** — the one structural
claim that had no measurement at all. Building them found five things.

| | defect | fix |
|---|---|---|
| ⚠ 23 | **P10's bound belongs to the early exit, and neither `04` §4.1 nor `performance-model` §5.4 said so.** The arithmetic counts filter false positives only; a reader that examines every candidate — which `04` §4 *requires* absent the level-discipline proof — also probes every segment legitimately holding an older version. Measured: p99 1 / p99.9 2 with the early exit at every size from 10⁴ to 2×10⁵ documents; **p99 3 / p99.9 4** at 25 000 without it. | the condition is stated in both places, and `11` §6's new read-tail test requires an implementation to report which path it measured |
| ⚠ 24 | **`04` §4's level-discipline sentence predates §3.1's range-partition groups.** "L0 newest-flush-first, then strictly increasing level" gives no order *within* a tiered level, which now holds up to `overlap_bound` runs where one key may sit in more than one. Without that order the early exit of defect 23 is not actually available. | `segment_id` is globally unique, never reused and allocated from `next_segment_id`, so descending `segment_id` within a level is newest-first. Written into `04` §4 |
| 25 | **§4.1's attribution was backwards at the desktop shape.** It credited range-partitioned tiers with the bound and the filter with "the residue". Measured at 2×10⁵ documents: filter off takes the mean from 1.01 to 3.91 with range partitioning intact; range partitioning off leaves it at 1.01 with the filter intact. At `tier_width = 4` the filter carries the tail. | the table and the correction are in §4.1; range partitioning is credited where it is worth something — a wide tier, or a filterless build |
| 26 | **§3.1 gave no rule for output segment size, and both its bounds cannot hold without one.** A fixed size at every level made each tiered level cross `tier_width` after its *second* run and compact immediately, so no level ever held more than one run and range partitioning could not do anything. | `segment_entries(L)` is derived from `l0_trigger`, `overlap_bound` and `tier_width` in §3.1 — a writer rule, not a format rule |
| 27 | **The reference implementation's `get` did not consult the memtable.** Phase 2's read path walked segments only, so every write since the last flush was invisible to a point read. An implementation defect rather than a specification one — `10` §2 step 5 is unambiguous — but it survived 259 tests because every test called `compact()` first. | fixed, with a test that reads back an unflushed write |

Defect 23 has a shape worth naming, because it is the third time this project
has hit it: **a bound that is arithmetic on one mechanism, stated as a property
of the system.** §2.4's filter rate was classic-Bloom arithmetic applied to a
blocked filter; §6.9's `locality_debt` was arithmetic on the clustered flag
rather than on runs; P10 is arithmetic on false positives rather than on
versions. Each was right about its own term and silent about the one that
dominated.

There is also a **measurement** lesson, and it belongs here rather than in the
implementation report because it is about how these documents are validated. The
P10 benchmark's first version inserted keys in ascending order and reported
p99 = 1 for every shape **including both of its controls**. Sequential inserts
give every memtable flush a disjoint key range, so manifest pruning alone leaves
one candidate. A control that cannot fail has not controlled anything, and the
number it produces is not evidence — it is the shape of the harness. `11` §6 now
makes the write load part of the mandatory read-tail test for exactly this
reason.

### 8.3 Phase 4 — the language-independence audit, and one measured target that missed

Phase 4 was prompted by a reader's question: *does a portable storage format's
spec have implementation details in it, and does a feature require a particular
language?* The question named Argon2id as the example.

**On Argon2id the premise was wrong**, and the disproof is running code:
Argon2id is RFC 9106, and it is now implemented in **pure Dart with no
dependency**, alongside the BLAKE2b it is defined over, both reproducing their
RFCs' published vectors byte for byte. Naming an algorithm is the *opposite* of
a language dependency — a format that said "a memory-hard KDF" instead of
Argon2id with its parameters would have two SDKs derive different keys from one
password and neither able to open the other's file.

**On the general point the question was right.** The audit found leaks, all of
them requirements about the *host runtime* rather than about the bytes, and
`00-conventions.md` §1.1 is new and states the rule so the question has a
written answer next time.

| | defect | fix |
|---|---|---|
| 28 | `10` §7 made a **language** the subject of a MUST — "a Dart implementation cannot reach `F_FULLFSYNC` without FFI and MUST therefore report `sync` on Darwin" — and made a platform syscall table normative, one of whose entries (`FileChannel.force`) is a *Java API* rather than an OS primitive | two language-neutral MUSTs (use the strongest primitive available; record what you actually performed); the table is demoted to non-normative guidance |
| 29 | `11` §1.1's threadless carve-out was written against a language — "a single-isolate **Dart** implementation" — rather than the capability it means | written against "a runtime without shared-memory threads", with Dart and JavaScript as worked examples |
| 30 | `11` §7 named **Rust** as *the* reference implementation inside the normative conformance chapter, two sections after the mandatory test list | marked non-normative; the reference's language is a project decision, and §7 already said the reference is not normative |
| 31 | `14` §11 stated key-material handling as a normative table with **Java / Dart / Rust** rows | rules keyed to language *properties* — immutable or interned strings, moving collectors, deterministic destruction — with the three SDKs as a non-normative note |
| ⚠ 32 | **`14` §3.2's Argon2id cost targets are unreachable where they matter most.** They were costed against a native implementation with parallel lanes. Measured in pure Dart on an M2 Pro: `mobile` **405 ms** against "~250 ms on a mid-range ARM", `desktop` **2183 ms** against "~500 ms". `mobile` is `p = 1`, so it has no lanes to recover with, and it is also the profile most likely to be running an interpreted or JIT runtime | §3.2 states the assumption and names three conforming ways out, of which a hardware-backed platform keystore (`kdf = 0`) is the right answer on a phone and removes the cost entirely |

Defect 32 is the interesting one, because it is the first time this project has
found a **profile constant** wrong rather than a mechanism. The others in §8.1
and §8.2 were rules that would return a wrong answer; this one returns the right
answer too slowly, on the device the profile exists for, in the runtime that
device most often runs. That is a different failure mode and it is only visible
by measuring — no amount of re-reading §3.2 would have shown it, because the
table is arithmetically fine and simply assumed a faster implementation than the
one the profile targets.

One claim in the audit was itself wrong and is recorded because the correction
matters: **Level 0 was said to be unreachable for a single-threaded runtime, and
it is not.** `11` §1.1 already had the carve-out and §1.2 already had a
`single-writer` reduced write profile. The mechanism was right; only its wording
named a language. A format that had genuinely barred a threadless language from
full conformance would have contradicted the proposition on the first page, and
it does not.

### 8.4 Phase 5 — chapter 10, and a levelled level that had quietly stopped being disjoint

Phase 5 implemented `10-transactions.md` apart from §2's concurrent write
protocol, which needs threads this SDK does not have: snapshots (§1), the commit
and its ordering invariants (§2.3), transactions with snapshot / read-committed
/ serializable / read-only isolation, conflict detection and savepoints (§3),
recovery (§4), the normative backpressure curve (§6), durability reporting (§7),
retention watermarks (§8), store events (§9) and close (§10). Three defects, and
the first is the most serious this project has found.

| | defect | fix |
|---|---|---|
| ⚠⚠ 33 | **The last level's disjointness test compared whole internal keys, so the level silently stopped being disjoint.** An internal key carries `~seq`, so two segments holding *different versions of one user key* occupy disjoint internal-key ranges; the overlap test reported "no overlap", the compaction left both in place, and §4's early exit then stopped at whichever it reached first and **returned a stale version**. Every structural check still passed — `min_key`, `max_key`, `subtree_entries`, every checksum | disjointness is over `u32be(tree_id) ‖ CKE(key)`, stated as new `04` §3.1.1, and `01` §9 step 3's verifier check says so too |
| 34 | **`min_retained_seq` floors at `visible_seq`, so a watermark that never advances makes retention unbounded.** Compaction can then never satisfy §5's condition 2, keys never collapse, and the key index grows without bound while the value side looks healthy — measured as an aged scan's key pages going 34 → 369 with value pages unchanged | `10` §8 now says the watermark advances whenever a batch's records become durable, which for a single writer is the flush of §2 step D |
| 35 | **`pinned_by_snapshots` is not `allocated − live`.** A snapshot's effect is to stop superseded versions from *becoming* dead, so the bytes it pins never enter that difference; the obvious derivation reads **0** on a database holding a large pinned set. `13` §6 listed the metric without saying how to derive it | `13` §6 now says where to accumulate it: at the retention decision itself |

**Defect 33 is worth dwelling on, because of how it stayed hidden.** An engine
that drops every superseded version at the last level has exactly one entry per
user key there, so internal-key and user-key disjointness *coincide* and the
test is accidentally correct. It only diverges once versions are genuinely
retained — which requires a live snapshot, which requires §5's condition 2,
which is precisely what phase 5 added. The defect was present through phases 3
and 4, under 338 passing tests including a read-tail benchmark whose whole
subject is which segments cover a key.

That is the same shape as §8.1's defect 9 and §8.2's defect 23: **a rule that is
correct under an assumption nobody wrote down**, holding until the assumption
stops. Here the unwritten assumption was "the last level holds one version per
key". Two of the three phases-3-and-4 defects were of that kind too, and it is
now the most common failure mode this project has found — more common than
arithmetic errors, and much harder to see by reading.

### 8.5 Phase 6 — range deletes, TTL, containment, metrics

Phase 6 completed `04-segments.md` — range deletes (§2.5) and time to live
(§9) — and built the operational surface every conformance level requires:
corruption containment (`13` §4) and the required metrics (`13` §6).

**Two of the four are mandatory conformance tests**, and both now exist:
the range-delete-under-filter test, and the containment test. The first is the
one whose failure mode is a *resurrected deleted key*, and the construction it
needs is specific: the segment carrying the range delete must not hold the
deleted key as a point key, so its filter genuinely answers "absent" — the test
asserts that the filter would prune it before asserting that the key is still
deleted, because otherwise the test passes for the wrong reason.

**One defect, and it is a gap rather than an error:**

| | defect | fix |
|---|---|---|
| 36 | **§4 mandates corruption containment; §6's required-metric list gave no way to observe it.** A partially-available database is therefore indistinguishable from a healthy one until a read happens to land in the hole — the caller cannot ask "is this database whole?" at all, which is exactly the class of question §6 exists to make answerable | `unavailable_ranges` added to §6, with 0 as the normal state |

Worth recording what *did not* happen: range deletes and TTL were implemented
from the chapter with **no defects found**, first run, fourteen tests green.
Those two sections are among the oldest in the document and among the least
revised — which is mild evidence that the defect density this project has been
reporting is concentrated in the parts that were rewritten under review, not
spread evenly. A section rewritten three times has had three chances to acquire
an unwritten assumption; §2.5 is nine lines and has had none.

### 8.6 Phase 7 — checkpoints, planner statistics, and a bound on the wrong dimension

Phase 7 built `13-operations.md` §1 (checkpoints) and §9 (planner statistics),
and added `11-conformance.md` §6's **mandatory stale-version test**.

| | defect | fix |
|---|---|---|
| 37 | **§9 bounds the histogram in the wrong dimension.** It caps the bucket *count* at 64 and specifies CKE keys as bounds — but a CKE key runs to kilobytes, and `params.stats` lives in a catalog descriptor, which is one cell of a copy-on-write B+tree and MUST fit one page. Measured: 64 bounds over 300 string keys came to **4734 B against a 4096 B page**, and the descriptor could not be written at all | §9 now bounds it in **bytes**, with the count as a maximum rather than a target, and says to drop alternate buckets so the histogram stays equi-depth at twice the width |

Defect 37 is a small instance of a pattern this document has now recorded four
times: **a bound stated over the quantity that is easy to count rather than the
one that is actually scarce.** §2.4's filter rate was arithmetic on the wrong
Bloom structure, §6.9's `locality_debt` counted flags rather than runs, P10
counted false positives rather than versions, and §9 counts buckets rather than
bytes. In each case the stated bound was *satisfiable* while the real constraint
was violated.

It is also the first defect found by the format's own layering rather than by a
measurement: nothing about statistics is wrong, and nothing about the
copy-on-write trees is wrong — the two chapters were each internally consistent
and disagreed only where they met. That is the failure mode a single-chapter
review cannot catch, and it argues for the implementation order this project has
been using, where a later chapter is built on top of an earlier one rather than
beside it.

**What phase 7 did not find:** checkpoints went in from §1 with no defects, and
the section's two load-bearing rules — that `checkpoint_root` is deliberately
not captured, and that a restore rolls back roots but never counters — were both
directly implementable and are both now tested. The second is the one with a
security consequence, and it is worth noting that the *reason* it works in the
reference implementation is a simplification recorded back in phase 3: the page
store never reclaims freed pages, so an old copy-on-write root is still readable.
A production implementation reclaiming pages under `min_retained_commit` gets the
same property from the retention rule instead — and a checkpoint that pins
retention is exactly what makes that safe.

### 8.7 Phase 8 — the verifier, repair, profiles, and a mandatory test that failed

Phase 8 built the verification pass of `04-segments.md` §11, the manifest
rebuild of `13-operations.md` §3, and `12-profiles.md` — which between them
close the last two mandatory conformance tests this SDK can run.

| | defect | fix |
|---|---|---|
| ⚠ 38 | **`11-conformance.md` §6's mandatory profile round-trip test asks for a conversion the format forbids.** It named `mobile → desktop → mobile`; `12-profiles.md` §6 says `page_size` "cannot change. It is fixed at creation", and `mobile` is 4 KiB while `desktop` is 8 KiB. **The mandatory test could not be run by a conforming implementation** | §6 now requires the two profiles to share a `page_size`, names `mobile ↔ tablet` as the usable 4 KiB pair, and suggests additionally asserting that the forbidden change is *refused* |
| 39 | **A scan sourced its cursors from the extent map rather than from the manifest**, so it read segments the manifest had retired. Invisible while compaction keeps the two in step — and wrong the moment they are not, which phase 7's checkpoints made reachable: after a restore the manifest points at an older root while every later segment's bytes are still present, so a scan returned the data the restore was supposed to abandon | scans go through the manifest; implementation-level, but it is the same *shape* as defect 33 and worth counting |
| 40 | **`group` was written into every segment header as 0 while the manifest recorded the real value.** Caught by §11.5, the header-against-manifest check — on its first run, against a database the engine had just written | the group is decided before the outputs are built rather than after |

**Defect 40 is the one that justifies a written rule.** `13-operations.md` §3
says a verifier "MUST check header-against-manifest agreement on every
duplicated field, or the redundancy rots unnoticed until the day it is needed".
That is exactly what had happened: the rot was total — *every* segment above the
last level disagreed — and nothing noticed, because nothing had ever compared
them. And the consequence was not cosmetic: `rebuildManifest` reads `group` back
out of the headers, so a repair would have re-filed two disjoint runs into one
group, which then overlaps, which breaks §4's early exit. **A repair that
silently corrupts the level structure is worse than no repair.**

It is also a small vindication of the format's own design: `group` is duplicated
into the header *for no other reason* than the rebuild, the spec says so, and
the first time anything checked the duplication it found it broken.

### A mandatory conformance test that this implementation failed, and now passes

`12-profiles.md` §4's foreground stall budget is normative for every profile,
and phase 8 measured the reference implementation **failing it**: a `put` that
filled the memtable ran the flush and the whole compaction cascade
synchronously, at **22.3 ms against `mobile`'s 8 ms budget**, 2.8× over.

Phase 9 fixed it by building what §5.2 has always required — a compaction
decomposed into `compaction_step_bytes` steps with a yield between them, held
as a resumable job whose partial output is published only when it finishes.
Measured after: **worst 3.10 ms, p99.9 2.46 ms, 0 of 4000 puts over the
budget**, with a control confirming the bound is what does it (unbounded steps
on the same workload: 10.03 ms worst, 1 violation).

Two honest notes attach to that number. The first measurement of the fixed
engine still showed a single 21.7 ms `put` — at index 199, the *first* flush,
while the identical flush a moment later cost 0.7 ms. That is Dart's JIT
compiling the segment builder on first execution, not the decomposition;
Flutter ships release builds AOT-compiled, so it does not arise on the target
this profile exists for, but on a JIT runtime the first write of a cold process
really does stall and the benchmark warms the path deliberately rather than
quietly. The second is that §5 of `12-profiles.md` says thermal behaviour "is
measured, not modelled" on a real mid-range device, and this is a desktop.

### 8.8 Phase 9 — clearing the board

Phase 9 fixed everything phases 1–8 had left outstanding rather than merely
recorded. Two items:

**`04-segments.md` §5.2's stepwise compaction, which was the only mandatory
conformance test this implementation failed.** Built as a resumable
[CompactionJob]; the foreground path now does `compaction_step_bytes` of merging
and returns. §5.2's own argument is what makes the state cheap to hold — "the
partially built output is just a prefix — abandoning it costs the work done and
nothing else, and no reader can see it" — and that is now exercised directly: a
test abandons a part-done job mid-cascade and asserts that no reader can tell.

It also changed an API boundary in a way worth recording, because it is §4's
distinction made real: **a `flush` no longer drains the level policy.** Bounded
work happens on the caller; a caller who wants the shape settled calls
`drainCompaction()`, which is the "explicitly requested bulk operation" §4
exempts. P10's benchmark had been relying on the implicit drain and had to be
told to ask — and P10 *improved* once it did, from p99.9 2 to p99.9 1 at three
of the five sizes, because the settled shape is reached more cleanly than the
old cascade-inside-flush reached it.

**Metrics that reported plausible constants for quantities nothing measured.**
`13-operations.md` §6 exists so that questions are answerable from outside, and
a fabricated answer defeats that more thoroughly than a missing one:
`page_cache_hit_rate` returned 1.0 and `unencrypted_pages` returned 0 from an
engine that measured neither. Four are now really measured
(`page_cache_hit_rate`, `value_reads_per_scanned_row`,
`compaction_backlog_bytes`, `stall_events`) and the four that cannot be are
**declared unavailable by name** rather than given a value.

That second item is not a spec defect — §6 lists what to expose and says nothing
about what to do when you cannot. But it is worth a sentence in §6, because "MUST
expose" invites exactly the failure it got here.

### 8.9 Phase 10 — chapter 13 finished, and no defects

Phase 10 built the rest of `13-operations.md` that a single-process
implementation can build: §2 (backup, full and incremental), §5 (the
compaction, space and key-management API) and §7 (the change feed). Nineteen
tests, green on the first run, **no defects found**.

That is worth a sentence rather than silence, because it is the second time
(after phase 6's range deletes and TTL) that a chapter has gone in clean, and
the two have something in common: **both are sections that were written once and
not revised under review.** §8.6 already noted the pattern; phase 10 is more
evidence for it. The chapters that have produced defects — `04` §3–§6, `06` §7,
`10` §5, `13` §9, `14` §3.2 — are the ones that were rewritten between review
rounds, and the rewriting is where the unwritten assumptions entered.

Three of §2's rules are worth recording as *implemented* rather than merely
described, because each is a MUST whose violation is silent:

- a backup MUST NOT copy the source's `database_uuid` — and the reason is not
  tidiness: `14-security.md` §3.4 derives every subkey with the uuid as HKDF
  salt, so two files sharing one **share a content key**, and a nonce that
  repeats across them is a real collision;
- the **ciphertext copy is the exception**, for exactly that reason — it is the
  same cryptographic object, so it keeps the binding, and therefore MUST NOT be
  opened for writing while the source is, since two writers allocating from one
  `next_nonce` lineage collide;
- an unencrypted backup of an encrypted database is a **silent downgrade** and
  MUST be refused unless asked for by name.

`13-operations.md` §8, multi-process readers, is the one section left. It cannot
be built here in any meaningful sense: the whole content is a lock sidecar
coordinating *processes*, and this implementation has no file under it.

### 8.10 Phase 11 — full text, and the claim the whole project rests on

Phase 11 built `07-fulltext.md`: the `cryptand.std.v1` analyzer, the three
trees, the postings block layout, and the `analyzer/` conformance vector set
`11-conformance.md` §6 names. **No defects found.**

The chapter opens by saying the analyzer is the hard part — "Two implementations
that tokenize `"Bäckerei-Straße 12"` differently will produce two indexes that
disagree about what documents exist" — and `README.md` names full-text
tokenization as one of the **two genuinely hard parts** of the whole
proposition. So the result worth recording is not that it was built, it is what
it was checked against.

Dart's standard library supplies **none** of what §2.2 requires: no NFKC, no
UAX #29 word segmentation, no `Simple_Lowercase_Mapping`. `String.toLowerCase()`
is close, and close is exactly what produces two indexes that disagree. All
three were therefore implemented against tables generated from the **Unicode
15.1.0 UCD** — the release §2.2 pins — and verified against Unicode's own
published conformance suites:

| suite | cases | failures |
|---|---|---|
| `NormalizationTest-15.1.0` (NFC and NFKC) | **19 074** | **0** |
| `WordBreakTest-15.1.0` (UAX #29) | **1 826** | **0** |

Both passed on the first run, and both data files are now committed under
`reference/conformance/unicode/` so the check is reproducible rather than
anecdotal.

**This is the strongest evidence the project has produced for its central
claim.** §1.1 of `00-conventions.md` argues that naming an algorithm is what
makes a format portable rather than what constrains it; phase 4 demonstrated it
for Argon2id, where the vector set is a handful of cases. Full text is the case
where the argument is hardest to believe — the analyzer is a pipeline of eight
steps over the entire Unicode character database — and it holds there too: a
language whose runtime offers none of the required operations reproduced all
20 900 published cases from the specification alone.

The corollary is the one §2.1 already states and is worth repeating with the
evidence attached: an implementation that *cannot* do this MUST NOT write to a
full-text index. That rule now has a measurable meaning — run the two suites, and
if either reports a failure, the implementation is in the class §2.1 excludes.

### 8.11 Phases 12 and 13 — spatial and vector, and the end of the chapter list

Phase 12 built `08-spatial.md` — ISO WKB, the in-container R-tree, the exact
predicates — and phase 13 built `09-vector.md` — the `VECTOR_REGION` layout, the
adjacency record, the codebook, the slot↔document maps and §8's search
contract. **No defects found in either.**

With those, **every chapter of the specification has an implementation**, and
the remaining gaps are all of one kind: they need something the runtime does not
have (threads for `10` §2, processes for `13` §8) or they are a published
algorithm deliberately declared rather than approximated (`porter2` in `07`
§2.4).

Two rules are worth recording as enforced rather than described, because both
are cases where a plausible implementation is silently wrong:

- **`08` §1's EWKB rejection.** PostGIS signals Z, M and SRID by setting high
  bits of the same type word ISO uses additively, so "a `PointZ` is `1001` in
  ISO and `0x80000001` in EWKB, and a decoder that guesses wrong reads
  coordinates as garbage". A reader that accepted both would produce geometry
  that decodes without error and means nothing. All three flag bits are refused.
- **`08` §4's two-phase rule.** "An implementation MUST NOT return box-level
  results as if they were exact." The test that proves it uses a triangle whose
  bounding box contains the origin and whose area does not: the candidate phase
  returns it, the exact phase rejects it, and a box-only implementation would
  return a wrong answer that looks entirely reasonable.

`09` earns a note of its own for what it *did not* require. The chapter's
principle — "specify the durable layout, not the algorithm" — is why a vector
index fits in a few hundred lines here: there is no HNSW construction, no
Vamana, no recall tuning, because none of that is in the format. What is in the
format is the region, the adjacency record, the two maps, and the rule that
makes interchange work at all: an implementation that will not traverse another
SDK's graph "MUST then fall back to a brute-force scan of the vector region,
which is always possible and always correct, rather than returning nothing."
That fallback is what lets a Flutter app open a database whose vector index only
a Rust service knows how to build — which §9 calls "the specific interchange
scenario this whole format exists for".

### 8.12 Phase 14 — the stemmer, and a version that was not pinned

Phase 14 implemented `07-fulltext.md` §2.4's `porter2` stemmer, which every
previous phase had left as a deliberate refusal. It is verified against
Snowball's **own 42 649-word vocabulary**, zero failures, and it found a defect.

| | defect | fix |
|---|---|---|
| ⚠ 41 | **§2.4 named an algorithm family, not a release.** It wrote `porter2:<lang>` and justified it with "an unambiguous published algorithm" — true of a given Snowball *release*, not of the name. Snowball's change log records behavioural changes at 3.0.0 (`past`/`paste`, `universe`/`university`, `lateral`/`later`, `emerge`/`emergency`, `organ`/`organic`, `-ogist` → `-og`) and 3.1.0, and one 3.1.0 entry **reverses** a 3.0.0 one — "Removed exception for skis", then "Restored exception for skis which is needed" | the stored form is `porter2:<lang>:<snowball version>`, an implementation records and checks its release, and a new release is a new stemmer name — §2.2's Unicode treatment, applied to the other pinned algorithm in the same chapter |

**Defect 41 is the most self-inflicted one this project has found**, and that is
what makes it worth recording. §2.2 of the *same chapter*, two subsections
earlier, gets this exactly right: it pins Unicode 15.1, explains that a moved
boundary silently changes what documents an index contains, and requires
`cryptand.std.v2` rather than a silent upgrade. §2.4 then names a second
versioned external algorithm and omits the same precaution.

The generalisation is worth stating because the format names four external
algorithms in total: **every dependency on an external specification needs its
version in the file, not merely its name.** Unicode had it. Snowball did not.
RFC 8439 and RFC 9106 are safe by accident — they are frozen documents rather
than evolving projects — which is a property of those particular references and
not a rule the format can rely on.

It is also the second time a defect has been found by *implementing against the
authority's own conformance data* rather than by reasoning: the Unicode suites
found nothing wrong because §2.2 was right, and Snowball's vocabulary found this
because §2.4 was not. A published test corpus does not only check the
implementation.

### 8.13 Phase 15 — a second implementation reads the vectors

Phase 15 is the first phase that did not add a chapter. It built an independent
Rust implementation of the format's byte layer — `reference/rust/cryptand-conformance`
— written from `spec/` and checked against the vectors the Dart implementation
generated. Until it ran, "portable" was a claim: **the vectors were produced by
the implementation they test, so they caught regression but never misreading.**

Forty-one tests over nine of the ten vector groups (CKE, the numeric torture
set, CVE, strings, documents, the container, the filter, security derivation,
index entries and the catalog) reproduced byte for byte. The analyzer group is
not ported — it needs the Unicode 15.1 tables and `porter2` again, and it is a
phase of its own.

| | defect | fix |
|---|---|---|
| ⚠ 42 | **`filter/blocked_bloom.json` called 16 bytes `header_bytes` when the filter page header is 20.** The generator wrote `payload[0..16]`, stopping four bytes into the `u64 distinct_keys`. A consuming SDK that trusted the field's *name* rather than re-deriving §2.4's layout builds a 16-byte header, so every 64-byte block lands four bytes early: probes read the wrong bits and the filter returns false **negatives**, which is the one filter failure mode that loses data silently | record all 20 bytes, plus a `header_note` naming each field and stating that the blocks begin at byte 20 |
| 43 | **`03-key-encoding.md` §7's MUST-reject list was incomplete.** A key whose type code says integer over an ordering region that is not an integer (`m x 2^e` with a fractional part at that exponent, or an exponent above the declared width) was not named, so truncating, rounding and refusing were all conforming | §7 now requires refusal, with the reason: a decoder that rounded would return a value no writer encoded, and two decoders that chose differently would disagree about the same bytes |

**Defect 42 is the one that argues for this whole phase.** It is not a mistake
about the bytes — the recorded bytes are correct as far as they go — it is a
mistake about *what the vector says they are*, and no amount of re-running the
generating implementation could surface it, because that implementation knows
what it meant. A vector's field name is part of its contract with a reader who
has nothing else.

Defect 43 arrived the other way round. Both implementations already refused the
malformed key, independently, with almost the same error message — the spec was
simply silent about a case two careful readers happened to agree on. Agreement
by coincidence is not portability; a third implementation reading the same §7
would have been free to truncate. The rule is now written down.

**The remaining finding is not a defect and is the phase's main result:**
everything else reproduced on the first run. CKE's escaped byte strings, the
complemented negative ordering region, the exponent bias, the document field
table's sort-by-resolved-name-bytes rule, the `name_ref` inline index, the
20-byte filter header, HKDF's `database_uuid` salt, the 56-bit nonce offset, the
index cartesian product with its `\.` path escape, and the catalog descriptor's
byte-exact re-encode were all recovered from the specification alone by a reader
that never saw the Dart source. That is the strongest available evidence for
`00-conventions.md` §1.1, and the first that does not come from the
implementation being tested.

One process note, since it cost time: `tool/generate_vectors.dart` contained two
literal NUL bytes (in the `'a\u0000b'` string cases), which made `file(1)` call
it `data` and made `grep` treat it as binary and print nothing. A search for the
filter generator returned no matches and very nearly produced a wrong finding —
that the filter vector was not generated at all. The literals are now escapes.

### 8.14 Phase 16 — P3 measured, and a claim that belongs to the host

Phase 16 built `reference/rust/cryptand-write`: `10-transactions.md` §2's
writer and committer, §2.2's requirements and §2.3's three ordering invariants,
over real files with real threads. It closes the item every report since phase 5
has carried — Dart has no shared-memory threads, so **P3 could not be measured
at all**. Twelve tests; the interesting ones are the three invariants, each of
which produces a database that opens cleanly and is wrong when violated.

**P3's own-scaling half is CONFIRMED, and better than predicted — in a durable
mode.** 1 → 32 writer threads, 512-byte values, `sync`:

| threads | disjoint | scale | overlapping | scale | p50 |
|---|---|---|---|---|---|
| 1 | 388 /s | 1.00× | 347 /s | 1.00× | 3.0 ms |
| 4 | 915 | 2.36× | 738 | 2.13× | 4.2 ms |
| 8 | 1 782 | 4.59× | 1 696 | 4.89× | 4.3 ms |
| 16 | 3 184 | 8.20× | 2 891 | 8.33× | 5.1 ms |
| 32 | 5 749 | **14.80×** | 5 439 | **15.68×** | 5.6 ms |

It does not plateau at the 8–16 threads the prediction expected, and p50 stays
flat while throughput rises 15×: that is §2.4's group commit, one barrier
amortized over a growing commit group. The overlapping case tracks the disjoint
one within 6 %, so memtable-shard collisions are not a factor at this width.

| | defect | fix |
|---|---|---|
| ⚠ 44 | **P3 does not name a durability mode, and the answer inverts with it.** Under `os` — the same protocol with the barrier removed — throughput peaks at **two** threads and falls to 0.84× by 32. Both numbers are honest measurements of "insert throughput versus writer threads"; they disagree because in a durable mode the shared cost is a barrier that amortizes, and in a non-durable one it is the host's write path, which does not | P3 states the durable configuration, and reports the non-durable one as a separate line rather than as the same prediction |
| ⚠ 45 | **§2.1 credits the design with a property of the host.** "N writers drive N independent append streams into the device" is asserted as a consequence of having no write-ahead log. Measured on macOS/APFS at 512-byte records, concurrent `pwrite` at disjoint offsets in one file runs **380 757/s at one thread and 97 542/s at 32** — and spreading the identical writes over **one file per thread** degrades the same way, 629 266 → 159 039. So the format's one-file rule is not the cause, and the parallel-stream claim is a statement about the operating system's write path, which `00-conventions.md` §1.1 says must be a declared capability rather than an asserted property | §2.1 states the *obligation* — never funnel writers through one journal offset or one shared buffer — and reports what the design actually buys where the write path does not scale: the group-commit amortization above |
| 46 | §2.1's cost table says the shared counter is "~20 ns even at 64 threads". Measured: 11.1 ns at 1 thread, 51.9 at 8, **59.9 at 64** | the figure is 3× optimistic and now says so. It changes nothing — 60 ns is 0.02 % of a batch — and the *shape* of the claim survives, which is the point of measuring it |

**Defect 45 is the phase's real result, and it is the same shape as defect 28.**
Phase 4 found a normative MUST written against a language ("a Dart
implementation cannot reach `F_FULLFSYNC`…"); this is a performance claim
written against an operating system. §1.1's rule was formulated for the first
and applies unchanged to the second: state the obligation, let the
implementation declare what it achieved. What makes this one costlier to have
missed is that the parallel-stream argument is the **headline** of the write
design — it is the sentence that justifies having no write-ahead log at all.

The justification survives, but for a different reason than the one written
down. With no WAL there is no journal offset to serialize on and no group-commit
leader, so a commit group's cost is one barrier over *n* batches no matter how
many threads produced them — which is exactly the 14.8× above. The parallel
streams may or may not materialise, depending on the platform; the absent
journal is a property of the format and is there on every platform.

**Where the ceiling actually is, decomposed rather than guessed:**

| shared thing | 1 thread | 32 threads | |
|---|---|---|---|
| the one `fetch_add` | 11.1 ns | 59.9 ns (at 64) | not the ceiling |
| the committer handoff — one mutex-guarded queue plus a notify | 35 320 088 /s | 22 601 597 /s | 60–100× above the achieved rate; not the ceiling |
| `pwrite`, one file | 380 757 /s | 97 542 /s | **the ceiling** |
| `pwrite`, one file per thread | 629 266 /s | 159 039 /s | the same ceiling, so not the one-file rule |

**And P3's own stated fragility is real, and now has a number on it.** The
prediction warns: "if the committer becomes the bottleneck (one thread building
segments for many writers), scaling stops early." This crate builds no segments,
so the benchmark injects the cost rather than pretending it away — 1 versus 16
writers under `sync`:

| committer work per batch | scale at 16 writers |
|---|---|
| 0 µs | **9.23×** |
| 25 µs | 8.72× |
| 100 µs | 6.68× |
| 400 µs | **3.49×** |

Segment building has to stay under roughly 100 µs per batch for the mitigation
in §2.1 — each memtable shard flushing its **own** L0 segment, so segment
building parallelizes too — to be optional rather than required. That mitigation
is in the format; an implementation still has to do it.

*A note on method, since this project keeps relearning it.* The first version of
that sweep ran under `os`, where scaling is already flat, so every row read
about 1× and the knob appeared to do nothing — a control that cannot fail,
measuring nothing, for the fourth time in this project's benchmarks. The sweep
belongs in the configuration that scales.

### 8.15 Phase 17 — multi-process readers, and two header fields no rule read

Phase 17 built `13-operations.md` §8's lock sidecar in
`reference/rust/cryptand-write`, with **real processes** — the last part of the
specification that no implementation had touched, and one that cannot be
exercised any other way. Twelve tests: the protocol's arithmetic in-process,
and slot claiming, retention pinning, heartbeat expiry and a claim race run
across separate spawned processes.

The chapter is small and its rules are individually right. What it was missing
is what happens when the shape it assumes is not there.

| | defect | fix |
|---|---|---|
| ⚠ 47 | **The sidecar header declares `writer_pid` and `writer_heartbeat_ms`, and no rule in §8 read either.** They are not decorative: with rule 3 attributing reclamation to the writer alone, a database whose writing process has died — or that never had one, which is two `dbinspect` sessions against a file no application currently holds — reclaims nothing. Stale slots accumulate, and after `slot_count` reader opens **every later reader silently falls to volatile mode**, for a reason it cannot see, against a database where volatile mode protects against a reclamation that will never happen | rule 1 makes a stale slot a free slot **to a claimer**, so reclamation is not the writer's alone; rule 5 gives the two header fields their purpose — the writer refreshes on the same schedule, and a reader treats an absent or aged-out writer as "no live writer" and reports it |
| 48 | **Rule 4's volatile mode was written for one cause and reached by two.** "A reader that cannot write the sidecar (read-only filesystem)" says nothing about a sidecar whose slots are all held, so an implementation could error, block, or silently degrade, and two SDKs could each be conforming while behaving differently | rule 4 covers both, and requires the implementation to report **which** — a downgrade whose cause is invisible is the failure mode this chapter exists to prevent |
| 49 | **§8 never says the sidecar is host-local.** It depends on the platform's advisory locking and on a clock shared between the processes reading it, and a network filesystem gives neither. Nothing stopped an implementation from claiming `MULTIPROC_READ` across two hosts, where both mechanisms fail quietly | §8 puts a database opened concurrently from two hosts outside `MULTIPROC_READ`, SHOULD-refuses it, and forbids reporting a coordination that was not achieved |

**Defect 47 is the chapter's own principle turned on it.** Rule 4 requires a
volatile reader to *report* the mode, precisely because reading without a pin is
a downgrade someone must know about. The gap made that report arrive for an
invisible reason, at a moment when it was also unnecessary — the worst of both,
and reachable by nothing more exotic than the writing application exiting.

**A note on what "compare-and-swap" means on a file.** §8 says a reader claims a
slot with a CAS. A plain file offers no cross-process atomic word, so the claim's
read-scan-write runs under an exclusive advisory lock on the sidecar. That is
the CAS, it is taken once per reader open and never on the heartbeat path, and
twelve processes racing for twelve slots produced twelve distinct slots. The
spec's word is the right one; it is worth writing down that it is satisfied by a
lock rather than by an instruction, because an implementer looking for
`compare_exchange` will not find one.

### 8.16 Phase 19 — the definition of value order, tested for the first time

`02-value-encoding.md` §8 is the chapter that opens *"defined here once, for all
SDKs, ending the current divergence"*. A coverage run across the three
implementations found it was the least tested chapter in the project, and the
reason is worth stating plainly: **it is the one chapter whose output never
reaches a file.** Every other chapter is checked by the cross-language round
trip, because a disagreement changes bytes. §8's order is consumed in memory,
by sorts and equality checks, so three implementations could disagree
completely and every conformance vector, every interop direction and every
verifier would still pass.

They did disagree. Coverage before this phase: Dart `compare.dart` **0 of 144
lines**, Rust `compare.rs` **7 of 134**, and Java had **no implementation of §8
at all** — it had CKE's byte comparison and nothing that ordered values.

| | defect | fix |
|---|---|---|
| ⚠ 66 | **Rule 10 defers to `03-key-encoding.md` §2's tag table for cross-type order, and that table has no entry for `DOC` or `MAP`** — correctly, since it is a table of *key* group tags and neither has a key encoding. But rule 8 orders them, so the order §8 calls total was not. Dart ranked `DOC` below `MAP`, using `0xB0`/`0xB1` — inside the range §2 **reserves**; Rust ranked `MAP` below `DOC` at `0xA1`/`0xA2`. Two shipped implementations, opposite answers, and nothing could observe it because the ranks are never written to a file | rule 10 gains the two ranks explicitly, as **ordering ranks and not group tags**: `ARRAY < MAP < DOC`, which is the order rule 8 itself lists them in. `0xB0`–`0xEF` stay reserved. Dart moved |
| ⚠ 67 | **Comparing two values §8 does not order returned "equal" in Rust.** The closing paragraph made using them as an index key an error and said nothing about comparing them, and an infallible `Ordering` signature has no other answer available. Measured: `values_equal` on two **different** `GEOMETRY` values returned `true`. That is not a conservative default — it makes them indistinguishable to a sort, a deduplication and an equality check, silently | §8 makes the comparison itself an error, and forbids returning equal. `compare_values` is now fallible in Rust, as it already was in Dart. An unordered value *inside* a container is still ranked deterministically, because sorting a list of documents has to stay defined |
| 68 | **Every `DEC128` compared equal to every other, and to integer zero.** Rule 2 puts `DEC128` in the numeric domain; Rust routed it to `compare_numeric`, whose exact decomposition has no case for it, so it decomposed to zero. `DEC128(5)` tested equal to `INT(0)`. The code even said the caller avoids this, and nothing made the caller avoid it | §8 requires an implementation without exact decimal arithmetic to **refuse** rather than approximate. Both now refuse, as Dart already did |
| 69 | **Dart's own header named `test/cke_order_test.dart` as "the single most important test in this package".** That file had never existed. `cke_test.dart` does test the numeric ordering invariant — against a `referenceCompareNumeric` local to the test, so the *shipped* order and the *shipped* key encoding were never compared to each other | §8 now requires the agreement test by name: `sign(compare(a,b))` and `sign(memcmp(CKE(a), CKE(b)))` over every key-encodable pair. Written in all three: Dart +26, Rust +24, Java +24 tests |

**The pattern, and it is the project's oldest one.** Defects 66 through 68 are
each *a rule that is correct under an assumption nobody wrote down* — rule 10
assumed every ordered type has a group tag; the closing paragraph assumed
"cannot be a key" and "cannot be compared" are the same sentence; rule 2 assumed
an implementation in the numeric domain can do decimal arithmetic. Defects 9, 23
and 33 were the same shape.

**What is new here is the reason they survived so long.** The cross-language
gate is this project's strongest instrument and it is blind to anything that
does not change a byte. Chapter 08's EWKB rejection, chapter 14's page
encryption and chapter 04's disjointness were all eventually caught by a file;
§8 cannot be. A chapter whose output is not durable needs a test that names the
invariant, because there is no file to disagree about.

**A control that cannot fail, the sixth time.** The first version of the pair
sweep contained no character in `U+E000`–`U+FFFF`. UTF-16 code-unit order and
UTF-8 byte order differ only for a pair that straddles the surrogate range, so
replacing the comparison with Java's `String.compareTo` — the exact mistake the
rule exists to prevent — left the 20 000-pair sweep passing, and only the
hand-written rule 4 case failed. Adding `U+FF61` to the corpus makes the sweep
itself the control: the same substitution now fails two tests.

### 8.17 Phase 20 — the codec nobody wrote

`01-container.md` §7 says LZ4 is "the default and the only codec a Level-0
implementation MUST support", and `12-profiles.md` §1's table gives every
profile a `page_codec`. A coverage run found the row was fiction: **compression
was in no write path in any of the three implementations.**

| implementation | what it had |
|---|---|
| Rust | a correct `codec.rs` over `lz4_flex`, and an `encode_data_page` with **no callers**; the pager never mentioned `COMPRESSED` |
| Java | `Lz4.decompress` wired into the pager's read path and **0 % coverage**; the write path *cleared* `flags.COMPRESSED` and set `codec = 0` |
| Dart | **no LZ4 at all**, and no code path that read `flags.COMPRESSED` anywhere |

All three wrote `page_codec = 0`, so the twelve-direction interop gate passed —
and would have kept passing forever. The conformance vector recorded
`page_codec = 0` at offset 177, which is a superblock no conforming `mobile`
writer would produce, so **the vector encoded the defect**.

**This is defect 58's shape a second time**, and the resemblance is exact: the
primitive existed, was correct, and was called only from somewhere that is not
the write path; a metric-shaped signal (here, the vector) reported the
reassuring value; and every test round-tripped, which a page does perfectly
when nothing happened to it.

| | defect | fix |
|---|---|---|
| ⚠⚠ 70 | **§7 unimplemented in every write path, and Dart could not read a conforming file at all** — it ignored `flags.COMPRESSED` and handed the compressed bytes to the B+tree parser. Turning Rust's profile default on produced, on the first run, `page 8235: cell pointers overrun the payload` from Dart. A page that happened to parse would have returned garbage instead | LZ4 in the pager in all three — the one place both the CoW trees and the segment builder pass through, which is where defect 58 put the cipher. `page_codec` is a real profile constant, and comes from the *file* on open, so a desktop opening a phone's database keeps the codec the phone chose |
| 71 | **`lz4_flex` takes the declared size as a capacity *hint*.** A truncated block decoded **short and returned `Ok`**; Dart and Java refuse. A page then decodes to fewer bytes than `payload_len` declares and the caller reads its tail as zeros — silent corruption from a crafted file, which is precisely what `14 §9` is about | §7 requires a decoder to refuse anything but exactly `payload_len` bytes; `codec::decompress` checks it |
| 72 | **Compressing a page inside an extent breaks a reader that parses the extent at fixed offsets** — which the Rust `Segment` does, holding the extent as raw bytes. Dart's `writeExtent` routed through the compressing `write`, so a segment head was compressed and Rust reported "segment header magic mismatch" several steps later, in the other language | §7 states the rule, and all three check it **on the header** (`extent_pages > 1`) rather than on the call path, because the call path is what got it wrong |
| 73 | **A keyless reader tried to LZ4-decode ciphertext.** §5.1 keeps headers in the clear so that verify, repair and containment run without the key — so such a reader legitimately sees `COMPRESSED` set over bytes it cannot decrypt. Reachable with no bug at all | §7 spells out the read order and forbids decompressing a page still holding ciphertext |
| 74 | **The vector generator had drifted from the vector.** Defect 59's `stored_len` at offset 28, and its note, were hand-edited into the committed JSON and never put in `tool/generate_vectors.dart` — so the first regeneration in three days silently reverted them | both are in the generator. A generated file that is hand-edited stops being generated |

**What §7 is worth, measured.** A document-shaped page — repeated field names,
short values, which is what this format actually holds — stores in **under half
a page**, and the tests assert that rather than only asserting the round trip,
because a correctness-only test lets the benefit quietly go to zero.

**The new conformance vector is `codec/lz4.json`, and it says something the
others do not: only the decoder is normative.** Any conforming LZ4 block
decompresses to the same output whatever produced it, so a reader is checked
against the recorded blocks and a writer is *not* required to reproduce them —
the same freedom §2.3 gives the R-tree split. The blocks were cross-checked in
all six directions between the three compressors and the three decoders, 50
blocks each way, before any of this was wired in; that check is what made it
safe to change three write paths at once.

**What is still not implemented, stated rather than left to be discovered
again:** §7's *value-log record* compression. Records are compressed
individually and flagged in the segment header's `codec`, and no implementation
does it. On a `desktop` profile, where `vlog_min` is 256 B, that is where the
bulk of the bytes are — so the space win now measured is the smaller half.

### 8.18 Phase 21 — the chapter that was present and unimplemented

`13-operations.md` §9's planner statistics were in the same state as §7's
codec, one layer up. Coverage found it:

| implementation | what it had |
|---|---|
| Dart | the whole chapter, wired into `analyze` / `statsOf` / `mostSelective` |
| Rust | `stats.rs` — the HyperLogLog, the equi-depth histogram, the byte-bounded `fit_to` — at **0 % line coverage, with no caller anywhere in the crate**, held in the build by a `pub fn _unused()` at the bottom |
| Java | **absent entirely**: no sketch, no histogram, no `params.stats`, and nothing that chose an index on evidence |

There is no defect number for this because nothing is *wrong*: Rust's sketch is
correct and Dart's wiring is correct. It is the gap the project keeps finding
in a new place — **code that is present and unreached** — and the reason it
survives is always the same one. §9 is advisory by design, so a database with
no statistics behaves identically to a database with good ones, only slower.
Nothing fails. The interop gate cannot see it, because statistics are per-file
metadata that a reader is explicitly allowed to ignore.

Rust's `stats.rs` is now reached through `Indexing::analyze`, `stats_of` and
`most_selective`; Java has `ops.IndexStats` and the same three on
`Collection.IndexBinding`. 14 Rust tests, 13 Java.

**What the tests assert, beyond the arithmetic.** §7.1's complaint about
Nitrite's `FindPlan` is that it chooses an index "by whether it is unique and
how many fields it covers", and so "routinely picks a unique index on a field
the query barely constrains over a non-unique index that would eliminate 99 %
of the collection". The test builds exactly that shape — `city` with 2 distinct
values over 300 rows against `age` with 50 — and asserts `most_selective`
picks `age`. Before `analyze` it asserts the method returns **nothing**, because
§9 requires "no statistics" to be *choose some other way* rather than a guess.

**Defect 37's bound is tested in both directions, which it had not been.** §9
bounds the histogram in *bytes* rather than buckets, because a CKE key runs to
kilobytes and `params.stats` is one cell of a copy-on-write B+tree: 64 bounds
over 300 string keys measured 4734 B against a 4096 B page. The test uses
200-byte keys, asserts the encoded size fits the budget, asserts the bucket
count really was reduced — and asserts that the **last bound still equals
`max_key`**, which is the difference between §9's remedy (drop alternate
buckets) and the obvious wrong one (truncate). A negative control that
truncates instead fails exactly that assertion and nothing else.

**A control that could not fail, caught while writing it.** The first version
asserted `histogram.len() == MAX_BUCKETS` for a generous budget. 500 entries at
a quota of `ceil(500/64) = 8` gives **63** buckets, not 64 — `MAX_BUCKETS`
bounds the count, it does not fix it. Asserting 64 would have been asserting an
arithmetic accident of the corpus size.

**And one test-harness fix.** `stall_test` is a wall-clock test that already
reported rather than asserted on an unoptimized build, "because an unoptimized
build is not the artifact the budget is about". Coverage instrumentation is the
same case for the same reason — a counter increment per region, roughly 2× here
— and it was failing every `cargo llvm-cov` run at 9 ms against an 8 ms budget,
which meant **the Rust coverage report could not be produced at all**. It now
detects `LLVM_PROFILE_FILE` and reports there too. The build-independent half —
§5.2's bounded step, asserted in bytes — is still asserted on every build, which
is what stops this from becoming a test that cannot fail.

### 8.19 Phase 22 — the codec that saved nothing, measured

Phase 20 implemented `01-container.md` §7's page codec in all three
implementations, turned it on in every profile because the spec said to, and
recorded a real defect on the way (Dart could not read a conforming compressed
file at all). The **first thing the new cross-language benchmark measured was
that the codec buys nothing**, and the reason is a property of the container
rather than of LZ4.

20 000 documents of §1's shape, `desktop`, `page_codec` at 0 and at 1:

| | bytes to device | pages allocated | file bytes | seconds |
|---|---|---|---|---|
| `page_codec = 0` | 5 345 280 | 650 | 5 767 168 | 7.682 |
| `page_codec = 1` | 5 345 280 | 650 | 5 767 168 | 7.680 |

Identical in all three space columns. **A page is a fixed-size slot addressed
by page id**, so a compressed page occupies the same slot and is written with
the same `page_size`-byte `write_at`. Compressing it cannot save space and
cannot save I/O; it can only cost CPU, and it leaks compressibility through the
cleartext `payload_len` — the CRIME/BREACH shape §7's own security note
describes.

**The obvious repair does not work either.** Letting the page builder pack
cells until the *compressed* payload reaches the cap is how block compression
pays in a variable-block-size LSM. It cannot work here: a B+tree node must
materialize into a `page_size` buffer to be navigated, so a payload that
decompresses past `page_size − 40` cannot be read back at all. The fixed page
is load-bearing for navigation, and it is what makes the codec inert.

**What changed.** `page_codec` is now 0 in every profile, in the spec's table
and in all three implementations, with the measurement written next to it. The
write path stays — a writer may set the field deliberately, and another
container shape may make it pay. The **read** path stays and is now guarded by
a test in each implementation, because it is the half that has no natural
exercise once nothing writes a compressed page: the only thing between a
conforming file from a fourth SDK and "cell pointers overrun the payload" is a
test that writes one on purpose.

**Where §7 does pay, and why it is still not implemented.** The other half of
§7 — value-log record compression, flagged in the segment header's `codec` at
`04-segments.md` §6.2 offset 38 — saves real bytes, and for exactly the reason
the page half does not: records are packed **back to back across page
boundaries with no interior page headers**, so a record that compresses to half
its size leaves the next record half a record earlier. It shrinks the log and,
through `vlog_space_target_pct`, directly reduces how often GC runs.

The design worked out for it, so the next attempt does not start cold: when a
segment's `codec ≠ 0`, an unencrypted record carries `uvar plain_len` after
`tree_id`, where 0 means "the block that follows is plaintext" and any other
value is the decompressed length of the block — so §7's 12.5 % rule stays a
per-record decision inside a per-segment codec, and a segment written at
`codec = 0` is byte-identical to today's. The encrypted framing needs the
length inside the encrypted unit (§7's compress-then-encrypt order puts it
there), which is the part that needs care and is why this is written down
rather than half-built.

**It is deliberately not implemented, and that is recorded here rather than
discovered later.** This project has now found the same shape four times —
§14.5.2's page encryption, §13.9's statistics, §01.7's page codec, and the CLI
— where code was *present and unreached* and nothing failed. Adding a fifth by
specifying a format change and shipping three implementations that ignore it
would be the same mistake with better paperwork.

### 8.20 Phase 23 — a bounded scan that cost the whole tree

The first thing the new benchmark's index row measured was **7 782 µs for a
one-row index lookup** on 20 000 documents. Profiling it took one probe: the
lookup read **2 pages** and returned **1 row**. All of the time was CPU.

Rust's `scan_tree` collected every record of every segment into a `BTreeMap`
and applied `lower` / `upper` to the **result**. So a lookup for one key walked
all 20 000 index entries and all 20 000 data entries, every time. After pushing
the bounds into the segment walk — seek to the lower bound, stop at the upper,
and skip a segment whose manifest `[min_key, max_key]` cannot intersect the
range — the same lookup is **44.7 µs**, a **174×** difference, with the same 2
page reads and the same row.

**Dart and Java never had it.** Dart seeks every segment cursor to `lower` and
runs a k-way merge; Java's `Cursor` carries `lowUk`/`highUk` and prunes on the
manifest's `minKey` first. This was a Rust-only defect, and `04-segments.md`
§8's "cursors are mandatory" is the rule it broke.

**Why nothing caught it, and it is the sharpest instance of this yet.** A scan
that post-filters returns *exactly the same rows* as one that seeks. Once the
segments are resident it reads *exactly the same number of pages*. So:

- every correctness test passed, because the answers were right;
- the **page-read counter** — the number this project elevates over wall time,
  for good reasons, in `design/performance-model.md` §8 — read 2 in both cases;
- the twelve-direction interop gate passed, because the files are identical;
- and P10, whose whole subject is how many segments a read touches, is about
  *point* reads and never looked at a range.

The instrument the project trusts most was blind here, and the instrument it
distrusts — wall time — was the only one that could see it. That is not an
argument for gating on wall time; it is an argument for **having a counter that
counts the right thing**. `Engine::scan_records_examined` is that counter now,
and the regression test asserts on it with an unbounded control, because a
bound of "under 200 records" on a counter that never moves would measure
nothing.

**Sixth instance of "a control that cannot fail".** The bounded assertion alone
would pass on an engine whose scan counter was never incremented. The control
scans the same tree unbounded and requires the counter to reach 20 000.

**One near-miss worth recording.** The first version of the fix seeked to the
segment's *first* cell when there was no lower bound. A segment holds the
entries of every tree an L0 flush covered, ordered by
`u32be(tree_id) || CKE(key)`, so that landed in whichever tree sorts first and
the walk's "past this tree, stop" branch ended it immediately: an unbounded scan
of an index tree returned **zero rows**. The sparse-index test caught it. Seek
to the tree's own prefix, never to cell 0.

### 8.21 Phase 24 — a data race the whole gate found and no test could

Running `reference/conformance/interop/run.sh` in a loop, rather than once,
produced:

```
java.lang.NullPointerException: Cannot assign field "color" because "this.root" is null
   FAIL java could not mutate
```

about **one run in six**. `color` and `root` are `java.util.TreeMap.Entry`
fields; that exception from `fixAfterInsertion` is the signature of a `TreeMap`
two threads have corrupted. No such field exists anywhere in the Cryptand
sources — the whole trace is inside the JDK, which is why grepping for it found
nothing.

**The race.** Two threads reach `Vlog`. The committer calls `append` from
`Engine.commitBatch`, which takes **no structural lock**; the compactor calls
`appendCold` from `Engine.compactOnce`, which holds `structure`. The shared
state — the `hot` and `known` maps, each `Open`'s watermark bookkeeping, and its
`completed` `TreeMap` — had no lock at all. `Vlog` contained the word
`synchronized` zero times.

**An NPE is the lucky outcome.** The same race silently drops a `completed`
entry, which leaves the durable watermark short of what was actually written,
which is a value-log record that no longer resolves. That is the value-log GC
visibility failure — a live record collected because the watermark it is judged
against never moved (defect 34 in §7's table) — reached by a different road.

Fixed by synchronizing `Vlog`'s entry points on the instance. There is no
lock-order inversion to worry about: `commitBatch` never takes `structure`, so
the only nesting is `structure` then this monitor, always in that order. Ten
consecutive gate runs clean afterwards.

**Why 300 unit tests could not see it**, and this is the part worth keeping.
The suite's engine tests are short. The committer and the compactor overlap on
the same value log only when a database is large enough that compaction is
still running while new commits arrive — which is what the interop fixture's
400 documents with a 900-byte note every tenth row produces, and what a
150-millisecond unit test does not. The gate was not written to find races; it
found one because it is the only thing in the project that drives a *realistic*
amount of work through a *complete* engine.

**The lesson is about how the gate is run, not what it contains.** It had been
run once per change since it was written, and it passes about five times in six.
A gate whose failure rate is 1/6 and which is run once reports "pass" 83 % of
the time on a broken build. `11-conformance.md` §6 should say to run it
repeatedly, and the honest reading of every previous "the gate passes" in this
document is *"it passed the time we ran it"*.

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
