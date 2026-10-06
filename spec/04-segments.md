# CFF-04 — Segments, levels, the value log, and cursors

**Normative.** Assumes `00-conventions.md`, `01-container.md`,
`03-key-encoding.md`. Tuning constants named here come from the device profile
in `12-profiles.md`; the defaults quoted are the `desktop` profile's.

```
                              writes
              ┌─────────────────┼──────────────────┐   sharded, lock-free
              ▼                 ▼                  ▼
          memtable 0        memtable 1   …    memtable S-1
              │                                    │
              │ keys + 16-byte pointers            │ values ≥ vlog_min
              ▼ flush: bulk-build a segment        ▼
   L0   [seg][seg][seg][seg]   overlapping     ┌───────────────────────┐
   ─────────────────────────────────────       │  HOT value log        │
   L1   [seg]…[seg]  TIERED, range-partitioned │  churns; most records │
   L2   [seg]…[seg]  TIERED                    │  die here             │
   …                                           └──────────┬────────────┘
   Lmax [seg][seg][seg]  LEVELLED, DISJOINT                │ promotion, in key
        └── last-level compaction promotes surviving ──────┘ order, during
            values into the cold log, IN KEY ORDER           compaction
                          ┌──────────────────────────────┐
                          │  COLD value log — key-clustered by construction,
                          │  high liveness, rarely collected             │
                          └──────────────────────────────┘
```

Four decisions carry the design, and each is stated where it is specified:

1. **Key–value separation** (§6). Only keys and 16-byte pointers are re-merged.
2. **No write-ahead log** (§7). The value-log record *is* the durability record,
   so a value is written once, not twice.
3. **Lazy levelling with range-partitioned tiers** (§3). Tiered upper levels
   for cheap writes; a disjoint levelled last level for cheap scans; partitioned
   tiers so the read tail stays bounded.
4. **A two-tier value log with clustered promotion** (§6.5). Surviving values
   are promoted into the cold log *during last-level compaction, which already
   runs in key order* — so the cold log is key-clustered **by construction, at no
   extra cost**. Scan locality is a structural property here, not a background
   chore that an implementation might skip.

---

## 1. The internal key

Every entry in every segment is keyed by an **internal key**, compared as raw
bytes:

```
internal_key := u32be(tree_id) || CKE(key) || u64be(seq XOR 0xFFFF_FFFF_FFFF_FFFF) || u8(op)
```

| | |
|---|---|
| `tree_id` big-endian first | a tree's entries are one contiguous range of the global key space, so a scan of one tree never steps through another's |
| `CKE(key)` | prefix-free by construction (`03-key-encoding.md` §7), so the concatenation is unambiguous and order-preserving |
| `seq` inverted | the **newest** version of a key sorts **first**, so a read at snapshot *S* seeks the key and walks forward to the first entry with `seq ≤ S` |
| `op` | `0` PUT, `1` DELETE, `2` MERGE (reserved), `3` RANGE_DELETE |

Several versions of one key may coexist across segments and, after a
long-running snapshot, within one segment. Compaction collapses every version
older than the oldest live snapshot.

`seq` is a global `u64` from one atomic counter (`10-transactions.md` §2). It is
the only serialization point on the write path.

## 2. Segment

A **segment** is an immutable, sorted, page-indexed B+tree over a contiguous
range of internal keys, written once as one extent and never modified.

```
extent:
  page 0        SEGMENT_HEADER
  pages 1..a    B+tree leaves and internal pages (page types 1 and 2)
  pages a+1..b  filter pages
```

Immutability is what makes concurrency tractable: a reader holding a segment
never coordinates with a writer, a compaction never blocks a read, and there is
no page-level locking anywhere in the format.

### 2.1 Segment header page

After the 40-byte page header:

| off | size | field |
|---|---|---|
| 0 | 8 | `magic` = `43 52 59 5F 53 45 47 1A` (`"CRY_SEG"` + `0x1A`) |
| 8 | 8 | `segment_id` — globally unique, never reused |
| 16 | 1 | `level` |
| 17 | 1 | `flags` — bit0 `HAS_RANGE_DELETES`, bit1 `SINGLE_TREE`, bit2 `HAS_TTL` |
| 18 | 2 | `filter_bits_per_key` |
| 20 | 4 | `tree_count` |
| 24 | 8 | `root_page` — relative to the extent start |
| 32 | 8 | `entry_count` |
| 40 | 8 | `tombstone_count` |
| 48 | 8 | `min_seq` |
| 56 | 8 | `max_seq` |
| 64 | 8 | `filter_page` — relative to the extent start, 0 if none |
| 72 | 8 | `value_bytes` — inline value bytes |
| 80 | 8 | `vlog_bytes` — bytes this segment references in the value log |
| 88 | 8 | `min_expiry` — earliest TTL deadline in this segment, 0 if none |
| 96 | 1 | `group` — range-partition group within a tiered level, 0 at L0 and at the last level (§3.1) |
| 97 | 7 | reserved |
| 104 | 4 | `min_key_len` |
| 108 | 4 | `max_key_len` |
| 112 | … | `min_key`, then `max_key` |
| … | … | `tree_span[]` — `tree_count` × { `u32 tree_id`, `u64 entry_count` } |

`min_key`/`max_key` let the manifest prune a segment without opening it, which
is what makes a levelled point lookup one segment per level. `min_expiry` lets a
compaction know, without reading the segment, whether it can drop anything.

**`min_key` and `max_key` are bounds, not necessarily the exact extreme keys.**
A writer MUST satisfy `min_key ≤ every internal key in the segment ≤ max_key`,
and SHOULD make them exact. It MAY shorten them — truncate `min_key` downward
and extend `max_key` upward to a shorter byte string — which is what keeps the
header inside one page:

**The whole header MUST fit in the head page.** With `page_size = 4096` and the
key limit at `page_size / 4` (`00-conventions.md` §8), two exact 1 KiB keys plus
`tree_span[]` can overflow it. A writer MUST shorten the bounds, and if that is
still not enough, split the segment. Shortened bounds only ever widen the range a
pruner considers, so they cost a candidate, never a correct answer.

`group` is duplicated here from the manifest key (§3.2) so that
`13-operations.md` §3 can rebuild a lost manifest entirely from segment headers.
Every other manifest field is likewise present above.

### 2.2 B+tree pages inside a segment

Identical framing for leaf and internal pages, after the 40-byte page header.
Offsets are relative to the payload.

| off | size | field |
|---|---|---|
| 0 | 2 | `cell_count` |
| 2 | 2 | `free_start` |
| 4 | 2 | `prefix_len` |
| 6 | 2 | `flags` — bit0 `IS_LEAF` |
| 8 | 8 | `subtree_entries` |
| 16 | `prefix_len` | `prefix` — common internal-key prefix of the page |
| … | 2 × `cell_count` | `cell_ptr[]`, sorted by key |
| … | | free gap |
| … | | cells, growing downward from the payload end |

**Leaf cell:**

```
uvar  suffix_len
bytes suffix_len        -- internal key with `prefix` removed (includes seq and op)
u8    kind_flags        -- low nibble  value_kind: 0 INLINE, 1 OVERFLOW,
                        --                         2 BLOB, 3 EMPTY, 4 VLOG
                        -- high nibble flags:      bit4 HAS_EXPIRY
[u64  expiry_ms]        -- present iff HAS_EXPIRY; Unix ms, UTC (§9)
[uvar value_len]        -- present ONLY for INLINE and OVERFLOW
bytes value             -- INLINE:   `value_len` bytes of CVE value
                        -- VLOG:     exactly 16 bytes, the pointer of §6.4
                        -- BLOB:     exactly 16 bytes, the pointer of 01 §5
                        -- OVERFLOW: `value_len` inline bytes + u64 next_page
                        -- EMPTY, or op == DELETE: nothing
```

**Two bytes are deliberately absent, and both absences are the point.**

`value_kind` and the entry flags share one byte because five kinds need three
bits and the flags need one. And `value_len` is **omitted for `VLOG` and
`BLOB`**, because both pointers are exactly 16 bytes: a length field whose only
legal value is 16 is not information, it is a second place for two
implementations to disagree.

That brings a separated leaf cell to `1 + ~12 + 1 + 16 + 2` (the cell pointer)
= **32 bytes**, which is the merged footprint `K` that
`design/performance-model.md` §1 costs the entire write-amplification argument
against. The reference implementation measured 34 B before this change and 115
entries per leaf against a predicted 127; the model was right and the layout was
two bytes fatter than it.

`value_kind` by `op`: a `PUT` uses any kind; a `DELETE` writes
`value_kind = EMPTY` and no value; a `RANGE_DELETE` writes `value_kind = INLINE`
and the payload of §2.5. A reader MUST reject a `kind_flags` whose low nibble is
above 4, and MUST reject a set bit in the high nibble other than bit 4.

A tree whose values are raw byte layouts rather than CVE — `postings`
(`07-fulltext.md` §4.2) and `vector_graph` (`09-vector.md` §3) — stores them as
a CVE `BYTES` value (`0x13`), so that "INLINE means a CVE value" holds without
exception and generic tooling can dump any tree.

**Internal cell:**

```
uvar  suffix_len
bytes suffix_len        -- separator, prefix removed
u64   child_page        -- relative to the extent start
u64   child_subtree_entries
```

Cell *i* holds the least internal key reachable in child *i*. A writer SHOULD
truncate separators to the shortest string that still separates the neighbouring
subtrees.

`subtree_entries` is what makes `skip(n)` cost O(height) instead of O(n). It
MUST be accurate; `01-container.md` §9 verifies it.

**No sibling pointers.** Iteration uses the cursor of §8.

### 2.3 Bulk construction

A segment is always built **bottom-up from a sorted stream**: leaves are filled
and emitted in order, internal pages are built from the separators as leaves
complete, and the extent is written with one sequential `pwrite`/`writev`.

There is no insertion path into a segment, and therefore no split algorithm, no
rebalancing, and no in-place page update anywhere in the format. Every write to
the device is sequential.

A writer MAY leave leaves partially full. A reader MUST accept any fill factor
from one cell upward.

### 2.4 Filter

A membership filter over every **user key** in the segment — over
`u32be(tree_id) || CKE(key)`, *excluding* `seq` and `op`, so all versions of a
key share one entry.

**Blocked Bloom**, 512 bits (64 bytes) per block. Specified to the bit, because a
filter that disagrees between languages produces **wrong results**, not slow
ones — a false *negative* silently loses a key.

```
hash        = CFH64(user_key)                      -- §2.4.1, u64
h1          = hash & 0xFFFF_FFFF                   -- u32
h2          = (hash >> 32) | 1                     -- u32, forced ODD
block_count = max(1, ceil(entry_count * filter_bits_per_key / 512))
block        = (h1 * block_count) >> 32            -- u64 multiply, take the high half
k           = max(1, min(16, round(filter_bits_per_key * ln 2)))

for i in 0 … k-1:
    bit = (h1 + i * h2) mod 512                    -- u32 arithmetic, wrapping
    set / test bit `bit` of `block`
```

- `entry_count` here is the number of **distinct user keys** in the segment, not
  `entry_count` from the header (which counts versions). It is recomputed by the
  builder as it streams, and `block_count` is written into the filter page so a
  reader never recomputes it.
- Bit `b` of a block is bit `b mod 8` of byte `b div 8`, counting bits from the
  least-significant end of the byte. This is the one place bit order is
  observable, so it is stated.
- `h2` is forced odd so that the probe sequence `h1 + i*h2 (mod 512)` never
  degenerates to a single bit.
- `k` is derived, not stored: the profile table's bit rates give
  `k = 7` at 10 bits, `k = 8` at 12, `k = 10` at 14 and `k = 11` at 16.

Filter page layout, after the 40-byte page header:

```
u32  magic = 0x43465031            -- "CFP1"
u32  block_count
u16  bits_per_key
u16  probes                        -- k, as derived above; a reader MUST use
                                   --   this value, not recompute it
u64  distinct_keys
bytes(block_count * 64)            -- the blocks, spanning pages of the extent
```

Writing `probes` down rather than deriving it at read time means a future
minor version can change the derivation without invalidating existing files.

`filter_page = 0` means no filter, and a reader MUST then treat every probe as a
hit.

#### 2.4.1 CFH-64 — the filter hash

**The hash is specified here, in full, rather than named.** That is the whole
point of it.

```
CFH64(key):                       -- all arithmetic is u64 and wraps;
                                  -- >>> is a logical (zero-fill) shift
  P1 = 0x9E3779B185EBCA87
  P2 = 0xC2B2AE3D27D4EB4F
  P3 = 0x165667B19E3779F9
  M1 = 0xBF58476D1CE4E5B9
  M2 = 0x94D049BB133111EB

  h = P1 XOR (length(key) * P2)
  i = 0
  while length(key) - i >= 8:
      w = u64le(key[i .. i+8])                 -- little-endian, 00 §3
      h = h XOR (w * P2)
      h = rotl64(h, 31) * P1
      i = i + 8

  tail = 0                                     -- the final 0..7 bytes,
  while i < length(key):                       --   folded most-significant
      tail = (tail << 8) OR key[i]             --   byte first
      i = i + 1
  h = h XOR (tail * P3)
  h = rotl64(h, 27) * P1

  h = (h XOR (h >>> 30)) * M1                  -- finalizer
  h = (h XOR (h >>> 27)) * M2
  h = h XOR (h >>> 31)
  return h
```

Every operation is a wrapping 64-bit multiply, an XOR, a logical shift or a
rotate. Java has all four on `long` (`Long.rotateLeft`, `>>>`); Rust has
`wrapping_mul` and `rotate_left`; Dart's `int` is a wrapping 64-bit two's
complement value with `>>>`. There is no table, no secret, and nothing to look
up.

**Why not XXH3-64**, which an earlier draft named. XXH3-64 is roughly 500 lines
with seven length-dependent branches and a fixed 192-byte secret table. For a
structure whose failure mode is a silent false *negative*, that made the single
largest and least verifiable primitive in Level 0 the one guarding the most
dangerous failure — and it had to be reproduced bit-exactly, from the paper, in
three languages. A hash small enough to print here is one an implementer reads
rather than sources, and the conformance vectors pin it.

**Why not CRC-32C**, which is already mandatory for every page and would
therefore have been free. CRC is affine in its initial state, so
`CRC(i1, m) XOR CRC(i2, m)` depends only on `length(m)`, and appending or
prepending a salt is likewise an invertible linear map of the original value.
**Any pair of CRC-32C evaluations over the same key therefore carries 32 bits of
entropy, not 64** — a finalizer spreads those bits but cannot create more. Two
distinct keys colliding in 32 bits set identical filter bits, so one is a
*guaranteed* false positive whenever the other is present, and the number of
such pairs grows as `n^2 / 2^33`. The reference implementation measured
4 000 000 random keys: the CRC pair produced **1868** collisions against
**1863** predicted by that bound, and CFH-64 produced **none**.

Measured false-positive rate at 16 bits per key, 200 000 keys and 2 000 000
absent probes, across five key shapes — snowflake ids, dense sequential ids,
sparse ids, strings with a long shared prefix, and compound index keys:
**0.222 % – 0.235 %**, stable to within 6 % across all five. The raw CRC pair
ranged from 0.18 % to 0.45 % on the same shapes, which is the linearity showing.

CFH-64 is used **only** for filters. It is not a checksum (CRC-32C, §6 of
`00-conventions.md`), it is not a MAC (`14-security.md` §6), and it MUST NOT be
used where either is required.

**A filter need not be resident** — on an unencrypted file. Block selection
depends only on `h1`, so a probe reads exactly one 64-byte block.

On an *encrypted* file this does not hold: the filter page must be decrypted
whole before a block can be read, so demand-loading costs a page decrypt per
miss. An encrypted implementation SHOULD therefore cache decrypted filter pages
in preference to data pages (`14-security.md` §12). An implementation MAY serve probes from
the page cache on demand rather than holding whole filters in memory — which
matters because tiering puts a key's versions in several segments.

**Filter bits are set per level, not globally.** Upper levels hold little data,
so a high bit rate there is nearly free and it is what bounds the read tail
(§4.1):

| level | default `filter_bits_per_key` | false positive |
|---|---|---|
| L0 and tiered levels | **16** | **≈0.33 %** |
| last level | **10** | **≈1.7 %** |

**Those are blocked-Bloom rates, and they are the ones that matter.** An
earlier draft printed 0.04 % and 1 %, which are the *classic* Bloom figures
`(1 − e^(−kn/m))^k` for the same bits per key. Blocking costs roughly 7× that,
and the reason is structural rather than a matter of hash quality: at 16 bits
per key a 512-bit block holds ~32 keys *on average*, the Poisson spread in
keys-per-block is wide at that count, and the overfull blocks dominate the
rate. The reference implementation measured both structures over the same keys
with the same hash — classic landed at 0.051 % against a 0.046 % prediction,
blocked at 0.331 % — which isolates blocking as the cause.

The trade is still the right one and is now stated rather than hidden: blocking
buys a probe that touches **one 64-byte line and one I/O**, which is what makes
a demand-loaded filter viable at all, and it costs about 7× the false-positive
rate. Raising `filter_bits_per_key` recovers less than it looks like it should
— measured 0.22 % at 18 bits, 0.12 % at 24, 0.065 % at 32 — because `k` is
clamped at 16 and a fuller block hurts more than more probes help. An
implementation that genuinely needs classic-Bloom rates raises the bit rate and
accepts the size; it is a superblock field, so that needs no format change.

The last level contributes exactly one candidate, so its filter only avoids a
descent, never a fan-out. Spending bits there is the wrong trade; spending them
above is the right one.

### 2.5 Range deletes

`op = RANGE_DELETE` marks a half-open interval `[key, end_key)` deleted at `seq`.
The value payload holds `uvar end_key_len || end_key`. Set
`flags.HAS_RANGE_DELETES` on the segment. `end_key` is `CKE(end)`, encoded as
`key` is in §1, **without** `tree_id`: the interval lies inside the entry's own
tree.

This makes `clear()`, `drop()` and rollback of a bulk insert O(1) writes rather
than O(n) tombstones. A reader MUST apply range deletes: an entry at
`seq' < seq` whose key falls in the interval is invisible.

## 3. Levels and the manifest

### 3.1 Level policy — lazy levelling with range-partitioned tiers

| level | policy | segments |
|---|---|---|
| **L0** | overlapping | one per memtable-shard flush; `l0_trigger` before compaction |
| **L1 … Lmax−1** | **tiered, range-partitioned** | up to `tier_width` size-similar segments, arranged so that no more than `overlap_bound` (default **2**) of them cover any single key |
| **Lmax** | **levelled, disjoint** | segments partition the **user** key space with no overlap (§3.1.1) |

This is *lazy levelling* — tiering everywhere except the largest level — with
one addition. Plain tiering lets all `tier_width` segments at a level overlap a
key, so a point lookup's worst case grows with the tier width. **Range
partitioning** splits each tiered level's segments into `overlap_bound` groups
of mutually disjoint segments, so a lookup consults at most `overlap_bound`
segments per level regardless of how wide the tier is.

Cost: a compaction producing a tiered level must respect the group's key
boundaries, which occasionally forces a split. That is cheap — segments are
bulk-built anyway — and it converts an unbounded read tail into a bounded one.

**The two bounds fix the output segment size, and an implementation that picks
it freely cannot satisfy both.** A tiered level holds up to `tier_width`
size-similar segments arranged in `overlap_bound` disjoint runs, so a run
occupies `tier_width / overlap_bound` segments; a run at L1 is `l0_trigger`
memtables and a run at level *L* is `overlap_bound` runs of the level below.
A conforming writer therefore sizes its outputs so that

```
run_entries(1)    = l0_trigger × memtable_entries
run_entries(L)    = overlap_bound × run_entries(L−1)
segment_entries(L) = ceil( run_entries(L) ÷ (tier_width ÷ overlap_bound) )
```

This is a **writer** rule, not a format rule — the paragraph below still holds,
a reader MUST NOT depend on the policy — but it is stated because the reference
implementation's first version used one fixed output size at every level, and
every tiered level then crossed `tier_width` after its *second* run and
compacted immediately. No level ever held more than one run, so range
partitioning had no opportunity to do anything, and the read-tail measurement
that follows would have been meaningless.

**Plain tiering is this policy with `overlap_bound = tier_width`**, and nothing
else changed: `tier_width` runs of one whole-range segment each. That equality
is worth stating because it makes the comparison in §4.1 a change of one
superblock field rather than a different engine.

#### 3.1.1 Disjointness is over **user** keys

**A levelled level's segments MUST NOT overlap in `u32be(tree_id) || CKE(key)`,
and testing this on whole internal keys is wrong.** An internal key is
`tree_id || CKE(key) || ~seq || op` (§1), so two segments holding *different
versions of the same key* occupy disjoint internal-key ranges — one holds
`~11 … ~5`, the other `~4 … ~1` — and an overlap test on internal keys reports
them as non-overlapping. A compaction that trusts that test leaves both in
place, and the level stops being disjoint while `min_key`, `max_key`,
`subtree_entries` and every checksum remain perfectly valid.

The consequence is a **wrong answer, not a slow one**: §4's early exit rests on
at most one segment per group covering a key, so a lookup stops at whichever of
the two it reaches first and returns a stale version. A verifier's levelled-
overlap check (`01-container.md` §9 step 3) is on user keys for the same reason.

This is stated because it is invisible until superseded versions are actually
retained. An engine that drops every superseded version at the last level has
one entry per user key there, so internal-key and user-key disjointness
coincide, and the defect stays hidden until §5's condition 2 — a live snapshot —
keeps versions the compaction would otherwise have collapsed. The reference
implementation found it exactly that way.

A conforming reader MUST NOT depend on the policy. It reads the manifest and
resolves by `seq`. An implementation MAY use a different policy — pure levelled,
pure tiered, adaptive — and the files it writes stay readable by everyone,
because the format records only the level, key range and seq range
(`11-conformance.md` §1.3).

### 3.2 Manifest tree

Reserved tree 6, a plain copy-on-write B+tree rooted from the superblock:

```
key   = CKE(Array[ U8 level, U8 group, BYTES min_internal_key ])
value = CVE {
    "segment_id": U64, "start_page": U64, "pages": U32, "root": U64,
    "filter":     U64, "min_seq":   U64, "max_seq": U64,
    "entries":    U64, "tombstones": U64, "min_expiry": U64,
    "min_key":    BYTES, "max_key": BYTES,
    "value_bytes": U64, "vlog_bytes": U64,
    "trees":      ARRAY[U32]
}
```

`group` is the range-partition group within a tiered level (always 0 at L0 and
at the last level). Keying by `(level, group, min_internal_key)` means "find the
segments at level *L* covering key *k*" is `overlap_bound` seeks, each returning
at most one segment.

### 3.3 Internal trees are not levelled

Trees 0–15 (`05-catalog.md` §2) are **plain copy-on-write B+trees**, each rooted
from the superblock or the catalog. They are small, hot and almost entirely
cached; levelling them would add indirection for nothing and would make the
manifest need a manifest.

Their pages use the formats of §2.2, written copy-on-write: a write copies the
path from leaf to root, appends the copied pages, and publishes the new root in
the next superblock. Freed pages go to the free tree at the committing
`commit_id`.

## 4. Read resolution

```
get(tree_id, key, snapshot_seq):
  ik_prefix = u32be(tree_id) || CKE(key)
  candidates = []          -- may hold the key
  rd_sources = []          -- may hold a RANGE_DELETE covering the key
  for seg in L0 ∪ (level 1 … Lmax, groups 0 … overlap_bound-1):
      if not seg.covers(ik_prefix): continue          -- manifest prune, no I/O
      if seg.flags.HAS_RANGE_DELETES: rd_sources += seg
      if seg.filter.may_contain(ik_prefix): candidates += seg

  best = none
  for seg in candidates:                              -- ALL of them, no early exit
      e = seg.seek(ik_prefix).first entry with seq ≤ snapshot_seq
      if e and (best is none or e.seq > best.seq): best = e

  rd = the greatest seq ≤ snapshot_seq among RANGE_DELETEs in rd_sources
       whose interval contains the user key            -- none ⇒ 0
  if best is none or rd > best.seq:                    return absent
  if best.op == DELETE or expired(best, now):          return absent
  return resolve_value(best)                           -- inline, or one vlog read
```

**Two things in that loop are load-bearing and were wrong in an earlier draft.**

1. **Candidates are resolved by the winning entry's own `seq`, not by segment
   order.** A segment's `max_seq` is an aggregate over *every* key it holds, so a
   segment at a lower level can carry a higher `max_seq` — from some unrelated
   key — than a segment above it. Taking the first hit in `max_seq` order
   therefore returns a stale version. An implementation MAY stop early only when
   it can prove no unexamined candidate can hold a newer version of *this* key —
   the standard proof is level discipline: L0 newest-flush-first, then strictly
   increasing level. Absent that proof, it MUST examine every candidate.
2. **A segment that may hold a covering range delete MUST NOT be pruned by its
   filter.** The filter contains the segment's *point* keys (§2.4); a
   `RANGE_DELETE` covers keys that are not in it, so filtering a segment out
   loses the delete and resurrects a deleted key. `flags.HAS_RANGE_DELETES` in
   the segment header exists exactly so this test costs no I/O: a segment without
   the flag is filter-pruned as usual, and range deletes are rare, so the number
   of segments in `rd_sources` is normally zero.

An implementation SHOULD keep a per-segment range-delete summary (the union of
its intervals) in memory alongside the manifest entry, so `rd_sources` is
normally empty after an in-memory test rather than after a page read.

### 4.1 The bounded read tail

Three mechanisms compose so that the *worst* case, not just the average, is
bounded:

| | effect |
|---|---|
| manifest key-range pruning | removes every segment that cannot hold the key, with no I/O |
| range-partitioned tiers (§3.1) | at most `overlap_bound` (2) candidates per tiered level |
| per-level filter bits (§2.4) | ≈0.33 % false positive above the last level (measured, blocked Bloom) |

Candidates are bounded by

```
l0_trigger  +  overlap_bound × (level_count − 2)  +  1
└─ L0 ─┘       └──── tiered levels L1 … Lmax−1 ────┘   └ the disjoint last level
```

Worst realistic case at `level_count = 4` (L0 … L3, L3 disjoint):
`4 + 2 × 2 + 1 = 9` candidates. The eight above the last level survive their
16-bit filter with probability **0.0033** (§2.4) → **expected extra descents
≈ 0.026**, and the p99.9 case is one extra descent rather than several.

The read tail is therefore unaffected by §2.4's correction: at 0.026 expected
extra descents, `segments_probed_per_lookup` p99 is still 1 and p99.9 is still
2.

**Two things about that arithmetic, both learned by measuring it.**

*First, it counts only false positives, so it holds only for a reader that takes
the early exit of §4.* A reader that examines every candidate — which is what §4
*requires* of a reader without the level-discipline proof — also probes every
segment that legitimately holds an older version of the key, and under an
update-heavy load that is routinely two or three. Measured on the reference
implementation over 20 000 uniform-random point reads after random-order inserts
plus updates: **p99 1 and p99.9 2 with the early exit at every size from 10⁴ to
2×10⁵ documents, against p99 3 and p99.9 4 at 25 000 documents without it.** The
bound belongs to the early exit, and `design/performance-model.md` §5.4 now says
so.

*Second, the attribution in the sentence this paragraph replaced was backwards
at the desktop shape.* It read: "the bounded-read-tail property comes from
range-partitioned tiers and manifest pruning; the filter is what stops the
residue." Measured at 2×10⁵ documents, mean segments probed per lookup:

| | filter on | filter off |
|---|---|---|
| range-partitioned (`overlap_bound` 2) | **1.01** | 3.91 |
| plain tiered (`overlap_bound` = `tier_width` = 4) | 1.01 | 5.55 |

With the filter on, range partitioning is worth nothing in the mean and one step
in the tail (p99 1 vs 2, max 2 vs 3); with the filter off it is worth 1.64
probes. At `tier_width = 4` it is **manifest pruning and the filter** that
produce the bound and range partitioning that stops the residue — the reverse of
what was written. Range partitioning earns its keep as `tier_width` grows, which
is exactly when a `server` profile (`tier_width = 6`) or a filterless build needs
it; it is not what delivers p99 = 1 on a phone or a desktop.

## 5. Compaction

Compaction reads *n* input segments, merges them by internal key, drops entries
made unreachable, and writes new output segments. It is the only thing that
rewrites keys.

Normative outcome, not mechanism: after a compaction, every `get` at every live
snapshot returns exactly what it returned before.

An entry may be dropped only when **all** hold:

1. a newer version of the same user key exists in the same compaction, **and**
2. that newer version's `seq` is ≤ the oldest live snapshot's seq, **and**
3. the compaction includes every segment that could hold an older version of
   that key — i.e. it reaches the last level, or no lower level overlaps the key.

An expired entry (§9) may be dropped when condition 3 holds and its deadline is
older than the oldest live snapshot's wall-clock floor.

A `DELETE` or `RANGE_DELETE` tombstone may be dropped only when condition 3
holds **and** its own `seq` is ≤ the oldest live snapshot's seq. The second half
is not optional: if a snapshot older than the tombstone is live, the versions the
tombstone hides cannot be dropped (condition 2 fails for them), so dropping the
tombstone alone would resurrect them for every reader at or after the delete.

### 5.1 Parallel compaction

Compaction jobs on **disjoint internal-key ranges** MUST be able to run
concurrently. Segments are immutable, outputs are new extents, and the only
shared mutable state is the manifest tree, whose edit is a short critical
section at publish time (`10-transactions.md` §5).

An implementation SHOULD run `compaction_threads` jobs (profile-dependent) and
MUST NOT serialize compaction behind the write path.

### 5.2 Compaction must be interruptible — the mobile requirement

**A compaction job MUST be decomposable into steps of at most
`compaction_step_bytes` (profile default: 256 KiB on `mobile`), between which it
can yield.**

This is not a nicety. Wherever the database shares its execution context with a
UI — which is the normal arrangement for an embedded database on a phone, and is
unavoidable on a runtime with no threads to move it to — a compaction that runs
to completion before yielding drops frames, and a dropped frame is visible in a
way a throughput difference is not. An implementation that cannot run compaction
concurrently with foreground work MUST interleave compaction steps with it and
MUST respect `max_foreground_stall_ms` (profile default: **8 ms** on `mobile`).
The bound is a profile constant rather than a framework's number, so the
requirement holds without naming one.

A step boundary is any point between two output leaf pages. Because segments are
built bottom-up from a sorted stream, the partially built output is just a
prefix — abandoning it costs the work done and nothing else, and no reader can
see it.

### 5.3 Compaction pacing

An implementation MUST rate-limit compaction I/O to `compaction_bytes_per_sec`,
derived from the observed foreground write rate (a common rule: 2–4× the
trailing foreground rate, clamped by the profile). Unpaced compaction is the
main cause of write-latency spikes in LSM engines, and it is the difference
between a p99 that tracks p50 and one that does not.

On `mobile` and `tablet`, an implementation SHOULD additionally accept a host
hint (`idle`, `charging`, `thermal_pressure`) and defer non-urgent compaction
accordingly. Compaction is the single largest discretionary consumer of battery
and thermal headroom in an embedded database; running it while the screen is on
and the device is warm is the wrong choice, and only the host knows.

## 6. The value log

### 6.1 Why, and the shape

Compaction rewrites every byte it merges, several times over a record's life.
If values are merged with keys, a 500-byte document pays that; if only the key
and a 16-byte pointer are merged, it does not.

The classic cost of that trade is **scan locality**: values adjacent in key
order end up scattered on disk, and a full scan degrades as data ages. The value
log here is built in **two tiers** specifically to eliminate that:

| tier | written by | ordered by | liveness | collected |
|---|---|---|---|---|
| **HOT** | the write path | insertion | low — most records die or are promoted | often, by liveness |
| **COLD** | last-level compaction (promotion), bulk writers, and cold GC | **key** | high | rarely |

**Promotion happens during last-level compaction, which already walks keys in
sorted order.** Appending each surviving value to the cold log as it passes
therefore produces a key-clustered cold log *by construction* — the ordering is
free, because the sort had to happen anyway.

Since the last level holds the large majority of the data, the large majority of
scanned bytes are key-clustered, and a scan's value reads are sequential.

### 6.2 Value-log segments

A value-log segment is a page-aligned extent, head page type `VLOG_SEGMENT`
(7), `flags.EXTENT_HEAD` set.

**The head page is written once, when the extent is allocated, and is never
rewritten.** It therefore holds only the segment's *immutable identity*:

| off | size | field |
|---|---|---|
| 0 | 8 | `magic` = `43 52 59 5F 56 4C 47 1A` (`"CRY_VLG"` + `0x1A`) |
| 8 | 8 | `segment_id` — a **separate id space** from tree segments (`00-conventions.md` §7) |
| 16 | 8 | `created_seq` |
| 24 | 8 | `capacity` — bytes of record space in this extent, i.e. `extent_pages × page_size − data_offset` |
| 32 | 4 | `data_offset` — bytes from the extent start to the first record |
| 36 | 1 | `tier` — 0 HOT, 1 COLD |
| 37 | 1 | `heat_class` — §6.6, HOT tier only |
| 38 | 1 | `codec` |
| 39 | 1 | `encrypted` — 0 or 1; per segment, like `flags.ENCRYPTED` is per page |
| 40 | 8 | `nonce_base` — the segment's allocated nonce counter value, 0 if not encrypted (`14-security.md` §4.2) |
| 48 | 16 | reserved |

Everything about a value-log segment that **changes as it fills** —
`bytes` (the durable watermark), `records`, `sealed`, `clustered`, `min_key`,
`max_key`, and the liveness counters — lives in the **value-log stats tree,
tree 7** (§6.7), which is a copy-on-write B+tree updated by the committer in the
ordinary commit path.

This split is not bookkeeping taste; it is what keeps the container's central
rule true. `01-container.md` §1 says no page a live superblock references is
ever overwritten. A mutable `byte_len` in the head page would violate that on
every append, and would leave the page's CRC-32C stale between the append and
the rewrite — a page that fails its own checksum for most of its life. Putting
the watermark in tree 7 makes advancing it an ordinary transactional write,
which is exactly what `10-transactions.md` §2.3 already requires of it.

`data_offset` is the head page's 40-byte page header plus this 64-byte header,
rounded up to 8 — i.e. 104 — but it is written down so a future minor version
can grow either header without changing how records are addressed.

`clustered` in tree 7 asserts that the segment's records appear in
non-decreasing `(tree_id, CKE(key))` order. A reader MAY use tree 7's
`min_key`/`max_key` to prefetch a whole cold segment when a scan enters its
range. Both are known only at seal, which is the other reason they cannot live
in a write-once head page.

Records follow, back to back from `data_offset`. They span page boundaries with
no interior page headers (`01-container.md` §3):

```
uvar  record_len          -- count of the bytes that follow this field,
                          --   INCLUDING the trailing crc32c
[u64  nonce]              -- present iff the segment is encrypted; in the clear
u32   tree_id
uvar  key_len             -- ┐
bytes key_len             -- │ CKE(key), NOT the internal key: no seq, no op
uvar  value_len           -- │ encrypted as one unit when the segment is
bytes value_len           -- ┘ encrypted (14-security.md §5.3)
[u8   tag[16]]            -- present iff encrypted; the Poly1305 tag
u32   crc32c              -- over `tree_id … tag`, i.e. every byte after
                          --   record_len except these four, as STORED
```

`record_len`, `nonce` and `crc32c` stay in the clear so that a segment can be
walked, and damage in it bounded, without the key — the same reason page headers
are clear. The CRC covers the stored bytes (`00-conventions.md` §6), so it is
computed over ciphertext; integrity comes from the tag, error detection from the
CRC, and `14-security.md` §9.4 is emphatic that these are not the same thing.

A record therefore occupies `sizeof(uvar record_len) + record_len` bytes, and a
reader that knows only the offset reads the varint first.

**The key is stored with the value**, which is what makes garbage collection
possible without a reverse index: to test liveness, look the key up and check
whether the live entry points at this offset.

**Writers reserve, then write directly.** To append, a writer takes a byte range
with one `fetch_add` on the open segment's tail counter and `pwrite`s its whole
batch at that offset. There is no shared write buffer and no writer lock, so:

- the number of open value-log segments is bounded by the number of **heat
  classes**, *not* by the number of writer threads — write-path memory is O(1)
  in concurrency, which matters on mobile;
- concurrent writers never touch the same bytes, buffer, or cache line.

A crash can leave a reserved-but-unwritten hole below the tail. That is safe
because durability is defined by a **contiguous** watermark: the committer
advances tree 7's `bytes` only to the end of a prefix in which every reservation
has completed, and **only records entirely below `bytes` may be referenced by a
`VLOG` pointer**. Bytes above the watermark are debris.

**A writer MUST NOT append to a value-log segment it did not itself open in the
current session.** On open, every unsealed segment is sealed at its durable
`bytes` watermark and a fresh segment is opened for new writes
(`10-transactions.md` §4).

Unencrypted, re-appending after a crash would be harmless — nothing references
the debris. Encrypted, it writes different plaintext at the same segment and
offset, which is a nonce collision and a total loss of confidentiality for both
records (`14-security.md` §4.3). The rule is unconditional rather than
encryption-only, because a rule that applies sometimes is a rule that gets
implemented wrong, and the cost is one partly-filled segment per unclean
shutdown, reclaimed by ordinary GC.

A writer SHOULD coalesce all of one batch's records into a single reservation
and a single `pwrite`.

### 6.3 Promotion — clustered by construction

**During a compaction that outputs the last level, for every surviving entry
whose value is a HOT-tier pointer, the implementation MUST either promote the
value into a COLD segment or re-inline it.**

Because the compaction emits entries in internal-key order, appending promoted
values in that order yields a COLD segment marked `clustered` in tree 7. The
implementation MUST set that flag only when the ordering actually holds.

Consequences worth stating:

- A value that dies before reaching the last level is **never promoted** — the
  hot tier absorbs the churn, which is most of it under a skewed update
  distribution.
- A value that survives is written **twice** in the common case: once on write,
  once on promotion. Values that never reach the last level are written once.
- **A long-lived value may be written more than twice.** Promotion clusters a
  *generation* of surviving values into one run; ten rounds of compaction
  produce ten runs, and merging them back into one is a collection (§6.8),
  which is a further write of every value that survives it. An earlier draft
  said "at most twice over their whole life", which is true only of a database
  that is never collected — and one that is never collected is the database
  whose scans decay (§6.9). Measured on the aged-scan workload of
  `spec/11-conformance.md` §6, holding `locality_debt` under 20 % cost
  **2.12×** value-side write amplification against **1.76×** with no collection
  at all: 20 % more value writes, in exchange for an aged scan that stays at
  1.00× instead of degrading to 2.14×, and a value log that stays at 1.00×
  its live size instead of 5.82×.
- A **bulk or sequential writer MAY write directly to a COLD segment**, skipping
  the hot tier and the promotion write entirely. If the batch is sorted, it MUST
  set `clustered`; if not, it MUST NOT.

### 6.4 Pointer

`value_kind = 4 (VLOG)`, 16 bytes:

```
u64  vlog_segment_id
u32  offset          -- byte offset, from the START OF THE EXTENT, of the
                     --   record's `record_len` varint
u32  len             -- the record's total size, varint included, so a reader
                     --   issues exactly one sized read
```

`offset` is extent-relative, not `data_offset`-relative, so resolving a pointer
is one addition against the extent's `start_page` and needs nothing from the
head page. `offset + len` MUST be ≤ `data_offset + bytes` for the segment's
tree-7 entry (§6.2); a pointer past the watermark is corruption and
`01-container.md` §9 checks it.

Both `offset` and `len` are `u32`, so a value-log segment MUST NOT exceed 4 GiB.
`vlog_segment_bytes` is a `u32` field, so this is not a new constraint.

### 6.5 Inline threshold

Values shorter than `vlog_min` stay inline in the tree segment. Index trees
store `EMPTY` and never reach the value log.

The threshold is a genuine trade, and its default is **profile-dependent**
(`12-profiles.md`) because the right answer differs by an order of magnitude
between a phone and a server. Separating a value of *v* bytes costs, on disk:

```
  ~26 B   value-log record framing (record_len, tree_id, key_len, key,
          value_len, crc) — the key is duplicated so GC can test liveness
  ~15 B   net growth of the tree cell (16-byte pointer)
  ─────
  ~41 B   plus one extra random read whenever the value is dereferenced
```

and saves roughly `(WA_key − 1.5) × v` device bytes.

| *v* | space overhead | device bytes saved per write |
|---|---|---|
| 64 B | 64 % | ~0.6 KB |
| 256 B | 16 % | ~2.6 KB |
| 1 KiB | 4 % | ~10.7 KB |
| 4 KiB | 1 % | ~43 KB |

Separation pays on write bytes from about 7 bytes upward. But the extra random
read is **size-independent**, and its cost is what varies by device: ~80 µs on
NVMe, 200–500 µs on the UFS/eMMC flash in a mid-range phone. Hence:

| profile | `page_size` | `vlog_min` | rationale |
|---|---|---|---|
| `mobile` | 4 KiB | **1024** | documents stay inline — point reads cost one I/O; only genuine attachments separate. Phone write volumes make write amplification nearly irrelevant, and read latency is what a user feels. |
| `tablet` | 4 KiB | 1024 | |
| `desktop` | 8 KiB | 256 | large datasets, cheap random reads, write amplification is the binding constraint |
| `server` | 16 KiB | 256 | |

**`vlog_min` MUST be ≤ `page_size / 4`** (`00-conventions.md` §8), which is the
inline-value limit. A threshold above the cap is not merely aggressive, it is
incoherent: it names values that the writer intends to inline and that a leaf
cell cannot hold, which forces them into overflow chains — two I/Os, the very
cost inlining was meant to avoid. On `mobile`'s 4 KiB pages the cap is 1024, and
that is the number. An earlier draft said 4096 here, which was unreachable.

1024 still keeps the documents this format is shaped for inline: the assumed
20-field, ~500-byte document (`design/performance-model.md` §1) is well under
the cap, and a phone application wanting a higher threshold raises `page_size`
at creation, which raises the cap with it.

A tree MAY opt out entirely with `params.inline_values = true` in its catalog
descriptor — for a tree read randomly and hot whose values are small, a vector
adjacency graph being the motivating case (`09-vector.md` §3). A reader MUST
honour whichever `value_kind` it finds; the flag is a writer's policy, not a
promise about what is already on disk.

**`vlog_min` is a superblock field and `value_kind` is per cell**, so an engine
can move anywhere on this axis — including all the way to inlining everything —
without a format change and without rewriting a file that already exists.

### 6.6 Heat classes (HOT tier)

Records in the hot tier are routed to one of a few open segments by expected
lifetime, so a segment tends to become garbage all at once:

| class | meaning |
|---|---|
| `0` FIRST | first write of this key that this writer has seen |
| `1` WARM | key updated recently |
| `2` HOT | key updated frequently |

The format records the class; the classifier is the implementation's. A writer
with no heat information MUST use `FIRST`, which is correct and merely slower.

### 6.7 Liveness statistics

Reserved tree 7, a plain copy-on-write B+tree:

```
key   = CKE(U64 vlog_segment_id)
value = CVE { "bytes":       U64,     -- durable contiguous watermark (§6.2)
              "records":     U64,
              "sealed":      BOOL,    -- no further appends
              "clustered":   BOOL,    -- key-clustered; set only at seal
              "min_key":     BYTES?,  -- present iff clustered
              "max_key":     BYTES?,  -- present iff clustered
              "start_page":  U64,
              "pages":       U32,
              "live_bytes":  U64, "live_records": U64,
              "tier": U8, "heat": U8,
              "created_seq": U64, "last_gc_seq": U64 }
```

This tree is the **authority** for everything mutable about a value-log segment.
The head page (§6.2) carries only immutable identity, so an entry here and a
head page can never disagree about a value that changes.

`bytes` is the durability watermark of §6.2 and `10-transactions.md` §2.3, and it
MUST advance only over a contiguous prefix of completed reservations.

`live_bytes` is decremented when a compaction observes a record superseded or
deleted. It is an **estimate that MUST be conservative**: it may overstate
liveness (GC skips a segment) and MUST NOT understate it (GC would skip live
data). A verifier can recompute it exactly.

Because overstating is always safe, **an implementation that never updates
liveness statistics is still correct** — it merely never collects. This is what
lets a reduced-profile implementation (`11-conformance.md` §1.2) participate in
a database it does not fully manage.

### 6.8 Garbage collection

1. Choose segments with the lowest `live_bytes / bytes`, preferring the HOT tier
   and the `FIRST` class.
2. Scan each chosen segment's records in order. For each, look the key up in the
   trees. The record is live only if the live entry is a `VLOG` pointer to this
   exact `(segment_id, offset)`.
3. Append live records to a new segment, in the same tier. (A new extent and a
   new head page — a value-log segment is never rewritten in place, so GC has the
   same immutability guarantee as compaction.)
4. Write the updated pointers as an ordinary write batch through the normal
   commit path.
5. Free the old segment's extent once the step-4 commit is durable **and** no
   live snapshot predates it.

Every step is an ordinary commit, so GC is crash-safe by construction and
interruptible at any point. A partly finished GC leaves duplicate value records,
which are garbage, not corruption.

**Three invariants, all MUST.** GC is the most dangerous code in the format — a
liveness mistake loses data silently, and nothing else in the design has that
property:

1. A record is live **only** if the tree's current entry for its key is a `VLOG`
   pointer to this exact `(segment_id, offset)`. A key match alone is not
   sufficient: a superseded record carries the same key.
2. A segment's extent is not freed until the pointer-rewrite commit is durable.
3. `live_bytes` may overstate liveness and MUST NOT understate it.

**Collecting a COLD segment MUST preserve key clustering**: survivors are
emitted in `(tree_id, CKE(key))` order and the output keeps `clustered`. Since
every input run is already sorted, this is a merge, not a sort.

**Collection is what keeps the cold tier one run rather than many**, and it is
therefore not optional maintenance — it is half of §6.9's bound. Promotion
(§6.3) clusters each generation of surviving values as it passes; only
collection merges the generations. An implementation that promotes but never
collects has a cold tier that is *individually* sorted and *collectively*
fragmented, which is the exact state §6.9 now measures and which an earlier
draft's metric could not see.

**A collection MUST be triggered by `locality_debt` as well as by
`vlog_space_target_pct`.** The two bounds share a cause — surplus runs — but
they are not the same quantity, and a value log can sit comfortably inside its
space target while a key-ordered scan interleaves nineteen runs. Measured, a
space-only trigger left an aged scan at 1.58× where a debt trigger held it at
1.00×.

### 6.9 Locality debt — a MUST with a number

Define, over the live value-log bytes of a database:

```
ideal_runs    = ceil(live bytes in COLD-tier runs / vlog_segment_bytes)

locality_debt = live bytes in surplus runs
                ─────────────────────────────
                  total live value-log bytes
```

where the **surplus runs** are found by sorting the **cold-tier** value-log
segments that still hold live data by live bytes, descending, and taking
everything past the first `ideal_runs` of them. Live bytes in a cold-tier run
that is not key-clustered are surplus regardless of where it sorts. The
denominator stays *all* live value-log bytes.

**The cold tier only, and an earlier draft said "the value-log segments"
without the qualifier.** Both halves of that draft flagged a healthy database:

- A hot run is unclustered by construction — §6.3 clusters a generation when it
  is *promoted* — so the "not key-clustered is surplus regardless" clause made
  a freshly loaded database, every live value in one hot run, read **100 %**.
- A hot run is also the write path's *tail*: it holds everything written since
  the last last-level compaction, and neither remedy §6.9 names can act on it.
  Promotion (§6.3) happens at the next last-level compaction, which the level
  policy schedules; collection (§6.8) merges cold generations. So a perfectly
  healthy database with one clustered cold run and a live tail read **40 %**,
  and collecting could not move it. A bound whose remedies cannot reach the
  bytes it counts is not a bound.

Both reference implementations reproduced both the first time either verified a
fresh file. A bound a healthy database cannot satisfy is not a bound; it trains
its reader to ignore the metric.

The measurement that motivated the definition is unaffected: the nineteen runs
below are cold generations, which is what promotion produces and what collection
merges.

**An implementation MUST keep `locality_debt` at or below `locality_debt_pct`
(profile default: 20 %)** whenever the database is not under active write
pressure, by promoting (§6.3) or collecting (§6.8) surplus runs.

**Why it counts runs and not flags.** An earlier draft defined this as "live
bytes in segments *without* the clustered flag", and the reference
implementation showed that measures the wrong thing. After ageing a database by
ten times its size in random updates, it held **nineteen** live cold segments,
**every one of them internally sorted** — so the old definition read **0 %** —
while a key-ordered scan had to interleave all nineteen and cost **2.14×** a
fresh scan. Nineteen individually sorted runs are not one sorted run, and a scan
pays for the difference.

Under the definition above the same database reads **89 % debt**, which is what
a bound is for. Measured, with collection triggered on it:

| live runs | `locality_debt` | aged scan | `value_reads_per_scanned_row` | value-log space |
|---|---|---|---|---|
| 2 | 0 % | **1.00×** | 0.100 | 1.00× |
| 4 | ~40 % | 1.58× | 0.163 | 1.63× |
| 19 | ~89 % | 2.14× | 0.224 | 5.82× |

The bound is stated as an *outcome* rather than a mechanism because that is what
can be measured, tested and enforced. Scan performance over separated values
depends entirely on how many runs a scan interleaves, the degradation is gradual
and shows up months later as "the database got slow", and a format whose scan
performance silently decays is not acceptable.

**It is also the space bound in disguise.** The same surplus runs that cost a
scan are the ones holding dead bytes: at nineteen runs the value log was 5.82×
its live size against a `vlog_space_target_pct` of 150 %. An implementation that
collects on `locality_debt` gets `vlog_space_target_pct` for free; one that
collects only on space does **not** get locality for free, because a log can sit
inside its space target with its live data spread across many runs.

An implementation MUST expose `locality_debt` as a metric
(`13-operations.md` §6).

## 7. There is no write-ahead log

The durability record for a value is its value-log record; for a key, its L0
segment entry. Both are written once, in their final location, and are queryable
as soon as the superblock names them.

RocksDB and Fjall write each record to a journal *and then again* on flush —
Fjall's own accounting is three writes per item. Recovery here is not log replay:
it is reading the superblock (`10-transactions.md` §4).

## 8. Cursors

A cursor is the only iteration mechanism, and every implementation MUST provide
one.

```
Cursor := {
    heap:      a merge heap over one iterator per candidate segment
    per-seg:   a path stack (page_id, cell_index) from that segment's root
    snapshot:  seq watermark
    dedup:     collapse versions of a user key, honouring range deletes and TTL
}
```

Required, all O(1) amortized except where noted:

| | |
|---|---|
| `seek_first` / `seek_last` | O(levels × height) |
| `seek`, `seek_ceiling`, `seek_floor` | O(levels × height) |
| `next` / `prev` | O(log levels) heap step + O(1) amortized inside a segment |
| `skip(n)` | O(levels × height) via `subtree_entries` |
| `key()` / `value()` | O(1); `value()` MUST be lazy, so a key-only scan never touches the value log |

Because the last level is disjoint and tiers are range-partitioned, a scan
merges at most `l0_trigger + overlap_bound × (level_count − 2) + 1` sources —
the same bound as §4.1, a small bounded heap rather than an unbounded N-way
merge.

**Reverse iteration is a first-class direction**, not `next` collected and
reversed.

### 8.1 Value readahead — a MUST

**A cursor that dereferences values MUST issue its value-log reads in
non-decreasing `(vlog_segment_id, offset)` order within a sliding window of at
least `readahead_window` entries (profile default: 256), and MUST coalesce reads
of records that fall in the same page.**

Sorting a window of pointers turns scattered reads into mostly-sequential ones,
and over a `clustered` cold segment it turns them into strictly sequential
ones. Combined with promotion (§6.3), this is what keeps a scan returning whole
documents competitive with an engine that inlines them.

It is a MUST for the same reason §6.9 is: a conforming-but-slow implementation
here is indistinguishable from a broken one to the user, and the effect grows
with data age.

A key-only scan — an index scan, a count, a covering query — dereferences
nothing and is unaffected.

### 8.2 Snapshot binding

Cursors are bound to a snapshot; the segments and value-log segments they hold
are protected from reclamation by `min_retained_commit`
(`01-container.md` §6). A cursor MUST be closed.

## 9. Time to live

Optional per entry, via `entry_flags.HAS_EXPIRY` and a `u64 expiry_ms`
(Unix milliseconds, UTC). A tree turns it on with `params.ttl_ms` in its catalog
descriptor, or a writer sets it per entry.

- **Read**: an entry whose `expiry_ms` is at or before the reader's wall clock is
  invisible — treated exactly as a `DELETE`. Expiry is evaluated at read time, so
  it is exact regardless of when compaction runs.
- **Reclaim**: compaction drops expired entries under the rule in §5, and
  `min_expiry` in the segment header lets a compaction picker prefer segments
  with expired data.
- **Indexes**: an expired document's index entries carry the same `expiry_ms`, so
  index scans agree with collection scans without a lookup.
- **Clocks**: expiry uses wall-clock time and is therefore subject to clock
  changes. An implementation MUST NOT use expiry to enforce anything security
  relevant, and MUST treat a backwards clock jump as resurrecting entries rather
  than as corruption.

TTL exists because caching is one of Nitrite's most common embedded uses, and
the alternative — an application-level sweeper — costs a full scan and a write
per expiry.

## 10. Batch writes

`put_all(entries)` MUST be a first-class operation. A batch is sorted once and
inserted in order, and it acquires one seq range rather than one seq per entry.
A sorted batch of at least `segment_target_bytes / 4` SHOULD go directly to a
`clustered` COLD value-log segment and be bulk-built into a segment at the
lowest level that accepts it, skipping L0 entirely. The threshold is derived
from `segment_target_bytes` — a superblock field — rather than being a constant
of its own, because what the rule is really asking is "is this batch a
worthwhile segment on its own?", which is exactly what that field already
answers. (An earlier draft named a `bulk_threshold` that no chapter defined.)

## 11. Invariants a verifier checks

1. Internal keys strictly increase within a page and across pages of a segment.
2. Every internal separator is ≥ every key in the subtree left of it and ≤ every
   key in the subtree it points at.
3. `subtree_entries` sums correctly; all leaves of a segment are at one depth.
4. `prefix` is a prefix of every key on its page.
5. A segment's `min_seq`/`max_seq`/`min_expiry` match its contents; `min_key`
   and `max_key` *bound* its contents (§2.1 permits shortening, so equality is
   not required); and its manifest entry — including `level` and `group` —
   matches its header.
6. Segments at the last level do not overlap; segments within one tiered
   level-group do not overlap.
7. Every key in a segment passes that segment's filter.
8. Every `VLOG` pointer resolves to a record whose stored key equals the entry's
   user key, whose CRC validates, and which lies entirely below its segment's
   durable `bytes` watermark in tree 7 (§6.2).
8b. Every value-log segment's head page holds only immutable identity, and every
   mutable field for it exists in tree 7. A head page and a tree-7 entry that
   disagree on `segment_id`, `tier`, `heat` or `created_seq` is corruption.
9. Every value-log segment marked `clustered` in tree 7 really is in
   `(tree_id, CKE(key))` order, and its tree-7 `min_key`/`max_key` bound its
   records.
10. `live_bytes` in tree 7 is ≥ the true live bytes (conservative, never low).
11. `locality_debt` is at or below `locality_debt_pct`.
12. Reachable pages, value-log extents and free extents partition `page_count`
    with no overlaps and no leaks.
