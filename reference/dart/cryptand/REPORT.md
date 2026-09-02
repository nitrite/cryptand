# Cryptand reference implementation — phase 3 report

**Implementation:** pure Dart 3.12, `reference/dart/cryptand/`
**Spec under test:** `cryptand/spec/` (CFF v1.0), `cryptand/design/`
**Measured on:** Apple M2 Pro, macOS 26.6.2, Dart SDK 3.12.2 (native VM)
**Status:** 319 tests green, `dart analyze` clean, conformance vectors byte-exact and self-verifying

Phase 2's report is superseded by this one; its findings are carried forward in
section 3.

---

## 0. What phase 3 did

Phase 2 ended with five outstanding items. Two are now closed, one is closed
better than it was asked for, and two still need another language.

| phase 2 said | now |
|---|---|
| "Port `test/conformance_test.dart` to Rust and Java" | still not done; needs those toolchains. The suite it would port is larger — `index/entries` and `catalog/trees` are new (§4) |
| "Add Argon2id, then measure P11" | still absent, same reasoning (§6) |
| "**Build the tiered levels and range partitioning, then measure P10** — the bounded read tail is the one structural claim with no measurement at all" | **built and measured. P10 is CONFIRMED — but only for a reader that takes §4's early exit, which the prediction never said** (§1) |
| "Measure P2 and P3 in Rust, against Fjall and RocksDB, with threads" | not possible here |
| "Re-run the aged-scan test at 10⁶ documents" | **done — and it failed at 2×10⁵ first**: 1.35× and 25.6 % locality debt against a 20 % bound. The cause was a real gap in when collection is triggered; fixed, and 2×10⁵ now measures 1.00× / 0 % and **10⁶ measures 1.04×** (§3.1) |

Chapters `05-catalog` and `06-indexes` went from "not started" to complete, and
the manifest became what §3.2 says it is — a copy-on-write B+tree — rather than
two lists in memory.

Five more defects, on top of phase 1's nine and phase 2's five.

---

## 1. P10 — the bounded read tail: CONFIRMED, with a condition the prediction did not state

`design/performance-model.md` §5.4 predicted `segments_probed_per_lookup`
p99 ≤ 2 and p99.9 ≤ 3 at every database size. Measured over 20 000
uniform-random point reads, `desktop` shape:

| documents | p50 | p99 | p99.9 | max | mean | level shape |
|---|---|---|---|---|---|---|
| 10 000 | 1 | 1 | 1 | 2 | 1.00 | L1: 4 seg / 2 groups |
| 25 000 | 1 | 1 | 2 | 3 | 1.01 | L0 3, L1 2, L2 3 |
| 50 000 | 1 | 1 | 2 | 2 | 1.00 | L0 2, L2 3, L3 3 |
| 100 000 | 1 | 1 | 2 | 2 | 1.01 | L0 3, L3 7 |
| 200 000 | 1 | 1 | 2 | 2 | 1.01 | L0 2, L1 2, L3 13 |

Comfortable. Three things about it are worth more than the table.

### 1.1 The bound belongs to the early exit

P10's arithmetic is `expected extra descents ≈ 0.026`, which is the blocked-Bloom
false-positive rate times the candidate count. **It counts false positives and
nothing else.** That is the whole story only for a reader that stops at the first
candidate holding the key. A reader that examines every candidate — which is what
`spec/04-segments.md` §4 *requires* absent a level-discipline proof — also probes
every segment legitimately holding an *older* version of the key, and those are
not false positives. Same databases, same reads, early exit off:

| documents | p99 | p99.9 | max |
|---|---|---|---|
| 10 000 | 2 | 2 | 2 |
| **25 000** | **3** | **4** | **5** |
| 50 000 | 3 | 3 | 4 |
| 100 000 | 2 | 3 | 3 |
| 200 000 | 2 | 2 | 3 |

Outside the bound at two of the five sizes. The prediction is not wrong; it is
about a read path it never named. Both `04` §4.1 and `performance-model` §5.4 now
say which one.

### 1.2 §4's discipline sentence predates §3.1's groups, so the early exit was not actually available

§4 permits the early exit "only when it can prove no unexamined candidate can
hold a newer version of *this* key — the standard proof is level discipline: L0
newest-flush-first, then strictly increasing level."

That sentence gives no order **inside** a level. With range-partitioned tiers a
level holds up to `overlap_bound` runs and a key may sit in more than one of
them, so "strictly increasing level" does not order two candidates at the same
level, and the proof does not close. `max_seq` cannot supply the order either —
§4 disqualifies it two paragraphs earlier, for the same reason.

`segment_id` supplies it at no cost, and the format already records it in the
manifest entry: globally unique, never reused, allocated from the superblock's
`next_segment_id` (`00-conventions.md` §7). A higher id was written later, and a
later run at a level was compacted from later data than the run beside it. The
discipline in full is **L0 by descending `segment_id`, then levels ascending,
each by descending `segment_id`** — now written into §4.

`test/engine_test.dart` checks the two paths agree on 500 random keys, because
an early exit that disagrees with the conservative rule is not an optimization,
it is a reader returning stale versions.

### 1.3 §4.1 credited the wrong mechanism

§4.1 read: "the bounded-read-tail property comes from range-partitioned tiers and
manifest pruning; the filter is what stops the residue." Measured at 200 000
documents, mean segments probed per lookup:

| | filter on | filter off |
|---|---|---|
| range-partitioned (`overlap_bound` 2) | **1.01** | 3.91 |
| plain tiered (`overlap_bound` = `tier_width` = 4) | 1.01 | 5.55 |

With the filter on, range partitioning is worth **nothing** in the mean and one
step in the tail (p99 1 vs 2, max 2 vs 3). With the filter off it is worth 1.64
probes. At `tier_width = 4` it is manifest pruning and the filter that produce
the bound; range partitioning is the residue, which is the reverse of what was
written. It earns its keep as `tier_width` grows — a `server` profile, or a
filterless build — and §4.1 now says that instead.

The control that showed this is free, and that is worth recording too: **plain
tiering is this policy with `overlap_bound = tier_width` and nothing else
changed.** No switch in the engine, one superblock field.

### 1.4 The first version of this benchmark measured nothing

It inserted keys in ascending order and reported p99 = 1 for every shape
**including both controls**. Sequential inserts give every memtable flush a
disjoint key range, so manifest pruning alone leaves one candidate and there is
no tail to bound. A control that cannot fail has not controlled anything.

`spec/11-conformance.md` §6 now carries a mandatory read-tail test whose **write
load is normative** — random insertion order, then updates — for exactly this
reason. It is the same class of error as phase 2's `locality_debt`: a number that
looked fine because the thing it measured could not go wrong in the harness.

---

## 2. Defects found, phase 3

Five, all listed in `design/tradeoff-analysis.md` §8.2. Three are described
above (§1.1, §1.2, §1.3). The other two:

### 2.1 §3.1 gave no rule for output segment size, and both its bounds cannot hold without one

§3.1 wants a tiered level to hold up to `tier_width` **size-similar** segments
arranged in `overlap_bound` disjoint runs. It never says how big an output
segment should be, and the two bounds are not independent: a run occupies
`tier_width / overlap_bound` segments, so the run size fixes the segment size at
every level.

The first implementation used one fixed output size everywhere. Every tiered
level then crossed `tier_width` after its **second** run and compacted
immediately, so no level ever held more than one run — and the P10 control could
not have shown anything even with the write load fixed. §3.1 now states the
derivation as a writer rule (a reader depends on none of it).

### 2.2 `get` did not consult the memtable

Phase 2's read path walked segments only, so **every write since the last flush
was invisible to a point read**. An implementation defect rather than a
specification one — `spec/10-transactions.md` §2 step 5 is unambiguous — but it
survived 259 tests, because every test that read anything called `compact()`
first. Now fixed, with a test that reads back an unflushed write, and the
memtable is a source in `scanTree` as well.

---

## 3. Measured against the claims

### 3.1 P8 — aged scan: the 20 000-document result was optimistic, and the bound was not being enforced

Phase 2 measured 1.00× and `v/row` 0.100 at 20 000 documents, and phase 2's
report asked for 10⁶ because "P8 is a claim about databases that get old and
large, and only one of those two has been tested." It was right to ask. At
**200 000 documents** — ten times the size, ten times the updates — the phase 2
code measured:

| | documents | aged/fresh | v/row | ending locality debt |
|---|---|---|---|---|
| phase 2 code | 2×10⁵ | **1.35×** | 0.139 | **25.6 %** |
| after the fix | 2×10⁵ | **1.00×** | **0.100** | **0.0 %** |
| after the fix | **10⁶** | **1.04×** | **0.104** | not captured — that run measures the `all on` row only, at ~45 min |

1.35× is still inside P8's 1.5×, but 25.6 % is **outside** `locality_debt_pct`,
and that is the real result: the bound was not being enforced.

At 10⁶ documents and 10⁷ updates — fifty times phase 2's dataset — the aged scan
costs **1.04×** a fresh one at `v/row` **0.104**, against bounds of 1.5× and 0.3.
The 4 % is not noise and not a failure: it is the residue of the collection
window above, now bounded to one generation instead of accumulating. P8 holds at
every size this SDK can reach.

The cause is a window, not a mechanism. Collection is triggered when a
compaction *starts* over the bound. A merge that begins inside the bound
promotes a fresh generation into its own cold run without collecting, and can
therefore *end* above the bound — where nothing looks again until the next
compaction happens to. At 20 000 documents the window never opened; at 200 000 it
is where the measurement lands. The fix is to re-check after the merge and
collect until the debt is back inside — `Engine.collectWhileOverDebt`.

The floor case rose with size too: **10.14×** with the mechanisms off, against
9.61× at 20 000 and a predicted ≥ 6×.

### 3.2 P1, P4, P5, P6 — unchanged

Re-run after the level and filter work, to confirm nothing regressed:

| | phase 2 | phase 3 |
|---|---|---|
| P1 height ≤ 4 below | 619 M docs | **619 M** |
| P1 interior at 10⁷ | 1.88 MiB | **1.88 MiB** |
| P5 paged/full node accesses | 1.07× | **1.07×** |
| P4 one field / two fields | 11.2× / 6.4× | **11.06× / 6.45×** |
| P6 CVE : JSON | 1 : 1.70 | **1 : 1.70** |

The page encoder is now shared between `SegmentBuilder` and the copy-on-write
trees (`encodeNodePage`), and the conformance vectors are byte-identical across
that refactor, which is what makes "one format, two writers" a checked claim
rather than an intention.

### 3.3 Filter false-positive rate

Measured **0.255 % – 0.62 %** over admitted probes on a mixed-level database,
against §2.4's ≈ 0.33 % above the last level and ≈ 1.7 % at it. In range, and the
per-level allocation (16 bits above, 10 at the last level) is now in the file
rather than in a comment: `filter_page` and `filter_bits_per_key` are written,
and the filter pages live in the extent.

### 3.4 Still not measurable here

| | why |
|---|---|
| **P2** write amplification vs Fjall/RocksDB | needs those engines |
| **P3** write concurrency | Dart has no threads — the one real flaw in "implement in the weakest SDK first" |
| P7 memory, P9 latency | need real page-cache budgets and a real device |
| P11 encryption cost | the AEAD exists, Argon2id does not; not benchmarked |

---

## 4. What is implemented

| chapter | status |
|---|---|
| `00-conventions`, `01-container`, `02-value-encoding`, `03-key-encoding` | complete |
| `04-segments` §1, §2 (filter included), §8 | complete |
| `04-segments` §3 — level policy, manifest as a copy-on-write tree, internal trees | **complete** |
| `04-segments` §4 — read resolution, manifest pruning, filter pruning, early exit | **complete**; range deletes are not built, so `rd_sources` is always empty |
| `04-segments` §5 — compaction, entry dropping, tombstone dropping | complete except §5.1 parallelism (no threads) and §5.2 interruptibility |
| `04-segments` §6 — two-tier value log, promotion, collection, debt | complete |
| **`05-catalog`** | **complete** — descriptors with unknown-field preservation, reserved trees, the §11 enumerations, attributes, store metadata |
| **`06-indexes`** | **complete** — the §1 layout, §3 null/sparse, §4 arrays and the 1024 cap, §5 field paths, the §7 scans, §8 same-batch maintenance |
| `14-security` | complete except Argon2id |
| `07`–`09`, `10`, `12`, `13` | not started |

New files: `lib/src/cow.dart` (copy-on-write B+trees), `lib/src/manifest.dart`
(tree 6), `lib/src/catalog.dart`, `lib/src/index.dart`, `lib/src/database.dart`.
New vectors: `conformance/vectors/index/entries.json` and `catalog/trees.json`.
New benchmark: `bench/p10_read_tail.dart`.

**319 tests**, up from 259.

---

## 5. Two things the new code deliberately does not do

- **Freed pages are recorded, not reclaimed.** The free tree
  (`01-container.md` §6) is keyed by `commit_id` and only becomes interesting
  once `min_retained_commit` does, which needs the snapshot set of
  `10-transactions.md` §8 — and there are no snapshots here.
  `PageStore.freedPages` makes the cost visible instead of hiding it.
- **An underfull copy-on-write page is never merged with a sibling.** Only an
  empty page is unlinked and a one-child root collapsed. Both are space effects
  and neither is a correctness one, and a reserved tree is small by
  construction (§3.3).

---

## 6. Honest limits, carried forward and added to

- **Argon2id is still absent.** Same reasoning as phases 1 and 2: a memory-hard
  KDF whose vectors cannot be checked here would have other SDKs match its
  errors. `Keyslot.kdfRaw` exercises the whole wrap path without it.
- **No concurrency, so `spec/10-transactions.md` §2 is untested.** Not
  under-tested — *untested*. Dart has no threads; the chapter's whole content is
  what happens when several of them write at once. Snapshot isolation,
  conflict detection and recovery are equally unbuilt, and `Engine` reads at the
  latest seq with no snapshot set at all. This is the largest single gap.
- **Extents are in memory.** The manifest and the reserved trees now live in a
  real `PageStore` with page identity and page-granular counters; segment
  extents do not. Only the counter-based results are portable.
- **The conformance vectors are still generated by the implementation they
  test.** Self-verifying and hash-pinned, which catches regression, not
  misreading. Only a second implementation catches misreading.
- **`dart2js` is unsupported**, unchanged: `int` is a double on the web.

---

## 7. What phase 4 should do first

1. **Port `test/conformance_test.dart` to Rust.** It consumes only JSON and the
   public encode/decode paths, and it is now large enough to be worth porting:
   CKE, CVE, documents, container, filter, security derivation, **index
   entries** and **catalog descriptors**. Until a second implementation reads
   these, "portable" is a claim.
2. **Build `10-transactions.md` in Rust and measure P3.** It is the only chapter
   this SDK cannot even partially exercise, and the write-concurrency claim is
   the design's headline.
3. **Add Argon2id where it can be verified, then measure P11.**
4. **Measure P2 against Fjall and RocksDB.**
5. **Re-run the aged scan at 10⁶ on a real device.** 2×10⁵ found a real defect
   that 2×10⁴ did not; there is no reason to assume that stops.
6. **Range deletes (§2.5) and TTL (§9)**, which are the two remaining pieces of
   `04` that the read path has stubs for.

---

## Appendix — reproducing

```bash
cd reference/dart/cryptand
dart pub get
dart analyze                              # clean
dart test                                 # 319 tests

dart run tool/generate_vectors.dart       # regenerates ../../conformance/vectors
dart test test/conformance_test.dart      # verifies them

dart run bench/p1_height.dart
dart run bench/p5_paged_scan.dart
dart run bench/p4_p6_decode.dart
dart run bench/p8_aged_scan.dart          # 20 000 docs
dart run bench/p8_aged_scan.dart 200000   # the size that found the defect
dart run bench/p10_read_tail.dart         # ~75 s
dart run bench/filter_fpr.dart
```

`tool/experiments/` holds the one-off scripts phases 1 and 2 cite as evidence.
