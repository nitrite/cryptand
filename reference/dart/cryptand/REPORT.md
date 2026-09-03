# Cryptand reference implementation — phase 13 report

**Implementation:** pure Dart 3.12, `reference/dart/cryptand/`
**Spec under test:** `cryptand/spec/` (CFF v1.0), `cryptand/design/`
**Measured on:** Apple M2 Pro, macOS 26.6.2, Dart SDK 3.12.2 (native VM)
**Status:** 533 tests green, **no skips**, `dart analyze` clean, conformance vectors byte-exact and self-verifying, `dart analyze` clean, conformance vectors byte-exact and self-verifying

Earlier phase reports are superseded by this one; their findings are carried
forward. **Phase 4 was short and had one theme**: it was prompted by the question
"why does a portable format spec have implementation details in it, and why does
a feature need Rust?" — and the answer turned out to be one correction and one
audit, both of which are now in the documents. Section 0.1 is the whole of it.

---

## 0.-7 Phases 12 and 13 — spatial, vector, and the end of the chapter list

Phase 12 built `spec/08-spatial.md`, phase 13 built `spec/09-vector.md`, and
**neither found a defect**. With them, **every chapter of the specification has
an implementation.**

### Spatial (`08`)

ISO WKB with EWKB rejection, the in-container R-tree of §2.1, a quadratic
split, and the exact predicates §4's two-phase rule requires. 21 tests.

Two rules are the ones that matter, because a plausible implementation of either
is silently wrong:

- **§1's EWKB rejection.** PostGIS sets high bits of the same type word ISO uses
  *additively* — "a `PointZ` is `1001` in ISO and `0x80000001` in EWKB, and a
  decoder that guesses wrong reads coordinates as garbage". A reader accepting
  both produces geometry that decodes cleanly and means nothing. All three flag
  bits are refused, with the reason in the error.
- **§4's two-phase rule.** "An implementation MUST NOT return box-level results
  as if they were exact." The test uses a triangle whose bounding box contains
  the origin and whose area does not: phase one returns it, phase two rejects
  it. A box-only implementation returns a wrong answer that looks entirely
  reasonable — which is why the rule is normative rather than advisory.

§2.2's structural invariants are verified rather than assumed: all leaves at one
depth, and every internal box the **exact** union of its children — "a box that
is merely a superset is a defect because it silently degrades every query".

§2.2 also declines to specify the split algorithm, and §2.3 says why that is
safe: "two implementations inserting the same documents will produce different
(equally valid) trees. A conformance test therefore compares **query results**,
never tree shape." So this implementation picks quadratic split and the tests
assert results.

### Vector (`09`)

The `VECTOR_REGION` layout, the adjacency record, the codebook, the two
slot↔document maps and §8's search contract. 20 tests.

The chapter's principle is why this is a few hundred lines rather than a vector
database: **"specify the durable layout, not the algorithm."** There is no HNSW
construction here, no Vamana, no recall tuning — none of that is in the format.
§8 is explicit: "Recall is not specified. Two conforming implementations may
return different neighbours for the same query."

Three things §9 *does* specify, all tested:

- **Deletes are correct immediately.** §6: removing both mappings makes a
  document disappear from search before consolidation touches the graph — "the
  FreshDiskANN property `nitrite-vector` already implements".
- **The brute-force fallback.** §8: an implementation that will not traverse a
  graph another SDK built "MUST then fall back to a brute-force scan of the
  vector region, which is always possible and always correct, rather than
  returning nothing". That is what lets a Flutter app open a database whose
  vector index only a Rust service maintains — §9's "specific interchange
  scenario this whole format exists for".
- **No mmap anywhere.** §2: "An implementation that cannot `mmap` reads
  positionally. Dart does exactly this... No part of this format requires mmap."
  The region here is read positionally and the layout is identical.

---

## 0.-6 Phase 11 — full text, checked against Unicode's own suites

Built `spec/07-fulltext.md`: the `cryptand.std.v1` analyzer, the three trees
(`term_dict`, `term_index`, `postings`), the §4.2 block layout, term and phrase
queries, and the `analyzer/` conformance vector set `11-conformance.md` §6
names. **No defects found.**

### The part that matters is what it was checked against

The chapter's first paragraph: "Full text is the hardest thing in this format to
make portable, and the reason is not the postings — it is the **analyzer**."
The top-level `README.md` calls full-text tokenization one of the **two
genuinely hard parts** of the whole proposition.

Dart's standard library supplies **none** of what §2.2 requires — no NFKC, no
UAX #29 word segmentation, no `Simple_Lowercase_Mapping`. `String.toLowerCase()`
is close, and close is precisely what produces two indexes that disagree about
what documents exist. So all three were implemented against tables generated
from the **Unicode 15.1.0 UCD** (the release §2.2 pins) and verified against
Unicode's published conformance suites:

| suite | cases | failures |
|---|---|---|
| `NormalizationTest-15.1.0` — NFC and NFKC | **19 074** | **0** |
| `WordBreakTest-15.1.0` — UAX #29 word boundaries | **1 826** | **0** |

Both on the first run. Both data files are committed under
`reference/conformance/unicode/`, so the check is reproducible rather than a
claim, and `test/fulltext_test.dart` runs them as ordinary tests.

**This is the strongest evidence this project has produced for
`00-conventions.md` §1.1** — that naming an algorithm is what makes a format
portable rather than what constrains it. Phase 4 showed it for Argon2id, where
the vector set is a handful of cases. Full text is where the argument is hardest
to believe, because the analyzer is eight steps over the entire Unicode
character database — and a language whose runtime offers none of the required
operations still reproduced all 20 900 published cases from the specification
alone.

### The three traps §2.2 names, each tested

- **Locale-sensitive lowercasing.** `I` → `i`, never `ı`, because the mapping
  is table-driven rather than `String.toLowerCase()`.
- **Full case folding is not simple lowercasing.** `STRAẞE` → `straße`, not
  `strasse`. The test asserts both the equality and the inequality.
- **Unicode version drift.** The tables report `15.1.0`, and
  `Analyzer.requireUnicode` refuses an index pinning anything else — §2.2's
  "MUST refuse to write an index whose analyzer pins a version they do not
  have".

### One design detail worth flagging to implementers

§2.2 step 8 makes a token's position "the index of the segment among the
segments emitted from step 3, **before filtering**". So dropping a stopword
leaves a **gap** rather than shifting everything after it — which is what makes
a phrase query mean the same thing whether or not a stopword list was
configured. It is easy to miss and impossible to detect later without
re-indexing, so it has its own test and its own conformance case.

### What is not implemented, and why that is the specified behaviour

`porter2` stemming (§2.4). Declaring it and not having it is not a gap to paper
over: §2.1 says an implementation that cannot reproduce the named analyzer
exactly MUST NOT write to the index, so `Analyzer(stemmer: 'porter2:en')`
**throws** rather than tokenizing approximately. That is the specified failure —
loud and specific — and it is tested as such.

---

## 0.-5 Phase 10 — chapter 13 finished

Built the rest of `13-operations.md` that a single-process implementation can:

| | |
|---|---|
| **§2 backup** | online full and incremental, with the uuid rule, the two encrypted modes and the verify-before-success requirement |
| **§5 space API** | `compactStep`, `collect`, `cluster`, `shrink`, `add_key`, `remove_key`, `crypto_erase` — all incremental, which §5's closing line requires and which phase 9's stepwise compaction made possible |
| **§7 change feed** | tree 9, per-tree opt-in, appended in the same batch as the mutation |

Nineteen tests, green on the first run, **no defects found**.

### Three MUSTs that are now enforced rather than described

Each is silent when violated, which is why they are tested rather than trusted:

- **A backup MUST NOT copy the source's `database_uuid`.** Not tidiness:
  `14-security.md` §3.4 derives every subkey with the uuid as HKDF salt, so two
  files sharing one **share a content key**, and a nonce repeating across them
  is a real collision. `Backup.full` refuses.
- **The ciphertext copy is the exception, for exactly that reason** — it is the
  same cryptographic object, so it keeps the binding. The result carries the
  warning §2.1 requires: it MUST NOT be opened for writing while the source is,
  because two writers allocating from one `next_nonce` lineage collide.
- **An unencrypted backup of an encrypted database is a silent downgrade** and
  is refused unless asked for by name, then reported in the result.

### The incremental backup property, measured

§2.2: "an incremental backup's size is proportional to what changed, not to
what the changes touched." Tested directly — a second backup with nothing
changed copies **zero** segments, and after touching 20 of 600 documents the
delta copies strictly fewer segments than the full backup did. That is what
immutable segments give and an in-place B-tree cannot.

### A second clean chapter, and what the two have in common

This is the second time a chapter has gone in with no defects — phase 6's range
deletes and TTL were the first. Both are sections **written once and not revised
under review**. The chapters that have produced defects are the ones rewritten
between review rounds, which is where the unwritten assumptions entered.
`design/tradeoff-analysis.md` §8.9 records it as evidence rather than as a
theory.

### What is left of chapter 13

**§8, multi-process readers.** It cannot be built here in any meaningful sense:
the content is a lock sidecar coordinating *processes*, and this implementation
has no file under it. Modelling it in memory would test the data structure and
none of the property.

---

## 0.-4 Phase 9 — clearing the board

Phase 9 fixed what earlier phases had recorded rather than repaired. Two items,
and after them **no test is skipped and no mandatory conformance test this SDK
can run is failing**.

### The foreground stall budget: 22.3 ms → 3.10 ms

`12-profiles.md` §4 is normative for every profile and phase 8 measured this
implementation failing it at **22.3 ms against `mobile`'s 8 ms**, because a
`put` that filled the memtable ran the flush *and* the whole compaction cascade
synchronously on the caller.

Built `04-segments.md` §5.2: a compaction is now a resumable [CompactionJob]
that merges `compaction_step_bytes` and yields. §5.2's own argument is what makes
holding that state cheap — "the partially built output is just a prefix —
abandoning it costs the work done and nothing else, and no reader can see it" —
and a test now exercises exactly that, abandoning a part-done job mid-cascade
and asserting no reader can tell.

| | worst put | over an 8 ms budget |
|---|---|---|
| before (cascade on the caller) | 22.3 ms | many |
| **after, 256 KiB steps** | **3.10 ms** | **0 of 4000** |
| control: unbounded steps | 10.03 ms | 1 of 4000 |

The control matters: without it the test would pass on any fast enough machine
and prove nothing about the decomposition.

**One honest note.** The first measurement of the *fixed* engine still showed a
single 21.7 ms `put` — at index 199, the first flush, while the identical flush
a moment later cost 0.7 ms. That is Dart's JIT compiling the segment builder on
first execution, not the decomposition. Flutter ships release builds
AOT-compiled so it does not arise on the target, but on a JIT runtime the first
write of a cold process really does stall; the test warms the path deliberately
and says why, rather than quietly.

### An API boundary moved, and P10 improved because of it

A `flush` no longer drains the level policy — that is §4's bulk/foreground
distinction made real. Bounded work happens on the caller; a caller wanting the
shape settled calls `drainCompaction()`, the "explicitly requested bulk
operation" §4 exempts.

P10's benchmark had been relying on the implicit drain. Told to ask for it, P10
**improved**:

| documents | phase 8 p99 / p99.9 | phase 9 p99 / p99.9 | settled shape |
|---|---|---|---|
| 10 000 | 1 / 1 | 1 / 1 | L1: 4 seg, 2 groups |
| 25 000 | 1 / 2 | 1 / 2 | L0 3, L2 4 |
| 50 000 | 1 / 2 | **1 / 1** | L3 4 |
| 100 000 | 1 / 2 | **1 / 1** | L3 7 |
| 200 000 | 1 / 2 | **1 / 1** | L3 13 |

The settled shape is reached more cleanly than the old cascade-inside-flush
reached it. P8 is unchanged at 1.00× / 0.100, at 2×10⁴ and at 2×10⁵.

### Metrics that were reporting numbers nothing measured

`13-operations.md` §6 exists so that questions are answerable from outside, and
**a fabricated answer defeats that more thoroughly than a missing one**:
`page_cache_hit_rate` returned 1.0 and `unencrypted_pages` returned 0 from an
engine that measured neither. `page_cache_hit_rate: 1.0` reads exactly like a
perfect cache.

Four are now really measured — `page_cache_hit_rate` from the segment
node-access and page-read counters, `value_reads_per_scanned_row` from the last
scan, `compaction_backlog_bytes` from what the level policy still wants, and
`stall_events` from §4's own samples. The four that cannot be are **declared
unavailable by name**.

§6 now carries the rule, because "MUST expose" invites exactly the failure it
got here.

---

## 0.-3 Phase 8 — the verifier, repair, profiles, and a test that failed

| | |
|---|---|
| **the verifier** (`04` §11, `01` §9) | the invariants, including §11.6's disjointness check — the one that would have caught phase 5's worst defect — and §11.5's header-against-manifest agreement |
| **repair** (`13` §3) | the manifest rebuilt by scanning segment headers, which is §3's central bet |
| **profiles** (`12`) | the behavioural constants, host hints, `set_profile`, `reprofile` |

That closes the last two mandatory conformance tests this SDK can run — and one
of them fails.

### The verifier caught a live bug on its first run, in the repair path

`13-operations.md` §3: "A verifier MUST check header-against-manifest agreement
on every duplicated field, **or the redundancy rots unnoticed until the day it
is needed**."

It had rotted. **Every segment above the last level carried `group = 0` in its
header while its manifest entry recorded the real group.** The builder was
constructed before the group was chosen. Nothing had ever compared the two, so
nothing noticed.

The consequence is not cosmetic. `rebuildManifest` reads `group` back out of the
headers — that is the *only* reason `group` is in a header at all
(`04-segments.md` §2.1) — so a repair would have re-filed two disjoint runs into
one group, which then overlaps, which breaks §4's early exit. **A repair that
silently corrupts the level structure is worse than no repair.** Fixed: the
group is decided before the outputs are built.

Two things about this are worth stating. The spec predicted the failure mode
exactly, in the sentence quoted above. And the format's own redundancy design
was vindicated on the first occasion anything checked it.

### A second defect, made reachable by phase 7

**Scans sourced their cursors from the extent map rather than from the
manifest**, so they read segments the manifest had retired. Harmless while
compaction keeps the two in step — and wrong the moment they are not, which
checkpoints made reachable: after a `restore` the manifest points at an older
root while every later segment's bytes are still present, so a scan returned
exactly the data the restore was supposed to abandon. Verified before and after:
100 rows before the fix, 50 after, 50 expected.

Same shape as phase 5's defect 33 — a rule that held under an assumption nobody
wrote down, here "the manifest and the extent map agree".

### A spec contradiction the mandatory test exposed

`11-conformance.md` §6 required: "create under `mobile`, write, call
`set_profile(desktop)`…". `12-profiles.md` §6 says `page_size` **cannot
change** — and `mobile` is 4 KiB while `desktop` is 8 KiB. **The mandatory test
asked for the one conversion the format refuses**, and no conforming
implementation could have run it. §6 now requires the two profiles to share a
page size and names `mobile ↔ tablet` as the usable pair.

### The mandatory test this implementation failed — **fixed in phase 9**

`12-profiles.md` §4's foreground stall budget is normative for every profile,
and phase 8 measured this implementation failing it: **22.3 ms against
`mobile`'s 8 ms budget**, because a `put` that filled the memtable ran the flush
and the whole compaction cascade synchronously on the caller.

The cause was `04-segments.md` §5.2's stepwise, interruptible compaction, listed
as unbuilt since phase 3. Phase 8's contribution was to **measure** it against
the budget rather than note it as missing, and to write the mandatory test.
Phase 9 built §5.2 and the test passes at 3.10 ms (§0.-4).

The part of the write path that was already decomposed passed even then: a `put`
that did not trigger a flush stayed far inside the budget, which located the
problem precisely at the compaction cascade.

---

## 0.-2 Phase 7 — checkpoints, planner statistics, and the stale-version test

| | |
|---|---|
| **checkpoints** (`13` §1) | tree 8; a named retained snapshot, one small write, "an undo point around a migration for the price of one tree entry, which is not something the current storage backends can offer at any price" |
| **planner statistics** (`13` §9) | HyperLogLog `distinct_estimate` and an equi-depth histogram, completing what `06` §7.1 promised |
| **the stale-version test** | `11` §6's third mandatory test, now written |

### One defect: a bound stated over the wrong dimension

**§9 caps the histogram at 64 *buckets*, and that does not bound its size.**
Bounds are CKE keys, a CKE key runs to kilobytes, and `params.stats` lives in a
catalog descriptor — which is **one cell of a copy-on-write B+tree** and must
fit one page. Measured: 64 bounds over 300 string keys came to **4734 B against
a 4096 B page**, and the descriptor could not be written at all.

§9 now bounds it in bytes, with 64 as a maximum rather than a target, dropping
alternate buckets so the histogram stays equi-depth at twice the width. That is
safe for exactly one reason and §9 already stated it: statistics are advisory,
so a coarser histogram is a worse estimate and never a wrong answer.

This is the first defect here found by the format's **layering** rather than by
a measurement. Nothing about statistics is wrong and nothing about the
copy-on-write trees is wrong; the two chapters were each internally consistent
and disagreed only where they met. A single-chapter review cannot catch that.

### The mandatory stale-version test, and a fixture bug worth admitting

`11` §6 requires: "Build a file in which a segment at a *lower* level has a
higher `max_seq` than a segment above it, from an unrelated key, while both
cover the queried key." Written, and it passes.

The first version of it queried id 500 while its own padding loop wrote
`i * 10` for `i` up to 100 — so the fixture overwrote the key under test and the
assertion was measuring itself. Caught because the expected bytes did not match;
it would have passed silently had I chosen the padding differently. Same class
as phase 3's ascending-insert benchmark, and worth recording each time.

### What phase 7 did not find

Checkpoints went in from §1 with **no defects**, and both of the section's
load-bearing rules are now tested: `checkpoint_root` is deliberately not
captured, so a restore does not delete its own siblings; and a restore rolls
back roots but **never counters** — the one with a security consequence, since
rolling `next_nonce` back would reissue nonces against pages still in the file.

Worth naming why restore *works* here: the page store never reclaims freed pages
(a simplification recorded in phase 3 §5), so an old copy-on-write root stays
readable. A production implementation gets the same property from retention
instead — and a checkpoint pinning `min_retained_commit` is exactly what makes
that safe, which is §1's own argument.

---

## 0.-1 Phase 6 — chapter 04 finished, and the operational surface

Phase 6 completed `spec/04-segments.md` and built the part of
`spec/13-operations.md` that every conformance level requires:

| | |
|---|---|
| **range deletes** (`04` §2.5) | `clear()`, `drop()` and bulk-insert rollback become **O(1) writes** rather than O(n) tombstones |
| **time to live** (`04` §9) | per-entry `expiry_ms`, evaluated at read time so it is exact whenever compaction runs |
| **corruption containment** (`13` §4) | one damaged page no longer makes the database unreadable |
| **required metrics** (`13` §6) | the normative observability surface, in `lib/src/metrics.dart` |

**Two of these are mandatory conformance tests** (`spec/11-conformance.md` §6)
and both now exist.

The range-delete-under-filter test needs a specific construction to be worth
anything: the segment carrying the range delete must **not** hold the deleted
key as a point key, so its filter genuinely answers "absent" for it. The test
asserts `filter.mayContain(key) == false` *before* asserting the key is still
deleted — otherwise it would pass for the wrong reason, which is the same trap
as phase 3's ascending-insert benchmark.

The containment test corrupts a page in the middle of a mid-level segment and
checks all five of §4's steps: the segment is identified, its key range is
reported **from the manifest** (so the range is knowable without touching the
damaged extent — that is what makes containment cheap), every key outside is
still served, every key inside fails with `UnavailableRangeException` naming the
range rather than returning null, and the affected trees are marked so a planner
does not substitute an incomplete index scan. Measured: most of the database
survives one bad block.

### One defect, and it is a gap

**§4 mandates containment; §6's required-metric list had no way to observe it.**
A partially-available database was therefore indistinguishable from a healthy
one until a read happened to land in the hole — a caller could not ask "is this
database whole?", which is precisely the class of question §6 exists to make
answerable. `unavailable_ranges` is now in §6, with 0 as the normal state.

### And one non-finding worth recording

Range deletes and TTL were implemented straight from the chapter with **no
defects found** — fourteen tests, green first run. Those are among the oldest
and least-revised sections in the spec. It is mild evidence that this project's
defect density is concentrated in the parts that were *rewritten under review*
rather than spread evenly: a section revised three times has had three chances
to acquire an unwritten assumption, and §2.5 is nine lines that have had none.

---

## 0.0 Phase 5 — chapter 10, and the worst defect this project has found

Phase 5 implemented `spec/10-transactions.md` apart from §2, the concurrent
write protocol, which needs threads Dart does not have. Everything else in the
chapter is independent of thread count and is now built and tested: snapshots
(§1), the commit and its ordering invariants (§2.3), transactions with all four
isolation levels, conflict detection and savepoints (§3), the normative
backpressure curve (§6), durability reporting (§7), retention watermarks (§8),
store events (§9) and close (§10).

That split matters: a single writer still has to get **atomicity, visibility,
conflict detection and retention** right, and those are where a database returns
wrong answers rather than slow ones. Which is exactly what happened.

### The last level had quietly stopped being disjoint

`spec/04-segments.md` §3.1 says the last level's "segments partition the key
space with no overlap". The compaction's overlap test compared whole **internal**
keys — and an internal key is `tree_id ‖ CKE(key) ‖ ~seq ‖ op`. Two segments
holding *different versions of the same user key* therefore occupy **disjoint**
internal-key ranges: one holds `~11 … ~5`, the other `~4 … ~1`. The test
reported "no overlap", the merge left both in place, and the level stopped being
disjoint.

Everything structural still passed. `min_key` and `max_key` were right,
`subtree_entries` was right, every checksum verified, the manifest was
consistent. What broke was the read: §4's early exit rests on at most one
segment per group covering a key, so a lookup stopped at whichever of the two it
reached first and **returned a stale version** — version 8 of 11, in the test
that caught it.

**It had been there since phase 3, under 338 passing tests**, including a
read-tail benchmark whose entire subject is which segments cover a key. It
stayed hidden because an engine that drops every superseded version at the last
level has exactly one entry per user key there — so internal-key and user-key
disjointness *coincide*, and the test is accidentally correct. It only diverges
once versions are genuinely retained, which needs a live snapshot, which is what
§5's condition 2 does, which is what phase 5 added.

`04` §3.1.1 is new and states the rule; `01` §9 step 3's verifier check now says
user keys too.

### Two more, both about retention

- **`min_retained_seq` floors at `visible_seq`, so a watermark that never
  advances makes retention unbounded.** Compaction can then never satisfy §5's
  condition 2, keys never collapse, and the key index grows without bound while
  the value side looks perfectly healthy — measured as the aged scan's key pages
  going **34 → 369** with its value-page count unchanged. `10` §8 now says the
  watermark advances whenever a batch's records become durable.
- **`pinned_by_snapshots` is not `allocated − live`.** A snapshot's effect is to
  stop superseded versions from *becoming* dead, so the bytes it pins never
  enter that difference, and the obvious derivation reads **0** on a database
  holding a large pinned set. `13` §6 listed the metric without saying how to
  derive it; it now says to accumulate it at the retention decision itself.

### What §2 costs to skip

`spec/10-transactions.md` §2 is not implemented and **prediction P3 remains
unmeasurable here**. That is the whole of what `Level 0 (single-writer)` gives
up (`11` §1.1), and it is worth being exact about what is *not* given up: the
files this implementation writes are byte-identical to a concurrent writer's,
and every rule in §1, §3, §4, §5, §6, §7, §8, §9 and §10 is exercised.

---

## 0.1 Phase 4 — language independence, audited and tested

The question was whether the spec is truly implementation-language independent,
with Argon2id offered as the example of a "Rust-specific detail".

**On Argon2id the premise was wrong, and this phase disproves it with running
code.** Argon2id is RFC 9106, the Password Hashing Competition winner, with
implementations in every mainstream language. It is now implemented **in pure
Dart, in `lib/src/argon2.dart`, with no dependency**, together with the BLAKE2b
it is defined over, and both reproduce their RFCs' published vectors byte for
byte — RFC 9106 §5.3's pre-hashing digest **and** its 32-byte tag, and RFC
7693's `BLAKE2b-512("abc")` digest plus **all thirteen** of the working vectors
Appendix A prints around its twelve rounds. That closes the item that has been
open since phase 1. It was never a language matter: the reason it waited was
that a memory-hard KDF whose output has not been checked against published
vectors must not ship, because a subtly wrong KDF still "works" and every SDK
that copies it reproduces the error.

`spec/00-conventions.md` §1.1 is new and states the rule the spec follows, so
this question has a written answer next time:

> the bytes → normative and fully specified, algorithms named to the parameter;
> the host runtime → a **declared capability**, never a bare MUST;
> why a rule exists → non-normative.

**On the general point the question was right, and the audit found four real
leaks** — none of them an algorithm, all of them requirements about the *host*
rather than the bytes. All four are fixed:

| where | was | now |
|---|---|---|
| `10` §7 | "**A Dart implementation** cannot reach `F_FULLFSYNC` without FFI and MUST therefore report `sync` on Darwin" | two language-neutral MUSTs — use the strongest primitive the platform provides, record what you actually performed. The syscall table is demoted to non-normative guidance |
| `10` §7 | the platform table was normative, and one of its entries (`FileChannel.force`) is a *Java API*, not an OS primitive | non-normative |
| `11` §1.1 | "A single-isolate **Dart** implementation MAY declare `Level 0 (single-writer)`" | written against the capability — "a runtime without shared-memory threads" — with Dart and JavaScript as worked examples |
| `11` §7 | "One reference implementation, **in Rust**" | marked non-normative; the reference's language is a project decision, and §7 already said the reference is not normative |
| `14` §11 | a normative table with **Java / Dart / Rust** rows | rules keyed to language *properties* (immutable strings, moving collectors, deterministic destruction); the three SDKs move to a non-normative note |
| `04` §5.2, `12` | MUSTs justified by "on Flutter … a 16 ms frame budget" | the MUSTs stand; the justification is generalised, and the bound was already a profile constant |

**One claim in my own audit was wrong and is worth recording.** I said Level 0
was unreachable for a single-threaded runtime. It is not: `11` §1.1 already had
the carve-out and `11` §1.2 already had a `single-writer` reduced write profile.
The mechanism was right; only its wording named a language.

A re-scan for "a requirement keyword on the same line as a language or platform
token" now returns five hits, all correct: the struck-through counter-example in
the new §1.1, the `JavaScript`/`BigInt` rule (which binds *a class of languages*
and names one as an instance — the pattern §1.1 explicitly endorses), and two
rules in `03` that constrain **bytes** while naming the SDK construct being
retired.

### Phase 4 also measured P11, and its open half missed

With Argon2id present, prediction P11 became measurable for the first time. Its
two halves are reported separately, because `performance-model` §5 says
averaging them is how an encryption overhead number becomes meaningless.

| half | measured | against |
|---|---|---|
| open, `mobile` (t 3, m 64 MiB, p 1) | **405 ms** | "~250 ms on a mid-range ARM" |
| open, `desktop` (t 4, m 256 MiB, p 4) | **2183 ms** | "~500 ms" |
| steady state, 4 KiB page | 53.9 µs encrypt / 53.5 µs decrypt — 73 MiB/s | not comparable; see below |

The KDF is not slow for a reason worth fixing: its memory-filling core runs at
**~473 MiB/s**, about 3–6× off a native implementation, which is ordinary for a
scalar VM. **The targets are what missed** — they were costed against a native
Argon2id with parallel lanes, and `mobile` is `p = 1`, so it has no lanes to
recover with and is also the profile most likely to be running an interpreted
runtime. `spec/14-security.md` §3.2 now says so and names the three conforming
ways out, of which "use a hardware-backed platform keystore via `kdf = 0`" is
the right answer on a phone and removes the cost entirely.

**The steady-state half is not measured against P11's terms and must not be read
as if it were.** There is no storage under this implementation, so the ratio P11
predicts cannot be formed. 73 MiB/s is the cost of the primitive in the slowest
reasonable implementation of it. Its use is as the constant a real-device
measurement divides by — and on that reading it is a warning: a pure-Dart SDK is
**cipher-bound rather than storage-bound**, which inverts P11's premise for that
SDK specifically.

### One more defect, found by a test that had rotted

`test/conformance_test.dart` asserted that XChaCha20-Poly1305 and Argon2id were
**not implemented**, reading a `not_implemented` list out of the security
vector. The AEAD landed in phase 2. The assertion kept passing for a whole phase
because the generator's list went stale and the test enforced the staleness. **A
test that asserts what is absent rots into asserting what is present.** It now
asserts the list is empty and that each primitive reproduces a published vector.

---

## 0. What phase 3 did

Phase 2 ended with five outstanding items. Two are now closed, one is closed
better than it was asked for, and two still need another language.

| phase 2 said | now |
|---|---|
| "Port `test/conformance_test.dart` to Rust and Java" | still not done; needs those toolchains. The suite it would port is larger — `index/entries` and `catalog/trees` are new (§4) |
| "Add Argon2id, then measure P11" | still absent — for want of verified vectors, not for want of a language (§6) |
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
| `04-segments` §1, §2 (filter and **range deletes**), §8, **§9 TTL** | complete |
| `04-segments` §3 — level policy, manifest as a copy-on-write tree, internal trees | **complete** |
| `04-segments` §4 — read resolution, manifest pruning, filter pruning, early exit, **`rd_sources`** | **complete** |
| `04-segments` §5 — compaction, entry dropping, tombstone dropping, **retention**, **§5.2 stepwise interruptible steps** | complete except §5.1 parallelism, which needs threads |
| `04-segments` §6 — two-tier value log, promotion, collection, debt | complete |
| **`05-catalog`** | **complete** — descriptors with unknown-field preservation, reserved trees, the §11 enumerations, attributes, store metadata |
| **`06-indexes`** | **complete** — the §1 layout, §3 null/sparse, §4 arrays and the 1024 cap, §5 field paths, the §7 scans, §8 same-batch maintenance |
| `14-security` | **complete**, Argon2id included and vector-verified |
| **`10-transactions`** | **complete except §2** — the concurrent write protocol needs threads Dart does not have |
| **`13-operations`** | **complete except §8**, multi-process readers, which needs real files and processes |
| **`12-profiles`** | **complete**, §4's budget measured and **met** (§0.-4) |
| **`01-container` §9 / `04-segments` §11** — the verification pass | **complete** for the invariants this engine can express |
| **`07-fulltext`** | **complete** except `porter2` stemming, which §2.1 makes a refusal rather than an approximation |
| **`08-spatial`** | **complete** — WKB, the R-tree, the §4 queries and their exact phase |
| **`09-vector`** | **complete** — the durable layout of §2–§6 and §8's search contract; the graph *algorithms* are explicitly not part of the format |

New in phase 3: `lib/src/cow.dart` (copy-on-write B+trees),
`lib/src/manifest.dart` (tree 6), `lib/src/catalog.dart`, `lib/src/index.dart`,
`lib/src/database.dart`, `bench/p10_read_tail.dart`, and the
`index/entries.json` and `catalog/trees.json` vectors.

New in phases 12 and 13: `lib/src/wkb.dart`, `lib/src/geometry_ops.dart`,
`lib/src/rtree.dart`, `lib/src/vector.dart`, `test/spatial_test.dart`,
`test/vector_test.dart`.

New in phase 11: `lib/src/unicode.dart`, `lib/src/unicode_tables.dart`
(generated), `lib/src/analyzer.dart`, `lib/src/fulltext.dart`,
`test/fulltext_test.dart`, the `analyzer/` vector set, and the two Unicode
conformance files under `reference/conformance/unicode/`.

New in phase 10: `lib/src/backup.dart`, `lib/src/changefeed.dart`,
`lib/src/spaceapi.dart`, `test/backup_feed_test.dart`.

New in phase 9: `CompactionJob` and the stepwise driver in `lib/src/engine.dart`,
plus honest reporting in `lib/src/metrics.dart`.

New in phase 8: `lib/src/verify.dart`, `lib/src/repair.dart`,
`lib/src/profile.dart`, `test/verify_repair_test.dart`, `test/profile_test.dart`.

New in phase 7: `lib/src/checkpoint.dart`, `lib/src/stats.dart`,
`test/checkpoint_stats_test.dart`, and `Collection.analyze` / `statsOf` /
`mostSelective` — the evidence-based index choice `06` §7.1 asks for.

New in phase 6: `lib/src/metrics.dart`, `test/rangedelete_ttl_test.dart`,
`test/operations_test.dart`, and `Segment.rangeDeletes` — §4's in-memory
range-delete summary, built only for a segment whose header carries
`HAS_RANGE_DELETES`, so the normal case pays nothing.

New in phase 5: `lib/src/txn.dart` (snapshots, transactions, backpressure,
durability, events) and `test/txn_test.dart`.

New in phase 4: `lib/src/blake2b.dart`, `lib/src/argon2.dart`,
`bench/p11_encryption.dart`, the `argon2id` and `profile_costs` blocks in
`conformance/vectors/security/derivation.json`, and `deriveKek` /
`unlockWithPassword` in `lib/src/security.dart`.

**533 tests**, up from 259 at the end of phase 2. **No skips.** Every chapter of
the specification now has an implementation.

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

- **Argon2id is implemented and verified** (§0.1), in pure Dart, against RFC
  9106 §5.3. The password keyslot path of `14` §3.2–§3.3 is exercised end to
  end for the first time. What remains unproven about it is only what a vector
  cannot prove: that the *cost* is right on a real device, which §0.1 shows it
  is not, for `mobile`, in this runtime.
- **`spec/10-transactions.md` §2 is untested, and only §2.** Dart has no
  shared-memory threads, so *N* writers contending on one counter cannot be
  exercised and prediction P3 cannot be measured. Everything else in the chapter
  is built and tested (§0.0). This implementation declares
  `Level 0 (single-writer)`, which `11` §1.1 defines, and writes byte-identical
  files.
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
2. **Measure P3 in Rust.** `10-transactions.md` §2 is now the only part of the
   chapter left, and the write-concurrency claim is the design's headline.
3. ~~Add Argon2id, then measure P11.~~ **Done** (§0.1). What is left of P11 is
   its steady-state half, which needs real storage.
4. **Measure P2 against Fjall and RocksDB.**
5. **Re-run the aged scan at 10⁶ on a real device.** 2×10⁵ found a real defect
   that 2×10⁴ did not; there is no reason to assume that stops.
6. ~~Range deletes and TTL.~~ **Done** (§0.-1). ~~Checkpoints and planner
   statistics.~~ **Done** (§0.-2). What is left of `13` is backup, repair, the
   compaction API, the change feed and multi-process readers; chapters `07`–`09`
   are untouched. ~~`04` §5.2's stepwise compaction.~~ **Done** (§0.-4).
   ~~The rest of `13`.~~ **Done** (§0.-5) except §8. The highest-value remaining
   items are now the three that need something this runtime does not have:
   `10-transactions.md` §2 with prediction P3 (threads), `13-operations.md` §8
   (processes), and `07-fulltext.md` §2.4's `porter2` (a published algorithm
   deliberately declared rather than approximated).

---

## Appendix — reproducing

```bash
cd reference/dart/cryptand
dart pub get
dart analyze                              # clean
dart test                                 # 533 tests, no skips

dart run tool/generate_vectors.dart       # regenerates ../../conformance/vectors
dart test test/conformance_test.dart      # verifies them

dart run bench/p1_height.dart
dart run bench/p5_paged_scan.dart
dart run bench/p4_p6_decode.dart
dart run bench/p8_aged_scan.dart          # 20 000 docs
dart run bench/p8_aged_scan.dart 200000   # the size that found the defect
dart run bench/p10_read_tail.dart         # ~75 s
dart run bench/p11_encryption.dart        # ~10 s; Argon2id costs dominate
dart run bench/filter_fpr.dart
```

`tool/experiments/` holds the one-off scripts phases 1 and 2 cite as evidence.
