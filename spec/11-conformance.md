# CFF-11 — Conformance, feature flags, and safe degradation

**Normative.** This chapter is what makes "any future language" a real claim
rather than an aspiration.

---

## 1. Conformance levels

An implementation declares the highest level it fully implements. Levels are
cumulative.

| level | name | requires |
|---|---|---|
| **0** | Core | container (`01`), CVE (`02`), CKE (`03`), segments, levels, the value log, cursors (`04`), catalog (`05`), concurrent commit and recovery (`10`), LZ4, CRC-32C |
| **1** | Collections | Level 0 + documents, name dictionaries, unique / non-unique / compound indexes (`06`), attributes |
| **2** | Text | Level 1 + full-text with `cryptand.std.v1` (`07`) |
| **3** | Spatial | Level 1 + WKB and the R-tree (`08`) |
| **4** | Vector | Level 1 + vector regions and adjacency (`09`) |

Every level also requires the operational surface of `13-operations.md`:
verification, repair, corruption containment, the required metrics, and the
incremental/resumable maintenance API. An engine that cannot say *why* it is
slow, or that dies whole on one bad page, is not conforming.

**Every level also requires the hardening of `14-security.md` §9**, at every
level, whether or not the implementation supports encryption: bounds-checked
lengths, no dispatch on file content, and a reader that has been fuzzed. Opening
a file another party produced is what this format is *for*, so every reader is a
parser of untrusted input. Encryption itself is a feature bit, not a level
(§2) — an SDK either implements it or refuses encrypted files, and both are
conforming.

**Every Nitrite SDK MUST be at least Level 1.** Levels 2, 3 and 4 correspond to
the existing optional modules and may be shipped separately.

Levels 2, 3 and 4 are independent of each other: an implementation may be
"Level 1 + 3" without being Level 2.

### 1.1 Concurrency is part of Level 0

Level 0 conformance includes the write-path requirements of
`10-transactions.md` §2.2: a sharded memtable, no database-wide lock on the
write path, reserve-then-`pwrite` value-log appends (which is *not* a value-log
segment per writer — open segments are bounded by heat class), an off-thread
committer, and concurrent compaction on disjoint key ranges. An implementation that serializes
writers is **not** Level 0, because the format's write-throughput properties are
what it exists for and a serialized writer silently forfeits them.

The one exception is a runtime without shared-memory threads. Such an
implementation MAY declare `Level 0 (single-writer)`, MUST still produce
byte-identical files, and MUST say so in `writer_id`. It is a runtime
limitation, not a format variant, and it is a **declared capability** rather
than a failure — `00-conventions.md` §1.1 is the general rule, and this is its
main instance. A single-isolate Dart or a JavaScript implementation is the
worked example, but the declaration is written against the capability, not
against either language.

### 1.2 Reduced write profiles

An implementation MAY declare a **reduced write profile** — it reads everything
and writes a restricted subset:

| declaration | may not write | still MUST |
|---|---|---|
| `no-vlog` | value-log records — it writes `vlog_min` at its maximum, `page_size / 4`, so every value it writes is inline, an overflow chain, or a blob | read `VLOG` pointers written by others; leave liveness statistics alone |
| `no-compaction` | segments above L0 | read every level |
| `single-writer` | — | produce byte-identical files |

This is what makes a small or constrained implementation — a Dart phone SDK, a
CLI, an embedded reader — a first-class participant rather than a hazard.

It is safe because of two properties already in the format:

1. `value_kind` is **per cell**, so a database may hold inline and separated
   values side by side with no flag and no conversion. Note that `no-vlog` is
   `vlog_min = page_size / 4`, not `vlog_min = ∞`: the cap of
   `00-conventions.md` §8 is a format invariant, and a value above it goes to an
   overflow chain or a blob rather than into a leaf cell that cannot hold it.
2. Value-log liveness statistics **may overstate liveness and must never
   understate it** (`04-segments.md` §6.7), so an implementation that never
   updates them is correct — it simply never collects. A fully capable
   implementation opening the same file later recomputes and collects.

A reduced implementation MUST declare its profile in `writer_id` and MUST NOT
claim unqualified Level 0.

### 1.3 Level policy is not part of conformance

`l0_trigger`, `fanout`, `tier_width`, which levels are tiered and which are
levelled, the compaction picker, the split points of a segment, the value-log
heat classifier and the GC victim policy are all **implementation choices**.
Files written under any of them are readable by every conforming
implementation, because the format records only the level number, key range,
seq range and liveness statistics — never the policy that produced them.

This is deliberate. It is where implementations are expected to compete, and it
is the pressure valve that keeps a frozen format from freezing performance.

## 2. Feature bits

`features_required` and `features_optional` in the superblock
(`01-container.md` §2), and `features` in each tree descriptor
(`05-catalog.md` §9).

The rule that decides the column, stated before the table because an earlier
draft's column header and its own following paragraph disagreed:

> **A bit goes in `features_required` only when a reader that does not
> understand it would return *wrong data*.** A bit goes in `features_optional`
> when ignoring it costs a capability and nothing else.

| bit | name | set when | word | needed for |
|---|---|---|---|---|
| 0 | `CORE` | always | required | Level 0 |
| 1 | `DOCUMENTS` | any `data` tree exists | required | Level 1 |
| 2 | `TEXT` | any `postings` tree exists | **optional** | Level 2 |
| 3 | `SPATIAL` | any `rtree` tree exists | **optional** | Level 3 |
| 4 | `VECTOR` | any `vector_graph` tree exists | **optional** | Level 4 |
| 5 | `ZSTD` | any page uses codec 2 | required | Zstd |
| 6 | `CIPHER` | `cipher ≠ 0` | required | encryption (`14-security.md`) |
| 7 | `HASH64` | a CFH-64 checksum is stored for a blob or value-log body | required | |
| 8 | `DEC128` | any `DEC128` value stored | required | decimal128 |
| 9 | `MULTIPROC` | multi-process **writing** enabled | required | post-1.0 |
| 10 | `DEDUP` | blob deduplication in use | required | |
| 11 | `MULTIPROC_READ` | reader processes coordinate through the lock sidecar | optional | `13-operations.md` §8 |
| 12 | `ZDICT` | any page or record is compressed against a Zstd dictionary | required | `01-container.md` §7 |
| 13 | `TTL` | any entry carries an expiry | required | `04-segments.md` §9 |
| 14 | `CHANGEFEED` | tree 9 is in use | optional | `13-operations.md` §7 |
| 15 | `CHECKPOINTS` | tree 8 holds retained snapshots | optional | `13-operations.md` §1 |
| 16–47 | reserved for future minor versions | | | |
| 48–63 | **vendor** | never `required` in a portable writer's file | | |

Working through the interesting ones:

- `TEXT`, `SPATIAL` and `VECTOR` are **optional**, not required — a Level-1
  reader reads the documents perfectly well without them. What governs *writing*
  is the bit on the index *tree's* `features` (`05-catalog.md` §9), enforced by
  §5. This is the single most important row in the table, because it is what
  makes a Flutter app able to edit a collection whose vector index only the Rust
  service maintains.
- `TTL` is **required**: a reader that ignores expiry returns deleted data,
  which is the definition of wrong.
- `HASH64` is required only when a 64-bit checksum is actually *stored* for a
  blob or value-log body (`00-conventions.md` §6). CFH-64 is unconditionally
  mandatory for segment filters (`04-segments.md` §2.4.1) at every level, and
  that use does not set this bit — a Level-0 implementation implements CFH-64
  regardless. It is twenty lines and it is printed in the spec, which is the
  point of having replaced XXH3-64 with it.
- `CHECKPOINTS` is optional, but a reader that ignores tree 8 MUST still honour
  the retention it implies or it will reclaim extents a checkpoint needs. The
  safe behaviour for a reader that does not understand tree 8 is not to reclaim
  anything, which follows from the preserve-unknown rule in §4.

**A writer MUST set a bit in `features_required` only when the feature is
genuinely needed to *interpret* the file.** Over-declaring locks out readers for
no reason; under-declaring corrupts data.

## 3. Reader behaviour matrix

| situation | required behaviour |
|---|---|
| unknown bit in `features_required` | refuse to open; report bit number and, if known, name |
| unknown bit in `features_optional` | open normally; ignore the structures; **preserve them** |
| `version_major` > supported | refuse to open |
| `version_minor` > supported, `write_version_minor` ≤ supported | open read-write |
| `write_version_minor` > supported | open **read-only** |
| unknown `kind` in a catalog descriptor | list the tree; treat as opaque; never delete |
| unknown page type inside an opaque tree | ignore; do not reclaim its pages |
| unknown page type inside a tree the reader owns | corruption |
| unknown CVE type tag | surface as opaque; round-trip its bytes (§4) |
| unknown field in a catalog descriptor | preserve on rewrite |

## 4. Preserve-unknown — the round-trip rule

**A read-modify-write MUST NOT destroy data the implementation does not
understand.** Concretely, all MUST:

1. An unknown CVE type tag, or a CVE `OPAQUE` value, round-trips byte for byte
   when a document is rewritten for an unrelated reason. This is only
   implementable because every unassigned tag is length-prefixed
   (`02-value-encoding.md` §1.1) — a reader cannot preserve a value whose end
   it cannot find, and inside an `ARRAY` there is no field table to bound it
   with.
2. Unknown fields in a catalog descriptor, an attributes document or a store
   metadata document round-trip.
3. Trees of unknown `kind` survive. They are not deleted when the collection
   they belong to is modified, and their pages are not reclaimed.
4. Blob extents referenced from anything preserved above are not freed.
5. Superblock reserved bytes are copied forward, not zeroed. (This is the one
   exception to `00-conventions.md` §5's "write reserved as zero" — a *creator*
   writes zeros, a *rewriter* preserves.)

Without this rule, one save from a Dart app silently deletes a Java
application's POJO fields and a Rust service's vector index. With it, an SDK that
understands less than the file contains is merely limited, not destructive.

## 5. Degradation when a writer lacks a feature

The scenario this format exists for: a Flutter app updates a document in a
collection that has a vector index, and the Flutter SDK has no vector module.

An implementation mutating a `data` tree MUST check every index tree whose
`owner` is that data tree. For each such index whose `features` includes a bit
the implementation does not have, it MUST take exactly one of:

**(a) Strict — refuse.** Fail the write with an error naming the index, the
missing feature, and the SDK that can maintain it. Nothing is written.

**(b) Repair-log.** Perform the write, and in the *same commit*:

- append the mutation to the repair log (tree 4, `05-catalog.md` §2):

  ```
  key   = CKE(Array[U32 index_tree_id, U64 commit_id, U64 seq])
  value = CVE { "op": "insert"|"update"|"delete",
                "id": NITRITE_ID,
                "before": DOC?,          -- for update/delete, the prior document
                "after":  DOC? }         -- for insert/update
  ```

- set `stale_from` on that index's descriptor to this `commit_id`, if not
  already set.

A capable implementation opening the file:

1. sees `stale_from`;
2. replays the repair log for that index, in `(commit_id, seq)` order;
3. clears `stale_from` and truncates the replayed entries — in one commit.

If the repair log has been truncated by policy, or replay fails, the capable
implementation rebuilds the index from the data tree. Rebuild is always
possible: every index in this format is derivable from documents.

**Default is (a) strict.** (b) is an opt-in configuration, because it trades a
loud failure for a bounded, self-healing inconsistency, and that is the
application's choice, not the library's.

A reader MUST treat a query against an index with `stale_from` set as
unreliable: it either refuses, or falls back to a collection scan, and it says
which. It MUST NOT return possibly-incomplete index results as if they were
complete.

The repair log is bounded by configuration (default 64 MiB); exceeding the bound
converts the index to "rebuild required" and truncates the log.

## 6. Test vectors

Conformance is defined as passing the vectors, not as matching the reference
implementation's source.

```
conformance/
  vectors/
    cke/          value → expected CKE bytes, and ordering assertions over sets
    cve/          value → expected CVE bytes, round-trip assertions
    numbers/      the numeric torture set: ±0, subnormals, 2^53±1, i64/i128/u128
                  extremes, NaN payloads, int/float cross-type ordering
    strings/      NFC/NFD pairs, surrogates, embedded NUL, 4-byte code points
    documents/    nesting, dictionary reuse, inline names, opaque round-trip
    analyzer/     text → expected token+position stream for cryptand.std.v1
  files/
    v1.0-core.cryptand          golden file with a known expected read set
    v1.0-collections.cryptand
    v1.0-text.cryptand
    v1.0-spatial.cryptand
    v1.0-vector.cryptand
    v1.0-future.cryptand        unknown optional feature bit + unknown kind +
                               unknown CVE tag — tests §3 and §4
    v1.0-corrupt-*.cryptand     bad CRC, truncated segment, torn value-log tail,
                               cyclic tree, overlapping levelled segments,
                               dangling VLOG pointer, bad UTF-8, huge declared len
    v1.0-multilevel.cryptand    L0 + tiered + levelled, several versions per key,
                               live range deletes, a pinned old snapshot
    v1.0-vlog-gc.cryptand       mid-GC state: duplicate value records, stale
                               liveness stats, one sealed segment at 3 % live
  manifest.json                for each file: expected reads, expected errors,
                               expected error class
```

Rules:

- Every implementation runs the whole suite, including the levels it does not
  claim — for those, the expected outcome is a *specific* degradation, not an
  exception.
- The `corrupt-*` files MUST produce a corruption error and MUST NOT crash,
  hang, or allocate unboundedly. (`nitrite-rust` has already lost a process to a
  corrupt model file that a library could not translate into an error; a database
  file must never do that.)
- **A round-trip test is mandatory**: for each golden file, open it in
  implementation A, mutate it, close it, open it in B, verify, mutate, close,
  reopen in A. This is the actual product claim and it must be tested as such,
  in CI, on every SDK's every commit.
- **A concurrency test is mandatory** for any implementation claiming full
  Level 0: *N* threads writing overlapping key ranges while *M* threads scan,
  with a compaction forced throughout. Every reader must observe a snapshot
  (no torn batch, no missing index entry for a document it can see), and the
  final database must pass `cryptand verify`.
- **An aged-scan test is mandatory.** Load a dataset, scan it, apply 10× its
  size in random updates, then scan again. The second scan MUST cost no more
  than **1.5×** the first, and `value_reads_per_scanned_row` MUST stay below
  **0.3**. It MUST also assert `locality_debt` is within `locality_debt_pct`
  at the end, because that is the bound the other two numbers follow from.

  This is the test that enforces **four** MUSTs whose violation is invisible to
  every other check and shows up months later as "the database got slow":
  clustered promotion (`04-segments.md` §6.3), cold-tier collection (§6.8),
  the locality-debt bound (§6.9), and value readahead (§8.1). An earlier draft
  named only three, omitting collection — and the reference implementation
  found that promotion without collection lands at **2.14×**, failing the test
  it was supposed to pass.

  The reference implementation measures **1.00×** and 0.100 with all four in
  force, and **9.62×** and 1.038 with promotion and readahead disabled.
- **A read-tail test is mandatory**, and **its write load is part of the
  test**. Build a database by writing keys in **random order** and then updating
  a substantial fraction of them, with no forced full compaction; then issue
  uniform-random point reads and record `segments_probed_per_lookup`
  (`13-operations.md` §6). p99 MUST be ≤ 2 and p99.9 ≤ 3.

  The write load is normative here because it is the only thing that creates the
  condition being tested. Ascending inserts give every memtable flush a disjoint
  key range, so manifest pruning alone leaves one candidate: the reference
  implementation's first attempt reported p99 = 1 for every shape *including its
  controls*, which is a measurement of nothing. An implementation MUST also
  report which read path it used — with §4's early exit or without — because the
  bound holds for the first and not the second (`04-segments.md` §4.1).

- **A stale-version test is mandatory.** Build a file in which a segment at a
  *lower* level has a higher `max_seq` than a segment above it, from an unrelated
  key, while both cover the queried key. A reader that resolves candidates by
  segment order instead of by entry `seq` returns the stale version and fails
  (`04-segments.md` §4). This is `v1.0-multilevel.cryptand`'s reason for
  existing, and it must include that arrangement explicitly.
- **A range-delete-under-filter test is mandatory.** A `RANGE_DELETE` covering a
  key that is *not* a point key of the segment holding it. A reader that
  filter-prunes that segment resurrects a deleted key and fails
  (`04-segments.md` §4).
- **A filter cross-check is mandatory.** Every implementation runs the same key
  set through its blocked-Bloom builder and compares the resulting bytes, not
  merely the false-positive rate. A filter that differs by one probe is a false
  negative — a lost key, not a slow lookup (`04-segments.md` §2.4).
- **A containment test is mandatory.** Corrupt one page of a mid-level segment;
  the database MUST still open, MUST still serve every key outside that
  segment's range, and MUST name the affected range
  (`13-operations.md` §4).
- **A foreground-stall test is mandatory** for `mobile` and `tablet`: under
  sustained write and compaction load, no single foreground operation may exceed
  `max_foreground_stall_ms` (`12-profiles.md` §4).
- **A profile round-trip test is mandatory**: create under one profile, write,
  `set_profile` to another **with the same `page_size`**, compact fully, verify,
  then switch back and verify again. Data must be identical at every step.

  **The two profiles must share a page size, and an earlier version of this
  requirement did not.** It named `mobile → desktop → mobile`, which
  `12-profiles.md` §6 forbids outright: `page_size` "cannot change. It is fixed
  at creation", and `mobile` is 4 KiB while `desktop` is 8 KiB. The mandatory
  test as written could not be run by a conforming implementation — it asked
  for the one conversion the format refuses. `mobile ↔ tablet` (both 4 KiB) and
  `desktop ↔ server` after creating at a shared size are the usable pairs; an
  implementation MAY additionally assert that the forbidden change is *refused*,
  which is the other half of the property and is what the reference
  implementation does.
- **A crash test is mandatory**: kill the process at randomized points during
  a sustained write, reopen, and assert that every acknowledged batch is
  present, no unacknowledged batch is partially present, and verification is
  clean. Run it at each durability mode.

## 7. Reference implementation

**Non-normative. Nothing in this chapter requires a particular language of
anyone, and this section least of all** — which language the reference is
written in is a project decision about where effort goes, not a property of the
format. It is recorded here only so readers know what the CLI below is.

The current reference is in Dart (`reference/dart/cryptand/`), which was chosen
to implement the format in the *weakest* SDK first on the theory that whatever
survives there ports upward. A second reference is planned in Rust, because
`nitrite-rust` already has the closest analogues (`ordered_key.rs`,
`disk_rtree`, `nitrite-vector`), because it compiles to a CLI that Java and Dart
CI can invoke, and because it has the threads that `10-transactions.md` §2
cannot be exercised without.

It ships as:

- a library crate,
- `cryptand verify <file>` — the integrity pass of `01-container.md` §9,
- `cryptand dump <file>` — catalog, level/segment map, value-log liveness, feature
  bits, writers,
- `cryptand vectors` — regenerates the conformance vectors,
- `cryptand fuzz` — structure-aware fuzzing of the reader,
- `cryptand repair <file>` — `13-operations.md` §3,
- `cryptand backup <file> <dest>` and `cryptand backup --incremental`,
- `cryptand stats <file>` — the required metrics of `13-operations.md` §6.

The reference implementation is **not** normative. Where it disagrees with these
documents, the documents win and the implementation is wrong. This has to be
stated, or the spec quietly becomes "whatever Rust does", which is exactly the
failure mode Nitrite is in today with Java.

## 8. Changing the format

1. New structures go behind a new feature bit, in `features_optional` where
   possible.
2. `version_minor` increments. `write_version_minor` increments **only** if an
   older writer would corrupt the file by rewriting it.
3. New CVE type tags come from the reserved range, carry the mandatory length
   prefix of `02-value-encoding.md` §1.1, and are covered by §4's round-trip
   rule, so an older reader preserves them. A new tag that is not
   length-prefixed is not a minor-version change; it is a major one, because
   every existing reader loses the array it appears in.
4. New CKE group tags are a **breaking change to ordering** and therefore
   require a `version_major` bump. Reserve generously; the tag space in
   `03-key-encoding.md` §2 is spaced by 0x10 for exactly this reason.
5. Every change lands with conformance vectors in the same commit, and no
   implementation ships support for a bit whose vectors do not exist.

## 9. Deprecation and the compatibility promise

- Version 1.x files remain readable by every 1.x implementation, forever.
- A structure may be deprecated (writers stop producing it) but a reader MUST
  keep understanding it for the life of the major version.
- The three SDKs release the same `format_version` support in lockstep. An SDK
  that ships a new required feature bit before the others can read it has broken
  the product's central promise, and the release checklist must make that
  impossible to do by accident.
