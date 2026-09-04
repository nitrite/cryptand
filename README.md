# Cryptand

**A cross-language storage engine and file format for Nitrite.**

A **cryptand** is a macrobicyclic ligand — a molecular cage that encapsulates an
ion inside its cavity and holds it there. Azacryptands are studied precisely as
receptors for small anions, nitrite among them. A cage built to hold nitrite,
and a name whose root is *crypt*: a vault.

(It is a cage, not a cipher — the name is about *holding*, not concealing. The
format does encrypt, thoroughly, and `spec/14-security.md` is where that lives;
it just is not what the word means.)

---

## The proposition

> A database file created by `nitrite-java` can be opened, queried, mutated and
> closed by `nitrite-flutter` or `nitrite-rust`, then reopened by `nitrite-java`
> — with no export step, no conversion, no loss, and no corruption. A Nitrite SDK
> written tomorrow in Go, Swift, C# or JavaScript reaches the same file by
> implementing one document: the spec in `spec/`.

File extension `.cryptand`; magic `"CRYPTAND"` — exactly 8 ASCII bytes.

## Verdict: viable

Technically viable, and the precedent is strong — SQLite, Parquet, Arrow, LMDB
and Zstandard are all byte-level contracts implemented independently in a dozen
languages. Nothing in Nitrite's data model requires language-specific storage.

The four things that make today's files non-portable are all *choices*, not
constraints, and every one of them is fixable:

| Blocker today | Fix in Cryptand |
|---|---|
| Values are serialized by a language-specific serializer (Java serialization on MVStore, Kryo on RocksDB, Hive binary on Dart, bincode on Fjall) | One self-describing value encoding, **CVE**, specified byte-for-byte |
| Key order is defined by the host language's comparator (`Comparable`, `Ord`, `compareTo`) and is *not* the byte order the engine scans | One order-preserving key encoding, **CKE**, where `memcmp` *is* the logical order |
| The three SDKs already disagree on semantics — index type names, numeric key normalization, index entry layout (see `research/nitrite-survey.md` §6) | A normative logical model that all SDKs must implement, with shared conformance vectors |
| Map names are mangled differently per engine (`\|` → `_P_` for Fjall, base64 for Hive) | Trees are addressed by numeric id; names live in a catalog as plain UTF-8 |

The genuinely hard parts are not technical. They are (a) keeping three
codebases in lockstep on a byte contract, and (b) full-text tokenization, which
is only reproducible across languages if the analyzer is *specified* rather than
delegated to whatever the host ecosystem provides. Both are addressed
(`spec/11-conformance.md`, `spec/07-fulltext.md`) — and (b) is now
**demonstrated**: Dart supplies none of NFKC, UAX #29 or
`Simple_Lowercase_Mapping`, and the reference implementation reproduces all
**19 074** normalization and **1 826** word-break cases of Unicode's own
conformance suites from the specification alone.

## The engine

A **key-separated, lazily-levelled, immutable-segment store** with no
write-ahead log.

```
  many writer threads → sharded memtables
        │                              │
        │ keys + 16-byte pointers      │ values ≥ vlog_min, written ONCE,
        ▼                              ▼ straight to the device
   L0  [seg][seg][seg][seg]        ┌──────────────────┐
   L1  [seg]…[seg]   TIERED        │   VALUE LOG      │
   L2  [seg]…[seg]   TIERED        │  append-only,    │
   Lmax [seg][seg]   LEVELLED      │  heat-grouped,   │
                     DISJOINT      │  liveness-GC'd   │
                                   └──────────────────┘
                                     compaction NEVER rewrites a value
```

Seven decisions, in `design/architecture.md`:

0. **One engine, four device profiles.** `mobile`, `tablet`, `desktop`,
   `server` — a named set of superblock constants that changes how a writer
   behaves and nothing about how a file is read. On `mobile`, `vlog_min` sits at
   its ceiling (a quarter page, 1024 B) so documents stay inline and a point read
   is one I/O, because write amplification is a server problem and 400 µs of UFS
   latency is a phone problem. A file moves between profiles by ordinary
   compaction.
1. **Values are written once and never re-merged.** Everything at or above
   `vlog_min` — 256 B on `desktop`, 1024 B on `mobile`, and never more than a
   quarter page — goes to an append-only value log; the tree holds a 16-byte
   pointer. Compaction rewrites ~6 % of the data, not 100 %.
2. **There is no write-ahead log.** The value-log record *is* the durability
   record. Conventional LSMs write every record twice before it is even
   queryable — Fjall's own accounting is three writes per item.
3. **Lazy levelling.** Tiered upper levels for cheap writes; a disjoint levelled
   last level for cheap scans and bounded space.
4. **Writers do not share an append stream.** *N* writers drive *N* independent
   append streams. The only global serialization point is one `fetch_add`.
5. **Everything is immutable.** Segments are bulk-built and written once, so
   there are no page latches, snapshots are free, and no crash at any durability
   setting can produce an unopenable file.
6. **The on-disk value layout is the memory layout.** Reading one field is a
   binary search and a slice, not a deserialization — and field names live once
   per tree, not once per document.
7. **Clustering is structural, not scheduled.** The value log has a hot tier and
   a cold tier; surviving values are promoted into the cold tier *during
   last-level compaction, which already runs in key order* — so the cold log is
   key-clustered for free. Scan locality is a property of the design, enforced
   by a bounded `locality_debt` MUST and a mandatory aged-scan test, not a
   background chore an implementation might skip.
8. **Security is a property of the file, not a wrapper on it.** Authenticated
   encryption over every page and record; a wrapped master key so changing a
   password costs 32 bytes instead of a rewrite; an authenticated superblock, so
   nobody can flip `cipher` to 0 or weaken the KDF; nonces from a counter with a
   published floor, so a crash cannot reuse one. And, encrypted or not: no host
   deserializer ever sees file bytes, which removes the whole
   `readObject`-on-untrusted-input class that MVStore has today.

## Security

The realistic attacker on an embedded database has **the file** — a lost phone,
a leaked backup, a forensic image — not a socket. `spec/14-security.md` starts
with a threat model, says what is out of scope as plainly as what is in, and
specifies the bytes.

| | |
|---|---|
| **Encrypted** | every page payload, every value-log record, every blob and vector chunk — XChaCha20-Poly1305 |
| **Authenticated** | the same, plus the superblock, so `cipher = 0` and a weakened Argon2id cost cannot be forged in |
| **In the clear, deliberately** | page headers and superblocks, so `verify`, repair, containment and incremental backup all run **without the key** |
| **Keys** | a random master key wrapped in up to four keyslots; password change is one superblock write, and destroying the slots is a real erase on flash, where overwriting is not |
| **Not defended** | an attacker inside the process; rollback to an authentic earlier file; page-count and modification metadata. Each is stated, with the mitigation that does work |

## Can it beat MVStore, RocksDB, Hive and Fjall?

`design/performance-model.md` does the arithmetic. The headline predictions,
all of them predictions and none of them measured:

| | claim |
|---|---|
| **Sustained random writes ≫ RAM** | **1.4–1.6× fewer device bytes than Fjall; 4–9× fewer than RocksDB as `nitrite-rocksdb-adapter` configures it.** Write amplification ≈ 2.2× against Fjall's ≈ 3.3× and RocksDB's ≈ 20×. The margin over Fjall is almost exactly the write-ahead log it writes and Cryptand does not. |
| **Write concurrency** | **≥ 2× RocksDB and ≥ 3× Fjall at 16 writer threads.** Fjall as `nitrite-rust` uses it is literally single-writer; RocksDB funnels every writer through one WAL. |
| Paged scans | Rust's measured 40.4× penalty collapses to ~1.0×, because the cause — re-descending from the root per row — is fixed by requiring cursors |
| Projected reads | ≥ 3× MVStore, ≥ 2× Fjall; ≥ 5× on key-only index scans, which never touch the value log |
| File size | ≤ 0.6× MVStore, ≤ 0.8× Fjall |
| Memory | bounded by a configured budget; Hive's grows linearly with key count |

### And what it costs

Stated up front rather than buried, after two rounds of attacking them:

| | |
|---|---|
| **Space amplification** | ~1.5× on desktop against leveled RocksDB's ~1.2× (~1.2× on `mobile`). Bounded and tunable; the real remaining cost. |
| Opening an encrypted database | ~250 ms on a phone, ~500 ms on a desktop, once — Argon2id, deliberately. Throughput is unaffected: XChaCha20 outruns every storage device Nitrite runs on. |
| **Implementation complexity** | The largest genuine cost, and it is paid three times. Mitigated by reduced write profiles, but it does not go away. |
| Point read of a whole document | 2 I/Os on desktop/server, **1 on mobile and tablet** |
| Write p99 | compaction exists; paced, and bounded by a specified backpressure curve |
| Scan of documents | **structurally clustered**, enforced by a mandatory aged-scan test |

The full accounting — every property the design touched, the **eight
mis-specifications** the two analysis rounds uncovered, and the **fourteen
specification defects** a third, independent review pass found in the written
chapters — is [`design/tradeoff-analysis.md`](design/tradeoff-analysis.md)
(§8 and §8.1).

## Documents

Read in this order.

| | |
|---|---|
| [`research/nitrite-survey.md`](research/nitrite-survey.md) | What the three SDKs actually do today: storage abstraction, engines, layouts, and every interchange blocker found in the source |
| [`research/prior-art.md`](research/prior-art.md) | MVStore, RocksDB, Hive, Fjall, LMDB, redb, SQLite, WiscKey, lazy levelling — what each one teaches and what it costs |
| [`design/architecture.md`](design/architecture.md) | The engine and why it has this shape |
| [`design/performance-model.md`](design/performance-model.md) | Analytic cost model, predicted wins and losses per engine, benchmark plan |
| [`design/tradeoff-analysis.md`](design/tradeoff-analysis.md) | What the write-path design costs reads, durability, space, memory, latency and complexity — the full accounting |
| [`spec/`](spec/) | The normative format specification — this is the contract |
| [`adoption/rollout.md`](adoption/rollout.md) | How the three SDKs get there from here, and how existing files migrate |
| [`reference/dart/cryptand/REPORT.md`](reference/dart/cryptand/REPORT.md) | **Reference implementation report (phase 15)** — what is built, the spec defects building it has found, and every measurement against a claim in `design/` |
| [`reference/rust/cryptand-conformance/`](reference/rust/cryptand-conformance/) | **The second implementation** — an independent Rust reader of the byte layer, written from `spec/` alone, that passes nine of the ten conformance vector groups |
| [`reference/rust/cryptand-write/`](reference/rust/cryptand-write/) | **The write protocol** — `10-transactions.md` §2 with real threads, where prediction **P3** is measured, and `13-operations.md` §8's multi-process readers with real processes |

### Specification chapters

| | |
|---|---|
| [`spec/00-conventions.md`](spec/00-conventions.md) | Normative language, byte order, primitives, varints, checksums |
| [`spec/01-container.md`](spec/01-container.md) | File layout, superblock, pages, extents, free space, compression, encryption |
| [`spec/02-value-encoding.md`](spec/02-value-encoding.md) | **CVE** — the value and document encoding |
| [`spec/03-key-encoding.md`](spec/03-key-encoding.md) | **CKE** — the order-preserving key encoding |
| [`spec/04-segments.md`](spec/04-segments.md) | Segments, levels, lazy levelling, the value log, cursors |
| [`spec/05-catalog.md`](spec/05-catalog.md) | Catalog, tree descriptors, attributes, the logical Nitrite model |
| [`spec/06-indexes.md`](spec/06-indexes.md) | Unique, non-unique, compound index layouts |
| [`spec/07-fulltext.md`](spec/07-fulltext.md) | Term dictionary, block postings, the normative analyzer |
| [`spec/08-spatial.md`](spec/08-spatial.md) | R-tree pages, WKB geometry |
| [`spec/09-vector.md`](spec/09-vector.md) | Flat vector region, HNSW graph, DiskANN, quantization |
| [`spec/10-transactions.md`](spec/10-transactions.md) | Sequencing, concurrent commit, MVCC, durability, recovery |
| [`spec/11-conformance.md`](spec/11-conformance.md) | Conformance levels, feature flags, unknown-data preservation, test vectors |
| [`spec/12-profiles.md`](spec/12-profiles.md) | Device profiles — phone, tablet, desktop, server — and the frame-budget rules |
| [`spec/13-operations.md`](spec/13-operations.md) | Backup, checkpoints, repair, corruption containment, required metrics, TTL, change feed, planner statistics |
| [`spec/14-security.md`](spec/14-security.md) | **Threat model**, keys and keyslots, nonces, what is encrypted, superblock authentication, what still leaks, crypto-erase, hardening against a hostile file |

## Status

**Every chapter of the specification is implemented**, in pure Dart at [`reference/dart/cryptand/`](reference/dart/cryptand/) across
fifteen phases — **546 tests, no skips**, and a conformance vector set at
[`reference/conformance/vectors/`](reference/conformance/) that is generated,
byte-exact and self-verifying.

Since phase 15 the vectors are also read by a **second implementation** that did
not generate them — [`reference/rust/cryptand-conformance/`](reference/rust/cryptand-conformance/),
41 tests over nine of the ten vector groups, written from `spec/` alone. That is
what makes "portable" a measurement rather than a claim: a self-generated vector
set catches regression, and only a second reader catches misreading.

| chapter | status |
|---|---|
| `00` conventions, `01` container, `02` CVE, `03` CKE | complete |
| `04` segments | complete except §5.1's parallel compaction, which needs threads |
| `05` catalog, `06` indexes | complete |
| `07` full text | complete — the analyzer against Unicode's suites, `porter2` against Snowball's vocabulary |
| `08` spatial | complete — ISO WKB, the in-container R-tree, and §4's exact second phase |
| `09` vector | complete — the durable layout and §8's search contract; the graph *algorithms* are deliberately not in the format |
| `10` transactions | complete — §1 and §3–§10 in Dart; §2, the concurrent write protocol, in Rust (`reference/rust/cryptand-write`), where P3 measures **14.8×** over 32 writer threads |
| `11` conformance, `12` profiles | complete |
| `13` operations | complete — §8's multi-process readers built in Rust (`reference/rust/cryptand-write`), tested with processes it spawns |
| `14` security | complete, Argon2id and BLAKE2b verified against RFC 9106 and RFC 7693 |

**Every section of the specification now has an implementation.** `04` §5.1's
parallel compaction is the one part left, and it needs an engine underneath it
rather than a new capability.

Read [`reference/dart/cryptand/REPORT.md`](reference/dart/cryptand/REPORT.md).
Building the code has found **forty-nine defects in these documents** — a headline
invariant that was literally false, a page header whose field table did not fit
its own declared size, a nonce rule that did nothing, filter rates quoted from
the wrong formula, "unknown tags round-trip" that no reader could implement —
and three gaps in the **design** rather than its description: the aged-scan bound
was missing a mechanism and the metric meant to detect that was blind to it, the
read-tail bound turned out to belong to a read path the prediction never named,
and the last level's disjointness rule was stated over the wrong key space — a
levelled level that had quietly stopped being disjoint returned **stale
versions**, under 338 passing tests, until snapshot retention exposed it. The
two before last came from the second implementation: a conformance vector whose
field name promised more bytes than it carried, in the one structure whose
failure mode is silent key loss, and a decoder reject rule that both
implementations followed and neither had read. The most recent is the write
design's **headline claim** — "N writers drive N independent append streams into
the device" — which measurement showed to be a property of the operating
system's write path rather than of the format, false on at least one mainstream
platform, and not recoverable by any file layout. The argument for having no
write-ahead log survives, but the reason is the group-commit barrier that
amortizes over a whole commit group, not the parallel streams. The three after
that came from building the multi-process reader protocol: a sidecar header
declaring two fields no rule read, which left an abandoned database silently
degrading every reader that opened it, and a volatile mode reachable two ways
with only one of them written down.

**Confirmed by measurement:**

| | predicted | measured |
|---|---|---|
| **P8** aged scan | ≤ 1.5×, v/row < 0.3 | **1.00×** / 0.100 at 2×10⁴ and 2×10⁵ documents, **1.04×** / 0.104 at **10⁶** — after adding cold-tier collection, then after fixing when it is triggered |
| **P10** read tail | p99 ≤ 2, p99.9 ≤ 3 | **p99 1, p99.9 1–2** from 10⁴ to 2×10⁵ documents — but only with §4's early exit, and it is the *filter* rather than range partitioning that delivers it |
| **P5** paged scan | 1.0–1.2× | **1.07×**, with the `nitrite-rust` defect reproduced at 15.7× |
| **P1** height ≤ 4 below | 613 M docs | **619 M**, interior 1.88 MiB per 10⁷ |
| **P6** density | CVE:JSON 1 : 1.53 | **1 : 1.70** — denser than claimed |
| **P11** encryption | ~250–500 ms open | **MISSED on the open half** — 405 ms `mobile` / 2183 ms `desktop` in pure Dart, because the targets assumed a native KDF with parallel lanes; the throughput half needs real storage and stays unmeasured |
| **P4** mechanism | ~10× for a projection | **11.1×** one field, 6.5× two |
| **P3** write concurrency | near-linear to 8–16 threads | **14.8×** at 32 writer threads with p50 flat — but **only in a durable mode**; without the barrier it peaks at two threads, and that number measures the host's write path, not this design |

**Still unmeasured, and stated as such:** P2 and P3 — write amplification
against Fjall and RocksDB, and write concurrency — because they need those
engines and real threads, and Dart has neither. `spec/10-transactions.md` is
therefore not merely under-tested but *untested*, which is the largest single
gap and the reason phase 4 is Rust. Every other figure in these documents
remains an analytic prediction, labelled as such, with the measurement that
would confirm or refute it.
