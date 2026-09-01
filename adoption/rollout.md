# Adoption and migration

How three shipped SDKs and four existing storage backends get to one format
without a flag day.

---

## 1. Shape of the work

Cryptand plugs in at `NitriteStore` / `NitriteMap`, the seam all three SDKs
already have. Nothing above the store layer needs to change to *use* it — the
collection, repository, filter, index and transaction code all keep working.

Four new artifacts:

| | |
|---|---|
| `cryptand` (Rust crate) | reference implementation, plus the `cryptand` CLI |
| `nitrite-cryptand-adapter` (Java) | pure Java, no JNI |
| `nitrite_cryptand_adapter` (Dart) | pure Dart |
| `nitrite_cryptand_adapter` (Rust) | thin bridge from the crate to `NitriteStoreProvider` |

**Pure implementations, not bindings.** A JNI or FFI binding to the Rust crate
would be faster to ship and would recreate exactly the problem Nitrite has with
RocksDB today: per-op crossings, platform-specific build breakage, and a
`.so`/`.dylib` that has to be shipped for every ABI. It also would not work in
Flutter web at all. Three independent implementations validated against shared
vectors is more work up front and is the thing being asked for.

There is prior evidence for the binding trap in this project: profile APKs once
shipped with no ggml/llama `.so` at all because a build plugin silently dropped
the `jniLibs` for that profile. Native artifacts fail quietly.

## 2. Phasing

### Phase 0 — freeze the semantics (no new code)

The divergences in `research/nitrite-survey.md` §6 are bugs today, independent of
Cryptand. Fix them in the existing SDKs first, so that the shared behaviour is
already proven on the existing engines before a new format depends on it.

- [ ] One set of index type strings across the three SDKs (`spec/05-catalog.md` §10)
- [ ] One catalog tag set (Rust's `TAG_COLLECTION` singular vs `collections`)
- [ ] One cross-type numeric equality rule — Dart currently has none
- [ ] One index layout: flat composite keys everywhere; retire Java's nested
      `NavigableMap` compound layout
- [ ] A cross-SDK behavioural test suite driven from one data file, running in
      all three CIs

Phase 0 has value even if Cryptand is never built.

### Phase 1 — the reference implementation

Rust crate + CLI + conformance vectors. Reviewed against the spec, and **the spec
is amended when the implementation finds it ambiguous** — that is the point of
building it first.

Exit criterion: `cryptand verify` and `cryptand fuzz` clean, all vectors generated,
`v1.0-corrupt-*` files produce named errors and no crashes.

### Phase 2 — three adapters, read-only

Each SDK opens and queries a Cryptand file. Read-only removes the entire class of
"two writers disagree" bugs while the encodings are being validated.

Exit criterion: every SDK reads every golden file and agrees, byte for byte, on
every query result in `manifest.json`.

### Phase 3 — writing, concurrency, and engine-level transactions

Each SDK writes. The round-trip test (`spec/11-conformance.md` §6) becomes a CI
gate in all three repos, alongside the mandatory concurrency and crash tests.

Also in phase 3: replace the SDK-level transaction machinery
(`TransactionalMap` + journal + undo entries, present in all three) with engine
snapshots. Engine snapshots are correct under concurrent readers, free to roll
back, atomic across maps, and — unlike the current layer — they do not serialize
writers.

**The write path is where the performance claims are won or lost**, so it ships
in this order and each step is measured before the next starts:

1. sharded memtables and the sequence counter — no database-wide write lock;
2. lazy-levelled compaction with range-partitioned tiers and parallel jobs;
3. the value log: hot tier, heat classes, GC victim picker;
4. **clustered promotion** during last-level compaction, locality-debt
   accounting, and cursor readahead;
5. backpressure curve, compaction pacing, and the required metrics.

Note the order: the **`mobile` profile is complete after step 2**, because it
inlines values. That means a shippable Flutter SDK exists before the most
complex part of the engine is built, and the value log lands with a working
baseline to compare against.

Step 4 is the highest-risk item. Measure `aged-scan` immediately after it and
before anything is built on top; if `value_reads_per_scanned_row` does not land
under 0.3, promotion is not doing what §6.3 says it does.

Exit criterion: `java → dart → rust → java` round trip with mutations at each
hop, on a file exercising every conformance level; plus P2 and P3 from the
performance model measured on at least the Rust implementation.

### Phase 3.5 — security

Encryption ships **after** the write path is measured and **before** Cryptand
becomes anyone's default (phase 5), for one reason: a nonce discipline
(`spec/14-security.md` §4) constrains the write path, and retrofitting it onto a
shipped write path is how nonce-reuse bugs are born.

It lands in this order:

1. **The hardening of `spec/14-security.md` §9 — in phase 1, not here.** Bounds
   checks, no dispatch on file content, and `cryptand fuzz` are required of every
   implementation at every level whether or not it encrypts. They are a property
   of the *reader*, and the reference reader is phase 1.
2. Primitives and vectors: XChaCha20-Poly1305, Argon2id, HKDF-SHA256,
   HMAC-SHA256, validated against `conformance/vectors/security/` in all three
   SDKs **before** any of them writes an encrypted byte.
3. Keyslots, master-key wrapping, `sb_mac`.
4. Page and record encryption, the nonce counter and its published floor.
5. The conversion path (`encrypt()`, `decrypt()`, `rotate_master_key()`,
   `crypto_erase()`), all incremental and resumable.

Exit criterion: the **nonce-uniqueness test** (`spec/14-security.md` §13) passes
under randomized process kills; every `v1.0-security-*` vector produces a named
security error; and the cross-SDK round trip of phase 3 passes again on an
encrypted file.

**The Dart risk is concentrated here.** Argon2id at 64 MiB in pure Dart on a
mid-range phone may well miss the 250 ms target, and unlike CVE or CKE there is
no way to make it cheaper without making it weaker. Measure a pure-Dart Argon2id
in phase 1 alongside the CVE/CKE prototype. If it is too slow, the fallback is
an FFI fast path for the four primitives only — a much narrower binding than the
whole engine, and one whose correctness is pinned by shared vectors.

### Phase 4 — modules

Text (Level 2), spatial (Level 3), vector (Level 4), one at a time, each with
vectors before code. Spatial in Java means WKB via JTS instead of the current
WKT round-trip; vector in Java and Dart is new capability, not a port.

### Phase 5 — default

Cryptand becomes the default store for new databases. MVStore, RocksDB, Hive and
Fjall adapters remain supported for existing files and for workloads where they
genuinely win (`design/performance-model.md` §7).

## 3. Migrating existing databases

`cryptand import` and a matching API in each SDK: open the old database through
its existing adapter, stream every map into a new Cryptand file, verify, swap.

Per-engine notes:

| from | notes |
|---|---|
| **MVStore** | values arrive as live Java objects. Anything the mapper cannot express in CVE becomes `OPAQUE` with `origin = "java"` — it round-trips but is not queryable from Dart or Rust. **Report the count.** A migration that silently produces 40 % opaque documents has not migrated anything. |
| **RocksDB** | same, through Kryo. Kryo's registration ids are not in the file, so a migration must run with the same registrations the database was written with. |
| **Hive** | keys must be base64-decoded and Hive-decoded before re-encoding as CKE. Straightforward; the Dart adapters already know every type. |
| **Fjall** | the cleanest path. `Value` maps onto CVE almost one-to-one, and `ordered_key.rs`'s layout is close enough to CKE that the mapping is mechanical (the difference is the number encoding, `spec/03-key-encoding.md` §4). |
| **Tantivy FTS** | not migratable — Tantivy's tokens are not `cryptand.std.v1`'s. The index is **rebuilt**, and the rebuild is the migration. |
| **Rust `disk_rtree`** | rebuilt from the documents' geometry; geometry itself converts to WKB. `Circle` geometries must be polygonized (`spec/08-spatial.md` §1). |
| **`nitrite-vector`** | vectors copy into a vector region; the graph is rebuilt. Rebuilding is what `nitrite-vector` already does on torn state, so the code path exists. |
| **any encrypted source** | none of the four engines encrypts today, so every migration source is plaintext. A migration MAY produce an encrypted Cryptand file directly — write the keyslot first, then stream — which is strictly better than importing plaintext and converting, because it never lands a plaintext copy on disk. An implementation that converts afterwards MUST say so, since the plaintext intermediate is recoverable from the free space until it is overwritten. |

Migration MUST be **non-destructive**: write the new file beside the old one,
verify it, and only then swap. Never in place.

`schema_version` (`spec/05-catalog.md` §7) carries over unchanged, so Nitrite's
application-level migration framework keeps working across the storage change.

## 4. Test releases and release mechanics

Two rules carried in from this project's history:

- **Test builds use `-rc` tags.** Never spend a real version number on a
  throwaway build; the gap is permanent and visible forever.
- **Push at most three release tags at a time.** Six tags in one push has already
  produced *zero* publish workflow runs on the Flutter side. A five-artifact
  Cryptand release is exactly the shape that trips this.

And a third, specific to this project:

- **The three SDKs release `format_version` support in lockstep**
  (`spec/11-conformance.md` §9). An SDK that ships a new required feature bit
  before the other two can read it has broken the product's one promise. The
  release checklist must make that impossible by accident, not merely
  discouraged.

Derive release artifact lists from the workspace, never hardcode them — every
pipeline in this project has at some point had a hardcoded list with something
missing from it. And make publishes resumable: skip versions already on the
registry, and always set a timeout, because a missing credential hangs rather
than fails.

## 5. Risks

| risk | mitigation |
|---|---|
| Three implementations drift | Conformance vectors are the contract; round-trip tests gate every SDK's CI. The reference implementation is explicitly non-normative so "whatever Rust does" cannot become the spec. |
| The analyzer is not reproducible | `cryptand.std.v1` pins Unicode 15.1 and stores stopwords in the file. Any SDK that cannot run it refuses to write the index rather than corrupting it. |
| Dart is too slow to be a first-class writer | Dart pays no serializer (that is the point), but it does pay CRC32C, LZ4, XXH3 and CKE in Dart. Measure early — a Dart prototype of CVE encode/decode and CKE compare should be phase 1 work, not phase 3. If it is too slow, the fallback is an FFI fast path for the codecs only, with the pure-Dart path kept as the correctness reference. |
| Dart cannot use threads, so it forfeits the write-concurrency win | Declared rather than hidden: `single-writer` in `spec/11-conformance.md` §1.2. On the `mobile` profile Dart also declares `no-vlog` — `vlog_min` at its ceiling of `page_size / 4`, so every document it writes is inline and only genuine attachments become blobs; it implements no value log, no promotion, no GC and no clustering on the write path, only the readers for them. That is a large reduction in what the hardest SDK has to get right. |
| Value-log GC and promotion are the new write amplification | The margin over Fjall lives here. Heat classes and tiers are in the format so the policy can improve without a format change, and the required metrics decompose write amplification into value / promotion / key-index / GC so a regression is attributable rather than mysterious. |
| Profiles multiply the test matrix | They do, but they also let each SDK ship the profile it needs first. The mandatory profile round-trip test (`spec/11-conformance.md` §6) is what keeps them one format rather than two. |
| A frozen format blocks future optimization | Feature bits, and a reserved tag space spaced for growth. Buffered internal nodes, better split policies, new codecs and new index types are all additive. |
| Migration produces mostly-`OPAQUE` documents | Report the opaque count per collection and refuse to call a migration successful above a threshold. The real fix is mapper coverage in each SDK, which is work worth doing regardless. |
| Three independent AEAD/KDF/nonce implementations drift | Shared vectors before code (`conformance/vectors/security/`), and a cross-SDK **encrypted** round trip in CI. A drifted tag is not a slow read — it is a file one SDK can no longer open, and a drifted nonce is a silent loss of confidentiality that no test except the mandatory nonce-uniqueness sweep detects. |
| Pure-Dart Argon2id is too slow on a phone | Measure in phase 1, not phase 3.5. The fallback is FFI for the four primitives only; lowering the cost parameters is **not** a fallback, and `spec/14-security.md` §3.2 forbids it on open. |
| An application thinks a user password protects the data | `spec/14-security.md` §10 makes the distinction normative, and an implementation SHOULD warn when a user is created on a file with `cipher = 0`. This is the most likely way a Nitrite application ends up believing it is protected when it is not. |
| Scope | Levels 2–4 are independent and land separately. A Level-1 Cryptand that replaces MVStore, RocksDB and Hive for plain document workloads is already the majority of the value. |

## 6. Definition of done

The product claim, stated as a test:

> Create a database in `nitrite-java` with two collections, one repository, a
> unique index, a compound index, a full-text index and a spatial index.
> Close it. Open it in `nitrite-flutter`, query every index, insert and update
> documents, close it. Open it in `nitrite-rust`, add a vector index, query
> everything, mutate, close it. Reopen in `nitrite-java`: every query returns
> what it should, the vector index is intact and untouched, and `cryptand verify`
> is clean.

Until that runs in CI on every commit of all three repositories, the format is a
document and not a product.
