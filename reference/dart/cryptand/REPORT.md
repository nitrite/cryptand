# Cryptand reference implementation — phase 2 report

**Implementation:** pure Dart 3.12, `reference/dart/cryptand/`
**Spec under test:** `cryptand/spec/` (CFF v1.0), `cryptand/design/`
**Measured on:** Apple M2 Pro, macOS 26.6.2, Dart SDK 3.12.2 (native VM)
**Status:** 259 tests green, `dart analyze` clean, conformance vectors byte-exact and self-verifying

Phase 1's report is superseded by this one; its findings are carried forward in
section 2.

---

## 0. What phase 2 did

Phase 1 built the format — container, CVE, CKE, segments, cursors — and found
nine defects. It ended with five items outstanding. Four are now closed:

| phase 1 said | now |
|---|---|
| "Settle the filter hash. It blocks portable filter vectors." | **CFH-64**, specified in full in `spec/04-segments.md` §2.4.1. Filter vectors are byte-exact and portable (§1) |
| "Add XChaCha20-Poly1305 and Argon2id against published vectors" | **XChaCha20-Poly1305 shipped and verified** against every RFC 8439 vector. Argon2id still absent (§5) |
| "Take the P1 cell-layout saving, or correct §1's `K` to 34 B" | **Taken.** Leaf cells are 2 bytes smaller and P1 now *exceeds* its prediction (§3.2) |
| "Build the value log and compaction, then run `aged-scan` immediately" | **Built.** P8 measured, and it **failed at first** — the design was missing a mechanism (§3.1) |
| "Port `test/conformance_test.dart` to Rust and Java" | not done; needs those toolchains |

Five more spec defects were found, one of them a genuine gap in the design
rather than in its description.

---

## 1. CFH-64: the filter hash is now in the spec

Phase 1 declined to ship XXH3-64 — ~500 lines, seven branches, a 192-byte
secret — guarding the one structure whose failure mode is a silent false
*negative*, and recommended two CRC-32C evaluations instead.

**Measurement killed that recommendation, and it is worth showing why.** CRC is
affine in its initial state, so `CRC(i₁,m) XOR CRC(i₂,m)` depends only on
`length(m)`, and salting is likewise an invertible linear map. **Any pair of
CRC-32C evaluations over the same key therefore carries 32 bits of entropy, not
64.** Over 4 000 000 random keys:

| hash | collisions | 32-bit birthday bound predicts |
|---|---|---|
| two CRC-32C + splitmix64 finalizer | **1868** | 1863 |
| CFH-64 | **0** | — |

Each collision is a *guaranteed* false positive, and they grow as `n²/2³³` — at
4 M keys in one segment that is a 0.047 % floor against a 0.22 % target.

So the recommendation became: a hash **small enough to print in the spec**.
CFH-64 is twenty lines of wrapping multiply, XOR, shift and rotate — four
operations every target language has on its widest integer. No table, no
secret, nothing to source. Measured across five key shapes (snowflake ids,
dense sequential, sparse, long shared prefix, compound index keys):
**0.222 % – 0.235 %**, stable to 6 %. The raw CRC pair ranged 0.18 % – 0.45 % on
the same shapes, which is the linearity showing.

The practical consequence: `conformance/vectors/filter/blocked_bloom.json` now
carries the **filter block bytes**, and `test/conformance_test.dart` asserts
they reproduce bit for bit. In phase 1 that file had to warn that its bytes were
not portable.

---

## 2. Defects found, phase 2

Five, on top of phase 1's nine. The first is the significant one.

### 2.1 The design was missing a mechanism, and its own metric could not see it

`spec/04-segments.md` §6.9 named three things that keep an aged scan fast:
clustered promotion, a bounded `locality_debt`, and cursor readahead.
Implementing exactly those and running the mandatory aged-scan test gave
**2.14×**, against a bound of 1.5×. A failure.

The cause: **promotion clusters a *generation*, not the log.** Each last-level
compaction promotes the values that survived it into a fresh cold run, in key
order. Ten rounds produce ten runs. Every one is perfectly sorted — so the
original `locality_debt`, defined as "live bytes in segments *without* the
clustered flag", read **0 %** throughout — while a key-ordered scan interleaved
**nineteen** runs holding 8 MB of live data inside 48 MB of extents.

> The metric that `spec/13-operations.md` §6 calls "the number that predicts
> scan decay" was blind to the only decay this design exhibits.

Two changes followed, both in the spec:

- **`locality_debt` is redefined** over *surplus runs*: sort the live value-log
  segments by live bytes descending, keep the `ceil(live / segment_bytes)` the
  data genuinely needs, and every byte past that is debt. The same database
  reads 89 % under this definition, which is what a bound is for.
- **Cold-tier collection is a MUST triggered by that debt**, not only by
  `vlog_space_target_pct`. §6.8 already required collection to preserve
  clustering; nothing required it to *happen*.

Measured, after the fix:

| mechanisms | live runs | aged / fresh | v/row | value-log space |
|---|---|---|---|---|
| all four | 2 | **1.00×** | **0.100** | 1.00× |
| promotion, no collection | 19 | 2.14× | 0.224 | 5.82× |
| none | 19 | **9.62×** | 1.038 | 5.82× |

The space column is the part I did not expect. **The same surplus runs that
cost a scan are the ones holding dead bytes**, so a debt-triggered collection
delivers `vlog_space_target_pct` for free — while a space-only trigger does
*not* deliver locality, because a log can sit inside its space target with its
live data spread across nineteen runs. The design treated these as separate
concerns with separate bounds; they have one cause and one fix.

### 2.2 "Values are written at most twice" — §6.3

Directly contradicted by the fix above: a collection is a third write of every
value that survives it. §6.3 now says so, with the price attached — holding the
debt under 20 % cost **2.12×** value-side write amplification against **1.76×**
with no collection. 20 % more value writes, for an aged scan at 1.00× instead of
2.14× and a value log at 1.00× its live size instead of 5.82×.

### 2.3 `02` §5.2's "binary search and a slice"

The field table holds two varints per entry, so it cannot be *indexed* without
first walking it — a binary search pays an O(n) index build before its O(log n)
probes. Measured, a single forward pass over the sorted table wins outright at
realistic field counts. §5.2 now says what it is, and records that a
fixed-width table was considered and rejected (≈10 % on every document to save
≈30 % of an already-small projection cost).

### 2.4 The leaf cell was two bytes fatter than the model — §2.2

`design/performance-model.md` §1 costs the entire write-amplification argument
against `K ≈ 32 B`; phase 1 measured 34 B. Both bytes were recoverable without
losing anything:

- `value_kind` (5 values) and the entry flags (1 bit) now share one byte;
- `value_len` is **omitted for `VLOG` and `BLOB`**, whose pointers are always
  exactly 16 bytes — a length field with one legal value is not information, it
  is a second place for two implementations to disagree.

### 2.5 Argon2id's floor was unreachable in `kdfRaw` slots

`spec/14-security.md` §3.2's minimum cost applies to Argon2id, but the wrap path
applied it unconditionally, making a host-supplied key (`kdf = 0`, which §3.3
explicitly defines) impossible to store. Fixed in the implementation; the spec
was already right.

---

## 3. Measured against the claims

Counters are the primary result and wall time an observation, per
`design/performance-model.md` §8: "Never assert on a wall-clock ratio in CI."

### 3.1 P8 — aged scan: **CONFIRMED, after §2.1**

20 000 documents, then 200 000 random updates; values in the value log
(`vlog_min` 256 B), laid out over real 4 KiB pages and read through a bounded
LRU. A value log held in a flat map would make every locality claim vacuously
true, so it is not one.

**1.00× aged/fresh** against a predicted ≤ 1.5×, **v/row 0.100** against < 0.3,
and **9.62×** with the mechanisms disabled against a predicted ≥ 6×. Both halves
hold comfortably.

**Readahead made no measurable difference**, and that is the design working:
once promotion and collection leave one key-ordered run, sorting a window of
already-ordered pointers is a no-op. §8.1 stays a MUST because it bounds the
*unclustered* case — exactly when the other mechanisms have not caught up.

**The promotion term is workload-sensitive, as §3.1 warned.** That section costs
promotion at 0.29× assuming ~30 % of values reach the last level, and adds: "If
the fraction … is much higher than ~30 % … promotion costs closer to 0.97×."
P8's harness is deliberately that workload, and promotion measured **1.06×**.
The caveat was right; P2 must be measured on its own workload.

### 3.2 P1 — height and key-index size: **CONFIRMED, now exceeding the prediction**

| | predicted | phase 1 | phase 2 |
|---|---|---|---|
| entries per leaf | ~127 | 114.9 | **121.9** |
| children per internal page | ~169 | 168.4 | **171.9** |
| height ≤ 4 below | 613 M docs | 548 M | **619 M** |
| interior at 10⁷ docs | "under 2 MiB" | 2.03 MiB | **1.88 MiB** |

The two bytes of §2.4 closed a gap that phase 1 could only report. `K` measures
33.1 B against a model of 32 B; the residual 1 B is the prefix-compressed key
running ~13 B rather than 12 on snowflake ids, and `performance-model` §1 now
says so.

### 3.3 P5 — paged scan: **CONFIRMED** (unchanged from phase 1)

**1.07×** against a predicted 1.0–1.2×, with the `nitrite-rust` no-cursor defect
reproduced at 27.9× node accesses and 15.7× wall time.

### 3.4 P4's mechanism and P6 — density: **CONFIRMED**

One field costs **11.2×** less than a full decode, two fields **6.4×** less
(`design/architecture.md` predicted ~10× for two — directionally right, ~35 %
optimistic, and now corrected to the measured figures).

CVE with a name dictionary is **388 B** against JSON's **661 B** — a ratio of
1 : 1.70 against a predicted 1 : 1.53. CVE is *relatively* denser than the model
claimed. The dictionary alone recovers 39 % of the document.

### 3.5 The AEAD: verified

Every published vector reproduces byte for byte — RFC 8439 §2.3.2 (block
function), §2.4.2 (encryption), §2.5.2 and A.3 (Poly1305), §2.8.2 (the full
AEAD ciphertext *and* tag), and draft-irtf-cfrg-xchacha §2.2.1 (HChaCha20).

That is what changed since phase 1, which declined to ship an AEAD it could not
verify. Reproducing a published ciphertext from an independent derivation *is*
the verification; without those vectors passing, the file should not be used.

Wired into the page and record paths with the AAD and nonce construction of
`spec/14-security.md` §5, and tested for the attacks the chapter names: a page
moved to another offset fails, a relabelled `tree_id` fails, a keyslot lifted
from another database fails to unwrap (threat T3), and crypto-erase works.

### 3.6 Still not measurable here

| | why |
|---|---|
| **P2** write amplification vs Fjall/RocksDB | needs those engines |
| **P3** write concurrency | Dart has no threads — the one real flaw in "implement in the weakest SDK first" |
| P7 memory, P9 latency | need real page-cache budgets and a real device |
| P11 encryption cost | now possible (the AEAD exists); not yet benchmarked |

---

## 4. What is implemented

| chapter | status |
|---|---|
| `00-conventions`, `01-container`, `02-value-encoding`, `03-key-encoding` | complete |
| `04-segments` §1, §2, §8 — internal keys, bulk builder, cursor, filter | complete |
| `04-segments` §4, §5, §6 — read resolution, compaction, two-tier value log, promotion, collection | **complete enough to measure P8**; see §5 |
| `06-indexes` | complete as vectors |
| `14-security` — SHA-256, HMAC, HKDF, XChaCha20-Poly1305, subkeys, nonces, keyslots, page and record encryption, superblock MAC | complete except Argon2id |
| `05`, `07`–`13` | not started |

7 393 lines of library, 3 923 of test, 754 of benchmark.

---

## 5. Honest limits

- **The engine is the smallest one that can measure P8 honestly.** It has a
  memtable, an L0 and a levelled last level. It does **not** have tiered
  intermediate levels, range partitioning, range deletes, TTL, transactions, or
  the manifest as a copy-on-write tree. Those are orthogonal to P8 and are not
  built. `spec/04-segments.md` §3, §5.1–5.3 and §9 are therefore unexercised.
- **Argon2id is still absent.** Same reasoning as phase 1's: a memory-hard KDF
  whose vectors cannot be checked here would have other SDKs match its errors.
  Every layout it lives in is implemented, and `Keyslot.kdfRaw` — a
  host-supplied key, which §3.3 defines — exercises the whole wrap path without
  it. P11 cannot be measured until it exists.
- **One machine, one runtime, in-memory extents.** No file I/O, no OS page
  cache. Value-log reads go through a bounded LRU over real page-granular
  offsets, which is what makes the P8 numbers mean something, but a real device
  will differ. Only the counter-based results are portable.
- **`dart2js` is unsupported.** `int` is a double on the web and `ByteData` has
  no `getUint64`, so `U128`, `NitriteId`, CFH-64 and every 64-bit field break.
  `spec/00-conventions.md` §7 anticipates this; a web target needs a `BigInt`
  build and will be slow. The rollout plan's Flutter-web ambition should be
  costed against that.
- **The conformance vectors are generated by the implementation they test.**
  They are self-verifying and hash-pinned, which catches regression, not
  misreading. Only a second independent implementation catches misreading, and
  that is phase 3.

---

## 6. What phase 3 should do first

1. **Port `test/conformance_test.dart` to Rust and Java.** It consumes only JSON
   and the public encode/decode paths. Until a second implementation reads
   these vectors, "portable" is a claim, not a result.
2. **Add Argon2id** in whichever SDK can verify it, then measure P11.
3. **Build the tiered levels and range partitioning**, then measure P10 — the
   bounded read tail is the one structural claim with no measurement at all.
4. **Measure P2 and P3 in Rust**, against Fjall and RocksDB, with threads.
5. **Re-run the aged-scan test at 10⁶ documents and on a real device.** The
   20 000-document result is clean, but P8 is a claim about databases that get
   old and large, and only one of those two has been tested.

---

## Appendix — reproducing

```bash
cd reference/dart/cryptand
dart pub get
dart analyze                              # clean
dart test                                 # 259 tests
dart run tool/generate_vectors.dart       # regenerates ../../conformance/vectors
dart test test/conformance_test.dart      # verifies them

dart run bench/p1_height.dart
dart run bench/p5_paged_scan.dart
dart run bench/p4_p6_decode.dart
dart run bench/p8_aged_scan.dart
dart run bench/filter_fpr.dart
```

`tool/experiments/` holds the one-off scripts this report cites as evidence —
the hash entropy and blocked-Bloom comparisons, the value-log fragmentation
diagnosis, and the locality/write-amplification sweep.
