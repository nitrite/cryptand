# Cryptand reference implementation — phase 1 report

**Implementation:** pure Dart 3.12, `reference/dart/cryptand/`
**Spec under test:** `cryptand/spec/` (CFF v1.0), `cryptand/design/`
**Measured on:** Apple M2 Pro, macOS 26.6.2, Dart SDK 3.12.2 (native VM, AOT-less JIT)
**Status:** 204 tests green, `dart analyze` clean, conformance vectors generated and self-verifying

---

## 0. On the choice of Dart

The brief was: implement in the weakest SDK, because if the weakest can comply,
the strongest can. **That reasoning is sound for conformance and unsound for
performance**, and the split matters enough to state before any numbers.

**Sound for conformance.** Dart is genuinely the hostile environment for this
format, and it found real defects precisely because it is:

- no 128-bit integer, which forced `U128` as two 64-bit halves and thereby
  *proved* the spec's claim that CKE number normalization "requires no
  arbitrary-precision arithmetic in any language" — a claim that would have
  been untested had Rust gone first, since `u128` is native there. Java has
  exactly Dart's problem and will reuse exactly Dart's shape.
- UTF-16 strings, so unpaired surrogates are representable and `utf8.encode`
  silently substitutes U+FFFD — the exact silent corruption
  `spec/00-conventions.md` section 4 forbids. A Rust implementation cannot
  even construct the failing input.
- no threads, so the concurrency requirements had to be read rather than
  assumed away.

**Unsound for performance.** Two of the design's headline predictions cannot be
tested here *at all*:

| prediction | why Dart cannot test it |
|---|---|
| **P3** — write concurrency, ">= 2x RocksDB and >= 3x Fjall at 16 writer threads" | Dart has no threads. `spec/11-conformance.md` section 1.1 already grants a `single-writer` exception for exactly this reason. The claim is untestable in the SDK chosen to test it. |
| **P2** — write amplification, "1.4-1.6x fewer device bytes than Fjall" | needs the full LSM (memtable, levels, compaction, value log) *and* Fjall and RocksDB to compare against, neither reachable from Dart. |

So this phase validates the **format** and the **read path**, which is where
Dart is a fair and even pessimistic proxy. P2 and P3 need the Rust phase, and
the rollout plan should say so rather than implying Dart-first covers them.

---

## 1. What is implemented

| chapter | status |
|---|---|
| `00-conventions` — primitives, varints, CRC-32C, limits, error taxonomy | **complete** |
| `01-container` — superblock, page header, open procedure, feature bits, profiles | **complete** |
| `02-value-encoding` — CVE, all 30 tags, documents, name dictionary, lazy `DocView` | **complete** |
| `03-key-encoding` — CKE, all groups, decoder, all five range helpers | **complete** |
| `04-segments` — internal key, bulk builder, B+tree pages, reader, cursor, `skipTo`, filter | **§1, §2, §8 complete**; §3 manifest, §5 compaction, §6 value log: not started |
| `06-indexes` — the `Array[v1..vk, id]` layout and its range construction | **complete** as vectors |
| `14-security` — SHA-256, HMAC-SHA256, HKDF, subkeys, nonces, keyslots, superblock MAC | **complete except two primitives** (§4) |
| `05`, `07`–`13` | not started (phase 1 scope) |

**Line counts:** 5 789 library, 2 849 test, 620 benchmark, 599 vector generator.
The test-to-code ratio is deliberate: this is a byte contract, and a byte
contract is worth exactly what its tests are worth.

### 1.1 Deliberately not implemented, with reasons

**XChaCha20-Poly1305 and Argon2id.** Both are named by
`spec/14-security.md` section 2. Neither is here, and the reason is not effort.

A reference implementation's output is a set of conformance vectors that three
other SDKs will be written to match. This environment cannot check an AEAD or a
memory-hard KDF against its canonical published vectors. Shipping an
*unverified* one would not produce a slightly-wrong artifact — it would **bake
my error into the contract**, and for an AEAD that surfaces as data nobody can
decrypt, and for a KDF as a silently weaker key. The correct output of "I
cannot verify this" is a stated gap, not a plausible-looking implementation.

Everything those two primitives live *inside* is implemented and tested — the
keyslot layout, the wrap AAD, subkey derivation, nonce construction, the
watermark discipline, the superblock MAC — so adding them is a drop-in against
a tested frame. `conformance/vectors/security/derivation.json` declares them
missing in the artifact itself.

**XXH3-64** is the same call for a different reason, and it comes with a
recommendation. See section 5.

---

## 2. Defects found in the spec

Nine, all fixed in `spec/` and `design/` as part of this work. Four would have
produced wrong data or wrong bytes; the rest are arithmetic and completeness.
The first three were found by *writing the code*, which is the argument for
building the reference before the SDKs.

### 2.1 The CKE invariant, as stated, was false — `03` §1

The chapter's headline invariant read:

> `memcmp(CKE(a), CKE(b))` has the same sign as the logical comparison of *a*
> and *b*.

The first test to exercise it failed on the first pair it tried. `I8(0)` and
`I16(0)` are **equal** under `02` §8 rule 2 ("all numeric tags form one
domain"), but CKE deliberately gives them different trailing type codes — so
they encode as `30 02 00` and `30 02 01` and `memcmp` says −1, not 0.

This is not a bug in the encoding; the type code is load-bearing (`03` §4.3, and
it is what keeps an exact-type point lookup a point lookup). The **statement**
was wrong. It is now stated as a refinement, in two clauses: a non-zero
comparison never inverts, and an equal comparison yields keys that differ only
in the trailing type code and are adjacent inside `[N(v), successor(N(v)))`.
That is the property an engine actually needs, and it is what
`test/cke_test.dart` now asserts over the full 20 000-pair cross product.

### 2.2 The page header table did not fit its own header — `01` §3

The field table summed to **36 bytes** under a declared **32-byte** header, with
`commit_id` (8 bytes at offset 12) running into `extent_pages` at offset 16. No
reader could have implemented it. It survived three review passes because nobody
added the column up; writing `writeInto` added it up immediately.

Adding the security chapter's `nonce` needed 8 more. The header is now **40
bytes** with every field naturally aligned, costing 0.2 % of a 4 KiB page.
`test/container_test.dart` asserts the fields tile 0..39 exactly, and does the
same for the superblock's 4 096.

### 2.3 The nonce watermark rule did nothing — `14` §4.1

My own security chapter said:

> On open, a writer MUST begin allocating at `persisted_next_nonce + 2^20`.

The test that tried to prove a crashed session's nonces are never reissued
failed, because the rule is empty: a session that crashes **without publishing**
leaves the watermark unmoved, so the next session computes the same start and
hands out the same values. For a stream cipher that discloses both plaintexts
and the Poly1305 key, and every affected page still verifies perfectly.

The rule now has three parts, and any two of them leave the hole: publish
`persisted + 2^20` **durably before allocating anything**, allocate upward from
`persisted`, and never reach the published value without publishing again.

This is the finding I would most want a reviewer to notice: the chapter had
already identified nonce reuse as the catastrophic failure, named the crash
scenario correctly, and *still* wrote a rule that did not close it.

### 2.4 "Unknown tags round-trip byte for byte" was unimplementable — `11` §4

`spec/11-conformance.md` requires an unknown CVE tag to round-trip. Writing the
decoder made it obvious that a reader cannot preserve a value whose **end it
cannot find**, and for an unknown scalar tag inside an `ARRAY` there is nothing
to derive the length from. (A `DOC` escapes, because its field table bounds each
value — but `ARRAY` and `MAP` store values back to back.) A reader meeting one
would have to abandon the whole containing array, losing every *known* sibling
with it — precisely the silent loss §4 exists to prevent.

`02` §1.1 now requires every reserved and implementation-private tag to be
`tag || uvar byte_len || bytes`.

### 2.5 The filter's false-positive rates were classic-Bloom figures — `04` §2.4

The spec promised **0.04 %** at 16 bits per key and **1 %** at 10. Measured:
**0.33 %** and **1.67 %** — 7x and 1.7x worse.

The decisive experiment (`tool/experiments/bloom_compare.dart`) builds a classic
and a blocked filter over the same keys with the same hash:

| bits/key | k | classic | blocked | textbook `(1−e^(−kn/m))^k` |
|---|---|---|---|---|
| 10 | 7 | 0.8103 % | 1.6651 % | 0.8194 % |
| 12 | 8 | 0.3170 % | 0.8724 % | 0.3142 % |
| 14 | 10 | 0.1202 % | 0.5268 % | 0.1201 % |
| 16 | 11 | 0.0510 % | **0.3306 %** | 0.0459 % |

Classic tracks the textbook formula to within 11 %. So the hash is fine and
**blocking is the cause** — at 16 bits a 512-bit block holds ~32 keys on
average, and the Poisson spread means the overfull blocks dominate. This is the
known Putze/Sanders/Singler trade; the spec had simply quoted the wrong formula.

It is not tunable away either: the curve flattens because `k` is clamped at 16
(0.22 % at 18 bits, 0.12 % at 24, 0.065 % at 32), and only a 4 KiB block
recovers classic rates — which defeats the one-cache-line probe that motivates
blocking at all.

**The architecture survives.** `04` §4.1's read tail goes from 0.003 to 0.026
expected extra descents across 8 candidates; p99 is still 1 and p99.9 still 2.
P10 was never sensitive to the filter's exact rate — range partitioning bounds
the tail and the filter only has to be *good*. The numbers are corrected in `04`
§2.4, `04` §4.1, `performance-model` §1/§5/§5.4 and `tradeoff-analysis` §1.3,
and the trade is now stated: blocking buys a one-cache-line probe and costs ~7x
the false-positive rate.

### 2.6 Five smaller ones

| | where | what |
|---|---|---|
| a | `03` §7 | The "does not round-trip" list named one lossy decoding. There are **three**: instants (all tags decode as `TIMESTAMP_NS`), **`-0.0`** (decodes as `+0.0`), and NaN payloads. Each is forced — a key that distinguished two values the order calls equal would sit strictly between them. |
| b | `02` §8 rule 3 | Same omission from the value side, now cross-referenced. |
| c | `06` §6 | `DEC128` was missing from the not-indexable list, though `03` §4.4 had already removed it from the key domain. |
| d | `04` §2.1 | Segment header needed a bound: `min_key` + `max_key` at the key limit cannot fit a 4 KiB head page. They are now explicitly **bounds** a writer may shorten. |
| e | `04` §6.2 | `data_offset` said 96; with the 40-byte page header it is 104. |

---

## 3. Measured against the claims

Every number below is a **median of 7 runs** after warm-up, on the hardware
named at the top. Where a *counter* exists it is the primary result and wall
time is an observation, per `design/performance-model.md` section 8's own rule:
"Never assert on a wall-clock ratio in CI."

### 3.1 P5 — paged scan versus full scan: **CONFIRMED**

The claim: "A paged walk over a whole collection costs ~1.0–1.2x one full scan,
and `nitrite-rust`'s measured 40.4x collapses to that."

Harness from `research/nitrite-survey.md` section 7: 20 000 rows, 400 per page.

| strategy | node accesses | vs full scan | median ms |
|---|---|---|---|
| A full scan | 2 237 | 1.00x | 1.420 |
| B paged walk, cursor + `skipTo` | 2 384 | **1.07x** | 1.535 |
| C paged walk, re-seek per row (*the defect*) | 62 379 | 27.9x | 22.296 |

**1.07x against a predicted 1.0–1.2x.** Cold (cache disabled, every fetch a
miss) it is also 1.07x.

Row C reproduces the actual `nitrite-rust` defect — "its store navigates by
repeated `higher_key` from the root; there is no cursor in the `NitriteMap`
API" — and measures **15.7x** wall time against the survey's measured 40.4x on
a real Fjall-backed store. The mechanism is confirmed; the absolute multiple is
lower here because this segment is a single in-memory extent with no block cache
or engine overhead between the descents.

`skipTo` costs O(height) page reads, asserted directly: `skipTo(49 000)` on a
50 000-entry segment reads at most `height` pages.

**This is the strongest result in the report.** It is also the one that matters
most, because it is the only claim with a *measured* baseline to beat.

### 3.2 P1 — segment height and key-index size: **CONFIRMED, slightly optimistic**

| | predicted | measured | verdict |
|---|---|---|---|
| entries per leaf | ~127 | **114.9** | 9.5 % optimistic |
| children per internal page | ~169 | **168.4** | exact |
| height <= 4 below | 613 M docs | **548 M docs** | follows from the leaf fanout |
| interior at 10^7 docs | "under 2 MiB" | **2.03 MiB** | 1.5 % over |

Measured shape, 4 KiB pages, snowflake keys:

| shape | docs | height | per leaf | per internal | extent | interior |
|---|---|---|---|---|---|---|
| separated | 10^4 | 2 | 113.6 | 88.0 | 360 KiB | 1.1 % |
| separated | 10^5 | 3 | 114.8 | 125.3 | 3 516 KiB | 0.8 % |
| separated | 10^6 | 3 | 114.9 | 168.4 | 35 032 KiB | 0.6 % |
| inline (`mobile`) | 10^6 | 4 | 9.0 | 179.3 | 446 944 KiB | 0.6 % |

**Where it differs and why.** `performance-model` section 1 costs the merged
footprint `K` at ~32 B (12 B prefix-compressed key + 4 B cell overhead + 16 B
pointer). Measured it is **~34 B**: the internal key is 22 B raw and ~12 B after
prefix compression, but the cell overhead is 6 B, not 4 — `suffix_len` varint,
`value_kind`, `entry_flags`, `value_len` varint, and the 2-byte cell pointer.

That propagates: `k = K/R` is **6.6 %**, not 6.2 %, so the key-index contribution
to write amplification is 12 x 0.066 = **0.79x** rather than 0.75x, and the §3.1
total becomes **2.20–2.40x** rather than 2.16–2.36x. A 2 % shift; P2's margin
over Fjall is unaffected.

**Could the code close the gap? No — only a format change could**, and I did not
make one. Two bytes per cell are recoverable and both are byte-contract changes,
not optimizations:

1. `value_len` is always 16 for `VLOG` and `BLOB`, so the varint is dead weight.
2. `value_kind` (5 values) and `entry_flags` (1 bit) fit in one byte.

Together those give ~32 B/cell and ~122 entries/leaf — close to the prediction.
I am **recommending, not applying**: changing the leaf cell now would invalidate
the conformance vectors this phase exists to produce, and a 6 % key-index saving
is not worth that mid-review. It belongs in the phase-1 spec-amendment pass the
rollout plan already provides for.

### 3.3 P4's mechanism — projection decode: **CONFIRMED for one field, optimistic for two**

P4 itself ("≥ 3x MVStore, ≥ 2x Fjall on projections") is not testable from Dart.
What is testable is the mechanism it rests on, stated in
`design/architecture.md` section 3: "on a 20-field document where a query needs
two fields, that is ~10x less decode work".

| work per document | ns | vs full decode |
|---|---|---|
| decode all 20 fields | 4 034 | 1.00x |
| decode 1 field | 360 | **11.2x cheaper** |
| decode 2 fields (10 %) | 626 | **6.4x cheaper** |
| decode 5 fields (25 %) | 1 194 | 3.4x cheaper |

**One field beats the claim; two fields fall ~35 % short of it.** The mechanism
is real and the direction is right; "~10x for two fields" should read "~11x for
one, ~6x for two". On an already-parsed view the ratio is 20x, so the residual
cost is the per-document header walk, not the field lookup.

Getting there took three **portable** optimizations, all of which a Java or Rust
implementation would make for the same reasons — none trades portability, and
none touches the byte format:

| optimization | effect | why it is not a Dart trick |
|---|---|---|
| `NameDict` caches each name's UTF-8 bytes | single-field read 508 → 191 ns | the lookup path compares *bytes*; re-encoding a string per binary-search probe is waste in any language. Java stores the same `byte[]`. |
| decode the field table's two varints inline instead of through `ByteReader` | part of the same win | avoids an allocation per probe; the bounds checks that matter are still enforced |
| `DocView.parse` walks the table with direct byte access | parse 235 → 80 ns | the canonical-encoding checks were redundant for a walk that needs only each entry's length and low bit |

**And a format observation.** `02` §5.2 describes the lookup as "a binary search
and a slice". It is not, and cannot be: the field table holds two *varints* per
entry, so it cannot be indexed without first walking it — a binary search pays
an O(n) index build before its O(log n) probes. Measured, a single forward pass
wins outright at 20 fields, so `DocView` uses one below 64 fields and binary
search above. A fixed-width table would make the parse O(1) and cost ~10 % of
document size; I did **not** propose it, because 10 % on every document to save
~30 % of a projection's already-small cost is not obviously the right trade.
`02` §5.2's wording should be corrected either way.

### 3.4 P6 — encoding density: **CONFIRMED, better than predicted**

At the shape `performance-model` section 1 assumes (20 fields; realized 11.6 B
names, 17.2 B values):

| encoding | bytes | vs CVE+dict |
|---|---|---|
| CVE with a per-tree name dictionary | **388** | 1.00x |
| CVE, every name inline | 639 | 1.65x |
| JSON | 661 | 1.70x |

Section 6 predicted 485 B for CVE+dict and 740 B for JSON, at slightly larger
values (20 B). Both absolutes came in ~20 % lower because the realized document
is smaller; the **ratio** is the portable number, and CVE:JSON measured **1:1.70**
against a predicted 1:1.53 — CVE is *relatively better* than the model claimed.

The name dictionary alone recovers 251 B of a 639 B document (39 %), which is
section 5.3's "single largest space win available" confirmed.

LZ4 and Zstd are not implemented, so the "CVE + LZ4 ~330 B" row is untested.

### 3.5 Not testable in this phase

| | why |
|---|---|
| P2 write amplification | needs compaction, the value log, and Fjall/RocksDB to compare against |
| P3 write concurrency | Dart has no threads |
| P7 memory | needs the page cache and memtable budgets |
| P8 aged scan | needs the value log and clustered promotion — **the highest-risk item in the whole design**, and it is untouched here |
| P9 latency / foreground stalls | needs compaction and a real device |
| P11 encryption cost | needs XChaCha20 and Argon2id (section 1.1) |

---

## 4. Recommendation: reconsider XXH3-64 for the segment filter

Not a measurement, an engineering judgement, offered because implementing the
chapter surfaced it.

`04` §2.4 mandates **XXH3-64** for the segment filter, and the chapter is right
that a filter which disagrees between languages "produces wrong results, not
slow ones" — a false negative loses a key silently, and no checksum catches it.

XXH3-64 is also a ~500-line algorithm with seven length-dependent branches and a
fixed 192-byte secret table. It is the **single largest and least verifiable
primitive in Level 0**, and it must be reproduced bit-exactly, from scratch, in
three languages, to protect against a failure mode that is invisible.

CRC-32C is already mandatory for every page in the format, is already
hardware-accelerated on every target, is a small table in Dart, is
`java.util.zip.CRC32C` on the JVM, and — verified here against the RFC 3720
vectors — is *already correct in this implementation*. Two domain-separated
CRC-32C evaluations produce a 64-bit hash that, measured above, reproduces
textbook Bloom behaviour to within 11 %.

**The recommendation:** either specify the filter hash as two CRC-32C
evaluations (removing an entire primitive from every SDK's Level-0 burden), or
keep XXH3-64 and ship *verified* vectors for it before any SDK writes a filter.
What should not happen is three teams each writing XXH3 from the paper and
discovering the divergence from a user's missing row.

Until that is settled, `conformance/vectors/filter/blocked_bloom.json` carries
only the **structure** assertions (block size, probe count, block count), which
are hash-independent and portable today, and marks its block bytes as not yet
portable.

---

## 5. Honest limits of this report

- **One machine, one runtime.** Every timing is an M2 Pro on the Dart JIT. AOT
  and other CPUs will differ. Only the counter-based results (node accesses,
  page reads, byte counts, fanout, false-positive rates) are portable.
- **In-memory extents.** Segments are built and read in memory; there is no
  file I/O, page cache or device in the loop. This *understates* the value of
  the cursor fix (row C would be far worse against real storage) and makes the
  wall-clock ratios optimistic in absolute terms.
- **No compaction, no value log.** The riskiest prediction in the design (P8,
  aged-scan locality) is completely untested, and `design/performance-model.md`
  itself calls it "the failure mode that would otherwise be found by a user a
  year in".
- **The filter's block bytes are not portable** until the hash question above is
  answered.
- **`dart2js` is not supported.** `int` is a double on the web and `ByteData`
  has no `getUint64`, so `U128`, `NitriteId` and every 64-bit field break.
  `spec/00-conventions.md` section 7 already anticipates this ("an
  implementation in a language without a native 64-bit integer MUST use
  `BigInt`"); a web target needs a `BigInt` build of `u128.dart` and
  `bytes.dart`, and it will be slow. The rollout plan's Flutter-web ambition
  should be costed against that, not assumed.

---

## 6. What phase 2 should do first

1. **Settle the filter hash** (section 4). It blocks portable filter vectors.
2. **Add XChaCha20-Poly1305 and Argon2id** against published vectors, in
   whichever SDK can verify them, and regenerate `security/`.
3. **Build the value log and compaction**, then run `aged-scan` immediately —
   `adoption/rollout.md` already names this the highest-risk step, and nothing
   here has touched it.
4. **Port `test/conformance_test.dart` to Rust and Java** before either writes a
   byte. It consumes only JSON and the public encode/decode paths, which is
   what makes it portable, and it is the cheapest possible proof that three
   implementations agree.
5. **Take the P1 cell-layout saving** (section 3.2) in the spec-amendment pass,
   or decide explicitly not to and correct §1's `K` to 34 B.

---

## Appendix — reproducing

```bash
cd reference/dart/cryptand
dart pub get
dart analyze                              # clean
dart test                                 # 204 tests
dart run tool/generate_vectors.dart       # regenerates ../../conformance/vectors
dart test test/conformance_test.dart      # verifies them

dart run bench/p1_height.dart
dart run bench/p5_paged_scan.dart
dart run bench/p4_p6_decode.dart
dart run bench/filter_fpr.dart
```
