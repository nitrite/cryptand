# The Rust reference implementation — report

`reference/rust/cryptand/` is a complete implementation of the Cryptand File
Format, every chapter of `spec/00` … `spec/14`, written against the
specification and checked against the conformance vectors, the mandatory tests
of `11-conformance.md` §6, the mandatory tests of `14-security.md` §13, and —
the thing none of those can do alone — a real `.cryptand` file crossing to the
Dart implementation and back.

**The spec is normative. Where this code and the spec disagree, the spec wins
and this code is wrong** (`11-conformance.md` §7).

- **147 Rust tests** in this crate (**212 across the workspace**), `cargo test`
  clean in **both** the debug and release profiles, zero warnings, no `unsafe`
  anywhere in the library.
- **Level 4** declared (`11-conformance.md` §1), full write profile.
- The Dart suite is **561 tests** and still passes with the changes §7 lists.
- The round-trip gate runs in **four** directions: plaintext both ways and
  **encrypted** both ways (§3).

**Read §5's defects 58–65 first if you are returning to this.** The largest by
some distance is 58: `14-security.md` §5.2's page encryption was not
implemented, so every inline value, every key and every index entry in an
"encrypted" database sat on disk in the clear, and every test passed.

---

## 1. What is here

| chapter | modules |
|---|---|
| `00` conventions | `varint`, `hash`, `limits`, `error` |
| `01` container | `container`, `pager`, `codec` |
| `02` CVE | `value`, `cve`, `compare` |
| `03` CKE | `cke` |
| `04` segments | `segment`, `filter`, `vlog`, `cow`, `manifest`, `engine` |
| `05` catalog | `catalog` |
| `06` indexes | `index` |
| `07` full text | `unicode`, `unicode_tables`, `analyzer`, `porter2`, `fulltext` |
| `08` spatial | `wkb`, `geometry`, `rtree` |
| `09` vector | `vector` |
| `10` transactions | `txn`, `store` |
| `11` conformance | `tests/` |
| `12` profiles | `profile` |
| `13` operations | `checkpoint`, `backup`, `changefeed`, `repair`, `verify`, `metrics`, `stats`, `spaceapi`, `multiproc` |
| `14` security | `security` |

Binaries: `cryptand` (verify / dump / stats / repair / backup / fuzz / create),
`interop` (the round-trip gate's Rust half), and the six benchmarks of §4.

`cryptand-conformance` and `cryptand-write` are unchanged. They keep their
documented purpose: an *independent* byte-layer reader written without reading
the Dart, and the write-protocol harness that measured P3 on threads.

## 2. Conformance

| suite | tests | what it checks |
|---|---|---|
| `conformance_test` | 41 | nine of the ten vector groups (`11-conformance.md` §6) |
| `text_test` | 13 | the tenth — `analyzer/std_v1` — plus Unicode's own suites and Snowball's vocabulary |
| `mandatory_test` + `stall_test` | 10 | every mandatory test of §6 |
| `security_test` | 13 | every mandatory test of `14-security.md` §13, plus §9.3's structure-aware fuzzing |
| `collections_test` | 15 | Level 1: documents, name dictionaries, indexes, the catalog's enumerations |
| `spatial_test` | 12 | Level 3 |
| `vector_test` | 8 | Level 4 |
| `operations_test` | 18 | `13-operations.md` end to end |
| `engine_test` | 10 | the engine end to end |
| `interop_test` | 3 | §6's round-trip gate, against Dart |

`14-security.md` §9.3 requires structure-aware fuzzing of the reader, and
"structure-aware" is load-bearing: most of a database's bytes are unused
value-log record space, so uniform bit flips land in padding and measure
nothing. Targeting the superblock's own fields, page headers and the payloads
behind them, 1 500 mutations give:

```
  451 refused at open with a named error
  835 opened and reported by the verification pass
  214 opened with nothing to report
    0 panics
```

A mutation that changes nothing a reader may act on — a reserved byte, an unread
payload — is not a failure; a panic, a hang or an unbounded allocation would be,
and there were none. `cryptand fuzz <file> <n>` runs it; a 300-iteration version
runs in `cargo test`.

**The tenth vector group is new here.** `cryptand-conformance` deliberately did
not port `analyzer/`, because it needs Unicode 15.1 tables and porter2. This
implementation has both, and they reproduce, first run:

- `NormalizationTest-15.1.0`: **19 074 cases, 0 failures**
- `WordBreakTest-15.1.0`: **1 826 cases, 0 failures**
- Snowball English 3.1.0's own vocabulary: **42 649 words, 0 differences**
- `analyzer/std_v1`: all 14 cases, token text and pre-filter positions

Together with `cryptand-conformance`'s result, that is the strongest evidence
`00-conventions.md` §1.1 has: naming an algorithm to the parameter makes a
format portable, and 20 900 published cases reproduce from the specification
alone.

### 2.1 The mandatory tests of §6, with their numbers

| test | bound | measured |
|---|---|---|
| read tail | p99 ≤ 2, p99.9 ≤ 3 | **p99 1, p99.9 2** (early exit on, random-order write load) |
| aged scan | ≤ 1.5×, `value_reads_per_scanned_row` < 0.3 | **1.00×, 0.079**, `locality_debt` **0.0 %** |
| foreground stall | ≤ 8 ms on `mobile` | **worst 1 ms**, 0 violations in 4 000 operations (release; on an unoptimized build the clock is reported and the §5.2 step bound asserted instead) |
| containment | serve outside the range, name it | **800 keys served, 200 refused by name** |
| filter cross-check | bytes, not the rate | header and blocks byte-identical to the vector |
| concurrency | snapshot per reader, verify clean | 8 writers × 3 scanners, compaction throughout, verify clean |
| stale version | resolve by entry `seq` | passes with **and without** the early exit |
| range delete under filter | no resurrection | passes, with the filter asserted to prune first |
| profile round trip | data identical, page size fixed | `mobile ↔ tablet`, and `→ desktop` refused |
| crash | acknowledged batches survive | 3 durability modes × 4 kill points |
| writer exclusion (`01` §10) | second writer refused by name | `Error::Locked`, and the lock released on `close` |
| encrypted round trip | A ↔ B over a file neither can read without the key | both directions, plus the wrong key refused by both |

The aged-scan controls fail, which is what makes the test mean anything:

```
shape                                                scan    v/row   debt %   runs
all four MUSTs in force                             1.00x    0.079      0.0      1
  control: promotion but no collection              1.61x    0.128     35.7      4
  control: no readahead window                      1.00x    1.000      0.0      1
  floor: no promotion, no collection                1.00x    1.000      1.7      5
```

Two of those columns moved in this round and both moves are the point:

- The floor case's debt was **100 %** and is now 1.7 %. That was defect 64 —
  §6.9 counting the hot tier, which made a database with *no* cold runs at all
  read as maximally unclustered.
- The scan ratio is the wrong control for the readahead row and the *right* one
  for the promotion row; they are two mechanisms and they now have two controls.
  Turning everything off degrades the fresh scan by the same factor as the aged
  one, which is why the floor case reads 1.00× while its `v/row` reads 1.000.

## 3. Cross-language portability — the round-trip gate

`11-conformance.md` §6: *"open it in implementation A, mutate it, close it, open
it in B, verify, mutate, close, reopen in A. **This is the actual product claim
and it must be tested as such.**"*

`reference/conformance/interop/run.sh`, and `interop_test.rs` for `cargo test`:

```
== 1. rust writes, dart reads, dart mutates, rust reads
   ok   rust wrote 400 documents, digest cf3da902
   ok   dart read the same digest cf3da902 from rust's file
   ok   dart agrees on documents, dictionary, index and page size
   ok   dart verified rust's file clean
   ok   dart mutated it to 419 documents, digest c47efb25
   ok   rust reads back exactly what dart wrote: digest c47efb25
   ok   the field name dart added to the dictionary is visible to rust
   ok   after mutations by both, they agree: digest 0ce6b59b

== 2. dart writes, rust reads, rust mutates, dart reads
   ok   dart wrote 400 documents, digest cf3da902
   ok   rust read the same digest cf3da902 from dart's file
   ok   rust agrees on documents, dictionary, index and page size
   ok   rust verified dart's file: no corruption, 8 repairable leaks
   ok   rust mutated it to 419 documents, digest 0ce6b59b
   ok   dart reads back exactly what rust wrote: digest 0ce6b59b
   ok   the field name rust added to the dictionary is visible to dart
   ok   after mutations by both, they agree: digest c47efb25

== 3. rust writes, dart reads, dart mutates, rust reads -- ENCRYPTED
   ... the same eight lines, over a file neither can read without the key

== 4. dart writes, rust reads, rust mutates, dart reads -- ENCRYPTED
   ... and the same eight the other way

== 5. an encrypted file refuses the wrong key, in both implementations
   ok   rust refused the wrong key: cannot unlock: no keyslot accepted the key
   ok   dart refused the wrong key: cannot unlock: no keyslot accepted the key
```

**Directions 3 and 4 are new, and `14-security.md` is the chapter with the most
ways to be individually right and mutually incompatible.** The page AAD, the
stored payload length, the per-record counter, the per-chunk counter, the
keyslot AAD and the superblock MAC are six independent chances for two
implementations to each encrypt correctly and neither to read the other. A
plaintext round trip exercises none of them. Everything below the MAC reproduced
first run; the MAC did not, and that is defect 62.

The fixture is 400 documents with a name dictionary, a non-unique index, values
on both sides of `vlog_min` (so inline *and* separated), and a mutation that
updates, deletes, inserts, and adds a field name the other side has never seen.
Each side computes a CRC-32C digest over the visible `(id, country, note)`
state; the two agree to the bit.

**This required a file layer on the Dart side, because there was none.** Dart's
`PageStore` was a `List<Uint8List>` and segment extents lived in a `Map`, so no
`.cryptand` file had ever existed. §7 lists what was added.

## 4. Performance

`design/performance-model.md` §8: assertions go on plan shape or a store
counter; wall time is recorded and charted, not gated. Run
`cargo run --release --bin <name>`.

**P1 — B+tree height** (`p1_height`). Measured leaf-cell footprint for a
separated entry: **32.2 B**, against `04-segments.md` §2.2's stated 32. Full
internal fan-out 187 at 4 KiB, 128 entries per leaf, so **height ≤ 4 covers
8.4 × 10⁸ documents** — the same shape as the Dart reference's 619 M.

**P3 — concurrent write scaling** (`p3_write_scale`). §2.1's first consequence
is a property of the format and it holds: rows per barrier rises from **3 000 at
one writer to 32 000 at 32**, which *is* group commit — one barrier over a
growing commit group. Throughput on this host rose 1 → 32 writers by **3.3×**
(disjoint ranges, `os`). §2.1 forbids claiming the second consequence in
advance, and this bench reports which was observed rather than asserting it.

**P8 — aged scan** (`p8_aged_scan`): the table in §2.1 above.

**P10 — read tail** (`p10_read_tail`), 50 000 documents:

| shape | mean | p99 | p99.9 | max |
|---|---|---|---|---|
| range-partitioned, filter on, early exit | 1.01 | 1 | 2 | 3 |
| control: filter off | 3.71 | 4 | 4 | 4 |
| control: plain tiered (`overlap_bound = tier_width`) | 1.01 | 1 | 2 | 3 |
| control: plain tiered, filter off | 4.10 | 5 | 5 | 5 |
| control: no early exit | 1.22 | 3 | 3 | 4 |

This **reproduces §4.1's corrected attribution**: with the filter on, range
partitioning is worth nothing in the mean; it is manifest pruning and the
filter that produce the bound at `tier_width = 4`. And the bound belongs to the
early exit — without it p99 is 3, exactly as §4.1 records.

**P11 — what security costs** (`p11_encryption`):

| | measured | §12 / §3.2 says |
|---|---|---|
| XChaCha20-Poly1305 encrypt / decrypt | 366 / 429 MiB/s | 1–3 GB/s per core |
| tag overhead per 8 KiB page | 0.20 % | 0.4 % at 4 KiB — consistent |
| Argon2id `mobile` (t=3, 64 MiB, p=1) | 90 ms | ~250 ms on a mid-range ARM |
| Argon2id `desktop` (t=4, 256 MiB, p=4) | 530 ms | ~500 ms |
| cipher cost on the write path | **1.30×** | "not the bottleneck" below 1–3 GB/s storage |

**Argon2id hits its target natively**, which confirms the Dart report's defect
32 diagnosis: the KDF is not slow, a scalar VM is 3–6× off native.

**The 1.30× is now a real number.** Before defect 58 it measured the cost of
encrypting value-log records and nothing else, on a write path where pages were
stored in the clear; it now covers every page as well. That it barely moved is
the useful part: the AEAD is not what a write costs, which is exactly §12's
claim, and the 0.20 % tag overhead is the whole space bill on an 8 KiB page.

**Filter false-positive rate** (`filter_fpr`), 200 000 keys over five key
shapes, 2 000 000 absent probes:

| shape | 10 bits | 12 bits | 16 bits | 24 bits |
|---|---|---|---|---|
| snowflake | 1.125 % | 0.565 % | 0.227 % | 0.103 % |
| dense | 1.130 % | 0.581 % | 0.235 % | 0.107 % |
| sparse | 1.129 % | 0.570 % | 0.231 % | 0.104 % |
| prefixed | 1.125 % | 0.568 % | 0.232 % | 0.106 % |
| compound | 1.128 % | 0.570 % | 0.234 % | 0.105 % |

Stable to within 5 % across shapes, and **0.227–0.235 % at 16 bits** reproduces
§2.4's measured 0.222–0.235 %.

## 5. Defects and divergences found

Numbering continues the Dart report's, which ended at 49.

### ⚠⚠ Defect 58 — `14-security.md` §5.2's page encryption was not implemented, in either language

An "encrypted" database encrypted its **value-log records and nothing else**.
Every inline value, every key, every index entry, every catalog descriptor and
every B+tree page sat on disk in the clear under a `cipher = 1` superblock.

```
plaintext occurrences of the secret in an ENCRYPTED file: 50
```

50 of 50, from a test that writes `TOPSECRETPAYLOAD` fifty times through the
ordinary `put` path on `desktop`, where `vlog_min` is 256 B so nothing separates.
On `mobile`, where `vlog_min` is 1024 B, *most documents are inline* — so the
profile aimed at the device most likely to be stolen was the one that encrypted
least.

Nothing caught it, and the reasons are worth writing down:

- `KeyRing::encrypt_page` and `decrypt_page` existed, were correct, and were
  called **only from a benchmark**. The primitive being present and tested is
  what made the absence invisible.
- `unencrypted_pages` was a `Counters` field no code path ever incremented, so
  it read **0** — which is exactly "fully encrypted". `13-operations.md` §6
  already forbids this ("a metric you cannot compute MUST be reported
  unavailable, never given a plausible value"); the rule was in the spec and the
  metric still lied. It now counts on the read path, from each page's own
  `flags.ENCRYPTED`, and reports *unavailable* when no page has been read.
- §13's mandatory security tests all passed. `structure_and_checksums_are_
  readable_without_the_key` verifies page **headers** without a key, which §5.1
  keeps in the clear — it passes identically whether or not payloads are
  encrypted. `a_flipped_ciphertext_byte…` flips a byte in a value-log record,
  the one thing that *was* encrypted.
- There was **no API to create an encrypted database**. Every test converted one
  after the fact, which is §8.3's mixture, so the pages written before the
  switch are legitimately in the clear — and that legitimate mixture masked the
  fact that the pages written *after* it were too. `Engine::create_encrypted`
  now exists, and the flag test uses it.

Fixed by putting the cipher in the `Pager`, which is the only place both the
copy-on-write trees and the segment builder pass through, plus §5.4 for vector
regions. Three new tests, all of which fail against the old code: no needle in
the clear, every data page carries `flags.ENCRYPTED` with a distinct nonce, and
a vector slot's `f32` bytes are not on disk. The Dart side has the same three.

**The general lesson, for a format with a security chapter: test what is
*absent* from the bytes, not what the API returns.** Every test here asked "does
it round-trip", and encryption round-trips perfectly when it does not happen.

### ⚠ Defect 59 — `01-container.md` §3 and `14-security.md` §5.2 contradict each other on `payload_len`

§3: "`payload_len` — uncompressed, unencrypted payload length". §5.2: the AEAD
tag "is appended to the ciphertext and **is inside `payload_len`**". Both cannot
hold, and neither is implementable alone — a decryptor needs the exact stored
length (Poly1305 covers exactly the ciphertext, one byte either way fails the
tag) and a decompressor needs the plaintext length. A page that is compressed
*and* encrypted needs both at once.

Fixed by giving the reserved `u32` at offset 28 a name: `stored_len`, the
payload bytes as stored, `0` meaning "same as `payload_len`". Nothing moves —
every page that is neither compressed nor encrypted writes 0 there and is
byte-identical to what the draft described, which is why the conformance vector
needed only a rename.

Also new in §5.2, because it is not derivable and both implementations had to
discover it: **a page builder must reserve the tag before laying out cells.** A
page filled to `page_size - 40` has nowhere to put 16 more bytes, and finding
that out at write time means a page that cannot be written at all.

### ⚠ Defect 60 — `14-security.md` §5.4's per-extent nonce is reused on the first ordinary write

§5.4 fixed a chunk's nonce at `1 || counter || head_page_id || i` with
"`counter` … the extent's single allocated nonce value, stored in its head
page". That holds only if every chunk is written exactly once. A vector region
breaks it immediately: `stride` is far below `page_size`, so two slots share a
chunk and are written at different times, and a slot may be rewritten outright.
Same key, same nonce, two plaintexts — the failure §4 opens by calling "not a
hardening measure; it is the whole thing".

Fixed: the counter is **per chunk and per write**, stored in the clear at the
head of the chunk, exactly as §5.3 already does for a value-log record and for
the same reason. A partial-chunk write is a read-modify-write under a fresh
counter. The cost is 8 bytes a chunk, so an encrypted extent is ~0.6 % larger
rather than ~0.4 %.

### ⚠ Defect 61 — `14-security.md` §4.1's nonce floor was derived, not held, and underflowed

`allocate_nonce` computed its base as `sb.next_nonce - NONCE_GAP`, which is
correct only if rule 1's publish has already run. Encryption can be switched on
*after* open (§8.3's conversion), which is a writer that never passed through
the open-time publish, so on a converting database the subtraction ran at
`next_nonce = 0`.

- **Debug**: `attempt to subtract with overflow`, three of thirteen security
  tests panicking.
- **Release**: it wraps, `base + n` wraps back, and the session quietly hands
  out nonces `0 … 2²⁰` **from a floor that was never published** — precisely the
  crash-reuse hole §4.1 exists to close.

The report this file replaces said "zero warnings, `cargo test` clean". It was
run in release only. **`cargo test` and `cargo test --release` are different
tests of arithmetic**, and a format whose security rests on a counter should run
both. Fixed by holding the cursor and the published limit as engine state, with
one cursor shared by pages and value-log records — two would be two chances to
hand the same value out twice.

### ⚠ Defect 62 — a writer sealed `sb_mac` into the file and kept the old one in memory

`write_superblock` sealed the image it wrote but never updated
`self.sb.sb_mac`. From the next write on, `verify_superblock` recomputed the MAC
over the *current* fields and compared it against a MAC that described the
fields as they were *before* — so it reported the writer's own file as
**tampering**. §4.1's open-time nonce publish is a superblock write, which makes
this every encrypted file immediately after every open.

**The only verifier that noticed was the other implementation's**, in the
encrypted round trip: Rust opened a Dart-written encrypted file fine and then
failed it on `sb_mac`. This implementation's own tests could not see it — the
one test that runs `verify()` on an encrypted engine asserts that
`Class::Corruption` is empty, and tampering is deliberately a different class.

§6.2 now states the second half of the rule explicitly.

### ⚠ Defect 63 — tree 1 was written as a log of everything ever freed, not as the free list

`write_free_list` only ever *inserted*, on the reasoning that "a commit writes
only what is new". But an extent **leaves** the free list when it is reclaimed
(§6), and a best-fit allocation that takes part of one moves the remainder to a
different key. Neither was ever removed, so the persisted tree 1 was a strict
superset of the truth.

That is invisible to the implementation that wrote it, which keeps its own list
in memory and never reads tree 1 back within a session. It is fatal to any
*other* implementation: it allocates a page tree 1 calls free, the live
superblock still names it, and the catalog it overwrites is gone. Found by the
round-trip gate the moment the Dart side started reading tree 1 at all — Dart
could not open a file it had written and Rust had mutated.

### ⚠ Defect 64 — `04-segments.md` §6.9's locality debt flags a healthy database, twice over

§6.9's surplus set was defined over "the value-log segments", with "live bytes
in a run that is not key-clustered at all are surplus regardless of where it
sorts". Both halves flag a database that is not sick:

- A hot run is unclustered **by construction** — §6.3 clusters a generation when
  it is *promoted* — so a freshly loaded database, every live value in one hot
  run, reads **100 %** against a 20 % bound. This implementation's own
  `cryptand verify` said so on its own fresh file.
- A hot run is also the write path's *tail*, holding everything written since
  the last last-level compaction, and **neither remedy §6.9 names can reach
  it**: promotion happens at the next last-level compaction, which the level
  policy schedules, and collection merges cold generations. A healthy database
  with one clustered cold run plus a live tail read **40 %** that collecting
  could not move.

Fixed by defining `ideal_runs` and the surplus set over the **cold tier** only,
with the denominator staying all live bytes. The measurement that motivated the
definition is untouched — the nineteen runs of §6.9's table are cold
generations — and P8's control still fails at 35.7 % debt with collection off.

### ⚠ Defect 65 — `10-transactions.md` §2 step B says "seal/flush", and the two words are different things

Step B is "flush the open value-log segments' tails". Sealing is
`04-segments.md` §6.2's *terminal* state — no further appends, ever — and doing
it per commit retires the open run every time, so a database gets **one
value-log run per commit**. That is precisely the surplus §6.9 bounds: the Dart
implementation sealed at commit, loaded 400 documents in three commits, produced
three runs against an `ideal_runs` of one, and read 45 % locality debt on a
freshly written database. §2 now says "flush", and says why.

### ⚠ Defect 50 — `04-segments.md` §6.2 puts records inside a page whose checksum covers the whole page

§6.2 fixes `data_offset` at **104**, so a value-log segment's records begin at
byte 104 **of its head page** — which `01-container.md` §1 explicitly permits
("an append into the open tail of a value-log segment"). But that head page is a
page: §3 gives it a 40-byte header, and `00-conventions.md` §6 says a page's
checksum covers "every byte of its page … except the four bytes of the checksum
field itself".

So **the head page fails its own checksum from the first append onward**, for
the entire life of the segment. The two rules cannot both hold as written.

§3's carve-out — "a verifier MUST use the extent's mechanism for these pages" —
is only satisfiable if the head page's checksum covers its *immutable header
region*, `4 … data_offset`, with the records covered by their own per-record
`crc32c` as §6.2 already specifies. Both implementations now do that
(`PageHeader::checksum_range_end` in Rust, `PageHeader.checksumEnd` in Dart).
**§6 needs the exception stated, or `data_offset` needs to be `page_size`.**

This is invisible without a file: an in-memory implementation never checksums
the head page after an append.

### ⚠ Defect 51 — the Dart value-log head page carried no page header at all

`_writeHeadPage` wrote §6.2's 64-byte segment header at offset 40 and nothing at
offset 0 — no `page_type`, no `flags`, no `extent_pages`, no checksum. In memory
nothing noticed. In a file:

- `13-operations.md` §3's repair — "recompute by scanning segments", "scanning
  the segment's records forward from `data_offset`" — **cannot find a value-log
  segment at all**, because it scans for `VLOG_SEGMENT` pages;
- `04-segments.md` §11's invariant 8b, "a head page and a tree-7 entry that
  disagree on `segment_id`, `tier`, `heat` or `created_seq` is corruption", has
  nothing to compare against.

Fixed in `lib/src/vlog.dart`, with a test that walks the file and reads the
header back.

### Defect 52 — §6.9's `locality_debt` reads 100 % on a healthy fresh database

§6.9 makes "live bytes in a run that is not key-clustered at all … surplus
regardless of where it sorts". A database that has been written but has not yet
compacted to the last level holds every live value in **hot**-tier runs, which
are unclustered by construction — the hot tier is where "most records die". So
`locality_debt` reads **100 %** and `04-segments.md` §11's invariant 11 makes a
conforming verifier flag a database that is not sick.

The bound is qualified — "whenever the database is not under active write
pressure" — but nothing gives that qualifier teeth, and a metric
`13-operations.md` §6 calls "the number that predicts scan decay" is not usable
as a health signal while it reads 100 % on every new database. Either the hot
tier is excluded from the ratio, or invariant 11 needs the same qualifier.

### Defect 53 — §2.4's blocked-Bloom figures are pessimistic, and the ratio it attributes to blocking is smaller than stated

§2.4 gives ≈1.7 % at 10 bits and says blocking "costs roughly 7×" the classic
rate. Measured, same hash and same `k`, 200 000 keys:

| bits | classic | classic predicted | blocked | ratio |
|---|---|---|---|---|
| 10 | 0.818 % | 0.819 % | **1.130 %** | 1.4× |
| 16 | 0.049 % | 0.046 % | **0.235 %** | 4.8× |

The 16-bit row matches §2.4's own measured range (0.222–0.235 %); the **10-bit
row does not** — 1.13 % against a stated ≈1.7 %. The ratio is 4.8× at 16 bits
and 1.4× at 10, not "roughly 7×" at both. These are non-normative performance
figures, and the trade §2.4 describes is unaffected; the numbers should be
corrected.

### Defect 54 — §12's AEAD throughput is 3–8× optimistic against a standard implementation

§12 predicts "1–3 GB/s per core on ARM and x86 without hardware AES". Measured
with the RustCrypto `chacha20poly1305` crate on an Apple M-series CPU, over
8 KiB buffers: **366 MiB/s encrypt, 429 MiB/s decrypt** — 0.37–0.43 GB/s, with
`-C target-cpu=native` making no difference. §12's *conclusion* survives (that
is still far above phone storage), but the number does not, and it is the number
an implementation would size a cache against.

### Defect 55 — nothing says how the free tree records the pages its own writes orphan

`01-container.md` §6 puts free extents in tree 1, a copy-on-write B+tree. Writing
an entry into it copies a root-to-leaf path, which orphans pages, which are new
entries, which orphan more. **The free tree cannot record its own churn in the
commit that causes it**, and the spec never says what to do about it.

This implementation persists them on the *next* commit — a bounded one-commit
lag whose residue (7 pages at close, on the interop fixture) `01-container.md`
§9 step 7 reports as a **leak**, repairable, and which `cryptand repair`
reclaims. A first attempt at a fixed-point loop *diverged*: re-putting the whole
free list each round copied a path per entry and produced 68 leaks instead of 7.
§6 should say which discipline it expects.

### Divergence 56 — CLOSED: a Dart-written file now carries a free tree

The original finding: Dart recorded free pages without reclaiming them and wrote
`freelist_root = 0`, so a Rust reader's §9 step 7 reported **33 leaks** on the
interop fixture.

Dart's `PageStore` now keeps §6's free tree, best-fits from it among extents at
or below `min_retained_commit`, extends the file only when nothing fits, and
persists it as tree 1. The remaining count on that fixture is **8**, all of them
tree 1's own pages — defect 55, which is a property of the format and which Rust
leaks about the same number of.

Closing it produced defect 63 on the Rust side, which is the value of a round
trip stated precisely: the moment one implementation *reads* what the other
writes, an internally consistent lie stops being consistent.

### Defect 57 — §2.4.1's negative control depends on the key set, and the obvious key set cannot fail

§2.4.1 argues CRC-32C must not be the filter hash because "any pair of CRC-32C
evaluations over the same key therefore carries 32 bits of entropy, not 64", and
records 1868 collisions over 4 000 000 keys against 1863 predicted.

Reproducing it with **sequential** ids gives **zero** collisions for the CRC pair
— the differences span ~22 bits, inside the burst length CRC-32 is designed to
detect, so the control cannot fail and measures nothing. With random 64-bit ids:

```
CRC-32C pair: 1868 collisions (n^2 / 2^33 predicts 1863)
CFH-64:       0 collisions
```

**1868, to the unit.** This is the fifth instance of the project's recurring
"a control that cannot fail has measured nothing"; §2.4.1 should say the key set
is part of the claim.

### Implementation defects the tests found

These are this implementation's, not the spec's, and each was caught by a test
that exists because a chapter asked for it:

1. **A `RANGE_DELETE` has the internal-key shape of a point key** (§2.5 gives it
   `internal_key(tree, key, seq, RANGE_DELETE)`), so a point read seeking that
   key found the range delete first and returned *the interval's payload as a
   value*. §4 resolves range deletes separately, through `rd_sources`; the
   lookup path must skip them. Caught by §6's range-delete test.
2. **A tiered → last-level compaction did not include the overlapping
   last-level segments**, so the last level quietly stopped being disjoint —
   §3.1.1's defect exactly, reached from a different direction. Caught by the
   verifier's user-key overlap check.
3. **Compaction never released superseded value-log records**, so `live_bytes`
   never fell, `locality_debt` read 100 % on a fully promoted database, and
   collection never fired. §6.7 says liveness "is decremented when a compaction
   observes a record superseded or deleted"; nothing was doing it. Caught by the
   aged-scan test.
4. **Promotion appended each generation into the still-open cold segment**, so
   one segment held several runs and lost `clustered`. §6.3 clusters a
   *generation*; each last-level compaction must start a fresh cold run and
   leave merging them to collection (§6.8).
5. **The compaction picker always drained L0 first**, so a deeper level grew
   without bound (18 segments at L2 against a `tier_width` of 2) and §4.1's
   per-level bound stopped holding. Now the worst overshoot wins, deepest first.
6. **Tree 3's root was never persisted**, so every open rebuilt it by scanning
   the catalog and orphaned the previous tree — a leak per open. §2 says "tree
   3's root is in its catalog descriptor"; the descriptor has to be *written*.
7. **The `Store`'s per-row registration took a global mutex**, which is what
   `10-transactions.md` §2.2 forbids ("MUST NOT route concurrent writers through
   a shared write buffer"). Replaced by two atomics — issued and landed — whose
   agreement is exactly §2.3's contiguous-prefix condition. Scaling at 32
   writers went 2.67× → 3.31×.
8. **`value_reads_per_scanned_row` counted dereferences, not I/Os**, so it read
   1.000 by construction and could never approach §6's 0.3. §8.1 requires reads
   in the same page to be *coalesced*; counting the coalesced I/Os is what the
   metric is for.

### Implementation defects the encrypted round trip found

Listed separately because they are what a second implementation buys. None was
reachable from this crate's own tests:

1. **`sb_mac` stale in memory** — defect 62. Rust opened Dart's encrypted file
   and then failed its own `verify()` on the MAC.
2. **Tree 1 as an append-only log** — defect 63. Dart read Rust's free tree,
   allocated pages it named, and overwrote the live catalog.
3. **The gate's own last comparison could not fail.** It compared two digests
   after both sides had mutated, and when *both* readers failed to open the file
   it compared two empty strings and printed `ok`. It reported success while
   printing `Bad state: the file does not hold orders` two lines above. Fifth
   instance in this project of "a control that cannot fail measures nothing",
   and the first one inside the test harness rather than a benchmark.

## 6. What is not here

- **Zstd and Zstd dictionaries** (`ZSTD`, `ZDICT`). LZ4 is implemented and is
  the only codec a Level-0 implementation MUST support; a page carrying codec 2
  is refused by name rather than guessed at.
- **Blob extents and overflow chains** are specified and reachable
  (`BLOB_REF`, `OVERFLOW_REF` round-trip through CVE, and `01-container.md` §5's
  16-byte pointer is implemented), but the write path never produces one:
  `vlog_min ≤ page_size / 4` means the ordinary path always separates first.
- **`DEC128`** is stored and round-trips as a value; it has no key encoding, by
  §4.4, and indexing one is refused.
- **HNSW and Vamana construction.** §9's principle is "specify the durable
  layout, not the algorithm": the region, the adjacency records, the codebook
  and the two id maps are implemented, and search is §8's mandatory brute-force
  fallback over the flat region.
- **Multi-process *writing*** (`MULTIPROC`), which is not part of version 1.0.

## 7. Changes to the Dart implementation

Additive, and each is needed for a file to exist at all:

- `lib/src/file.dart` — `DatabaseFile.save` / `.open`, §1's layout.
- `PageStore` reserves **pages 0 and 1** for the two superblock slots, and gained
  `fromBytes`, `allocExtent`, `writeExtent`, `readExtent`, `toBytes`.
- `VlogSegment` writes a real page header (defect 51), pads its buffer to whole
  pages, remembers `startPage`, and gained `fromExtent`.
- `PageHeader` checksums a value-log head page over `4 … data_offset`
  (defect 50).
- `Database` puts the catalog and attributes in the **engine's** page space,
  which is where `05-catalog.md` §2 puts trees 0 and 2, instead of a second
  `PageStore` no superblock could name.
- `Engine` accepts an injected store and the roots a superblock carries, and
  exposes `restoreCounters` — ids that are "never reused" have to survive a
  reopen for the same reason they survive a crash.
- `tool/interop.dart`, the Dart half of the round-trip gate.
- `test/file_test.dart`, six tests over the file layer.

Since then the Dart side has closed the gaps that made it a *reader* of the
format rather than a peer implementation of it. Its own `REPORT.md` §12 has the
detail; in summary:

- **`14-security.md` end to end.** Page encryption (§5.2), value-log record
  encryption (§5.3), `sb_mac` (§6.2), the §4.1 nonce discipline with a durable
  publish, keyslots, and `DatabaseFile.create` for a database that is encrypted
  from its first page. It could previously open only unencrypted files, and had
  the primitives without an engine that used them — the same shape as defect 58
  on this side.
- **`01-container.md` §6**, the free tree: kept, best-fitted from, persisted as
  tree 1, and read back. Divergence 56 above.
- **`01-container.md` §10**, the exclusive writer lock, tested with a real
  second process because Dart's `lockSync` is a POSIX `fcntl` lock and those are
  held per *process* — a second handle inside one process is granted it, so a
  same-process assertion would have passed while testing nothing.
- **`05-catalog.md` §2**, tree 3's root in its own descriptor, which was the
  leak-per-open this side had already fixed.
- **Superblock fidelity**: the real profile rather than a hardcoded `desktop`,
  the durability actually performed, `min_retained_commit`/`min_retained_seq`,
  and the keyslots.
- **`01-container.md` §9 step 8** in its verifier: `sb_mac`, every page's AEAD
  tag, and no `(key, nonce)` pair twice.

All **561** Dart tests pass, `dart analyze` is clean.

## 8. Running it

```
cargo test --workspace                    # 212 tests, debug
cargo test --workspace --release          # and release: they test different arithmetic
cargo run --release --bin cryptand -- verify <file>
reference/conformance/interop/run.sh      # the round trip, plaintext and encrypted
cargo run --release --bin p10_read_tail 200000
cargo run --release --bin p8_aged_scan 20000
cargo run --release --bin filter_fpr
cargo run --release --bin p3_engine_write_scale 20000
cargo run --release --bin p11_encryption
cargo run --release --bin p1_height
cargo run --release --bin cryptand -- fuzz <file> 5000
```
