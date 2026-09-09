# Hardening pass — findings

A security and edge-case pass over the three reference implementations, against
`spec/14-security.md` §9 ("Hardening against a hostile file") and §11 ("Key
material in memory").

Baseline before this pass, all green: **Rust 286, Dart 637, Java 304**.

Every defect below is recorded with the instrument that was blind to it, in the
style this project already uses — because in each case the code was *present*
and *tested*, and the question that found it was not "is this correct?" but
"what does nothing here look at?"

---

## Defect 71 — Rust panics on a hostile segment filter

`04-segments.md` §2.4's filter header carries `block_count` and `probes`, both
read from the file and both attacker-controlled. **Dart and Java validate them;
Rust validated neither.**

`block_count = 0` makes `BlockedBloom::locate` compute `block = (h1 * 0) >> 32 =
0` and then index `blocks[0 * 64 + bit/8]` into a **zero-length** array:

```
thread '...' panicked at cryptand/src/filter.rs:75:24:
index out of bounds: the len is 0 but the index is 63
```

That is exactly what §9.1 forbids — "a typed corruption error rather than an
allocation failure, a panic, an abort, or an unbounded recursion" — reachable by
anyone who hands the process a `.cryptand` file. `probes` is an
attacker-controlled loop count that §2.4 bounds at 1..16, and a reader MUST take
it from the file rather than recompute it, so it cannot be sanitised by ignoring
it.

**Fixed** in `Segment::filter`, where the other two implementations already
validate: `block_count < 1` and `probes` outside 1..16 are named corruption
errors.

### Why nothing saw it

Two instruments, both blind, for different reasons:

- **`cryptand fuzz` never reaches the filter at all.** Its read oracle opens,
  verifies, and *scans* every tree. A scan does not consult a segment filter —
  only a **point read** does. So §2.4's filter, the structure every `get` passes
  through, was outside the fuzzer's reach for its entire life. Fixed: the oracle
  now point-reads each key the scan returns.
- **Even reaching it, random mutation cannot reliably find it.** `block_count`
  is one specific u32 at one specific offset. With the oracle fixed, a control
  run of **3 000 mutations with the bug reintroduced still reported 0 panics**.

That second point is the useful one, and it generalises past this defect.

---

## The field-boundary sweep — a deterministic instrument where the fuzzer is random

Bugs of this class live at the **boundaries of a named field**, and boundaries
are enumerable. So the new sweep is exhaustive rather than random: for one page
of every `page_type` in the shared corpus, every u32-aligned slot in the 40-byte
page header and in the first 32 bytes of payload is set to each of `{0, 1, 2,
0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF}`, the page checksum is **repaired** (§9.4:
an attacker recomputes it trivially, so leaving it broken tests the CRC and not
the decoder), and the file is opened, verified, scanned and point-read.

Added in all three: `tests/hostile_test.rs`, `test/hostile_test.dart`,
`HostileTest.java`. Roughly 1 200 cases each, a few seconds to run.

**It has a control, and the control fails.** With defect 71 reintroduced the
sweep names the exact field on the first run:

```
page_type 6: setting the u32 at offset 44 to 0x00000000 panicked.
§9.1 requires a typed corruption error.
```

Offset 44 is header (40) + payload offset 4 — `block_count`. What 3 000 random
mutations missed, the sweep finds deterministically.

Each sweep also asserts `refused > 0`: a sweep that reaches no decoder would
otherwise pass against a reader that validates nothing, which is this project's
recurring "a control that cannot fail measures nothing".

---

## Defect 72 — an untrusted extent length drives the verifier into an unbounded allocation, in all three

Found by the Dart sweep on its first run:

```
Exhausted heap space, trying to allocate 34359738384 bytes.
package:cryptand/src/verify.dart 210  EngineVerify._checkPageAccounting
```

32 GiB, from one edited u32. The verifier's page accounting walks each extent's
page ids to detect double-allocation, and `start_page` / `pages` come out of the
file:

| | shape |
|---|---|
| Dart | `claim([for (var i = 0; i < seg.pageCount; i++) …])` — materialises one list element per declared page |
| Rust | `for p in s.start_page .. s.start_page + s.pages` inserting into a `HashMap` — one entry per declared page |
| Java | `for (long p = start; p < start + pages; p++) owners.put(…)` — the same |

§9.1's "bounds-check **before allocating**" applies to the verifier's own
working set, not only to its decoders.

**The most interesting part is that the mitigation was already written, ten
lines below, by the same hand.** Dart's leak report caps its output for exactly
this reason and says so:

> *"`page_count` comes out of the file, and one finding per leaked page means a
> hostile superblock claiming four billion pages drives the verifier into four
> billion allocations — section 9.1's ... applies to the verifier's own output"*

The hazard was correctly identified and the fix applied to one of the three
loops that had it.

**Fixed** in all three: an extent that runs past the end of the file is a named
corruption finding, and the page ids are produced lazily rather than
materialised. Rust and Java were hardened defensively — the sweep did not reach
their instances, and "the sweep did not reach it" is not "it is bounded".

---

## Defect 73 — Rust key material was zeroed only on the path that calls `close()`

`14-security.md` §11: *"a runtime with deterministic destruction SHOULD bind key
material to a type that zeroes on release and that cannot be debug-printed or
copied implicitly."*

Rust's `KeyRing` had a `zeroize()` method called from exactly one place,
`Engine::close`, and **no `Drop` impl**. Every other way a ring dies left the
master key and all three subkeys in freed memory:

- an early `?` anywhere between `open` and `close`;
- a panic unwinding through the caller;
- a value simply falling out of scope;
- **every `clone`** — and `KeyRing` is `#[derive(Clone)]`, which is "copied
  implicitly" in the words of the rule.

Three further copies were never zeroed at all: the KEK returned by `derive_kek`
in both `unlock` and `make_keyslot`, and the **heap `Vec` the AEAD hands back
holding the plaintext master key** in `unwrap_master_key`, which was copied into
an array and then freed intact.

**Fixed**: a `Drop` impl, and explicit clearing of all three intermediates.

Zeroing is done through a new `secure_zero`, because a plain `fill(0)` before a
drop is a **dead store** the optimizer is entitled to delete — which would make
§11's MUST a comment. It uses `black_box` plus a compiler fence rather than
`write_volatile`, because this crate contains no `unsafe` and that is a property
worth keeping; the honest description is that it is a strong hint, not a
guarantee.

**The test is a control that fails.** Every field of `KeyRing` is a `Copy`
array, so the type has no drop glue of its own and `std::mem::needs_drop` is
`false` unless the `Drop` impl puts it there. Removing the impl fails the test.

---

## Defect 74 — §11's best-effort caveat was documented in neither Dart nor Java

§11 has one requirement whose deliverable *is* the documentation:

> | **A runtime that may relocate or copy heap objects** (a moving or copying
> garbage collector) | MUST document that zeroing is best-effort, because a copy
> the program never sees cannot be zeroed. **Documenting it is the
> requirement**; achieving what the runtime forbids is not. |

Both the Dart VM and the JVM have moving, copying collectors. Neither
implementation said so anywhere — not in source, README or report. Java had
documented the *other* half of §11 correctly (why the password parameter is
`byte[]` and not `String`), which is what makes the omission easy to miss.

**Fixed**: the caveat now sits on the API that accepts the credential in each —
`Engine.Options.password` and `DatabaseFile.open`'s `key` — with the practical
consequence stated: a heap dump of a process that has ever opened an encrypted
database may contain the master key even after a clean `close()`.

---

## Defect 75 — Java verified credential records against parameters it took from the file unchecked

`05-catalog.md` §8's tree 5 record carries its own `kdf` and `params`.
`Database.authenticate` read `t_cost`, `m_cost_kib` and `parallelism` straight
out of the record and passed them to Argon2id.

The keyslot analogue is *deliberately* not validated, and §3.2 is explicit about
why: *"on open it MUST use whatever the slot says — the superblock MAC (§6) is
what prevents an attacker weakening those numbers."* **That reasoning does not
reach tree 5.** `sb_mac` covers the superblock, not a tree's contents, and §10
explicitly contemplates users on an *unencrypted* database — where nothing
authenticates the record at all. §9 then governs, and it "applies to every
implementation, whether or not it supports encryption, because T5 does not
require the attacker to have a key."

Four things were wrong, in rising order of how quietly they failed:

1. **No ceiling.** `Argon2id.hash` has an RFC floor (`p < 1 || t < 1 || m < 8p`)
   which catches `0xFFFFFFFF` only because it narrows to `-1`. **`0x7FFFFFFF`
   passes that check and asks for roughly 2 TiB.** A floor is not a ceiling.
2. **No §3.2 floor.** A record declaring `t_cost = 1, m_cost_kib = 8` was
   accepted and used — the KDF downgrade the corpus has a vector for on
   keyslots, unguarded on user records. Every profile in §3.2's table is above
   the floor of 2 / 16384 / 1, so enforcing it refuses no conforming file.
3. **`kdf` was read and ignored.** A record declaring `"scrypt"` was verified
   with Argon2id anyway. §8 says `kdf` MUST be `"argon2id"`; §9.2 forbids
   resolving the name to anything, so refusing is the only conforming answer.
4. **Unchecked casts and null dereferences** on a record whose shape is
   attacker-chosen: a non-`Doc` value in tree 5, or a record missing `salt`,
   produced `ClassCastException` / `NullPointerException` rather than a typed
   error.

**Fixed**, with a floor, a ceiling (1 GiB — four times `desktop`'s 256 MiB and
still bounded), a `kdf` check, and typed errors for every structural case.

Rust and Dart do not implement tree 5 at all, so they are unaffected; §8's MUSTs
are conditional on having the feature.

---

## One operational note, not a defect

**The three test suites cannot run concurrently.** They share
`reference/conformance/files/`, and a reader takes `01-container.md` §10's
exclusive writer lock over it, so a parallel CI matrix reports three spurious
corpus failures:

```
v1.0-security-tamper-page.cryptand  FAIL  locked by another process
```

Worth knowing before anyone parallelises the build.

---

## Defect 76 — Rust decoded the whole segment filter on every probe

`04-segments.md` §2.4's filter is consulted by every point read. Rust's
`Segment::may_contain` called `self.filter()`, which for each probe walked the
filter's pages, copied the entire payload into a fresh `Vec`, and then copied
the block array out of it **a second time** — to read one bit.

**Dart and Java both already cached it** (`_filterLoaded`, `filterLoaded`). This
was a divergence, not a design.

`14-security.md` §12 costs a probe as "exactly one 64-byte block". Measured with
the new `benches/filter_probe.rs` (`cargo run --release --bin filter_probe`),
200 000 probes per row:

| keys | filter bytes | per probe | cached | ratio |
|---|---|---|---|---|
| 1 000 | 1 280 | 188.6 ns | 14.3 ns | 13.2× |
| 10 000 | 12 544 | 726.5 ns | 10.9 ns | 66.7× |
| 100 000 | 125 056 | 6 660.9 ns | 10.8 ns | **616×** |
| 500 000 | 625 024 | 26 277.4 ns | 10.6 ns | **2488×** |

The cached column is **flat at ~11 ns** across a 500× range of filter sizes,
which is what "one 64-byte block" looks like when it is true. The uncached
column is linear in filter size, which is what it looks like when it is not: a
single probe on a 500 000-key segment cost **26 µs**.

**Fixed** with a `std::sync::OnceLock` on `Segment` — `OnceLock` and not
`OnceCell` because a `Segment` lives in an `Arc` and is probed from every reader
thread.

### On the honest size of this number

`reference/bench`'s end-to-end `ops_bench` at 20 000 documents moves only from
**p50 121.8 µs → 116.2 µs**, about **5 %** (medians of three runs each; p99
166 → 158). That is not the fix underperforming — it is the benchmark's scale.
At 20 000 documents a segment's filter is two or three 64-byte blocks, so the
copy being removed is a couple of hundred bytes. The cost removed is O(filter
size), and the table above is the shape of the claim; the 5 % is one point on
it, at the small end.

This is exactly the case `reference/bench/README.md` warns about when it says a
row in µs "is a property of this machine and this run". The primary result here
is the **counter**: `a_thousand_probes_decode_the_filter_once` asserts that 1 000
probes decode the payload exactly once, and it fails if the cache is removed.

### What it costs

The parsed filter now stays resident for the life of an open segment — roughly
`10 bits × entry_count`, about 3 % on top of a segment extent that is already
held in memory in full. Dart and Java have always paid it. A zero-copy borrow
into the extent is not available in general: a filter spanning more than one
page is interrupted by 40-byte page headers, so the block array is not
contiguous in the file.

---

## Defect 77 — a leaf cell with an empty key panicked the Rust reader

Found by `cryptand fuzz` **on the first run after its oracle learned to do a
point read** — the same instrument fix that defect 71 needed:

```
panicked at cryptand/src/segment.rs:380:78:
called `Option::unwrap()` on a `None` value
```

`Node::record_at` took the `op` byte as `*key.last().unwrap()`. `prefix_len` and
`suffix_len` are both read from the file, so a hostile leaf page can declare a
zero-length key. §1's internal key is
`u32be(tree_id) || CKE(key) || u64be(~seq) || u8 op` and is never shorter than
13 bytes, so this is corruption — but it arrived as a panic.

**Fixed** by routing the op through `parse_internal_key`, which already holds
the 13-byte minimum, rather than keeping a second copy of the rule that could
drift from it.

**Java and Dart were both already correct** — Java's `Ikey` calls
`checkLength(ik)` on every accessor, Dart's `parseInternalKey` refuses anything
under 13 bytes.

---

## The pattern across defects 71, 76 and 77

Three unrelated findings in the Rust read path, and in every one of them **Dart
and Java both did the right thing and Rust did not**:

| | Dart | Java | Rust |
|---|---|---|---|
| filter `block_count` / `probes` bounded (71) | yes | yes | **no** |
| internal key ≥ 13 bytes before indexing it (77) | yes | yes | **no** |
| parsed filter cached per segment (76) | yes | yes | **no** |

That is not three coincidences. Dart was built in eighteen phases against the
conformance vectors, and Java was built against the vectors a third time; both
arrived at each rule by being made to fail it. The Rust implementation was
written in one pass, and one pass produces code that is right about what the
author was thinking about.

**The cheapest audit available on this project is therefore a differential one:
for each decoder, ask which of the three validates the most, and treat the other
two as suspects.** It costs one `grep` per rule and it found every defect above.

---

# Part 2 — compliance and performance, by differential audit

Part 1 ended with a rule: **for each decoder, ask which of the three
implementations validates the most, and treat the other two as suspects.** Part 2
applies it deliberately rather than by accident, to `02-value-encoding.md`.

## Defect 79 — all three compared MAP entries in stored order, where §8 says sorted

§8 rule 8: *"`ARRAY` compares element-wise, then by length. `MAP` and `DOC`
compare as their **sorted** `(key, value)` sequences."* One sentence, two
containers. Every implementation sorted `DOC` and none sorted `MAP`:

```rust
(Value::Map(x), Value::Map(y)) => compare_pairs(x, y),            // stored order
(Value::Doc(x), Value::Doc(y)) => { xs.sort_by(..); compare_pairs(..) }
```

Dart (`_docEntries` sorts, `a.entries` does not) and Java (`docEntries(x)` vs
`x.entries()`) had it identically. So two maps holding the same entries, written
in a different order, compared **unequal** — and sorting a list of them was
therefore not sorting by value.

### Why every existing instrument was blind

§8 is consumed **in memory**. Three implementations can disagree completely
about how values sort and every direction of the cross-language file gate still
passes, because the bytes never differ. §8 knows this about itself — it opens
"defined here once, for all SDKs, ending the current divergence" and then records
that a divergence survived *inside* it, "and no test could see it because nothing
tested this section at all".

**And the differential audit alone would not have found this one.** All three
implementations agreed, exactly, on a 90 × 90 comparison matrix. Agreement was
the wrong question; the spec was the right one.

### The instrument added: `conformance/vectors/order/values.json`

A new vector group — the twelve that existed covered CKE, CVE, containers,
filters, catalogs, indexes, numbers, strings, documents, codecs, the analyzer and
security, and **none covered §8**.

90 values chosen to exercise all ten rules, and **two** checks over them:

- a **90 × 90 matrix** of `sign(compare(i, j))`, which every implementation must
  reproduce. A matrix and not a sorted permutation, deliberately: §8 makes many
  of these values equal — every numeric tag holding 5 is one value, a
  `TIMESTAMP` of 1000 ms equals a `TIMESTAMP_NS` of (1 s, 0), `-0.0` equals
  `+0.0` — and equal elements have no defined relative position in an unstable
  sort. A permutation would encode the sort algorithm; the matrix encodes the
  order.
- **281 named rules**, each citing a §8 rule number, two corpus indices and the
  sign required between them. This is the half that reads the spec instead of
  the neighbours, and it is the half that found the defect.

Plus, in each implementation, a total-order check over all 90 × 90 pairs
(reflexivity, antisymmetry) and all 90³ triples (transitivity) — the property a
comparator built out of per-type special cases is likeliest to break.

Tests: `tests/order_test.rs`, `test/order_test.dart`,
`OrderConformanceTest.java`. Reverting the fix in any one of them fails the
matrix check with the differing row printed.

## Defect 80 — Rust enforced none of §4's four MAP invariants; Dart and Java enforced all four

The differential audit, run deliberately this time, on `02 §4`:

| §4 rule | Dart | Java | Rust |
|---|---|---|---|
| writer rejects a map key with no CKE encoding | yes | yes | **no** |
| writer rejects duplicate keys | yes | yes | **no** |
| reader refuses entries not sorted by `CKE(key)` | yes | yes | **no** |
| reader refuses duplicate keys as corruption | yes | yes | **no** |

Rust had a *comment* citing the rule on the encode side and no check on either
side. Worse than absent: the encoder sorted with

```rust
cke::encode(&a.0).unwrap_or_default()
```

so a key with **no** CKE encoding — a `DOC`, a `MAP`, a `REGEX`, all of which §4
names — silently became the **empty byte string**, sorted first, and was written.
The resulting file is one Dart and Java both refuse to open, because their
readers check exactly this. A format whose purpose is interchange had one
implementation able to write files the other two reject.

§4's justification is not stylistic: *"sorting makes maps comparable, hashable
and diffable across languages, and makes a lookup a binary search"* — and a
binary search over unsorted entries silently returns the wrong answer rather
than failing.

### The API was the reason, and the fix respects it

`cve::encode` returns `Vec<u8>`, not `Result` — the Rust encoder is structurally
**unable** to reject anything, which is why Dart and Java (whose encoders are
fallible) enforce the rules there and Rust could not.

Changing the signature would touch 42 call sites. It would also be the wrong
change: **every one of those call sites in `src/` encodes a value the engine
itself built** — a catalog document, a tree name, a byte string — none of which
can carry a map at all. A caller's value reaches the encoder at exactly one
seam, `Collection::insert`, which already returns `Result`.

So the reader checks went into the decoder where they belong, and the writer
checks into a new `cve::check_writable` called from that one seam. **The tests
go through `Collection::insert`, not through the helper** — a validator nothing
calls is this project's most-repeated defect, and testing the helper directly
would reproduce it exactly.

One test detail worth keeping: the duplicate-key case uses `I32(5)` and `I64(5)`
— different CVE tags, *equal* CKE bytes. A check that compared keys structurally
rather than by their key encodings would pass it while violating §4, which
defines a duplicate as "two entries whose `CKE(key)` bytes are equal".

---

## Defect 81 — Rust re-probed the whole name dictionary on every insert: 789 → 93 794 docs/s

`Collection::persist_dict`, called from every `insert`:

```rust
for (id, name) in self.dict.by_id.clone() {      // deep-copies every name
    let existing = e.get(self.dict_tree, &key)?; // one engine read PER NAME
    if existing.is_none() { e.put(..)?; }
}
```

So writing one 20-field document cost **one `Engine::get` per name in the
dictionary** — around 25 point reads whose answer, after the first document, was
always "already there" — plus a full deep copy of the dictionary. Two further
copies sat in `insert` and `get` (`by_name.clone()`, `by_id.clone()`), left over
from a borrow-checker workaround.

`05-catalog.md` §5.3 requires only that *new* entries are written in the same
commit as the document that first uses them. The type's own doc comment already
carried the property that makes a high-water mark exact: *"`name_id` is
allocated append-only and is **never reused**"*.

**Measured** (`ops_bench 20000`, medians of three, same machine, back to back):

| | before | after |
|---|---|---|
| `insert_docs_per_s` | 789 | **93 794** |
| `insert_bytes_device` | 9 917 043 | 9 917 043 |
| `write_amplification` | 0.775 | 0.775 |

**119×**, and `insert_bytes_device` is identical **to the byte** across all six
runs — which is the point. The removed work produced no output at all: it was
redundant reads and copies, not writing the engine had to do. A throughput
number that moves two orders of magnitude deserves a counter beside it saying
the result is unchanged, and this is that counter.

**Java was already correct**: `internNames` writes only names the dictionary
does not already hold. Fourth instance of the differential rule.

### The control, and why a high-water mark needs one

A high-water mark is right until a name is interned on a path that does not
advance it — and then a document is written referring to a `name_id` no reader
can resolve, which is silent and permanent. So the test
(`every_field_name_survives_a_reopen_after_incremental_interning`) writes 40
documents that each introduce a name the previous ones did not, closes, reopens
into a **fresh** `Database` that reloads the dictionary from tree bytes and
shares nothing with the writer, and reads every field name back. Advancing the
mark without writing fails it.

---

## Defect 82 — Dart's full-text index was frozen at the moment it was built

`Collection.put` maintained every `TreeKind.index` tree and no `postings` tree;
`_indexDocumentText` was called only from `createFullTextIndex`. So a full-text
index was correct exactly once and silently wrong from the next write on — in
**both** directions:

```
after build      : brown -> [id(1)]
after insert     : brown -> [id(1)]        <- id(2) contains "brown" and is invisible
after update     : brown -> [id(1)]        <- id(1) no longer contains "brown"
                 : grey  -> []             <- id(1) does contain "grey"
after remove     : brown -> [id(1)]
```

The middle line is the serious one: a search returning a document that does not
contain the word. `07-fulltext.md` §1 makes `df` and `ttf` accuracy a MUST, and
`11-conformance.md` §5 exists precisely so an index is never *silently* wrong —
its two permitted responses are to refuse the write or to repair-log it and mark
the index `stale_from`. Dart did neither, while **having** the feature.

**Fixed**: `_unindexDocumentText`, the mirror of the indexing pass, plus both
halves wired into `put` and `remove`. All four lines above are now correct, and
four tests in `fulltext_test.dart` hold them there.

**Java has always maintained its text indexes** in `put` and `remove`
(`for (FullTextIndex index : textIndexes()) index.put(id, doc);`). Rust has no
Collection-level full-text API at all, which is a gap rather than a defect —
nothing there can go silently stale because nothing there indexes for you.

### The test that existed, and what it was working around

`fulltext_test.dart` already had "an update rewrites the block, and df follows".
It passed. It passed by **building a second index after the update** and querying
that:

```dart
c.put(const CNitriteId(2), CDoc({'body': const CStr('the lazy grey dog')}));
c.createFullTextIndex(['body'], indexName: 'fts:rebuilt');   // <- rebuild
expect(c.termEntry(rebuilt, 'brown')!.df, 1);
```

A test that rebuilds the index before asserting on it cannot observe that writes
do not maintain it. The workaround was in the test, so the test was green and the
behaviour was wrong.

---

## A benchmark that measured nothing, caught before it was believed

The first attempt at measuring defect 81's Dart sibling — `_internTerm`
allocating a `term_id` as `_e.scanTree(revId).length + 1`, a full scan of the
reverse term index **per new term**, where Java holds a `nextTermId` counter —
produced this:

| terms | before | after |
|---|---|---|
| 500 | 64.4 ms | 64.0 ms |
| 1000 | 58.1 | 57.9 |
| 2000 | 107.7 | 106.7 |
| 4000 | 279.0 | 275.0 |

Identical within noise, which read as "the fix does nothing". Adding a counter to
the function said why: **`intern=0`**. The benchmark inserted documents into a
collection whose full-text index had already been created, and — defect 82 —
`put` did not maintain it, so `_internTerm` was never called. The benchmark
measured the absence of the bug it was written to measure.

The counter is the whole lesson, and it is this project's own: a benchmark that
shows no change is indistinguishable from a benchmark that runs no code, and only
an execution count tells them apart. The `term_id` fix stands on the structural
argument — O(V) per new term against O(1), and Java's counter as the third
opinion — and is honestly labelled as unmeasured rather than propped up by a
table that would have looked like evidence.

---

## Defect 83 — Dart's memtable could not be looked up, so every read walked all of it

```dart
final Map<Uint8List, _Pending> _memtable = {};
```

Dart gives `Uint8List` **identity** equality. A key rebuilt from the same bytes
is a *different* key, so this map can never be looked up by content — and
`_memtableLookup` did the only thing left: iterated **every pending entry**,
comparing the prefix byte by byte, on every point read.

Rust range-seeks an ordered map and breaks when the prefix stops matching
(`shard.range(prefix.to_vec()..)`); Java uses a `ConcurrentSkipListMap`. Dart
alone was O(pending writes) per `get`, against a default memtable of **20 000**
entries.

**Fixed** with a `SplayTreeMap<Uint8List, _Pending>(compareKeys)` — `dart:collection`,
no new dependency. Every internal key for one user key is `prefix || u64 ~seq ||
u8 op`, so they form one contiguous run: seek to its start, stop at its end. It
also makes `_memtable[k]` work by content (the identity map was a live footgun
for any future caller) and makes two `..sort(compareKeys)` calls redundant,
because `keys` now arrives in that order.

**Measured** (`bench/memtable_read.dart`, 20 000 reads per row):

| pending writes | linear scan | ordered | speedup |
|---|---|---|---|
| 250 | 4.98 µs | 2.18 µs | 2.3× |
| 500 | 7.42 | 0.86 | 8.6× |
| 1000 | 14.38 | 0.83 | 17.3× |
| 2000 | 27.62 | 0.81 | **34×** |

The **shape** is the result, not the last number: the control's `vs previous`
column reads **1.49×, 1.94×, 1.92×** — doubling per doubling, exactly linear —
against **0.96×, 0.98×** for the ordered map. At the default 20 000-entry
memtable the linear line extrapolates to ~276 µs per read.

### The benchmark that said there was no win

The first measurement used `reference/bench`'s `ops.dart` and reported **no
improvement at all** (6412 against 6698 docs/s inserted; p50 identical at 11 µs).
Taken at face value that is a clear "revert this".

It is instead the benchmark answering a different question. `bench/README.md`
says so in its own rules: *"Measure after a compaction, never before. A benchmark
that reads what it just wrote measures the memtable."* That is the right rule for
what `ops.dart` exists to measure, and it makes `ops.dart` **structurally
incapable** of seeing this change — by the time it reads, there is nothing
pending.

Second time in this session that a fixed-shape benchmark was the wrong
instrument, after defect 76's filter cache showing 5 % at 20 000 documents and
2 488× at 500 000 keys. The rule that keeps falling out: **when a change is
O(some dimension), the benchmark has to move along that dimension** — and if the
existing suite holds that dimension fixed by design, it will report zero with
complete confidence.

---

## Defect 84 — Dart derived the next `term_id` by scanning the whole term index

```dart
final next = _e.scanTree(revId).length + 1;   // per NEW TERM
```

`07-fulltext.md` §1: *"`term_id` is allocated append-only and never reused (same
discipline as `name_id`)."* Append-only and never reused is exactly what makes a
**held** counter correct, and Java has always held one (`nextTermId++`,
recovered once at load). Dart re-derived it with a full scan of the reverse term
index for every new term, so building a vocabulary of V terms cost O(V²).

**Fixed** with a per-tree counter, recovered once by a single scan on the first
new term after open.

**Measured** (`bench/term_intern.dart`, one new term per document):

| terms | derived | held | speedup |
|---|---|---|---|
| 500 | 207.1 ms | 155.3 ms | 1.33× |
| 1000 | 362.7 | 194.3 | 1.87× |
| 2000 | 1258.3 | 539.5 | 2.33× |
| 4000 | 4858.7 | 1956.5 | **2.48×** |

A speedup that *grows* with V is the signature of removing an O(V) term. The
residual growth in the fixed column was defect 83 — the memtable — which this
benchmark also exercises.

This is the same shape as defect 61, where `14-security.md` §4.1's nonce floor
was derived (`next_nonce - GAP`) rather than held. **"Derived instead of held"
is now a named recurring defect in this project**, and the tell is always the
same: a monotone counter recomputed from the data it counts.

---

## The differential audit's record, across both parts

| defect | rule or path | Dart | Java | Rust |
|---|---|---|---|---|
| 71 | filter `block_count` / `probes` bounded | yes | yes | **no** |
| 77 | internal key ≥ 13 bytes before indexing | yes | yes | **no** |
| 76 | parsed filter cached per segment | yes | yes | **no** |
| 80 | §4's four MAP invariants | yes | yes | **no** |
| 81 | dictionary persisted incrementally | n/a | yes | **no** |
| 82 | full-text index maintained on write | **no** | yes | n/a |
| 83 | memtable ordered and seekable | **no** | yes | yes |
| 84 | `term_id` counter held, not derived | **no** | yes | n/a |
| 79 | §8 sorts MAP entries | **no** | **no** | **no** |

Two things this table says that the individual entries do not.

**The audit works, and it is cheap.** Eight of nine rows were found by asking one
question per rule — *which of the three does the most here?* — and reading the
two that did less. It costs a `grep` and it does not need a failing test to start
from.

**And it has one blind spot, which row 79 is.** All three implementations agreed,
exactly, on a 90 × 90 comparison matrix while all three violated §8 rule 8.
Agreement is not conformance. The differential audit finds where implementations
*disagree*; only reading the spec finds where they are wrong *together* — which
is why the new order vectors carry 281 rules citing §8 by number, and not just
the matrix the three of them happen to produce.

---

# Part 3 — the chapters with no vectors

Twelve vector groups existed. Cross-referencing them against the chapters showed
`08-spatial.md` and `09-vector.md` had **none** — the same structural gap
`02 §8` was in, and for the same reason: their contracts are consumed in memory,
so three implementations can disagree completely and every direction of the file
gate still passes.

Both turned out to contain a **spec** gap, not just implementation drift.

## Defect 85 — §4 said "exact containment" and three implementations read it three ways

`08 §4` specifies the two-phase rule and then defines the predicates as "exact
WKB predicate", "exact containment", "exact predicate" — and stops. Over an
18-geometry corpus the three reference implementations **disagreed on 32 of the
pairwise predicates**, each internally consistent, each wrong in a different way:

| what | Rust | Dart | Java |
|---|---|---|---|
| outer holds no polygon → **envelope** containment | 1 | 0 | 0 |
| `contains(A, A)` for a non-polygon A | 1 | **0** | 1 |
| inner shares a boundary edge with outer | 1 | 1 | **0** |

The first is a §4 violation on its own terms. Rust's `within` did

```rust
if polys.is_empty() {
    return outer.envelope().contains(&inner.envelope(), 2);
}
```

so `within(POINT(5 5), MULTIPOINT(1 1, 9 9))` answered **true** — (5,5) is
inside that multipoint's bounding box. §4 says "An implementation MUST NOT
return box-level results as if they were exact", and this is that rule broken by
the *second* phase rather than the first, which is why nothing about the R-tree
could catch it.

The other two are not violations of anything, because there was nothing to
violate. §4's closing sentence — *"This is the difference between Nitrite's
spatial queries meaning the same thing in Java and in Rust"* — was false in 32
places.

### The spec change: §4.1, "What exact means"

Every geometry is the **closed** set of points it occupies. Then:

| predicate | definition |
|---|---|
| `intersects(A, B)` | `A ∩ B ≠ ∅` |
| `within(A, B)` | every point of A is a point of B |
| `contains(A, B)` | `within(B, A)` |

with four consequences stated because an implementation got each wrong:
the predicates are **reflexive**; **sharing a boundary does not disqualify**; a
geometry with no area **contains only its own points** (never its bounding box);
and an **empty geometry** intersects, contains and is within nothing.

This is OGC's `covers`/`coveredBy` rather than `contains`/`within`. The
difference is OGC's extra "the interiors must intersect" clause, which makes
`within` non-reflexive for a geometry with empty interior and excludes a
linestring lying along a polygon's edge — both surprising in a database query.
The spec says so and says why.

**Implemented in all three**, and the three now agree on all 972 pairs. Rust lost
the envelope fallback for a point-set membership test; Dart's `contains` moved
from "is each part of B covered by some one part of A" (which had no case for
line-in-line at all) to point-set membership against the whole of A; Java
replaced a `pathsProperlyCross` boundary test with the same midpoint rule the
other two use, so all three are now conservative in the *same* way rather than
in three ways.

## Defect 86 — Java accepted trailing bytes after a complete WKB geometry

Found by the same corpus's reject list. Rust and Dart both refuse it; Java
decoded the geometry and ignored whatever followed, so two different byte strings
decoded to the same geometry and anything appended to a stored WKB value rode
along unnoticed. A length that is not consumed exactly is corruption.

## Defect 87 — `09` named three metrics and defined none of them

`09 §5`'s descriptor carries `"metric": "cosine" | "l2" | "dot"`. §8 requires
results "ordered nearest first" with "the true distances". Nothing anywhere said
what the three compute — and **a dot product is a similarity**, so an
implementation returning it unchanged sorts every result set backwards while
satisfying every other sentence in the chapter.

The three implementations happened to agree (`-Σaᵢbᵢ`, `1 − cos`, Euclidean not
squared, `1.0` for a zero vector). A fourth SDK had no written rule to agree
with, and the sign convention is a coin flip.

**The spec change: §8.1**, pinning all three as distances, the zero-vector case
as `1.0` rather than a NaN, and — the part that was a real divergence —
**accumulation in at least 64-bit floating point**. Rust summed `f32` products
in `f32`; Dart and Java both used `f64`. Over 1024 dimensions that is a **3e-4**
difference in the answer, so the same query against the same region returned
different distances in Rust and ordered near-ties differently.

**Fixed in Rust** (`distance_f64`, with `distance` narrowing only on the way
out), and pinned by `conformance/vectors/vector/metrics.json` — 10 cases with a
`1e-9` tolerance, including a `wide_1024` case that exists solely to fail an
`f32` accumulation. It does: reverting the fix reports `want -2214.3861759752012,
got -2214.386474609375`.

## What the two new vector groups are, and what they deliberately are not

`08 §2.3` and `09 §8` both refuse to specify the thing an obvious conformance
test would compare:

> §2.3: "two implementations inserting the same documents will produce different
> (equally valid) trees. A conformance test therefore compares **query
> results**, never tree shape."
>
> §8: "**Recall is not specified.** Two conforming implementations may return
> different neighbours for the same query."

So neither vector group contains a tree, a graph, or a neighbour list. They
contain the parts that *are* determined: for `08`, envelopes, the reject list and
the full pairwise predicate matrices; for `09`, the metric arithmetic. Where a
chapter declines to specify something, the vectors have to decline too — the
alternative is a conformance suite that fails a conforming implementation.

---

# Part 4 — `03`, `05`, `06`, `10`, `13`

The remaining chapters, audited the same way. Most of what the differential
found here was **already right**, and that is worth recording as precisely as the
defects, because "we checked and it holds" is the other half of a compliance
claim.

## What held

- **`03` key encoding, `05` catalog, `06` indexes** already have shared vector
  groups (`cke/values.json`, `numbers/torture.json`, `strings/cases.json`,
  `catalog/trees.json`, `index/entries.json`, `index/layout.json`) and all three
  implementations consume them. These were the chapters least likely to drift and
  they had not.
- **`08 §1`'s EWKB rejection** — all three reject a type word with any of
  `0x80000000`, `0x40000000`, `0x20000000` set, each with the reasoning written
  out. **`08 §1`'s both-byte-orders rule** and **`08 §3`'s page-versus-descriptor
  `dimensions` check** are likewise in all three.
- **`10 §7`'s durability rule**, which the chapter itself flags as "the
  load-bearing one, because the failure is silent". All three record what they
  **performed**: Java derives it from what `sync()` did, Dart records `sync`
  because it writes with `flush: true` and says so, and Rust returns `Full` only
  on Darwin — matching §7's own platform table, where `F_FULLFSYNC` exists and
  Linux and Windows coincide with `sync`. This is the rule most likely to be
  quietly wrong in a storage engine and none of the three got it wrong.
- **`13 §6`'s 26 required metrics** are present, by name, in all three.

## Defect 88 — two of those 26 metrics were fabricated in Rust

Presence is not the rule. §6's second paragraph is:

> "A metric an implementation cannot compute MUST be reported as unavailable, by
> name, and MUST NOT be given a plausible-looking value. A fabricated answer
> defeats this section more thoroughly than a missing one, because a caller
> cannot tell the two apart."

Auditing each counter for a **mutation site** rather than a declaration found
`stall_events` and `stall_total_ms` reported as `Count(self.counters.stall_events)`
against a counter **nothing anywhere increments**. They read **0**, and zero
stalls is the most plausible-looking value in the whole table.

Underneath it, two more of this project's signature shape: `StoreEvent::Backpressure`
is declared and **never constructed**, and the delay `Backpressure::compute`
derives is reported to callers and **never applied**. Java increments a real
`stallEvents` in its committer; Dart reports `stallViolations.length`.

`pinned_by_checkpoints` was the same — a counter with no writer, reported as 0 —
and §6 names that exact metric as one whose obvious derivation "reads **0** on a
database holding a large pinned set".

**Fixed**: the two stall metrics now report `Metric::Unavailable` with a reason,
which is what §6 prescribes and what the variant already existed for; and
`pinned_by_checkpoints` makes the same coarse attribution Dart and Java both make.

### The test that existed, and the one that was missing

`operations_test.rs` already asserted all 26 names are present. It passed
throughout. A name-presence check cannot see a fabricated value — which is the
failure §6 is written about — so the new test asserts the *kind*: these two are
`Unavailable`, with a reason. It fails in both directions: if the stall path is
implemented and the metric is not updated, and — the case that matters — if
someone "fixes" the metric by handing it a zero. It carries a control of its own,
that a computable metric is still reported as a count, so it cannot be satisfied
by marking everything unavailable.

---

# The audit, complete

| defect | rule or path | Dart | Java | Rust |
|---|---|---|---|---|
| 71 | filter `block_count` / `probes` bounded | yes | yes | **no** |
| 76 | parsed filter cached per segment | yes | yes | **no** |
| 77 | internal key ≥ 13 bytes before indexing | yes | yes | **no** |
| 80 | `02 §4`'s four MAP invariants | yes | yes | **no** |
| 81 | dictionary persisted incrementally | n/a | yes | **no** |
| 82 | full-text index maintained on write | **no** | yes | n/a |
| 83 | memtable ordered and seekable | **no** | yes | yes |
| 84 | `term_id` counter held, not derived | **no** | yes | n/a |
| 86 | WKB trailing bytes refused | yes | **no** | yes |
| 88 | `13 §6` metrics not fabricated | yes | yes | **no** |
| 79 | `02 §8` sorts MAP entries | **no** | **no** | **no** |
| 85 | `08 §4` predicate semantics | **no** | **no** | **no** |
| 87 | `09 §8` metric definitions | — | — | — |

**Java was wrong once, in thirteen rows.** It is the implementation to diff
against, and that is not a coincidence: it was written third, against vectors the
other two had already been made to fail.

**The last three rows are the audit's blind spot, and they are the reason the
spec changed.** In 79 and 85 all three implementations were wrong *together* —
and in 85 they were wrong in three different directions while each was internally
consistent, agreeing on nothing and disagreeing on 32 predicates. In 87 all three
happened to agree on a convention no sentence anywhere required. A differential
audit finds disagreement; only reading the spec finds shared error, and only
writing the spec down prevents the fourth SDK from picking the other convention.

That is why each of the three new vector groups carries **named rules citing the
spec by section number** alongside its matrix — 281 for `02 §8`, 17 for `08 §4.1`,
10 metric cases for `09 §8.1`. The matrix proves the implementations agree. The
rules prove they agree with the spec. Only the second one is conformance.

## Spec changes made

Three, all portable and all implemented in all three languages:

1. **`02 §8`** — clarified that `MAP`'s sorted comparison is by (key, then
   value), the tie-break §4 leaves open (duplicate keys being corruption there).
2. **`08 §4.1`, "What exact means"** — the predicates as point sets, with the
   four consequences that had diverged, and the reason for choosing OGC's
   `covers`/`coveredBy` over `contains`/`within`.
3. **`09 §8.1`, "The metrics, numerically"** — the three metrics as distances,
   the zero-vector case as `1.0`, and 64-bit accumulation.

`cryptand/spec/` is the normative source; `nitrite-doc/cryptand/spec/` holds a
copy, **re-synced** — see below.

## The doc re-sync, and the drift it exposed

`nitrite-doc/cryptand/` carries a copy of the spec and the design docs, each
prefixed with four lines of retype frontmatter and otherwise byte-identical to
the normative source. Re-syncing the three changes above meant diffing all
eighteen copied documents, and **six chapters plus one design doc were already
behind** — not from this session:

| document | what the copy was missing |
|---|---|
| `01-container.md` | the superseded `page_codec` text, still describing LZ4 as a default that saves space |
| `02-value-encoding.md` | §8 rule 10's `MAP`/`DOC` rank table |
| `11`, `12` | a profile row for `page_codec` that no longer exists, and a trailing line |
| `design/tradeoff-analysis.md` | **318 lines**, including a whole `§8.16` from an earlier phase |

Every difference was the copy being *behind*; nothing had been edited on the doc
side, so nothing was lost. But a documentation copy that drifts silently is the
same failure this whole audit is about — a second source of truth nobody
compares. The check is four lines of Python and should run in CI:

```python
body_after_frontmatter(doc_copy) == normative_source
```

### One defect the re-sync found

`retype build` reported an unresolved URL at `tradeoff-analysis.md:1419`:

```
[[cryptand-gc-visibility-defect]]
```

A **wiki-link to a private memory file** had leaked into a published normative
document in an earlier session — retype parses `[[…]]` as a link and could not
resolve it. It is now prose that stands on its own ("the value-log GC visibility
failure — a live record collected because the watermark it is judged against
never moved (defect 34 in §7's table)"), and a scan confirms it was the only one
in `spec/` or `design/`.

`retype build`: **117 pages, 0 errors, 0 warnings** — the recorded baseline.

---

# The CRUD-under-load pass — findings 78–84

A second pass, driven by a question the existing benchmarks could not be asked:
**what does each implementation cost per operation under a sustained mixed
workload?** `reference/bench/ops.*` measures a bulk insert, a point read, a scan
and an index lookup — **C** and **R**, each in isolation, each against a freshly
compacted and otherwise idle database. There was no **U**, no **D**, and no
phase in which maintenance was running.

Baseline before this pass, all green: **Rust 307, Dart 651, Java 317.**
After: **Rust 311, Dart 652, Java 318**, and the corpus is byte-identical after
a run of all three in parallel, which it was not before.

The new matrix is `reference/rust/cryptand/benches/crud.rs`,
`reference/dart/cryptand/bench/crud.dart` and
`org.dizitart.cryptand.bench.CrudBench`. Every defect below was found by one of
its **counters**, not by a wall-clock row — which is `design/performance-model.md`
§8's rule earning its keep for the eighth time.

---

## Defect 78 — Dart reports the one value `13-operations.md` §6 forbids by name

§6 is unusually specific:

> "A metric an implementation cannot compute MUST be reported as unavailable, by
> name, and MUST NOT be given a plausible-looking value. A fabricated answer
> defeats this section more thoroughly than a missing one, because a caller
> cannot tell the two apart: **`page_cache_hit_rate: 1.0` from an engine with no
> page-cache accounting reads exactly like a perfect cache.**"

A fresh Dart engine returned exactly that:

```
page_cache_hit_rate = 1.0
isAvailable = true
```

from `accesses == 0 ? 1 : (accesses - misses) / accesses`. Rust returns
`Metric::Unavailable` for the same state and Java declares it unconditionally,
so Dart was alone.

**Fixed**: the empty case joins the `unavailable` list, beside the
`unencrypted_pages` case directly below it that was already reasoned through
correctly.

### Why nothing saw it

The mechanism, the doc comment and the test were all present — and all aimed one
inch to the left of the defect:

- `metrics.dart` carries an `unavailable` list, and its doc comment names this
  defect: *"An earlier version of this file returned `page_cache_hit_rate: 1.0`
  and `unencrypted_pages: 0` from an engine that measured neither."* The fix was
  applied to `unencrypted_pages` and to the prose. Not to the rate.
- `operations_test.dart` has a test named *"a metric this engine cannot compute
  is declared, not faked"*. It asserts on `unencrypted_pages`.
- It has a second test, *"page_cache_hit_rate is measured from the segment
  counters"*, which puts 500 documents in first. It exercises `accesses > 0` and
  only that.

**Nothing asked a fresh engine what its hit rate was**, which is the one state
where the answer is 0/0.

---

## Defect 79 — `12-profiles.md` §1's page cache budget was honoured by none of the three

The profile table gives a **page cache budget** — 4 / 16 / 64 / 512 MiB — and
`design/performance-model.md` P7 predicts resident set bounded by it.

| | before |
|---|---|
| Rust | a segment cache with **no eviction at all**; `page_cache_bytes` was declared in `profile.rs` and read by nothing in the crate |
| Java | **no page cache of any kind**; `readRaw` was a `readFully` every time, and `Profile` did not carry the constant |
| Dart | every segment extent resident, by construction |

Measured on Rust, `mobile`, 400-byte payloads:

| documents | resident | segments | × the 4 MiB budget |
|---|---|---|---|
| 60 000 | 28.0 MB | 30 | 6.7× |
| 150 000 | 70.0 MB | 75 | **16.7×** |

2.5× the data, 2.5× the resident set: it was not oversized, it was **unbounded**.
On `mobile` — the profile whose whole purpose is a phone's memory ceiling.

**Fixed in Rust** (`Engine::admit`, an LRU bounded by `page_cache_bytes`): the
same 150 000-document workload now holds **3.74 MB, 0.89× the budget**, an
18.7× reduction, with every document still read and no change in wall time.
Eviction is safe because every segment is written through the pager *before* it
is cached, so a miss is always re-readable.

**Fixed in Java** by adding the cache (see defect 84 for what that exposed).

**Not fixed in Dart**, and declared rather than quietly left: Dart's segment
extents never enter the `PageStore` at all — a limit `REPORT.md` already
recorded — so there is nothing to evict *to*. A budget is enforceable only if a
miss has somewhere to read from. `REPORT.md` now ties the two together instead
of stating them as separate facts.

---

## Defect 80 — every Rust point read re-walked the manifest, once per level

`candidates_for` loops `0..=last_level()` calling `refs_at`, and `refs_at` did a
**B-tree scan of tree 6 through the pager** on every call. `range_deletes_for`,
which a point read also calls, did a whole-manifest scan on top of that.

Per point read, measured at 20 000 documents with the segment cache warm:

| profile | before | after | what the remainder is |
|---|---|---|---|
| `desktop` | 6.000 pages | **1.000** | the value-log read it actually wanted |
| `mobile` | 5.000 pages | **0.000** | the value is inline; nothing is left to read |

The `mobile` row is the one that matters. `12-profiles.md` §2.1 justifies
`vlog_min = 1024` — the profile's defining choice — on the grounds that
"a point read costs **one** I/O rather than two". It was costing five, and none
of them were the document.

**Fixed**: tree 6's decoded levels are cached, keyed on a `(epoch, root)` stamp.
The epoch is drawn from a process-global counter by `Manifest::new`, `add` and
`remove` — global rather than per-instance because a manifest is also *replaced
whole* by repair and by checkpoint restore, and a per-instance counter restarts
at 0, which is a value a cache may already hold. Both of those paths served a
stale manifest until the counter became global, and **the engine's own
operations test caught both**; the root half of the stamp closes
`checkpoint.rs`'s direct `manifest.tree.root = …`, which edits tree 6 without
passing through either mutator.

Effect on the matrix (`desktop`, 20 000 documents, 20 000 mixed ops):

| row | before | after |
|---|---|---|
| `read_ops_per_s` | 8 916 | **187 196** (21×) |
| `read_us_p50` | 109 µs | **4 µs** |
| `mixed_ops_per_s` | 10 925 | **163 477** (15×) |

---

## Defect 81 — a range-delete lookup scanned the whole memtable on every read, and no test covered the path at all

`range_deletes_for` iterates **every entry of every memtable shard** parsing
internal keys, on every point read, to find range deletes — of which there are
almost always none.

**Fixed** by counting range deletes at `insert_mem`, the single point every
memtable write passes through, and skipping the scan when the count is zero.
Skipped, not sampled: zero is a proof, not a heuristic.

### Why nothing saw it — and the control that said so

Disabling the memtable half of `range_deletes_for` **outright**, so a range
delete in the memtable could never be found:

```
CONTROL PASSED: 308 FAILED: 0
```

The whole suite passed with the path dead. `range_delete_is_one_write_and_hides_the_interval`
flushes immediately after `remove_range`, so its range delete is always resolved
out of a *segment*; the memtable half had never been exercised by anything.

`a_range_delete_still_in_the_memtable_hides_the_interval` now covers it, and
fails on the first assertion with the path disabled.

---

## Defect 82 — all three implementations wrote to the shared conformance corpus while reading it

`11-conformance.md` §6: *"Conformance is defined as passing the vectors, not as
matching the reference implementation's source."* A runner that writes to the
vectors moves the target on every run.

All three did, by two different mechanisms:

| | files changed | mechanism |
|---|---|---|
| Java | **12 of 18** | `Database.open` records the writer id when the handle is writable (`05-catalog.md` §7) — superblock `commit_id` advanced, a page appended |
| Rust | 4 | opening an encrypted database publishes a nonce floor (`14-security.md` §4.1) with a synchronous superblock write |
| Dart | 4 | the same nonce floor |

The corrupt and security fixtures were among them in every case, which is the
part worth stating plainly: **each implementation wrote to files it was about to
reject as corrupt or tampered.** §4.1 requires a floor before nonces are
*allocated*; a handle that writes nothing allocates none.

It also broke parallel runs. The very first act of this session — running the
three suites at once — produced three Rust conformance failures reading
`locked by another process … open for writing by another process`, because Java
held write locks on files it was only reading.

**Fixed** in all three: the corpus runners open read-only. Each now carries a
`reading the corpus does not modify it` test that digests every file before and
after, and each control fails, naming the files.

The Rust control incidentally shows how thin the previous margin was:
`v1.0-corrupt-crc.cryptand` used to be reported as *"refused as corruption"* and
is now *"opened, 1 finding from verify"*. Both satisfy the manifest, but the
earlier refusal came from the reader's own **write** hitting the bad page — the
corruption was being detected as a side effect of an operation that should never
have happened.

---

## Defect 83 — Rust had no read-only mode, and read-only handles took the exclusive writer lock

`11-conformance.md` §3's reader matrix requires read-only opening outright:
`write_version_minor > supported` → *"open **read-only**"*. `Engine` had no such
mode, so that row was unimplementable.

Adding it surfaced a second half. `Engine::open_read_only` still took
`Pager::open`'s **exclusive writer lock**, so two readers of one file refused
each other — `01-container.md` §10 is "one writing *process* per database", and
a handle that cannot write is not a writer. `13-operations.md` §8's coordinating
readers depend on several holding the file at once. This is the same lock that
made the parallel suite run fail in defect 82.

**Fixed**: `open_read_only` skips the open-time writes and uses
`Pager::open_shared`. Writes are refused at `Engine::arm` **and** at
`Engine::write` — two checks because they are not the same set:
`put_with_expiry` arms and `put` does not, so `arm` alone let a read-only handle
accept a `put`. It would never have reached the device, but it would have been
visible to that handle's own `get` — a read-only view returning data that is not
in the file.

`a_read_only_handle_writes_nothing_at_open_and_refuses_writes_after` asserts both
halves, because either alone is satisfiable by accident.

---

## Defect 84 — eight call sites write to the device around the pager, which only a page cache could reveal

Adding Java's page cache (defect 79) broke **19 tests** with findings like:

```
CORRUPTION: segment 19's subtree_entries sum to 11, its header declares 8
InvalidArgumentException: segment input is not strictly increasing
```

Written correctly, read stale. `SegmentBuilder`, `Vlog`, `Blob` and
`VectorRegion` write whole extents in one I/O through `pager.file().write(…)`,
reaching past `Pager.writePage` — so a page freed, reallocated and rewritten
through one of those left the old bytes cached.

Harmless for as long as there was no cache, which is exactly why it survived:
**the bypass was invisible until something depended on the pager seeing every
write.**

**Fixed**: `Pager.writeAt(offset, bytes)` writes and invalidates every page the
write covers, and all eight sites use it. The two superblock slots are never
cached at all — `Engine` writes them straight to the `PageFile` on every commit,
so excluding pages 0 and 1 costs two pages of caching and removes an invariant
that would otherwise have to be remembered in a file where the cache is not
visible.

Effect on Java's counters, at 20 000 documents:

| counter | before | after |
|---|---|---|
| `read_page_reads_per_op` | 227.9 | **1.049** |
| `update_page_reads_per_op` | 715.8 | **0.020** |
| `delete_page_reads_per_op` | 808.3 | **1.107** |
| `mixed_page_reads_per_op` | 334.5 | **0.605** |

---

## One finding measured and left open

Java's `*_us_p999` is **136–423 ms** for every operation, against `desktop`'s
`max_foreground_stall_ms` of **25** and `13-operations.md` §5's "none may block
longer than `max_foreground_stall_ms` per step". `MAX_DELAY_MS` caps a single
backpressure delay at 100 ms, so an operation waiting 423 ms is waiting on
something that is not backpressure — most likely contention with the background
compactor.

It is recorded here rather than fixed, and the `*_us_p999` rows exist in the
matrix so it stays visible. The p50 and p99 hide it completely: Java's read p50
is 7 µs, better than Dart's 12 µs.

---

# The Java stall pass — defects 85–87, and two reverted fixes

Java's p99.9 was **136–423 ms on every operation** against `desktop`'s
`max_foreground_stall_ms` of **25**, while its p50 sat at 7–27 µs. The engine was
fast and almost never running.

It was root-caused by sampling rather than reading: 25 `jstack` samples of the
main thread during the CRUD matrix, then 40 more after each change. That is the
whole method, and it named the holder every time.

---

## Defect 85 — every insert read the catalog under the global structure lock

24 of the first 25 samples had the main thread parked on
`Engine.lockStructure`, all from one path:

```
Engine.lockStructure  <-  Database.catalog  <-  Collection.indexes  <-  Collection.stage
```

`Collection.stage` asks for the collection's indexes on **every document
written**, and `Database.catalog` answered by decoding the whole catalog — a CKE
key and a `TreeDescriptor` per entry, into a fresh map — while holding
`structure`, the lock the committer and the compactor hold for the whole of
their critical sections. So every insert queued behind whatever maintenance was
running.

**Fixed**: the decoded catalog is cached against a new `PageTree.version()`,
bumped by `put` and `remove` — the only two ways to change a tree's content, so
bumping there is exhaustive. The version is `volatile`, so the hot path reads
one field and returns; the map is immutable and published through a `volatile`
reference, so a reader that finds a current one takes no lock at all.

Delete went from 650 to 3 642 ops/s and its p99.9 from **422 632 µs to 291 µs**.

---

## Defect 86 — the exact liveness scan ran on every maintenance tick, before deciding whether it was needed

With the catalog fixed, the samples moved to `Vlog.append` **`BLOCKED` on the
value-log monitor**, held by the compactor inside `Vlog.recomputeLiveness`.

`recomputeLiveness` reads **every record of every value-log segment**, and it is
`synchronized` on the object every append needs. Worse, `collectIfNeeded0`
called it *unconditionally and first*, before computing the debt and space
triggers that decide whether collection is wanted at all. Every maintenance tick
paid for a whole-database walk.

**Fixed**, in the direction §6.7 allows. Between scans `Vlog.publish` maintains
`live_bytes` incrementally and only ever raises it for an append, so stale
statistics **overstate** liveness — which `04-segments.md` §6.7 explicitly
permits ("may overstate liveness and must never understate"). The cost of
overstating is a collection deferred, not a record lost. The scan now runs on a
byte budget — a quarter of a value-log segment of growth forces the next one, so
collection still makes progress. `11-conformance.md` §1.3 puts the GC victim
policy on the implementation's side of the line.

## Defect 87 — the walk did two syscalls per record

`Vlog.walk` framed each record with a 16-byte `readFully` and then read it with
a second one, inside that same monitor: ~40 000 syscalls under the lock at
20 000 documents. It now reads in 64 KiB windows.

---

## Two fixes built, measured, and reverted

Both removed the stall. Both bought it back with a correctness violation that a
test caught, and neither shipped. They are recorded because the measurement is
the useful part, and because the next attempt should start from what they hit.

**Scanning without the monitor** — snapshot under the lock, scan outside it,
apply under it — measured **mixed 1 573 → 52 697 ops/s (33x)** and read p99.9
**147 574 µs → 91 µs**. It races: two appends completing out of order leave the
earlier reservation as a hole, `complete` advances the watermark only over a
contiguous prefix, and the later pointer is published past it. The compactor
found it:

```
value-log pointer to segment 1 ends at 4163294, past the durable watermark 4161273
```

**A byte-budgeted resumable sweep**, which is what `13-operations.md` §5 asks
for, *understated* liveness on a segment whose extent was not yet published when
its sweep began, and the verifier said so:

```
CORRUPTION: value-log segment 15 declares 0 live bytes but holds 212346;
liveness statistics MUST NOT understate
```

Understating is the direction that frees a segment still holding live data. A
correct incremental version needs a segment's true extent before its first
publish, and needs a partial count to leave the previous value standing rather
than replace it.

**A third change was reverted for being pointless rather than wrong**: moving
the value-log `pwrite` outside the monitor, which is literally what
`10-transactions.md` §2.2's reserve-then-`pwrite` asks for. It measured nothing
on this workload — the contended holder was the liveness scan, not the append —
and it introduced the watermark race above. The honest state is recorded in
`Vlog.append`'s comment: **this implementation serializes value-log appends,
which `11-conformance.md` §1.1 makes a Level 0 gap.**

---

## Where Java ended, and what is still open

At 20 000 documents, against the numbers at the start of the pass:

| | before | after |
|---|---|---|
| `delete_ops_per_s` | 650 | **5 731** (8.8x) |
| `delete_us_p999` | 422 632 | **335** (1 262x) |
| `update_ops_per_s` | 494 | **1 767** (3.6x) |
| `create_ops_per_s` | 2 017 | **4 617** (2.3x) |
| `read_ops_per_s` | 2 279 | **4 513** (2.0x) |
| `mixed_ops_per_s` | 1 394 | **3 206** (2.3x) |

**Delete's stall is fixed; create, read and update still show 60–172 ms at
p99.9.** The remaining holder is the same one: a single monitor on `Vlog` that
covers reads, appends and maintenance alike, so `Engine.resolveValue` contends
with `Vlog.append` contends with the compactor. Narrowing it is the fix, and the
two attempts above are the evidence for how carefully it has to be done.

Java is now ahead of Dart on p50 for every operation and behind it on
throughput, because throughput here is still a tail story.

## One open defect, pre-existing, not fixed

The CRUD matrix's mixed phase intermittently fails with

```
CorruptionException: value-log segment 5 has no entry in tree 7
```

A live pointer into a value-log segment whose tree-7 entry has been removed —
the collector freeing a segment something still references. It reproduced **on
unmodified sources** before any change in this pass, so it is not caused by the
work above; the frequency moved from roughly 2 in 5 runs to 1 in 30, which is
timing, not a fix. It is the same failure mode as the value-log GC visibility
defect this project has met before, and it is the most important thing left in
the Java implementation.


---

# The tree-7 collection race — defect 88, partly fixed

The open defect at the end of the previous section, chased with instrumentation
rather than reading:

```
CorruptionException: value-log segment 6 has no entry in tree 7
```

Two real causes were found and fixed. **A third remains**, and the rate went
from roughly **2 runs in 5** to **1 in 50** of the CRUD matrix's mixed phase —
which is a reduction, not a fix, and is recorded as such.

## Cause 1 — liveness was judged at `visible_seq`, which is not the set of seqs a reader can reach

`collectSegment`, `mergeColdRuns` and `refreshLiveness` all asked
`lookup(treeId, key, visibleSeq, now)` — "is this record the current entry?".
`visible_seq` is wrong in both directions:

- **Above it**: a batch written into the memtable whose `visible_seq` has not
  yet advanced is invisible to that lookup, so the record it points at reads as
  dead — while the entry pointing at it survives every compaction and becomes
  visible moments later. This one is intermittent by construction, because it
  depends on whether the committer has caught up.
- **Below it**: a live snapshot resolves to the newest version at *its* seq,
  which may be a superseded version whose value the current view no longer
  names.

**Fixed**: liveness is now judged at every seq a reader can still resolve —
`nextSeq` (everything written, visible or not) and each live snapshot's own seq.
The callback changed from "what pointer does this key have" to "is this exact
`(segment_id, offset)` referenced", because the answer is a disjunction over
that set and a single pointer cannot express it. Every seq added can only mark
*more* records live, which is the direction §6.7 allows.

## Cause 2 — the extent was freed before the commit carrying its pointer rewrites

`04-segments.md` §6.8's second invariant is explicit: "a segment's extent is not
freed until the pointer-rewrite commit is durable." Collection rewrote the
survivors, called `flushShards` and `makeVisible`, and then **immediately**
removed the tree-7 entry and freed the extent — with no superblock yet naming
the rewrites.

Two ways that loses:

- `makeVisible` cannot always deliver visibility. `visible_seq` advances only
  over a **contiguous** prefix of completed reservations (§2.3), so a foreground
  batch holding a lower seq range keeps the watermark below the rewrites. A
  rewrite that is not visible is one every reader resolves *past*, back to the
  old pointer, into the extent being freed.
- Even when visible, nothing had been published.

**Fixed**, and the fix is an ordering rather than a wait: a collected segment
goes into `pendingVlogRemoval`, and `retireCollectedSegments` releases its
tree-7 entry and extent only after `publishSuperblock`. A collection whose
rewrites are not yet visible is **deferred entirely** rather than waited on —
counted in `deferredCollections` — because waiting here would block the
compactor while it holds `structure`, which is the stall the rest of this pass
exists to remove. The cost is one deferred reclaim; the alternative is a lost
record.

## What is still there

At 1 in 50 runs, with both fixes in, the diagnostic reads:

```
retire visible=24657 next=24658 commit=38 liveBytes=161950 bytes=916350 sealed=true tier=1
```

Everything written is visible, the commit is published, and the collector's own
walk examined the whole segment — so the surviving cause is something that makes
a *currently referenced* record read as unreferenced during the walk. The two
candidates not yet eliminated are the promotion path in `compactLevel`, which
resolves value-log pointers for entries retained only by §5's condition 2, and
the `levels` snapshot a liveness lookup reads while the committer republishes it.

**No regression test ships for this.** One was written and deleted: it drove
collection against a concurrent writer for 40–110 s and passed with the fix
removed, so it did not exercise the defect. A control that cannot fail measures
nothing, and this project's own rule is that such a test is worse than none. The
only known reproducer is `CrudBench`'s mixed phase, run repeatedly at 1 000 and
5 000 documents.


---

# The watermark-hole protocol — and the 30x it unblocks

The previous section ended with two fast paths built and reverted, and Java at
2.3x Dart's distance in the wrong direction. This section builds the protocol
those two attempts were missing, lands both of them on it, and closes the
tree-7 race.

## What the hole is

`10-transactions.md` §2.3 makes the value log's `bytes` watermark advance only
over a **contiguous** prefix of completed reservations, because that is what a
recovering reader can trust: bytes past a gap were never necessarily written.

`04-segments.md` §6.2 asks appends to reserve a disjoint byte range with one
`fetch_add` and then `pwrite` into it, with no lock — and §2.2 makes that a MUST,
with `11-conformance.md` §1.1 adding that "an implementation that serializes
writers is **not** Level 0".

Put together, those two produce **holes**: writer B finishes while writer A's
earlier reservation is still in flight, so B's record is written, checksummed
and sitting *beyond* the contiguous watermark. Judging readability by the
watermark rejects B's own pointer, which is exactly how the first attempt failed:

```
value-log pointer to segment 1 ends at 4163294, past the durable watermark 4161273
```

**Recoverability and readability are not the same question**, and conflating
them is what made concurrent appends look impossible.

## The protocol

Three parts, all in `Vlog`:

1. **`Open.covers(offset, len)` — the read half.** A record is readable if the
   contiguous watermark covers it *or* if a completed-but-not-yet-folded range
   does. `Vlog.read` uses it for open segments. Recoverability still uses the
   watermark alone, which is what `publish` records, so nothing about the file
   changes.

2. **`drain(open)` before a seal — the publish half.** Once a segment stops
   being open, `completed` is gone and tree 7's `bytes` is the only thing a read
   can consult. Sealing with a hole open would leave every record past it
   permanently unreadable — written, checksummed and unreachable. So a seal
   waits for `watermark == tail` first. It is rare (once per
   `vlog_segment_bytes`) and a hole is one `pwrite` wide.

3. **`drain` waits, it does not spin.** It runs holding the monitor, and the
   appender it waits for needs that same monitor to fold its range in. A spin
   deadlocks the moment appends stop being serialized — which is the change the
   protocol exists to allow. `Object.wait` releases the monitor; `complete`
   signals.

With that in place, `Vlog.append` is `reserve` (monitor: segment choice,
`fetch_add`, nonce, bookkeeping) → **`pwrite` with no lock held** → `complete`
(monitor: fold and signal).

### It has a control, and the control fails

`VlogConcurrencyTest` runs 8 writers x 1 500 records and has each writer read its
own record back **immediately**, while the others still hold reservations —
which is the only way to reach the hole state deliberately. It asserts
`Vlog.HOLE_READS` actually moved, because a concurrency test that never produces
a hole has not tested the protocol whatever else it asserts.

Replacing `covers`'s hole branch with `return false` reproduces the original
failure on the first run:

```
value-log pointer to segment 1 ends at 13927, past the written extent
of the open segment (watermark 7474, tail 14849)
```

The test also isolates the value log from the **seq** watermark by reading at
`Long.MAX_VALUE`. That is not a dodge, and it surfaced a separate finding worth
recording: under concurrent writers a batch acknowledged at `os` durability is
**not** immediately visible to its own writer, because `visible_seq` is also a
contiguous prefix and another thread's in-flight range holds it back. §7's
"acknowledged" and §2.3's "contiguous" disagree here. It is pre-existing, it is
not what this section fixed, and it is the next thing to look at.

## The tree-7 race, closed

Defect 88's remaining third cause did not survive this work. With the two
ordering fixes of the previous section plus the protocol above, the CRUD
matrix's mixed phase ran **60 times at 1 000, 5 000 and 20 000 documents with
zero failures**, against roughly two runs in five when it was first found. The
12-direction cross-language round-trip gate — plaintext and encrypted, every
pairing of Rust, Dart and Java — passes six runs out of six.

## What it measures

At 20 000 documents, Java against where the previous section left it:

| | before | after |
|---|---|---|
| `mixed_ops_per_s` | 3 114 | **37 552** (12x) |
| `read_ops_per_s` | 5 184 | **71 593** (14x) |
| `create_ops_per_s` | 4 396 | **18 207** (4.1x) |
| `update_ops_per_s` | 1 616 | **7 508** (4.6x) |
| `read_us_p999` | 150 965 | **111** (1 360x) |
| `update_us_p999` | 175 680 | **1 532** (115x) |
| `create_us_p999` | 63 676 | **1 762** (36x) |

**Every p99.9 is now inside `desktop`'s `max_foreground_stall_ms` of 25**, which
`13-operations.md` §5 requires and which no Java operation met before.

And on the headline mixed workload Java now sits where it should:

```
rust 159 629   >   java 37 552   >   dart 16 420   ops/s
```

## What is still serialized

`reserve` holds the monitor for the `fetch_add`, the nonce allocation (§5.3
needs it) and the per-segment bookkeeping. Only the `pwrite` is outside. That is
the expensive part and it is where the win came from, but §2.2's "writers do not
contend even while sharing a segment" is not yet literally true, and this is
recorded as a remaining gap rather than claimed as met.


---

# The `os` visibility gap, and the read path — defects 89–92

## Defect 89 — an acknowledged write was not readable by its own writer

Found by the concurrency test built for the watermark-hole protocol, which
failed on a plain `get`:

```
id 4500 did not read back immediately after its own append
```

`10-transactions.md` §7 acknowledges an `os`-durability batch when
`commitBatch` returns. §2.3 makes `visible_seq` a **contiguous** prefix. Under
concurrent writers those disagree: a batch that has completed sits beyond the
prefix whenever another writer holds a lower range still in flight, so the
writer could not read back what it had just been told was written.

**Fixed with the same shape as the value log's `Open.covers`**, and for the same
reason — recoverability and readability are different questions. A live read
resolves at `readHorizon()` (everything handed out) and `isPublished(seq)`
filters what is still in flight: the contiguous prefix **plus** the completed
ranges. Batch atomicity survives because `completeRange` publishes a batch's
whole range at once, after every one of its entries is in the memtable, so an
admitted seq never belongs to a half-published batch.

Only the memtable needs the filter — a flush takes entries at or below
`completedThrough`, so anything in a segment was published before it got there.
Collection passes `requirePublished = false`, because an in-flight entry is a
live reference and filtering it out would free the record underneath it.

Reverting `get` to `visibleSeq` reproduces the failure on the first run.

## Defect 90 — the interruptible-compaction yield point yielded nothing

`SegmentBuilder` called `compactionStep()` every `compaction_step_bytes`, which
is exactly the granularity `12-profiles.md` gives for interruptible compaction.
The method was `Thread.onSpinWait()` — with `structure` still held. §5's
"publishing the manifest edit is the only place concurrent compactions
serialize, and it is microseconds" was not what the code did: a merge held the
lock from its first input page to its last output page, and 18 of 50 sampled
stacks had the main thread parked on it inside `Database.commit`.

It now releases and reacquires, but **only when a thread is actually waiting**
and **only at hold depth 1** — a single `unlock` of a reentrant lock held twice
releases nothing.

### The first version live-locked

Applying the same yield per **record** in the liveness and collection walks took
the test suite from four minutes to not finishing. Releasing and reacquiring a
contended lock on every record means maintenance loses it as fast as it takes
it. The yield is now on a 4 096-call interval. A yield point that yields too
often is not a slow path, it is a stall of a different shape.

## Defect 91 — every delete and update read and decoded a document to maintain indexes that did not exist

`Collection.remove` and `Collection.update` fetch the previous document, and it
is used for exactly one thing: retracting the index entries it produced —
`previous` appears only inside `stage`'s index loop. On a collection with no
index that is a value-log read and a full CVE decode per operation, spent on a
value immediately discarded.

**Fixed** with `indexed()`, cached on the identity of the catalog map so it
costs a reference comparison. `remove` falls back to `containsKey`, which
answers "does this key exist" without resolving the value, so the semantics are
unchanged: deleting an absent key is still a no-op rather than a tombstone.

| counter | before | after |
|---|---|---|
| `delete_page_reads_per_op` | 1.101 | **0.027** (Rust: 0.006) |

## Defect 92 — the page cache held raw pages, so every B+tree node was re-checksummed

A JFR profile put `Segment$Cursor.page` second only to `resolve`. Each visit to
a **cached** page cloned 8 KiB, ran CRC-32C over all of it, then decrypted,
decompressed and copied again — a checksum per node on bytes that had already
been verified and could not have changed, because every write invalidates.

The cache now holds **decoded payloads**, verified once at the miss that read
them. `Cursor.page` fell from 166 samples to 47.

Both caches share **one** budget, because `12-profiles.md` §1 states one:
sizing each to the full figure would hold twice what `mobile` says it holds,
which is the decoration that budget stopped being.

## Where Java ended

Medians of five runs at 20 000 documents, against the start of this pass:

| | before | after |
|---|---|---|
| `mixed_ops_per_s` | 38 549 | **60 113** |
| `read_ops_per_s` | 82 376 | **94 598** |
| `update_ops_per_s` | 10 541 | **15 173** |
| `delete_ops_per_s` | 5 249 | **15 274** |
| `create_ops_per_s` | 18 107 | **16 970** |

**Java is now ahead of Dart on every operation**, and on the counters — the
results `design/performance-model.md` §8 makes primary — it is at parity with
Rust: mixed `pages/op` 0.570 against 0.537, mixed read p50 6 µs against 5 µs.
Every p99.9 is inside `desktop`'s 25 ms budget.

The remaining throughput gap to Rust is 2.5x on the mixed workload and is
**not** a counter gap. Two things are in it, and only the first is a defect:

- Compaction is now roughly as expensive as the read path in the profile
  (`SegmentBuilder.add` and `BtreePage.encodeLeaves`, 85 samples each), and in
  Java it runs on a background thread **during** the measured phases.
- The isolated CREATE/READ/UPDATE/DELETE phases are not like-for-like across
  implementations: Rust's engine compacts only when the benchmark asks it to,
  so its isolated phases pay no concurrent maintenance at all, while Java's
  compactor runs throughout. The delete loop measured **0.035 s uncontended and
  0.68 s with the compactor active** in two runs of the same binary. The
  **mixed** phase is the fair comparison, because all three drive maintenance
  through it.


---

# Making compaction cheaper — defects 93–95

The previous section closed with the remaining gap attributed to compaction:
`SegmentBuilder.add` and `BtreePage.encodeLeaves` at 85 JFR samples each, with
compaction running on a background thread during the measured phases. This
section attacks that, and every finding came from profiling the **compactor
thread by name** rather than the process.

## Defect 93 — the page cache copied every page it served

`readPage` returned `payload.clone()`. A B+tree descent visits a page per level
and a compaction merges page after page, so an 8 KiB copy per visit was the
largest single cost left on both paths — `Segment$Cursor.page` was second only
to `resolve`.

**Fixed** by sharing the cached array. Every caller decodes out of it and none
writes: `BtreePage.parse` and `BlockedBloom.decode` read lazily, `ByteReader`
cannot write. The contract is now stated on the method — a caller that needs to
mutate must clone — and the cache never writes to a payload after admitting it,
because a page whose bytes change on the device is invalidated rather than
edited. `Cursor.page` left the profile entirely.

## Defect 94 — both binary searches allocated a key per probe

`lowerBound` compared with `memcmp(key(mid), target)`, and `key(i)` rebuilds
`prefix + suffix` into a fresh array — two allocations and two copies. Per
probe. `childIndexFor` was worse: `internal(mid)` also built the joined
separator and an `Internal` record. A single descent allocated on the order of
`log2(cell_count)` keys per level, all garbage the moment the comparison
returned. `lowerBound` was the compactor's top frame, with `Arrays.copyOf`
behind it.

**Fixed** with `compareCellKey`, which compares in place: the prefix against the
head of the target first — it is shared by every cell, so it decides the order
for the whole page when it differs — and only then the suffix, straight out of
the payload. Both searches use it; separators have the same layout as keys.

Equivalence against `memcmp(key(i), target)` was asserted inside the method and
the whole suite run five times with the assertion live, including the
conformance vectors and the order tests.

## Defect 95 — and the one the fuzzer caught, which was mine

`FuzzTest` failed roughly one run in six:

```
fuzz: 600 mutants, 276 refused, 82 reported, 240 benign, 2 UNTYPED
java.lang.IllegalArgumentException: fromIndex(6405) > toIndex(6404)
    at java.util.Arrays.compareUnsigned
    at BtreePage.compareCellKey
```

`key(i)` validated the suffix length for free, because `ByteReader.bytes`
refuses a length it cannot satisfy. Reading the bytes in place skipped that, so
an attacker-controlled varint reached `Arrays.compareUnsigned` as a negative
length and came back **untyped** — which `14-security.md` §9.1 forbids outright.

**Fixed** by bounds-checking the length before it is used in arithmetic rather
than after. The lesson is not the bug, it is that an optimisation which moves a
read off a validated path inherits the obligation to validate, and that the
instrument built for exactly this caught it within a few runs of the suite.

## Defect 96 — the common prefix scanned every key on the page

`commonPrefix` compared every key against the first, O(cells x prefix), on every
page a compaction built. Both callers pass a **sorted** list — `SegmentBuilder`
refuses input that is not strictly increasing — and for sorted keys the common
prefix of the whole list is the common prefix of the **first and last**: any key
between them agrees with both wherever they agree. That is one `Arrays.mismatch`
instead of a scan. The sortedness is checked rather than assumed, so the
function stays correct for any caller.

## Where Java ended

Medians of seven runs at 20 000 documents, against the start of this pass:

| | before | after |
|---|---|---|
| `read_ops_per_s` | 94 598 | **102 714** |
| `update_ops_per_s` | 15 173 | **19 989** |
| `mixed_ops_per_s` | 60 113 | **66 065** |
| `delete_ops_per_s` | 15 274 | 11 946 |

```
MIXED    rust 150 085   >   java 66 065   >   dart 15 865   ops/s
```

**On the read path Java is now at Rust's speed**: mixed read p50 **5 µs against
Rust's 6**, p99 12 against 12, `pages/op` 0.570 against 0.537. Java leads Dart
on every operation.

The remaining 2.3x on mixed throughput is dominated by the write path — create
and update are 5x and 6x from Rust — and by compaction running concurrently in
Java where Rust's benchmark compacts only when asked. Both remain honest gaps
rather than measurement artefacts, and the counters say the read path is done.


---

# The write path — defects 97–100

With the read path at Rust's speed, the gap was create and update. Every
finding here came from JFR **allocation** profiling rather than CPU sampling:
on a JVM the write path's cost is largely what it allocates.

## Defect 96b — the page cache tried to stop copying, and could not

`readPage` returns `payload.clone()`. Returning the cached array directly is
tempting — a B+tree descent visits a page per level and a compaction merges page
after page — and it measured roughly **10 %** on the mixed workload.

It was also wrong. With the array shared, the CRUD matrix began failing

```
IllegalStateException: the delete phase deleted nothing
```

about once in fifteen runs at 5 000 documents, where the committed baseline was
clean in thirty. Bisecting one file at a time found it: restoring that single
`clone()`, and changing nothing else, went back to **0 failures in 40**.

A read of every `readPage` call site did not find the caller that mutates or
takes ownership of the result, which is the reason the copy stays rather than a
reason to remove it. **A shared cache needs the ownership rule enforced at the
callers, not assumed in the cache.** The payload cache itself — which is what
skips the per-visit CRC and decode — is unaffected and keeps its win.

This is also a note on method. The bug was rare enough that three earlier
bisection steps came back 1/30, 2/30 and 14/30 and pointed at the wrong files;
what settled it was stressing the **committed baseline** first (0/30) to prove
the regression was mine, then reverting one file at a time against that number.

## Defect 97 — filling a leaf page was O(n²)

`SegmentBuilder.add` appended the cell and then called
`BtreePage.encodeLeaves(batch, ...)` — **re-encoding every cell in the page** —
to discover whether the new one fitted. Adding the k-th cell encoded k cells, so
filling a page of K cells cost K²/2 cell-encodings against the K it needs, and
then `emitLeaf` encoded them once more. At a hundred-odd cells to a page that is
a ~50× multiplier, and it made `encodeLeaves` the top frame in the profile of
**both** the compactor and the foreground.

The packed size is arithmetic:

```
HEADER + prefix_len + sum(leafCellBytes(cell, prefix_len))
```

which is exactly what `pack` computes as `free_start + total`, because
`leafCellBytes` already counts each cell's two-byte pointer. The prefix is the
only moving part: keys arrive sorted, so it is the shared prefix of the batch's
first key and its newest, it only ever shrinks, and when it does the running
total is recomputed in one pass — O(k) on a rare event rather than O(k) on every
add.

**Controlled**: the old trial encode was run alongside the new arithmetic for a
whole suite run, asserting they reach the same verdict. They never disagreed, so
page packing is byte-for-byte what it was.

## Defect 98 — `Utf8.encode` built a `CharsetEncoder` per string

The strict encoder exists because `00-conventions.md` requires an unpaired
surrogate to be **reported**, not silently replaced with U+FFFD. But it was
allocated fresh on every call, along with a `CharBuffer`, a `ByteBuffer` and the
result array — and a document carries twenty strings. It was, by a wide margin,
the largest allocator on the write path.

The two encoders differ on exactly one class of input, and **ill-formed UTF-16
requires a surrogate code unit to be present**. A string with none cannot be
malformed, so `String.getBytes(UTF_8)` — intrinsified, one allocation — is
byte-for-byte identical there. Scanning for a surrogate is an allocation-free
pass over the chars.

`Utf8.decode` got the mirror of it: pure ASCII is valid UTF-8 by definition, and
ISO-8859-1 maps those bytes one-to-one onto the same characters, which the JDK
stores as a Latin-1 `String` with no transcoding. Everything else still goes
through the strict `CharsetDecoder`.

`PrimitivesTest` and `CkeConformanceTest` already assert the reporting
behaviour — "an unpaired surrogate is refused on write, not replaced" — and both
still pass.

## Defect 99 — the liveness scan decoded values it never read

`04-segments.md` §6.8's scan asks one question of every record in the value log:
is this key's current entry a pointer to this exact offset. It never looks at
the value. `decodeRecord` materialised it anyway, which made `Vlog.walkRange`
the single largest allocator in the process.

`decodeRecordKeyOnly` skips the copy and **keeps the checksum**: not decoding the
value is not the same as not verifying it, and §6.4's framing depends on the CRC.
It applies only in the clear — an encrypted record is one AEAD unit, so leaving
its value undecrypted would leave it unauthenticated.

## Defect 100 — two read paths in one class, at two different horizons

Introduced by this work and caught by the CRUD matrix, one run in twenty-four:

```
IllegalStateException: the delete phase deleted nothing
```

`Collection.remove` skips the previous-document read when the collection has no
index (defect 91) and asks `containsKey` instead. It passed `visibleSeq`, while
`get` had moved to the read horizon of defect 89. A document written moments
earlier was therefore *present* to `get` and *absent* to the check, so `remove`
returned early and deleted nothing.

**Fixed** by giving the engine a `containsKey(treeId, cke)` that resolves at the
same horizon `get` uses, so the two cannot drift apart at a call site. The
lesson is narrow and worth stating: adding a second visibility horizon to an
engine means every existing read has to be told which one it is on.

## Where Java ended

Medians of eleven runs at 20 000 documents, against the start of this pass:

| | before | after |
|---|---|---|
| `create_ops_per_s` | 17 219 | **29 937** (1.7x) |
| `read_ops_per_s` | 102 714 | **111 021** |
| `update_ops_per_s` | 19 989 | **23 881** |
| `delete_ops_per_s` | 11 946 | **28 618** (2.4x) |
| `mixed_ops_per_s` | 66 065 | **73 817** |

Against the other two, at 20 000 documents:

```
CREATE   rust  96 188   >  java  29 937   >  dart  7 165
READ     rust 178 976   >  java 111 021   >  dart 72 710
UPDATE   rust 122 209   >  java  23 881   >  dart  7 540
DELETE   rust 1 152 572 >  java  28 618   >  dart  8 840
MIXED    rust 151 525   >  java  73 817   >  dart 15 849
```

Java is between Dart and Rust on every operation, several times Dart's
throughput on all four, and on the mixed workload its read p50 is **5 µs against
Rust's 6** with p99 identical at 12. Every p99.9 is inside `desktop`'s 25 ms
budget — the worst is create at 1.3 ms.

The remaining distance to Rust is widest on `DELETE`, where Rust's is a bare
memtable tombstone at a p50 below a microsecond, and on `CREATE`/`UPDATE`, where
the JVM's encode-and-allocate path is doing genuine work the counters agree on:
`pages/op` is 0.015 against 0.004 for update and 0.020 against 0.006 for delete.


---

# The create p99.9, and a comparison — defects 101–102

## Why Java's create p99.9 was ~100x its p50

Not a stall in the engine's code paths: **it is `10-transactions.md` §6's
backpressure doing exactly what the chapter says**, and the interesting part is
what triggered it. Instrumenting every create slower than 200 µs:

```
SLOW create i=2730 us=1349  stalls=5 flushes=32 backpressureMs=1  cause=l0_segments
SLOW create i=2731 us=12793 stalls=6 flushes=32 backpressureMs=11 cause=l0_segments
```

Always in pairs, always `cause=l0_segments`, always with the delay stepping 1 →
11 ms as §6's quadratic curve climbs.

**The cause is the flush granularity.** `flushShards` emits one L0 segment *per
memtable shard* — eight on `desktop` — against an `l0_trigger` of **4**. So a
single full flush overshoots §6's soft L0 bound by 2x before any compaction can
react, and the writer is then charged the delay for it. The two profile
constants are in tension with each other as long as a flush is shard-granular.

Rust does not have this: its `flush` drains every shard into **one** sorted L0
segment. Sharding exists so writers do not contend (§2.2); it is not a
partitioning of the data, and nothing downstream wants it preserved.

### The fix works, and it is not shipped

Merging the shards into one L0 segment measured, at 20 000 documents:

| | before | after |
|---|---|---|
| `mixed_ops_per_s` | 73 817 | **130 754** |
| `create_ops_per_s` | 29 937 | 36 442 |
| `create_us_p999` | 1 284 | **831** |

It also breaks the mandatory round-trip gate of `11-conformance.md` §6, in
**2 runs out of 8**:

```
CorruptionException: segment head magic is 0300190003000100, expected CRY_SEG
FAIL java could not reopen after its own mutation
```

`0300190003000100` is a B+tree leaf header — cell count 3, free start 6400,
prefix 3, `FLAG_IS_LEAF`. A segment's head page holds a tree page, which means
two structures were handed the same extent. Bisecting one file at a time against
a baseline measured at 8/8 put it on this change and nothing else.

**So it is reverted.** A 1.8x throughput win that corrupts a file a quarter of
the time is not a win, and the gate is mandatory for a reason. What the
experiment established stands and is worth writing down: the p99.9 is
`l0_segments` backpressure, its cause is shard-granular flushing, and merging is
the right shape — it needs the extent allocation on that path understood first.

## Defect 101 — an integer overflow let a hostile length reach the allocator

Found by the structure-aware fuzzer, one run in six:

```
fuzz: 600 mutants, 335 refused, 35 reported, 229 benign, 1 UNTYPED
java.lang.OutOfMemoryError: Requested array size exceeds VM limit
    at java.util.Arrays.copyOfRange
    at org.dizitart.cryptand.util.ByteReader.bytes
    at org.dizitart.cryptand.container.BtreePage.key
```

`ByteReader.need` checked `pos + n > limit` in **int** arithmetic. A length near
`Integer.MAX_VALUE` — which is one varint in a hostile file — overflows the
addition to a negative number, the bound passes, and the allocation throws
`OutOfMemoryError`. Untyped, which `14-security.md` §9.1 forbids outright: a
hostile file must produce "a typed corruption error rather than an allocation
failure".

`(long) pos + n` fixes it at the one place every decoder in the implementation
funnels through. Six consecutive fuzz runs: 0 UNTYPED.

## Defect 102 — a mandatory test's fixture had no precondition

`MandatoryTest.containment` damages a page and requires keys outside the damaged
range to still be served. Containment is **per segment**, so the property is only
observable when more than one segment exists — and this fixture's segmentation
came entirely, and silently, from one-segment-per-shard flushing. Change the
flush and the fixture collapses to a single segment holding every key, where
damaging its root takes out everything and the test fails for a reason that has
nothing to do with §4.

The Rust version of the same test carries the precondition explicitly — "the
fixture needs more than one segment" — and Java's now does too, with periodic
flushes that put three L0 segments in place deliberately rather than by
accident. A fixture that degenerates silently measures nothing.

---

# How Java Cryptand compares to MVStore and RocksDB

`reference/java/src/test/java/org/dizitart/cryptand/bench/CompareBench.java`
runs the same CRUD-under-load shape against MVStore — the engine Nitrite ships
on today — and RocksDB. All three are handed the **same already-encoded CVE
bytes** under the same 8-byte key, so encoding is not the variable.

At 20 000 documents, medians of nine runs. Every engine runs the whole matrix
twice on its own fresh database and the first pass is discarded: 5 000
operations on a cold JVM measure the interpreter, and they measure it hardest
for whichever engine has the longest code path.

| engine | create | read | update | delete | mixed | on disk |
|---|---|---|---|---|---|---|
| **cryptand** | 723 922 | 1 349 892 | **894 528** | **1 790 323** | 951 690 | 44 MB |
| **mvstore** | 1 207 420 | 1 945 273 | 417 169 | 1 541 465 | 1 143 039 | 33 MB |
| **rocksdb** | 295 666 | 824 068 | 220 202 | 324 769 | 363 359 | 20 MB |

**Cryptand is faster than RocksDB on every operation — 1.6× to 5.5× — and
faster than MVStore on update and delete. MVStore is still ahead on create,
read and mixed.** Both halves of that are the honest headline.

Where it stood before the work below, on the same benchmark and the same
machine — 49 775 create, 139 094 read, 26 987 update, 36 147 delete, ~153 000
mixed, 137 MB on disk — the gap was 5–9× to MVStore and 2–5× to RocksDB. What
closed it was not tuning. It was six defects, each of which had an
implementation doing work the format does not ask for:

1. **`vlog_min` at 256 on `desktop` and `server`**, which put this format's own
   639-byte reference document in the value log: a `pwrite` per write, a second
   fetch per read, and a 64 MiB value-log extent preallocated to hold what fits
   in the tree. `12-profiles.md` §2.5 now puts it at a quarter page in every
   profile. Worth 2.5× on create and 2× on read on its own, and it is most of
   the `on disk` column.
2. **The memtable was flushed on every commit**, because step D's "any memtable
   shard *over its budget*" had no budget test. A workload committing one
   document at a time got one L0 segment per document: 525 flushes and 42
   compactions for 20 000 mixed operations, 119 MB to device for 3.2 MB of
   documents, and 648 ms of an 866 ms wall clock spent stalled in backpressure
   that the flushing itself created. `10-transactions.md` §2.1.1 now states the
   gate.
3. **A flush emitted one L0 segment per memtable shard** — 8 against an
   `l0_trigger` of 4, so every flush cycle overshot the trigger by 2× on its own
   and the next writer was stalled 11 ms waiting for a compaction the flush had
   just made necessary. Merging the shards, which are disjoint and each already
   sorted, makes it one run. Delete went from 191 000/s to 1 288 000/s and mixed
   from 312 000 to 749 000.
4. **`applyBackpressure` counted the memtable on every commit** by calling
   `ConcurrentSkipListMap.size()` on every shard — a documented O(n) walk, up to
   32 768 node traversals, to decide whether to stall for zero milliseconds. It
   was the write path's largest single cost. It also recounted the manifest's
   per-level histogram, which is an immutable snapshot.
5. **The page cache copied and re-parsed every page of every descent.** A point
   read visits a page per level, reads a header and runs a binary search, and
   never writes — and paid an 8 KiB `clone` and a re-parse per level for the
   privilege. `Segment.Cursor.seek` was the top frame of the read profile by a
   factor of three. Sharing an immutable parsed page was worth 2.7×.
6. **A freshly built segment was thrown out of the cache and read back.**
   Writing an extent invalidates the pages it covers, correctly; but a flush or
   a compaction has every page of its output in memory and then paid a `pread`
   per page on first touch. `page_reads_per_lookup` was **0.34 on a dataset that
   fits the cache several times over**. Admitting the built pages took it to
   **0.00** and reads from 889 000/s to 1 240 000/s.

Plus, in the same pass: an O(k²) trial-encode in the internal-page build (the
leaf path had already been fixed and the sibling loop had not), a `ByteWriter`
and a `toBytes()` per cell in every page written, a copy of every distinct user
key kept alive to build a Bloom filter that only wants their hashes, a boxed
`Map.merge` per entry to count a tree span that is almost always one run, two
lock acquisitions and nine allocations per single-document commit, a compactor
that parked 5 ms *before* each round so backpressure's wake-up and the
compactor's nap ran in series, and a bare `pread` per value-log record read that
bypassed the page cache entirely.

`13-operations.md` §6.1 and §2.1.1 of `10-transactions.md` carry the two that
are general enough to be worth a reader's attention.

**What the remaining gap is, and why it does not close.** MVStore's numbers are
an in-memory B-tree's. It keeps the map resident and writes at commit: a `put`
does not reach the device, there is no value separation, no per-read checksum
verification, no manifest and no GC. Cryptand's create is 81 % **flush** — 20 000
single-document commits take 4.4 ms and building the 13 MB L0 segment they
produce takes 15 ms, of which 3.6 ms is the write and the CRC-32C that cannot be
avoided. Its read is a descent through a file-backed B+tree with a checksum
already verified and a leaf cell copied out. Those three rows are where holding
everything in the heap shows, and no amount of tuning turns one engine into the
other.

**The `on disk` column, once the most misleading row here, now reads
straight.** It was 137 MB, almost all of it value-log segments preallocated at
`vlog_segment_bytes` to hold documents that now stay inline. At 44 MB against 33
and 20 it is comparable data, not reserved space.

**A caveat on the comparison itself.** Cryptand is a document database with a
manifest, segment filters, liveness statistics and a value-log GC live during
these numbers, page-level CRC-32C verified on every read, optional
authenticated encryption, and a file three other language runtimes can open.
MVStore and RocksDB are key-value stores. This table says Cryptand is in the
same league on the workload it is designed for; it does not say the three do the
same amount of work, and they do not.
