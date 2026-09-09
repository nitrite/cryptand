# Benchmark results

Two tables, measured together on one machine (Apple Silicon, macOS/APFS, JDK 25,
Dart stable, Rust release with debuginfo). Both are reproducible with the
scripts named beside them.

Every number is a **median**, and every run discards a first pass on a fresh
database: a few thousand operations on a cold process measure the process, and
on the JVM they measure the interpreter — hardest for whichever engine has the
longest code path. Cryptand read 492 000/s at the original 2 000-operation
warm-up and 1.4M/s once compiled, the same engine either way.

Measured 2026-09-09.

Both suites are run from the same tree as the test suites they sit beside; all
three harnesses are **outside** their libraries (Java `src/test`, Dart outside
`lib/` and out of the published archive, Rust behind a non-default `harness`
feature), so nothing measured here ships to a consumer.

---

## 1. Java Cryptand against MVStore and RocksDB

`reference/java/src/test/java/org/dizitart/cryptand/bench/CompareBench.java`
— 20 000 documents, medians of 7 runs.

```
mvn -q -B test-compile -DskipTests
java -cp target/classes:target/test-classes:$CP org.dizitart.cryptand.bench.CompareBench
```

| engine | create | read | update | delete | mixed | on disk |
|---|---|---|---|---|---|---|
| **cryptand** | 703 890 | 1 360 699 | **877 745** | **1 869 042** | 922 082 | 44.0 MB |
| **mvstore** | 1 131 771 | 1 709 572 | 423 218 | 1 670 263 | 1 127 571 | 33.1 MB |
| **rocksdb** | 294 631 | 840 371 | 215 414 | 323 897 | 359 394 | 20.3 MB |

Operations per second. **Cryptand is faster than RocksDB on every operation —
1.6× to 5.8× — and faster than MVStore on update and delete. MVStore is ahead
on create, read and mixed.**

MVStore's mixed and delete rows move a lot between runs, because its
`auto_commit_delay` (below) may or may not fire inside a phase: mixed has been
measured from 0.78M to 1.13M and delete from 1.18M to 1.67M on this machine,
against Cryptand's 0.90M–0.95M and 1.74M–1.87M. The median of seven is what is
printed; treat a single-run comparison of those two rows as noise.

**MVStore is file-backed here, not in-memory.** `MVStore.Builder().fileName(...)`
is what makes it so: without `fileName` the builder returns a store whose
`getFileStore()` is null and which never touches a disk. With it, a run leaves a
13.2 MB `db.mv` behind and a reopen finds all 20 000 entries. Its
`auto_commit_delay` is the default 1000 ms, so over a ~20 ms phase nothing is
written in the background and the whole file lands in the `store.commit()` the
benchmark times inside the create phase. Both facts are printed in the
benchmark's own header so the table cannot be read without them.

All three are handed the **same already-encoded CVE bytes** under the same
8-byte key, so encoding is not the variable. What is still not equal is in the
benchmark's class docs; the short version is that MVStore keeps the whole map in
the heap and writes at commit, RocksDB is native code across a JNI boundary, and
Cryptand maintains a manifest, segment filters, liveness statistics and a
value-log GC, verifies a CRC-32C per page, and writes a file three other
language runtimes can open.

---

## 2. The three implementations against each other

`reference/bench/run_xlang_crud.sh` — 20 000 documents, medians of 5 runs.

```
reference/bench/run_xlang_crud.sh
```

This is the **one table in this directory that compares implementations to each
other**, and it exists because nothing else here does: `run_all.sh`'s rows drive
a `Collection` and build and encode a document inside the timed loop, and
`README.md` says plainly that they are not comparable across languages. This one
drives the **engine**, hands it values encoded before the clock starts, encodes
the key inside the loop in all three (Java's engine takes CKE bytes directly,
Rust's and Dart's take a `Value` and encode it themselves — hoisting the keys
would hand Java a per-operation saving the others cannot have), and uses a
pseudo-random sequence that is identical bit for bit in all three.

| row | rust | dart | java |
|---|---|---|---|
| create | **881 277** | 460 532 | 734 723 |
| read | 654 847 | 390 320 | **1 350 105** |
| update | 669 579 | 352 584 | **880 695** |
| delete | **2 072 718** | 933 881 | 1 852 881 |
| mixed | 500 540 | 285 996 | **979 128** |
| persist (ms) | 0.3 | 11.8 | 0.2 |
| file bytes | 31 457 280 | 21 217 280 | 43 982 848 |
| storage model | file-backed, segments resident | in-memory page space | file-backed |

Operations per second, except the last three rows.

**Read `storage_model` before reading anything else.** The three do not have the
same storage model, and it is the largest term in any gap between them:

- **java** — a pager over an open file with a bounded page cache. Segments are
  read from the file on demand and written as they are built.
- **rust** — a real file with incremental extent writes, but whole segment
  extents held in memory under an LRU, so a read rarely reaches the file.
- **dart** — the whole page space is a list of pages in the heap. A file is read
  whole on open and written whole on save, so **nothing reaches a disk during a
  run** — which is what its 12.1 ms `persist` is, against Java's 0.2 ms barrier
  and superblock.

The `ops/s` rows therefore measure engine work up to the segment build, which is
the part all three actually do; `persist` is measured once and separately
because averaging a whole-file write into a per-operation figure would hide
exactly the thing worth seeing.

### What this table found

It was built to make the next round of work findable, and it did. Every number
in it moved because of a defect the table pointed at, and none of them because
of tuning:

- **Dart's mixed row read 35 894/s.** `hasAnyRangeDeletes` walked every key of
  the memtable on every point read to return `false` — 479 ms of a 521 ms
  read cost, so reads ran 15× slower whenever writes were interleaved and full
  speed whenever they were not. The Rust implementation already had the counter
  that fixes it, with a comment explaining why; Dart never got it.
- **Rust's CRC-32C was a bit-at-a-time loop** — eight shift-and-xor iterations
  per byte, no table and no instruction, in an implementation of a format that
  chose CRC-32C *because* "it is hardware-accelerated on every current ARM and
  x86". A flush of 20 000 documents spent 41.8 of its 45.9 ms there. Dart's was
  a byte table, eight times better and eight times worse than it needed to be.
  Both are slicing-by-8 now, verified byte-identical against what they replaced
  on every length from 0 to 600 and on page-sized buffers.
- **Rust routed memtable shards by the internal key**, which includes `seq`, so
  the versions of one key scattered across all eight shards and every point read
  had to probe all eight. `10-transactions.md` §2 step 5 says `h(key) % shards`,
  and `store.rs` already did it that way.
- **Both maintained a per-key write-sequence map on every write** for
  `10-transactions.md` §3's conflict detection, whether or not a transaction was
  open. A write made while none is open cannot conflict with one that begins
  later, so the map is only needed while a transaction is live. In Dart the key
  is a hex **string**, built with a `StringBuffer` and a `toRadixString` per byte
  of the key, per write.
- **Dart's flush took the memtable's keys and then looked each one up again** —
  an O(log n) splay per entry, with a byte-array comparator, to re-find a value
  the iteration was standing on.

And one that the *fixes* broke, which is worth recording because it is the same
shape as the fixtures in §1: **a control test calibrated against a slow
engine.** `profile_test.dart`'s foreground-stall control asserted that removing
`compaction_step_bytes` pushes some `put` past the 8 ms budget, and it did — at
a measured 10.03 ms, a 25 % margin. Once CRC-32C stopped being a byte table the
unbounded cascade came in under 8 ms and the control started failing about half
the time, on an engine that had got *faster*. It now asserts on
`maxCompactionSpendBytes`, which is what `04-segments.md` §5.2 actually
constrains: bounded merges 262 400 bytes against a 262 144 budget (one entry
over, which §5.2 allows), unbounded merges 1 312 000. A factor of five apart,
and nothing a faster machine can flip. The positive test kept its millisecond
bound but moved it to the p99, because under `dart test -j 4` a descheduled
`put` lands at 13 ms about one run in eight and that is a fact about the
scheduler, not about the engine.

Where each row started, before any of it:

| row | rust | dart | java |
|---|---|---|---|
| create | 399 357 → **881 277** | 247 121 → **460 532** | 726 613 → 734 723 |
| read | 637 037 → 654 847 | 440 529 → 390 320 | 1 226 969 → 1 350 105 |
| update | 357 492 → **669 579** | 224 346 → **352 584** | 893 602 → 880 695 |
| delete | 1 635 702 → **2 072 718** | 582 819 → **933 881** | 1 867 326 → 1 852 881 |
| mixed | 365 648 → **500 540** | 273 075 → 285 996 | 913 494 → 979 128 |

Java's rows are unchanged within noise; nothing in this round touched it. The
three are now within a factor of two of each other on most rows, which is where
implementations of one format should be, and Rust leads create and delete.

What is left: Dart's read is the slowest row and is genuinely the B+tree
descent — measured at 10 ms of a 14 ms read phase inside `Segment.lookup`, not
in overhead around it — and Rust's mixed still costs more than its own read and
update rows predict.
