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
| **cryptand** | 725 802 | 1 364 520 | **893 083** | **1 740 442** | 949 318 | 44.0 MB |
| **mvstore** | 1 158 184 | 2 269 161 | 410 551 | 1 641 744 | 1 129 080 | 33.1 MB |
| **rocksdb** | 294 830 | 872 543 | 241 365 | 332 214 | 395 890 | 20.3 MB |

Operations per second. **Cryptand is faster than RocksDB on every operation —
1.6× to 5.2× — and faster than MVStore on update and delete. MVStore is ahead
on create, read and mixed.**

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
| create | 399 357 | 247 121 | **726 613** |
| read | 637 037 | 440 529 | **1 226 969** |
| update | 357 492 | 224 346 | **893 602** |
| delete | 1 635 702 | 582 819 | **1 867 326** |
| mixed | 365 648 | 273 075 | **913 494** |
| persist (ms) | 0.8 | 12.1 | 0.2 |
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

**Java is now the fastest of the three, and that is new.** It was the slowest by
a wide margin before the work recorded in `reference/HARDENING.md`, and the
inversion is a statement about how much of that work has not been done in the
other two rather than about the languages. The value of this table is that it
makes the next round findable: Dart's mixed row was **35 894/s** here until
`hasAnyRangeDeletes` stopped walking every key of the memtable on every point
read — 479 ms of a 521 ms read cost, and a defect the Rust implementation had
already fixed and written a comment about. Rust's create and update rows are the
next ones to look at.
