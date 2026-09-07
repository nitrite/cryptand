# The cross-language operational benchmark

`design/performance-model.md` states predictions **P1**–**P11** and each has a
benchmark in `reference/rust/cryptand/benches/` and
`reference/dart/cryptand/bench/`. Those measure the *design*: whether a bound
holds, whether a mechanism is the one doing the work.

This suite measures something else, and it is what the phrase "performance
claim" usually means to a person choosing a database: **what an implementation
does per second, and what it costs on the device.** It runs the same workload,
in the same shape, in all three languages, and prints the same rows — so the
numbers can be put next to each other without an argument about what was
measured.

## Running it

```bash
reference/bench/run_all.sh
```

or one at a time:

```bash
cd reference/rust        && cargo run --release --bin ops_bench
cd reference/dart/cryptand && dart run bench/ops.dart
cd reference/java        && mvn -q -B compile exec:java -Dexec.mainClass=org.dizitart.cryptand.bench.OpsBench -Dexec.classpathScope=compile
```

Every one takes an optional document count (default 20 000) as its first
argument.

## What it measures, and why each row is there

| row | unit | why |
|---|---|---|
| `insert_docs_per_s` | docs/s | the headline write number, on a single writer with `os` durability |
| `insert_bytes_device` | bytes | what actually reached the device for those documents |
| `write_amplification` | ratio | `insert_bytes_device / logical bytes`. The number key–value separation exists to move, and the one the `design/tradeoff-analysis.md` space discussion is about |
| `point_read_us_p50` / `_p99` | µs | a random point read on a database that has been compacted, so it measures the engine and not the memtable |
| `point_read_page_reads` | pages/lookup | pages fetched **through the pager** per lookup. Wall time varies with the machine; this does not |
| `scan_rows_per_s` | rows/s | a full ordered scan, the operation the value-log clustering of `04 §6` exists to protect |
| `scan_page_reads_per_row` | pages/row | P8's `v/row`, the locality number |
| `index_lookup_us_p50` | µs | an equality lookup through a secondary index |
| `codec_bytes_on` / `_off` | bytes | file size with `page_codec = LZ4` against `page_codec = 0`, same data. Supports `01 §7`'s reason for existing |
| `codec_saving` | ratio | `1 - on/off` |
| `cipher_write_ratio` | ratio | insert throughput unencrypted ÷ encrypted. P11's cost, on the write path |

## One row that is not comparable, and why it is still here

`point_read_page_reads` counts pages fetched **through the pager**, and the
three implementations cache at different layers. Rust's engine re-reads a
segment's pages through the pager and reports ~6 per lookup; Dart holds a
segment's whole extent in memory once it is loaded and reports **0**, because
after the load a lookup touches no page at all.

Neither number is wrong and neither is a defect. What they are is *not the same
measurement*, so the row must not be read as "Dart does six times less I/O than
Rust" — it says where each implementation's caching boundary sits. Compare a
number to itself across a change, not to another implementation's.

`insert_logical_bytes` is the second such row. Java encodes the fixture through
a name dictionary and reports ~1.30 MB where Rust and Dart encode the names
inline and report ~1.92 MB for the same 3 000 documents. That is
`02-value-encoding.md` §5.3 working as designed — the dictionary is the largest
space win in the format — but it means the *denominator* of
`write_amplification` is not the same quantity in all three, so that ratio
compares an implementation to itself and not to its neighbours.

**Nothing here is comparable between implementations except `codec_saving`**,
which is a ratio of one implementation's own two runs and which all three
independently report as zero. Every other row compares a number to itself
across a change. This is written down because a benchmark table invites exactly
the comparison it does not support, and the reader deserves to be told which
columns lie.

## A counter that is not a counter

`bytes_written_device` is one of `13-operations.md` §6's required metrics and it
looks like the ideal primary result: it counts bytes, not time. On the Java
implementation it varies **2.2× between two runs of the same configuration**,
because the compactor runs in the background and has done a variable amount of
work by the moment the counter is read.

That was caught by a control, and it mattered: a codec comparison built on it
reported a **27 % saving** — flatly contradicting the controlled measurement in
`01-container.md` §7, which found compression saves exactly zero. The 27 % was
noise. Running the same comparison with the codec *unchanged* on both sides gave
1 114 112 and 1 064 960 bytes for `none`, and 983 040 and 450 560 for `lz4`.

So on this suite `bytes_written_device` and `write_amplification` are printed as
**observations** by the Java implementation and as counters by Rust, whose
single-threaded compaction makes them deterministic. The codec rows use
`page_count × page_size`, which is deterministic everywhere and is the right
question anyway: does compression reduce the space the database occupies?

The general lesson, and it is the seventh time this project has met a version of
it: **being a counter is not the same as being deterministic.** A counter read
at an uncontrolled moment measures the scheduler.

## The rules this suite follows

They come from `design/performance-model.md` §8, which took them from this
project's own history of flaky timing guards.

- **A counter is the primary result; wall time is an observation.** Every row
  above that is a ratio or a count is comparable across machines and across
  languages. Every row in µs or per-second is not, and is labelled as an
  observation in the output. Nothing here is asserted in CI.
- **The median, not the mean.** One GC pause, one compaction, or one page fault
  should not decide a headline number.
- **Measure after a compaction, never before.** A benchmark that reads what it
  just wrote measures the memtable. Each phase below drains compaction first
  and says so.
- **The same document in all three.** 20 fields, names averaging 12 B, values
  averaging 20 B — the shape `design/performance-model.md` §1 assumes and every
  density figure in §6 is costed against. A smaller document would flatter the
  name dictionary and understate decode work; a larger one would do the
  reverse.
- **The same profile in all three**: `desktop`, so `vlog_min` is 256 B and
  values are separated. `mobile` inlines them and measures a different engine;
  it is a separate run, not a footnote.

## A companion, for a cost this suite is the wrong shape to see

`reference/rust/cryptand/benches/filter_probe.rs`
(`cargo run --release --bin filter_probe`) measures one thing: what a
`04-segments.md` §2.4 filter probe costs, across filter sizes.

It exists because this suite could not see defect 76. Rust decoded the entire
filter payload on **every** probe where Dart and Java cached it, and at this
suite's 20 000 documents that showed up as about **5 %** on
`point_read_us_p50` — a segment's filter at that size is two or three 64-byte
blocks, so the copy being removed is a couple of hundred bytes. The cost is
O(filter size): at 500 000 keys the same probe cost **26 µs against 10.6 ns**,
a factor of 2 488.

The lesson is not about that defect. It is that **a fixed-size workload measures
a size-dependent cost at exactly one point on its curve**, and 20 000 documents
is at the flat end of several curves in this format. When a change is O(some
dimension), measure along that dimension; this suite answers "what does an
implementation do per second", which is a different and equally real question.

## What it does not measure

Concurrency. `10 §2`'s multi-writer scaling is P3, it needs threads, and it has
its own harness in `reference/rust/cryptand/benches/p3_write_scale.rs` — a
single-writer number from three languages, one of which has no shared-memory
threads at all, would not mean the same thing in each. See
`design/tradeoff-analysis.md` §8.14 for what P3 actually measured and for the
half of `10 §2.1`'s headline claim that turned out to belong to the host's
write path rather than to this design.
