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
| `point_read_page_reads` | pages/lookup | **the primary result.** Wall time varies with the machine; page reads per lookup is the property P10 bounds, and it is what a slow implementation and a slow disk look different on |
| `scan_rows_per_s` | rows/s | a full ordered scan, the operation the value-log clustering of `04 §6` exists to protect |
| `scan_page_reads_per_row` | pages/row | P8's `v/row`, the locality number |
| `index_lookup_us_p50` | µs | an equality lookup through a secondary index |
| `codec_bytes_on` / `_off` | bytes | file size with `page_codec = LZ4` against `page_codec = 0`, same data. Supports `01 §7`'s reason for existing |
| `codec_saving` | ratio | `1 - on/off` |
| `cipher_write_ratio` | ratio | insert throughput unencrypted ÷ encrypted. P11's cost, on the write path |

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

## What it does not measure

Concurrency. `10 §2`'s multi-writer scaling is P3, it needs threads, and it has
its own harness in `reference/rust/cryptand/benches/p3_write_scale.rs` — a
single-writer number from three languages, one of which has no shared-memory
threads at all, would not mean the same thing in each. See
`design/tradeoff-analysis.md` §8.14 for what P3 actually measured and for the
half of `10 §2.1`'s headline claim that turned out to belong to the host's
write path rather than to this design.
