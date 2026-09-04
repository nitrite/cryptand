# cryptand-write

`10-transactions.md` §2 — the **concurrent write protocol** — and
`13-operations.md` §8 — **multi-process readers**. The two parts of the design
the Dart reference implementation could not reach, because one needs threads and
the other needs processes.

Dart has no shared-memory threads, so *N* writers contending on one counter
could not be exercised and **prediction P3 could not be measured**. Every phase
report since phase 5 has carried that as the highest-value remaining item. This
crate is it.

```bash
cargo test -p cryptand-write                       # 24 tests, some of which spawn processes
cargo run --release --bin p3_write_scale [batches] # P3
cargo run --release --bin p3_bottleneck            # where scaling actually stops
```

## What is implemented

| | |
|---|---|
| `engine` | §2's writer (7 steps) and committer (7 steps), §2.4 group commit, §7 durability modes |
| `vlog` | `04-segments.md` §6.2 — a value-log segment and the **reserve-then-`pwrite`** protocol §2.2 requires |
| `prefix` | the contiguous-prefix watermark that both `visible_seq` and a segment's `bytes` are |
| `nonce` | `14-security.md` §4.1 — the publish-before-allocate reservation watermark |
| `multiproc` | `13-operations.md` §8 — the `<name>.cryptand-lock` sidecar: slot claiming, heartbeats, reclamation, and the retention floor a reader pins |

The byte encodings come from `cryptand-conformance`, so the two crates cannot
drift apart on the format itself.

### The three ordering invariants of §2.3, each with a test

1. **What is published must already be durable.** The committer's barrier
   precedes the publish, and every enqueued range completed its `pwrite` before
   it was enqueued.
2. **A watermark advances only over a contiguous prefix of completed
   reservations.** A writer that reserved a range and died leaves a hole, and
   `a_reserved_but_unwritten_range_pins_every_later_one` asserts the later,
   fully written range stays unreachable until the hole is filled.
3. **A nonce's floor is published before the nonce is allocated.** Three
   simulated crashed sessions, and no value is ever handed out twice.

## What this measures, and what it does not

**It is not an engine.** There is no B+tree, no manifest, no compaction, and the
memtable never flushes to an L0 segment. That matters for exactly one number:
P3's own stated fragility is *"if the committer becomes the bottleneck (one
thread building segments for many writers), scaling stops early"* — and a
committer that builds no segments is the cheapest committer possible.

So the scaling figure here is an **upper bound** on what a full engine reaches,
and the benchmark says so by sweeping `committer_work_per_batch`: the cost of
the work this crate does not do is injected rather than pretended away. A run
with the knob at zero is the control that cannot fail; the sweep is the
measurement.

Also absent, and deliberately: backpressure (§6), conflict detection and
isolation levels (§3 — implemented in Dart), segment rotation (one open segment
per heat class for the engine's life, which is what §2.1's O(1)-in-concurrency
claim is about anyway), and record encryption (`cryptand-conformance` covers
`14-security.md`'s bytes).

`write_at`/`read_at` are `std::os::unix::fs::FileExt`, so the crate is
Unix-only. Positional I/O without a shared file cursor is the whole point of
reserve-then-`pwrite`; a portable version needs the same call under another
name.

## What it measured

**P3 is confirmed in a durable mode and only there** — 1 → 32 writer threads
scales **14.8×** (disjoint keys) and **15.7×** (overlapping) under `sync`, with
p50 latency roughly flat at 3–6 ms, because group commit amortizes one barrier
over a growing number of batches. That is P3's own-scaling half, and it does not
plateau at 8–16 threads the way the prediction expected.

Under `os` — no barrier — throughput peaks at **two** threads and falls to
0.84× by 32. `p3_bottleneck` says why, and the answer is none of the three
things the design worries about:

| shared thing | 1 thread | 32 threads |
|---|---|---|
| `pwrite` at disjoint offsets, one file | 380 757 /s | 97 542 /s (0.26×) |
| the same writes, **one file per thread** | 629 266 /s | 159 039 /s (0.25×) |
| one mutex-guarded queue plus a notify | 35 320 088 /s | 22 601 597 /s (0.64×) |

The committer handoff runs 60–100× above the rate the engine achieves, and the
one-file rule is not the cause — spreading the writes over one file per thread
degrades identically. On this host the OS write path is the ceiling for small
buffered writes, whatever the file layout.

`design/tradeoff-analysis.md` §8.14 has the consequences.

## Multi-process readers

`src/bin/mp_reader.rs` is a reading **process**; `tests/multiproc.rs` spawns
several of them, because a protocol whose whole subject is coordination between
processes cannot be tested any other way. Three readers claim distinct slots and
move the writer's `min_retained_commit` to the oldest commit any of them pinned;
one stops beating and is reclaimed; twelve racing processes produce twelve
distinct slots.

The claim's "compare-and-swap" is an exclusive advisory lock around a
read-scan-write of the sidecar — a plain file has no cross-process atomic word.
It is taken once per reader open and never on the heartbeat path.

Three gaps found, in `design/tradeoff-analysis.md` §8.15; the one that matters
is that the sidecar header declared `writer_pid` and `writer_heartbeat_ms` and
no rule read them, which left an abandoned database silently degrading every
reader that opened it.
