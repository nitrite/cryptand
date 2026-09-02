# CFF-10 — Sequencing, concurrent commit, durability, recovery

**Normative.** Assumes `01-container.md`, `04-segments.md`.

This chapter specifies how many threads write at once and how a commit becomes
durable. It is where the write-concurrency claim lives.

---

## 1. Snapshot

A **snapshot** is a sequence number plus the structural state at one commit:

```
Snapshot := ( seq, commit_id,
              catalog_root, freelist_root, attributes_root,
              manifest_root, vlog_stats_root,
              checkpoint_root, changefeed_root )
```

**All nine superblock roots, not a subset.** A snapshot that omits one is not a
consistent view of the database: a reader restored to it would see the current
change feed against an older manifest. `13-operations.md` §1 stores exactly this
tuple for a checkpoint, for the same reason.

A read at snapshot *S* sees exactly the records with `seq ≤ S.seq` that were not
superseded or deleted by a record with a seq also `≤ S.seq`. Because segments
are immutable and every version carries its own seq (`04-segments.md` §1), a
snapshot needs no locks, no copying and no coordination with writers.

`visible_seq` in the superblock is the greatest seq that is committed and
durable. A new reader takes `S.seq = visible_seq`.

## 2. Concurrent write protocol

This is the core of the design. Multiple application threads write at once and
contend on one atomic counter.

```
writer thread (any number of them):

  1. begin        S = current visible_seq                    -- read snapshot
  2. buffer       build the write batch in thread-local memory
  3. values       for each value ≥ vlog_min:
                     reserve a range in the open value-log segment for this
                     record's heat class (one fetch_add on its tail offset)
                     pwrite the batch's records there; keep 16-byte pointers
  4. sequence     seq_base = next_seq.fetch_add(batch_size)  -- one of the two
                                                             --  global points;
                     -- an encrypted writer also does one fetch_add on
                     -- next_nonce per page or record (14-security.md §4.1)
  5. publish      insert into memtable shard h(key) % shards
                     -- each shard is an independent concurrent sorted
                     --  structure; writers to different shards never meet
  6. enqueue      register (seq_base, seq_base+batch_size) with the committer
  7. wait         until visible_seq ≥ seq_base + batch_size
                     -- per the durability mode; `none`/`os` return immediately
```

```
committer (one, background):

  A. collect      all batches whose records are fully written
  B. seal/flush   flush the open value-log segments' tails
  C. barrier      one fdatasync covering every write since the last commit
  D. flush        any memtable shard over its budget → bulk-build an L0
                  segment (04 §2.3), append it, and edit the manifest tree
  E. barrier      fdatasync
  F. superblock   write the inactive slot with commit_id+1,
                  visible_seq = the highest fully durable seq,
                  next_seq, and the new roots
  G. barrier      fdatasync; wake every writer waiting at or below visible_seq
```

### 2.1 Why this scales

| shared thing | cost |
|---|---|
| `next_seq` | one `fetch_add`; ~20 ns even at 64 threads |
| `next_nonce` (encrypted files only) | one `fetch_add` per encrypted page or record, same cost, plus one extra superblock write per 2²⁰ allocations (`14-security.md` §4.1) |
| value-log segment tail | one `fetch_add` to reserve a byte range, then a `pwrite` straight to the reserved offset — no shared buffer, no lock, and no two writers touching the same bytes |
| memtable shard | independent per shard; a concurrent skip list or a sharded map |
| committer | one thread, amortized over a whole commit group |

Open value-log segments are bounded by the number of **heat classes**, not by
the number of writers (`04-segments.md` §6.2), so write-path memory does not
grow with concurrency.

**There is no single write-ahead log.** A conventional LSM funnels every writer
through one sequential journal file, so writers serialize on that file's offset
and on the group-commit leader. Cryptand's durability records are the value-log
segments and the L0 segments themselves, of which there are as many as the
implementation opens — so *N* writers drive *N* independent append streams into
the device. On NVMe, where a single append stream cannot saturate the device,
that is the difference between using the hardware and not.

### 2.2 Requirements

An implementation claiming Level 0 MUST:

- allow concurrent `put`/`remove` from multiple threads with no
  database-wide lock on the write path;
- shard the memtable (`memtable_shards`, default 8);
- route value-log appends through the **reserve-then-`pwrite`** protocol of
  `04-segments.md` §6.2, so that writers do not serialize on a shared buffer or
  a lock. Note what this requirement is *not*: open value-log segments are
  bounded by the number of **heat classes**, not by the number of writers.
  Writers do not contend even while sharing a segment, because each takes a
  disjoint byte range with one `fetch_add` and writes into it directly. An
  earlier draft asked for a segment per writer, which would have made write-path
  memory scale with thread count for no benefit
  (`design/tradeoff-analysis.md` §8, defect 2);
- run the committer off the writer threads;
- run compaction concurrently with writes and with other compactions on disjoint
  key ranges (`04-segments.md` §5.1).

An implementation MUST NOT make a `put` wait for a compaction except through
explicit backpressure (§6).

### 2.3 Atomicity

A batch is atomic because `visible_seq` advances past its seq range only after
**every** byte of it — value-log records, memtable entries that have been
flushed, and the manifest edit — is durable. A partially written batch is
invisible: its records have `seq > visible_seq` and every reader ignores them.

This holds even though the batch's writes are scattered across several value-log
segments and several memtable shards. There is no commit record and no two-phase
protocol; the watermark is the commit.

A **third** invariant applies to an encrypted file, and it is of the same
kind — an ordering rule whose violation produces a file that opens cleanly and
is wrong:

3. **A writer MUST advance and durably publish `next_nonce` before allocating
   any nonce — on open, and again whenever allocation reaches the published
   value** (`14-security.md` §4.1). Without the publish-first half, a crashed
   session leaves the watermark unmoved and the next session reissues its
   nonces; a stream cipher reusing a nonce discloses both plaintexts and the
   authentication key. No checksum and no tag catches it — every affected page
   verifies perfectly.

**Two ordering invariants, both MUST.** They are the price of having no
write-ahead log, and violating either produces a database that opens cleanly and
is wrong:

1. **A superblock MUST NOT name a segment whose value-log records are not
   already durable.** The committer's barrier over the value-log tails (step C)
   precedes the segment write (D) and the superblock (F). Reversing them yields
   a key index pointing into bytes that were never written — a dangling pointer
   that no checksum catches, because the key side is intact.
2. **The `bytes` watermark in a value-log segment's tree-7 entry
   (`04-segments.md` §6.2, §6.7) MUST advance only over a contiguous prefix of
   completed reservations.** A writer that reserved a range and died leaves a
   hole; advancing past it publishes garbage as a live record. The watermark
   lives in tree 7 — a copy-on-write tree written through the ordinary commit
   path — and not in the segment's head page, which is written once and never
   rewritten.

A batch spanning many trees — a document insert plus its five index
updates — is therefore atomic by construction. Today only the Fjall backend gives
Nitrite that.

### 2.4 Group commit

Batches arriving within one commit window share the committer's barriers. Under
load the per-batch fsync cost approaches zero while per-batch latency stays one
commit window. An implementation MUST NOT acknowledge a batch before the barrier
its durability mode requires.

## 3. Transactions

| level | how |
|---|---|
| **Snapshot isolation** (default) | reads at the start snapshot; writes are buffered and sequenced at commit; write–write conflicts against batches sequenced in between are detected by key |
| **Read committed** | each statement takes a fresh snapshot |
| **Serializable** | the transaction additionally records its read set and validates it at commit |
| **Read-only** | pins a snapshot; cannot conflict; never blocks and is never blocked |

Conflict detection compares the transaction's written key set against keys
written by batches with `seq` in `(start_seq, commit_seq)`. Segment filters and
the memtable make this cheap. On conflict the transaction aborts; the format
does not define automatic retry.

**Savepoints** discard buffered entries after a mark. Nothing durable is written
before sequencing, so rollback is free and leaves no trace — unlike the undo-log
approach all three SDKs use today, which writes and then reverses.

Value-log records written by a transaction that then aborts are garbage, not
corruption: nothing points at them, and GC reclaims them.

### 3.1 Relationship to Nitrite's existing transaction layer

Nitrite implements transactions above the store in all three SDKs
(`TransactionalMap` + journal + undo entries). That layer can sit on Cryptand
unchanged. It should not: engine snapshots are correct under concurrent readers,
free to roll back, atomic across maps, and do not serialize writers. See
`adoption/rollout.md` phase 3.

## 4. Recovery

There is no log to replay.

```
1. read superblock slots A and B
2. discard any slot failing magic / CRC / version checks
3. pick the survivor with the greater commit_id
4. treat everything at or past its page_count as debris
```

That is the whole procedure, O(1) in database size. Compare: MVStore scans chunk
headers, RocksDB and Fjall replay a journal, Hive reads every key of every box
into memory.

**What a crash loses**: batches whose seq range had not reached `visible_seq`.
What a crash *cannot* do, at any durability setting, is produce a structurally
invalid database — no write ever overwrites a page a live superblock references.

Debris (value-log records and segments written but never published) is
unreferenced. An implementation MAY truncate to `page_count` on open; it MUST NOT
require truncation to be correct. A value-log segment whose tail was being
appended when the process died is **sealed** at the last durable `bytes`
watermark in its tree-7 entry (`04-segments.md` §6.7); new writes go to a fresh
segment. The debris past the watermark is never overwritten in place, because on
an encrypted file that would reuse a nonce (`14-security.md` §4.3); it is
reclaimed with the rest of the segment by ordinary GC.

## 5. Publishing a manifest edit

Compactions and memtable flushes both end by editing the manifest tree (tree 6).
The manifest is a plain copy-on-write B+tree, so an edit copies a root-to-leaf
path and produces a new root.

Concurrent editors serialize only here:

```
lock(manifest)                 -- short: microseconds
  re-read the current manifest root
  apply this job's edit (add output segments, remove input segments)
  write the copied pages
  new_root = ...
unlock(manifest)
```

A job whose input segments were removed by another job in the meantime MUST
abort and be rescheduled; because parallel compaction jobs are chosen on
disjoint key ranges, this is rare by construction rather than by luck.

Input segments removed from the manifest are added to the free tree at the
publishing `commit_id`, and become allocatable once `min_retained_commit`
passes them (`01-container.md` §6).

## 6. Backpressure

An implementation MUST bound each of these and MUST slow writers rather than
exceed them indefinitely:

| bound | soft | hard |
|---|---|---|
| L0 segment count | `l0_trigger` | `l0_trigger` × 4 |
| segments per tiered level | `tier_width` | `tier_width` × 2 |
| total memtable bytes | profile budget | 2 × budget |
| value-log space amplification | `vlog_space_target_pct` | 2 × target |
| locality debt | `locality_debt_pct` | 2 × |

**The backpressure curve is normative.** Let `x` be the worst normalized
overshoot across the bounds above:

```
x = max over bounds of  (current − soft) / (hard − soft),  clamped to [0, 1]
delay_ms = max_delay_ms × x²
```

with `max_delay_ms` defaulting to 100. Quadratic, so it is imperceptible while
the engine is merely busy and firm before it is in trouble.

An implementation MUST NOT stall at the hard threshold without having applied
increasing delay before it — a cliff turns a throughput problem into a hang, and
that is the failure users report. It MUST expose the current delay and the bound
that caused it (`13-operations.md` §6).

### 6.1 Compaction pacing

An implementation MUST rate-limit compaction and GC I/O rather than letting it
run at device speed. A workable rule: 2–4× the trailing foreground write rate,
clamped to the profile's ceiling, raised while a bound is in overshoot.

Unpaced background I/O is the main cause of write-latency spikes in LSM engines.
It is also, on a phone, the main cause of unexplained battery drain — which is
why `12-profiles.md` §5 lets the host defer it entirely.

## 7. Durability modes

| mode | after data | after superblock | acknowledged data survives |
|---|---|---|---|
| `none` | — | — | process crash, not power loss |
| `os` | — | — | process crash; ordering only |
| `sync` *(default)* | `fdatasync` | `fdatasync` | OS crash and power loss on hardware that honours the flush |
| `full` | full-device flush | full-device flush | power loss, unconditionally |

**The normative rule is an obligation, not a syscall** (`00-conventions.md`
§1.1). Two MUSTs, and they are the whole of it:

1. An implementation MUST use the **strongest durable-flush primitive its
   platform and runtime actually provide** for the requested mode.
2. It MUST record in `durability_achieved` **what it performed**, never what was
   requested. An implementation that cannot reach a mode reports the mode it
   reached and is conforming; one that claims a mode it did not reach is not.

That second MUST is the load-bearing one, because the failure is silent: a file
whose `durability_achieved` says `full` when only a page-cache flush happened
looks perfect until the power goes out. Requesting `full` and recording `sync` is
correct behaviour on any platform or runtime that cannot do better — including
one whose standard library exposes no device-level flush at all.

*Non-normative — the platform mapping as of writing.* Implementations are
expected to consult their own platform documentation; this table is guidance and
will age.

| platform | `sync` | `full` |
|---|---|---|
| Linux | `fdatasync(2)` | `fdatasync(2)` — Linux exposes no stronger portable call, so `full` and `sync` coincide, and `durability_achieved` should read `sync` |
| macOS / iOS | `fsync(2)` | `fcntl(fd, F_FULLFSYNC)` — **`fsync` alone does not flush the drive cache** |
| Windows | `FlushFileBuffers` | `FlushFileBuffers` reaches the drive on a handle opened **without** `FILE_FLAG_NO_BUFFERING`; `full` and `sync` coincide here too |
| Android | `fsync(2)` | `fsync(2)`, plus whatever device-level flush the runtime exposes |

A runtime that reaches these primitives only through a foreign-function
interface, or not at all, reports the mode it reached under rule 2. That is a
capability difference, not a conformance failure, and no requirement here is
written against a particular language.

`os` and `none` never risk structural corruption; they risk losing recent
batches. That property comes from append-only and copy-on-write, and is worth
stating to applications because it is not true of Hive's append-only file.

## 8. Reclamation and long readers

`min_retained_commit` bounds page reuse; `min_retained_seq` bounds version
collapsing in compaction. Both are computed from the live snapshot set and
persisted every commit.

A long-lived reader **pins space and pins versions** — and now also pins
**value-log segments**, which a garbage collector would otherwise have freed. A
reader held open across a heavy update burst can therefore hold far more space
than its own data, and the amount is not obvious from the outside. Named
checkpoints (`13-operations.md` §1) and reader processes
(`13-operations.md` §8) pin in exactly the same way. An implementation MUST:

- expose the retention watermarks and the age of the oldest live snapshot;
- warn when a snapshot has pinned more than a configurable amount of otherwise
  reclaimable space (default 64 MiB);
- never break a live snapshot to reclaim space.

Abandoned cursors are the realistic failure mode — an undrained Dart `Stream`, a
Rust iterator held too long. The diagnostic exists so the cause is findable.

## 9. Store events

| event | fires |
|---|---|
| `opened` | after the superblock is chosen |
| `commit` | after step G, carrying the new `commit_id` and `visible_seq` |
| `flushed` | when a memtable shard becomes an L0 segment |
| `compacted` | when a compaction publishes, carrying levels and bytes |
| `backpressure` | when the applied write delay changes materially |
| `closing` / `closed` | around release of the writer lock |

Events are delivered after durability, never before.

## 10. Close

```
1. finish or abort in-flight transactions
2. seal open value-log segments
3. flush memtables (policy; default: yes)
4. write a final superblock
5. release the writer lock; delete the lock sidecar **only if no reader slot in
   it is live** (`13-operations.md` §8) — a reader process still holding a slot
   needs the file to keep publishing its pinned `commit_id`
```

An unclean close is not a special case — the file is valid at every commit, and
reopening after a kill takes the same path as after a clean close. There is no
recovery mode and no repair prompt.
