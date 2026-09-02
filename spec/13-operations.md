# CFF-13 — Backup, checkpoints, repair, containment, observability

**Normative.** Assumes `01-container.md`, `04-segments.md`,
`10-transactions.md`.

The operational surface that separates a storage engine from a data structure.
Most of it is unusually cheap here, because **segments are immutable and
identified by a never-reused id** — which turns online backup, incremental
backup and point-in-time recovery into bookkeeping rather than machinery.

---

## 1. Checkpoints

A **checkpoint** is a named, retained snapshot. Reserved tree 8:

```
key   = CKE(STR name)
value = CVE { "commit_id": U64, "seq": U64, "created": TIMESTAMP,
              "catalog_root":    U64, "freelist_root":  U64,
              "attributes_root": U64, "manifest_root":  U64,
              "vlog_stats_root": U64, "changefeed_root": U64,
              "expires": TIMESTAMP? }
```

That is the full `Snapshot` tuple of `10-transactions.md` §1 **less
`checkpoint_root`**, which is deliberately not captured: restoring a checkpoint
must not delete the other checkpoints, so a restore keeps the *current*
`checkpoint_root` and replaces the other eight. An earlier draft omitted
`changefeed_root` as well, which left a restore silently pairing the current
change feed with an older manifest.

Creating one is a single small write; it costs nothing until data diverges.

**Retention.** A checkpoint holds `min_retained_commit` and `min_retained_seq`
down to its own values, exactly as a live reader does
(`10-transactions.md` §8). It therefore **pins space**, and an implementation
MUST:

- report the space each checkpoint pins;
- refuse, by default, to create a checkpoint that would pin more than
  `checkpoint_space_limit` (default: 25 % of the live size), unless the caller
  overrides it;
- honour `expires` and drop the checkpoint automatically past it.

**Opening one.** `open_at(checkpoint)` yields a read-only database at that
snapshot. **Restoring one** rewrites the superblock to the checkpoint's roots;
everything written after it becomes unreachable and is reclaimed. Restore is one
superblock write and is therefore atomic and instant.

**Restore rolls back roots, never counters.** `next_seq`, `next_tree_id`,
`next_segment_id`, `next_vlog_segment_id` and — critically — **`next_nonce`**
keep their current values, and `sb_mac` is recomputed over the result. Rolling
`next_nonce` back would hand out nonce values the abandoned commits already
used, and the pages that used them are still in the file until they are
reclaimed: same key, same nonce, two plaintexts (`14-security.md` §4.1). Ids
that are "never reused" must survive a restore for the same reason a crash does
not reset them.

This gives Nitrite an undo point around a migration or a risky bulk operation
for the price of one tree entry, which is not something the current storage
backends can offer at any price.

## 2. Backup

### 2.1 Online full backup

```
1. take a snapshot (or use a checkpoint)
2. copy the superblock's roots and every extent reachable from them
3. write a fresh superblock into the destination naming the copied extents
```

The source database stays open and writable throughout. Nothing is locked;
nothing is quiesced. That falls out of immutability — every extent the backup
reads is one nothing will ever modify.

The destination is a normal `.cryptand` file with a **new `database_uuid`** and
its `writers` list carried over plus the backup tool's id. An implementation MUST
NOT copy the source's `database_uuid`; two files with the same uuid break
incremental backup and confuse tooling — **and, on an encrypted file, they share
a content key** (`14-security.md` §3.4 derives subkeys with the uuid as HKDF
salt), which makes a nonce that repeats across the two files a real collision.

**Backing up an encrypted database.** Two modes, and an implementation MUST make
the caller choose rather than pick one:

| mode | how | when |
|---|---|---|
| **ciphertext copy** | copy extents byte for byte; the backup needs the source's `database_uuid` and keyslots, so its uuid **cannot** change | an untrusted destination — cloud storage, a shared drive. The backup tool never needs the key |
| **re-encrypted copy** | decrypt and re-encrypt under a fresh master key and a new `database_uuid` | a rotation, a compacting backup, or handing a copy to someone who should have a different credential |

The ciphertext copy is the exception to the new-uuid rule, and the reason is
exactly why the rule exists: the copy is the *same* cryptographic object, so it
must keep the same key binding. Its nonce space is the source's, so an
implementation MUST NOT open a ciphertext copy for **writing** while the source
is also being written — two writers allocating from the same `next_nonce`
lineage collide. A ciphertext copy is a restore source, not a second live
database.

An unencrypted backup of an encrypted database is a silent downgrade. An
implementation MUST refuse it unless the caller asks for it by name, and MUST
report it in the result.

A backup MAY compact as it copies — dropping superseded versions, expired
entries and unreferenced value-log records. A compacting backup is usually
smaller than the source, and it is the recommended way to reclaim space fully.

### 2.2 Incremental backup

Because `segment_id` and `vlog_segment_id` are globally unique and never reused,
an incremental backup is a set difference:

```
copy every segment whose id is absent from the destination's manifest,
then copy the destination's new superblock
```

A backup manifest records the ids present, so an implementation never needs to
diff file contents. Deleted segments are dropped from the destination's manifest
and their extents freed there.

This is exactly the property an LSM's immutable SSTs give and an in-place B-tree
cannot: **an incremental backup's size is proportional to what changed, not to
what the changes touched.**

### 2.3 Restore and verification

Restore is a file copy plus an open. An implementation MUST run the verification
pass (`01-container.md` §9) over a restored file before reporting success, and
MUST report a partial restore as a failure rather than opening a truncated file
in the hope that it works.

## 3. Repair

Verification (`01-container.md` §9) reports; repair fixes. An implementation
SHOULD provide, and the reference implementation MUST:

| damage | repair |
|---|---|
| leaked extents (neither reachable nor free) | add to the free tree |
| corrupt or stale manifest | **rebuild it** by scanning the file for `SEGMENT_HEADER` pages and reading their `level`, `group`, key bounds and seq range — every field the manifest holds is duplicated in the segment header for exactly this reason (`04-segments.md` §2.1) |
| corrupt value-log liveness stats | recompute by scanning segments and resolving pointers. Note that tree 7 also holds the durable `bytes` watermark and the `clustered`/`min_key`/`max_key` of every value-log segment (`04-segments.md` §6.7); a lost entry is rebuilt by scanning the segment's records forward from `data_offset`, accepting the longest prefix whose per-record CRCs all validate, and setting `bytes` to the end of that prefix |
| corrupt free tree | rebuild as the complement of the reachable set |
| a corrupt tree segment | quarantine (§4) and rebuild what is derivable |
| a corrupt index / postings / rtree / vector tree | drop and rebuild from the data tree — every index in this format is derivable (`11-conformance.md` §5) |
| both superblocks invalid | recover from the newest checkpoint if one is intact, else rebuild the manifest and synthesize a superblock. **On an encrypted file the keyslots live only in the superblocks**, so if both are damaged beyond their keyslot bytes the data is unrecoverable by anyone, key or no key. An implementation SHOULD let an application export the 576-byte keyslot area for out-of-band storage, and MUST warn that doing so puts the wrapped key wherever it is stored |
| `sb_mac` or an AEAD tag fails | **not corruption** — tampering. Report it as its own class, name the page, and do not attempt repair: repairing tampered data is laundering it (`14-security.md` §6.2) |
| double-allocated extents | **not repairable**; report precisely which segments and which key ranges are affected |

**The manifest is deliberately redundant with the segment headers.** That
duplication costs a few dozen bytes per segment and is what makes the single most
likely catastrophic failure — a damaged manifest root — into a scan-and-rebuild
rather than a total loss. The redundancy has to be *complete* for the claim to
hold: `group` (`04-segments.md` §2.1) is in the header for no other reason than
this, because it is part of the manifest key and nothing else would recover it.
A verifier MUST check header-against-manifest agreement on every duplicated
field (`04-segments.md` §11, invariant 5), or the redundancy rots unnoticed until
the day it is needed.

Repair MUST be non-destructive by default: write the repaired database beside
the original and swap only after verification.

## 4. Corruption containment

**Normative.** A single damaged page MUST NOT make the whole database
unreadable.

When a page fails its checksum, an implementation MUST:

1. identify the segment or extent it belongs to;
2. report the **affected key range** — a segment's `min_key`/`max_key` from the
   manifest, or the affected tree for an internal tree;
3. **continue serving every key outside that range**;
4. fail reads that land inside it with a specific corruption error naming the
   range, never with a wrong or empty answer;
5. mark the affected trees so that a query planner does not silently substitute
   an index scan that would return incomplete results.

A corrupt segment at a level above the last is often fully recoverable: the
older versions of its keys survive lower down, so dropping it loses only the
updates it held. An implementation SHOULD offer that as an explicit, reported
choice — never as a silent one.

Partial availability matters most on the device where storage is least reliable.
The alternative behaviour, which every engine Nitrite uses today exhibits, is
that one bad block turns a phone user's entire journal into an error message.

## 5. Compaction and space management API

An implementation MUST expose, and all MUST be incremental and resumable
(`12-profiles.md` §4):

| | |
|---|---|
| `compact(range?)` | full or ranged compaction to the last level |
| `collect()` | a value-log GC pass |
| `cluster()` | drive `locality_debt` back under its bound (`04-segments.md` §6.9) |
| `shrink()` | relocate live extents downward and truncate the file |
| `reprofile()` | convert to the current profile's constants (`12-profiles.md` §6) |
| `encrypt()` / `decrypt()` | convert the file's pages to or from encrypted, page by page (`14-security.md` §8.3) |
| `add_key()` / `remove_key()` | add or drop a keyslot — one superblock write, no data touched |
| `rotate_master_key()` | re-encrypt every page and record under a fresh master key |
| `crypto_erase()` | zero every keyslot in both superblock slots; irreversible (`14-security.md` §8.2) |

None may block longer than `max_foreground_stall_ms` per step.

## 6. Observability — required metrics

**An implementation MUST expose the following.** They are normative because
every one of them is the answer to a question that is otherwise unanswerable
from outside, and because the performance claims in `design/performance-model.md`
cannot be validated without them.

**Write path**

| | |
|---|---|
| `bytes_written_logical` | what the application wrote |
| `bytes_written_device` | what reached the device |
| `write_amp_value` / `write_amp_key_index` / `write_amp_gc` | the decomposition — without it, a regression is unattributable |
| `backpressure_delay_ms` | current applied write delay, and why |
| `stall_events` | count and total duration of foreground stalls |

**Space**

| | |
|---|---|
| `live_bytes` / `allocated_bytes` | space amplification |
| `vlog_live_bytes` / `vlog_allocated_bytes` | value-log amplification against its target |
| **`locality_debt`** | `04-segments.md` §6.9 — live value bytes in surplus runs. **This is the number that predicts scan decay**, and it has to be the run-based definition: the earlier flag-based one read 0 % on a database whose scans had already degraded 2.1× |
| `vlog_live_runs` / `vlog_ideal_runs` | the raw counts behind it: how many value-log runs a key-ordered scan interleaves, against how many the live data needs |
| `pinned_by_snapshots` / `pinned_by_checkpoints` | why space is not being reclaimed. **Not derivable as `allocated − live`**: a live snapshot's effect is to stop superseded versions from *becoming* dead, so the bytes it pins never enter that difference and the obvious derivation reads **0** on a database holding a large pinned set. Accumulate it where the retention decision is made — the bytes of every entry a compaction kept solely because `10-transactions.md` §5's condition 2 was not met |
| `unencrypted_pages` | 0 on a fully encrypted file; non-zero mid-conversion. An implementation MUST NOT report a database as encrypted while this is above 0 (`14-security.md` §8.3) |
| `nonces_allocated` / `nonce_floor` | headroom to the next published floor (`14-security.md` §4.1) |

**Read path**

| | |
|---|---|
| `page_cache_hit_rate` | |
| `segments_probed_per_lookup` (p50/p99) | validates the bounded read tail |
| `filter_false_positive_rate` | validates §2.4's bit allocation |
| `value_reads_per_scanned_row` | validates readahead and clustering. **Measured 0.100 when clustering is working and 1.038 when it is not** (`reference/dart/cryptand/bench/p8_aged_scan.dart`); an earlier draft estimated 0.13 and 1.0 |

**Structure**

| | |
|---|---|
| segment count and bytes per level | |
| `oldest_snapshot_age_ms` | the usual cause of unreclaimed space |
| `compaction_backlog_bytes` | |
| **`unavailable_ranges`** | key ranges §4 has taken out of service after a checksum failure, and the trees they affect. **0 is the normal state.** Without it §4's containment is observable only by *hitting* it: a caller has no way to ask whether the database is whole, so a partially-available database looks identical to a healthy one until a read happens to land in the hole. An implementation MUST expose the count and SHOULD expose the ranges |

`value_reads_per_scanned_row` and `locality_debt` deserve emphasis: they are the
two numbers that detect the format's most insidious failure mode — a database
whose scans decay with age — long before a user notices.

## 7. Change feed

Optional, per tree, `params.change_feed = true` (`05-catalog.md` §3.1).
Reserved tree 9:

```
key   = CKE(Array[ U32 tree_id, U64 seq ])
value = CVE { "op": STR, "key": BYTES, "id": NITRITE_ID? }
```

Entries are appended in the same batch as the mutation, so the feed is exactly
consistent with the data. `read_changes(tree, from_seq)` is a range scan, and
because the key is `(tree_id, seq)` it is sequential.

Retention is `changefeed_retain_seq` or `changefeed_retain_ms`, whichever is
reached first; compaction drops entries past it.

This exists because Nitrite has a replication layer, and the alternative — a full
scan comparing `_revision` fields — is the thing every sync implementation does
badly. A monotonic per-record `seq` is already in the format
(`04-segments.md` §1); the feed just makes it addressable in seq order.

It is **optional and off by default**, because it costs a write per mutation and
most databases do not sync.

## 8. Multi-process readers

Feature bit `MULTIPROC_READ`. **One writing process, any number of reading
processes.** (Multi-process *writing* remains `MULTIPROC`, reserved.)

Immutability makes reading from another process nearly free: a reader opens the
file, reads a superblock, and every extent it names is one nothing will modify.
The only coordination needed is retention — the writer must not reclaim extents a
reader still holds.

Protocol, via the lock sidecar `<name>.cryptand-lock`:

```
header:  u32 magic, u32 slot_count, u64 writer_pid, u64 writer_heartbeat_ms
slots:   slot_count × { u64 pid, u64 commit_id, u64 heartbeat_ms }
```

1. A reader claims a free slot with a compare-and-swap and publishes the
   `commit_id` it pinned, refreshing `heartbeat_ms` at least every
   `reader_heartbeat_ms` (default 2000).
2. The writer computes `min_retained_commit` as the minimum over its own
   snapshots **and** every live slot.
3. A slot whose heartbeat is older than `3 × reader_heartbeat_ms` is reclaimed;
   the reader MUST detect that its slot was reclaimed — its own `pid` no longer
   present — and MUST reopen rather than continue against possibly-freed extents.
4. A reader that cannot write the sidecar (read-only filesystem) MUST open in
   **volatile mode**: it may read the current snapshot and MUST revalidate the
   superblock before each operation, accepting that a long scan may fail if the
   writer reclaims underneath it. It MUST report that it is in volatile mode.

The motivating case is ordinary: a CLI, a `dbinspect` bridge, or a background
service reading a database a running application owns — today impossible with
every backend Nitrite uses.

## 9. Statistics for the query planner

Maintained at compaction, stored in each index tree's catalog descriptor under
`params.stats` (`05-catalog.md` §3.1):

```
params.stats = {
    "updated_seq": U64, "entries": U64, "distinct_estimate": U64,
    "null_count": U64, "min_key": BYTES, "max_key": BYTES,
    "histogram": ARRAY[ { "bound": BYTES, "cumulative": U64 } ]
}
```

`distinct_estimate` comes from a HyperLogLog sketch computed during the
last-level compaction that produced the segment — free, because that compaction
already touches every key. The sketch is chosen for the property that makes it
usable at all here: it is **mergeable and fixed-size**, so a compaction
accumulates it in a few hundred bytes while streaming and two segments' sketches
combine by register-wise maximum. An exact distinct count needs memory
proportional to cardinality, which a compaction cannot afford.

The histogram is equi-depth, bounds being CKE keys so a planner can compare them
without decoding.

**Its size is bounded in bytes, not only in buckets, and the byte bound is the
binding one.** `params.stats` lives inside a catalog descriptor, and a catalog
descriptor is **one cell of a copy-on-write B+tree** (`04-segments.md` §3.3),
so it MUST fit one page. A CKE key runs to kilobytes (`00-conventions.md` §8),
so a bucket *count* does not bound the histogram's size at all: the reference
implementation measured 64 bounds over 300 string keys at **4734 B against a
4096 B page**, and the descriptor could not be written.

A writer therefore MUST reduce the bucket count until the encoded
`params.stats` fits the descriptor's page budget, and SHOULD do so by dropping
alternate buckets — which keeps the histogram equi-depth at twice the width
rather than truncating its range. **64 buckets is a maximum, not a target.**

This is safe for exactly one reason, and it is the reason the next paragraph
gives: statistics are advisory, so a coarser histogram is a worse estimate and
never a wrong answer.

Nitrite's `FindPlan` currently chooses an index by static descriptor properties —
uniqueness and field count — with no idea of selectivity. Real statistics let it
choose the *selective* index rather than the *unique-looking* one, and let it
decide between an index scan and a collection scan on evidence.

**Statistics are advisory.** They may be stale or absent; a planner MUST produce
correct results without them, and MUST NOT refuse to run because they are
missing.
