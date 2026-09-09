# CFF-12 — Device profiles

**Normative.** Assumes `01-container.md`, `04-segments.md`.

Nitrite runs on phones, tablets, desktops and servers, and the right storage
engine for those is not the same engine. A phone has 200–500 µs random reads,
a few megabytes of memory to spare, a thermal budget, a battery, and a UI thread
that drops a frame if anything blocks for 16 ms. A server has 20 µs random
reads, gigabytes of cache, and cares about nothing but throughput.

A **profile** is a named set of tuning constants. It is recorded in the
superblock, it changes only *how a writer behaves*, and it changes **nothing
about how a file is read**. A file written under `mobile` and a file written
under `server` are the same format, mutually readable, and either can be
converted to the other by ordinary compaction.

---

## 1. The profiles

| | `mobile` | `tablet` | `desktop` | `server` |
|---|---|---|---|---|
| **superblock `profile`** | 1 | 2 | 3 | 4 |
| typical dataset | 10 MB – 1 GB | 50 MB – 4 GB | 100 MB – 100 GB | 1 GB – 10 TB |
| **`page_size`** | 4 KiB | 4 KiB | 8 KiB | 16 KiB |
| page cache budget | 4 MiB | 16 MiB | 64 MiB | 512 MiB |
| memtable budget (total) | 2 MiB | 8 MiB | 32 MiB | 256 MiB |
| **`memtable_shards`** | 1 | 2 | 8 | 32 |
| **`vlog_min`** (MUST be ≤ `page_size`/4) | **1024** | **1024** | **2048** | **4096** |
| `blob_threshold` | 65536 | 131072 | 262144 | 262144 |
| **`l0_trigger`** | 2 | 4 | 4 | 8 |
| **`fanout`** | 4 | 6 | 8 | 10 |
| **`tier_width`** | 2 | 3 | 4 | 6 |
| **`overlap_bound`** | 1 | 2 | 2 | 3 |
| segment target size | 2 MiB | 8 MiB | 32 MiB | 128 MiB |
| **`vlog_segment_bytes`** | 4 MiB | 16 MiB | 64 MiB | 256 MiB |
| `page_codec` | **0** | 0 | 0 | 0 |
| filter bits, upper / last | 12 / 10 | 14 / 10 | 16 / 10 | 16 / 10 |
| **`vlog_space_target_pct`** | 120 | 130 | 150 | 150 |
| **`locality_debt_pct`** | 20 | 20 | 20 | 25 |
| **`readahead_window`** | 128 | 256 | 256 | 1024 |
| `compaction_threads` | 1 | 2 | 4 | 8 |
| **`compaction_step_bytes`** | 256 KiB | 1 MiB | 8 MiB | 32 MiB |
| **`max_foreground_stall_ms`** | **8** | 8 | 25 | 100 |
| Argon2id `t_cost` / `m_cost_kib` / `parallelism` | 3 / 64 MiB / 1 | 3 / 128 MiB / 2 | 4 / 256 MiB / 4 | 4 / 256 MiB / 4 |
| compaction scheduling | idle / charging only | idle-preferred | continuous, paced | continuous, paced |
| durability default | `sync` | `sync` | `sync` | `sync` |

Bold rows are the ones where the profiles differ enough to change the engine's
character rather than merely its constants.

**`page_codec` is 0 in every profile**, and it used to be LZ4 in every profile.
`01-container.md` §7 carries the measurement: a page is a fixed-size slot, so a
compressed page occupies the same slot and is written with the same
`page_size`-byte write — identical bytes to device, identical page count,
identical file size, at 20 000 documents. It cost CPU and leaked
compressibility through the cleartext `payload_len` and saved nothing. The row
is kept rather than deleted because a writer may still set it deliberately, and
because **a reader MUST decode a compressed page whatever this row says**.

## 2. What each profile is optimising, and why

### 2.1 `mobile` — read latency, memory, and never dropping a frame

**`vlog_min` at its ceiling is the defining choice.** Documents stay inline, so
a point read costs **one** I/O rather than two, and there is no scan-locality
problem to manage at all. Only genuine attachments — images, audio, blobs —
separate, and those are exactly the values that should not be re-merged.

The number is **1024**, not 4096. `vlog_min` MUST be ≤ `page_size / 4`
(`00-conventions.md` §8), which is the largest value a leaf cell can hold, and
`mobile` uses 4 KiB pages. An earlier draft said 4096 here, which would have sent
every value between 1 KiB and 4 KiB into an overflow chain — two I/Os, exactly
the cost inlining was chosen to avoid, and the opposite of what the number was
meant to buy.

1024 still keeps the documents this format is shaped for inline: the assumed
20-field, ~500-byte document (`design/performance-model.md` §1) sits comfortably
under it, and so does the great majority of what a note, journal or contacts app
stores. An application that genuinely wants a higher threshold raises `page_size`
at creation — 8 KiB pages give a 2048-byte ceiling — and pays for it in page
cache granularity, which is the honest trade rather than a number that cannot be
honoured.

The justification is arithmetic, not taste. Key–value separation buys write
amplification; a phone-scale workload writes single-digit megabytes a day, so
the saving is a few tens of megabytes a day of device traffic — invisible
against a 128 GB device's endurance. What a phone user *does* feel is a 400 µs
random read on every document fetch, and paying two of those instead of one is a
real, visible regression on exactly the operation a note or journal app performs
most.

The rest follows from memory and thermals:

- **One memtable shard, one compaction thread.** An embedded database on a
  phone usually shares its execution context with the UI, and on a runtime with
  no shared-memory threads there is nothing to shard *across* — sharding would
  cost memory and buy nothing. (Flutter is the worked example; the constant is
  chosen for the shape, not the framework.)
- **`overlap_bound = 1`** — tiered levels are fully range-partitioned, so a
  point lookup touches exactly one segment per level. Read tail over throughput.
- **Small segments (2 MiB) and small compaction steps (256 KiB)** so compaction
  is fine-grained and interruptible.
- **`max_foreground_stall_ms = 8`**, half a frame. See §4.
- **`vlog_space_target_pct = 120`** — storage is scarce and shared with photos;
  space matters more than the GC work it costs.
- **Compaction only when idle or charging.** See §5.
- **Argon2id at 64 MiB, not 256.** Password stretching is the one moment an
  encrypted `mobile` database wants far more memory than its whole steady-state
  budget — 64 MiB against a 4 MiB page cache — and it is transient, once per
  open, ~250 ms (`14-security.md` §3.2). Cost parameters live in the keyslot,
  not in the profile constant, so a file created on a phone still opens at phone
  cost after a desktop has written to it.

### 2.2 `tablet` — the same shape, with room

Larger datasets and a bigger battery, so a middle setting: separation begins at
1 KiB, two shards, two compaction threads, Zstd at the last level. Still
frame-budget-aware, because tablets run the same Flutter UI.

### 2.3 `desktop` — the balanced default

The profile the rest of this specification quotes. Eight memtable shards, four
compaction threads, continuous paced compaction, 8 KiB pages, and separation at
a quarter page.

### 2.4 `server` — throughput

16 KiB pages, 32 memtable shards, aggressive tiering (`fanout = 10`,
`tier_width = 6`), a 1024-entry readahead window, and a 100 ms foreground stall
allowance because there is no frame budget to protect.

### 2.5 `vlog_min` is at its ceiling in every profile, and that is a change

`desktop` and `server` separated at **256 bytes** until this revision. §2.1's
argument for `mobile` was written as if it were a phone argument — 400 µs random
reads, a UI thread — and it is not. It is an argument about **document
databases**, and it applies wherever one runs:

- §1 of `design/performance-model.md` fixes this format's reference document at
  20 fields and ~500 bytes; encoded, the one the benchmarks use is **639
  bytes**. At `vlog_min = 256` that document is separated. Every write of one
  costs a `pwrite` of its own, every read of one costs a second fetch, and a
  `vlog_segment_bytes` extent — 64 MiB on `desktop` — is preallocated to hold
  what fits in the tree.
- Measured on the CRUD matrix at 20 000 such documents, moving the cut-off above
  the document was worth **2.5× on create and 2× on point read**, and took the
  file from 137 MB to a size dominated by real data rather than by reserved
  value-log space.
- What separation buys is write amplification, and that is worth buying for
  **attachments** — an image, an audio clip, a blob — which is what
  `blob_threshold` and the value log are for. It is not worth two I/Os per
  document fetch on the operation an application performs most.

So every profile now sits at the ceiling `00-conventions.md` §8 sets:
`page_size / 4`, which is 1024 at 4 KiB, 2048 at 8 KiB and 4096 at 16 KiB. An
application whose values are genuinely large still gets separation, because they
exceed the threshold; an application storing documents no longer pays for a
value log it does not need.

**This changes nothing about the format.** `vlog_min` is a superblock field and
a *writer's* choice (§3): a file written under the old constant and one written
under the new one are the same format, mutually readable, and either converts to
the other by ordinary compaction. A reader MUST continue to resolve a `vlog`
cell of any size.

## 3. Profiles are a writer's choice, never a reader's

**Normative.** The superblock's `profile` field is **advisory metadata**. A
reader MUST NOT change its behaviour based on it, and MUST NOT refuse a file
because of it.

Every profile-dependent constant is either:

- recorded in the superblock as its own field (`vlog_min`, `fanout`,
  `l0_trigger`, `tier_width`, `overlap_bound`, `page_size`, …), so a reader uses
  the *value*, never the profile name; or
- purely about the writer's runtime behaviour (thread counts, pacing, stall
  budgets), which leaves no trace in the file.

The consequence is the property that matters: **a database created on a phone
opens unchanged on a desktop, and vice versa.** Nothing about a profile is
baked in.

## 4. The foreground stall budget

**Normative for every profile.** An implementation MUST NOT block a caller's
thread for longer than `max_foreground_stall_ms` in any single operation that
the application did not explicitly request as a bulk operation.

This binds:

- compaction steps (`04-segments.md` §5.2);
- value-log garbage collection passes;
- clustering passes;
- `compact()` and other maintenance, which MUST be incremental and resumable;
- segment builds during a memtable flush.

On `mobile` the budget is **8 ms** — half of a 60 Hz frame — because an embedded
database on a phone frequently shares its execution context with the UI. An
engine that stalls 120 ms to finish a compaction is, from the user's side,
indistinguishable from a janky app, and no amount of throughput compensates. The
number comes from the frame, which every UI toolkit has; it is not a property of
any one of them.

Meeting the budget is what §5.2 of `04-segments.md` exists for: every long
operation in this format decomposes into bounded steps, because every long
operation writes immutable output that can simply be abandoned mid-way.

## 5. Host hints

An implementation SHOULD accept, and an application SHOULD supply, three hints:

| hint | meaning | effect |
|---|---|---|
| `idle` | no user interaction in progress | run deferred compaction, GC and clustering |
| `charging` | on external power | raise `compaction_bytes_per_sec`; allow full-file maintenance |
| `thermal_pressure` | device is hot or throttled | reduce compaction threads to 1 and pacing to a trickle; never stop entirely |

On `mobile` and `tablet`, non-urgent maintenance SHOULD be deferred until `idle`
or `charging`. "Non-urgent" means everything except what backpressure requires
to keep the write path healthy (`10-transactions.md` §6) — the engine must never
deadlock waiting for a hint that never arrives.

Compaction is the largest discretionary consumer of battery and thermal headroom
in an embedded database, and only the host knows when spending it is acceptable.
An engine that compacts hard while the user is scrolling has optimised the wrong
number.

**Thermal behaviour is measured, not modelled.** An implementation targeting
mobile SHOULD validate on a real mid-range device under sustained load, because
big.LITTLE scheduling and thermal throttling on such a device do not resemble
anything a desktop or an emulator will show.

## 6. Switching profiles

A file's profile can be changed. `set_profile(p)` writes the new constants into
the superblock; from that commit onward, new writes follow them.

Existing data converts **lazily, through ordinary compaction**:

| change | how existing data converts |
|---|---|
| `vlog_min` lowered | values above the new threshold move to the value log as segments are rewritten; until then they stay inline, which is always valid |
| `vlog_min` raised (e.g. mobile → desktop, or a file written before §2.5) | values below the new threshold are re-inlined during compaction; the vacated value-log segments become garbage and are collected |
| `fanout`, `tier_width`, `overlap_bound` | the next compactions produce the new shape |
| filter bits | new segments get the new rate; old segments keep theirs |
| `page_codec` | per page, so a mixture is normal |
| **`page_size`** | **cannot change.** It is fixed at creation. Changing it requires a full copy through `13-operations.md` §2. |

An implementation MAY offer `reprofile()` to force the conversion eagerly rather
than waiting for organic compaction. It MUST be incremental and resumable.

This is what makes the phone/desktop story real rather than theoretical: a
Flutter app writes a `mobile`-profile database, a desktop tool opens it, calls
`set_profile(desktop)`, and the file reorganises itself for the machine it is now
on — without an export, an import, or a moment where the data is unreadable.

## 7. Auto-detection

An implementation MAY select a profile automatically at creation. Reasonable
signals, in order of usefulness:

1. an explicit application setting — always wins;
2. the platform (`Platform.isAndroid`/`isIOS` → `mobile`, screen size or
   `isTablet` → `tablet`);
3. physical memory and core count;
4. measured random-read latency of the target directory, sampled once at
   creation — the most honest signal of all, and the one that correctly
   classifies an SD card, a network mount, or a desktop still on a spinning
   disk.

An implementation that auto-detects MUST record which profile it chose and MUST
let the application override it. Silent auto-tuning that cannot be inspected is
worse than a wrong default.

## 8. Custom profiles

`profile = 0` means "custom": every constant is read from its own superblock
field and no named profile is implied. Tooling SHOULD display the constants
rather than a name.

Nothing in the format privileges the four named profiles; they exist so that the
common cases have a good answer without the application tuning fifteen numbers.
