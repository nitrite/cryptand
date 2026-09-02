# CFF-01 — Container

**Normative.** Assumes `00-conventions.md`.

---

## 1. File layout

```
page 0    superblock slot A          (page_size bytes, first 4096 significant)
page 1    superblock slot B
page 2+   pages and extents, in allocation order:
            · tree segments        (04 §2)   — immutable, bulk-written
            · value-log segments   (04 §6)   — append-only, then sealed
            · blob extents         (§5)
            · copy-on-write B+tree pages of the internal trees (04 §3.3)
            · overflow pages
            · vector flat regions
```

Slots A and B are written **alternately**: the commit at `commit_id = N` writes
slot `A` if `N` is odd, slot `B` if `N` is even, so a crash during a superblock
write leaves the previous superblock intact.

Every write to the file is either an append into fresh space or an append into
the open tail of a value-log segment. **No page that a live superblock
references is ever overwritten.** That single rule is what makes recovery O(1)
and makes torn pages impossible.

## 2. Superblock

Exactly 4096 bytes, regardless of `page_size`, at offset `0` (slot A) and offset
`page_size` (slot B).

| off | size | field | notes |
|---|---|---|---|
| 0 | 8 | `magic` | `43 52 59 50 54 41 4E 44` — `"CRYPTAND"`, exactly 8 ASCII bytes, no padding |
| 8 | 2 | `version_major` | `1` |
| 10 | 2 | `version_minor` | |
| 12 | 2 | `write_version_minor` | minimum minor version required to modify |
| 14 | 2 | `page_size_log2` | 12…16 |
| 16 | 8 | `commit_id` | monotonic, `≥ 1` |
| 24 | 8 | `features_required` | bitmap; unknown bit ⇒ refuse to open |
| 32 | 8 | `features_optional` | bitmap; unknown bit ⇒ ignore, preserve |
| 40 | 8 | `page_count` | pages in use; the file MAY be longer |
| 48 | 8 | `visible_seq` | every record with `seq ≤ visible_seq` is committed |
| 56 | 8 | `next_seq` | next sequence number to allocate |
| 64 | 8 | `catalog_root` | tree 0 |
| 72 | 8 | `freelist_root` | tree 1 |
| 80 | 8 | `attributes_root` | tree 2 |
| 88 | 8 | `manifest_root` | tree 6 — the segment manifest (`04` §3.2) |
| 96 | 8 | `vlog_stats_root` | tree 7 — value-log liveness (`04` §6.7) |
| 104 | 8 | `min_retained_commit` | pages freed at or below this are allocatable |
| 112 | 8 | `min_retained_seq` | versions older than this may be collapsed |
| 120 | 8 | `next_tree_id` | |
| 128 | 8 | `next_segment_id` | tree segments |
| 136 | 8 | `next_vlog_segment_id` | value-log segments |
| 144 | 8 | `created_utc_ms` | |
| 152 | 8 | `modified_utc_ms` | |
| 160 | 16 | `database_uuid` | RFC 4122 v4, stable for the life of the file |
| 176 | 1 | `durability_achieved` | 0 none, 1 os, 2 sync, 3 full |
| 177 | 1 | `page_codec` | 0 none, 1 LZ4, 2 Zstd |
| 178 | 1 | `cipher` | 0 none, 1 XChaCha20-Poly1305 |
| 179 | 1 | `level_count` | levels currently in use, 1…16 |
| 180 | 1 | `fanout` | tiering / levelling fanout |
| 181 | 1 | `l0_trigger` | L0 segments before compaction |
| 182 | 1 | `tier_width` | segments per tiered level |
| 183 | 1 | `memtable_shards` | 1…64 — advisory, a reader ignores it |
| 184 | 4 | `vlog_min` | inline/value-log cut-off in bytes (`04-segments.md` §6.5) |
| 188 | 4 | `blob_threshold` | value-log/blob cut-off in bytes |
| 192 | 4 | `vlog_segment_bytes` | target sealed size |
| 196 | 4 | `vlog_space_target_pct` | space-amplification ceiling ×100 |
| 200 | 8 | `live_key_bytes` | estimate, for tooling |
| 208 | 8 | `live_value_bytes` | estimate, for tooling |
| 216 | 1 | `profile` | 0 custom, 1 mobile, 2 tablet, 3 desktop, 4 server — **advisory** (`12-profiles.md` §3) |
| 217 | 1 | `overlap_bound` | max segments per tiered level covering one key (`04` §3.1) |
| 218 | 1 | `locality_debt_pct` | ceiling on unclustered live value bytes (`04` §6.9) |
| 219 | 1 | `filter_bits_upper` | filter bits/key at L0 and tiered levels |
| 220 | 1 | `filter_bits_last` | filter bits/key at the last level |
| 221 | 3 | reserved | |
| 224 | 4 | `readahead_window` | minimum cursor value-readahead window (`04` §8.1) |
| 228 | 4 | `segment_target_bytes` | target size of a compaction output segment |
| 232 | 8 | `checkpoint_root` | tree 8 — named checkpoints (`13-operations.md` §1) |
| 240 | 8 | `changefeed_root` | tree 9 — change feed, 0 if unused (`13-operations.md` §7) |
| 248 | 8 | reserved | |
| 256 | 32 | `writer_id` | UTF-8, zero-padded, e.g. `"nitrite-rust/0.5.0"` |
| 288 | 8 | `next_nonce` | monotonic AEAD nonce counter; never reused (`14-security.md` §4.1) |
| 296 | 32 | `sb_mac` | keyed MAC over this superblock; zero when `cipher = 0` (`14-security.md` §6.2) |
| 328 | 3184 | reserved | |
| 3512 | 576 | `keyslots` | 4 × 144 bytes; the wrapped master key (`14-security.md` §3.3) |
| 4088 | 4 | reserved | |
| 4092 | 4 | `checksum` | CRC-32C over bytes `0…4091` |

`next_nonce`, `sb_mac` and `keyslots` are meaningful only when `cipher ≠ 0` and
are written as zero otherwise. They replace the single `kdf_params` field an
earlier draft placed at offset 4024: one KDF slot cannot express a password
change without re-encrypting the file, and it left the superblock — including
`cipher` itself — unauthenticated. `14-security.md` §3.1 and §6.1 are the
arguments.

There is **no run list in the superblock**. Segments live in the manifest tree
(`04` §3.2), which is rooted at `manifest_root`, so the number of segments is
unbounded by the superblock's size and a compaction publishes by writing one
small copy-on-write path plus one superblock.

**Every tuning constant is stored as its own field, never derived from
`profile`.** A reader uses the values; the profile name is metadata for tooling
and for a writer picking defaults (`12-profiles.md` §3). This is what makes a
phone-written and a server-written database the same format.

### 2.1 Open procedure

1. Read 4096 bytes at offset 0 and at offset `page_size`.
2. For each: verify `magic`, `checksum`, `version_major == 1`.
3. Choose the valid slot with the greater `commit_id`. If neither is valid, the
   file is not a Cryptand database, or is corrupt beyond container-level repair.
4. If `cipher ≠ 0`: unwrap the master key from a keyslot and **verify `sb_mac`
   before reading any other field** (`14-security.md` §6.2). A mismatch is
   tampering, reported distinctly from corruption; nothing further is read.
5. If `features_required` holds any unknown bit, refuse to open and name it.
6. If `write_version_minor` exceeds the implementation's minor version, open
   read-only.
7. Ignore everything at or beyond `page_count` — debris from an interrupted
   commit.
8. A writer durably publishes a superblock with `next_nonce` advanced by 2²⁰
   **before allocating any nonce** (`14-security.md` §4.1), and seals every
   unsealed value-log segment (`14-security.md` §4.3).

No log replay. Open is O(1) in database size.

## 3. Page header

Every page except the two superblocks begins with a 40-byte header — with one
exception, stated here because three chapters depend on it:

**A multi-page extent carries a page header only on its head page.** The interior
pages of a value-log segment (`04-segments.md` §6.2), a blob (§5) and a vector
region (`09-vector.md` §2) hold raw payload with no header and no per-page
checksum, because their payload is a byte stream that crosses page boundaries.
Integrity for those bytes comes from the extent's own mechanism: a per-record
`crc32c` for value-log records, the `crc32c` in the 16-byte blob pointer for a
blob, and — for a vector region — nothing, deliberately, because a region is
rebuildable from the documents (`09-vector.md` §7) and a per-vector checksum
would cost more than it protects. A verifier MUST use the extent's mechanism for
these pages and MUST NOT report a missing page header on them as corruption.

The header is **40 bytes**:

| off | size | field | notes |
|---|---|---|---|
| 0 | 4 | `checksum` | CRC-32C over bytes `4…page_size-1`, **as stored** |
| 4 | 1 | `page_type` | §4 |
| 5 | 1 | `flags` | bit0 `COMPRESSED`, bit1 `ENCRYPTED`, bit2 `HAS_OVERFLOW`, bit3 `EXTENT_HEAD` |
| 6 | 2 | `codec_or_reserved` | codec id when `COMPRESSED` |
| 8 | 4 | `tree_id` | owning tree; `0xFFFFFFFF` for segment, value-log, blob and vector-region pages. `0xFFFFFFFF` is therefore never a valid `tree_id` (`00-conventions.md` §7) |
| 12 | 4 | `extent_pages` | 1 for an ordinary page; > 1 for a multi-page extent head |
| 16 | 8 | `commit_id` | commit that wrote this page — drives reclamation |
| 24 | 4 | `payload_len` | uncompressed, unencrypted payload length |
| 28 | 4 | reserved | |
| 32 | 8 | `nonce` | the allocated `next_nonce` value when `flags.ENCRYPTED`; 0 otherwise (`14-security.md` §4.2) |

`checksum` verifies before decompression and before decryption, so a corrupt
page is never fed to a codec or a cipher.

**Why 40 and not 32.** An earlier draft declared a 32-byte header over a field
table whose widths sum to 36, with `commit_id` (8 bytes at offset 12) running
into `extent_pages` at 16 — an overlap no reader could have implemented, and one
that survived three review passes because nobody added the column up. Adding the
`nonce` needed 8 more. Every field above is naturally aligned within the header,
which is a property worth having even though `00-conventions.md` §5 forbids
*assuming* alignment, and 40 bytes costs 0.2 % of a 4 KiB page.

## 4. Page types

| id | type | defined in |
|---|---|---|
| 0 | `FREE` | §6 |
| 1 | `BTREE_INTERNAL` | `04-segments.md` §2.2 |
| 2 | `BTREE_LEAF` | `04-segments.md` §2.2 |
| 3 | `OVERFLOW` | §5 |
| 4 | `BLOB` | §5 |
| 5 | `SEGMENT_HEADER` | `04-segments.md` §2.1 |
| 6 | `SEGMENT_FILTER` | `04-segments.md` §2.4 |
| 7 | `VLOG_SEGMENT` | `04-segments.md` §6.2 |
| 8 | `RTREE_INTERNAL` | `08-spatial.md` |
| 9 | `RTREE_LEAF` | `08-spatial.md` |
| 10 | `VECTOR_REGION` | `09-vector.md` |
| 11 | `POSTINGS_BLOCK` | `07-fulltext.md` |
| 12–191 | reserved for future minor versions | |
| 192–255 | **implementation-private**; a reader MUST ignore these pages and MUST NOT reuse their space unless it also owns the feature bit that allocated them | |

## 5. Overflow and blobs

`04-segments.md` §6 covers the ordinary case: values at or above `vlog_min` go
to the value log. Two other mechanisms exist.

**Overflow** — for an inline value that exceeds the inline limit
(`page_size / 4`) but that the writer chose not to separate. Because
`vlog_min` MUST be ≤ `page_size / 4` (`00-conventions.md` §8), the ordinary
write path never produces an overflow chain: anything too large to inline is at
or above `vlog_min` and goes to the value log or a blob. Overflow exists for the
one case that bypasses the value log — a tree with `params.inline_values = true`
(`04-segments.md` §6.5) holding a value larger than a quarter page.

The leaf cell stores the first fragment plus a `u64` overflow page id; each
overflow page is a full page with its own 40-byte header, and its payload is:

```
page header (32)
u64  next_page_id     (0 = last)
u32  fragment_len
bytes(fragment_len)
```

**Blob** — for a value at or above `blob_threshold` (256 KiB on `desktop`;
`12-profiles.md` §1 gives the value for each profile). `byte_len` below is the
**plaintext** length; an encrypted blob is chunked per page and is slightly
larger on disk (`14-security.md` §5.4). The leaf cell stores a 16-byte blob
pointer:

```
u64 start_page
u32 byte_len
u32 crc32c
```

The blob occupies a contiguous, page-aligned extent whose head page has
`page_type = BLOB`, `flags.EXTENT_HEAD` set, and `extent_pages` covering the
extent. Payload begins after the head page's 40-byte header.

A blob is its own extent, so a very large value is reclaimed on its own rather
than pinning a shared value-log segment, and it can be memory-mapped directly.
A blob is never rewritten by compaction (`04-segments.md` §6.8).

## 6. Space management

**Allocation unit is the extent** — one or more contiguous pages.

Tree 1 (the free tree) maps

```
key   = CKE(Array[ commit_id : u64, start_page : u64 ])
value = CVE( { "pages": u32 } )
```

Keying by `commit_id` first means a scan from the beginning yields the oldest,
most-reclaimable extents first.

**Reclamation rule.** An extent freed at `commit_id = N` may be reallocated once
`N ≤ min_retained_commit`, the greatest commit id such that no live reader holds
a snapshot at or below it.

Allocation order:

1. Best-fit from the free tree among extents with `commit_id ≤ min_retained_commit`.
2. Failing that, extend the file at `page_count`.

An implementation MAY grow the file in chunks larger than the request
(`fallocate`, `SetFileValidData`); `page_count`, not the file length, defines
what is in use. Preallocating in large chunks is strongly recommended: it keeps
segment extents physically contiguous, which is what lets a segment be written
with one sequential I/O.

**Shrinking.** `compact()` relocates live extents downward and truncates. It is
an ordinary sequence of commits and is interruptible.

There is deliberately no chunk garbage collector. Freeing space never requires
rewriting live pages.

## 7. Compression

Per page and per value-log record, never per file.

- `page_codec` is the **default** for newly written pages; a page's actual state
  is in its own `flags.COMPRESSED` and `codec_or_reserved`, so a file may hold a
  mixture and a codec may change without a rewrite.
- Codec ids: `0` none, `1` **LZ4 block format** (raw block, no frame header;
  `payload_len` gives the decompressed size), `2` **Zstd** (raw block).
- LZ4 is the default and the only codec a Level-0 implementation MUST support.
  Zstd is feature bit `ZSTD`; a writer setting `page_codec = 2` MUST set it in
  `features_required`.
- A page is stored compressed only if compression saves ≥ 12.5 % of the page.

**Compression before encryption leaks length.** `payload_len` is in the clear,
so how well a page compressed is observable. Where an attacker can influence
some of a page's content and watch the file, that is the CRIME/BREACH shape.
An implementation MUST offer `page_codec = 0` on an encrypted file and SHOULD
default to it for a tree the application marks sensitive
(`14-security.md` §7).
- Value-log records are compressed individually, flagged in the segment header's
  `codec`. Compressing individually (rather than per block) keeps a single-record
  read to one decompression.

An implementation SHOULD apply a heavier codec to segments at the last level
(cold, read-mostly, rarely rewritten) than to L0. The codec is per page, and
`12-profiles.md` makes this a profile default from `tablet` upward.

**Zstd dictionaries** (feature bit `ZDICT`) address the case this format sees
most: many small, structurally similar documents, where a per-page codec has too
little context to work with. A dictionary trained on a sample of a tree's values
is stored as a blob and named in the tree's catalog descriptor
(`params.zdict`); pages and value-log records compressed against it carry the
dictionary id in `codec_or_reserved`. A dictionary is immutable once written —
retraining produces a new one, and old data keeps referencing the old one until
it is rewritten. Typical gain on small JSON-shaped records is 2–3× beyond plain
Zstd, which on a phone is the difference between a 200 MB and an 80 MB
database.

## 8. Encryption

Optional, feature bit `CIPHER`, `cipher = 1` for **XChaCha20-Poly1305**.
**`14-security.md` is the specification**; this section states only the
container-level facts the rest of this chapter depends on.

- **Scope: page payloads, value-log records, and the payload of a blob or vector
  extent.** The 40-byte page header, a value-log segment's head page, and both
  superblocks are written in the clear, so structure, checksums, free-space
  accounting, verification and repair all work **without the key**. Sizes,
  page types and per-tree page counts are visible to an attacker; content is
  not. `14-security.md` §7 enumerates exactly what that leaks.
- Encryption is **per page**, flagged in `flags.ENCRYPTED` and not inferred from
  `cipher`, so a file may hold a mixture while a conversion is in progress
  (`14-security.md` §8.3) — the same per-cell discipline that lets `value_kind`
  and `page_codec` vary within one file.
- Order is **compress, then encrypt** on write; **verify checksum, decrypt, then
  decompress** on read (§7, §6 of `00-conventions.md`).
- The 16-byte Poly1305 tag is appended and is inside `payload_len`.
- The superblock is authenticated by `sb_mac`, because an attacker who can edit
  it can otherwise set `cipher = 0` or weaken the KDF cost
  (`14-security.md` §6).

An implementation that cannot perform XChaCha20-Poly1305, Argon2id, HKDF-SHA256
and HMAC-SHA256 MUST refuse to open an encrypted file rather than partially read
it.

## 9. Integrity checking

A conforming implementation MUST expose a verification pass that:

1. validates both superblocks;
2. walks the manifest and every segment, verifying page checksums, key order,
   separator invariants, `subtree_entries`, and each segment's declared key and
   seq ranges;
3. verifies that segments at a levelled level do not overlap **in user keys**
   — `u32be(tree_id) || CKE(key)`, not whole internal keys, which carry `seq`
   and would report two versions of one key as disjoint (`04-segments.md`
   §3.1.1);
4. verifies every value-log record's CRC and that every `VLOG` pointer resolves
   to a record whose stored key matches, and that no pointer resolves past the
   segment's durable `bytes` watermark in tree 7 (`04-segments.md` §6.2);
5. verifies value-log liveness statistics are conservative;
6. validates blob checksums;
7. reconciles reachable pages against the free tree and reports leaks (neither
   reachable nor free) and double-allocations;
8. when the file is encrypted **and a key is supplied**, verifies `sb_mac`, every
   page's AEAD tag, and that no `(key, nonce)` pair occurs twice anywhere in the
   file (`14-security.md` §4). Without a key, steps 1–7 still run: that is the
   point of leaving headers in the clear.

A leak is repairable. A double-allocation is corruption. **A failed AEAD tag or
`sb_mac` is neither** — it is tampering, and MUST be reported as its own class
(`14-security.md` §6.2), because "your disk has a bad sector" and "someone
edited your database" call for different responses.

Verification **reports**; `13-operations.md` §3 specifies repair, and §4
specifies **corruption containment** — a damaged page MUST NOT make the whole
database unreadable, and an implementation MUST keep serving every key outside
the affected range while naming that range precisely.

## 10. Concurrency and locking

**Cryptand is a multi-writer engine.** Concurrency inside one process is a
first-class requirement, and the format is built for it:

- **Segments are immutable.** A reader that has opened a segment never
  coordinates with anyone. There is no page latch, no reader-writer lock on
  data, and no lock protocol in the format.
- **Writers do not share an append stream.** Each memtable shard flushes its own
  L0 segment, and a writer may hold its own open value-log segment. Independent
  writers therefore write to independent extents and never contend on a file
  offset or a cache line. `10-transactions.md` §2 specifies the protocol.
- **The only serialization point is a `fetch_add` on `next_seq`**, plus a short
  critical section when the manifest edit is published.
- **Compaction runs concurrently with writes and with other compactions** on
  disjoint key ranges (`04-segments.md` §5.1).

Between processes:

- One writing **process** per database, enforced by an exclusive advisory lock on
  the database file (`flock` / `LockFileEx`) held for its writing lifetime.
  Multi-threaded writing within that process is unrestricted.
- **Multi-process *reading* is supported** under feature bit `MULTIPROC_READ`:
  one writing process, any number of reading processes, coordinated only for
  extent retention through the lock sidecar (`13-operations.md` §8).
  Immutability makes this nearly free — every extent a reader holds is one
  nothing will modify.
- **Multi-process *writing* is feature bit `MULTIPROC` and is not part of
  version 1.0.** Without it, a second process opening for writing MUST fail with
  a clear "locked by another process" error and MUST NOT fall back to opening
  anyway.
- An implementation MUST NOT assume the lock survives a network filesystem.
  Opening a `.cryptand` file on NFS/SMB SHOULD warn.
