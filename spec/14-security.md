# CFF-14 — Security

**Normative.** Assumes `00-conventions.md`, `01-container.md`,
`04-segments.md`, `10-transactions.md`.

Nitrite is an *embedded* database. Its file sits inside an application's own
storage — a phone's app sandbox, a laptop's home directory, a container volume,
a backup bucket — and the realistic attacker is not on the network. The
realistic attacker has **the file**: a lost phone, a stolen laptop, a leaked
backup, a shared machine, a forensic image.

That shapes everything here. This chapter specifies what a `.cryptand` file
protects, what it deliberately does not, and the exact bytes of how.

Two things it is not. It is not transport security — Nitrite has no wire
protocol, and replication sits above the engine. And it is not access control:
one file, one key, all or nothing (§10).

---

## 1. Threat model

Stated first, because a security section without one is a list of primitives.

### 1.1 In scope — what the format defends against

| | attack | defended by |
|---|---|---|
| **T1** | **Offline disclosure.** The attacker obtains the file — stolen device, lost backup, recovered disk block, a copy taken by another app — and reads its contents. | AEAD over every page payload and every value-log record (§5) |
| **T2** | **Tampering.** The attacker modifies bytes in the file so the application reads something the application never wrote. | Poly1305 tag per page and per record; a modified page fails to open, it does not decrypt to garbage (§5) |
| **T3** | **Splicing and relocation.** The attacker moves a valid encrypted page to another offset, or copies a page from one database into another, to substitute one record for another. | the nonce binds ciphertext to its `nonce` counter value, and the AAD binds it to its page header; the master key is bound to `database_uuid` (§3.4, §5.2) |
| **T4** | **Downgrade.** The attacker edits the plaintext superblock to set `cipher = 0`, to weaken `kdf` cost parameters so a password can be brute-forced, to clear a `features_required` bit, or to swap in another file's roots. | the superblock carries a keyed MAC covering every field that governs how the file is interpreted (§6) |
| **T5** | **Malicious file.** The attacker hands the application a crafted `.cryptand` file — as a "shared database", an import, a restored backup — aiming for memory corruption, unbounded allocation, or code execution in the reader. | the untrusted-input rules of §9, which apply **whether or not the file is encrypted** |

**T5 is the one that applies to every Cryptand file, encrypted or not**, and it
is the threat most likely to be met in practice, because opening a file someone
else produced is the entire point of this format.

### 1.2 Out of scope — stated plainly

An honest boundary is worth more than a broad claim.

| | not defended | why, and what to do instead |
|---|---|---|
| **N1** | **An attacker inside the process.** A debugger, a memory dump, a malicious library in the same address space, or a rooted device reads the key from RAM. | Nothing a file format can do. §11 reduces the window; it does not close it. |
| **N2** | **Rollback to an authentic earlier state.** The attacker replaces the whole file with a genuine older copy of itself. Every byte verifies, because it *was* valid. | Unpreventable inside a single self-contained file: there is no trust anchor outside it to compare against. §6.3 gives the two mitigations that work — an externally pinned `commit_id`, or an external MAC over the file — and neither is in the format. |
| **N3** | **Structure and metadata.** Page types, per-tree page counts, `commit_id`s, file size, growth over time, and which pages are read are all visible. An observer learns *how much* each collection holds and *when* it changed, never *what*. | §7 enumerates exactly what leaks. |
| **N4** | **Side channels.** Timing, cache and power analysis against the host's AEAD implementation. | Use the platform's constant-time primitive; the format does not and cannot enforce it. |
| **N5** | **Multi-user separation.** Whoever can open the file can read all of it. There is no per-collection key and no in-file authorization. | §10. Separate trust domains use separate files. |
| **N6** | **Anything above the engine.** Application logs, exports, crash reports, screenshots, the clipboard, and `nitrite-support`'s JSON dump are all plaintext by construction. | An encrypted database whose contents are exported to a plaintext file is not protected. Say so to users. |

### 1.3 Security is a property of the *whole* format, not of §5

Two facts about the design carry more real-world security weight than the
cipher does, and they hold even with encryption switched off:

- **No host-language deserializer is ever fed file bytes.** MVStore falls
  through to Java object serialization for `Document`, `NitriteId` and
  `IndexEntryKey` (`research/nitrite-survey.md` §3), and `readObject` on
  untrusted input is a remote-code-execution primitive with a decade of
  published gadget chains. CVE (`02-value-encoding.md`) is a tagged byte
  encoding with a fixed type set and no constructor dispatch. **Opening a
  hostile Cryptand file cannot instantiate a class.** That is the single largest
  security improvement in this format, it applies to every file, and it costs
  nothing.
- **Every length is bounds-checked before it is allocated** (`00-conventions.md`
  §8), so a crafted file cannot drive a reader into an out-of-memory abort. This
  project has already lost a process to an unvalidated model file; a database
  file reaches further.

---

## 2. Cryptographic primitives

Exactly four, chosen so that independent implementations can all get them right.
Every one is a **published standard with a specified test-vector set**, which is
the property that matters: an implementation is checked against the vectors, not
against another implementation. All four have widely-used implementations across
mainstream languages, and all four are small enough to write from the standard
where one is not available — which is what makes them a portability asset rather
than a dependency. Naming them is what `00-conventions.md` §1.1 requires: a
format that said "a memory-hard KDF" instead of Argon2id with its parameters
would have two SDKs derive different keys from one password and neither able to
open the other's file.

| purpose | primitive | why this one |
|---|---|---|
| authenticated encryption | **XChaCha20-Poly1305** | 24-byte nonce, so nonces may be *constructed* rather than kept in a table; no AES hardware requirement, which matters on the mid-range ARM devices Nitrite targets; constant-time in software by construction, unlike table-driven AES |
| password stretching | **Argon2id** | memory-hard, the PHC winner, parameterised per device profile (§3.2) |
| key derivation | **HKDF-SHA256** (RFC 5869) | one subkey per purpose from one master key; SHA-256 is everywhere, and HKDF is thirty lines |
| superblock authentication | **HMAC-SHA256** | already present as HKDF's building block, so it adds no new primitive |

**No cipher agility.** `cipher = 1` is the only defined value. An implementation
that cannot perform all four MUST refuse to open an encrypted file rather than
partially read it. A future algorithm arrives as a new `cipher` value behind a
new feature bit, and files written with it are simply unreadable by older
implementations — which is the correct outcome, and the reason the field exists.

An implementation MUST use a constant-time tag comparison. A byte-by-byte
early-exit compare on a Poly1305 or HMAC tag is a forgery oracle.

---

## 3. Keys

### 3.1 Two levels, and why

The file is encrypted under a **master key**: 32 random bytes, generated by a
cryptographic RNG when encryption is first enabled, and never derived from
anything the user types.

The user's password derives a **key-encryption key**, which is used only to wrap
the master key inside a keyslot (§3.3).

```
password ──Argon2id(salt, cost)──▶ KEK ──unwrap──▶ master key
                                                     │
                          HKDF-SHA256(info=purpose) ──┼──▶ page subkey
                                                      ├──▶ value-log subkey
                                                      └──▶ superblock MAC key
```

One level would be simpler and is wrong for three reasons, each of which is a
real operation an application performs:

- **Changing a password rewrites 32 bytes**, not the database. Deriving the
  content key from the password directly makes a password change a full-file
  re-encryption — hours on a phone, and non-atomic.
- **Several ways to unlock one file.** A password *and* an OS keychain entry
  *and* a hardware-backed key can each occupy a keyslot, all wrapping the same
  master key. This is how a Flutter app offers biometric unlock without keeping
  a password anywhere.
- **Crypto-erase.** Destroying the keyslots makes the file unrecoverable in
  microseconds, without touching the data (§8.2). On flash, where overwriting is
  a lie the controller tells you, this is the only erase that means anything.

### 3.2 Argon2id parameters

Cost is a **per-device** decision and therefore a profile default
(`12-profiles.md`), stored per keyslot so a file created on a phone still opens
on a phone after a desktop has written to it:

| profile | `t_cost` | `m_cost_kib` | `parallelism` | target |
|---|---|---|---|---|
| `mobile` | 3 | 65536 (64 MiB) | 1 | ~250 ms on a mid-range ARM |
| `tablet` | 3 | 131072 (128 MiB) | 2 | ~250 ms |
| `desktop` | 4 | 262144 (256 MiB) | 4 | ~500 ms |
| `server` | 4 | 262144 (256 MiB) | 4 | ~500 ms |

The memory cost is **transient and much larger than the engine's entire steady-
state budget** — 64 MiB against `mobile`'s 4 MiB page cache. An implementation
MUST allocate it, use it, and release it before opening proceeds, and MUST NOT
hold it for the life of the database. On a memory-constrained platform an
implementation MAY fall back to a lower `m_cost_kib` **only when creating** a
file, never when opening one: on open the parameters come from the file, and an
implementation that cannot meet them MUST fail rather than derive a different
key.

A writer MUST reject `t_cost < 2`, `m_cost_kib < 16384` or `parallelism < 1` when
*creating* a keyslot. On *open* it MUST use whatever the slot says — the
superblock MAC (§6) is what prevents an attacker weakening those numbers.

**The targets in that table assume a native Argon2id and, above `mobile`,
parallel lanes.** Measured on a pure-Dart implementation (RFC 9106-verified,
`reference/dart/cryptand/bench/p11_encryption.dart`, Apple M2 Pro,
single-threaded): the memory-filling core runs at ~473 MiB/s, giving 405 ms for
the `mobile` row and 2183 ms for `desktop` — against targets of ~250 ms and
~500 ms. Native implementations run roughly 3–6× faster and parallelise lanes,
which is what the table was costed against.

This matters most exactly where it is least convenient: **`mobile` is the
profile whose rationale is a phone UI, it is where an interpreted or JIT runtime
is most likely, and it is `p = 1`, so there are no lanes to parallelise.** An
implementation that cannot reach its profile's target has three conforming
options, in order of preference:

1. **Use `kdf = 0` with a platform keystore.** On a phone the OS keychain is
   hardware-backed and is a better answer than any KDF the process can run: the
   32 supplied bytes are the KEK, and the whole cost disappears. §3.3 already
   defines this path.
2. **Lower `t_cost` toward the floor of 2 when *creating*, keeping
   `m_cost_kib` high.** Memory hardness is the property being bought; passes
   are a linear multiplier on both the defender and the attacker, so trading
   passes costs less than trading memory.
3. **Accept the slower open and say so.** A one-time cost at open is the
   honest failure mode, and `13-operations.md` §6 exposes it.

What an implementation MUST NOT do is any of this **on open**: the parameters
then come from the file, and deriving under different ones yields a different
KEK and reports "wrong password" for a correct one.

### 3.3 Keyslots

Four slots at superblock offset 3512, 144 bytes each. A slot:

| off | size | field | notes |
|---|---|---|---|
| 0 | 1 | `state` | 0 empty, 1 occupied; anything else ⇒ corrupt |
| 1 | 1 | `kdf` | 0 raw (the caller supplies 32 key bytes directly), 1 Argon2id |
| 2 | 1 | `label_len` | 0…16 |
| 3 | 1 | reserved | |
| 4 | 4 | `t_cost` | Argon2id only |
| 8 | 4 | `m_cost_kib` | Argon2id only |
| 12 | 4 | `parallelism` | Argon2id only |
| 16 | 32 | `salt` | random per slot, never reused across slots or files |
| 48 | 24 | `wrap_nonce` | random; wrapping is rare, so a random nonce is safe at this rate |
| 72 | 32 | `wrapped_key` | the master key, XChaCha20-Poly1305 under the KEK |
| 104 | 16 | `wrap_tag` | |
| 120 | 16 | `label` | UTF-8, not secret, for tooling — `"password"`, `"keyring"`, `"recovery"` |
| 136 | 8 | reserved | |

- `kdf = 0` is for a key the host already holds — an OS keychain item, a
  hardware-backed key, a key supplied on a command line by an operator. The
  32 supplied bytes *are* the KEK; `salt`, `t_cost`, `m_cost_kib` and
  `parallelism` MUST be written as zero.
- **AAD for the wrap** is `database_uuid || slot_index : u8`. This binds a slot
  to its file: a keyslot lifted from another database does not unwrap here, so
  an attacker cannot graft a slot whose password they know onto a file they
  want to read (T3).
- Unwrapping tries each occupied slot in order and stops at the first whose tag
  verifies. A failure across all slots is "wrong key", and an implementation
  MUST NOT distinguish "no such slot" from "bad password" in what it reports.
- Adding, replacing or removing a slot is a superblock write and nothing else.
  An implementation MUST refuse to remove the **last** occupied slot while
  `cipher ≠ 0` — that is crypto-erase (§8.2), and it MUST be asked for by name.

### 3.4 Subkeys

Never use the master key directly. Derive with HKDF-SHA256:

```
salt   = database_uuid                      (16 bytes)
ikm    = master key                         (32 bytes)
info   = "cryptand/v1/" || purpose
subkey = HKDF-Expand(HKDF-Extract(salt, ikm), info, 32)
```

| `purpose` | used for |
|---|---|
| `"page"` | page payloads (§5.2) |
| `"vlog"` | value-log records (§5.3) |
| `"sbmac"` | the superblock MAC (§6) |

Domain separation matters here for a concrete reason: pages and value-log
records use *different* nonce spaces (§4), and reusing one key across two
independently-constructed nonce spaces is exactly how nonce collisions become
possible again. Separate keys make the two spaces independent by construction.

Using `database_uuid` as the HKDF salt means **two files with the same password
have different content keys**, so a nonce that repeats across files is harmless.
`13-operations.md` §2.1 already forbids copying a source's `database_uuid` into
a backup; that rule is now load-bearing for security, not only for tooling.

---

## 4. Nonces — the part that must not be got wrong

XChaCha20-Poly1305 is a stream cipher with a polynomial MAC. **Encrypting two
different plaintexts under the same key and nonce discloses their XOR and leaks
the Poly1305 authentication key**, which turns tampering detection off. Nonce
uniqueness is not a hardening measure; it is the whole thing.

The counter, not the commit id, is what guarantees it.

### 4.1 `next_nonce`

The superblock holds `next_nonce : u64` at offset 288. A writer allocates a
nonce value with one `fetch_add` — the same idiom as `next_seq`
(`10-transactions.md` §2), and the second and last global atomic on the write
path.

**The allocated value is stored, in the clear, in the page header** (offset 24,
`nonce`). Nonces are public; only their uniqueness matters. Storing rather than
recomputing means a reader never has to reconstruct the writer's state, and it
puts the nonce inside the AAD (§5.2) at no cost.

**`next_nonce` is a reservation watermark, not a counter.** Its meaning is:

> Every value **below** `next_nonce` may already have been allocated. Every
> value **at or above** it has not been.

Three MUSTs follow, and all three are needed — any two of them leave a hole:

1. **On open, before allocating anything, a writer MUST durably publish a
   superblock whose `next_nonce` is `persisted_next_nonce + 2²⁰`.**
2. A writer allocates from `persisted_next_nonce` upward and MUST NOT reach the
   value it published.
3. On reaching it, the writer MUST publish `published + 2²⁰` and only then
   continue.

Walk a crash through it. A session opens at a persisted watermark *W*,
publishes *W + 2²⁰*, and allocates somewhere inside `[W, W + 2²⁰)` before
dying. The next session reads *W + 2²⁰*, publishes *W + 2²¹*, and allocates
inside `[W + 2²⁰, W + 2²¹)` — disjoint from anything the dead session could
have touched, because rule 2 bounded it. Rule 1 is what makes the watermark
move even for a session that writes nothing else, and without it two successive
crashed sessions both start at *W* and hand out the same values.

(An earlier draft of this section said only "on open, begin allocating at
`persisted_next_nonce + 2²⁰`" and left out the publish. That rule does nothing:
a session that crashes without publishing leaves the watermark unchanged, so
the next session computes the same start and reissues the same nonces. The
reference implementation's nonce-uniqueness test caught it, which is the test
existing for exactly this reason.)

The cost is one extra superblock write per open, plus one per 2²⁰ allocations —
about 4 GiB of page writes on `mobile`. The bound is a MUST rather than a hope,
so a long-running session cannot silently outrun it.

That rule is what makes a crash safe, and it closes a defect the earlier draft
had. The earlier nonce was `page_id || commit_id || record_offset`, justified by
"copy-on-write and append-only guarantee uniqueness". They do not:

> A commit at `commit_id = N` writes pages and dies before its superblock.
> `01-container.md` §2.1 discards everything past `page_count`, so the surviving
> superblock still reads `N−1` — and the **next** commit is also `N`. It
> allocates the same freed extents and writes *different plaintext* to the same
> `page_id` under the same `commit_id`. Same key, same nonce, two plaintexts.

With the watermark discipline above, the crashed attempt consumed nonces
strictly below the value its own opening publish moved the watermark to, so no
value is ever handed out twice.

### 4.2 Construction

24 bytes, little-endian throughout:

```
nonce := u8  domain          -- 1 page, 2 value-log record, 3 key wrap
      || u64 counter         -- the allocated next_nonce value
      || u64 object_id       -- page_id, or vlog_segment_id
      || u56 offset          -- 0 for a page; the record's extent offset otherwise
```

`1 + 8 + 8 + 7 = 24`. The `object_id` and `offset` are redundant given a correct
counter, and they are there deliberately: if a counter value were ever reused
through an implementation bug, a collision additionally requires the same page —
which turns a catastrophic break into an unlikely one. Defence in depth is
cheap when the field is already 24 bytes wide.

`offset` is a `u56`, which bounds a value-log segment at 2⁵⁶ bytes; the real
bound is 4 GiB from `vlog_segment_bytes` being a `u32` (`04-segments.md` §6.4).

### 4.3 The value-log re-append rule — a MUST

`10-transactions.md` §4 says that after a crash, the bytes past a value-log
segment's durable watermark "are overwritten by the next append". Unencrypted,
that is safe: nothing references them. **Encrypted, it is a nonce collision** —
the same segment and the same offsets, written twice with different content.

Therefore:

> **A writer MUST NOT append to a value-log segment that it did not itself open
> in the current session.** On open, every value-log segment that is not sealed
> is sealed at its durable `bytes` watermark (`04-segments.md` §6.7) and a fresh
> segment is opened for new writes.

The cost is one partially-filled segment per unclean shutdown, reclaimed by
ordinary GC. The rule is stated unconditionally rather than only for encrypted
files, because a rule that applies sometimes is a rule that gets implemented
wrong, and sealing early costs nothing.

A whole-segment nonce base is not used: each record derives its own nonce from
the segment's allocated `counter` and its own `offset`, so a record can be
decrypted without reading any other record — which is what §5.3's single-record
read requires.

---

## 5. What is encrypted

### 5.1 Scope

| | state |
|---|---|
| page payload — everything after the 40-byte page header | **encrypted** |
| value-log record — `tree_id` through `value` | **encrypted** |
| the 40-byte page header | **clear** |
| both superblocks | **clear**, and authenticated (§6) |
| a value-log segment's head page | **clear** |
| a blob's payload | **encrypted**, as an extent (§5.4) |
| a vector region's payload | **encrypted**, as an extent (§5.4) |

Headers stay in the clear so that **structure, checksums, free-space accounting
and repair all work without the key.** A `cryptand verify` run, a leak scan, an
incremental backup and the containment logic of `13-operations.md` §4 all
operate on an encrypted file that no one can read. That is a deliberate trade,
and §7 is the bill for it.

### 5.2 Pages

```
ciphertext = XChaCha20-Poly1305-Encrypt(
    key   = subkey("page"),
    nonce = 1 || counter || page_id || 0,
    aad   = the 40-byte page header with `checksum` zeroed,
    pt    = the payload, after compression )
```

- The 16-byte tag is appended to the ciphertext and is inside **`stored_len`**
  (`01-container.md` §3, offset 28), *not* `payload_len`. `payload_len` keeps
  the meaning §3 gives it — the uncompressed, unencrypted length — and
  `stored_len` is what the page actually holds. An earlier draft of this bullet
  said `payload_len`, which contradicted §3 outright and left a page that is
  compressed *and* encrypted with no way to record both lengths.
- **A page builder MUST reserve the 16 bytes before it lays out its payload.**
  A page filled to `page_size - 40` has nowhere to put a tag, and a builder that
  discovers this at write time has produced a page that cannot be written at
  all. The usable payload of an encrypted page is `page_size - 40 - 16`.
- Order is **compress, then encrypt** on write; **verify checksum, decrypt,
  then decompress** on read. Encrypting compressed output is the only order that
  compresses at all, and checking the CRC first means a corrupt page is never
  fed to a cipher (`00-conventions.md` §6).
- AAD includes `page_type`, `flags`, `tree_id`, `commit_id`, `extent_pages`,
  `payload_len` and `nonce`, so none of them can be edited without detection —
  an attacker cannot relabel an index page as a data page, or move a page
  between trees.
- `flags.ENCRYPTED` MUST be set. A reader MUST NOT infer encryption from
  `cipher` alone: a file may hold a mixture while conversion is in progress
  (§8.3).

### 5.3 Value-log records

```
ciphertext = XChaCha20-Poly1305-Encrypt(
    key   = subkey("vlog"),
    nonce = 2 || counter || vlog_segment_id || record_offset,
    aad   = u64le(vlog_segment_id) || u64le(record_offset) || u32le(tree_id),
    pt    = `key_len || key || value_len || value` )
```

`record_len`, the `counter`, and the trailing `crc32c` stay in the clear so that
a segment can be walked, and its damage bounded, without the key. The `crc32c`
covers the stored (ciphertext) bytes, consistent with `00-conventions.md` §6;
the Poly1305 tag is what provides integrity, and it is appended before the CRC.

Each record's `counter` is stored in the clear immediately after `record_len`,
costing 8 bytes per separated value. That is the price of being able to decrypt
one record without reading the segment — which is exactly what a point read
does, and losing it would defeat key–value separation entirely. On `desktop`,
where `vlog_min` is 256 B, it is ~3 % on the smallest separated value and under
1 % on a typical document.

### 5.4 Extents without page headers

Blobs and vector regions run raw payload across interior pages with no per-page
header (`01-container.md` §3). Each is encrypted **per page-sized chunk**, not
as one stream, so that a reader can decrypt the chunk it wants:

```
chunk i  = bytes [ i × (page_size − 24), (i+1) × (page_size − 24) )
on disk  = u64le counter || ciphertext || tag        -- one page
nonce    = 1 || counter || head_page_id || i
aad      = u64le(head_page_id) || u64le(i)
```

**`counter` is per chunk and per write, and it is stored in the clear at the
head of the chunk.** An earlier draft made it "the extent's single allocated
nonce value, stored in its head page", which is correct only if every chunk of
the extent is written exactly once. A vector region breaks that on its first
ordinary use: `stride` is far below `page_size`, so two slots share a chunk and
are written at different times, and a slot may be rewritten outright. Rewriting
a chunk under a fixed per-extent counter is the same key and the same nonce over
different plaintext — the failure §4 opens by calling "not a hardening measure;
it is the whole thing". Storing the counter in the clear inside the chunk is
what §5.3 already does for a value-log record, and for the same reason: it is
what lets one chunk be decrypted, or rewritten, on its own.

A partial-chunk write is therefore a read-modify-write under a **fresh**
counter, never a patch in place.

Each chunk costs 8 bytes of counter plus a 16-byte tag, so an encrypted extent
needs `ceil(len / (page_size − 24))` pages rather than `ceil(len / page_size)` —
about 0.6 % more space at 4 KiB pages. A writer MUST size the extent
accordingly, and `01-container.md` §5's blob `byte_len` is the plaintext
length.

**This is where encryption costs an architectural property.** `09-vector.md` §2
lets an implementation `mmap` a vector region and read vectors as zero-copy
slices, which is what bounds DiskANN's resident memory by the OS page cache. An
encrypted region cannot be sliced in place: every access decrypts a chunk into a
buffer the implementation must hold and bound itself. §12 accounts for it.

---

## 6. Authenticating the superblock

### 6.1 The attack

Both superblocks are in the clear and protected only by CRC-32C, which any
attacker can recompute. Without a MAC, an attacker with write access can:

- set `cipher = 0`, so the next writer stores **plaintext**;
- lower `t_cost` and `m_cost_kib` in a keyslot so a captured file's password
  falls to a feasible brute force;
- clear a bit from `features_required`, so a reader silently misinterprets
  structures it should have refused;
- raise `vlog_min` past its cap, or set `page_size_log2` out of range, steering
  a reader into whatever the length checks do not cover;
- swap in another file's roots.

None of that touches a single encrypted byte, and all of it is invisible.

### 6.2 The MAC

`sb_mac`, 32 bytes at superblock offset 296:

```
sb_mac = HMAC-SHA256(
    key = subkey("sbmac"),
    msg = superblock bytes 0…4091, with bytes 296…327 (`sb_mac` itself) zeroed )
```

Rules, all MUST:

- A writer holding the key writes `sb_mac` on **every** superblock write, and
  **keeps the value it wrote**. The second half is the one that gets missed. An
  implementation that seals the image it writes but leaves its *in-memory*
  superblock holding the MAC it parsed at open will, from that moment,
  recompute the MAC over the current fields and compare it against a MAC that
  described the fields as they were *before* — and report its own file as
  tampering. §4.1's open-time nonce publish is a superblock write, so this makes
  every encrypted file fail `01-container.md` §9 step 8 immediately after every
  open. A reference implementation did exactly this, and the only verifier that
  noticed was the **other** implementation's, in the cross-language round trip.
- A reader that has unwrapped the master key verifies `sb_mac` immediately after
  choosing a slot (`01-container.md` §2.1 step 3) and **before acting on any
  other superblock field**, in constant time. A mismatch is a security failure
  and MUST be reported as tampering, distinctly from a CRC failure, which is
  corruption.
- Verification happens *before* Argon2id runs — the KEK derivation needs
  `salt`, `t_cost`, `m_cost_kib` and `parallelism` from a keyslot, so those four
  are read first and the MAC is checked immediately after unwrapping, before any
  root is followed. An implementation MUST NOT begin reading trees on an
  unverified superblock.
- When `cipher = 0`, `sb_mac` is written as zero and is not checked. An
  unencrypted file has no key and therefore cannot be authenticated; **CRC-32C
  is error detection, never integrity** (§9.4).

The MAC covers the keyslots, so the cost parameters are self-protecting: an
attacker who weakens them invalidates the MAC, and a conforming reader stops.

### 6.3 What the MAC does not stop

Rollback (N2). Both superblock slots are genuine, MAC'd states of this file, so
an attacker can restore an old copy of the whole file, or copy slot A over slot
B to revert one commit, and everything verifies. A single self-contained file
has no anchor to detect it against.

The two mitigations that actually work are both outside the format, and an
implementation with a threat model that includes rollback SHOULD offer the
first:

1. **Pin `commit_id` externally.** Record the last-seen `commit_id` where the
   attacker cannot write — an OS keychain entry, secure element, or server — and
   refuse to open a file whose `commit_id` is lower. This is ten lines and it
   closes the attack for the mobile case, which is the one that matters.
2. **MAC the file from outside**, e.g. a signed manifest alongside a backup.

Claiming otherwise would be worse than saying nothing, so the format says this.

---

## 7. What an encrypted file still reveals

The bill for keeping headers readable. An attacker holding the file, without the
key, learns:

| visible | what it tells them |
|---|---|
| file size, and its growth if they see the file twice | how much data, and how fast it accumulates |
| every page's `page_type` | how many index, segment, value-log, R-tree and vector pages exist — so, which *kinds* of index the database has |
| every page's `tree_id` | how many pages each tree holds — so, the relative size of each collection and each index |
| every page's `commit_id` | when each tree was last written, and which trees change together |
| segment and value-log extent boundaries | the level structure, roughly how much data is hot |
| `page_codec`, `profile`, `writer_id`, `created_utc_ms`, `modified_utc_ms` | which SDK and device wrote it, and when |
| `payload_len` per page | after compression: how compressible the content is |

They do **not** learn tree names (the catalog is a tree, so it is encrypted),
field names (in an encrypted name-dictionary tree), any key, or any value.

Two consequences worth stating rather than discovering:

- **Traffic analysis on a live file is real.** An observer who can watch reads —
  a shared host, an instrumented filesystem — sees which pages are touched, and
  page access patterns over a B+tree leak key locality. The format does not
  defend against it (N4).
- **Compression before encryption leaks length** (`01-container.md` §7). Where
  an attacker can influence some content and observe `payload_len`, this is the
  CRIME/BREACH shape: compressibility against a co-resident secret. It is far
  weaker here than in a request-response protocol — the attacker needs many
  adaptive writes and page-level observation — but it is not nothing. An
  implementation MUST offer `compression = none` while encrypted, and SHOULD
  default to it for a tree the application marks sensitive.

---

## 8. Erasure, retention, and turning encryption on

### 8.1 Deleted data persists, and applications must know

A `remove()` writes a tombstone. The old value survives in its segment and in
the value log until a compaction that satisfies `04-segments.md` §5 drops it,
and its extent survives until `min_retained_commit` passes it
(`01-container.md` §6). A long-lived reader, an open cursor, or a checkpoint
extends that indefinitely (`10-transactions.md` §8).

**An implementation MUST expose a way to force it**: `compact()` followed by
`collect()` and `shrink()` (`13-operations.md` §5) drops every superseded
version and returns the space. An application with a "delete my data" obligation
calls that; the format cannot infer the intent.

**On flash, overwriting is not erasure.** Wear levelling means the controller
writes elsewhere and the old block persists until it is garbage-collected, on
its own schedule, which no application can observe or force. An implementation
MUST NOT claim that `shrink()` destroys data on a phone. §8.2 is the erase that
means something.

### 8.2 Crypto-erase

Zeroing every occupied keyslot and writing that superblock makes the file
permanently unreadable in the time of one write, without touching a byte of
data. This is the only erase that works on flash, and it is the reason for the
two-level key (§3.1).

An implementation offering it MUST:

- require an explicit, separate call — never a side effect of `close()`,
  `remove()`, `drop()` or clearing a slot;
- overwrite the keyslot bytes with zeros, not merely set `state = 0`;
- write **both** superblock slots, since either may hold an intact keyslot copy;
- report that the operation is irreversible **before** performing it.

An implementation MUST NOT offer crypto-erase on an unencrypted file, or present
deleting the keyslots of one copy as erasing a database that has been backed up.

### 8.3 Enabling, rotating, disabling

| operation | cost |
|---|---|
| **add / remove / replace a keyslot** (change password, add biometric unlock) | one superblock write; the master key is unchanged, so no data is touched |
| **rotate the master key** | a full rewrite — every page and record re-encrypts. Offered as a background, resumable conversion (§8.4), not as an atomic operation |
| **encrypt an existing plaintext database** | `01-container.md` §5's rule that `flags.ENCRYPTED` is per page makes this a conversion, not a rewrite-or-nothing: set `cipher = 1`, write a keyslot, and every subsequently written page is encrypted. Existing pages convert as compaction reaches them |
| **decrypt** | the mirror, and an implementation MUST make the user confirm it, because it is a silent downgrade of everything |

**A converting file is honest about its state.** While a conversion is
incomplete, some pages are encrypted and some are not, and a reader MUST use
each page's own `flags.ENCRYPTED`. An implementation MUST expose the fraction
converted, and MUST NOT report a database as encrypted while plaintext pages
remain — that is the one place where a reassuring answer is a dangerous one.

`reprofile()`-style forcing is `compact()`: a full compaction rewrites every
page and completes the conversion.

### 8.4 Conversion is resumable

Like every other maintenance operation (`13-operations.md` §5), encryption
conversion is incremental, bounded by `max_foreground_stall_ms`, and safe to
interrupt at any point. A half-converted file is a valid file.

---

## 9. Hardening against a hostile file

**These rules apply to every implementation, whether or not it supports
encryption**, because T5 does not require the attacker to have a key.

### 9.1 Bounds

Restating `00-conventions.md` §8 because it is a security rule and belongs here
too: every length read from the file is untrusted. A decoder MUST bounds-check
against the containing page or extent **before allocating**, MUST enforce the
depth limit of 100, and MUST fail with a typed corruption error rather than an
allocation failure, a panic, an abort, or an unbounded recursion.

### 9.2 No dispatch on file content

A reader MUST NOT use any value read from the file to select a class, a
constructor, a deserializer, a codec plugin, or a path on the filesystem. CVE's
`OPAQUE` (`02-value-encoding.md` §7) carries a `type_name` written by another
SDK; it is **data to be preserved, never a name to be resolved**. An
implementation that maps `OPAQUE.type_name` to a host class has reintroduced the
exact deserialization vulnerability this format was designed to remove.

### 9.3 Required negative testing

An implementation MUST pass, and CI MUST run:

- the `v1.0-corrupt-*` vectors (`11-conformance.md` §6), each producing a named
  error and no crash, hang, or unbounded allocation;
- **structure-aware fuzzing** of the reader — `cryptand fuzz` for the reference
  implementation, and an equivalent for each SDK. A parser for a format read
  from untrusted sources that has never been fuzzed is not finished;
- the `v1.0-security-*` vectors of §13.

### 9.4 CRC is not integrity

CRC-32C detects accidental corruption. It is trivially recomputed by anyone who
edits the file. **An unencrypted `.cryptand` file offers no tamper detection at
all**, and an implementation MUST NOT describe checksums as protecting against
modification. Integrity comes from the AEAD tag, and only where the AEAD runs.

---

## 10. User authentication versus file encryption

Tree 5 (`05-catalog.md` §8) stores credential records. Its relationship to §3 is
the thing an application most often gets wrong, so it is stated normatively:

- **They protect different things.** File encryption protects the *bytes* from
  someone holding the file. A user record authenticates a *caller* to an
  application that has already opened the file.
- **A password-protected but unencrypted database protects nothing** against an
  attacker holding the file: tree 5 is itself in the file, and the data next to
  it is plaintext. An implementation MUST NOT present that configuration as
  protection, and SHOULD warn when a user is created on a file with
  `cipher = 0`.
- **On an encrypted database, tree 5 is not a second security boundary.**
  Whoever can open the file has the master key and can read everything,
  including every other user's data (N5). Tree 5 is application-level role
  separation, not confidentiality.
- Credential records MUST use Argon2id with the parameters of §3.2 and a
  per-record random salt, and MUST store only the derived hash. Verification
  MUST compare in constant time.
- An implementation MUST NOT reuse a user's password as a keyslot password
  without deriving them separately: `05-catalog.md` §8's record and §3.3's
  keyslot use independent salts, so the same typed password produces unrelated
  values and neither discloses the other.

**Cryptand's position: if the data needs protecting, encrypt the file.** Users
are for telling application roles apart.

---

## 11. Key material in memory

**The requirements here are stated against language *properties*, not against
languages** (`00-conventions.md` §1.1). Every implementation evaluates its own
runtime against them; the worked examples below the rules are not requirements.

| | requirement |
|---|---|
| **All** | Keys, passwords and derived subkeys MUST be held in mutable byte arrays and zeroed when no longer needed. An implementation MUST zero the master key and every subkey on `close()`. |
| **A runtime whose string type is immutable or interned** | MUST NOT offer a password parameter of that type. The API MUST accept a mutable byte or character sequence and MUST zero it after use. An immutable string holding a password survives until collection and may persist in a heap dump indefinitely, which no amount of care at the call site can undo. |
| **A runtime that may relocate or copy heap objects** (a moving or copying garbage collector) | MUST document that zeroing is best-effort, because a copy the program never sees cannot be zeroed. Documenting it is the requirement; achieving what the runtime forbids is not. |
| **A runtime with deterministic destruction** | SHOULD bind key material to a type that zeroes on release and that cannot be debug-printed or copied implicitly. |

*Non-normative — how those rules land on the three current SDKs.* Java: `String`
is immutable and interned, so take `char[]` or `byte[]`. Dart: `String` is
likewise immutable with no zeroing, so take a `Uint8List`, and document the
best-effort caveat the VM imposes. Rust: `zeroize` on drop, and keep the type out
of `Debug` and `Clone`.

Two more, both MUST:

- **Never log a key, a nonce-bearing structure with plaintext beside it, a
  keyslot, or a password** — including at trace level, in an error message, or
  in a panic payload.
- **`writer_id` and the `writers` list (`05-catalog.md` §7) are plaintext
  metadata.** They MUST NOT carry a user name, a device identifier, or anything
  else an application would not print on the front of the file.

An implementation SHOULD avoid writing key material to swap where the platform
allows it (`mlock`, `VirtualLock`), and MUST NOT fail to open merely because it
cannot.

---

## 12. What security costs

Honest accounting, in the style of `design/tradeoff-analysis.md`, all
predictions rather than measurements.

| | cost |
|---|---|
| **Open latency** | Argon2id at the §3.2 parameters is ~250 ms on a phone and ~500 ms on a desktop, **once per open**. It is the dominant term in opening an encrypted database, it is deliberate, and an implementation MUST NOT lower it to feel faster. |
| **Peak memory at open** | 64–256 MiB transient for Argon2id — far above the engine's steady-state budget, and the one moment an encrypted `mobile` database is memory-hungry. |
| **Throughput** | XChaCha20-Poly1305 runs at 1–3 GB/s per core on ARM and x86 without hardware AES, so on any device whose storage is slower than that — every phone, every SATA SSD — encryption is **not** the bottleneck. On fast NVMe it becomes measurable. |
| **Space** | 16 bytes of tag per page (0.4 % at 4 KiB), 16 per blob/vector chunk, and 24 per value-log record (16 tag + 8 counter) — ~5 % on a 500-byte separated value, under 1 % inline. |
| **Filters** | `04-segments.md` §2.4's "a probe reads exactly one 64-byte block" does not hold: the page must be decrypted whole. Filter probes on an encrypted file cost a page decrypt unless the page is cached, which raises the value of caching filter pages and weakens the demand-loading argument. |
| **Vector regions** | zero-copy `mmap` is unavailable (§5.4). DiskANN's bounded-resident-memory property becomes the implementation's problem rather than the OS's. |
| **Compression** | still works — order is compress-then-encrypt — but leaks length (§7), and disabling it costs the 1.5–2× that `design/performance-model.md` §6 attributes to it. |
| **Repair** | unchanged, and this is the payoff for clear headers: `cryptand verify` and the containment logic of `13-operations.md` §4 run on an encrypted file with no key. |

**What it does not cost**: recovery is still reading two superblocks; segments
are still immutable; compaction still never rewrites a value; and the
`mobile` profile's one-I/O point read is unaffected.

---

## 13. Conformance

Encryption is feature bit `CIPHER` (`11-conformance.md` §2), not a conformance
level: an SDK either implements §2's four primitives or refuses encrypted files,
and both are conforming. The hardening of §9 is **not** optional — it is
required at every level, for every implementation, encrypted or not.

Test vectors, alongside those of `11-conformance.md` §6:

```
conformance/
  vectors/
    security/
      kdf/          password + params → expected 32-byte KEK (Argon2id)
      hkdf/         master key + uuid + purpose → expected subkey
      nonce/        counter + object + offset → expected 24 bytes
      aead/         key + nonce + aad + plaintext → expected ciphertext + tag
      sbmac/        a superblock image → expected sb_mac
  files/
    v1.0-encrypted.cryptand         known password, known expected read set
    v1.0-security-tamper-page       one ciphertext byte flipped
    v1.0-security-tamper-header     tree_id edited in a page header (AAD)
    v1.0-security-tamper-sb         cipher forced to 0 in the superblock
    v1.0-security-downgrade-kdf     t_cost lowered in a keyslot
    v1.0-security-splice            a page moved to another offset
    v1.0-security-foreign-slot      a keyslot copied from another database
    v1.0-security-converting        a half-encrypted file, mixed page flags
```

Each `security-*` file MUST produce a **specific, named security error**,
distinct from a corruption error, and MUST NOT return data. Mandatory tests:

- **A tamper test**, over all `security-*` vectors above.
- **A nonce-uniqueness test.** Write until the published floor of §4.1 is
  crossed at least twice, kill the process at randomized points, reopen and
  continue, then assert across the whole file that **no `(key, nonce)` pair
  occurs twice** — pages, value-log records and extent chunks together. This is
  the test that would have caught the crash-reuse defect §4.1 describes, and
  nothing else catches it.
- **A key-rotation test.** Add a keyslot, remove the original, reopen with the
  new credential only, verify, and confirm the old credential fails.
- **A conversion round-trip.** Encrypt a populated plaintext database, verify
  mid-conversion that the file opens and reads correctly with mixed page flags,
  compact to completion, verify, decrypt, verify again.
- **A cross-SDK encrypted round trip.** The round-trip gate of
  `11-conformance.md` §6, run on an encrypted file. An AEAD, a KDF and a nonce
  construction that three SDKs implement independently is exactly the kind of
  contract that drifts, and a wrong tag is not a slow read — it is a file one
  SDK can no longer open.
