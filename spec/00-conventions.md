# CFF-00 — Conventions

Cryptand File Format, version 1.0. **Normative.**

---

## 1. Requirement language

MUST / MUST NOT / SHOULD / SHOULD NOT / MAY carry their RFC 2119 meanings. A
conforming implementation is one that passes the conformance vectors for the
levels it claims (`11-conformance.md`).

### 1.1 What may and may not be normative

**A normative requirement in these documents MUST be satisfiable by any language
with the primitives of §3 and §4.** That is the whole proposition: an SDK
written tomorrow reaches these files by implementing one document.

The line is not "no algorithms" — it is *what the requirement constrains*:

| constrains | status | examples |
|---|---|---|
| **the bytes** | normative, fully specified, named down to the parameter | CKE, CVE, CFH-64, CRC-32C, XChaCha20-Poly1305, Argon2id, HKDF-SHA256, the blocked-Bloom probe sequence, every page and header layout |
| **the host runtime** | a **declared capability** (`11-conformance.md` §1.1, §1.2), never a bare MUST | thread counts, flush primitives, memory budgets, scheduling |
| **why a rule exists** | non-normative | "this replaces Java's `IndexEntryKey`", frame budgets, battery |

**Naming an algorithm is the opposite of a language dependency.** A format that
said "use a memory-hard KDF" rather than Argon2id with its parameters would have
two SDKs derive different keys from one password and neither able to open the
other's file. Every algorithm above is a published standard with implementations
in every mainstream language, and each is specified here to the bit for exactly
that reason.

What is *not* permitted is a MUST an implementation cannot satisfy because of
its language or platform. Where a real platform difference exists, state the
**obligation** in language-neutral terms and let the implementation declare what
it achieved:

> An implementation MUST use the strongest durable-flush primitive its platform
> provides, and MUST record what it actually performed.

not

> ~~A Dart implementation cannot reach `F_FULLFSYNC` without FFI and MUST
> therefore report `sync` on Darwin.~~

Naming a language as an **example** of a class is fine and often clearer —
§7's "a language without a native 64-bit integer (JavaScript) MUST use an exact
representation" binds the class, not the example. Naming a language as the
**subject** of a requirement is not.

## 2. Names

| Term | Meaning |
|---|---|
| **CFF** | Cryptand File Format — the container (this spec) |
| **CVE** | Cryptand Value Encoding — values and documents (`02-value-encoding.md`) |
| **CKE** | Cryptand Key Encoding — order-preserving keys (`03-key-encoding.md`) |
| **tree** | One logical sorted map, identified by a `tree_id` |
| **segment** | An immutable, sorted, page-indexed B+tree written once as one extent |
| **extent** | A contiguous, page-aligned range of pages |
| **snapshot** | A consistent view: a sequence number plus one superblock's roots |
| **seq** | A monotonic `u64` version stamp on every record; the MVCC clock |
| **value log** | The append-only region holding separated values (`04-segments.md` §6) |
| **commit id** | A monotonically increasing `u64`; the version of the database |
| **master key** | 32 random bytes; the file's content key, wrapped in a keyslot (`14-security.md` §3) |
| **keyslot** | One wrapped copy of the master key, unlocked by a password or a host-supplied key |

File extension: `.cryptand`. A database is **one file**. An implementation MAY
create a sidecar lock file `<name>.cryptand-lock`; it carries no database state
and MUST be safe to delete when no process holds the database open.

## 3. Byte order

- **All fixed-width integers in structural headers, page headers, cells,
  descriptors and CVE payloads are little-endian.** Every target CPU is
  little-endian; this makes structure reads free where the language allows it.
- **Inside a CKE key, all multi-byte integers are big-endian.** CKE exists to
  make `memcmp` agree with logical order, and that requires most-significant
  byte first. This is the only exception, and it applies to the whole of
  `03-key-encoding.md`.

Floating point is IEEE 754 binary32 / binary64. NaN is canonicalized on encode:
any NaN payload MUST be written as the quiet NaN `0x7FF8000000000000`
(binary64) / `0x7FC00000` (binary32).

Signed integers are two's complement.

## 4. Primitives

| Symbol | Meaning |
|---|---|
| `u8 u16 u32 u64` | unsigned, fixed width, little-endian |
| `i8 i16 i32 i64 i128` | signed, fixed width, little-endian |
| `f32 f64` | IEEE 754, little-endian |
| `uvar` | LEB128 unsigned varint, max 10 bytes |
| `ivar` | zigzag-then-LEB128 signed varint |
| `bytes(n)` | *n* raw bytes |
| `str` | `uvar length` followed by that many bytes of **UTF-8** |

`uvar` encoding: seven payload bits per byte, low bits first, high bit set on
every byte but the last. A decoder MUST reject an encoding longer than 10 bytes
and MUST reject a non-canonical encoding (trailing byte `0x80`).

Strings are UTF-8 and MUST be well-formed. Unpaired surrogates MUST be rejected
on write. A reader encountering ill-formed UTF-8 MUST report corruption; it MUST
NOT substitute replacement characters silently.

Field names, tree names, and index field paths are compared as **exact byte
sequences**. No Unicode normalization is applied by the format. (An implementation
that normalizes user input does so above the format, and does so consistently
across SDKs or the SDKs will disagree — see `05-catalog.md` §7.)

## 5. Reserved and alignment

Every field named `reserved` MUST be written as zero and MUST be ignored on
read. Growing a header into its reserved bytes is a minor-version change.

Pages are aligned to `page_size`. Extents are aligned to `page_size`. Inside a
page, no alignment is required or assumed — a conforming reader MUST use
unaligned reads (or byte assembly). This keeps Dart and WASM implementations
honest.

## 6. Checksums

The page and header checksum algorithm is **CRC-32C (Castagnoli, polynomial
`0x1EDC6F41`, reflected, init `0xFFFFFFFF`, final xor `0xFFFFFFFF`)**. Chosen
because it is hardware-accelerated on every current ARM and x86, is in the JDK as
`java.util.zip.CRC32C`, is a small table in Dart, and is `crc32fast` in Rust.

Scope: a checksum covers **every byte of its page or header except the four
bytes of the checksum field itself**, over the bytes *as stored* — i.e. after
compression and after encryption, so verification precedes decoding. For an
ordinary page the checksum is the first field and the covered range is
`4 … page_size-1` (`01-container.md` §3); for the superblock the checksum is the
*last* field and the covered range is `0 … 4091` (`01-container.md` §2). There
are no other placements.

A 64-bit checksum (**CFH-64**, `04-segments.md` §2.4.1) MAY be used for blob
extents and value-log segment bodies when feature bit `HASH64` is set. CRC-32C
remains mandatory for pages and superblocks regardless.

CFH-64 is a *hash*, not a CRC: it has no burst-error guarantee, and it is used
here only where the alternative is nothing at all. An earlier draft named
XXH3-64 for both this and the segment filter; `04-segments.md` §2.4.1 records
why a hash small enough to print in the spec replaced it.

## 7. Integer identifiers

| | type | notes |
|---|---|---|
| `page_id` | `u64` | page index from file start; page 0 is superblock slot A |
| `tree_id` | `u32` | 0–15 reserved (`05-catalog.md` §2); `0xFFFFFFFF` reserved as the "no owning tree" sentinel in a page header (`01-container.md` §3); ids are never reused |
| `commit_id` | `u64` | monotonic; starts at 1; never reused |
| `segment_id` | `u64` | tree segments; globally unique, never reused |
| `vlog_segment_id` | `u64` | value-log segments; a **separate** id space from `segment_id` |
| `name_id` | `u32` | per-tree field-name dictionary id; append-only, never reused |
| `nonce` | `u64` | AEAD nonce counter; allocated by `fetch_add`, bounded by a published floor, **never reused** (`14-security.md` §4.1) |
| `NitriteId` | `i64` | signed; the SDKs' snowflake id |

`next_tree_id` and `next_segment_id` are `u64` fields in the superblock so the
counters never need widening, but `next_tree_id` MUST NOT be allowed to exceed
`0xFFFFFFFE`: `tree_id` is a `u32` and `0xFFFFFFFF` is the page-header sentinel.

**`NitriteId` is signed 64-bit and MUST be exchanged as such.** An
implementation in a language without a native 64-bit integer (JavaScript) MUST
use an exact representation (`BigInt`) and MUST NOT round-trip ids through a
double. Values outside ±2⁵³ occur in practice — snowflake and TSID ids live
there — and truncating them has already caused a unique-index bug in this
project (`research/nitrite-survey.md` §6.3).

## 8. Limits

| | limit | why |
|---|---|---|
| `page_size` | 4096, 8192, 16384, 32768, or 65536 | fixed at creation, in the superblock |
| key length (encoded) | `page_size / 4`, and at most 4 KiB | keys above this MUST be rejected. The limit is page-relative because a key must fit in a leaf *with room for peers*; a flat 4 KiB limit is unsatisfiable at `page_size = 4096` |
| inline value length | `page_size / 4` | above this a value goes to the value log, an overflow chain, or a blob |
| `vlog_min` | MUST be ≤ `page_size / 4` | otherwise the writer's own inline threshold names values that cannot be stored inline. A writer MUST reject a `vlog_min` above the cap; a reader MUST treat a file whose superblock violates it as corrupt |
| vector dimension | `65535 / sizeof(dtype)` | `stride` is a `u16` (`09-vector.md` §2) |
| document nesting depth | 100 | a decoder MUST enforce this and MUST NOT recurse unboundedly |
| document field count | 65535 | |
| trees per database | 2³² − 17 | ids 16 … `0xFFFFFFFE`; 0–15 are reserved and `0xFFFFFFFF` is the page-header sentinel |
| database size | 2⁶⁴ × `page_size` | |
| L0 segments before compaction | 1–64, default 4 | `l0_trigger` in the superblock |
| levels | 1–16 | `level_count` in the superblock |

A decoder MUST treat every length read from the file as untrusted: it MUST
bounds-check against the containing page or extent **before** allocating, and it
MUST fail cleanly rather than allocate an attacker-chosen size. (`nitrite-rust`
has already lost a process to an unvalidated model file abort; the same class of
bug in a database file is worse.)

This is a **security** requirement, not merely a robustness one — opening a file
another party produced is what this format exists for, so every reader is a
parser of hostile input. `14-security.md` §9 states the full rule set, and it
binds at every conformance level whether or not the implementation supports
encryption.

## 9. Error behaviour

An implementation MUST distinguish, and MUST NOT conflate:

| condition | behaviour |
|---|---|
| checksum mismatch | report corruption, name the page id, do not use the page |
| AEAD tag or `sb_mac` mismatch | report **tampering** — a distinct class from corruption; name the page; do not use it and do not attempt repair (`14-security.md` §6.2) |
| encrypted file, no key or wrong key | report "cannot unlock", identically for a missing keyslot and a wrong password; never open partially |
| unknown **required** feature bit | refuse to open; report the bit number and name |
| unknown **optional** feature bit | open; ignore the structures it governs; do not delete them |
| unknown page type inside a tree the reader owns | corruption |
| unknown page type inside a tree the reader does not understand | ignore; the tree is opaque |
| unknown CVE type tag | preserve the bytes (`11-conformance.md` §4); surface as an opaque value |
| format major version > supported | refuse to open |
| format minor version > supported | open read-write only if `write_version` ≤ supported, else read-only |

Silent data loss is the one outcome the format is designed to make impossible.
Every ambiguous case above resolves toward "refuse" or "preserve", never toward
"drop".

## 10. Versioning

`format_version` is `major.minor`, both `u16`.

- **Major** changes break readers. Reserved for a rewrite; not expected.
- **Minor** changes add structures behind feature bits. A `1.x` reader opens any
  `1.y` file whose *required* feature bits it knows.
- `write_version` in the superblock records the minimum minor version an
  implementation must have to *modify* this file. A `1.0` implementation may
  read a `1.3` file whose `write_version` is `1.3` — read-only.

Feature bits, not version numbers, gate behaviour. Version numbers exist for
diagnostics and for the read-only fallback rule above.
