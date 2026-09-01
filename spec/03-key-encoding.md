# CFF-03 — CKE, the Cryptand Ordered Key Encoding

**Normative.** Assumes `00-conventions.md`.

CKE turns a Nitrite value into a byte string with one property:

> **CKE order refines logical order, and never contradicts it.** For any two
> keys *a* and *b*, writing `L` for the logical comparison of
> `02-value-encoding.md` §8 and `M` for `memcmp(CKE(a), CKE(b))`:
>
> 1. if `L != 0` then `M` has the same sign as `L`; and
> 2. if `L == 0` then either `CKE(a) == CKE(b)`, or *a* and *b* are numerically
>    equal values of different declared types whose keys differ **only** in the
>    trailing type code of §4.3 — so both lie inside
>    `[N(v), successor(N(v)))` and are adjacent there.

Clause 2 is not a caveat bolted on. It is the entire purpose of the type code,
and it is what lets an exact-type point lookup stay a point lookup while `eq(5)`
across every numeric type stays one range scan (§4.4). Together the two clauses
say that CKE is a **total** order whose collapse — drop the type code — is the
logical order.

Stating it as a plain "same sign as" would be false, and demonstrably so:
`I8(0)` and `I16(0)` compare **equal** under §8 rule 2 of
`02-value-encoding.md`, and encode as `30 02 00` and `30 02 01`. The reference
implementation's ordering test asserts the two clauses above, which is the
property an engine actually needs; an earlier draft's one-line version failed on
the first pair of equal-valued differently-typed integers it was pointed at.

That property is what makes a Cryptand file mean the same thing in every
language. No implementation ever calls a host comparator (`Comparable`,
`Ord`, `compareTo`) to navigate the tree; the bytes decide, and the bytes are
specified here.

**All multi-byte integers in this chapter are big-endian.** This is the only
part of the format where that is true.

CKE is also **injective and decodable**: an encoded key can be turned back into
its value without consulting a schema.

---

## 1. Shape

```
CKE(v) := u8 group_tag || body(v)
```

## 2. Group tags and cross-type order

| tag | group |
|---|---|
| `0x00` | `NULL` |
| `0x10` | `BOOL` |
| `0x30` | `NUMBER` — every integer and float type, one ordered domain |
| `0x40` | `TEMPORAL` |
| `0x50` | `CHAR` |
| `0x60` | `STRING` |
| `0x70` | `BYTES` |
| `0x80` | `NITRITE_ID` |
| `0x90` | `UUID` |
| `0xA0` | `ARRAY` — composite / tuple keys |

Values of different groups order by tag. That order is total and stable but
carries no semantic meaning; a query SHOULD NOT depend on it. In practice keys
within one tree are homogeneous — a data tree holds only `NITRITE_ID`, an index
tree holds only `ARRAY`.

Tags `0xB0`–`0xEF` are reserved. Tag `0xFF` MUST NOT appear: it is reserved so
that `0xFF` repeated is always above every valid key, which §8 relies on.

`DOC`, `MAP`, `VECTOR`, `GEOMETRY`, `REGEX`, `OPAQUE`, `DEC128`, `BLOB_REF`,
`OVERFLOW_REF` and `VLOG_REF` have no CKE encoding. Attempting to use one as a
key is an error and MUST be reported as such. (`DEC128` is the one that looks
encodable and is not — see §4.4.)

## 3. Simple groups

```
NULL     0x00
BOOL     0x10 || 0x00 (false) | 0x01 (true)
CHAR     0x50 || u32be scalar
NITRITE_ID  0x80 || u64be( (id as u64) XOR 0x8000_0000_0000_0000 )
UUID     0x90 || 16 bytes, RFC 4122 network byte order
```

The XOR on `NITRITE_ID` flips the sign bit so that a signed `i64` sorts
correctly as unsigned bytes. Snowflake ids are positive in practice, but
`NitriteId.createId(long)` accepts any `i64` and the format must not depend on
application discipline.

### 3.1 STRING and BYTES

Both use the same **escaped, self-delimiting byte string** encoding, written
`esc(s)`:

```
for each byte b of s:
    if b == 0x00: emit 0x00, 0x01
    else:         emit b
emit 0x00, 0x00                     -- terminator
```

```
STRING   0x60 || esc(utf8(s))
BYTES    0x70 || esc(s)
```

Because the terminator `0x00 0x00` is below every escaped continuation, a
shorter string sorts before a longer one that extends it: `"ab" < "abc"`. Strings
compare by UTF-8 bytes, which is Unicode code-point order. There is no
normalization, no case folding and no locale.

The complementary function `esc_neg(s)` — used only by §4 — is `esc(s)` with
`0xFF` playing the role of `0x00`:

```
for each byte b of s:
    if b == 0xFF: emit 0xFF, 0xFE
    else:         emit b
emit 0xFF, 0xFF
```

## 4. NUMBER — one exact ordered domain for every numeric type

This is the chapter's centre of gravity, and the fix for the divergence recorded
in `research/nitrite-survey.md` §6.3.

```
NUMBER := 0x30 || sign_class || ordering_region || type_code
```

`sign_class` (one byte, ordered):

| value | meaning |
|---|---|
| `0x00` | −Infinity |
| `0x01` | negative finite |
| `0x02` | zero (+0.0, −0.0 and integer 0 are all this) |
| `0x03` | positive finite |
| `0x04` | +Infinity |
| `0x05` | NaN |

`ordering_region` is **empty** for `0x00`, `0x02`, `0x04` and `0x05`.

### 4.1 Normalization

For a finite non-zero value *v*, produce the exact pair `(e, m)` such that

```
|v| = m × 2^e ,  1 ≤ m < 2
```

with *m* held as a 128-bit big-endian fraction, MSB-aligned (bit 127 is *m*'s
integer bit and is therefore always 1).

**From an integer** `u = |v|` as `u128` (note `|i128::MIN| = 2^127` needs the
unsigned width):

```
n = 128 - leading_zeros(u)          -- significant bits, 1…128
e = n - 1
m = u << (128 - n)
```

**From an `f64`**: split into `sign`, `biased_exp` (11 bits), `frac` (52 bits).

```
if biased_exp != 0:                 -- normal
    sig = (1 << 52) | frac
    e   = biased_exp - 1023
else:                               -- subnormal, frac != 0
    k   = 52 - (63 - leading_zeros(frac))     -- shifts to normalize
    sig = frac << k
    e   = -1022 - k
m = sig << (128 - 53)
```

**From an `f32`**: identically, with 8/23-bit fields, bias 127, and
`m = sig << (128 - 24)`.

Every one of these is exact, uses only shifts and a count-leading-zeros, and
requires no arbitrary-precision arithmetic in any language.

### 4.2 Body

```
mbytes  = the 16 bytes of m, big-endian, with trailing 0x00 bytes removed
          (mbytes is never empty: its first byte is ≥ 0x80)
body    = u16be(e + 16384) || esc(mbytes)
```

Then:

```
v > 0:  ordering_region = body
v < 0:  ordering_region = complement(body)     -- bitwise NOT of every byte,
                                                  escaping applied as esc_neg
```

Equivalently for negatives: encode `|v|` exactly as above, then invert every
byte of the result. Inverting a byte string reverses its lexicographic order,
which is precisely what negatives need — larger magnitude must sort lower.

### 4.3 Type code

One byte, appended **after** the ordering region, purely to round-trip the
source type:

| | | | |
|---|---|---|---|
| `0x00` I8 | `0x01` I16 | `0x02` I32 | `0x03` I64 |
| `0x04` I128 | `0x05` U8 | `0x06` U16 | `0x07` U32 |
| `0x08` U64 | `0x09` U128 | `0x0A` F32 | `0x0B` F64 |
| `0x0C` INT_VAR | `0x0D` *reserved* | | |

Because the ordering region is self-delimiting, the type code only ever breaks
ties between **numerically equal** values. `I32(5)` and `F64(5.0)` therefore
produce two distinct keys that sort adjacently. This is clause 2 of §1's
invariant, and it is why a query planner MUST build numeric bounds from `N(v)`
(§8.2): a bound carrying a type code cuts *inside* an equality class.

### 4.4 Consequences — read this before implementing a query planner

- **Equality across numeric types is a prefix range scan**, not a point lookup.
  To find every entry whose value equals 5, scan
  `[ 0x30 03 <ordering_region(5)> , successor(same) )`. All numeric types with
  that exact value are contiguous. One seek, no false positives, no lossy fold.
- **Point lookup on an exact type is still a point lookup** — append the type
  code.
- **Ordering is exact everywhere**, including integers above 2⁵³. There is no
  magnitude bucket and no re-check. This is the improvement over
  `nitrite-fjall-adapter/src/ordered_key.rs`, which orders by an `f64` magnitude
  prefix and is therefore approximate in that range.
- **`DEC128` has no CKE encoding and MUST NOT be used as a key.** The
  normalization above produces an exact `m × 2^e`, and most decimal fractions —
  `0.1` being the obvious one — have no finite binary fraction, so a decimal128
  cannot be encoded exactly, cannot be decoded back (§7), and cannot be ordered
  against an `f64` without silently rounding one of them. A writer MUST reject a
  `DEC128` as an index key with a clear error; it remains fully storable as a CVE
  value and fully round-trips there. Type code `0x0D` stays reserved so that a
  future minor version can add an exact decimal ordering region under its own
  feature bit without renumbering.

  (This is the honest resolution. An earlier draft admitted `DEC128` as a key if
  it fitted 128 significant bits and an exponent within ±16383 — which is a bound
  on *size*, not on *representability*, and does not make `0.1` encodable.)
- Java's `DBValue.normalizeNumber` fold to `Double` becomes unnecessary and MUST
  NOT be applied when writing CKE. It exists only to make RocksDB's encoded-byte
  comparison approximate the logical one; CKE makes them identical.

## 5. TEMPORAL

```
TEMPORAL := 0x40 || subclass || body
```

| subclass | body | orders by | CVE tags |
|---|---|---|---|
| `0x01` INSTANT | `u64be(secs XOR 2^63) \|\| u32be(nanos)` | instant | `TIMESTAMP`, `TIMESTAMP_NS`, `ZONED` |
| `0x03` DATE | `u32be(days XOR 2^31)` | date | `DATE` |
| `0x04` TIME | `u64be(nanos_since_midnight)` | time of day | `TIME` |
| `0x05` DURATION | `u64be(secs XOR 2^63) \|\| u32be(nanos)` | length | `DURATION` |

Subclass `0x02` is **reserved and MUST NOT be written**. An earlier draft gave
millisecond and nanosecond instants two subclasses; because subclasses order by
their subclass byte before their body, that made a `TIMESTAMP` of 2000 ms sort
*below* a `TIMESTAMP_NS` of 1 s — precision deciding the order instead of the
instant, in direct contradiction of `02-value-encoding.md` §8 rule 7. There is now
**one instant subclass**, and every instant-valued CVE tag canonicalizes into it:

```
TIMESTAMP(millis)         → secs = floor_div(millis, 1000)
                            nanos = (millis - secs*1000) * 1_000_000
TIMESTAMP_NS(secs, nanos) → as given, with nanos normalized to 0…999_999_999
ZONED(millis, zone)       → as TIMESTAMP; the zone is dropped
```

`floor_div` is floor division, not truncation, so instants before the epoch
normalize correctly (`-1 ms` is `secs = -1, nanos = 999_000_000`, not
`secs = 0, nanos = -1_000_000`). A decoder recovers a `TIMESTAMP_NS`; an SDK
whose field is declared as milliseconds narrows on the way out. **The key does
not round-trip the source precision**, which is correct: two values denoting the
same instant must be the same key, or an index cannot answer an instant query.

`ZONED` therefore drops its zone id from the key: two zoned timestamps denoting
the same instant are the same key, and an index on a zoned field answers instant
queries, which is what applications mean.

`DATE`, `TIME` and `DURATION` order among themselves by subclass byte. Comparing
a `DATE` to an `INSTANT` is not meaningful and applications should not do it; the
format only guarantees the order is stable.

## 6. ARRAY — composite and tuple keys

```
ARRAY := 0xA0 || ( 0x01 || CKE(element) ) ×  n  || 0x00
```

`0x01` is `ELEM_CONTINUE`, `0x00` is `ELEM_END`. Because `ELEM_END < ELEM_CONTINUE`,
a shorter tuple sorts before a longer one that extends it: `[a] < [a, b]`.
Elements are compared position by position, which is what a compound index needs.

Every index key in Cryptand is an `ARRAY` (`06-indexes.md`). A single-field
non-unique index key is `[value, id]`; a three-field compound index key is
`[v1, v2, v3, id]`.

Nesting is permitted (an array element may itself be an array) and counts
against the depth limit.

## 7. Decoding

CKE is decodable. Each group's body is either fixed-width or self-delimiting, so
a decoder reads the tag, consumes exactly the body, and returns a value plus the
number of bytes consumed. This matters because index scans return keys, and the
SDK needs the indexed value and the document id back out of them without a
second lookup.

A decoder MUST reject: an unknown group tag, a truncated body, a non-canonical
escape (`0x00` followed by anything but `0x00` or `0x01`), a mantissa whose
first byte is below `0x80`, an empty mantissa, a numeric type code of `0x0D` or
above (§4.3), and temporal subclass `0x02` (§5).

**Three** decodings are lossy, by design, and an implementation MUST NOT treat
any of them as a defect. Each is a case where §8 of `02-value-encoding.md`
declares two distinct values *equal*, and a key that distinguished them would
break §1 clause 1:

| lossy case | decodes as | why |
|---|---|---|
| `TIMESTAMP`, `TIMESTAMP_NS` and `ZONED` | always `TIMESTAMP_NS(secs, nanos)`; a `ZONED` key has lost its zone | §5 — two values denoting the same instant must be one key, or an index on a timestamp field cannot answer an instant query |
| **`-0.0`** | `+0.0`, sign class `zero` | §8 rule 3 of `02-value-encoding.md`: "−0.0 equals +0.0 and they sort equal". A sign class that separated them would put a value strictly between two equal values |
| a NaN with a payload | the canonical quiet NaN | `00-conventions.md` §3 canonicalizes NaN on encode; §8 rule 3 makes all NaNs equal so a NaN key is findable |

**NUMBER otherwise round-trips exactly**, including its declared width, because
the type code carries it.

Everything else is exactly injective. A conformance vector set MUST include all
three lossy cases with their expected decoded value, because an implementation
that "fixes" one of them has broken the order.

## 8. Range construction

**Five normative helpers.** Every SDK's query planner uses these and only these;
no SDK invents its own bound sentinel. Every range below is **half-open**,
`[lo, hi)` — there is no exclusive lower bound anywhere in the format, because
`successor` already produces one.

```
successor(k):                       -- least byte string greater than every
    b = copy of k                   --   string having k as a prefix
    while b is non-empty and b.last == 0xFF: drop b.last
    if b is empty: return UNBOUNDED_ABOVE
    b.last += 1
    return b
```

```
prefix_of_array(p1 … pk):           -- the shared prefix of every ARRAY key
    0xA0 || ( 0x01 || CKE(pi) ) × k --   whose first k elements are p1 … pk
```

```
N(v):                               -- the NUMBER encoding of a numeric v with
    CKE(v) minus its trailing       --   the type code removed: the shared prefix
    type_code byte                  --   of every numeric type equal to v
```

```
esc_open(s):                        -- esc(s) with the 0x00 0x00 terminator
    esc(s) minus its last two bytes --   omitted: the shared prefix of every
                                    --   string beginning with s
```

```
array_prefix_numeric(p1 … pk):      -- prefix_of_array, but the LAST element
    0xA0 || ( 0x01 || CKE(pi) ) × (k-1)   is left type-agnostic
        || 0x01 || N(pk)
```

`UNBOUNDED_ABOVE` is an open upper bound, not a byte string; this is why tag
`0xFF` is reserved. `UNBOUNDED_BELOW` is the **empty byte string**, which is
below every key, so it needs no sentinel and no special case.

### 8.1 Scalar predicates

`v` below is a *non-numeric* value; numbers are §8.2, because they are the case
where using the full `CKE(v)` is wrong.

| predicate | scan |
|---|---|
| `field == v` | `[CKE(v), successor(CKE(v)))` |
| `field > v` | `[successor(CKE(v)), UNBOUNDED_ABOVE)` |
| `field >= v` | `[CKE(v), UNBOUNDED_ABOVE)` |
| `field < v` | `[UNBOUNDED_BELOW, CKE(v))` |
| `field <= v` | `[UNBOUNDED_BELOW, successor(CKE(v)))` |
| `field between a, b` inclusive | `[CKE(a), successor(CKE(b)))` |
| `field starts with "abc"` | `[0x60 ‖ esc_open("abc"), successor(same))` |

### 8.2 Numeric predicates — use `N(v)`, never `CKE(v)`

**A numeric comparison MUST be built from `N(v)`, not from `CKE(v)`.** Every
numeric tag is one ordered domain (`02-value-encoding.md` §8 rule 2), so a bound that
carries a type code cuts the domain in the middle of a group of numerically
equal keys:

| predicate | scan |
|---|---|
| `field == v` (any numeric type) | `[N(v), successor(N(v)))` |
| `field == v` (**one** declared type only) | `[CKE(v), successor(CKE(v)))` |
| `field > v` | `[successor(N(v)), UNBOUNDED_ABOVE)` |
| `field >= v` | `[N(v), UNBOUNDED_ABOVE)` |
| `field < v` | `[UNBOUNDED_BELOW, N(v))` |
| `field <= v` | `[UNBOUNDED_BELOW, successor(N(v)))` |
| `field between a, b` inclusive | `[N(a), successor(N(b)))` |

Why it matters, concretely. `CKE(I32(5))` is `30 03 40 02 A0 00 00 **02**` and
`CKE(U8(5))` is the same with type code `05`. Building `field > 5` as
`[successor(CKE(I32(5))), …)` starts the scan at `… 00 03`, which **excludes**
`I64(5)` (correct — it is not greater than 5) but **includes** `I128(5)`, `U8(5)`
and `F64(5.0)`, none of which are greater than 5 either. Symmetrically,
`field >= 5` built as `[CKE(I32(5)), …)` **misses** `I8(5)` and `I16(5)`, whose
type codes sort below `I32`'s. `N(v)` — `30 03 40 02 A0 00 00` — has no type code
and so cuts cleanly between numeric values instead of between numeric types.

`successor(N(v))` is well-formed for every sign class: the ordering region of a
finite value ends in the escape terminator `00 00`, so `successor` yields
`… 00 01`, which is above every type code (`0x00`–`0x0D`) and below the encoding
of any larger magnitude. For the empty-region classes it degenerates cleanly —
`successor(30 02)` is `30 03`, i.e. "all zeros" ends exactly where "positive
finite" begins.

### 8.3 Composite (index) predicates

Every index key is an `ARRAY` (`06-indexes.md` §1), so an index predicate is an
array-prefix scan. The last constrained element decides which helper to use:

| predicate | scan |
|---|---|
| equality on the prefix `v1 … vj`, last element non-numeric or type-exact | `[prefix_of_array(v1…vj), successor(same))` |
| equality on the prefix `v1 … vj`, **last element numeric, type-agnostic** | `[array_prefix_numeric(v1…vj), successor(same))` |
| equality on `v1 … v(j-1)`, range on the j-th | lower and upper built as §8.1 / §8.2 applied to the j-th element and appended to `prefix_of_array(v1…v(j-1)) ‖ 0x01` |
| `starts_with` on a string in the j-th position | `prefix_of_array(v1…v(j-1)) ‖ 0x01 ‖ 0x60 ‖ esc_open(s)`, and its `successor` |

`array_prefix_numeric` is what makes `02-value-encoding.md` §8 rule 2's "one numeric
domain" reachable *on an actual index*. Without it, an index on a numeric field
answers `eq(5)` only for the exact type that was written — which is the divergence
this chapter exists to remove.

The `LOWER = -1 / EXACT = 0 / UPPER = 1` bound byte that Java's `IndexEntryKey`
and Dart's `IndexKey._Bound` carry today is not needed and MUST NOT be stored:
`successor` and `prefix_of_array` do the same job outside the key, saving a byte
per index entry and removing a class of "sentinel accidentally persisted" bugs.

## 9. Worked examples

Bytes shown in hex, tags in **bold**.

| value | CKE |
|---|---|
| `null` | **00** |
| `true` | **10** 01 |
| `0` (i32) | **30** 02 02 |
| `5` (i32) | **30** 03 40 02 A0 00 00 02 |
| `5.0` (f64) | **30** 03 40 02 A0 00 00 0B |
| `-5` (i32) | **30** 01 BF FD 5F FF FF 02 |
| `-9` (i32) | **30** 01 BF FC 6F FF FF 02 |
| `"ab"` | **60** 61 62 00 00 |
| `"abc"` | **60** 61 62 63 00 00 |
| `NitriteId(1)` | **80** 80 00 00 00 00 00 00 01 |
| `["ab", NitriteId(1)]` | **A0** 01 60 61 62 00 00 01 80 80 00 00 00 00 00 00 01 00 |
| `TIMESTAMP(1000)` | **40** 01 80 00 00 00 00 00 00 01 00 00 00 00 |
| `TIMESTAMP_NS(1, 0)` | **40** 01 80 00 00 00 00 00 00 01 00 00 00 00 — **byte-identical**, as §5 requires |
| `TIMESTAMP(2000)` | **40** 01 80 00 00 00 00 00 00 02 00 00 00 00 |

Check the orderings that matter:

- `-9 < -5`: `BF FC …` < `BF FD …` ✓ (magnitudes inverted, so the larger
  magnitude sorts lower)
- `5 (i32) < 5.0 (f64)`: identical through `A0 00 00`, then type code `02 < 0B` ✓,
  and both are inside the scan `[N(5), successor(N(5)))` =
  `[30 03 40 02 A0 00 00, 30 03 40 02 A0 00 01)` so `eq(5)` finds both — which is
  precisely why a numeric bound is built from `N(v)` and not from `CKE(v)` (§8.2).
- `TIMESTAMP(1000) < TIMESTAMP(2000)` ✓, and `TIMESTAMP(2000)` sorts **above**
  `TIMESTAMP_NS(1, 0)` — which it must, and which the earlier two-subclass
  encoding got backwards, because it compared the subclass byte first.
