# CFF-07 — Full-text index

**Normative.** Conformance Level 2. Assumes `03-key-encoding.md`,
`05-catalog.md`.

Full text is the hardest thing in this format to make portable, and the reason
is not the postings — it is the **analyzer**. Two implementations that tokenize
`"Bäckerei-Straße 12"` differently will produce two indexes that disagree about
what documents exist. So this chapter specifies the analyzer first and the data
structures second.

---

## 1. Structure

Three trees per full-text index.

| kind | key | value |
|---|---|---|
| `term_dict` | `CKE(STR term)` | `CVE {"id": U32, "df": U32, "ttf": U64}` |
| `term_index` | `CKE(U32 term_id)` | `CVE STR term` — reverse lookup |
| `postings` | `CKE(Array[U32 term_id, NITRITE_ID first_doc])` | `CVE BYTES` wrapping a postings block, §4 |

The three trees are three `kind`s in the catalog: `term_dict`, `term_index` and
`postings` (`05-catalog.md` §4). All three carry `owner = <data tree name>`, so
`05-catalog.md` §11's "what indexes does X have?" finds them together.

`term_id` is allocated append-only and never reused (same discipline as
`name_id`, `02-value-encoding.md` §5.3). `df` is document frequency, `ttf` is
total term frequency; both are maintained for scoring and MUST be accurate after
a merge.

Descriptor:

```
kind   = "postings"           -- the postings tree is the index's identity
owner  = <data tree name>
params = {
    "index_type": "full_text",
    "data_tree":  U32,
    "fields":     [ STR, … ],
    "analyzer":   STR,                 -- §2, e.g. "cryptand.std.v1"
    "analyzer_params": DOC,            -- §2.4
    "term_dict":  U32,
    "term_index": U32,
    "positions":  BOOL                 -- §4.3
}
```

## 2. The analyzer

### 2.1 The rule

The analyzer is named in the descriptor. An implementation that **cannot
reproduce the named analyzer exactly** MUST NOT write to the index. It may still
read it (queries are analyzed with the same analyzer, so a reader that cannot
run it also cannot query it — it must report that, not guess).

This is the honest position. The alternative — letting each SDK tokenize with
whatever its ecosystem provides — produces an index that is silently wrong in a
way no checksum catches.

### 2.2 `cryptand.std.v1` — the normative default

Every Level-2 implementation MUST implement this analyzer exactly. It is
deliberately small, because every step is a step that can differ between
languages.

```
1. Decode the field value as UTF-8. Non-string values are skipped.
2. Normalize to Unicode NFKC.
3. Segment into words by Unicode UAX #29 word boundaries, keeping only
   segments that contain at least one character with the Unicode property
   Alphabetic or Numeric_Type != None.
4. Lowercase each segment using Unicode simple (non-tailored, locale-
   independent) case folding — the `Simple_Lowercase_Mapping` property, NOT
   full case folding and NOT a locale-sensitive `toLowerCase()`.
5. Drop segments longer than 64 code points.
6. Drop segments in the stopword set (§2.3); if no stopword set is
   configured, drop nothing.
7. Apply the stemmer (§2.4); if none is configured, apply nothing.
8. Emit the surviving segments in order, with their positions (the index of
   the segment among the segments emitted from step 3, before filtering).
```

Three specific traps, called out because they are where implementations diverge:

- **`toLowerCase()` is locale-sensitive in Java and Dart.** Java's
  `String.toLowerCase()` with a Turkish default locale maps `I` to `ı`.
  Implementations MUST pass an explicit invariant locale (`Locale.ROOT`) or use
  a code-point mapping.
- **Full case folding is not simple lowercasing.** `ẞ` folds to `ss` under full
  folding and to `ß` under simple lowercasing. The spec says simple.
- **UAX #29 is versioned by the Unicode release.** The analyzer name pins
  behaviour, so `cryptand.std.v1` also pins **Unicode 15.1** segmentation and
  case data. A later Unicode revision that changes a boundary requires
  `cryptand.std.v2`, not a silent upgrade. Implementations MUST record the
  Unicode version they implement and MUST refuse to write an index whose
  analyzer pins a version they do not have.

### 2.3 Stopwords live in the file

If a stopword set is configured it is stored **in the database**, not in the
implementation:

```
analyzer_params.stopwords = ARRAY[ STR … ]      -- sorted, NFKC, lowercased
```

Nitrite ships per-language stopword lists in all three SDKs today, and they are
not identical. Storing the actual list makes the index reproducible regardless
of which SDK's list was in scope when it was created.

`analyzer_params.stopwords_id` MAY name a well-known list (`"nitrite.en.v1"`)
*in addition*, for diagnostics; the inline array is authoritative.

### 2.4 Stemming

```
analyzer_params.stemmer = "none" | "porter2:<lang>:<snowball version>"
```

`porter2` (Snowball) is specified because it has an unambiguous published
algorithm and existing implementations in every relevant language. Anything else
is a custom analyzer with its own name.

**The version is part of the name, and an earlier draft left it out.** That
draft wrote `porter2:<lang>` and justified it with "an unambiguous published
algorithm" — which is true of a given Snowball *release* and not of the family
name. Snowball's own change log for English records behavioural changes at
3.0.0 (`past`/`paste`, `universe`/`university`, `lateral`/`later`,
`emerge`/`emergency`, `organ`/`organic`, `-ogist` → `-og`, and an `evening`
exception) and again at 3.1.0 — and one 3.1.0 entry **reverses** a 3.0.0 one:
"Removed exception for skis as the algorithm gives the same stem without it!",
then "Restored exception for skis which is needed."

Two SDKs on different Snowball releases therefore stem the same word to
different terms, which is an index that disagrees about what documents exist —
the precise failure this chapter opens by naming. It is also the identical
hazard §2.2 already handles for Unicode, and it gets the identical treatment:

- a writer MUST store the release, e.g. `porter2:en:3.1.0`;
- an implementation MUST record which release it implements, and MUST refuse to
  write an index pinning a release it does not have;
- a new Snowball release is a **new stemmer name**, not a silent upgrade, for
  the same reason a new Unicode release requires `cryptand.std.v2`.

An implementation MUST reject an unpinned `porter2:<lang>`: it cannot be made
to mean one thing, and guessing a release is how two SDKs come to disagree
without either of them being able to detect it.

### 2.5 Custom analyzers

An implementation may register `myapp.analyzer.v1`. The format stores the name
and the params; it does not and cannot verify the behaviour. Any SDK that does
not have that analyzer registered treats the index as unwritable and unqueryable
and says so. This is the correct failure — loud and specific.

## 3. Query-time analysis

A query string is analyzed with the same analyzer and params as the index. Phrase
queries require `positions = true`.

Scoring is **not** part of the format. BM25 parameters, field boosts and ranking
are the SDK's business; the format supplies `df`, `ttf`, per-document term
frequency and (optionally) positions, which is everything a scorer needs. Two
SDKs may legitimately rank the same result set differently; they MUST NOT
disagree about the set.

## 4. Postings

### 4.1 Blocking

A term's postings are split into blocks of at most 128 documents. Block *b* of
term *t* is stored at key `CKE(Array[U32 t, NITRITE_ID first_doc_of_block])`.
Blocks for one term are therefore contiguous and in document order, and a
posting can be located by seeking directly to a document id — which is what an
intersection of two terms needs.

### 4.2 Block payload

The block is a raw byte layout, stored as the payload of a CVE `BYTES` value
(tag `0x13`) so that `04-segments.md` §2.2's "an INLINE cell holds a CVE value"
holds without exception and `cryptand dump` can walk any tree without knowing
what kind it is. The two-byte cost is the price of one uniform rule.

```
u8    version               -- 1
u8    flags                 -- bit0 HAS_POSITIONS
u16   count                 -- 1…128
i64   first_doc             -- absolute NitriteId of the first posting
uvar  doc_delta × (count-1) -- zigzag deltas from the previous doc id
uvar  freq   × count        -- term frequency in that document
[ if HAS_POSITIONS ]
uvar  pos_bytes             -- total byte length of the positions area
for each document, in order:
    uvar pos_delta × freq   -- first absolute, then deltas
```

Document ids inside a block are strictly increasing, so the deltas are positive;
zigzag is used anyway so that a future out-of-order writer is representable
rather than undefined.

Positions are byte-length-prefixed as a group so that a scorer that only needs
frequencies can skip them without decoding.

### 4.3 Positions are optional

`params.positions = false` halves the index size and forbids phrase queries. An
implementation MUST reject a phrase query against an index without positions
rather than approximate it with a conjunction.

### 4.4 Updates

A document update rewrites every block it touches. Because blocks are ≤128
postings, a high-frequency term's index is many small blocks and an update
rewrites one of them, not the whole posting list. This is the property that the
current `Map<String token, List<NitriteId>>` layout in all three SDKs lacks —
there, every update to a common word rewrites a list that can be the size of the
collection.

Deleting a document removes its posting from each of its terms' blocks. A block
that empties is removed; a term whose blocks are all gone has its `df` set to 0
but keeps its dictionary entry (ids are never reused).

## 5. Relationship to Tantivy

`nitrite-tantivy-fts` writes a Tantivy directory outside the Nitrite store.
Nothing about that index is reachable from Java or Dart, and it is not covered by
the store's transactions.

Cryptand's position: the in-container index defined here is the portable one, and
it is what a `full_text` index means. An SDK may still offer Tantivy as a
separate, explicitly non-portable indexer — but it MUST declare a distinct
`index_type` (e.g. `"tantivy"`) and a feature bit, so that another SDK opening
the file sees an index it cannot maintain and behaves accordingly
(`11-conformance.md` §5) instead of assuming it is a normal full-text index.

## 6. Verification

A verifier MUST be able to rebuild the index from the data tree and compare:

1. every term in the dictionary is produced by analyzing some live document;
2. `df` equals the number of distinct documents in the term's blocks;
3. `ttf` equals the sum of frequencies;
4. block boundaries are consistent with the ≤128 rule and block keys match their
   first document;
5. positions, when present, are strictly increasing within a document.

Rebuilding requires the analyzer, so a verifier that cannot run the declared
analyzer reports "unverifiable", not "valid".
