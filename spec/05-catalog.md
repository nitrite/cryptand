# CFF-05 — Catalog, tree descriptors, and the logical Nitrite model

**Normative.** Assumes `02-value-encoding.md`, `03-key-encoding.md`,
`04-segments.md`.

This chapter defines what the trees in a Cryptand file *mean*. It is where the
semantic divergences catalogued in `research/nitrite-survey.md` §6 are settled.
A file can be byte-perfect and still be useless if the three SDKs disagree about
what `"Unique"` means — this chapter is the fix.

---

## 1. Trees are numbers; names live in the catalog

A tree is addressed by `tree_id : u32`. A tree's *name* is an arbitrary UTF-8
string stored in the catalog, subject to no escaping, mangling, or charset
restriction whatsoever.

This retires, permanently: Fjall's `| → _P_`, `+ → _K_` partition-name
substitution; Hive's base64 box keys; and every "reserved character" rule that
currently constrains what an application may call a collection. A collection may
be named `"orders|2026+eu"` and nothing downstream cares.

`tree_id`s are allocated from `next_tree_id` in the superblock and are **never
reused**, so a stale reference is detectably dangling rather than silently
pointing at a different tree.

## 2. Reserved tree ids

| id | tree | key | value |
|---|---|---|---|
| 0 | **catalog** | `CKE(STR name)` | `CVE` tree descriptor (§3) |
| 1 | **free space** | `CKE(Array[U64 commit_id, U64 start_page])` | `CVE {"pages": u32}` |
| 2 | **attributes** | `CKE(STR tree_name)` | `CVE` attributes document (§6) |
| 3 | **tree index** | `CKE(U32 tree_id)` | `CVE STR name` — reverse of the catalog |
| 4 | **repair log** | `CKE(Array[U32 tree_id, U64 commit_id, U64 seq])` | `CVE` pending index mutation (`11-conformance.md` §5) |
| 5 | **users** | `CKE(STR username)` | `CVE` credential record (§8) |
| 6 | **manifest** | `CKE(Array[U8 level, U8 group, BYTES min_internal_key])` | `CVE` segment descriptor (`04-segments.md` §3.2) |
| 7 | **value-log stats** | `CKE(U64 vlog_segment_id)` | `CVE` liveness record (`04-segments.md` §6.7) |
| 8 | **checkpoints** | `CKE(STR name)` | `CVE` retained snapshot (`13-operations.md` §1) |
| 9 | **change feed** | `CKE(Array[U32 tree_id, U64 seq])` | `CVE` change record (`13-operations.md` §7) |
| 10–15 | reserved | | |

Trees 0, 1, 3, 6 and 7 always exist. Trees 2, 4, 5, 8 and 9 are created on first
use.

Roots for trees 0, 1, 2, 6, 7, 8 and 9 are in the superblock. Every other tree's root
is in its catalog descriptor — including tree 3's, which is bootstrapped by
scanning the catalog if its descriptor is missing.

**Reserved trees are plain copy-on-write B+trees, not levelled segment sets**
(`04-segments.md` §3.3). They are small, hot and almost entirely cached;
levelling them would mean the manifest needed a manifest.

## 3. Tree descriptor

The catalog's value, a CVE document:

| field | type | meaning |
|---|---|---|
| `tree_id` | `U32` | |
| `kind` | `STR` | §4 |
| `root` | `U64` | root page id for an internal copy-on-write tree; **absent for a levelled tree**, whose segments are in the manifest |
| `levelled` | `BOOL` | true when this tree's data lives in manifest segments — `data`, `name_dict`, `index`, `term_dict`, `term_index`, `postings`, `vector_graph` and `kv`. False for `rtree`, which is a copy-on-write tree of its own page types rooted at `root`, and for the reserved trees 0–15. |
| `entries` | `U64` | live entry count (an estimate that MUST be exact after a merge) |
| `created` | `TIMESTAMP` | |
| `key_kind` | `STR` | `"nitrite_id"`, `"string"`, `"u32"`, `"array"`, `"opaque"` — advisory, for tooling |
| `owner` | `STR` | name of the tree this one serves, absent for a top-level tree |
| `name_dict` | `U32` | tree id of this tree's field-name dictionary, absent if none |
| `features` | `U64` | feature bits required to **maintain** this tree (§9) |
| `stale_from` | `U64` | commit id from which this tree is known incomplete, absent if current |
| `params` | `DOC` | kind-specific and policy fields; §3.1 and the per-kind sections below |

Unknown fields in a descriptor MUST be preserved on rewrite
(`11-conformance.md` §4).

### 3.1 `params` — the policy fields every kind may carry

**Everything that is a per-tree *policy* rather than a structural fact lives in
`params`, at the top level of that document.** An earlier draft listed five of
these as top-level descriptor fields while every other chapter wrote them as
`params.x`; `params` is the single place, and these are the names:

| `params` field | type | meaning |
|---|---|---|
| `ttl_ms` | `U64` | default time-to-live for entries written to this tree, absent if none (`04-segments.md` §9) |
| `change_feed` | `BOOL` | append this tree's mutations to tree 9 (`13-operations.md` §7) |
| `inline_values` | `BOOL` | never separate this tree's values (`04-segments.md` §6.5) |
| `zdict` | `BLOB_REF` | Zstd dictionary for this tree's values, absent if none (`01-container.md` §7) |
| `stats` | `DOC` | planner statistics, advisory (`13-operations.md` §9) |

They are policy — absent means "the default", and a reader that ignores any of
them still reads the tree correctly. That is the test for whether a field belongs
in `params`: a *structural* field (`tree_id`, `root`, `levelled`, `name_dict`,
`features`, `stale_from`) is one a reader must obey to read the tree at all, and
those stay at the descriptor's top level.

## 4. Tree kinds

| `kind` | purpose | key | value |
|---|---|---|---|
| `data` | a collection or repository's documents | `CKE(NITRITE_ID)` | `CVE DOC` |
| `name_dict` | field-name dictionary for a `data` tree | `CKE(U32 name_id)` | `CVE STR` |
| `index` | unique / non-unique / compound index | `06-indexes.md` | |
| `term_dict` | full-text term dictionary | `07-fulltext.md` | |
| `term_index` | full-text `term_id → term` reverse map | `07-fulltext.md` | |
| `postings` | full-text postings | `07-fulltext.md` | |
| `rtree` | spatial index | `08-spatial.md` | |
| `vector_graph` | ANN adjacency | `09-vector.md` | |
| `kv` | a plain key–value map, no Nitrite semantics | any `CKE` | any `CVE` |
| `internal` | reserved ids 0–15 | | |

A reader that does not recognize a `kind` MUST treat the tree as opaque: it may
be listed and copied, it MUST NOT be deleted, and it MUST NOT be interpreted.

## 5. Collection and repository naming — normative

`data` tree names, and the `params` that go with them:

| Nitrite concept | tree name | `params` |
|---|---|---|
| Collection `"orders"` | `orders` | `{"type": "collection"}` |
| Repository of `Employee` | `org.dizitart.no2.Employee` | `{"type": "repository", "entity": "org.dizitart.no2.Employee"}` |
| Keyed repository of `Employee`, key `"archive"` | `org.dizitart.no2.Employee+archive` | `{"type": "repository", "entity": "…", "key": "archive"}` |

The `+` in a keyed repository name is retained for continuity with existing
Nitrite names, but it is now **just a character in a string**, not a separator
that any layer has to escape. `params` carries the structured truth; the name is
for humans.

The registry documents that Java and Dart write under `"collections"` /
`"repositories"` / `"keyed-repositories"` and that Rust spells `"collection"`
(singular) are **removed**. Enumerating collections is a scan of the catalog
filtered on `kind == "data"` and `params.type`. There is no second place where
this list is written, so it cannot drift.

## 6. Attributes

Tree 2, replacing `$nitrite_meta_map`. Key is the tree's name; value:

```
{ "name": STR, "created_at": TIMESTAMP, "last_modified_at": TIMESTAMP,
  "owner": STR?, "uuid": STR?, … application keys … }
```

Attribute names are unrestricted UTF-8. `last_modified_at` MUST be updated in
the same commit as the mutation it describes — it is not a separate write, and
batch atomicity makes that free.

## 7. Store metadata

Replaces `$nitrite_store_info`. Stored as the attributes entry for the reserved
name `"$store"`:

```
{ "created": TIMESTAMP, "format_version": STR, "nitrite_version": STR,
  "schema_version": U32, "writers": [ STR … ] }
```

`schema_version` is Nitrite's application-level migration counter (initial value
1, as in all three SDKs today). `writers` accumulates each distinct
`writer_id` that has modified the file — a genuinely useful field the moment a
file is being handed between SDKs, and the first thing to look at when a file
misbehaves.

## 8. Users

Tree 5, replacing `$nitrite_users`:

```
{ "username": STR, "kdf": STR, "params": DOC, "salt": BYTES, "hash": BYTES }
```

`kdf` MUST be `"argon2id"` with the parameters of `14-security.md` §3.2, `salt`
MUST be random per record, and `hash` MUST be compared in constant time. Only
the derived hash is stored.

This authenticates a *user*, which is a different thing from encrypting the
*file*. `14-security.md` §10 is normative on the relationship, and the two rules
that matter are:

- **A password-protected but unencrypted database protects nothing** from an
  attacker holding the file — this tree is *in* the file, beside plaintext data.
  An implementation MUST NOT present that configuration as protection.
- **On an encrypted database this tree is not a second boundary.** Whoever
  opened the file has the master key and can read every user's data. Tree 5 is
  application-level role separation, not confidentiality.

## 9. Feature bits on a tree

`features` in a tree descriptor names what an implementation must be able to do
**to keep this tree correct**, not merely to read it. A vector index tree carries
the `VECTOR` bit; a spatial index carries `SPATIAL`.

The rule that follows from it is the heart of safe interchange, and it is
specified in `11-conformance.md` §5: an implementation that mutates a `data`
tree while lacking a feature bit required by one of that collection's index
trees MUST NOT silently leave the index wrong. It either refuses the write or
records the mutation in the repair log and marks the index `stale_from`.

## 10. Index type names — normative

The three SDKs disagree today (`Unique`/`NonUnique`/`Fulltext` in Java and Dart,
`unique`/`non-unique`/`full-text` in Rust). The on-disk spelling is now fixed:

| index | `params.index_type` |
|---|---|
| unique | `unique` |
| non-unique | `non_unique` |
| full text | `full_text` |
| spatial | `spatial` |
| vector | `vector` |

Lower snake case, no hyphens, no camel case. Every SDK maps its own public
constant to these on write and back on read. Public API constants do not have to
change; the *bytes* do.

These five are the **portable** names, and only these five. An implementation
MAY define a non-portable index type — `"tantivy"` is the worked example in
`07-fulltext.md` §5 — provided it declares a vendor feature bit on the tree
(`11-conformance.md` §2) so that another SDK sees an index it cannot maintain
rather than one it misinterprets. A reader encountering an unknown
`params.index_type` MUST treat the tree as opaque (§4).

Nothing derives a tree name by concatenating this string, because tree names are
not derived at all (§1) — the association between a data tree and its indexes is
by `tree_id` in the index descriptor's `owner` and `params`
(`06-indexes.md` §2), not by string surgery.

## 11. Enumerations a reader must support

Given only the catalog:

| question | answer |
|---|---|
| what collections exist? | scan tree 0, `kind == "data"`, `params.type == "collection"` |
| what repositories exist? | same, `params.type == "repository"`, no `params.key` |
| what keyed repositories? | same, with `params.key` |
| what indexes does `X` have? | scan tree 0, `owner == X`, `kind ∈ {index, term_dict, term_index, postings, rtree, vector_graph}` |
| is any index stale? | any descriptor with `stale_from` present |
| what features does this file need? | superblock `features_required`, plus the union of every tree's `features` |
