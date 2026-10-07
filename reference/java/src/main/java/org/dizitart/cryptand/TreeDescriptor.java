package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NameDict;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A catalog entry — {@code spec/05-catalog.md} §3.
 *
 * <p>The catalog is tree 0, keyed by {@code CKE(STR name)}, and its value is a
 * CVE document. This class is a <strong>typed view over that document, not a
 * replacement for it</strong>: the {@link #document()} is the truth, and every
 * field this implementation does not know about survives a rewrite untouched,
 * which is what {@code spec/11-conformance.md} §4 requires.
 *
 * <p>A view rather than a record with named fields is the difference between
 * preserving unknown fields and claiming to. A class with a fixed field list
 * silently drops whatever it was not compiled to know, and the first symptom is
 * a newer SDK's data disappearing when an older one rewrites a descriptor.
 *
 * <p>There is no second place where the list of trees is written, so it cannot
 * drift: enumerating collections is a scan of the catalog, and the
 * {@code "collections"} / {@code "repositories"} registries that Java and Dart
 * keep today are simply absent.
 */
public final class TreeDescriptor {

    /** {@code kind} values — §4. */
    public static final class Kind {
        private Kind() {
        }

        public static final String DATA = "data";
        public static final String NAME_DICT = "name_dict";
        public static final String INDEX = "index";
        public static final String TERM_DICT = "term_dict";
        public static final String TERM_INDEX = "term_index";
        public static final String POSTINGS = "postings";
        public static final String RTREE = "rtree";
        public static final String VECTOR_GRAPH = "vector_graph";
        public static final String KV = "kv";
        public static final String INTERNAL = "internal";
    }

    /**
     * The only portable index type names — §10: lower snake case, no hyphens,
     * no camel case.
     */
    public static final class IndexType {
        private IndexType() {
        }

        public static final String UNIQUE = "unique";
        public static final String NON_UNIQUE = "non_unique";
        public static final String FULL_TEXT = "full_text";
        public static final String SPATIAL = "spatial";
        public static final String VECTOR = "vector";
    }

    private final Value.Doc document;

    public TreeDescriptor(Value.Doc document) {
        this.document = document;
    }

    public static TreeDescriptor decode(byte[] cve, NameDict dict) {
        Value v = Cve.decode(cve, dict);
        if (!(v instanceof Value.Doc)) {
            throw new CorruptionException("a catalog value must be a CVE document, got " + v.getClass().getSimpleName());
        }
        Value.Doc d = ((Value.Doc) v);
        return new TreeDescriptor(d);
    }

    /** The underlying document, unknown fields and all. */
    public Value.Doc document() {
        return document;
    }

    public byte[] encode(NameDict dict) {
        return Cve.encode(document, dict);
    }

    /** The catalog key for a tree name: {@code CKE(STR name)}. */
    public static byte[] catalogKey(String name) {
        return Cke.encode(new Value.Str(name));
    }

    // --- structural fields, which a reader must obey to read the tree ----

    public int treeId() {
        return (int) requireLong("tree_id");
    }

    public String kind() {
        return requireString("kind");
    }

    /**
     * Root page id for an internal copy-on-write tree.
     *
     * <p><strong>Absent for a levelled tree</strong>, whose segments live in the
     * manifest instead.
     */
    public Long root() {
        return optionalLong("root");
    }

    /**
     * True when this tree's data lives in manifest segments. False for
     * {@code rtree}, which is a copy-on-write tree of its own page types, and
     * for the reserved trees 0–15.
     */
    public boolean levelled() {
        Value v = document.field("levelled");
        return v instanceof Value.Bool && ((Value.Bool) v).value();
    }

    /** Tree id of this tree's field-name dictionary, absent if none. */
    public Integer nameDict() {
        Long v = optionalLong("name_dict");
        return v == null ? null : v.intValue();
    }

    /** Feature bits required to <em>maintain</em> this tree. */
    public long features() {
        Long v = optionalLong("features");
        return v == null ? 0 : v;
    }

    /** Commit id from which this tree is known incomplete, absent if current. */
    public Long staleFrom() {
        return optionalLong("stale_from");
    }

    // --- advisory and policy --------------------------------------------

    /** Live entry count. An estimate that MUST be exact after a merge. */
    public long entries() {
        Long v = optionalLong("entries");
        return v == null ? 0 : v;
    }

    /** Advisory, for tooling: {@code nitrite_id}, {@code string}, {@code u32}, {@code array}, {@code opaque}. */
    public String keyKind() {
        return optionalString("key_kind");
    }

    /** Name of the tree this one serves, absent for a top-level tree. */
    public String owner() {
        return optionalString("owner");
    }

    /**
     * Kind-specific and policy fields.
     *
     * <p>Everything that is a per-tree <em>policy</em> rather than a structural
     * fact lives here. The test for which is whether a reader that ignores the
     * field still reads the tree correctly: {@code ttl_ms}, {@code change_feed},
     * {@code inline_values}, {@code zdict} and {@code stats} all pass it, and
     * {@code tree_id}, {@code root}, {@code levelled}, {@code name_dict},
     * {@code features} and {@code stale_from} all fail it and stay at the top
     * level.
     */
    public Value.Doc params() {
        Value v = document.field("params");
        return v instanceof Value.Doc ? ((Value.Doc) v) : new Value.Doc(Map.of());
    }

    /** {@code params.index_type} — the ONLY record of uniqueness. */
    public String indexType() {
        Value v = params().field("index_type");
        return v instanceof Value.Str ? ((Value.Str) v).value() : null;
    }

    /**
     * Whether an index tree is unique.
     *
     * <p>Uniqueness is {@code index_type == "unique"} and nothing else. An
     * earlier draft also carried a {@code "unique": BOOL} alongside; two records
     * of one fact drift and nothing said which wins, so the boolean is gone. A
     * reader meeting a stray {@code unique} field preserves it and ignores it —
     * which this does, because {@link #document()} keeps it.
     */
    public boolean unique() {
        return IndexType.UNIQUE.equals(indexType());
    }

    // --- building --------------------------------------------------------

    /** A builder that produces the document; unset fields are simply absent. */
    public static final class Builder {
        private final Map<String, Value> fields = new LinkedHashMap<>();

        public Builder treeId(int id) {
            fields.put("tree_id", Value.integer(NumType.U32, id));
            return this;
        }

        public Builder kind(String kind) {
            fields.put("kind", new Value.Str(kind));
            return this;
        }

        public Builder root(long root) {
            fields.put("root", Value.integer(NumType.U64, root));
            return this;
        }

        public Builder levelled(boolean levelled) {
            fields.put("levelled", levelled ? Value.TRUE : Value.FALSE);
            return this;
        }

        public Builder entries(long entries) {
            fields.put("entries", Value.integer(NumType.U64, entries));
            return this;
        }

        public Builder created(long utcMillis) {
            fields.put("created", new Value.Timestamp(utcMillis));
            return this;
        }

        public Builder keyKind(String keyKind) {
            fields.put("key_kind", new Value.Str(keyKind));
            return this;
        }

        public Builder owner(String owner) {
            fields.put("owner", new Value.Str(owner));
            return this;
        }

        public Builder nameDict(int treeId) {
            fields.put("name_dict", Value.integer(NumType.U32, treeId));
            return this;
        }

        public Builder features(long features) {
            fields.put("features", Value.integer(NumType.U64, features));
            return this;
        }

        public Builder params(Map<String, Value> params) {
            fields.put("params", new Value.Doc(params));
            return this;
        }

        public TreeDescriptor build() {
            return new TreeDescriptor(new Value.Doc(fields));
        }
    }

    // --- helpers ---------------------------------------------------------

    private long requireLong(String name) {
        Long v = optionalLong(name);
        if (v == null) {
            throw new CorruptionException("tree descriptor is missing required field '" + name + "'");
        }
        return v;
    }

    private Long optionalLong(String name) {
        Value v = document.field(name);
        if (v == null) {
            return null;
        }
        if (!(v instanceof Value.Int)) {
            throw new CorruptionException("tree descriptor field '" + name + "' is not an integer");
        }
        Value.Int i = ((Value.Int) v);
        Long l = i.asLong();
        if (l == null) {
            throw new CorruptionException("tree descriptor field '" + name + "' does not fit 64 bits");
        }
        return l;
    }

    private String requireString(String name) {
        String v = optionalString(name);
        if (v == null) {
            throw new CorruptionException("tree descriptor is missing required field '" + name + "'");
        }
        return v;
    }

    private String optionalString(String name) {
        Value v = document.field(name);
        if (v == null) {
            return null;
        }
        if (!(v instanceof Value.Str)) {
            throw new CorruptionException("tree descriptor field '" + name + "' is not a string");
        }
        Value.Str s = ((Value.Str) v);
        return s.value();
    }
}
