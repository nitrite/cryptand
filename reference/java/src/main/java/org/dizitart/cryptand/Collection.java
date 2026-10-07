package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.index.FullTextIndex;
import org.dizitart.cryptand.index.SpatialIndex;
import org.dizitart.cryptand.index.VectorIndex;
import org.dizitart.cryptand.index.VectorRegion;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.key.IndexKeys;
import org.dizitart.cryptand.ops.IndexStats;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.text.Analyzer;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NameDict;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A {@code data} tree and the indexes that serve it —
 * {@code spec/05-catalog.md} §4 and {@code spec/06-indexes.md}.
 *
 * <p>Documents are keyed by {@code CKE(NITRITE_ID)} and stored as
 * {@code CVE DOC}, against a per-collection field-name dictionary.
 *
 * <p><strong>Index maintenance and the document write go into the same
 * batch</strong> and therefore the same commit (§8). An index can never be
 * transiently out of step with its collection in a durable state — a guarantee
 * only the Fjall backend offers Nitrite today, and only because of
 * {@code run_atomic}.
 */
public final class Collection {

    private final Database db;
    private final String name;
    private final TreeDescriptor descriptor;
    private final Engine engine;
    private final NameDict names;
    private final int dictTreeId;
    private final AtomicLong idSource = new AtomicLong(System.currentTimeMillis() * 1000);

    Collection(Database db, String name, TreeDescriptor descriptor) {
        this.db = db;
        this.name = name;
        this.descriptor = descriptor;
        this.engine = db.engine();
        Integer dict = descriptor.nameDict();
        this.dictTreeId = dict == null ? -1 : dict;
        this.names = loadNameDict();
    }

    public String name() {
        return name;
    }

    public int treeId() {
        return descriptor.treeId();
    }

    public TreeDescriptor descriptor() {
        return descriptor;
    }

    // ==================================================================
    // the name dictionary — 02 §5.3, catalogued as its own tree
    // ==================================================================

    private NameDict loadNameDict() {
        NameDict d = NameDict.withReservedFields();
        if (dictTreeId < 0) {
            return d;
        }
        try (Engine.Cursor c = engine.scan(dictTreeId, null, null, false)) {
            while (c.next()) {
                int id = (int) SegmentMeta.longOf(Cke.decode(c.row().key()));
                d.put(id, ((Value.Str) Cve.decode(c.row().value())).value());
            }
        }
        return d;
    }

    /** Interns any field name the document uses that the dictionary does not hold yet. */
    private void internNames(Value value, Engine.Batch batch, List<Integer> added) {
        if (value instanceof Value.Doc) {
            Value.Doc doc = ((Value.Doc) value);
            for (Map.Entry<String, Value> e : doc.fields().entrySet()) {
                Integer known = names.idOf(e.getKey());
                if (known == null) {
                    int id = names.intern(e.getKey());
                    added.add(id);
                    batch.put(dictTreeId, Cke.encode(Value.integer(NumType.U32, id)),
                            Cve.encode(new Value.Str(e.getKey())));
                }
                internNames(e.getValue(), batch, added);
            }
        } else if (value instanceof Value.Array) {
            Value.Array a = ((Value.Array) value);
            for (Value v : a.items()) {
                internNames(v, batch, added);
            }
        }
    }

    // ==================================================================
    // documents
    // ==================================================================

    public static byte[] documentKey(long nitriteId) {
        return Cke.encode(new Value.NitriteId(nitriteId));
    }

    /** Inserts a document, allocating an id when the document has none. */
    public long insert(Value.Doc doc) {
        long id = idOf(doc);
        Value.Doc stored = withId(doc, id);
        Engine.Batch b = engine.batch();
        stage(b, id, stored, null);
        b.commit();
        return id;
    }

    /** One batch for many documents — {@code 04-segments.md} §10's first-class operation. */
    public void insertAll(List<Value.Doc> documents) {
        Engine.Batch b = engine.batch();
        for (Value.Doc doc : documents) {
            long id = idOf(doc);
            stage(b, id, withId(doc, id), null);
        }
        b.commit();
    }

    public void update(long id, Value.Doc doc) {
        // The previous document is read for **one** purpose: removing the index
        // entries it produced (see `stage`, where `previous` is used only
        // inside the index loop). With no index on this collection there is
        // nothing to remove, and the read is a value-log fetch and a full CVE
        // decode spent on a value that is then discarded.
        Value.Doc previous = indexed() ? get(id) : null;
        Engine.Batch b = engine.batch();
        stage(b, id, withId(doc, id), previous);
        b.commit();
    }

    public void remove(long id) {
        // As in `update`: the document itself is needed only to derive the
        // index entries to retract. Without indexes the question is just
        // "does this key exist", and `containsKey` answers it without
        // resolving the value — which on a `desktop` profile is a value-log
        // read per delete. Semantics are unchanged: a delete of an absent key
        // is still a no-op rather than a tombstone.
        Value.Doc previous;
        if (indexed()) {
            previous = get(id);
            if (previous == null) {
                return;
            }
        } else {
            previous = null;
            // The engine's own read horizon, which is what `get` above uses.
            // Checking at `visibleSeq` instead made a just-written document
            // look absent and the delete a no-op.
            if (!engine.containsKey(descriptor.treeId(), documentKey(id))) {
                return;
            }
        }
        Engine.Batch b = engine.batch();
        b.remove(descriptor.treeId(), documentKey(id));
        for (SpatialIndex index : spatialIndexes()) {
            index.remove(id);
        }
        for (VectorIndex index : vectorIndexes()) {
            index.remove(id);
        }
        for (FullTextIndex index : textIndexes()) {
            index.remove(id);
        }
        for (IndexBinding index : indexes()) {
            for (byte[] key : index.entriesFor(previous, id)) {
                b.remove(index.treeId, key);
            }
        }
        b.commit();
    }

    public Value.Doc get(long id) {
        byte[] raw = engine.get(descriptor.treeId(), documentKey(id));
        return raw == null ? null : Cve.decodeDoc(raw, names);
    }

    /**
     * Every document, in id order. Values are dereferenced lazily, so a
     * key-only walk never touches the value log.
     */
    public Engine.Cursor scan(boolean reverse) {
        return engine.scan(descriptor.treeId(), null, null, reverse);
    }

    public Value.Doc decode(byte[] cve) {
        return Cve.decodeDoc(cve, names);
    }


    /** Removes every document with one range delete rather than O(n) tombstones. */
    public void clear() {
        Engine.Batch b = engine.batch();
        b.removeRange(descriptor.treeId(), Cke.UNBOUNDED_BELOW, new byte[]{(byte) 0xFE});
        for (IndexBinding index : indexes()) {
            b.removeRange(index.treeId, Cke.UNBOUNDED_BELOW, new byte[]{(byte) 0xFE});
        }
        b.commit();
    }

    private void stage(Engine.Batch b, long id, Value.Doc doc, Value.Doc previous) {
        List<Integer> added = new ArrayList<>();
        internNames(doc, b, added);
        List<IndexBinding> indexes = indexes();
        for (IndexBinding index : indexes) {
            if (previous != null) {
                for (byte[] key : index.entriesFor(previous, id)) {
                    b.remove(index.treeId, key);
                }
            }
            List<byte[]> keys = index.entriesFor(doc, id);
            if (index.unique) {
                for (byte[] key : keys) {
                    checkUnique(index, key, id);
                }
            }
            for (byte[] key : keys) {
                // An index entry is self-describing: the key carries the values
                // AND the document id, so the value is EMPTY and never reaches
                // the value log.
                b.putEmpty(index.treeId, key);
            }
        }
        for (SpatialIndex index : spatialIndexes()) {
            index.put(id, doc, null);
        }
        for (VectorIndex index : vectorIndexes()) {
            index.put(id, doc);
        }
        for (FullTextIndex index : textIndexes()) {
            index.put(id, doc);
        }
        Long ttl = ttlMs();
        byte[] value = Cve.encode(doc, names);
        if (ttl != null) {
            b.putWithExpiry(descriptor.treeId(), documentKey(id), value,
                    engine.options().clock.getAsLong() + ttl);
        } else {
            b.put(descriptor.treeId(), documentKey(id), value);
        }
    }

    private Long ttlMs() {
        Value v = descriptor.params().field("ttl_ms");
        return v == null ? null : SegmentMeta.longOf(v);
    }

    /**
     * §1: the uniqueness check is on the {@code NitriteId} <em>behind</em> the
     * matching entries, not on their existence.
     *
     * <p>An entry whose id is the id being written is the writer's own and is
     * not a violation. A unique index over a multi-valued field reaches the
     * same key twice for {@code ["a", "b", "a"]}, and a rebuild or a replayed
     * write reaches keys the document already owns; a bare existence test
     * rejects all of these. Java, Dart and Rust all shipped that bare test
     * (nitrite/nitrite-java#1295).
     */
    private void checkUnique(IndexBinding index, byte[] key, long id) {
        List<Value> tuple = IndexKeys.valuesOf(key);
        if (!IndexKeys.uniquenessApplies(tuple)) {
            // §3: a unique index treats every NULL as distinct. The check is
            // skipped, not run and passed.
            return;
        }
        IndexKeys.Scan scan = IndexKeys.equalsPrefix(tuple);
        try (Engine.Cursor c = engine.scan(index.treeId, scan.lower(),
                scan.upper() == null ? null : scan.upper(), false)) {
            while (c.next()) {
                byte[] existing = c.row().key();
                if (!scan.contains(existing)) {
                    break;
                }
                if (IndexKeys.idOf(existing) != id) {
                    throw new InvalidArgumentException("unique index " + index.name
                            + " already holds " + tuple + " for document "
                            + IndexKeys.idOf(existing));
                }
            }
        }
    }

    private static long idOf(Value.Doc doc) {
        Value id = doc.field("_id");
        if (id instanceof Value.NitriteId) {
            Value.NitriteId n = ((Value.NitriteId) id);
            return n.id();
        }
        if (id instanceof Value.Int && ((Value.Int) id).asLong() != null) {
            Value.Int i = ((Value.Int) id);
            return i.asLong();
        }
        return java.util.UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE;
    }

    private static Value.Doc withId(Value.Doc doc, long id) {
        if (doc.field("_id") instanceof Value.NitriteId) {
            return doc;
        }
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("_id", new Value.NitriteId(id));
        for (Map.Entry<String, Value> e : doc.fields().entrySet()) {
            if (!"_id".equals(e.getKey())) {
                f.put(e.getKey(), e.getValue());
            }
        }
        return Value.Doc.of(f);
    }

    // ==================================================================
    // indexes — 06
    // ==================================================================

    /** One index tree bound to this collection. */
    public final class IndexBinding {
        public final String name;
        public final int treeId;
        public final List<String> fields;
        public final boolean unique;
        public final boolean sparse;

        IndexBinding(String name, int treeId, List<String> fields, boolean unique, boolean sparse) {
            this.name = name;
            this.treeId = treeId;
            this.fields = fields;
            this.unique = unique;
            this.sparse = sparse;
        }

        List<byte[]> entriesFor(Value.Doc doc, long id) {
            return IndexKeys.forDocument(fields, doc, sparse, id);
        }

        /** Document ids matching an equality on a prefix of the indexed fields. */
        public List<Long> find(List<Value> prefix) {
            return scan(IndexKeys.equalsPrefix(prefix));
        }

        /** The type-agnostic numeric form: {@code eq(5)} matches {@code I32(5)} and {@code F64(5.0)}. */
        public List<Long> findNumeric(List<Value> prefix) {
            return scan(IndexKeys.equalsPrefixNumeric(prefix));
        }

        public List<Long> startsWith(List<Value> prefix, String s) {
            return scan(IndexKeys.startsWith(prefix, s));
        }

        /** A range on the field after an equality on {@code prefix}. */
        public List<Long> range(List<Value> prefix, IndexKeys.Cmp op, Value bound) {
            return scan(IndexKeys.range(prefix, op, bound));
        }

        /**
         * Recomputes {@code params.stats} for this index —
         * {@code spec/13-operations.md} §9.
         *
         * <p>§9 maintains these "at compaction, ... free, because that
         * compaction already touches every key". This is the same walk, exposed
         * so the statistics can be refreshed on demand: a scan of the index
         * tree in key order, which is exactly what a last-level compaction of
         * it would do.
         *
         * <p>The result is <strong>advisory</strong> and is stored under
         * {@code params.stats}; a planner must work without it.
         */
        public IndexStats analyze() {
            IndexStats.Builder b = new IndexStats.Builder();
            try (Engine.Cursor c = engine.scan(treeId, null, null, false)) {
                while (c.next()) {
                    byte[] key = c.row().key();
                    // §9's `null_count`: an entry is null when any indexed
                    // value is. A sparse index never holds one, which is the
                    // whole difference between sparse and dense.
                    boolean isNull = false;
                    try {
                        for (Value v : IndexKeys.valuesOf(key)) {
                            if (v instanceof Value.Null) {
                                isNull = true;
                                break;
                            }
                        }
                    } catch (RuntimeException ignored) {
                        // A key this build cannot decode still counts toward
                        // `entries`; refusing here would make one unreadable
                        // entry lose the whole index's statistics, and §9's
                        // whole premise is that they are advisory.
                    }
                    b.add(key, isNull);
                }
            }
            // The descriptor is one cell of a copy-on-write B+tree, so
            // `params.stats` MUST fit one page (§9, defect 37). Half a page is
            // a deliberately conservative floor: the rest of the descriptor
            // shares the cell.
            IndexStats s = b.build(engine.visibleSeq(), engine.superblock().pageSize() / 2);

            TreeDescriptor d = db.descriptor(name);
            if (d == null) {
                throw new InvalidArgumentException("no catalog entry for index " + name);
            }
            Map<String, Value> params = new LinkedHashMap<>(d.params().fields());
            params.put("stats", s.toDoc());
            Map<String, Value> doc = new LinkedHashMap<>(d.document().fields());
            doc.put("params", new Value.Doc(params));
            db.putDescriptor(name, new TreeDescriptor(new Value.Doc(doc)));
            return s;
        }

        /**
         * The statistics stored for this index, or {@code null} when none have
         * been computed.
         *
         * <p>§9: "Statistics are advisory. They may be stale or absent."
         */
        public IndexStats stats() {
            TreeDescriptor d = db.descriptor(name);
            if (d == null) {
                return null;
            }
            Value v = d.params().fields().get("stats");
            return v == null ? null : IndexStats.fromDoc(v);
        }

        public List<Long> scan(IndexKeys.Scan range) {
            List<Long> out = new ArrayList<>();
            try (Engine.Cursor c = engine.scan(treeId, range.lower(), range.upper(), false)) {
                while (c.next()) {
                    byte[] key = c.row().key();
                    if (!range.contains(key)) {
                        break;
                    }
                    out.add(IndexKeys.idOf(key));
                }
            }
            return out;
        }
    }

    /**
     * Picks the most selective index among {@code candidates} —
     * {@code spec/06-indexes.md} §7.1.
     *
     * <p>This is the decision Nitrite's {@code FindPlan} makes today from
     * static descriptor properties — whether an index is unique and how many
     * fields it covers — which "routinely picks a unique index on a field the
     * query barely constrains over a non-unique index that would eliminate
     * 99 % of the collection". With statistics it is made on evidence.
     *
     * <p>{@code null} when no candidate has statistics, which a planner MUST
     * treat as "choose some other way" rather than as an error.
     */
    public IndexBinding mostSelective(List<IndexBinding> candidates) {
        IndexBinding best = null;
        double bestSelectivity = Double.POSITIVE_INFINITY;
        for (IndexBinding c : candidates) {
            IndexStats s = c.stats();
            if (s == null) {
                continue;
            }
            Double sel = s.selectivity();
            if (sel != null && sel < bestSelectivity) {
                bestSelectivity = sel;
                best = c;
            }
        }
        return best;
    }

    public List<IndexBinding> indexes() {
        List<IndexBinding> out = new ArrayList<>();
        for (Map.Entry<String, TreeDescriptor> e : db.catalog().entrySet()) {
            TreeDescriptor d = e.getValue();
            if (!TreeDescriptor.Kind.INDEX.equals(d.kind()) || !name.equals(d.owner())) {
                continue;
            }
            out.add(binding(e.getKey(), d));
        }
        return out;
    }

    public IndexBinding index(String indexName) {
        TreeDescriptor d = db.descriptor(indexName);
        if (d == null || !TreeDescriptor.Kind.INDEX.equals(d.kind())) {
            throw new InvalidArgumentException("no index named " + indexName);
        }
        return binding(indexName, d);
    }

    private IndexBinding binding(String indexName, TreeDescriptor d) {
        List<String> fields = new ArrayList<>();
        for (Value v : ((Value.Array) d.params().field("fields")).items()) {
            fields.add(((Value.Str) v).value());
        }
        Value sparse = d.params().field("sparse");
        return new IndexBinding(indexName, d.treeId(), fields, d.unique(),
                sparse instanceof Value.Bool && ((Value.Bool) sparse).value());
    }

    /**
     * Creates an index and populates it from the existing documents.
     *
     * <p>The recommended name convention is
     * {@code idx:<data tree>:<field1,field2>:<type>}, but nothing parses it: a
     * name collision is resolved by appending a counter, not by escaping, and
     * the association with the data tree is {@code params.data_tree}, not string
     * surgery.
     */
    public IndexBinding createIndex(List<String> fields, boolean unique, boolean sparse) {
        String type = unique ? TreeDescriptor.IndexType.UNIQUE : TreeDescriptor.IndexType.NON_UNIQUE;
        String indexName = uniqueName("idx:" + name + ":" + String.join(",", fields) + ":" + type);
        int treeId = engine.allocateTreeId();
        Map<String, Value> params = new LinkedHashMap<>();
        params.put("index_type", new Value.Str(type));
        params.put("data_tree", Value.integer(NumType.U32, descriptor.treeId()));
        List<Value> fieldValues = new ArrayList<>();
        for (String f : fields) {
            fieldValues.add(new Value.Str(f));
        }
        params.put("fields", new Value.Array(fieldValues));
        if (sparse) {
            params.put("sparse", new Value.Bool(true));
        }
        TreeDescriptor d = new TreeDescriptor.Builder()
                .treeId(treeId)
                .kind(TreeDescriptor.Kind.INDEX)
                .levelled(true)
                .created(engine.options().clock.getAsLong())
                .keyKind("array")
                .owner(name)
                .params(params)
                .build();
        db.putDescriptor(indexName, d);

        IndexBinding binding = binding(indexName, d);
        Engine.Batch b = engine.batch();
        try (Engine.Cursor c = scan(false)) {
            while (c.next()) {
                Value.Doc doc = decode(c.row().value());
                long id = ((Value.NitriteId) Cke.decode(c.row().key())).id();
                List<byte[]> keys = binding.entriesFor(doc, id);
                if (unique) {
                    for (byte[] key : keys) {
                        checkUnique(binding, key, id);
                    }
                }
                for (byte[] key : keys) {
                    b.putEmpty(treeId, key);
                }
            }
        }
        if (b.size() > 0) {
            b.commit();
        }
        return binding;
    }

    /**
     * Creates a spatial index over a geometry field and populates it —
     * {@code spec/08-spatial.md} §2.
     *
     * <p>{@code dimensions = 3} always means Z, never M: an {@code XYM}
     * geometry cannot go into a three-dimensional index, because silently
     * indexing M in Z's slot would make two geometries comparable that are not.
     */
    public SpatialIndex createSpatialIndex(String field, int dimensions, Integer srid) {
        if (dimensions < 2 || dimensions > 4) {
            throw new InvalidArgumentException("dimensions " + dimensions + " outside 2..4");
        }
        String indexName = uniqueName("idx:" + name + ":" + field + ":spatial");
        int treeId = engine.allocateTreeId();
        Map<String, Value> params = new LinkedHashMap<>();
        params.put("index_type", new Value.Str(TreeDescriptor.IndexType.SPATIAL));
        params.put("data_tree", Value.integer(NumType.U32, descriptor.treeId()));
        params.put("field", new Value.Str(field));
        params.put("dimensions", Value.integer(NumType.U8, dimensions));
        if (srid != null) {
            params.put("srid", Value.integer(NumType.U32, srid));
        }
        TreeDescriptor d = new TreeDescriptor.Builder()
                .treeId(treeId)
                .kind(TreeDescriptor.Kind.RTREE)
                // §3 of the catalog: false for rtree, which is a copy-on-write
                // tree of its own page types rooted at `root`.
                .levelled(false)
                .root(0)
                .created(engine.options().clock.getAsLong())
                .keyKind("opaque")
                .owner(name)
                .features(Feature.bit(Feature.SPATIAL))
                .params(params)
                .build();
        db.putDescriptor(indexName, d);
        SpatialIndex index = new SpatialIndex(db, this, indexName, d);
        try (Engine.Cursor c = scan(false)) {
            while (c.next()) {
                index.put(((Value.NitriteId) Cke.decode(c.row().key())).id(),
                        decode(c.row().value()), null);
            }
        }
        engine.addCommitHook(index::commit);
        spatialIndexes.add(index);
        engine.commitNow();
        return index;
    }

    private final List<SpatialIndex> spatialIndexes = new ArrayList<>();
    private final List<VectorIndex> vectorIndexes = new ArrayList<>();
    private final List<FullTextIndex> textIndexes = new ArrayList<>();

    /**
     * Creates a full-text index — {@code spec/07-fulltext.md} §1.
     *
     * <p>The stopword list is stored <em>in the file</em>, not taken from the
     * implementation: Nitrite ships per-language lists in all three SDKs today
     * and they are not identical, so storing the actual list is what makes the
     * index reproducible regardless of which SDK's list was in scope when it was
     * created.
     */
    public FullTextIndex createTextIndex(List<String> fields, List<String> stopwords,
                                         String stemmer, boolean positions) {
        // Constructed here so an analyzer this implementation cannot reproduce
        // is refused before a tree exists, not after.
        Analyzer.of(Analyzer.STD_V1, stopwords, stemmer);
        String indexName = uniqueName("idx:" + name + ":" + String.join(",", fields) + ":full_text");
        int postingsId = engine.allocateTreeId();
        int termDictId = engine.allocateTreeId();
        int termIndexId = engine.allocateTreeId();

        List<Value> fieldValues = new ArrayList<>();
        for (String f : fields) {
            fieldValues.add(new Value.Str(f));
        }
        List<String> sorted = new ArrayList<>(stopwords);
        java.util.Collections.sort(sorted);
        List<Value> stopwordValues = new ArrayList<>();
        for (String s : sorted) {
            stopwordValues.add(new Value.Str(s));
        }
        Map<String, Value> analyzerParams = new LinkedHashMap<>();
        analyzerParams.put("stopwords", new Value.Array(stopwordValues));
        analyzerParams.put("stemmer", new Value.Str(stemmer == null ? "none" : stemmer));

        Map<String, Value> params = new LinkedHashMap<>();
        params.put("index_type", new Value.Str(TreeDescriptor.IndexType.FULL_TEXT));
        params.put("data_tree", Value.integer(NumType.U32, descriptor.treeId()));
        params.put("fields", new Value.Array(fieldValues));
        params.put("analyzer", new Value.Str(Analyzer.STD_V1));
        params.put("analyzer_params", Value.Doc.of(analyzerParams));
        params.put("term_dict", Value.integer(NumType.U32, termDictId));
        params.put("term_index", Value.integer(NumType.U32, termIndexId));
        params.put("positions", new Value.Bool(positions));

        long now = engine.options().clock.getAsLong();
        TreeDescriptor d = new TreeDescriptor.Builder()
                .treeId(postingsId)
                .kind(TreeDescriptor.Kind.POSTINGS)
                .levelled(true)
                .created(now)
                .keyKind("array")
                .owner(name)
                .features(Feature.bit(Feature.TEXT))
                .params(params)
                .build();
        db.putDescriptor(indexName, d);
        db.putDescriptor(indexName + ":terms", new TreeDescriptor.Builder()
                .treeId(termDictId).kind(TreeDescriptor.Kind.TERM_DICT).levelled(true)
                .created(now).keyKind("string").owner(name).build());
        db.putDescriptor(indexName + ":termids", new TreeDescriptor.Builder()
                .treeId(termIndexId).kind(TreeDescriptor.Kind.TERM_INDEX).levelled(true)
                .created(now).keyKind("u32").owner(name).build());

        FullTextIndex index = new FullTextIndex(db, this, indexName, d);
        try (Engine.Cursor c = scan(false)) {
            while (c.next()) {
                index.put(((Value.NitriteId) Cke.decode(c.row().key())).id(), decode(c.row().value()));
            }
        }
        textIndexes.add(index);
        return index;
    }

    public List<FullTextIndex> textIndexes() {
        if (textIndexes.isEmpty()) {
            for (Map.Entry<String, TreeDescriptor> e : db.catalog().entrySet()) {
                TreeDescriptor d = e.getValue();
                if (TreeDescriptor.Kind.POSTINGS.equals(d.kind()) && name.equals(d.owner())) {
                    textIndexes.add(new FullTextIndex(db, this, e.getKey(), d));
                }
            }
        }
        return List.copyOf(textIndexes);
    }

    /**
     * Creates a vector index over a {@code VECTOR} field —
     * {@code spec/09-vector.md} §5.
     *
     * <p>Two slot maps, both named in the descriptor, because search returns
     * slots, filtering needs documents and deletion needs a document's slot.
     */
    public VectorIndex createVectorIndex(String field, int dim, String metric, int initialSlots) {
        String indexName = uniqueName("idx:" + name + ":" + field + ":vector");
        int treeId = engine.allocateTreeId();
        int slotToDoc = engine.allocateTreeId();
        int docToSlot = engine.allocateTreeId();
        VectorRegion region = VectorRegion.create(engine.pager(), dim,
                VectorRegion.DTYPE_F32, Math.max(2, initialSlots));

        Map<String, Value> params = new LinkedHashMap<>();
        params.put("index_type", new Value.Str(TreeDescriptor.IndexType.VECTOR));
        params.put("data_tree", Value.integer(NumType.U32, descriptor.treeId()));
        params.put("field", new Value.Str(field));
        params.put("dim", Value.integer(NumType.U32, dim));
        params.put("metric", new Value.Str(metric));
        params.put("algorithm", new Value.Str("vamana"));
        params.put("precision", new Value.Str("f32"));
        params.put("vector_region", Value.integer(NumType.U64, region.startPage));
        params.put("entry_points", new Value.Array(List.of()));
        params.put("max_level", Value.integer(NumType.U8, 0));
        params.put("m", Value.integer(NumType.U16, 32));
        params.put("ef_construction", Value.integer(NumType.U16, 200));
        params.put("neighbours_sorted", new Value.Bool(false));
        params.put("slot_to_doc", Value.integer(NumType.U32, slotToDoc));
        params.put("doc_to_slot", Value.integer(NumType.U32, docToSlot));
        // §3: adjacency records are read randomly and hot, so an extra
        // value-log indirection per hop is the worst place in the format to
        // spend one.
        params.put("inline_values", new Value.Bool(true));

        TreeDescriptor d = new TreeDescriptor.Builder()
                .treeId(treeId)
                .kind(TreeDescriptor.Kind.VECTOR_GRAPH)
                .levelled(false)
                .root(0)
                .created(engine.options().clock.getAsLong())
                .keyKind("array")
                .owner(name)
                .features(Feature.bit(Feature.VECTOR))
                .params(params)
                .build();
        db.putDescriptor(indexName, d);
        for (int id : new int[]{slotToDoc, docToSlot}) {
            db.putDescriptor(indexName + (id == slotToDoc ? ":slots" : ":docs"),
                    new TreeDescriptor.Builder()
                            .treeId(id)
                            .kind(TreeDescriptor.Kind.KV)
                            .levelled(true)
                            .created(engine.options().clock.getAsLong())
                            .owner(indexName)
                            .build());
        }
        VectorIndex index = new VectorIndex(db, this, indexName, d);
        try (Engine.Cursor c = scan(false)) {
            while (c.next()) {
                index.put(((Value.NitriteId) Cke.decode(c.row().key())).id(), decode(c.row().value()));
            }
        }
        engine.addCommitHook(index::commit);
        vectorIndexes.add(index);
        engine.commitNow();
        return index;
    }

    public List<VectorIndex> vectorIndexes() {
        if (vectorIndexes.isEmpty()) {
            for (Map.Entry<String, TreeDescriptor> e : db.catalog().entrySet()) {
                TreeDescriptor d = e.getValue();
                if (TreeDescriptor.Kind.VECTOR_GRAPH.equals(d.kind()) && name.equals(d.owner())) {
                    VectorIndex index = new VectorIndex(db, this, e.getKey(), d);
                    engine.addCommitHook(index::commit);
                    vectorIndexes.add(index);
                }
            }
        }
        return List.copyOf(vectorIndexes);
    }

    /**
     * Whether this collection has any index at all — secondary, spatial,
     * vector or full-text.
     *
     * <p>Cached on the identity of the catalog map, which {@code Database}
     * replaces only when the catalog actually changes, so this costs a
     * reference comparison on the write path.
     */
    private Map<String, TreeDescriptor> indexedFor;
    private boolean indexedValue;

    private boolean indexed() {
        Map<String, TreeDescriptor> catalog = db.catalog();
        if (catalog != indexedFor) {
            boolean any = false;
            for (TreeDescriptor d : catalog.values()) {
                if (!name.equals(d.owner())) {
                    continue;
                }
                String kind = d.kind();
                if (TreeDescriptor.Kind.INDEX.equals(kind)
                        || TreeDescriptor.Kind.RTREE.equals(kind)
                        || TreeDescriptor.Kind.VECTOR_GRAPH.equals(kind)
                        || TreeDescriptor.Kind.POSTINGS.equals(kind)) {
                    any = true;
                    break;
                }
            }
            indexedValue = any;
            indexedFor = catalog;
        }
        return indexedValue;
    }

    /** Opens the spatial indexes this collection already has. */
    public List<SpatialIndex> spatialIndexes() {
        if (spatialIndexes.isEmpty()) {
            for (Map.Entry<String, TreeDescriptor> e : db.catalog().entrySet()) {
                TreeDescriptor d = e.getValue();
                if (TreeDescriptor.Kind.RTREE.equals(d.kind()) && name.equals(d.owner())) {
                    SpatialIndex index = new SpatialIndex(db, this, e.getKey(), d);
                    engine.addCommitHook(index::commit);
                    spatialIndexes.add(index);
                }
            }
        }
        return List.copyOf(spatialIndexes);
    }

    private String uniqueName(String base) {
        if (db.descriptor(base) == null) {
            return base;
        }
        for (int i = 2; ; i++) {
            String candidate = base + "-" + i;
            if (db.descriptor(candidate) == null) {
                return candidate;
            }
        }
    }
}
