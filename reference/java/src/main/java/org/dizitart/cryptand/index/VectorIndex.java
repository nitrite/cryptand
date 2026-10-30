package org.dizitart.cryptand.index;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.key.IndexKeys;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * A vector index — {@code spec/09-vector.md}.
 *
 * <p>The design principle is stated in §0 and honoured here: <strong>specify the
 * durable layout, not the algorithm.</strong> A proximity graph is a flat vector
 * region plus an adjacency list per node; how an implementation searches or
 * builds that graph is its own business, as long as the recall it achieves is a
 * quality question and not a correctness one.
 *
 * <p>F-196: a Vamana graph built as documents arrive. A put runs a beam
 * search ({@code ef_construction} wide) from the entry point, keeps the
 * robust-pruned ({@link #ALPHA}) nearest {@code m} as the new slot's
 * neighbours and adds the reverse edges, pruning a list that overflows. A
 * search is the same beam, {@link #EF_SEARCH} wide, re-ranked by true
 * distance; a filtered search, and an index small enough that the beam would
 * visit it all, use the brute-force scan §8 permits.
 * <em>ponytail: deleted slots stay in the graph and are walked through (§6);
 * consolidation (§7) is not implemented, so a delete-heavy index degrades
 * toward the brute-force fallback.</em>
 */
public final class VectorIndex {

    public static final String METRIC_COSINE = "cosine";
    public static final String METRIC_L2 = "l2";
    public static final String METRIC_DOT = "dot";

    public static final class Hit {
        private final long nitriteId;
        private final double distance;

        public Hit(long nitriteId, double distance) {
            this.nitriteId = nitriteId;
            this.distance = distance;
        }

        public long nitriteId() {
            return nitriteId;
        }

        public double distance() {
            return distance;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Hit)) {
                return false;
            }
            Hit that = (Hit) o;
            return nitriteId == that.nitriteId
                    && Double.compare(distance, that.distance) == 0;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(nitriteId, distance);
        }

        @Override
        public String toString() {
            return "Hit[" + "nitriteId=" + nitriteId + ", " + "distance=" + distance + "]";
        }
    }

    private final Database db;
    private final Collection owner;
    private final String name;
    private final String field;
    private final int dim;
    private final String metric;
    private final int slotToDocTree;
    private final int docToSlotTree;
    private TreeDescriptor descriptor;
    private VectorRegion region;
    private final AdjacencyTree adjacency;
    /** Slot -> document, for the slots set in {@link #live}. */
    private long[] slotDoc = new long[16];
    private final BitSet live = new BitSet();
    private final LongMap docToSlot = new LongMap();
    private long nextSlot = 1;
    /** The search entry point (§5 {@code entry_points}); 0 for an empty graph. */
    private long entry;
    private final int m;
    private final int efConstruction;

    /** Robust-prune slack: a candidate is dropped if a kept neighbour is ALPHA times nearer to it. */
    static final double ALPHA = 1.2;
    /** Beam width of an unfiltered search (at least k). */
    static final int EF_SEARCH = 100;
    /** Unfiltered searches the beam could not answer (tests: a broken graph hides behind the scan). */
    int fallbacks;

    public VectorIndex(Database db, Collection owner, String name, TreeDescriptor descriptor) {
        this.db = db;
        this.owner = owner;
        this.name = name;
        this.descriptor = descriptor;
        Value.Doc params = descriptor.params();
        this.field = ((Value.Str) params.field("field")).value();
        this.dim = (int) SegmentMeta.longOf(params.field("dim"));
        this.metric = ((Value.Str) params.field("metric")).value();
        this.slotToDocTree = (int) SegmentMeta.longOf(params.field("slot_to_doc"));
        this.docToSlotTree = (int) SegmentMeta.longOf(params.field("doc_to_slot"));
        this.region = VectorRegion.open(db.engine().pager(),
                SegmentMeta.longOf(params.field("vector_region")));
        // F-072 g: a conversion step asks this object, which holds the region
        // and the graph in memory, to re-lay them itself.
        db.engine().registerOwner(descriptor.treeId(), this::convertInPlace);
        Long root = descriptor.root();
        this.adjacency = AdjacencyTree.load(db.engine().pager(), descriptor.treeId(), root == null ? 0 : root,
                descriptor.rootNonce());
        Value mv = params.field("m");
        this.m = mv == null ? 32 : (int) SegmentMeta.longOf(mv);
        Value ef = params.field("ef_construction");
        this.efConstruction = ef == null ? 200 : (int) SegmentMeta.longOf(ef);
        Value eps = params.field("entry_points");
        if (eps instanceof Value.Array && !((Value.Array) eps).items().isEmpty()) {
            entry = SegmentMeta.longOf(((Value.Array) eps).items().get(0));
        }
        loadMaps();
    }

    public String name() {
        return name;
    }

    public int dim() {
        return dim;
    }

    public String metric() {
        return metric;
    }

    public synchronized int size() {
        return live.cardinality();
    }

    // ==================================================================
    // §6 the two maps
    // ==================================================================

    /**
     * Both directions, both named in the descriptor. Search returns slots,
     * filtering needs documents, and deletion needs a document's slot — an
     * earlier draft named only one map and left the inverse unreachable from
     * the catalog.
     */
    private void loadMaps() {
        Engine e = db.engine();
        try (Engine.Cursor c = e.scan(slotToDocTree, null, null, false)) {
            while (c.next()) {
                long slot = SegmentMeta.longOf(Cke.decode(c.row().key()));
                long doc = ((Value.NitriteId) Cve.decode(c.row().value())).id();
                map(slot, doc);
                nextSlot = Math.max(nextSlot, slot + 1);
            }
        }
    }

    // ==================================================================
    // maintenance
    // ==================================================================

    /** Indexes a document's vector field, replacing any slot it already owns. */

    // ==================================================================
    // Concurrency — the commit hook runs on the committer thread
    // ==================================================================
    //
    // `Engine.publishSuperblock` runs this index's `commit()` from the
    // committer while the application thread is still calling `put` and
    // `remove` on it. The state underneath — a pair of maps here, an
    // `ArrayList` of entries in the spatial index — is not thread-safe, so the two must
    // not overlap: a repack that iterates the entry list while the application
    // grows it loses entries outright. Measured at 458 of 500 points found.
    //
    // One monitor over the mutators, the commit and the queries is the whole
    // fix. None of these is on a hot path — an index update is per document,
    // not per operation — and the committer holds `structure` around the hook,
    // so this monitor is always taken after it and never before.

    // F-078: the batch is built under this monitor and committed after it is
    // released. Committing inside waits (sync durability) for the committer,
    // which holds `structure` and waits for this monitor in commit().
    // ponytail: two concurrent puts of one document may commit their slot maps
    // out of order; serialise per document if that is ever possible here.
    public void put(long nitriteId, Value.Doc document) {
        Engine.Batch b = stagePut(nitriteId, document);
        if (b != null) {
            b.commit();
        }
    }

    private synchronized Engine.Batch stagePut(long nitriteId, Value.Doc document) {
        float[] vector = vectorOf(document);
        if (vector == null) {
            return stageRemove(nitriteId);
        }
        if (vector.length != dim) {
            throw new InvalidArgumentException("vector has " + vector.length
                    + " dimensions, index " + name + " declares " + dim);
        }
        long slot = docToSlot.get(nitriteId);
        if (slot == 0) {
            slot = nextSlot++;
            growTo(slot);
        }
        region.write(db.engine().pager(), slot, vector);
        map(slot, nitriteId);
        link(slot, vector);
        Engine.Batch b = db.engine().batch();
        b.put(slotToDocTree, Cke.encode(Value.integer(NumType.U64, slot)),
                Cve.encode(new Value.NitriteId(nitriteId)));
        b.put(docToSlotTree, Cke.encode(new Value.NitriteId(nitriteId)),
                Cve.encode(Value.integer(NumType.U64, slot)));
        return b;
    }

    /**
     * §6: a deleted document's slot is marked by removing both mappings; the
     * slot stays in the graph until consolidation repairs the neighbourhoods,
     * and a search skips a slot with no document mapping. That is what makes a
     * delete correct <em>immediately</em> even though the graph is repaired
     * later.
     */
    public void remove(long nitriteId) {
        Engine.Batch b = stageRemove(nitriteId);
        if (b != null) {
            b.commit();
        }
    }

    private synchronized Engine.Batch stageRemove(long nitriteId) {
        long slot = docToSlot.get(nitriteId);
        if (slot == 0) {
            return null;
        }
        docToSlot.remove(nitriteId);
        live.clear((int) slot);
        Engine.Batch b = db.engine().batch();
        b.remove(slotToDocTree, Cke.encode(Value.integer(NumType.U64, slot)));
        b.remove(docToSlotTree, Cke.encode(new Value.NitriteId(nitriteId)));
        return b;
    }

    /** {@link Engine#registerOwner}: region and graph re-laid in the pager's current mode. */
    private synchronized void convertInPlace() {
        Pager pager = db.engine().pager();
        boolean seals = pager.seals() && pager.crypto() instanceof org.dizitart.cryptand.crypto.FileCipher;
        if (region.encrypted != seals) {
            VectorRegion old = region;
            region = old.relocate(pager);
            region.liveCount = old.liveCount;
            pager.freeExtent(old.startPage, old.pages);
            Map<String, Value> params = new LinkedHashMap<>(descriptor.params().fields());
            params.put("vector_region", Value.integer(NumType.U64, region.startPage));
            Map<String, Value> fields = new LinkedHashMap<>(descriptor.document().fields());
            fields.put("params", Value.Doc.of(params));
            descriptor = new TreeDescriptor(Value.Doc.of(fields));
            regionDirty = true;
        }
        adjacency.markDirty();
    }

    private void growTo(long slot) {
        if (slot < region.slotCount) {
            return;
        }
        Pager pager = db.engine().pager();
        long want = Math.max(slot + 1, region.slotCount * 2);
        VectorRegion bigger = VectorRegion.create(pager, dim, region.dtype, want);
        for (int s = live.nextSetBit(0); s >= 0; s = live.nextSetBit(s + 1)) {
            bigger.writeRaw(pager, s, region.readRaw(pager, s));
        }
        pager.freeExtent(region.startPage, region.pages);
        region = bigger;
        Map<String, Value> params = new LinkedHashMap<>(descriptor.params().fields());
        params.put("vector_region", Value.integer(NumType.U64, region.startPage));
        Map<String, Value> fields = new LinkedHashMap<>(descriptor.document().fields());
        fields.put("params", Value.Doc.of(params));
        descriptor = new TreeDescriptor(Value.Doc.of(fields));
        // F-078: not db.putDescriptor here. That takes the engine's structure
        // lock under this monitor, while the committer holds structure and
        // waits for this monitor in commit(): a deadlock. commit() publishes it.
        regionDirty = true;
    }

    /** {@link #growTo} moved the region; {@link #commit} publishes the descriptor. */
    private boolean regionDirty;

    /**
     * Writes the graph's copied pages back and republishes the roots. Called on
     * the commit path, so the graph, the maps and the document write land
     * under one superblock.
     */
    public synchronized void commit() {
        long root = adjacency.commit();
        region.liveCount = live.cardinality();
        Map<String, Value> fields = new LinkedHashMap<>(descriptor.document().fields());
        boolean changed = descriptor.root() == null || descriptor.root() != root
                || descriptor.rootNonce() != adjacency.rootNonce();
        TreeDescriptor.putRoot(fields, root, adjacency.rootNonce());
        fields.put("entries", Value.integer(NumType.U64, live.cardinality()));
        Map<String, Value> params = new LinkedHashMap<>(descriptor.params().fields());
        List<Value> entryPoints = new ArrayList<>();
        if (entry != 0) {
            entryPoints.add(Value.integer(NumType.U64, entry));
        }
        params.put("entry_points", new Value.Array(entryPoints));
        fields.put("params", Value.Doc.of(params));
        if (changed || !entryPoints.isEmpty() || regionDirty) {
            regionDirty = false;
            descriptor = new TreeDescriptor(Value.Doc.of(fields));
            db.putDescriptor(name, descriptor);
        }
    }

    private void map(long slot, long doc) {
        if (slot >= slotDoc.length) {
            slotDoc = Arrays.copyOf(slotDoc, (int) Math.max(slot + 1, slotDoc.length * 2L));
        }
        slotDoc[(int) slot] = doc;
        live.set((int) slot);
        docToSlot.put(doc, slot);
    }

    // ==================================================================
    // the graph (Vamana, one layer)
    // ==================================================================

    /** A slot and its distance to the query being searched. */
    private static final class Scored {
        final long slot;
        final double d;

        Scored(long slot, double d) {
            this.slot = slot;
            this.d = d;
        }
    }

    private List<Long> adjacencyOf(long slot) {
        byte[] raw = adjacency.get(adjacencyKey(0, slot));
        return raw == null ? List.of() : decodeAdjacency(((Value.Bytes) Cve.decode(raw)).value());
    }

    private void setAdjacency(long slot, List<Long> neighbours) {
        adjacency.put(adjacencyKey(0, slot), Cve.encode(new Value.Bytes(encodeAdjacency(neighbours))));
    }

    /** Beam search from the entry point: the {@code ef} nearest slots seen, nearest first. */
    private List<Scored> beam(float[] q, int ef, Map<Long, float[]> cache) {
        List<Scored> out = new ArrayList<>();
        if (entry == 0) {
            return out;
        }
        Pager pager = db.engine().pager();
        PriorityQueue<Scored> open = new PriorityQueue<>(Comparator.comparingDouble((Scored c) -> c.d));
        PriorityQueue<Scored> best = new PriorityQueue<>(Comparator.comparingDouble((Scored c) -> -c.d));
        java.util.Set<Long> seen = new java.util.HashSet<>();
        Scored e = new Scored(entry, distance(q, vector(pager, entry, cache)));
        open.add(e);
        best.add(e);
        seen.add(entry);
        while (!open.isEmpty()) {
            Scored c = open.poll();
            if (best.size() >= ef && c.d > best.peek().d) {
                break;
            }
            for (long n : adjacencyOf(c.slot)) {
                if (!seen.add(n)) {
                    continue;
                }
                double d = distance(q, vector(pager, n, cache));
                if (best.size() < ef || d < best.peek().d) {
                    Scored s = new Scored(n, d);
                    open.add(s);
                    best.add(s);
                    if (best.size() > ef) {
                        best.poll();
                    }
                }
            }
        }
        out.addAll(best);
        out.sort(Comparator.comparingDouble(c -> c.d));
        return out;
    }

    private float[] vector(Pager pager, long slot, Map<Long, float[]> cache) {
        return cache == null ? region.read(pager, slot) : cache.computeIfAbsent(slot, s -> region.read(pager, s));
    }

    /**
     * Vamana's robust prune: nearest first, dropping a candidate a kept one
     * covers, up to {@code m - m/8}; F-201: the last {@code m/8} slots go to
     * the farthest candidates left. In high dimensions near neighbours rarely
     * cover each other, so a cluster larger than {@code m} filled every list
     * with itself, the edges out of it were pruned away, and a search never
     * left the entry point's cluster (recall@10 0.010 at 10^5 x 128-d).
     */
    private List<Long> prune(long self, List<Scored> nearestFirst, Map<Long, float[]> cache) {
        Pager pager = db.engine().pager();
        int near = m - Math.max(1, m / 8);
        List<Long> kept = new ArrayList<>();
        List<float[]> keptVectors = new ArrayList<>();
        for (Scored c : nearestFirst) {
            if (kept.size() >= near) {
                break;
            }
            if (c.slot == self || kept.contains(c.slot)) {
                continue;
            }
            float[] v = vector(pager, c.slot, cache);
            boolean covered = false;
            for (float[] k : keptVectors) {
                if (ALPHA * distance(k, v) <= c.d) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                kept.add(c.slot);
                keptVectors.add(v);
            }
        }
        for (int i = nearestFirst.size() - 1; i >= 0 && kept.size() < m; i--) {
            long s = nearestFirst.get(i).slot;
            if (s != self && !kept.contains(s)) {
                kept.add(s);
            }
        }
        return kept;
    }

    /** Links {@code slot} into the graph, reverse edges included. */
    private void link(long slot, float[] v) {
        if (entry == 0 || entry == slot) {
            entry = slot;
            if (adjacency.get(adjacencyKey(0, slot)) == null) {
                setAdjacency(slot, List.of());
            }
            return;
        }
        Map<Long, float[]> cache = new HashMap<>();
        cache.put(slot, v);
        List<Long> mine = prune(slot, beam(v, efConstruction, cache), cache);
        setAdjacency(slot, mine);
        Pager pager = db.engine().pager();
        for (long n : mine) {
            List<Long> theirs = new ArrayList<>(adjacencyOf(n));
            if (theirs.contains(slot)) {
                continue;
            }
            theirs.add(slot);
            if (theirs.size() > m) {
                float[] nv = vector(pager, n, cache);
                List<Scored> scored = new ArrayList<>(theirs.size());
                for (long t : theirs) {
                    scored.add(new Scored(t, distance(nv, vector(pager, t, cache))));
                }
                scored.sort(Comparator.comparingDouble(c -> c.d));
                theirs = prune(n, scored, cache);
            }
            setAdjacency(n, theirs);
        }
    }

    /** Primitive document -> slot map, open addressing; 0 is "absent" (slot 0 is never used). */
    static final class LongMap {
        private long[] keys = new long[16];
        private long[] vals = new long[16];
        private boolean[] used = new boolean[16];
        private int count;

        private int at(long k) {
            int mask = keys.length - 1;
            int i = (int) (Long.hashCode(k * 0x9E3779B97F4A7C15L)) & mask;
            while (used[i] && keys[i] != k) {
                i = (i + 1) & mask;
            }
            return i;
        }

        long get(long k) {
            int i = at(k);
            return used[i] ? vals[i] : 0;
        }

        void put(long k, long v) {
            if ((count + 1) * 2 > keys.length) {
                long[] ok = keys;
                long[] ov = vals;
                boolean[] ou = used;
                keys = new long[ok.length * 2];
                vals = new long[ok.length * 2];
                used = new boolean[ok.length * 2];
                count = 0;
                for (int j = 0; j < ok.length; j++) {
                    if (ou[j]) {
                        put(ok[j], ov[j]);
                    }
                }
            }
            int i = at(k);
            if (!used[i]) {
                used[i] = true;
                keys[i] = k;
                count++;
            }
            vals[i] = v;
        }

        /** Backward-shift deletion keeps every probe chain unbroken. */
        void remove(long k) {
            int i = at(k);
            if (!used[i]) {
                return;
            }
            int mask = keys.length - 1;
            int j = i;
            while (true) {
                j = (j + 1) & mask;
                if (!used[j]) {
                    break;
                }
                int home = (int) (Long.hashCode(keys[j] * 0x9E3779B97F4A7C15L)) & mask;
                if (((j - home) & mask) >= ((j - i) & mask)) {
                    keys[i] = keys[j];
                    vals[i] = vals[j];
                    i = j;
                }
            }
            used[i] = false;
            count--;
        }

        void clear() {
            Arrays.fill(used, false);
            count = 0;
        }
    }

    static byte[] adjacencyKey(int level, long slot) {
        return Cke.encode(new Value.Array(List.of(
                Value.integer(NumType.U8, level),
                Value.integer(NumType.U64, slot))));
    }

    /**
     * {@code u16 degree} then zigzag deltas of {@code slot_id}, the first a
     * delta from 0 (F-197: it was a plain uvar, which R and D read halved).
     *
     * <p>Zigzag because a proximity graph's neighbour list is ordered by
     * distance, not by id, so the deltas are signed.
     */
    public static byte[] encodeAdjacency(List<Long> neighbours) {
        ByteWriter w = new ByteWriter(2 + neighbours.size() * 2);
        w.u16(neighbours.size());
        long previous = 0;
        for (int i = 0; i < neighbours.size(); i++) {
            long id = neighbours.get(i);
            w.ivar(id - previous);
            previous = id;
        }
        return w.toBytes();
    }

    public static List<Long> decodeAdjacency(byte[] record) {
        ByteReader r = new ByteReader(record);
        int degree = r.u16();
        List<Long> out = new ArrayList<>(degree);
        long previous = 0;
        for (int i = 0; i < degree; i++) {
            long id = previous + r.ivar();
            out.add(id);
            previous = id;
        }
        return out;
    }

    public synchronized List<Long> neighbours(int level, long slot) {
        byte[] raw = adjacency.get(adjacencyKey(level, slot));
        return raw == null ? List.of() : decodeAdjacency(((Value.Bytes) Cve.decode(raw)).value());
    }

    // ==================================================================
    // §8 search
    // ==================================================================

    /**
     * {@code search(query, k, filter?)}, nearest first, in the declared metric.
     *
     * <p>Two rules from §8 are not negotiable and are both here: the distances
     * returned are the <strong>true</strong> distances to the documents
     * returned, and a slot with no live document is never returned — which is
     * what makes a delete correct immediately.
     */
    public synchronized List<Hit> search(float[] query, int k, java.util.function.LongPredicate filter) {
        if (query.length != dim) {
            throw new InvalidArgumentException("query has " + query.length
                    + " dimensions, index " + name + " declares " + dim);
        }
        Pager pager = db.engine().pager();
        int ef = Math.max(k, EF_SEARCH);
        if (filter == null && live.cardinality() > ef) {
            List<Hit> hits = new ArrayList<>();
            for (Scored c : beam(query, ef, null)) {
                if (live.get((int) c.slot)) {
                    hits.add(new Hit(slotDoc[(int) c.slot], c.d));
                }
                if (hits.size() == k) {
                    return hits;
                }
            }
            // Fewer than k live slots in the beam (deletes): the scan below answers.
            fallbacks++;
        }
        List<Hit> hits = new ArrayList<>();
        for (int s = live.nextSetBit(0); s >= 0; s = live.nextSetBit(s + 1)) {
            long doc = slotDoc[s];
            if (filter != null && !filter.test(doc)) {
                continue;
            }
            hits.add(new Hit(doc, distance(query, region.read(pager, s))));
        }
        hits.sort(Comparator.comparingDouble(Hit::distance));
        return hits.subList(0, Math.min(k, hits.size()));
    }

    public List<Hit> search(float[] query, int k) {
        return search(query, k, null);
    }

    double distance(float[] a, float[] b) {
        return distance(metric, a, b);
    }

    /**
     * §8.1 — the three metrics, as <b>distances</b>: smaller is nearer.
     *
     * <p>{@code dot} is negated because a dot product is a similarity;
     * {@code cosine} is {@code 1 - similarity}, not the similarity; {@code l2}
     * is the Euclidean distance and not its square. §8 requires the <em>true</em>
     * distance to be returned, so the square is not an option even though it
     * orders identically.
     *
     * <p>Accumulation is in {@code double} whatever the region's {@code dtype}:
     * summing 1024 {@code float} products in {@code float} drifts by ~1e-4, so
     * two implementations reading the same region would return different
     * distances and order near-ties differently.
     *
     * <p>Static, and public, because it is arithmetic: the shared conformance
     * vectors check it without constructing an index.
     */
    public static double distance(String metric, float[] a, float[] b) {
        switch (metric) {
            case METRIC_L2: {
                double sum = 0;
                for (int i = 0; i < a.length; i++) {
                    double d = (double) a[i] - b[i];
                    sum += d * d;
                }
                return Math.sqrt(sum);
            }
            case METRIC_DOT: {
                double dot = 0;
                for (int i = 0; i < a.length; i++) {
                    dot += (double) a[i] * b[i];
                }
                // Nearest first, so a larger dot product must sort lower.
                return -dot;
            }
            case METRIC_COSINE: {
                double dot = 0;
                double na = 0;
                double nb = 0;
                for (int i = 0; i < a.length; i++) {
                    dot += (double) a[i] * b[i];
                    na += (double) a[i] * a[i];
                    nb += (double) b[i] * b[i];
                }
                double denominator = Math.sqrt(na) * Math.sqrt(nb);
                // §8.1: a zero vector has no direction, so this is the
                // orthogonal value rather than a division by zero. A NaN here
                // propagates into a neighbour list and corrupts the ordering.
                return denominator == 0 ? 1 : 1 - dot / denominator;
            }
            default: throw new InvalidArgumentException("metric '" + metric
                    + "' is not one of cosine, l2, dot");
        }
    }

    /**
     * §7: a rebuild from the collection is always possible, because the vectors
     * also live in the documents as CVE {@code VECTOR} values. An
     * implementation encountering a graph it cannot trust MUST be able to
     * rebuild rather than fail.
     */
    public synchronized void rebuild() {
        live.clear();
        docToSlot.clear();
        nextSlot = 1;
        entry = 0;
        adjacency.clear();
        Engine.Batch clear = db.engine().batch();
        clear.removeRange(slotToDocTree, Cke.UNBOUNDED_BELOW, new byte[]{(byte) 0xFE});
        clear.removeRange(docToSlotTree, Cke.UNBOUNDED_BELOW, new byte[]{(byte) 0xFE});
        clear.commit();
        try (Engine.Cursor c = owner.scan(false)) {
            while (c.next()) {
                put(((Value.NitriteId) Cke.decode(c.row().key())).id(), owner.decode(c.row().value()));
            }
        }
    }

    private float[] vectorOf(Value.Doc document) {
        List<Value> values = IndexKeys.resolve(document, IndexKeys.splitFieldPath(field));
        if (values == null) {
            return null;
        }
        for (Value v : values) {
            if (v instanceof Value.Vector) {
                Value.Vector vec = ((Value.Vector) v);
                return floats(vec);
            }
        }
        return null;
    }

    static float[] floats(Value.Vector v) {
        ByteReader r = new ByteReader(v.payload());
        float[] out = new float[v.dim()];
        for (int i = 0; i < v.dim(); i++) {
            switch (v.dtype()) {
                case Value.Vector.DTYPE_F32: out[i] = r.f32(); break;
                case Value.Vector.DTYPE_F16: out[i] = VectorRegion.Half.toFloat(r.u16()); break;
                case Value.Vector.DTYPE_I8: out[i] = r.u8() - 128; break;
                default: throw new InvalidArgumentException("vector dtype " + v.dtype());
            }
        }
        return out;
    }
}
