package org.dizitart.cryptand.index;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.container.PageTree;
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
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A vector index — {@code spec/09-vector.md}.
 *
 * <p>The design principle is stated in §0 and honoured here: <strong>specify the
 * durable layout, not the algorithm.</strong> A proximity graph is a flat vector
 * region plus an adjacency list per node; how an implementation searches or
 * builds that graph is its own business, as long as the recall it achieves is a
 * quality question and not a correctness one.
 *
 * <p><em>ponytail: this implementation writes a conforming Vamana-shaped graph
 * whose adjacency is nearest-neighbour by construction, and searches by the
 * brute-force scan §8 permits.</em> §8 requires exactly that fallback of any
 * implementation that will not traverse a foreign graph, and a flat region is
 * the layout it is designed to make fast — so brute force here is a conforming
 * search, not a stub. The upgrade is a greedy graph traversal over the same
 * bytes; nothing on disk changes.
 */
public final class VectorIndex {

    public static final String METRIC_COSINE = "cosine";
    public static final String METRIC_L2 = "l2";
    public static final String METRIC_DOT = "dot";

    public record Hit(long nitriteId, double distance) {
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
    private final PageTree adjacency;
    private final Map<Long, Long> slotToDoc = new LinkedHashMap<>();
    private final Map<Long, Long> docToSlot = new HashMap<>();
    private long nextSlot = 1;

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
        Long root = descriptor.root();
        this.adjacency = PageTree.load(db.engine().pager(), descriptor.treeId(), root == null ? 0 : root);
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

    public int size() {
        return slotToDoc.size();
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
                slotToDoc.put(slot, doc);
                docToSlot.put(doc, slot);
                nextSlot = Math.max(nextSlot, slot + 1);
            }
        }
    }

    // ==================================================================
    // maintenance
    // ==================================================================

    /** Indexes a document's vector field, replacing any slot it already owns. */
    public void put(long nitriteId, Value.Doc document) {
        float[] vector = vectorOf(document);
        if (vector == null) {
            remove(nitriteId);
            return;
        }
        if (vector.length != dim) {
            throw new InvalidArgumentException("vector has " + vector.length
                    + " dimensions, index " + name + " declares " + dim);
        }
        Long slot = docToSlot.get(nitriteId);
        if (slot == null) {
            slot = nextSlot++;
            growTo(slot);
        }
        region.write(db.engine().pager(), slot, vector);
        slotToDoc.put(slot, nitriteId);
        docToSlot.put(nitriteId, slot);
        Engine.Batch b = db.engine().batch();
        b.put(slotToDocTree, Cke.encode(Value.integer(NumType.U64, slot)),
                Cve.encode(new Value.NitriteId(nitriteId)));
        b.put(docToSlotTree, Cke.encode(new Value.NitriteId(nitriteId)),
                Cve.encode(Value.integer(NumType.U64, slot)));
        b.commit();
    }

    /**
     * §6: a deleted document's slot is marked by removing both mappings; the
     * slot stays in the graph until consolidation repairs the neighbourhoods,
     * and a search skips a slot with no document mapping. That is what makes a
     * delete correct <em>immediately</em> even though the graph is repaired
     * later.
     */
    public void remove(long nitriteId) {
        Long slot = docToSlot.remove(nitriteId);
        if (slot == null) {
            return;
        }
        slotToDoc.remove(slot);
        Engine.Batch b = db.engine().batch();
        b.remove(slotToDocTree, Cke.encode(Value.integer(NumType.U64, slot)));
        b.remove(docToSlotTree, Cke.encode(new Value.NitriteId(nitriteId)));
        b.commit();
    }

    private void growTo(long slot) {
        if (slot < region.slotCount) {
            return;
        }
        Pager pager = db.engine().pager();
        long want = Math.max(slot + 1, region.slotCount * 2);
        VectorRegion bigger = VectorRegion.create(pager, dim, region.dtype, want);
        for (Map.Entry<Long, Long> e : slotToDoc.entrySet()) {
            bigger.writeRaw(pager, e.getKey(), region.readRaw(pager, e.getKey()));
        }
        pager.freeExtent(region.startPage, region.pages);
        region = bigger;
        Map<String, Value> params = new LinkedHashMap<>(descriptor.params().fields());
        params.put("vector_region", Value.integer(NumType.U64, region.startPage));
        Map<String, Value> fields = new LinkedHashMap<>(descriptor.document().fields());
        fields.put("params", Value.Doc.of(params));
        descriptor = new TreeDescriptor(Value.Doc.of(fields));
        db.putDescriptor(name, descriptor);
    }

    /**
     * Rebuilds adjacency and republishes the roots. Called on the commit path,
     * so the graph, the maps and the document write land under one superblock.
     */
    public void commit() {
        rebuildAdjacency();
        long root = adjacency.commit();
        region.liveCount = slotToDoc.size();
        Map<String, Value> fields = new LinkedHashMap<>(descriptor.document().fields());
        boolean changed = descriptor.root() == null || descriptor.root() != root;
        fields.put("root", Value.integer(NumType.U64, root));
        fields.put("entries", Value.integer(NumType.U64, slotToDoc.size()));
        Map<String, Value> params = new LinkedHashMap<>(descriptor.params().fields());
        List<Value> entryPoints = new ArrayList<>();
        if (!slotToDoc.isEmpty()) {
            entryPoints.add(Value.integer(NumType.U64, slotToDoc.keySet().iterator().next()));
        }
        params.put("entry_points", new Value.Array(entryPoints));
        fields.put("params", Value.Doc.of(params));
        if (changed || !entryPoints.isEmpty()) {
            descriptor = new TreeDescriptor(Value.Doc.of(fields));
            db.putDescriptor(name, descriptor);
        }
    }

    /**
     * §3's adjacency record, wrapped in a CVE {@code BYTES} value for the same
     * reason postings are: every INLINE cell in the format holds a CVE value,
     * with no exceptions, so generic tooling can dump a tree it does not
     * understand.
     */
    private void rebuildAdjacency() {
        if (slotToDoc.isEmpty()) {
            return;
        }
        Pager pager = db.engine().pager();
        int degree = Math.min(32, Math.max(1, slotToDoc.size() - 1));
        List<Long> slots = new ArrayList<>(slotToDoc.keySet());
        Map<Long, float[]> vectors = new HashMap<>();
        for (long s : slots) {
            vectors.put(s, region.read(pager, s));
        }
        for (long s : slots) {
            float[] v = vectors.get(s);
            List<long[]> ranked = new ArrayList<>();
            for (long other : slots) {
                if (other != s) {
                    ranked.add(new long[]{Double.doubleToRawLongBits(
                            distance(v, vectors.get(other))), other});
                }
            }
            ranked.sort(Comparator.comparingDouble(a -> Double.longBitsToDouble(a[0])));
            List<Long> neighbours = new ArrayList<>();
            for (int i = 0; i < Math.min(degree, ranked.size()); i++) {
                neighbours.add(ranked.get(i)[1]);
            }
            adjacency.put(adjacencyKey(0, s), Cve.encode(new Value.Bytes(encodeAdjacency(neighbours))));
        }
    }

    static byte[] adjacencyKey(int level, long slot) {
        return Cke.encode(new Value.Array(List.of(
                Value.integer(NumType.U8, level),
                Value.integer(NumType.U64, slot))));
    }

    /**
     * {@code u16 degree} then zigzag deltas of {@code slot_id}, first absolute.
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
            if (i == 0) {
                w.uvar(id);
            } else {
                w.ivar(id - previous);
            }
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
            long id = i == 0 ? r.uvar() : previous + r.ivar();
            out.add(id);
            previous = id;
        }
        return out;
    }

    public List<Long> neighbours(int level, long slot) {
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
    public List<Hit> search(float[] query, int k, java.util.function.LongPredicate filter) {
        if (query.length != dim) {
            throw new InvalidArgumentException("query has " + query.length
                    + " dimensions, index " + name + " declares " + dim);
        }
        Pager pager = db.engine().pager();
        List<Hit> hits = new ArrayList<>();
        for (Map.Entry<Long, Long> e : slotToDoc.entrySet()) {
            long doc = e.getValue();
            if (filter != null && !filter.test(doc)) {
                continue;
            }
            hits.add(new Hit(doc, distance(query, region.read(pager, e.getKey()))));
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
        return switch (metric) {
            case METRIC_L2 -> {
                double sum = 0;
                for (int i = 0; i < a.length; i++) {
                    double d = (double) a[i] - b[i];
                    sum += d * d;
                }
                yield Math.sqrt(sum);
            }
            case METRIC_DOT -> {
                double dot = 0;
                for (int i = 0; i < a.length; i++) {
                    dot += (double) a[i] * b[i];
                }
                // Nearest first, so a larger dot product must sort lower.
                yield -dot;
            }
            case METRIC_COSINE -> {
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
                yield denominator == 0 ? 1 : 1 - dot / denominator;
            }
            default -> throw new InvalidArgumentException("metric '" + metric
                    + "' is not one of cosine, l2, dot");
        };
    }

    /**
     * §7: a rebuild from the collection is always possible, because the vectors
     * also live in the documents as CVE {@code VECTOR} values. An
     * implementation encountering a graph it cannot trust MUST be able to
     * rebuild rather than fail.
     */
    public void rebuild() {
        slotToDoc.clear();
        docToSlot.clear();
        nextSlot = 1;
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
            if (v instanceof Value.Vector vec) {
                return floats(vec);
            }
        }
        return null;
    }

    static float[] floats(Value.Vector v) {
        ByteReader r = new ByteReader(v.payload());
        float[] out = new float[v.dim()];
        for (int i = 0; i < v.dim(); i++) {
            out[i] = switch (v.dtype()) {
                case Value.Vector.DTYPE_F32 -> r.f32();
                case Value.Vector.DTYPE_F16 -> VectorRegion.Half.toFloat(r.u16());
                case Value.Vector.DTYPE_I8 -> r.u8() - 128;
                default -> throw new InvalidArgumentException("vector dtype " + v.dtype());
            };
        }
        return out;
    }
}
