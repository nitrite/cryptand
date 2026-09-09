package org.dizitart.cryptand.index;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.geom.Geometry;
import org.dizitart.cryptand.geom.Wkb;
import org.dizitart.cryptand.key.IndexKeys;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A spatial index bound to a collection — {@code spec/08-spatial.md} §2 and §4.
 *
 * <p>Updates go in the same batch as the document write, so the index is never
 * durably out of step with its collection ({@code 06-indexes.md} §8 applies
 * identically): the R-tree's repacked pages and its descriptor's new
 * {@code root} are written by the committer that publishes the document's
 * segment, under one superblock.
 *
 * <p>Every query here is <strong>two-phase</strong>, which §4 makes normative:
 * the R-tree yields candidates by bounding box and the exact predicate runs on
 * the geometry. Returning box-level results as if they were exact is what makes
 * a spatial query mean different things in different SDKs.
 */
public final class SpatialIndex {

    private final Database db;
    private final Collection owner;
    private final String name;
    private final String field;
    private final int dimensions;
    private final Integer srid;
    private final RTree tree;
    private TreeDescriptor descriptor;

    public SpatialIndex(Database db, Collection owner, String name, TreeDescriptor descriptor) {
        this.db = db;
        this.owner = owner;
        this.name = name;
        this.descriptor = descriptor;
        this.field = ((Value.Str) descriptor.params().field("field")).value();
        Value dims = descriptor.params().field("dimensions");
        this.dimensions = dims == null ? 2 : (int) SegmentMeta.longOf(dims);
        Value s = descriptor.params().field("srid");
        this.srid = s == null ? null : (int) SegmentMeta.longOf(s);
        Long root = descriptor.root();
        this.tree = RTree.load(db.engine().pager(), descriptor.treeId(), dimensions,
                root == null ? 0 : root);
    }

    public String name() {
        return name;
    }

    public String field() {
        return field;
    }

    public int dimensions() {
        return dimensions;
    }

    /**
     * The index's coordinate reference system, or null for "unspecified,
     * planar".
     *
     * <p>SRID is carried here rather than in each geometry: per-geometry SRIDs
     * would mean an R-tree whose bounding boxes are in mixed units — boxes that
     * compare but do not mean anything. An application needing several reference
     * systems uses several indexes.
     */
    public Integer srid() {
        return srid;
    }

    public synchronized int size() {
        return tree.size();
    }

    // ==================================================================
    // maintenance
    // ==================================================================


    // ==================================================================
    // Concurrency — the commit hook runs on the committer thread
    // ==================================================================
    //
    // `Engine.publishSuperblock` runs this index's `commit()` from the
    // committer while the application thread is still calling `put` and
    // `remove` on it. The state underneath — an `ArrayList` of entries here, a
    // pair of maps in the vector index — is not thread-safe, so the two must
    // not overlap: a repack that iterates the entry list while the application
    // grows it loses entries outright. Measured at 458 of 500 points found.
    //
    // One monitor over the mutators, the commit and the queries is the whole
    // fix. None of these is on a hot path — an index update is per document,
    // not per operation — and the committer holds `structure` around the hook,
    // so this monitor is always taken after it and never before.

    /** Indexes a document's geometry field, or does nothing when it has none. */
    public synchronized void put(long nitriteId, Value.Doc document, Integer declaredSrid) {
        if (declaredSrid != null && srid != null && !declaredSrid.equals(srid)) {
            throw new InvalidArgumentException("geometry declares SRID " + declaredSrid
                    + " but index " + name + " works in SRID " + srid
                    + "; the format does not reproject (spec/08-spatial.md §1)");
        }
        tree.remove(nitriteId);
        List<Value> values = IndexKeys.resolve(document, IndexKeys.splitFieldPath(field));
        if (values == null) {
            return;
        }
        for (Value v : values) {
            if (v instanceof Value.Geometry g) {
                tree.insert(Wkb.envelope(g.wkb(), dimensions), nitriteId);
            }
        }
    }

    public synchronized void remove(long nitriteId) {
        tree.remove(nitriteId);
    }

    /** Repacks and republishes the root. Called by the engine's commit path. */
    public synchronized void commit() {
        long root = tree.commit();
        if (descriptor.root() == null || descriptor.root() != root) {
            Map<String, Value> fields = new LinkedHashMap<>(descriptor.document().fields());
            fields.put("root", Value.integer(NumType.U64, root));
            fields.put("entries", Value.integer(NumType.U64, tree.size()));
            descriptor = new TreeDescriptor(Value.Doc.of(fields));
            db.putDescriptor(name, descriptor);
        }
    }

    // ==================================================================
    // queries, §4 — box first, then the exact predicate
    // ==================================================================

    public synchronized List<Long> intersects(byte[] queryWkb) {
        return exact(tree.candidatesIntersecting(Wkb.envelope(queryWkb, dimensions)),
                g -> Geometry.intersects(g, queryWkb));
    }

    public synchronized List<Long> within(byte[] queryWkb) {
        return exact(tree.candidatesIntersecting(Wkb.envelope(queryWkb, dimensions)),
                g -> Geometry.within(g, queryWkb));
    }

    public synchronized List<Long> contains(byte[] queryWkb) {
        return exact(tree.candidatesIntersecting(Wkb.envelope(queryWkb, dimensions)),
                g -> Geometry.contains(g, queryWkb));
    }

    public synchronized List<Long> near(double x, double y, double radius) {
        double[] min = new double[dimensions];
        double[] max = new double[dimensions];
        min[0] = x;
        max[0] = x;
        if (dimensions > 1) {
            min[1] = y;
            max[1] = y;
        }
        Wkb.Box query = new Wkb.Box(min, max).expandedBy(radius);
        return exact(tree.candidatesIntersecting(query), g -> Geometry.near(g, x, y, radius));
    }

    /**
     * The k nearest by exact distance.
     *
     * <p>The R-tree's best-first order is by <em>box</em> distance, which is a
     * lower bound on the geometry's, so the candidate set is widened before the
     * exact ranking — otherwise a large polygon whose box is far away but whose
     * edge is near would be ranked below a point it is closer than.
     */
    public List<Long> nearestK(double x, double y, int k) {
        double[] point = dimensions > 1 ? new double[]{x, y} : new double[]{x};
        List<Long> candidates = tree.nearest(point, Math.max(k * 4, k + 8));
        // A NitriteId never travels through a double: everything above 2^53
        // comes back changed, and a changed id resolves to no document at all.
        record Ranked(double distance, long id) {
        }
        List<Ranked> ranked = new ArrayList<>();
        for (long id : candidates) {
            byte[] g = geometryOf(id);
            if (g != null) {
                ranked.add(new Ranked(Geometry.distance(g, x, y), id));
            }
        }
        ranked.sort(java.util.Comparator.comparingDouble(Ranked::distance));
        List<Long> out = new ArrayList<>();
        for (int i = 0; i < Math.min(k, ranked.size()); i++) {
            out.add(ranked.get(i).id());
        }
        return out;
    }

    private List<Long> exact(List<Long> candidates, java.util.function.Predicate<byte[]> predicate) {
        List<Long> out = new ArrayList<>();
        for (long id : candidates) {
            byte[] g = geometryOf(id);
            if (g != null && predicate.test(g)) {
                out.add(id);
            }
        }
        return out;
    }

    private byte[] geometryOf(long nitriteId) {
        Value.Doc doc = owner.get(nitriteId);
        if (doc == null) {
            return null;
        }
        List<Value> values = IndexKeys.resolve(doc, IndexKeys.splitFieldPath(field));
        if (values == null) {
            return null;
        }
        for (Value v : values) {
            if (v instanceof Value.Geometry g) {
                return g.wkb();
            }
        }
        return null;
    }
}
