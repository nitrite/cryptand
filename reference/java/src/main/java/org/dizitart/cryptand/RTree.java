package org.dizitart.cryptand;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.PriorityQueue;

/**
 * The spatial index — {@code spec/08-spatial.md} §2.
 *
 * <p>A tree of {@code RTREE_INTERNAL} and {@code RTREE_LEAF} pages in the same
 * container, rooted from its catalog descriptor. What the Rust
 * {@code disk_rtree}'s design loses here is only its <em>private container</em>:
 * the file header, the free list, the migration manager and the integrity
 * checker are all duplicates of things {@code 01-container.md} already
 * specifies for every page in the database.
 *
 * <p><strong>The split algorithm is deliberately not specified</strong>, so this
 * one bulk-loads by Sort-Tile-Recursive packing. Two implementations inserting
 * the same documents produce different, equally valid trees, and a conformance
 * test therefore compares query results and never tree shape.
 *
 * <p><em>ponytail: entries are held in memory and the tree is repacked when it
 * changes</em> — the same trade {@link PageTree} makes and for the same reason.
 * The ceiling is the number of indexed geometries in one index; an incremental
 * insert path with a real split is the upgrade when that stops fitting.
 */
public final class RTree {

    public static final int FLAG_IS_LEAF = 0x01;
    /** Fixed part of the payload, before the entries. */
    public static final int HEADER = 16;

    public record Entry(Wkb.Box box, long nitriteId) {
    }

    private final Pager pager;
    private final int treeId;
    private final int dimensions;
    private final List<Entry> entries = new ArrayList<>();
    private final List<Long> oldPages = new ArrayList<>();
    private long root;
    private boolean dirty;

    private RTree(Pager pager, int treeId, int dimensions, long root) {
        this.pager = pager;
        this.treeId = treeId;
        this.dimensions = dimensions;
        this.root = root;
    }

    public static RTree load(Pager pager, int treeId, int dimensions, long root) {
        RTree t = new RTree(pager, treeId, dimensions, root);
        if (root != 0) {
            t.read(root);
        }
        return t;
    }

    public int dimensions() {
        return dimensions;
    }

    public long root() {
        return root;
    }

    public int size() {
        return entries.size();
    }

    public List<Entry> entries() {
        return List.copyOf(entries);
    }

    public void insert(Wkb.Box box, long nitriteId) {
        entries.add(new Entry(box, nitriteId));
        dirty = true;
    }

    public void remove(long nitriteId) {
        if (entries.removeIf(e -> e.nitriteId() == nitriteId)) {
            dirty = true;
        }
    }

    // ==================================================================
    // page format, §2.1
    // ==================================================================

    private void read(long page) {
        oldPages.add(page);
        byte[] payload = pager.readPage(page);
        ByteReader r = new ByteReader(payload);
        int count = r.u16();
        int dims = r.u8();
        int flags = r.u8();
        r.skip(4);
        r.u64();
        if (dims != dimensions) {
            // A reader MUST use the page's own `dimensions` and MUST reject a
            // page whose value disagrees with the descriptor: the entry stride
            // grows with it, so a mismatch silently misreads every box.
            throw new CorruptionException("R-tree page " + page + " declares " + dims
                    + " dimensions, the descriptor says " + dimensions, page, null);
        }
        boolean leaf = (flags & FLAG_IS_LEAF) != 0;
        for (int i = 0; i < count; i++) {
            double[] min = new double[dims];
            double[] max = new double[dims];
            for (int d = 0; d < dims; d++) {
                min[d] = r.f64();
            }
            for (int d = 0; d < dims; d++) {
                max[d] = r.f64();
            }
            if (leaf) {
                entries.add(new Entry(new Wkb.Box(min, max), r.u64()));
            } else {
                long child = r.u64();
                r.u64();
                read(child);
            }
        }
    }

    private int entryStride(boolean leaf) {
        return 16 * dimensions + (leaf ? 8 : 16);
    }

    private int fanout(boolean leaf) {
        return Math.max(2, (pager.payloadSize() - HEADER) / entryStride(leaf));
    }

    /** Repacks the tree if it changed and returns the new root. */
    public long commit() {
        if (!dirty) {
            return root;
        }
        for (long p : oldPages) {
            pager.freeExtent(p, 1);
        }
        oldPages.clear();
        root = entries.isEmpty() ? 0 : build();
        dirty = false;
        return root;
    }

    /**
     * Sort-Tile-Recursive packing: sort by each axis in turn and slice into
     * tiles, which gives low-overlap nodes for a static set at O(n log n).
     */
    private long build() {
        List<Entry> sorted = new ArrayList<>(entries);
        sorted.sort(Comparator.comparingDouble(e -> centre(e.box(), 0)));
        int leafFanout = fanout(true);
        List<Object[]> level = new ArrayList<>();
        int slices = (int) Math.ceil(Math.sqrt(Math.ceil((double) sorted.size() / leafFanout)));
        int perSlice = Math.max(leafFanout, (int) Math.ceil((double) sorted.size() / Math.max(1, slices)));
        for (int start = 0; start < sorted.size(); start += perSlice) {
            List<Entry> slice = new ArrayList<>(
                    sorted.subList(start, Math.min(sorted.size(), start + perSlice)));
            slice.sort(Comparator.comparingDouble(e -> centre(e.box(), 1)));
            for (int i = 0; i < slice.size(); i += leafFanout) {
                List<Entry> node = slice.subList(i, Math.min(slice.size(), i + leafFanout));
                level.add(emitLeaf(node));
            }
        }
        int internalFanout = fanout(false);
        while (level.size() > 1) {
            List<Object[]> next = new ArrayList<>();
            for (int i = 0; i < level.size(); i += internalFanout) {
                next.add(emitInternal(level.subList(i, Math.min(level.size(), i + internalFanout))));
            }
            level = next;
        }
        return (long) level.get(0)[1];
    }

    private static double centre(Wkb.Box b, int axis) {
        if (axis >= b.dimensions() || b.isEmpty()) {
            return 0;
        }
        return (b.min()[axis] + b.max()[axis]) / 2;
    }

    /** {@code {Box, pageId, subtreeEntries}} for the level above. */
    private Object[] emitLeaf(List<Entry> node) {
        ByteWriter w = new ByteWriter(pager.payloadSize());
        w.u16(node.size()).u8(dimensions).u8(FLAG_IS_LEAF).u32(0).u64(node.size());
        Wkb.Box cover = Wkb.Box.empty(dimensions);
        for (Entry e : node) {
            writeBox(w, e.box());
            w.u64(e.nitriteId());
            cover = cover.union(e.box());
        }
        return new Object[]{cover, write(w, PageHeader.Type.RTREE_LEAF), (long) node.size()};
    }

    private Object[] emitInternal(List<Object[]> children) {
        ByteWriter w = new ByteWriter(pager.payloadSize());
        long total = 0;
        for (Object[] c : children) {
            total += (long) c[2];
        }
        w.u16(children.size()).u8(dimensions).u8(0).u32(0).u64(total);
        Wkb.Box cover = Wkb.Box.empty(dimensions);
        for (Object[] c : children) {
            Wkb.Box box = (Wkb.Box) c[0];
            writeBox(w, box);
            w.u64((long) c[1]).u64((long) c[2]);
            cover = cover.union(box);
        }
        return new Object[]{cover, write(w, PageHeader.Type.RTREE_INTERNAL), total};
    }

    private void writeBox(ByteWriter w, Wkb.Box box) {
        for (int d = 0; d < dimensions; d++) {
            w.f64(d < box.dimensions() ? box.min()[d] : Double.POSITIVE_INFINITY);
        }
        for (int d = 0; d < dimensions; d++) {
            w.f64(d < box.dimensions() ? box.max()[d] : Double.NEGATIVE_INFINITY);
        }
    }

    private long write(ByteWriter w, int pageType) {
        long page = pager.allocate(1);
        oldPages.add(page);
        PageHeader h = new PageHeader();
        h.pageType = pageType;
        h.treeId = treeId;
        pager.writePage(page, h, w.toBytes());
        return page;
    }

    // ==================================================================
    // queries, §4 — phase one only: these return CANDIDATES
    // ==================================================================

    /**
     * Ids whose bounding box intersects {@code query}.
     *
     * <p>These are <strong>candidates</strong>. §4 forbids returning box-level
     * results as if they were exact, so a caller runs {@link Geometry}'s
     * predicate over them — which is what {@link SpatialIndex} does.
     */
    public List<Long> candidatesIntersecting(Wkb.Box query) {
        return search(box -> box.intersects(query), box -> box.intersects(query));
    }

    /** Ids whose box is contained by {@code query} — the descent for {@code within}. */
    public List<Long> candidatesWithin(Wkb.Box query) {
        // A node is worth descending if it merely intersects; only a leaf entry
        // has to be contained.
        return search(query::intersects, query::contains);
    }

    /** Ids whose box contains {@code query} — the descent for {@code contains}. */
    public List<Long> candidatesContaining(Wkb.Box query) {
        return search(box -> box.contains(query), box -> box.contains(query));
    }

    /**
     * Descends the on-disk tree, pruning a subtree whose box fails
     * {@code descend}.
     *
     * <p>An uncommitted tree is scanned linearly instead: the packed pages are
     * then stale, and a query that used them would miss everything inserted
     * since. The in-memory entry list is the authority until {@link #commit}
     * repacks.
     */
    private List<Long> search(java.util.function.Predicate<Wkb.Box> descend,
                              java.util.function.Predicate<Wkb.Box> accept) {
        List<Long> out = new ArrayList<>();
        if (dirty || root == 0) {
            for (Entry e : entries) {
                if (accept.test(e.box())) {
                    out.add(e.nitriteId());
                }
            }
            return out;
        }
        descend(root, descend, accept, out);
        return out;
    }

    private void descend(long page, java.util.function.Predicate<Wkb.Box> descend,
                         java.util.function.Predicate<Wkb.Box> accept, List<Long> out) {
        Node node = node(page);
        for (int i = 0; i < node.boxes().size(); i++) {
            Wkb.Box box = node.boxes().get(i);
            if (node.leaf()) {
                if (accept.test(box)) {
                    out.add(node.payload().get(i));
                }
            } else if (descend.test(box)) {
                descend(node.payload().get(i), descend, accept, out);
            }
        }
    }

    private record Node(boolean leaf, List<Wkb.Box> boxes, List<Long> payload) {
    }

    private Node node(long page) {
        byte[] payload = pager.readPage(page);
        ByteReader r = new ByteReader(payload);
        int count = r.u16();
        int dims = r.u8();
        int flags = r.u8();
        r.skip(4);
        r.u64();
        if (dims != dimensions) {
            throw new CorruptionException("R-tree page " + page + " declares " + dims
                    + " dimensions, the descriptor says " + dimensions, page, null);
        }
        boolean leaf = (flags & FLAG_IS_LEAF) != 0;
        List<Wkb.Box> boxes = new ArrayList<>(count);
        List<Long> ids = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            double[] min = new double[dims];
            double[] max = new double[dims];
            for (int d = 0; d < dims; d++) {
                min[d] = r.f64();
            }
            for (int d = 0; d < dims; d++) {
                max[d] = r.f64();
            }
            boxes.add(new Wkb.Box(min, max));
            ids.add(r.u64());
            if (!leaf) {
                r.u64();
            }
        }
        return new Node(leaf, boxes, ids);
    }

    /**
     * Best-first search over node distances — §4's {@code nearest_k}. The
     * priority queue holds subtrees as well as entries, so a subtree further
     * away than the k-th best entry is never opened.
     */
    public List<Long> nearest(double[] point, int k) {
        List<Long> out = new ArrayList<>();
        PriorityQueue<Candidate> heap = new PriorityQueue<>(Comparator.comparingDouble(Candidate::distance));
        if (dirty || root == 0) {
            for (Entry e : entries) {
                heap.add(new Candidate(e.box().squaredDistanceTo(point), true, e.nitriteId()));
            }
        } else {
            heap.add(new Candidate(0, false, root));
        }
        while (!heap.isEmpty() && out.size() < k) {
            Candidate top = heap.poll();
            if (top.isEntry()) {
                out.add(top.payload());
                continue;
            }
            Node node = node(top.payload());
            for (int i = 0; i < node.boxes().size(); i++) {
                heap.add(new Candidate(node.boxes().get(i).squaredDistanceTo(point),
                        node.leaf(), node.payload().get(i)));
            }
        }
        return out;
    }

    /**
     * A heap entry. The payload is a {@code long} and not a {@code double}
     * field of an array: a NitriteId is a full 64-bit value, and everything
     * above 2^53 comes back changed from a double — a silently wrong id, which
     * then resolves to no document at all.
     */
    private record Candidate(double distance, boolean isEntry, long payload) {
    }
}
