package org.dizitart.cryptand.index;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.geom.Geometry;
import org.dizitart.cryptand.geom.Wkb;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.function.Predicate;

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
 * one inserts by least enlargement and splits a full node at the median of its
 * widest axis. Two implementations inserting the same documents produce
 * different, equally valid trees, and a conformance test therefore compares
 * query results and never tree shape.
 *
 * <p>F-195: the tree is copy-on-write. A write copies the path it touches into
 * memory and frees the old pages (reusable after the next commit, 01 §6);
 * {@link #commit} writes the copied nodes back as fresh pages. Past
 * {@link #DIRTY_BUDGET} copied nodes the same write-back runs early, so the heap
 * holds a bounded part of the tree whatever its size. Removal needs the
 * entry's box, which the caller derives from the previous document.
 * <em>ponytail: no reinsertion on underflow (2.2 allows any population from
 * 1); a long delete-heavy life leaves sparse nodes, R*-tree condense is the
 * upgrade.</em>
 */
public final class RTree {

    public static final int FLAG_IS_LEAF = 0x01;
    /** Fixed part of the payload, before the entries. */
    public static final int HEADER = 16;
    /** Copied nodes held before an early write-back: ~10 KB each, so ~20 MB of heap. */
    static int DIRTY_BUDGET = 2048;

    /** One node, read from a page or copied for a write. */
    private static final class Node {
        final boolean leaf;
        int n;
        Wkb.Box[] box;
        /** Leaf: nitrite id. Internal: child page, 0 while the child is only in {@link #kid}. */
        long[] ref;
        long[] cnt;
        long[] nonce;
        /** Internal: the copied child, or null when it is still on its page. */
        Node[] kid;

        Node(boolean leaf, int cap) {
            this.leaf = leaf;
            box = new Wkb.Box[cap];
            ref = new long[cap];
            cnt = new long[cap];
            nonce = new long[cap];
            kid = new Node[cap];
        }

        void add(Wkb.Box b, long r, long c, long nc, Node k) {
            if (n == box.length) {
                int cap = n * 2 + 1;
                box = Arrays.copyOf(box, cap);
                ref = Arrays.copyOf(ref, cap);
                cnt = Arrays.copyOf(cnt, cap);
                nonce = Arrays.copyOf(nonce, cap);
                kid = Arrays.copyOf(kid, cap);
            }
            box[n] = b;
            ref[n] = r;
            cnt[n] = c;
            nonce[n] = nc;
            kid[n] = k;
            n++;
        }

        void removeAt(int i) {
            n--;
            box[i] = box[n];
            ref[i] = ref[n];
            cnt[i] = cnt[n];
            nonce[i] = nonce[n];
            kid[i] = kid[n];
            box[n] = null;
            kid[n] = null;
        }

        long total() {
            if (leaf) {
                return n;
            }
            long t = 0;
            for (int i = 0; i < n; i++) {
                t += cnt[i];
            }
            return t;
        }

        Wkb.Box cover(int dimensions) {
            Wkb.Box c = Wkb.Box.empty(dimensions);
            for (int i = 0; i < n; i++) {
                c = c.union(box[i]);
            }
            return c;
        }
    }

    private final Pager pager;
    private final int treeId;
    private final int dimensions;
    /** The copied root, or null when the root is {@link #rootPage} (0: empty tree). */
    private Node root;
    private long rootPage;
    /** F-128: the root's header nonce, as the descriptor's {@code root_nonce}. */
    private long rootNonce;
    private long size;
    private int dirty;
    private boolean rewriteAll;
    /** Pages whose header nonce was checked against their parent (14 §5.5). */
    private final Set<Long> verified = new HashSet<>();

    private RTree(Pager pager, int treeId, int dimensions, long root, long rootNonce) {
        this.pager = pager;
        this.treeId = treeId;
        this.dimensions = dimensions;
        this.rootPage = root;
        this.rootNonce = rootNonce;
    }

    /** Reads the root; every other page is checked against its parent's nonce when first read. */
    public static RTree load(Pager pager, int treeId, int dimensions, long root, long rootNonce) {
        RTree t = new RTree(pager, treeId, dimensions, root, rootNonce);
        if (root != 0) {
            t.size = t.read(root, rootNonce).total();
        }
        return t;
    }

    /** Every page the tree occupies now. */
    public List<Long> pages() {
        List<Long> out = new ArrayList<>();
        if (root != null) {
            pagesUnder(root, out);
        } else if (rootPage != 0) {
            out.add(rootPage);
            pagesUnder(read(rootPage, rootNonce), out);
        }
        return out;
    }

    private void pagesUnder(Node node, List<Long> out) {
        if (node.leaf) {
            return;
        }
        for (int i = 0; i < node.n; i++) {
            if (node.kid[i] != null) {
                pagesUnder(node.kid[i], out);
            } else {
                out.add(node.ref[i]);
                pagesUnder(read(node.ref[i], node.nonce[i]), out);
            }
        }
    }

    /** The next {@link #commit} rewrites every page (F-072: conversion in place). */
    public void markDirty() {
        rewriteAll = true;
    }

    public int dimensions() {
        return dimensions;
    }

    public long root() {
        return rootPage;
    }

    public long rootNonce() {
        return rootNonce;
    }

    public int size() {
        return (int) size;
    }

    // ==================================================================
    // writes
    // ==================================================================

    public void insert(Wkb.Box box, long nitriteId) {
        Node r = rootNode();
        if (r == null) {
            r = root = new Node(true, fanout(true) + 1);
            dirty++;
        }
        Node split = insert(r, box, nitriteId);
        if (split != null) {
            Node up = new Node(false, fanout(false) + 1);
            up.add(r.cover(dimensions), 0, r.total(), 0, r);
            up.add(split.cover(dimensions), 0, split.total(), 0, split);
            root = up;
            dirty++;
        }
        size++;
        spillIfOver();
    }

    /** Returns the new sibling when {@code node} split. */
    private Node insert(Node node, Wkb.Box box, long nitriteId) {
        if (node.leaf) {
            node.add(box, nitriteId, 0, 0, null);
        } else {
            int i = choose(node, box);
            Node c = child(node, i);
            Node s = insert(c, box, nitriteId);
            node.box[i] = c.cover(dimensions);
            node.cnt[i] = c.total();
            if (s != null) {
                node.add(s.cover(dimensions), 0, s.total(), 0, s);
            }
        }
        return node.n > fanout(node.leaf) ? split(node) : null;
    }

    /** Least area enlargement, then least area. */
    private static int choose(Node node, Wkb.Box box) {
        int best = 0;
        double bestGrow = Double.POSITIVE_INFINITY;
        double bestArea = Double.POSITIVE_INFINITY;
        for (int i = 0; i < node.n; i++) {
            double area = node.box[i].area();
            double grow = node.box[i].union(box).area() - area;
            if (grow < bestGrow || (grow == bestGrow && area < bestArea)) {
                best = i;
                bestGrow = grow;
                bestArea = area;
            }
        }
        return best;
    }

    /** Median split on the axis whose entry centres spread widest; the upper half moves out. */
    private Node split(Node node) {
        int axis = 0;
        double widest = -1;
        for (int a = 0; a < dimensions; a++) {
            double lo = Double.POSITIVE_INFINITY;
            double hi = Double.NEGATIVE_INFINITY;
            for (int i = 0; i < node.n; i++) {
                double c = centre(node.box[i], a);
                lo = Math.min(lo, c);
                hi = Math.max(hi, c);
            }
            if (hi - lo > widest) {
                widest = hi - lo;
                axis = a;
            }
        }
        final int ax = axis;
        Integer[] order = new Integer[node.n];
        for (int i = 0; i < node.n; i++) {
            order[i] = i;
        }
        Arrays.sort(order, Comparator.comparingDouble(i -> centre(node.box[i], ax)));
        Node lo = new Node(node.leaf, node.box.length);
        Node hi = new Node(node.leaf, node.box.length);
        for (int k = 0; k < order.length; k++) {
            int i = order[k];
            (k < order.length / 2 ? lo : hi).add(node.box[i], node.ref[i], node.cnt[i], node.nonce[i], node.kid[i]);
        }
        node.n = lo.n;
        node.box = lo.box;
        node.ref = lo.ref;
        node.cnt = lo.cnt;
        node.nonce = lo.nonce;
        node.kid = lo.kid;
        dirty++;
        return hi;
    }

    /** Removes one entry of {@code nitriteId} whose box is {@code box}; false if there is none. */
    public boolean remove(Wkb.Box box, long nitriteId) {
        if (size == 0) {
            return false;
        }
        List<Integer> path = new ArrayList<>();
        if (!find(rootView(), box, nitriteId, path)) {
            return false;
        }
        List<Node> nodes = new ArrayList<>();
        Node node = rootNode();
        nodes.add(node);
        for (int d = 0; d < path.size() - 1; d++) {
            node = child(node, path.get(d));
            nodes.add(node);
        }
        node.removeAt(path.get(path.size() - 1));
        for (int d = nodes.size() - 2; d >= 0; d--) {
            Node parent = nodes.get(d);
            Node c = nodes.get(d + 1);
            int i = path.get(d);
            if (c.n == 0) {
                parent.removeAt(i);
                dirty--;
            } else {
                parent.box[i] = c.cover(dimensions);
                parent.cnt[i] = c.total();
            }
        }
        while (root.n == 1 && !root.leaf) {
            Node only = child(root, 0);
            root = only;
            dirty--;
        }
        if (root.n == 0) {
            root = null;
            dirty--;
        }
        size--;
        spillIfOver();
        return true;
    }

    private boolean find(Node node, Wkb.Box box, long nitriteId, List<Integer> path) {
        for (int i = 0; i < node.n; i++) {
            if (node.leaf) {
                // By value: Box.equals compares its arrays by reference.
                if (node.ref[i] == nitriteId && Arrays.equals(node.box[i].min(), box.min())
                        && Arrays.equals(node.box[i].max(), box.max())) {
                    path.add(i);
                    return true;
                }
            } else if (box.isEmpty() || node.box[i].contains(box)) {
                path.add(i);
                if (find(view(node, i), box, nitriteId, path)) {
                    return true;
                }
                path.remove(path.size() - 1);
            }
        }
        return false;
    }

    /** Writes the copied nodes back and returns the root page (0: empty tree). */
    public long commit() {
        writeOut();
        if (rewriteAll) {
            rewriteAll = false;
            if (rootPage != 0) {
                long[] at = rewrite(rootPage, rootNonce);
                rootPage = at[0];
                rootNonce = at[1];
            }
        }
        if (rootPage == 0) {
            rootNonce = 0;
        }
        return rootPage;
    }

    private void spillIfOver() {
        if (dirty > DIRTY_BUDGET) {
            writeOut();
        }
    }

    private void writeOut() {
        if (root == null) {
            return;
        }
        long[] at = write(root);
        rootPage = at[0];
        rootNonce = at[1];
        root = null;
        dirty = 0;
    }

    /** Streams the whole tree through fresh pages, O(depth) in memory. */
    private long[] rewrite(long page, long nonce) {
        Node node = read(page, nonce);
        free(page);
        if (!node.leaf) {
            for (int i = 0; i < node.n; i++) {
                long[] at = rewrite(node.ref[i], node.nonce[i]);
                node.ref[i] = at[0];
                node.nonce[i] = at[1];
            }
        }
        return writePage(node);
    }

    // ==================================================================
    // node access
    // ==================================================================

    /** The root for a write: copied from its page if it is not in memory yet. */
    private Node rootNode() {
        if (root == null && rootPage != 0) {
            root = read(rootPage, rootNonce);
            free(rootPage);
            rootPage = 0;
            dirty++;
        }
        return root;
    }

    /** Child {@code i} for a write: copied from its page, which is freed. */
    private Node child(Node node, int i) {
        if (node.kid[i] == null) {
            node.kid[i] = read(node.ref[i], node.nonce[i]);
            free(node.ref[i]);
            node.ref[i] = 0;
            dirty++;
        }
        return node.kid[i];
    }

    /** The root for a read; null for an empty tree. */
    private Node rootView() {
        return root != null ? root : rootPage == 0 ? null : read(rootPage, rootNonce);
    }

    private Node view(Node node, int i) {
        return node.kid[i] != null ? node.kid[i] : read(node.ref[i], node.nonce[i]);
    }

    private void free(long page) {
        pager.freeExtent(page, 1);
        verified.remove(page);
    }

    // ==================================================================
    // page format, §2.1
    // ==================================================================

    private Node read(long page, long nonce) {
        byte[] payload;
        if (verified.contains(page)) {
            payload = pager.readPage(page);
        } else {
            byte[] raw = pager.readRaw(page);
            PageHeader h = PageHeader.verify(raw, page);
            pager.checkNonce(page, h, nonce);
            payload = pager.decodePayload(raw, h, page);
            verified.add(page);
        }
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
        Node node = new Node(leaf, Math.max(count, fanout(leaf)) + 1);
        for (int i = 0; i < count; i++) {
            double[] min = new double[dims];
            double[] max = new double[dims];
            for (int d = 0; d < dims; d++) {
                min[d] = r.f64();
            }
            for (int d = 0; d < dims; d++) {
                max[d] = r.f64();
            }
            Wkb.Box b = new Wkb.Box(min, max);
            if (leaf) {
                node.add(b, r.u64(), 0, 0, null);
            } else {
                long child = r.u64();
                long cnt = r.u64();
                node.add(b, child, cnt, r.u64(), null);
            }
        }
        return node;
    }

    private int entryStride(boolean leaf) {
        return 16 * dimensions + (leaf ? 8 : 24);
    }

    private int fanout(boolean leaf) {
        return Math.max(2, (pager.payloadSize() - HEADER) / entryStride(leaf));
    }

    private static double centre(Wkb.Box b, int axis) {
        if (axis >= b.dimensions() || b.isEmpty()) {
            return 0;
        }
        return (b.min()[axis] + b.max()[axis]) / 2;
    }

    /** Writes {@code node}'s copied children, then {@code node}; {@code {pageId, nonce}}. */
    private long[] write(Node node) {
        if (!node.leaf) {
            for (int i = 0; i < node.n; i++) {
                if (node.kid[i] != null) {
                    long[] at = write(node.kid[i]);
                    node.ref[i] = at[0];
                    node.nonce[i] = at[1];
                    node.kid[i] = null;
                }
            }
        }
        return writePage(node);
    }

    /** {@code {pageId, nonce}}: the nonce is what the parent records (14 §5.5). */
    private long[] writePage(Node node) {
        ByteWriter w = new ByteWriter(pager.payloadSize());
        w.u16(node.n).u8(dimensions).u8(node.leaf ? FLAG_IS_LEAF : 0).u32(0).u64(node.total());
        for (int i = 0; i < node.n; i++) {
            writeBox(w, node.box[i]);
            if (node.leaf) {
                w.u64(node.ref[i]);
            } else {
                w.u64(node.ref[i]).u64(node.cnt[i]).u64(node.nonce[i]);
            }
        }
        long page = pager.allocate(1);
        PageHeader h = new PageHeader();
        h.pageType = node.leaf ? PageHeader.Type.RTREE_LEAF : PageHeader.Type.RTREE_INTERNAL;
        h.treeId = treeId;
        pager.writePage(page, h, w.toBytes());
        verified.add(page);
        return new long[]{page, h.nonce};
    }

    private void writeBox(ByteWriter w, Wkb.Box box) {
        for (int d = 0; d < dimensions; d++) {
            w.f64(d < box.dimensions() ? box.min()[d] : Double.POSITIVE_INFINITY);
        }
        for (int d = 0; d < dimensions; d++) {
            w.f64(d < box.dimensions() ? box.max()[d] : Double.NEGATIVE_INFINITY);
        }
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

    /** Descends the tree, copied nodes included, pruning a subtree whose box fails {@code descend}. */
    private List<Long> search(Predicate<Wkb.Box> descend, Predicate<Wkb.Box> accept) {
        List<Long> out = new ArrayList<>();
        Node r = rootView();
        if (r != null) {
            descend(r, descend, accept, out);
        }
        return out;
    }

    private void descend(Node node, Predicate<Wkb.Box> descend, Predicate<Wkb.Box> accept, List<Long> out) {
        for (int i = 0; i < node.n; i++) {
            if (node.leaf) {
                if (accept.test(node.box[i])) {
                    out.add(node.ref[i]);
                }
            } else if (descend.test(node.box[i])) {
                descend(view(node, i), descend, accept, out);
            }
        }
    }

    /**
     * Best-first search over node distances — §4's {@code nearest_k}. The
     * priority queue holds subtrees as well as entries, so a subtree further
     * away than the k-th best entry is never opened.
     */
    public List<Long> nearest(double[] point, int k) {
        List<Long> out = new ArrayList<>();
        PriorityQueue<Candidate> heap = new PriorityQueue<>(Comparator.comparingDouble(Candidate::distance));
        Node r = rootView();
        if (r != null) {
            heap.add(new Candidate(0, false, 0, 0, r));
        }
        while (!heap.isEmpty() && out.size() < k) {
            Candidate top = heap.poll();
            if (top.isEntry()) {
                out.add(top.payload());
                continue;
            }
            Node node = top.node != null ? top.node : read(top.payload(), top.nonce);
            for (int i = 0; i < node.n; i++) {
                double d = node.box[i].squaredDistanceTo(point);
                heap.add(node.leaf ? new Candidate(d, true, node.ref[i], 0, null)
                        : new Candidate(d, false, node.ref[i], node.nonce[i], node.kid[i]));
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
    private static final class Candidate {
        private final double distance;
        private final boolean isEntry;
        /** An entry's nitrite id, or a subtree's page. */
        private final long payload;
        private final long nonce;
        /** A copied subtree, or null: its page is read when it is popped. */
        private final Node node;

        Candidate(double distance, boolean isEntry, long payload, long nonce, Node node) {
            this.distance = distance;
            this.isEntry = isEntry;
            this.payload = payload;
            this.nonce = nonce;
            this.node = node;
        }

        double distance() {
            return distance;
        }

        boolean isEntry() {
            return isEntry;
        }

        long payload() {
            return payload;
        }
    }
}
