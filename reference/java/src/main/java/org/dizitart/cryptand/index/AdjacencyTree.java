package org.dizitart.cryptand.index;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A vector index's adjacency tree ({@code spec/09-vector.md} §3) as a
 * copy-on-write B+tree that copies only the paths a write touches — F-196.
 *
 * <p>The pages are {@code 04-segments.md} §2.2 copy-on-write pages, the same
 * bytes {@link org.dizitart.cryptand.container.PageTree} writes, so a reader
 * cannot tell the two apart. {@code PageTree} holds a whole tree on the heap
 * and rebuilds it per commit; a graph of 10^6 nodes is ~200 MB of records, so
 * this one keeps only copied nodes in memory, writes them back at commit or
 * past {@link #DIRTY_BUDGET}, and frees each old page when it is copied
 * (reusable after the next commit, 01 §6). Pages are read lazily, each checked
 * against its parent's nonce once (14 §5.5).
 *
 * <p><em>ponytail: put and a whole-tree clear only; §6 keeps a deleted slot's
 * record, so nothing removes one key.</em>
 */
final class AdjacencyTree {

    /** Copied nodes held before an early write-back. */
    static int DIRTY_BUDGET = 2048;

    private static final class Node {
        final boolean leaf;
        /** Leaf: keys. Internal: separators, each the first key under its child. */
        final List<byte[]> key = new ArrayList<>();
        final List<byte[]> val = new ArrayList<>();
        final List<Long> child = new ArrayList<>();
        final List<Long> cnt = new ArrayList<>();
        final List<Long> nonce = new ArrayList<>();
        final List<Node> kid = new ArrayList<>();

        Node(boolean leaf) {
            this.leaf = leaf;
        }

        int n() {
            return key.size();
        }

        long total() {
            if (leaf) {
                return key.size();
            }
            long t = 0;
            for (long c : cnt) {
                t += c;
            }
            return t;
        }

        void addChild(int at, byte[] sep, long page, long count, long nc, Node k) {
            key.add(at, sep);
            child.add(at, page);
            cnt.add(at, count);
            nonce.add(at, nc);
            kid.add(at, k);
        }
    }

    private final Pager pager;
    private final int treeId;
    private Node root;
    private long rootPage;
    private long rootNonce;
    private long size;
    private int dirty;
    private boolean rewriteAll;
    private final Set<Long> verified = new HashSet<>();

    private AdjacencyTree(Pager pager, int treeId, long root, long rootNonce) {
        this.pager = pager;
        this.treeId = treeId;
        this.rootPage = root;
        this.rootNonce = rootNonce;
    }

    static AdjacencyTree load(Pager pager, int treeId, long root, long rootNonce) {
        AdjacencyTree t = new AdjacencyTree(pager, treeId, root, rootNonce);
        if (root != 0) {
            t.size = t.read(root, rootNonce).total();
        }
        return t;
    }

    long root() {
        return rootPage;
    }

    long rootNonce() {
        return rootNonce;
    }

    long size() {
        return size;
    }

    /** The next {@link #commit} rewrites every page (F-072: conversion in place). */
    void markDirty() {
        rewriteAll = true;
    }

    byte[] get(byte[] k) {
        Node node = root != null ? root : rootPage == 0 ? null : read(rootPage, rootNonce);
        for (int depth = 0; node != null; depth++) {
            if (depth > 64) {
                // F-113: child pointers come from the file; a cycle must not spin.
                throw new CorruptionException("adjacency tree " + treeId + " is deeper than 64 levels", rootPage, null);
            }
            int i = find(node, k);
            if (node.leaf) {
                return i >= 0 && BtreePage.memcmp(node.key.get(i), k) == 0 ? node.val.get(i) : null;
            }
            node = node.kid.get(i) != null ? node.kid.get(i) : read(node.child.get(i), node.nonce.get(i));
        }
        return null;
    }

    /** Leaf: the last key <= k (-1 if none). Internal: the child to descend, the first one for a key below all. */
    private static int find(Node node, byte[] k) {
        int lo = 0;
        int hi = node.n() - 1;
        int at = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (BtreePage.memcmp(node.key.get(mid), k) <= 0) {
                at = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return node.leaf ? at : Math.max(0, at);
    }

    void put(byte[] k, byte[] v) {
        if (root == null && rootPage != 0) {
            root = read(rootPage, rootNonce);
            free(rootPage);
            rootPage = 0;
            dirty++;
        }
        if (root == null) {
            root = new Node(true);
            dirty++;
        }
        Node split = put(root, k, v);
        if (split != null) {
            Node up = new Node(false);
            up.addChild(0, root.key.get(0), 0, root.total(), 0, root);
            up.addChild(1, split.key.get(0), 0, split.total(), 0, split);
            root = up;
            dirty++;
        }
        if (dirty > DIRTY_BUDGET) {
            writeOut();
        }
    }

    /** Returns the new right sibling when {@code node} split. */
    private Node put(Node node, byte[] k, byte[] v) {
        int i = find(node, k);
        if (node.leaf) {
            if (i >= 0 && BtreePage.memcmp(node.key.get(i), k) == 0) {
                node.val.set(i, v);
            } else {
                node.key.add(i + 1, k);
                node.val.add(i + 1, v);
                size++;
            }
        } else {
            Node c = child(node, i);
            Node s = put(c, k, v);
            node.key.set(i, c.key.get(0));
            node.cnt.set(i, c.total());
            if (s != null) {
                node.addChild(i + 1, s.key.get(0), 0, s.total(), 0, s);
            }
        }
        return fits(node) ? null : split(node);
    }

    private boolean fits(Node node) {
        return encode(node) != null;
    }

    /** Moves the upper half out; halves until the left part fits (records are small, so once). */
    private Node split(Node node) {
        if (node.n() < 2) {
            throw new LimitException("adjacency tree " + treeId + ": one record does not fit a "
                    + pager.pageSize() + "-byte page");
        }
        int at = node.n() / 2;
        Node right = new Node(node.leaf);
        right.key.addAll(node.key.subList(at, node.n()));
        node.key.subList(at, node.key.size()).clear();
        if (node.leaf) {
            right.val.addAll(node.val.subList(at, node.val.size()));
            node.val.subList(at, node.val.size()).clear();
        } else {
            right.child.addAll(node.child.subList(at, node.child.size()));
            right.cnt.addAll(node.cnt.subList(at, node.cnt.size()));
            right.nonce.addAll(node.nonce.subList(at, node.nonce.size()));
            right.kid.addAll(node.kid.subList(at, node.kid.size()));
            node.child.subList(at, node.child.size()).clear();
            node.cnt.subList(at, node.cnt.size()).clear();
            node.nonce.subList(at, node.nonce.size()).clear();
            node.kid.subList(at, node.kid.size()).clear();
        }
        dirty++;
        return right;
    }

    private Node child(Node node, int i) {
        if (node.kid.get(i) == null) {
            node.kid.set(i, read(node.child.get(i), node.nonce.get(i)));
            free(node.child.get(i));
            node.child.set(i, 0L);
            dirty++;
        }
        return node.kid.get(i);
    }

    /** Frees every page: the tree is empty after the next commit. */
    void clear() {
        if (root != null) {
            freeUnder(root);
        } else if (rootPage != 0) {
            free(rootPage);
            freeUnder(read(rootPage, rootNonce));
        }
        root = null;
        rootPage = 0;
        rootNonce = 0;
        size = 0;
        dirty = 0;
    }

    private void freeUnder(Node node) {
        if (node.leaf) {
            return;
        }
        for (int i = 0; i < node.n(); i++) {
            if (node.kid.get(i) != null) {
                freeUnder(node.kid.get(i));
            } else {
                Node c = read(node.child.get(i), node.nonce.get(i));
                free(node.child.get(i));
                freeUnder(c);
            }
        }
    }

    /** Writes the copied nodes back; returns the root page (0: empty). */
    long commit() {
        writeOut();
        if (rewriteAll) {
            rewriteAll = false;
            if (rootPage != 0) {
                long[] at = rewrite(rootPage, rootNonce);
                rootPage = at[0];
                rootNonce = at[1];
            }
        }
        return rootPage;
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

    private long[] rewrite(long page, long nc) {
        Node node = read(page, nc);
        free(page);
        if (!node.leaf) {
            for (int i = 0; i < node.n(); i++) {
                long[] at = rewrite(node.child.get(i), node.nonce.get(i));
                node.child.set(i, at[0]);
                node.nonce.set(i, at[1]);
            }
        }
        return writePage(node);
    }

    private long[] write(Node node) {
        if (!node.leaf) {
            for (int i = 0; i < node.n(); i++) {
                if (node.kid.get(i) != null) {
                    long[] at = write(node.kid.get(i));
                    node.child.set(i, at[0]);
                    node.nonce.set(i, at[1]);
                    node.kid.set(i, null);
                }
            }
        }
        return writePage(node);
    }

    private byte[] encode(Node node) {
        if (node.leaf) {
            List<BtreePage.Leaf> cells = new ArrayList<>(node.n());
            for (int i = 0; i < node.n(); i++) {
                cells.add(BtreePage.Leaf.inline(node.key.get(i), node.val.get(i)));
            }
            return BtreePage.encodeLeaves(cells, pager.payloadSize(), cells.size());
        }
        List<BtreePage.Internal> cells = new ArrayList<>(node.n());
        for (int i = 0; i < node.n(); i++) {
            cells.add(new BtreePage.Internal(node.key.get(i), node.child.get(i), node.cnt.get(i), node.nonce.get(i)));
        }
        return BtreePage.encodeInternalsCow(cells, pager.payloadSize());
    }

    /** {@code {pageId, nonce}}: the nonce is what the parent records (14 §5.5). */
    private long[] writePage(Node node) {
        byte[] payload = encode(node);
        long page = pager.allocate(1);
        PageHeader h = new PageHeader();
        h.pageType = node.leaf ? PageHeader.Type.BTREE_LEAF : PageHeader.Type.BTREE_INTERNAL;
        h.treeId = treeId;
        pager.writePage(page, h, payload);
        verified.add(page);
        return new long[]{page, h.nonce};
    }

    private void free(long page) {
        pager.freeExtent(page, 1);
        verified.remove(page);
    }

    private Node read(long page, long nc) {
        byte[] payload;
        if (verified.contains(page)) {
            payload = pager.readPage(page);
        } else {
            byte[] raw = pager.readRaw(page);
            PageHeader h = PageHeader.verify(raw, page);
            pager.checkNonce(page, h, nc);
            payload = pager.decodePayload(raw, h, page);
            verified.add(page);
        }
        BtreePage p = BtreePage.parse(payload, 0, payload.length);
        Node node = new Node(p.isLeaf());
        for (int i = 0; i < p.cellCount(); i++) {
            if (node.leaf) {
                BtreePage.Leaf c = p.leaf(i);
                if (c.kind() != BtreePage.Kind.INLINE) {
                    throw new CorruptionException("adjacency tree " + treeId
                            + " holds a non-inline value kind " + c.kind(), page, null);
                }
                node.key.add(c.key());
                node.val.add(c.value());
            } else {
                BtreePage.Internal c = p.internalCow(i);
                node.addChild(i, c.separator(), c.childPage(), c.childSubtreeEntries(), c.childNonce(), null);
            }
        }
        return node;
    }
}
