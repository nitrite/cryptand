package org.dizitart.cryptand.container;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.LimitException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * One of the internal copy-on-write B+trees — {@code spec/04-segments.md} §3.3.
 *
 * <p>Trees 0–15 are plain copy-on-write B+trees rather than levelled segment
 * sets. They are small, hot and almost entirely cached; levelling them would
 * add indirection for nothing and would make the manifest need a manifest.
 * Their pages use the §2.2 format, and their keys are plain {@code CKE(key)}
 * with no {@code seq} and no {@code op}.
 *
 * <p><em>ponytail: the whole tree is held in memory and rebuilt bottom-up when
 * it is dirty, rather than copying just the root-to-leaf path.</em> Both
 * produce the identical on-disk format and both honour §3.3's publish and free
 * rules — a reader cannot tell them apart — but a rebuild is O(tree) per commit
 * instead of O(height). The ceiling is the number of live entries in one
 * internal tree; for the manifest that is the segment count and for tree 1 the
 * free-extent count. Switch to path-copying if either grows past what a commit
 * can afford to rewrite.
 */
public final class PageTree {

    private final Pager pager;
    private final int treeId;
    private final NavigableMap<byte[], byte[]> entries =
            new TreeMap<>(BtreePage::memcmp);
    private final List<Long> oldPages = new ArrayList<>();
    private long root;
    private boolean dirty;
    /**
     * Bumped by every content change, so a decoded view of this tree can tell
     * whether it is stale without rebuilding to find out.
     *
     * <p>{@code volatile} so a reader can check it without taking the lock that
     * guards {@code entries}. Reading the version is safe lock-free; *building*
     * from {@code entries} is not, and never happens without the lock.
     *
     * <p>{@code put} and {@code remove} are the only ways to change the
     * content, so bumping there is exhaustive — {@code load} starts a fresh
     * instance, which no cache can already hold a version of.
     */
    private volatile long version;

    private PageTree(Pager pager, int treeId, long root) {
        this.pager = pager;
        this.treeId = treeId;
        this.root = root;
    }

    /** Reads a whole tree. {@code root == 0} means the tree does not exist yet. */
    public static PageTree load(Pager pager, int treeId, long root) {
        PageTree t = new PageTree(pager, treeId, root);
        if (root != 0) {
            t.readInto(root);
        }
        return t;
    }

    private void readInto(long pageId) {
        oldPages.add(pageId);
        byte[] page = pager.readRaw(pageId);
        PageHeader h = PageHeader.verify(page, pageId);
        byte[] payload = pager.decodePayload(page, h, pageId);
        BtreePage p = BtreePage.parse(payload, 0, payload.length);
        if (p.isLeaf()) {
            for (int i = 0; i < p.cellCount(); i++) {
                BtreePage.Leaf c = p.leaf(i);
                if (c.kind() != BtreePage.Kind.INLINE) {
                    throw new CorruptionException("internal tree " + treeId
                            + " holds a non-inline value kind " + c.kind(), pageId, null);
                }
                entries.put(c.key(), c.value());
            }
        } else {
            for (int i = 0; i < p.cellCount(); i++) {
                readInto(p.internal(i).childPage());
            }
        }
    }

    public int treeId() {
        return treeId;
    }

    public long root() {
        return root;
    }

    public boolean isDirty() {
        return dirty;
    }

    public int size() {
        return entries.size();
    }

    public byte[] get(byte[] key) {
        return entries.get(key);
    }

    public boolean containsKey(byte[] key) {
        return entries.containsKey(key);
    }

    public void put(byte[] key, byte[] value) {
        byte[] old = entries.put(key.clone(), value.clone());
        if (old == null || !Arrays.equals(old, value)) {
            dirty = true;
            version++;
        }
    }

    public void remove(byte[] key) {
        if (entries.remove(key) != null) {
            dirty = true;
            version++;
        }
    }

    /** Changes on every {@link #put} or {@link #remove} that alters content. */
    public long version() {
        return version;
    }

    /** Every entry, in {@code memcmp} order. */
    public NavigableMap<byte[], byte[]> map() {
        return entries;
    }

    /** Entries whose key starts with {@code prefix}, in order. */
    public List<Map.Entry<byte[], byte[]>> withPrefix(byte[] prefix) {
        List<Map.Entry<byte[], byte[]>> out = new ArrayList<>();
        for (Map.Entry<byte[], byte[]> e : entries.tailMap(prefix, true).entrySet()) {
            if (!startsWith(e.getKey(), prefix)) {
                break;
            }
            out.add(e);
        }
        return out;
    }

    static boolean startsWith(byte[] k, byte[] prefix) {
        if (k.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (k[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Rebuilds the tree if it changed and returns the new root, freeing the old
     * pages at the committing {@code commit_id}. An unchanged tree keeps its
     * root and writes nothing.
     */
    public long commit() {
        if (!dirty) {
            return root;
        }
        releaseOldPages();
        root = entries.isEmpty() ? 0 : build(false);
        dirty = false;
        return root;
    }

    /**
     * Frees this tree's current pages at the committing {@code commit_id},
     * without rebuilding.
     *
     * <p>Split out for tree 1 alone: its own freed pages must be <em>in</em> the
     * content it is about to record, so the release has to happen before that
     * content is snapshotted.
     */
    public void releaseOldPages() {
        for (long p : oldPages) {
            pager.freeExtent(p, 1);
        }
        oldPages.clear();
        dirty = true;
    }

    /** Rewrites the tree at the next commit even if nothing in it changed. */
    public void markDirty() {
        dirty = true;
    }

    /** The pages the current generation occupies. */
    public List<Long> pages() {
        return List.copyOf(oldPages);
    }

    /** Rebuilds using only file-extending allocations — see {@link Pager#allocateFresh}. */
    public long commitFresh() {
        root = entries.isEmpty() ? 0 : build(true);
        dirty = false;
        return root;
    }

    /** Pages {@link #commitInto} will write, counted without writing them. */
    public int pagesNeeded() {
        if (entries.isEmpty()) {
            return 0;
        }
        counting = true;
        counted = 0;
        try {
            build(true);
        } finally {
            counting = false;
        }
        return counted;
    }

    /**
     * Rebuilds into the pages from {@code start} on, which the caller has
     * already taken off the free list ({@link #pagesNeeded} of them) - F-080:
     * tree 1 written fresh every commit grows the file by its own size each
     * time, and it grows with the fragments that growth leaves behind.
     */
    public long commitInto(long start) {
        next = start;
        try {
            root = entries.isEmpty() ? 0 : build(true);
        } finally {
            next = -1;
        }
        dirty = false;
        return root;
    }

    private long next = -1;
    private boolean counting;
    private int counted;

    private long place(boolean fresh) {
        if (next >= 0) {
            return next++;
        }
        return fresh ? pager.allocateFresh(1) : pager.allocate(1);
    }

    private long build(boolean fresh) {
        int payloadSize = pager.payloadSize();

        // Leaves, filled and emitted in order.
        List<BtreePage.Internal> level = new ArrayList<>();
        List<BtreePage.Leaf> batch = new ArrayList<>();
        for (Map.Entry<byte[], byte[]> e : entries.entrySet()) {
            BtreePage.Leaf cell = BtreePage.Leaf.inline(e.getKey(), e.getValue());
            batch.add(cell);
            byte[] packed = BtreePage.encodeLeaves(batch, payloadSize, batch.size());
            if (packed == null) {
                batch.remove(batch.size() - 1);
                if (batch.isEmpty()) {
                    throw new LimitException("internal tree " + treeId + ": a single entry of "
                            + (e.getKey().length + e.getValue().length)
                            + " bytes does not fit a " + pager.pageSize() + "-byte page");
                }
                level.add(emitLeaf(batch, fresh));
                batch.clear();
                batch.add(cell);
            }
        }
        if (!batch.isEmpty()) {
            level.add(emitLeaf(batch, fresh));
        }

        // Internal pages, built from the separators as the level below completes.
        while (level.size() > 1) {
            List<BtreePage.Internal> next = new ArrayList<>();
            List<BtreePage.Internal> group = new ArrayList<>();
            for (BtreePage.Internal c : level) {
                group.add(c);
                if (BtreePage.encodeInternals(group, payloadSize) == null) {
                    group.remove(group.size() - 1);
                    next.add(emitInternal(group, fresh));
                    group.clear();
                    group.add(c);
                }
            }
            if (!group.isEmpty()) {
                next.add(emitInternal(group, fresh));
            }
            level = next;
        }
        return level.get(0).childPage();
    }

    private BtreePage.Internal emitLeaf(List<BtreePage.Leaf> cells, boolean fresh) {
        byte[] payload = BtreePage.encodeLeaves(cells, pager.payloadSize(), cells.size());
        if (counting) {
            counted++;
            return new BtreePage.Internal(cells.get(0).key(), 0, cells.size());
        }
        long page = place(fresh);
        // Remembered so the NEXT commit frees it. Without this the tree's
        // current generation is invisible to `releaseOldPages`, and every
        // generation but the first leaks - a page neither reachable nor free,
        // which 01 §9 step 7 reports and 13 §3 has to repair.
        oldPages.add(page);
        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.BTREE_LEAF;
        h.treeId = treeId;
        pager.writePage(page, h, payload);
        return new BtreePage.Internal(cells.get(0).key(), page, cells.size());
    }

    private BtreePage.Internal emitInternal(List<BtreePage.Internal> cells, boolean fresh) {
        byte[] payload = BtreePage.encodeInternals(cells, pager.payloadSize());
        if (counting) {
            counted++;
            return new BtreePage.Internal(cells.get(0).separator(), 0, 0);
        }
        long page = place(fresh);
        oldPages.add(page);
        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.BTREE_INTERNAL;
        h.treeId = treeId;
        pager.writePage(page, h, payload);
        long entryCount = 0;
        for (BtreePage.Internal c : cells) {
            entryCount += c.childSubtreeEntries();
        }
        return new BtreePage.Internal(cells.get(0).separator(), page, entryCount);
    }
}
