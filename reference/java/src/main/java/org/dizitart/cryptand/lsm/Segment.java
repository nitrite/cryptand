package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

import java.util.ArrayList;
import java.util.List;

/**
 * An immutable, sorted, page-indexed B+tree over a contiguous range of internal
 * keys — {@code spec/04-segments.md} §2.
 *
 * <p>Written once as one extent and never modified. Immutability is what makes
 * concurrency tractable: a reader holding a segment never coordinates with a
 * writer, a compaction never blocks a read, and there is no page-level locking
 * anywhere in the format.
 *
 * <pre>
 *   page 0        SEGMENT_HEADER
 *   pages 1..a    B+tree leaves and internal pages
 *   pages a+1..b  filter pages
 * </pre>
 */
public final class Segment {

    private final Pager pager;
    private final long startPage;
    private final SegmentMeta meta;
    private BlockedBloom filter;
    private boolean filterLoaded;

    private Segment(Pager pager, long startPage, SegmentMeta meta) {
        this.pager = pager;
        this.startPage = startPage;
        this.meta = meta;
    }

    public static Segment open(Pager pager, long startPage) {
        byte[] payload = pager.readPage(startPage);
        SegmentMeta m = SegmentMeta.decodeHeadPayload(payload);
        m.startPage = startPage;
        PageHeader h = pager.readHeader(startPage);
        if (h.pageType != PageHeader.Type.SEGMENT_HEADER) {
            throw new CorruptionException("page " + startPage + " has type " + h.pageType
                    + ", expected SEGMENT_HEADER", startPage, null);
        }
        m.pages = h.extentPages;
        return new Segment(pager, startPage, m);
    }

    public SegmentMeta meta() {
        return meta;
    }

    public long startPage() {
        return startPage;
    }

    private long absolute(long relative) {
        if (relative < 0 || relative >= meta.pages) {
            throw new CorruptionException("segment page " + relative + " is outside a "
                    + meta.pages + "-page extent", startPage, null);
        }
        return startPage + relative;
    }

    /**
     * The membership filter, demand-loaded.
     *
     * <p>{@code filter_page = 0} means no filter, and a reader MUST then treat
     * every probe as a hit — never as a miss, which would lose keys.
     */
    public BlockedBloom filter() {
        if (!filterLoaded) {
            filterLoaded = true;
            if (meta.filterPage != 0) {
                filter = readFilter();
            }
        }
        return filter;
    }

    private BlockedBloom readFilter() {
        long first = absolute(meta.filterPage);
        byte[] head = pager.readPage(first);
        ByteReader r = new ByteReader(head);
        r.u32();
        int blockCount = r.u32();
        long needed = BlockedBloom.HEADER_BYTES + (long) blockCount * BlockedBloom.BLOCK_BYTES;
        if (needed <= head.length) {
            return BlockedBloom.decode(head);
        }
        // The blocks span pages of the extent (§2.4). Each filter page carries
        // its own 40-byte header: 01 §3's exception is for value-log, blob and
        // vector extents, and does not name filter pages.
        ByteWriter w = new ByteWriter((int) needed);
        w.bytes(head);
        long page = first + 1;
        while (w.length() < needed) {
            byte[] more = pager.readPage(page++);
            w.bytes(more, 0, (int) Math.min(more.length, needed - w.length()));
        }
        return BlockedBloom.decode(w.toBytes());
    }

    /** Whether this segment may hold {@code userKey}; a segment with no filter always may. */
    public boolean mayContain(byte[] userKey) {
        BlockedBloom f = filter();
        return f == null || f.mayContain(userKey);
    }

    public Cursor cursor() {
        return new Cursor();
    }

    private List<RangeDelete> rangeDeletes;

    /**
     * The segment's range deletes, computed once and held in memory —
     * {@code spec/04-segments.md} §4's "per-segment range-delete summary
     * alongside the manifest entry".
     *
     * <p>It exists because a segment that may hold a covering range delete MUST
     * NOT be pruned by its filter: the filter contains the segment's
     * <em>point</em> keys, a {@code RANGE_DELETE} covers keys that are not in
     * it, and filtering such a segment out resurrects a deleted key.
     * {@code flags.HAS_RANGE_DELETES} is what keeps that test free — a segment
     * without the flag never reaches this method at all, and range deletes are
     * rare, so the summary is normally empty.
     */
    public List<RangeDelete> rangeDeletes() {
        if (rangeDeletes == null) {
            List<RangeDelete> out = new ArrayList<>();
            if (meta.hasRangeDeletes()) {
                Cursor c = cursor();
                c.seekFirst();
                while (c.isValid()) {
                    if (Ikey.opOf(c.key()) == BtreePage.Op.RANGE_DELETE) {
                        out.add(RangeDelete.fromCell(c.entry()));
                    }
                    if (!c.next()) {
                        break;
                    }
                }
            }
            rangeDeletes = List.copyOf(out);
        }
        return rangeDeletes;
    }

    /**
     * A path stack from the segment's root — {@code spec/04-segments.md} §8.
     *
     * <p>There are no sibling pointers in the format, so iteration is a stack
     * walk. {@code skip(n)} costs O(height) rather than O(n) because every
     * internal cell carries {@code child_subtree_entries}.
     */
    public final class Cursor {

        // A primitive stack, not `List<Long>`/`List<Integer>`. A point read
        // opens a cursor, and the boxed pair meant two lists, their backing
        // arrays and a `Long` and an `Integer` per level, all garbage the
        // moment the read returned. Depth is bounded by the tree's height;
        // 16 levels of a B+tree over 8 KiB pages is far past any real file, and
        // the stack grows if one ever gets there.
        private long[] pages = new long[16];
        private int[] cells = new int[16];
        private int depth;
        private BtreePage leafPage;
        private boolean valid;

        private void push(long page, int cell) {
            if (depth == pages.length) {
                pages = java.util.Arrays.copyOf(pages, depth * 2);
                cells = java.util.Arrays.copyOf(cells, depth * 2);
            }
            pages[depth] = page;
            cells[depth] = cell;
            depth++;
        }

        private BtreePage page(long absolutePage) {
            // Shared and parsed once — see `Pager.readTreePage`. A segment is
            // written once and never edited, so the page a descent reads is the
            // page that was built.
            return pager.readTreePage(absolutePage);
        }

        public boolean isValid() {
            return valid;
        }

        public void seekFirst() {
            depth = 0;
            descendFrom(absolute(meta.rootPage), true);
        }

        public void seekLast() {
            depth = 0;
            descendFrom(absolute(meta.rootPage), false);
        }

        /** Positions on the first entry with an internal key {@code >= target}. */
        public void seek(byte[] target) {
            depth = 0;
            long p = absolute(meta.rootPage);
            while (true) {
                BtreePage b = page(p);
                if (b.cellCount() == 0) {
                    valid = false;
                    return;
                }
                if (b.isLeaf()) {
                    int i = b.lowerBound(target);
                    push(p, i);
                    leafPage = b;
                    if (i >= b.cellCount()) {
                        valid = true;
                        // Past the end of this leaf: step forward, which either
                        // lands on the next leaf or exhausts the cursor.
                        advance();
                        return;
                    }
                    valid = true;
                    return;
                }
                int i = b.childIndexFor(target);
                push(p, i);
                p = absolute(b.internal(i).childPage());
            }
        }

        public byte[] key() {
            require();
            return leafPage.key(cells[depth - 1]);
        }

        public BtreePage.Leaf entry() {
            require();
            return leafPage.leaf(cells[depth - 1]);
        }

        private void require() {
            if (!valid) {
                throw new IllegalStateException("cursor is not positioned on an entry");
            }
        }

        public boolean next() {
            if (!valid) {
                return false;
            }
            cells[depth - 1]++;
            return advance();
        }

        /** Repairs the stack after the leaf index ran past the end of its page. */
        private boolean advance() {
            if (cells[depth - 1] < leafPage.cellCount()) {
                return true;
            }
            for (int d = depth - 2; d >= 0; d--) {
                BtreePage b = page(pages[d]);
                int i = cells[d] + 1;
                if (i < b.cellCount()) {
                    cells[d] = i;
                    depth = d + 1;
                    descendFrom(absolute(b.internal(i).childPage()), true);
                    return valid;
                }
            }
            valid = false;
            return false;
        }

        public boolean prev() {
            if (!valid) {
                return false;
            }
            if (cells[depth - 1] > 0) {
                cells[depth - 1]--;
                return true;
            }
            for (int d = depth - 2; d >= 0; d--) {
                BtreePage b = page(pages[d]);
                int i = cells[d] - 1;
                if (i >= 0) {
                    cells[d] = i;
                    depth = d + 1;
                    descendFrom(absolute(b.internal(i).childPage()), false);
                    return valid;
                }
            }
            valid = false;
            return false;
        }

        private void descendFrom(long p, boolean leftmost) {
            while (true) {
                BtreePage b = page(p);
                if (b.cellCount() == 0) {
                    valid = false;
                    return;
                }
                int i = leftmost ? 0 : b.cellCount() - 1;
                push(p, i);
                if (b.isLeaf()) {
                    leafPage = b;
                    valid = true;
                    return;
                }
                p = absolute(b.internal(i).childPage());
            }
        }

        /**
         * Advances {@code n} entries in O(height) using {@code subtree_entries}
         * rather than O(n) steps — §8's one non-amortized-O(1) requirement, and
         * the reason that field MUST be accurate.
         */
        public boolean skip(long n) {
            if (n < 0) {
                throw new InvalidArgumentException("skip takes a non-negative count, got " + n);
            }
            long remaining = n;
            while (remaining > 0 && valid) {
                int last = depth - 1;
                long within = leafPage.cellCount() - cells[last];
                if (remaining < within) {
                    cells[last] = (int) (cells[last] + remaining);
                    return true;
                }
                remaining -= within;
                cells[last] = leafPage.cellCount();
                if (!advance()) {
                    return false;
                }
                // advance() lands on the first cell of the next leaf, which
                // consumed nothing; the loop re-measures from there.
            }
            return valid;
        }
    }

    /** Every entry of the segment, in internal-key order. Used by compaction and by the verifier. */
    public List<BtreePage.Leaf> readAll() {
        List<BtreePage.Leaf> out = new ArrayList<>();
        Cursor c = cursor();
        c.seekFirst();
        while (c.isValid()) {
            out.add(c.entry());
            if (!c.next()) {
                break;
            }
        }
        return out;
    }
}
