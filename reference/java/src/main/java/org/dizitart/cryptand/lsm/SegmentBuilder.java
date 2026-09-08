package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.key.Ikey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Bulk construction of a segment — {@code spec/04-segments.md} §2.3.
 *
 * <p>A segment is always built <strong>bottom-up from a sorted stream</strong>:
 * leaves are filled and emitted in order, internal pages are built from the
 * separators as leaves complete, and the extent is written with one sequential
 * write. There is therefore no insertion path into a segment, no split
 * algorithm, no rebalancing and no in-place page update anywhere in the format.
 *
 * <p>§5.2 makes interruptibility a MUST rather than a nicety: wherever the
 * database shares its execution context with a UI, a compaction that runs to
 * completion before yielding drops frames, and a dropped frame is visible in a
 * way a throughput difference is not. {@link #onStep} is called between two
 * output leaf pages — the only step boundary the format defines — once
 * {@code compaction_step_bytes} have accumulated. Because the output is built
 * bottom-up from a sorted stream, the partially built segment is just a prefix:
 * abandoning it costs the work done and nothing else, and no reader can see it.
 */
public final class SegmentBuilder {

    /** Called between output leaf pages, at most {@code stepBytes} apart. */
    public interface Step {
        void yieldNow();
    }

    private final Pager pager;
    private final SegmentMeta meta = new SegmentMeta();
    private final int payloadSize;

    private final List<byte[]> treePages = new ArrayList<>();
    private final List<BtreePage.Leaf> batch = new ArrayList<>();
    private final List<BtreePage.Internal> leafSeparators = new ArrayList<>();
    private final List<byte[]> distinctUserKeys = new ArrayList<>();
    private final Map<Integer, Long> treeSpan = new TreeMap<>();

    /** Running state for the fit test in {@link #add}. */
    private int batchPrefix;
    private int batchBytes;

    private byte[] lastKey;
    private byte[] lastUserKey;
    private byte[] firstKey;
    private long entryCount;
    private long tombstones;
    private long minSeq = Long.MAX_VALUE;
    private long maxSeq;
    private long minExpiry;
    private long valueBytes;
    private long vlogBytes;
    private int flags;

    private Step onStep;
    private long stepBytes = Long.MAX_VALUE;
    private long sinceStep;

    public SegmentBuilder(Pager pager, long segmentId, int level, int group, int filterBitsPerKey) {
        this.pager = pager;
        this.payloadSize = pager.payloadSize();
        meta.segmentId = segmentId;
        meta.level = level;
        meta.group = group;
        meta.filterBitsPerKey = filterBitsPerKey;
    }

    /** Sets the §5.2 step bound. Without one the builder runs to completion. */
    public SegmentBuilder yieldEvery(long bytes, Step step) {
        this.stepBytes = bytes;
        this.onStep = step;
        return this;
    }

    public long entryCount() {
        return entryCount;
    }

    /** Bytes of tree pages emitted so far — what a caller sizes an output segment by. */
    public long emittedBytes() {
        return (long) treePages.size() * pager.pageSize();
    }

    /**
     * Appends one entry. The stream MUST be strictly increasing in internal
     * key; a segment whose keys do not increase fails
     * {@code 01-container.md} §9 step 2, so the check is here rather than in a
     * verifier that runs later, if at all.
     */
    public void add(BtreePage.Leaf cell) {
        byte[] ik = cell.key();
        if (lastKey != null && BtreePage.memcmp(lastKey, ik) >= 0) {
            throw new InvalidArgumentException("segment input is not strictly increasing: "
                    + java.util.HexFormat.of().formatHex(lastKey) + " then "
                    + java.util.HexFormat.of().formatHex(ik));
        }
        lastKey = ik;
        if (firstKey == null) {
            firstKey = ik;
        }

        long seq = Ikey.seqOf(ik);
        int op = Ikey.opOf(ik);
        minSeq = Math.min(minSeq, seq);
        maxSeq = Math.max(maxSeq, seq);
        entryCount++;
        if (op == BtreePage.Op.DELETE || op == BtreePage.Op.RANGE_DELETE) {
            tombstones++;
        }
        if (op == BtreePage.Op.RANGE_DELETE) {
            flags |= SegmentMeta.HAS_RANGE_DELETES;
        }
        if (cell.hasExpiry()) {
            flags |= SegmentMeta.HAS_TTL;
            minExpiry = minExpiry == 0 ? cell.expiryMs() : Math.min(minExpiry, cell.expiryMs());
        }
        switch (cell.kind()) {
            case BtreePage.Kind.INLINE, BtreePage.Kind.OVERFLOW -> valueBytes += cell.value().length;
            case BtreePage.Kind.VLOG -> vlogBytes += VlogPointer.decode(cell.value()).len();
            default -> {
            }
        }
        treeSpan.merge(Ikey.treeIdOf(ik), 1L, Long::sum);

        byte[] uk = Ikey.userKeyOf(ik);
        if (lastUserKey == null || BtreePage.memcmp(lastUserKey, uk) != 0) {
            distinctUserKeys.add(uk);
            lastUserKey = uk;
        }

        // **Does it fit? — answered by arithmetic, not by encoding.**
        //
        // This used to append the cell and then call
        // `BtreePage.encodeLeaves(batch, ...)`, which re-encodes **every cell in
        // the page** to discover whether the newest one fits. Adding the k-th
        // cell encoded k cells, so filling a page of K cells cost K^2/2
        // cell-encodings against the K it needs — and then `emitLeaf` encoded
        // them once more. At a hundred-odd cells to a page that is a ~50x
        // multiplier, and it made `encodeLeaves` the single top frame in the
        // profile of *both* the compactor and the foreground.
        //
        // The packed size is computable directly:
        //
        //     HEADER + prefix_len + sum(leafCellBytes(cell, prefix_len))
        //
        // which is exactly `pack`'s `free_start + total`, because
        // `leafCellBytes` already counts each cell's two-byte pointer. The
        // prefix is the one moving part: keys arrive sorted, so it is the
        // common prefix of the batch's first key and its newest, and it only
        // ever shrinks. When it does, every earlier cell's suffix grows, and
        // the running total is recomputed in one pass — rare, and O(k) rather
        // than O(k) per add.
        int newPrefix = batchPrefixLen(cell.key());
        if (newPrefix != batchPrefix) {
            batchPrefix = newPrefix;
            batchBytes = 0;
            for (BtreePage.Leaf c : batch) {
                batchBytes += BtreePage.leafCellBytes(c, newPrefix);
            }
        }
        int cost = BtreePage.leafCellBytes(cell, newPrefix);
        if (BtreePage.HEADER + newPrefix + batchBytes + cost > payloadSize) {
            if (batch.isEmpty()) {
                throw new LimitException("a single segment entry of " + BtreePage.leafCellBytes(cell, 0)
                        + " bytes does not fit a " + pager.pageSize() + "-byte page");
            }
            emitLeaf();
            // A fresh page: the prefix is this cell's whole key.
            batchPrefix = batchPrefixLen(cell.key());
            batchBytes = 0;
            cost = BtreePage.leafCellBytes(cell, batchPrefix);
        }
        batch.add(cell);
        batchBytes += cost;
    }

    /**
     * The prefix length {@link BtreePage#commonPrefix} would return for the
     * batch once {@code newKey} joins it — the shared prefix of the batch's
     * first key and {@code newKey}, since the input is sorted, capped where
     * {@code prefix_len} stops fitting a u16.
     */
    private int batchPrefixLen(byte[] newKey) {
        if (batch.isEmpty()) {
            return Math.min(newKey.length, 0xFFFF);
        }
        byte[] first = batch.get(0).key();
        int max = Math.min(first.length, newKey.length);
        int i = java.util.Arrays.mismatch(first, 0, max, newKey, 0, max);
        return Math.min(i < 0 ? max : i, 0xFFFF);
    }

    private void emitLeaf() {
        byte[] payload = BtreePage.encodeLeaves(batch, payloadSize, batch.size());
        if (payload == null) {
            // The arithmetic above and `pack` disagreed, which they must not.
            // Failing loudly here beats writing a short page: a segment whose
            // last cell silently vanished passes every checksum.
            throw new IllegalStateException("leaf page overflowed after the fit test said it would not: "
                    + batch.size() + " cells, prefix " + batchPrefix + ", " + batchBytes + " body bytes");
        }
        long index = 1 + treePages.size();
        treePages.add(payload);
        leafSeparators.add(new BtreePage.Internal(batch.get(0).key(), index, batch.size()));
        batch.clear();
        batchPrefix = 0;
        batchBytes = 0;

        sinceStep += pager.pageSize();
        if (onStep != null && sinceStep >= stepBytes) {
            sinceStep = 0;
            onStep.yieldNow();
        }
    }

    /**
     * Finishes the segment, allocates its extent and writes it with one
     * sequential write. Returns the metadata, {@code startPage} and
     * {@code pages} filled in.
     */
    public SegmentMeta finish() {
        if (!batch.isEmpty()) {
            emitLeaf();
        }
        if (entryCount == 0) {
            throw new InvalidArgumentException("an empty segment is not a segment; nothing to publish");
        }

        // Internal pages, from the separators, as the level below completes.
        List<BtreePage.Internal> level = leafSeparators;
        while (level.size() > 1) {
            List<BtreePage.Internal> next = new ArrayList<>();
            List<BtreePage.Internal> group = new ArrayList<>();
            for (BtreePage.Internal c : level) {
                group.add(c);
                if (BtreePage.encodeInternals(group, payloadSize) == null) {
                    group.remove(group.size() - 1);
                    next.add(emitInternal(group));
                    group.clear();
                    group.add(c);
                }
            }
            if (!group.isEmpty()) {
                next.add(emitInternal(group));
            }
            level = next;
        }
        meta.rootPage = level.get(0).childPage();
        meta.entryCount = entryCount;
        meta.tombstoneCount = tombstones;
        meta.minSeq = minSeq == Long.MAX_VALUE ? 0 : minSeq;
        meta.maxSeq = maxSeq;
        meta.minExpiry = minExpiry;
        meta.valueBytes = valueBytes;
        meta.vlogBytes = vlogBytes;
        meta.treeSpan = new LinkedHashMap<>(treeSpan);
        if (treeSpan.size() == 1) {
            flags |= SegmentMeta.SINGLE_TREE;
        }
        meta.flags = flags;
        meta.minKey = firstKey;
        meta.maxKey = lastKey;

        // The filter, over distinct user keys only, so all versions of a key
        // share one entry.
        List<byte[]> filterPages = new ArrayList<>();
        if (meta.filterBitsPerKey > 0) {
            BlockedBloom f = BlockedBloom.build(distinctUserKeys, distinctUserKeys.size(), meta.filterBitsPerKey);
            byte[] encoded = f.encode();
            meta.filterPage = 1 + treePages.size();
            for (int off = 0; off < encoded.length; off += payloadSize) {
                filterPages.add(Arrays.copyOfRange(encoded, off, Math.min(encoded.length, off + payloadSize)));
            }
        }

        shortenBoundsToFit();

        int pages = 1 + treePages.size() + filterPages.size();
        long start = pager.allocate(pages);
        meta.startPage = start;
        meta.pages = pages;

        byte[] extent = new byte[pages * pager.pageSize()];
        PageHeader head = new PageHeader();
        head.pageType = PageHeader.Type.SEGMENT_HEADER;
        head.flags = PageHeader.Flags.EXTENT_HEAD;
        head.extentPages = pages;
        byte[] headPage = pager.buildExtentPage(start, head, meta.encodeHeadPayload());
        System.arraycopy(headPage, 0, extent, 0, headPage.length);

        int index = 1;
        for (byte[] payload : treePages) {
            PageHeader h = new PageHeader();
            BtreePage b = BtreePage.parse(payload, 0, payload.length);
            h.pageType = b.isLeaf() ? PageHeader.Type.BTREE_LEAF : PageHeader.Type.BTREE_INTERNAL;
            byte[] page = pager.buildExtentPage(start + index, h, payload);
            System.arraycopy(page, 0, extent, index * pager.pageSize(), page.length);
            index++;
        }
        for (byte[] payload : filterPages) {
            PageHeader h = new PageHeader();
            h.pageType = PageHeader.Type.SEGMENT_FILTER;
            byte[] page = pager.buildExtentPage(start + index, h, payload);
            System.arraycopy(page, 0, extent, index * pager.pageSize(), page.length);
            index++;
        }

        pager.writeAt(pager.offsetOf(start), extent);
        return meta;
    }

    private BtreePage.Internal emitInternal(List<BtreePage.Internal> cells) {
        byte[] payload = BtreePage.encodeInternals(cells, payloadSize);
        long index = 1 + treePages.size();
        treePages.add(payload);
        long entries = 0;
        for (BtreePage.Internal c : cells) {
            entries += c.childSubtreeEntries();
        }
        return new BtreePage.Internal(cells.get(0).separator(), index, entries);
    }

    /**
     * §2.1: the whole header MUST fit in the head page. With 4 KiB pages and
     * the key limit at a quarter page, two exact 1 KiB keys plus
     * {@code tree_span[]} can overflow it, so a writer MUST shorten the bounds.
     * Shortening only ever widens the range a pruner considers, so it costs a
     * candidate, never a correct answer.
     */
    private void shortenBoundsToFit() {
        int limit = payloadSize;
        while (meta.encodeHeadPayload().length > limit) {
            int shorter = Math.max(0, Math.max(meta.minKey.length, meta.maxKey.length) - 1);
            if (shorter == 0 && meta.minKey.length <= 1 && meta.maxKey.length <= 1) {
                throw new LimitException("segment header does not fit a " + pager.pageSize()
                        + "-byte page even with empty key bounds; split the segment");
            }
            meta.minKey = truncateDown(meta.minKey, Math.min(meta.minKey.length, shorter));
            meta.maxKey = extendUp(meta.maxKey, Math.min(meta.maxKey.length, shorter));
        }
    }

    /** A prefix of {@code k}, which is always {@code <= k}. */
    static byte[] truncateDown(byte[] k, int len) {
        return Arrays.copyOf(k, Math.min(len, k.length));
    }

    /**
     * The shortest string {@code >= k} of at most {@code len} bytes: take the
     * prefix, then increment its last byte below {@code 0xFF} and drop what
     * follows. If every byte of the prefix is {@code 0xFF}, {@code k} itself is
     * kept — there is no shorter upper bound.
     */
    static byte[] extendUp(byte[] k, int len) {
        if (len >= k.length) {
            return k;
        }
        for (int i = len - 1; i >= 0; i--) {
            if ((k[i] & 0xFF) != 0xFF) {
                byte[] out = Arrays.copyOf(k, i + 1);
                out[i] = (byte) ((k[i] & 0xFF) + 1);
                return out;
            }
        }
        return k;
    }
}
