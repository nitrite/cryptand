package org.dizitart.cryptand.container;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The B+tree page framing of {@code spec/04-segments.md} §2.2 — identical for
 * leaf and internal pages, and identical inside an immutable segment and inside
 * a copy-on-write internal tree (§3.3).
 *
 * <p>Offsets here are relative to the <em>payload</em>, i.e. to the byte after
 * the 40-byte page header. The header is {@link PageHeader}'s business; this
 * class never sees it.
 *
 * <pre>
 *   0  u16 cell_count
 *   2  u16 free_start
 *   4  u16 prefix_len
 *   6  u16 flags            -- bit0 IS_LEAF
 *   8  u64 subtree_entries
 *  16  prefix_len bytes     -- common key prefix of the page
 *  ..  2 * cell_count       -- cell_ptr[], sorted by key
 *  ..  free gap
 *  ..  cells, growing downward from the payload end
 * </pre>
 *
 * <p>The keys a page holds are opaque byte strings, compared with
 * {@code memcmp}. In a segment they are the internal keys of §1
 * ({@code tree_id || CKE(key) || ~seq || op}); in an internal tree they are
 * plain {@code CKE(key)}. Nothing in the framing depends on which.
 */
public final class BtreePage {

    /** Fixed part of the payload header, before {@code prefix}. */
    public static final int HEADER = 16;

    public static final int FLAG_IS_LEAF = 0x01;

    /** Low nibble of a leaf cell's {@code kind_flags} — §2.2. */
    public static final class Kind {
        private Kind() {
        }

        public static final int INLINE = 0;
        public static final int OVERFLOW = 1;
        public static final int BLOB = 2;
        public static final int EMPTY = 3;
        public static final int VLOG = 4;

        /** A reader MUST reject a low nibble above this. */
        public static final int MAX = VLOG;
    }

    /** High nibble of {@code kind_flags}. Bit 4 is the only legal one. */
    public static final int HAS_EXPIRY = 0x10;

    /** {@code op}, the last byte of an internal key — §1. */
    public static final class Op {
        private Op() {
        }

        public static final int PUT = 0;
        public static final int DELETE = 1;
        /** Reserved; never written by this implementation. */
        public static final int MERGE = 2;
        public static final int RANGE_DELETE = 3;
    }

    /**
     * One leaf cell. {@code key} is the whole key, prefix included — the
     * page's prefix is a storage detail and callers never see a suffix.
     */
    public record Leaf(byte[] key, int kind, long expiryMs, boolean hasExpiry, byte[] value, long overflowPage) {

        public static Leaf inline(byte[] key, byte[] value) {
            return new Leaf(key, Kind.INLINE, 0, false, value, 0);
        }

        public static Leaf empty(byte[] key) {
            return new Leaf(key, Kind.EMPTY, 0, false, new byte[0], 0);
        }

        public static Leaf vlog(byte[] key, byte[] pointer16) {
            if (pointer16.length != 16) {
                throw new InvalidArgumentException("a VLOG pointer is 16 bytes, got " + pointer16.length);
            }
            return new Leaf(key, Kind.VLOG, 0, false, pointer16, 0);
        }

        public static Leaf blob(byte[] key, byte[] pointer16) {
            if (pointer16.length != 16) {
                throw new InvalidArgumentException("a BLOB pointer is 16 bytes, got " + pointer16.length);
            }
            return new Leaf(key, Kind.BLOB, 0, false, pointer16, 0);
        }

        public Leaf withExpiry(long ms) {
            return new Leaf(key, kind, ms, true, value, overflowPage);
        }

        int kindFlags() {
            return kind | (hasExpiry ? HAS_EXPIRY : 0);
        }
    }

    /** One internal cell: the least key reachable in {@code childPage}. */
    public record Internal(byte[] separator, long childPage, long childSubtreeEntries) {
    }

    // ==================================================================
    // decoding
    // ==================================================================

    private final byte[] payload;
    private final int base;
    private final int cellCount;
    private final boolean leaf;
    private final long subtreeEntries;
    private final byte[] prefix;
    private final int ptrOffset;
    private final int payloadLen;

    private BtreePage(byte[] payload, int base, int payloadLen, int cellCount, boolean leaf,
                      long subtreeEntries, byte[] prefix, int ptrOffset) {
        this.payload = payload;
        this.base = base;
        this.payloadLen = payloadLen;
        this.cellCount = cellCount;
        this.leaf = leaf;
        this.subtreeEntries = subtreeEntries;
        this.prefix = prefix;
        this.ptrOffset = ptrOffset;
    }

    /** Parses the payload framing. {@code base} is where the payload starts in {@code buf}. */
    public static BtreePage parse(byte[] buf, int base, int payloadLen) {
        if (payloadLen < HEADER) {
            throw new CorruptionException("btree page payload is " + payloadLen + " bytes, header needs " + HEADER);
        }
        ByteReader r = new ByteReader(buf, base, payloadLen);
        int cellCount = r.u16();
        int freeStart = r.u16();
        int prefixLen = r.u16();
        int flags = r.u16();
        long subtreeEntries = r.u64();
        if (HEADER + prefixLen + 2 * cellCount > payloadLen) {
            throw new CorruptionException("btree page: prefix " + prefixLen + " plus " + cellCount
                    + " cell pointers overflow a " + payloadLen + "-byte payload");
        }
        byte[] prefix = r.bytes(prefixLen);
        int ptrOffset = HEADER + prefixLen;
        if (freeStart != ptrOffset + 2 * cellCount) {
            throw new CorruptionException("btree page: free_start " + freeStart + " does not match "
                    + (ptrOffset + 2 * cellCount) + " implied by prefix_len and cell_count");
        }
        return new BtreePage(buf, base, payloadLen, cellCount, (flags & FLAG_IS_LEAF) != 0,
                subtreeEntries, prefix, ptrOffset);
    }

    public int cellCount() {
        return cellCount;
    }

    public boolean isLeaf() {
        return leaf;
    }

    public long subtreeEntries() {
        return subtreeEntries;
    }

    public byte[] prefix() {
        return prefix.clone();
    }

    private int cellOffset(int i) {
        if (i < 0 || i >= cellCount) {
            throw new IndexOutOfBoundsException("cell " + i + " of " + cellCount);
        }
        int p = base + ptrOffset + 2 * i;
        return (payload[p] & 0xFF) | ((payload[p + 1] & 0xFF) << 8);
    }

    /** The full key of cell {@code i}, prefix restored. */
    public byte[] key(int i) {
        ByteReader r = readerAt(i);
        int suffixLen = (int) r.uvar();
        byte[] suffix = r.bytes(suffixLen);
        byte[] k = new byte[prefix.length + suffixLen];
        System.arraycopy(prefix, 0, k, 0, prefix.length);
        System.arraycopy(suffix, 0, k, prefix.length, suffixLen);
        return k;
    }

    private ByteReader readerAt(int i) {
        int off = cellOffset(i);
        // Cells grow downward from the payload end, so every cell is bounded by
        // it; a per-cell length would be a second place to disagree.
        if (off < ptrOffset + 2 * cellCount || off > payloadLen) {
            throw new CorruptionException("btree cell pointer " + off + " is outside the cell area");
        }
        return new ByteReader(payload, base + off, payloadLen - off);
    }

    public Leaf leaf(int i) {
        if (!leaf) {
            throw new CorruptionException("leaf cell requested from an internal page");
        }
        ByteReader r = readerAt(i);
        int suffixLen = (int) r.uvar();
        byte[] suffix = r.bytes(suffixLen);
        byte[] key = concat(prefix, suffix);
        int kindFlags = r.u8();
        int kind = kindFlags & 0x0F;
        int high = kindFlags & 0xF0;
        if (kind > Kind.MAX) {
            throw new CorruptionException("leaf cell value_kind " + kind + " is above " + Kind.MAX);
        }
        if ((high & ~HAS_EXPIRY) != 0) {
            throw new CorruptionException(String.format(
                    "leaf cell kind_flags %02x sets a reserved high-nibble bit", kindFlags));
        }
        boolean hasExpiry = high == HAS_EXPIRY;
        long expiry = hasExpiry ? r.u64() : 0;
        byte[] value;
        long overflow = 0;
        switch (kind) {
            case Kind.INLINE -> {
                int n = (int) r.uvar();
                value = r.bytes(n);
            }
            case Kind.OVERFLOW -> {
                int n = (int) r.uvar();
                value = r.bytes(n);
                overflow = r.u64();
            }
            case Kind.VLOG, Kind.BLOB -> value = r.bytes(16);
            default -> value = new byte[0];
        }
        return new Leaf(key, kind, expiry, hasExpiry, value, overflow);
    }

    public Internal internal(int i) {
        if (leaf) {
            throw new CorruptionException("internal cell requested from a leaf page");
        }
        ByteReader r = readerAt(i);
        int suffixLen = (int) r.uvar();
        byte[] suffix = r.bytes(suffixLen);
        long child = r.u64();
        long entries = r.u64();
        return new Internal(concat(prefix, suffix), child, entries);
    }

    /**
     * Index of the first cell whose key is {@code >= target}, or
     * {@link #cellCount()} if there is none. Binary search over
     * {@code memcmp} order — no host comparator is consulted anywhere.
     */
    public int lowerBound(byte[] target) {
        int lo = 0;
        int hi = cellCount;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (memcmp(key(mid), target) < 0) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    /**
     * The child to descend into for {@code target}: cell {@code i} holds the
     * least key reachable in child {@code i}, so the right child is the last
     * one whose separator is {@code <= target}.
     */
    public int childIndexFor(byte[] target) {
        int lo = 0;
        int hi = cellCount;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (memcmp(internal(mid).separator(), target) <= 0) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return Math.max(0, lo - 1);
    }

    // ==================================================================
    // encoding
    // ==================================================================

    /**
     * Packs cells into one page payload, or returns {@code null} when they do
     * not fit. Callers size their pages by trying and backing off; there is no
     * split algorithm in this format, because segments are built bottom-up from
     * a sorted stream and internal trees are rebuilt by copy-on-write.
     */
    public static byte[] encodeLeaves(List<Leaf> cells, int payloadLen, long subtreeEntries) {
        List<byte[]> bodies = new ArrayList<>(cells.size());
        List<byte[]> keys = new ArrayList<>(cells.size());
        for (Leaf c : cells) {
            keys.add(c.key());
        }
        byte[] prefix = commonPrefix(keys);
        for (Leaf c : cells) {
            ByteWriter w = new ByteWriter(32);
            int suffixLen = c.key().length - prefix.length;
            w.uvar(suffixLen).bytes(c.key(), prefix.length, suffixLen);
            w.u8(c.kindFlags());
            if (c.hasExpiry()) {
                w.u64(c.expiryMs());
            }
            switch (c.kind()) {
                case Kind.INLINE -> w.uvar(c.value().length).bytes(c.value());
                case Kind.OVERFLOW -> {
                    w.uvar(c.value().length).bytes(c.value());
                    w.u64(c.overflowPage());
                }
                case Kind.VLOG, Kind.BLOB -> {
                    // No `value_len`: the only legal value would be 16, and a
                    // length field with one legal value is not information, it
                    // is a second place for two implementations to disagree.
                    w.bytes(c.value());
                }
                default -> {
                }
            }
            bodies.add(w.toBytes());
        }
        return pack(bodies, prefix, payloadLen, true, subtreeEntries);
    }

    public static byte[] encodeInternals(List<Internal> cells, int payloadLen) {
        List<byte[]> bodies = new ArrayList<>(cells.size());
        List<byte[]> keys = new ArrayList<>(cells.size());
        long entries = 0;
        for (Internal c : cells) {
            keys.add(c.separator());
            entries += c.childSubtreeEntries();
        }
        byte[] prefix = commonPrefix(keys);
        for (Internal c : cells) {
            ByteWriter w = new ByteWriter(32);
            int suffixLen = c.separator().length - prefix.length;
            w.uvar(suffixLen).bytes(c.separator(), prefix.length, suffixLen);
            w.u64(c.childPage()).u64(c.childSubtreeEntries());
            bodies.add(w.toBytes());
        }
        return pack(bodies, prefix, payloadLen, false, entries);
    }

    private static byte[] pack(List<byte[]> bodies, byte[] prefix, int payloadLen,
                               boolean isLeaf, long subtreeEntries) {
        int n = bodies.size();
        int total = 0;
        for (byte[] b : bodies) {
            total += b.length;
        }
        int freeStart = HEADER + prefix.length + 2 * n;
        if (freeStart + total > payloadLen) {
            return null;
        }
        byte[] out = new byte[payloadLen];
        ByteWriter w = new ByteWriter(freeStart);
        w.u16(n).u16(freeStart).u16(prefix.length).u16(isLeaf ? FLAG_IS_LEAF : 0);
        w.u64(subtreeEntries);
        w.bytes(prefix);
        byte[] head = w.toBytes();
        System.arraycopy(head, 0, out, 0, head.length);

        int top = payloadLen;
        for (int i = 0; i < n; i++) {
            byte[] body = bodies.get(i);
            top -= body.length;
            System.arraycopy(body, 0, out, top, body.length);
            int p = HEADER + prefix.length + 2 * i;
            out[p] = (byte) top;
            out[p + 1] = (byte) (top >>> 8);
        }
        return out;
    }

    /** Bytes a leaf cell occupies, its 2-byte pointer included, at a given prefix length. */
    public static int leafCellBytes(Leaf c, int prefixLen) {
        int suffixLen = c.key().length - prefixLen;
        int n = 2 + varLen(suffixLen) + suffixLen + 1;
        if (c.hasExpiry()) {
            n += 8;
        }
        switch (c.kind()) {
            case Kind.INLINE -> n += varLen(c.value().length) + c.value().length;
            case Kind.OVERFLOW -> n += varLen(c.value().length) + c.value().length + 8;
            case Kind.VLOG, Kind.BLOB -> n += 16;
            default -> {
            }
        }
        return n;
    }

    public static int internalCellBytes(Internal c, int prefixLen) {
        int suffixLen = c.separator().length - prefixLen;
        return 2 + varLen(suffixLen) + suffixLen + 16;
    }

    private static int varLen(long v) {
        int n = 1;
        while (Long.compareUnsigned(v, 0x80L) >= 0) {
            v >>>= 7;
            n++;
        }
        return n;
    }

    // ==================================================================
    // helpers
    // ==================================================================

    static byte[] commonPrefix(List<byte[]> keys) {
        if (keys.isEmpty()) {
            return new byte[0];
        }
        byte[] first = keys.get(0);
        int n = first.length;
        for (byte[] k : keys) {
            int i = 0;
            int max = Math.min(n, k.length);
            while (i < max && k[i] == first[i]) {
                i++;
            }
            n = i;
            if (n == 0) {
                break;
            }
        }
        // A prefix must not swallow a whole key: a zero-length suffix is legal,
        // but keeping the prefix strictly shorter than the shortest key costs
        // nothing and keeps `prefix_len` inside u16 on pathological inputs.
        return Arrays.copyOf(first, Math.min(n, 0xFFFF));
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Unsigned lexicographic byte comparison — the only order this format has. */
    public static int memcmp(byte[] a, byte[] b) {
        return Arrays.compareUnsigned(a, b);
    }
}
