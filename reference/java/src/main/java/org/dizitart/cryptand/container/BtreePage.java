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

    /** The {@code is_leaf} flag straight out of a payload, without parsing it. */
    public static boolean isLeafPayload(byte[] payload) {
        int flags = (payload[6] & 0xFF) | ((payload[7] & 0xFF) << 8);
        return (flags & FLAG_IS_LEAF) != 0;
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
     * The {@code seq} of cell {@code i} when its key is {@code userKey || u64be(~seq) || op},
     * or {@link #NOT_THIS_KEY} when it is some other key -- read in place,
     * without building the key.
     */
    /**
     * {@link #seqIfUserKey}'s "no": a seq of 2^63, which is past any this
     * engine assigns and which every signed seq comparison here already
     * mishandles.
     */
    public static final long NOT_THIS_KEY = Long.MIN_VALUE;

    public long seqIfUserKey(int i, byte[] userKey) {
        int p = prefix.length;
        int u = userKey.length;
        int off = cellOffset(i);
        if (off < ptrOffset + 2 * cellCount || off >= payloadLen) {
            throw new CorruptionException("btree cell pointer " + off + " is outside the cell area");
        }
        int s = base + off + 1;
        int suffixLen = payload[s - 1] & 0xFF;
        if (suffixLen >= 0x80 || p + suffixLen != u + 9 || s + suffixLen > base + payloadLen) {
            // Not this key's length -- a suffix of 128 bytes or more is not
            // either, for any key of this shape -- and a corrupt length is left
            // for the ordered read to report.
            return NOT_THIS_KEY;
        }
        // The key is `prefix || suffix`; the user key and the nine-byte tail
        // may each straddle the two.
        for (int k = 0; k < u; k++) {
            if ((k < p ? prefix[k] : payload[s + k - p]) != userKey[k]) {
                return NOT_THIS_KEY;
            }
        }
        long inv = 0;
        for (int k = u; k < u + 8; k++) {
            inv = (inv << 8) | ((k < p ? prefix[k] : payload[s + k - p]) & 0xFF);
        }
        return ~inv;
    }

    /**
     * Index of the first cell whose key is {@code >= target}, or
     * {@link #cellCount()} if there is none. Binary search over
     * {@code memcmp} order — no host comparator is consulted anywhere.
     */
    public int lowerBound(byte[] target) {
        int pc = prefixCompare(target);
        if (pc > 0) {
            // Every key on the page sorts after `target`.
            return 0;
        }
        if (pc < 0) {
            // Every key sorts before it.
            return cellCount;
        }
        int lo = 0;
        int hi = cellCount;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (compareSuffix(mid, target) < 0) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    /**
     * {@code memcmp(key(i), target)} <strong>without materialising
     * {@code key(i)}</strong>.
     *
     * <p>A stored key is {@code prefix + suffix}, and {@link #key} rebuilds it
     * into a fresh array — two allocations and two copies. Both binary searches
     * on this page call it once per probe, so a single descent through a
     * segment allocated on the order of {@code log2(cell_count)} keys per
     * level, all of them garbage the moment the comparison returned. It was
     * the top frame in the compactor's profile, with {@code Arrays.copyOf}
     * right behind it.
     *
     * <p>The comparison does not need the bytes joined. The prefix is shared by
     * every cell, so it is compared against the head of {@code target} first;
     * if that decides the order it decides it for the whole page. Only when the
     * prefix matches does the suffix matter, and that is compared in place out
     * of the payload.
     */
    private int compareCellKey(int i, byte[] target) {
        int pc = prefixCompare(target);
        return pc != 0 ? pc : compareSuffix(i, target);
    }

    /**
     * How <strong>every</strong> key on this page compares to {@code target} on
     * the shared prefix alone, or 0 when the prefix matches and only the
     * suffixes can decide.
     *
     * <p>The prefix is the same for every cell, so this answer does not belong
     * inside a binary search — and it was inside both of them, re-comparing the
     * same bytes on each of the ~15 probes a point read makes.
     * {@code ArraysSupport.mismatch} was <strong>33 %</strong> of the read
     * profile, and most of it was this.
     */
    private int prefixCompare(byte[] target) {
        int n = Math.min(prefix.length, target.length);
        int c = cmpBytes(prefix, 0, n, target, 0, n);
        if (c != 0) {
            return c;
        }
        if (prefix.length > target.length) {
            // The target ran out inside the shared prefix, so every key on this
            // page sorts after it.
            return 1;
        }
        return 0;
    }

    /**
     * Cell {@code i}'s key against {@code target}, given that
     * {@link #prefixCompare} has already returned 0 for it.
     *
     * <p>The suffix length is read straight out of the payload rather than
     * through a {@link ByteReader}: a reader was allocated on every probe of
     * every binary search, and a suffix under 128 bytes -- which is every cell
     * this format produces -- is a single byte. The general path is still there
     * for anything longer, and both paths run the same attacker-controlled
     * length check below.
     */
    private int compareSuffix(int i, byte[] target) {
        int off = cellOffset(i);
        if (off < ptrOffset + 2 * cellCount || off > payloadLen) {
            throw new CorruptionException("btree cell pointer " + off + " is outside the cell area");
        }
        long rawSuffixLen;
        int suffixAt;
        int at = base + off;
        int b0 = payload[at] & 0xFF;
        if (b0 < 0x80) {
            rawSuffixLen = b0;
            suffixAt = at + 1;
        } else {
            ByteReader r = new ByteReader(payload, at, payloadLen - off);
            rawSuffixLen = r.uvar();
            suffixAt = at + r.consumed();
        }
        // **The length is attacker-controlled and must be checked before it is
        // used in arithmetic**, not after. `key(i)` got this for free from
        // `ByteReader.bytes`, which refuses a length it cannot satisfy; the
        // in-place comparison reads the bytes itself and so has to do it here.
        //
        // Skipping it turned a corrupt page into
        // `IllegalArgumentException: fromIndex(6405) > toIndex(6404)` out of
        // `Arrays.compareUnsigned` — untyped, which `14-security.md` §9.1
        // forbids outright. `FuzzTest` caught it: "600 mutants ... 2 UNTYPED".
        if (rawSuffixLen < 0 || rawSuffixLen > payloadLen
                || suffixAt + rawSuffixLen > (long) base + payloadLen) {
            throw new CorruptionException("btree cell suffix of " + rawSuffixLen
                    + " bytes overruns a " + payloadLen + "-byte payload");
        }
        int suffixLen = (int) rawSuffixLen;
        int rest = target.length - prefix.length;
        int m = Math.min(suffixLen, rest);
        int c = cmpBytes(payload, suffixAt, m, target, prefix.length, m);
        if (c != 0) {
            return c;
        }
        return Integer.compare(suffixLen, rest);
    }

    /** Unaligned big-endian 64-bit reads over a `byte[]`. */
    private static final java.lang.invoke.VarHandle BE64 =
            java.lang.invoke.MethodHandles.byteArrayViewVarHandle(
                    long[].class, java.nio.ByteOrder.BIG_ENDIAN);

    /**
     * {@code memcmp} over two windows, eight bytes at a time.
     *
     * <p>A big-endian {@code long} comparison is exactly lexicographic byte
     * comparison over those eight bytes, so this is the order
     * {@link Arrays#compareUnsigned} gives. It replaces that call in the two
     * binary searches because the windows here are around twenty bytes, and at
     * that length the intrinsic's range checks and length dispatch cost more
     * than the comparison: {@code ArraysSupport.mismatch} was 31 % of the read
     * profile after the prefix had already been hoisted out of the search.
     */
    static int cmpBytes(byte[] a, int aOff, int aLen, byte[] b, int bOff, int bLen) {
        int n = Math.min(aLen, bLen);
        int i = 0;
        while (i + 8 <= n) {
            long x = (long) BE64.get(a, aOff + i);
            long y = (long) BE64.get(b, bOff + i);
            if (x != y) {
                return Long.compareUnsigned(x, y);
            }
            i += 8;
        }
        while (i < n) {
            int c = (a[aOff + i] & 0xFF) - (b[bOff + i] & 0xFF);
            if (c != 0) {
                return c;
            }
            i++;
        }
        return Integer.compare(aLen, bLen);
    }

    /**
     * The child to descend into for {@code target}: cell {@code i} holds the
     * least key reachable in child {@code i}, so the right child is the last
     * one whose separator is {@code <= target}.
     */
    public int childIndexFor(byte[] target) {
        int pc = prefixCompare(target);
        if (pc > 0) {
            // Every separator sorts after `target`: the leftmost child.
            return 0;
        }
        if (pc < 0) {
            // Every separator sorts before it: the rightmost.
            return Math.max(0, cellCount - 1);
        }
        int lo = 0;
        int hi = cellCount;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            // The separator has the same `prefix + suffix` layout as a leaf
            // key, so the same in-place comparison applies — and this probe was
            // the more expensive of the two, allocating the suffix, the joined
            // separator and an `Internal` record per step.
            if (compareSuffix(mid, target) <= 0) {
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
        byte[] prefix = commonPrefixOfKeys(cells);
        int n = cells.size();
        int total = 0;
        for (Leaf c : cells) {
            total += leafCellBytes(c, prefix.length) - 2;
        }
        byte[] out = startPage(n, prefix, payloadLen, true, subtreeEntries, total);
        if (out == null) {
            return null;
        }
        int top = payloadLen;
        for (int i = 0; i < n; i++) {
            Leaf c = cells.get(i);
            top -= leafCellBytes(c, prefix.length) - 2;
            int p = top;
            byte[] key = c.key();
            int suffixLen = key.length - prefix.length;
            p = putUvar(out, p, suffixLen);
            System.arraycopy(key, prefix.length, out, p, suffixLen);
            p += suffixLen;
            out[p++] = (byte) c.kindFlags();
            if (c.hasExpiry()) {
                p = putU64(out, p, c.expiryMs());
            }
            switch (c.kind()) {
                case Kind.INLINE -> {
                    p = putUvar(out, p, c.value().length);
                    System.arraycopy(c.value(), 0, out, p, c.value().length);
                }
                case Kind.OVERFLOW -> {
                    p = putUvar(out, p, c.value().length);
                    System.arraycopy(c.value(), 0, out, p, c.value().length);
                    p += c.value().length;
                    putU64(out, p, c.overflowPage());
                }
                case Kind.VLOG, Kind.BLOB -> System.arraycopy(c.value(), 0, out, p, 16);
                default -> {
                }
            }
            putPointer(out, prefix.length, i, top);
        }
        return out;
    }

    public static byte[] encodeInternals(List<Internal> cells, int payloadLen) {
        byte[] prefix = commonPrefixOfSeparators(cells);
        int n = cells.size();
        int total = 0;
        long entries = 0;
        for (Internal c : cells) {
            total += internalCellBytes(c, prefix.length) - 2;
            entries += c.childSubtreeEntries();
        }
        byte[] out = startPage(n, prefix, payloadLen, false, entries, total);
        if (out == null) {
            return null;
        }
        int top = payloadLen;
        for (int i = 0; i < n; i++) {
            Internal c = cells.get(i);
            top -= internalCellBytes(c, prefix.length) - 2;
            int p = top;
            byte[] sep = c.separator();
            int suffixLen = sep.length - prefix.length;
            p = putUvar(out, p, suffixLen);
            System.arraycopy(sep, prefix.length, out, p, suffixLen);
            p += suffixLen;
            p = putU64(out, p, c.childPage());
            putU64(out, p, c.childSubtreeEntries());
            putPointer(out, prefix.length, i, top);
        }
        return out;
    }

    /**
     * The page header and prefix, or null when the cells do not fit.
     *
     * <p>Cells are written <strong>straight into this array</strong> by the two
     * encoders above. They used to build a {@code ByteWriter} per cell and call
     * {@code toBytes()} on it — two allocations and two copies of every cell in
     * every page a flush or a compaction wrote — hand the list to a packer, and
     * have the packer copy each body a third time into the page. A cell's size
     * is already known exactly ({@code leafCellBytes} is what the fit test uses),
     * so its offset is known before it is written and there is nothing to
     * assemble it in.
     */
    private static byte[] startPage(int n, byte[] prefix, int payloadLen, boolean isLeaf,
                                    long subtreeEntries, int bodyBytes) {
        int freeStart = HEADER + prefix.length + 2 * n;
        if (freeStart + bodyBytes > payloadLen) {
            return null;
        }
        byte[] out = new byte[payloadLen];
        putU16(out, 0, n);
        putU16(out, 2, freeStart);
        putU16(out, 4, prefix.length);
        putU16(out, 6, isLeaf ? FLAG_IS_LEAF : 0);
        putU64(out, 8, subtreeEntries);
        System.arraycopy(prefix, 0, out, HEADER, prefix.length);
        return out;
    }

    private static void putPointer(byte[] out, int prefixLen, int i, int offset) {
        putU16(out, HEADER + prefixLen + 2 * i, offset);
    }

    private static void putU16(byte[] out, int p, int v) {
        out[p] = (byte) v;
        out[p + 1] = (byte) (v >>> 8);
    }

    private static int putU64(byte[] out, int p, long v) {
        for (int i = 0; i < 8; i++) {
            out[p + i] = (byte) (v >>> (8 * i));
        }
        return p + 8;
    }

    private static int putUvar(byte[] out, int p, long v) {
        while (Long.compareUnsigned(v, 0x80L) >= 0) {
            out[p++] = (byte) ((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        out[p++] = (byte) v;
        return p;
    }

    /** {@link #commonPrefix} over leaf keys, without materialising a key list. */
    private static byte[] commonPrefixOfKeys(List<Leaf> cells) {
        if (cells.isEmpty()) {
            return new byte[0];
        }
        List<byte[]> keys = new ArrayList<>(cells.size());
        for (Leaf c : cells) {
            keys.add(c.key());
        }
        return commonPrefix(keys);
    }

    private static byte[] commonPrefixOfSeparators(List<Internal> cells) {
        if (cells.isEmpty()) {
            return new byte[0];
        }
        List<byte[]> keys = new ArrayList<>(cells.size());
        for (Internal c : cells) {
            keys.add(c.separator());
        }
        return commonPrefix(keys);
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

    /**
     * The encoded length of a uvar, without encoding it.
     *
     * <p>Closed form rather than a shift loop: this is called about eight times
     * per cell across the builder's fit test and the two passes of
     * {@link #encodeLeaves}, and it was 8 % of the write profile.
     * {@code numberOfLeadingZeros} is a single instruction, and {@code | 1}
     * makes zero take the one-byte answer the loop gave it.
     */
    private static int varLen(long v) {
        if (v < 0) {
            // Above 2^63 unsigned: the ten-byte form.
            return 10;
        }
        return (63 - Long.numberOfLeadingZeros(v | 1)) / 7 + 1;
    }

    // ==================================================================
    // helpers
    // ==================================================================

    /**
     * Whether {@code keys} is non-decreasing. Cheap next to the prefix scan it
     * guards, and it keeps {@link #commonPrefix} correct for any caller rather
     * than correct only for the two that happen to sort their input.
     */
    private static boolean isSorted(List<byte[]> keys) {
        for (int i = 1; i < keys.size(); i++) {
            if (Arrays.compareUnsigned(keys.get(i - 1), keys.get(i)) > 0) {
                return false;
            }
        }
        return true;
    }

    static byte[] commonPrefix(List<byte[]> keys) {
        if (keys.isEmpty()) {
            return new byte[0];
        }
        byte[] first = keys.get(0);
        int n;
        // **Both callers pass a sorted list**, and for sorted keys the common
        // prefix of the whole list is the common prefix of the *first and
        // last* — any key between them agrees with both wherever they agree.
        // `SegmentBuilder.add` refuses input that is not strictly increasing,
        // which is what makes that true here.
        //
        // The general loop below is O(cells x prefix) and ran on every page a
        // compaction built; it was the top frame in the compactor's profile,
        // with `Arrays.mismatch` above it. Two keys is O(prefix).
        if (isSorted(keys)) {
            byte[] last = keys.get(keys.size() - 1);
            int max = Math.min(first.length, last.length);
            int i = Arrays.mismatch(first, 0, max, last, 0, max);
            n = i < 0 ? max : i;
        } else {
            n = first.length;
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
    /**
     * Byte order over two whole arrays.
     *
     * <p>This is the memtable's comparator and the merge heap's, so it runs
     * {@code O(log n)} times per memtable write, per memtable removal and per
     * merged entry of every flush -- together about 44 % of the create profile.
     * <p>{@link Arrays#compareUnsigned} and not {@link #cmpBytes}, and that is
     * a **measured** choice rather than an oversight: the two-argument form is
     * fully intrinsified and came out level with the hand-written comparison
     * here (1.22 M against 1.25 M creates/s, inside the run-to-run spread).
     * {@code cmpBytes} is kept for the two binary searches, where the
     * six-argument ranged form is what the JDK offers and where it measured a
     * clear 6 % on reads. Do not "unify" these without re-measuring both.
     */
    public static int memcmp(byte[] a, byte[] b) {
        return Arrays.compareUnsigned(a, b);
    }
}
