package org.dizitart.cryptand;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A segment's identity and bounds — the head page of
 * {@code spec/04-segments.md} §2.1, which is also every field the manifest
 * entry of §3.2 carries.
 *
 * <p>The duplication is deliberate and is stated in §2.1: {@code group} and
 * everything else live in the head page too, so that
 * {@code 13-operations.md} §3 can rebuild a lost manifest entirely from segment
 * headers.
 *
 * <p><strong>{@code minKey} and {@code maxKey} are bounds, not necessarily the
 * exact extreme keys.</strong> A writer MUST satisfy
 * {@code minKey <= every internal key <= maxKey} and SHOULD make them exact,
 * but MAY shorten them so the whole header fits in the head page — with two
 * exact 1 KiB keys and a long {@code tree_span[]} it otherwise would not.
 * Shortened bounds only ever widen the range a pruner considers, so they cost a
 * candidate, never a correct answer.
 */
public final class SegmentMeta {

    /** {@code "CRY_SEG"} + {@code 0x1A}. */
    public static final byte[] MAGIC = {0x43, 0x52, 0x59, 0x5F, 0x53, 0x45, 0x47, 0x1A};

    public static final int HAS_RANGE_DELETES = 0x01;
    public static final int SINGLE_TREE = 0x02;
    public static final int HAS_TTL = 0x04;

    public long segmentId;
    public int level;
    public int flags;
    public int filterBitsPerKey;
    /** Page index of the B+tree root, relative to the extent start. */
    public long rootPage;
    public long entryCount;
    public long tombstoneCount;
    public long minSeq;
    public long maxSeq;
    /** Page index of the filter, relative to the extent start; 0 if none. */
    public long filterPage;
    public long valueBytes;
    public long vlogBytes;
    public long minExpiry;
    /** Range-partition group within a tiered level; always 0 at L0 and at the last level. */
    public int group;
    public byte[] minKey = new byte[0];
    public byte[] maxKey = new byte[0];
    /** {@code tree_id -> entry_count}, in ascending tree id. */
    public Map<Integer, Long> treeSpan = new LinkedHashMap<>();

    // --- manifest-side, not in the head page's field table but implied by it ---
    public long startPage;
    public int pages;

    public boolean hasRangeDeletes() {
        return (flags & HAS_RANGE_DELETES) != 0;
    }

    public boolean hasTtl() {
        return (flags & HAS_TTL) != 0;
    }

    /** Whether this segment's key range can contain {@code userKeyPrefix} — the no-I/O prune of §4. */
    public boolean covers(byte[] internalKey) {
        return BtreePage.memcmp(minKey, internalKey) <= 0 && BtreePage.memcmp(internalKey, maxKey) <= 0;
    }

    /** Whether the user-key ranges of two segments overlap — §3.1.1's test, on user keys. */
    public static boolean userRangesOverlap(SegmentMeta a, SegmentMeta b) {
        byte[] aLo = Ikey.userKeyOf(a.minKey);
        byte[] aHi = Ikey.userKeyOf(a.maxKey);
        byte[] bLo = Ikey.userKeyOf(b.minKey);
        byte[] bHi = Ikey.userKeyOf(b.maxKey);
        return BtreePage.memcmp(aLo, bHi) <= 0 && BtreePage.memcmp(bLo, aHi) <= 0;
    }

    // ==================================================================
    // the head page
    // ==================================================================

    /** The head-page payload, after the 40-byte page header. */
    public byte[] encodeHeadPayload() {
        ByteWriter w = new ByteWriter(256);
        w.bytes(MAGIC);
        w.u64(segmentId);
        w.u8(level).u8(flags).u16(filterBitsPerKey);
        w.u32(treeSpan.size());
        w.u64(rootPage).u64(entryCount).u64(tombstoneCount);
        w.u64(minSeq).u64(maxSeq).u64(filterPage);
        w.u64(valueBytes).u64(vlogBytes).u64(minExpiry);
        w.u8(group);
        for (int i = 0; i < 7; i++) {
            w.u8(0);
        }
        w.u32(minKey.length).u32(maxKey.length);
        if (w.length() != 112) {
            throw new IllegalStateException("segment header prefix is " + w.length() + " bytes, expected 112");
        }
        w.bytes(minKey).bytes(maxKey);
        for (Map.Entry<Integer, Long> e : treeSpan.entrySet()) {
            w.u32(e.getKey()).u64(e.getValue());
        }
        return w.toBytes();
    }

    public static SegmentMeta decodeHeadPayload(byte[] payload) {
        ByteReader r = new ByteReader(payload);
        byte[] magic = r.bytes(8);
        if (!java.util.Arrays.equals(magic, MAGIC)) {
            throw new CorruptionException("segment head magic is "
                    + java.util.HexFormat.of().formatHex(magic) + ", expected 435259 5f5345471a");
        }
        SegmentMeta m = new SegmentMeta();
        m.segmentId = r.u64();
        m.level = r.u8();
        m.flags = r.u8();
        m.filterBitsPerKey = r.u16();
        int treeCount = r.u32();
        m.rootPage = r.u64();
        m.entryCount = r.u64();
        m.tombstoneCount = r.u64();
        m.minSeq = r.u64();
        m.maxSeq = r.u64();
        m.filterPage = r.u64();
        m.valueBytes = r.u64();
        m.vlogBytes = r.u64();
        m.minExpiry = r.u64();
        m.group = r.u8();
        r.skip(7);
        int minLen = r.u32();
        int maxLen = r.u32();
        if (minLen < 0 || maxLen < 0 || minLen > r.remaining() || maxLen > r.remaining() - minLen) {
            throw new LimitException("segment head declares key bounds of " + minLen + " and " + maxLen
                    + " bytes, but only " + r.remaining() + " remain in the page");
        }
        m.minKey = r.bytes(minLen);
        m.maxKey = r.bytes(maxLen);
        if (treeCount < 0 || (long) treeCount * 12 > r.remaining()) {
            throw new LimitException("segment head declares " + Integer.toUnsignedString(treeCount)
                    + " trees, which does not fit the page");
        }
        for (int i = 0; i < treeCount; i++) {
            int treeId = r.u32();
            m.treeSpan.put(treeId, r.u64());
        }
        return m;
    }

    // ==================================================================
    // the manifest entry
    // ==================================================================

    /** {@code CKE(Array[ U8 level, U8 group, BYTES min_internal_key ])} — §3.2. */
    public byte[] manifestKey() {
        return manifestKey(level, group, minKey);
    }

    public static byte[] manifestKey(int level, int group, byte[] minInternalKey) {
        List<Value> parts = new ArrayList<>(3);
        parts.add(Value.integer(NumType.U8, level));
        parts.add(Value.integer(NumType.U8, group));
        parts.add(new Value.Bytes(minInternalKey));
        return Cke.encode(new Value.Array(parts));
    }

    public Value manifestValue() {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("segment_id", Value.integer(NumType.U64, segmentId));
        f.put("start_page", Value.integer(NumType.U64, startPage));
        f.put("pages", Value.integer(NumType.U32, pages));
        f.put("root", Value.integer(NumType.U64, rootPage));
        f.put("filter", Value.integer(NumType.U64, filterPage));
        f.put("min_seq", Value.integer(NumType.U64, minSeq));
        f.put("max_seq", Value.integer(NumType.U64, maxSeq));
        f.put("entries", Value.integer(NumType.U64, entryCount));
        f.put("tombstones", Value.integer(NumType.U64, tombstoneCount));
        f.put("min_expiry", Value.integer(NumType.U64, minExpiry));
        f.put("min_key", new Value.Bytes(minKey));
        f.put("max_key", new Value.Bytes(maxKey));
        f.put("value_bytes", Value.integer(NumType.U64, valueBytes));
        f.put("vlog_bytes", Value.integer(NumType.U64, vlogBytes));
        List<Value> trees = new ArrayList<>();
        for (int id : treeSpan.keySet()) {
            trees.add(Value.integer(NumType.U32, id));
        }
        f.put("trees", new Value.Array(trees));
        // Not in §3.2's table, and written anyway. §4 requires that a segment
        // which may hold a covering range delete escape filter pruning, and
        // says an implementation SHOULD keep that summary "in memory alongside
        // the manifest entry" - this is the one bit of it that has to survive a
        // reopen without touching the head page. The Rust and Dart references
        // both write it and Dart requires it, so a manifest without it is one
        // they cannot read: an extension all three now share.
        f.put("range_deletes", new Value.Bool(hasRangeDeletes()));
        return Value.Doc.of(f);
    }

    public static SegmentMeta fromManifest(byte[] key, Value value) {
        Value.Array k = (Value.Array) Cke.decode(key);
        SegmentMeta m = new SegmentMeta();
        m.level = (int) longOf(k.items().get(0));
        m.group = (int) longOf(k.items().get(1));
        Value.Doc d = (Value.Doc) value;
        m.segmentId = longOf(d.field("segment_id"));
        m.startPage = longOf(d.field("start_page"));
        m.pages = (int) longOf(d.field("pages"));
        m.rootPage = longOf(d.field("root"));
        m.filterPage = longOf(d.field("filter"));
        m.minSeq = longOf(d.field("min_seq"));
        m.maxSeq = longOf(d.field("max_seq"));
        m.entryCount = longOf(d.field("entries"));
        m.tombstoneCount = longOf(d.field("tombstones"));
        m.minExpiry = longOf(d.field("min_expiry"));
        m.minKey = ((Value.Bytes) d.field("min_key")).value();
        m.maxKey = ((Value.Bytes) d.field("max_key")).value();
        m.valueBytes = longOf(d.field("value_bytes"));
        m.vlogBytes = longOf(d.field("vlog_bytes"));
        for (Value v : ((Value.Array) d.field("trees")).items()) {
            m.treeSpan.put((int) longOf(v), 0L);
        }
        // Absent in a manifest written strictly to §3.2's table; the head page
        // is then the authority, and the engine reads it when it opens the
        // segment.
        if (d.field("range_deletes") instanceof Value.Bool b && b.value()) {
            m.flags |= HAS_RANGE_DELETES;
        }
        return m;
    }

    static long longOf(Value v) {
        if (v instanceof Value.Int i) {
            Long l = i.asLong();
            if (l == null) {
                throw new CorruptionException("manifest holds an integer too wide for a long");
            }
            return l;
        }
        throw new CorruptionException("manifest field is " + v + ", expected an integer");
    }
}
