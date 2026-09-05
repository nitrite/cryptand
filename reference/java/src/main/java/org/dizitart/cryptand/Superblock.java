package org.dizitart.cryptand;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * The superblock — {@code spec/01-container.md} §2.
 *
 * <p>Exactly 4096 bytes regardless of {@code page_size}, at offset 0 (slot A)
 * and offset {@code page_size} (slot B). The two slots are written
 * <strong>alternately</strong>: the commit at {@code commit_id = N} writes slot
 * A when N is odd and slot B when N is even, so a crash during a superblock
 * write leaves the previous superblock intact. That, plus the rule that no page
 * a live superblock references is ever overwritten, is the whole of recovery:
 * open is O(1) in database size and there is no log to replay.
 *
 * <p>There is <strong>no run list here</strong>. Segments live in the manifest
 * tree, so the number of segments is unbounded by the superblock's size and a
 * compaction publishes by writing one small copy-on-write path plus one
 * superblock.
 *
 * <p>Every tuning constant is its own field and is never derived from
 * {@link #profile} on read.
 */
public final class Superblock {

    /** Exactly 4096 bytes, whatever {@code page_size} is. */
    public static final int BYTES = 4096;

    /** {@code "CRYPTAND"} — exactly 8 ASCII bytes, no padding. */
    public static final byte[] MAGIC = {'C', 'R', 'Y', 'P', 'T', 'A', 'N', 'D'};

    public static final int VERSION_MAJOR = 1;
    public static final int VERSION_MINOR = 0;

    /** Offset of the CRC-32C, which covers bytes {@code 0 … 4091}. */
    public static final int CHECKSUM_OFFSET = 4092;

    /** {@code durability_achieved}, offset 176. */
    public static final class Durability {
        private Durability() {
        }

        public static final int NONE = 0;
        public static final int OS = 1;
        public static final int SYNC = 2;
        public static final int FULL = 3;
    }

    /** {@code page_codec}, offset 177. */
    public static final class Codec {
        private Codec() {
        }

        public static final int NONE = 0;
        public static final int LZ4 = 1;
        public static final int ZSTD = 2;
    }

    /** {@code cipher}, offset 178. */
    public static final class Cipher {
        private Cipher() {
        }

        public static final int NONE = 0;
        public static final int XCHACHA20_POLY1305 = 1;
    }

    public int versionMajor = VERSION_MAJOR;
    public int versionMinor = VERSION_MINOR;
    /** Minimum minor version an implementation must have to <em>modify</em> this file. */
    public int writeVersionMinor;
    public int pageSizeLog2 = 12;

    public long commitId = 1;
    public long featuresRequired = Feature.bit(Feature.CORE);
    public long featuresOptional;
    /** Pages in use. The file MAY be longer; everything at or beyond this is debris. */
    public long pageCount = 2;
    /** Every record with {@code seq <= visible_seq} is committed. */
    public long visibleSeq;
    public long nextSeq = 1;

    public long catalogRoot;
    public long freelistRoot;
    public long attributesRoot;
    public long manifestRoot;
    public long vlogStatsRoot;

    /** Pages freed at or below this are allocatable. */
    public long minRetainedCommit;
    /** Versions older than this may be collapsed. */
    public long minRetainedSeq;

    public long nextTreeId = TreeId.FIRST_USER_TREE;
    public long nextSegmentId = 1;
    public long nextVlogSegmentId = 1;

    public long createdUtcMs;
    public long modifiedUtcMs;
    /** RFC 4122 v4, stable for the life of the file. */
    public byte[] databaseUuid = new byte[16];

    public int durabilityAchieved = Durability.SYNC;
    public int pageCodec = Codec.NONE;
    public int cipher = Cipher.NONE;
    public int levelCount = 1;
    public int fanout;
    public int l0Trigger;
    public int tierWidth;
    /** Advisory; a reader ignores it. */
    public int memtableShards = 1;

    public int vlogMin;
    public int blobThreshold;
    public int vlogSegmentBytes;
    public int vlogSpaceTargetPct;

    public long liveKeyBytes;
    public long liveValueBytes;

    /** Advisory. A reader uses the stored constants, never this. */
    public int profile = Profile.CUSTOM.id();
    public int overlapBound;
    public int localityDebtPct;
    public int filterBitsUpper;
    public int filterBitsLast;
    public int readaheadWindow;
    public int segmentTargetBytes;

    public long checkpointRoot;
    /** 0 if unused. */
    public long changefeedRoot;

    /** UTF-8, zero-padded to 32 bytes, e.g. {@code "nitrite-java/1.0.0"}. */
    public String writerId = "";

    /** Monotonic AEAD nonce counter; never reused. Meaningful only when {@code cipher != 0}. */
    public long nextNonce;
    /** Keyed MAC over this superblock; zero when {@code cipher = 0}. */
    public byte[] sbMac = new byte[32];
    /** 4 x 144 bytes; the wrapped master key. Zero when {@code cipher = 0}. */
    public byte[] keyslots = new byte[576];

    /** A superblock carrying a named profile's constants. */
    public static Superblock forProfile(Profile p) {
        Superblock sb = new Superblock();
        sb.profile = p.id();
        sb.pageSizeLog2 = Integer.numberOfTrailingZeros(p.pageSize());
        sb.memtableShards = p.memtableShards();
        sb.vlogMin = p.vlogMin();
        sb.blobThreshold = p.blobThreshold();
        sb.l0Trigger = p.l0Trigger();
        sb.fanout = p.fanout();
        sb.tierWidth = p.tierWidth();
        sb.overlapBound = p.overlapBound();
        sb.segmentTargetBytes = p.segmentTargetBytes();
        sb.vlogSegmentBytes = p.vlogSegmentBytes();
        sb.filterBitsUpper = p.filterBitsUpper();
        sb.filterBitsLast = p.filterBitsLast();
        sb.vlogSpaceTargetPct = p.vlogSpaceTargetPct();
        sb.localityDebtPct = p.localityDebtPct();
        sb.readaheadWindow = p.readaheadWindow();
        return sb;
    }

    public int pageSize() {
        return 1 << pageSizeLog2;
    }

    /**
     * Which slot the commit at {@code commitId} writes: odd commits go to slot
     * A (offset 0), even to slot B (offset {@code page_size}).
     */
    public static int slotOffsetFor(long commitId, int pageSize) {
        return (commitId & 1L) == 1L ? 0 : pageSize;
    }

    // ==================================================================
    // encoding
    // ==================================================================

    public byte[] encode() {
        byte[] out = new byte[BYTES];
        ByteWriter w = new ByteWriter(BYTES);
        w.bytes(MAGIC);
        w.u16(versionMajor).u16(versionMinor).u16(writeVersionMinor).u16(pageSizeLog2);
        w.u64(commitId).u64(featuresRequired).u64(featuresOptional).u64(pageCount);
        w.u64(visibleSeq).u64(nextSeq);
        w.u64(catalogRoot).u64(freelistRoot).u64(attributesRoot).u64(manifestRoot).u64(vlogStatsRoot);
        w.u64(minRetainedCommit).u64(minRetainedSeq);
        w.u64(nextTreeId).u64(nextSegmentId).u64(nextVlogSegmentId);
        w.u64(createdUtcMs).u64(modifiedUtcMs);
        w.bytes(fixed(databaseUuid, 16));
        w.u8(durabilityAchieved).u8(pageCodec).u8(cipher).u8(levelCount);
        w.u8(fanout).u8(l0Trigger).u8(tierWidth).u8(memtableShards);
        w.u32(vlogMin).u32(blobThreshold).u32(vlogSegmentBytes).u32(vlogSpaceTargetPct);
        w.u64(liveKeyBytes).u64(liveValueBytes);
        w.u8(profile).u8(overlapBound).u8(localityDebtPct).u8(filterBitsUpper).u8(filterBitsLast);
        // 221..223 reserved
        w.u8(0).u8(0).u8(0);
        w.u32(readaheadWindow).u32(segmentTargetBytes);
        w.u64(checkpointRoot).u64(changefeedRoot);
        w.u64(0); // 248 reserved
        byte[] id = Utf8.encode(writerId);
        if (id.length > 32) {
            throw new InvalidArgumentException("writer_id is longer than 32 bytes: " + writerId);
        }
        w.bytes(fixed(id, 32));
        w.u64(nextNonce);

        // The sequential prefix runs to offset 296, where `sb_mac` begins. This
        // check exists because the field table is long and the widths have to
        // add up: an earlier draft of the *page* header declared 32 bytes over
        // fields summing to 36, and it survived three review passes because
        // nobody added the column up.
        byte[] head = w.toBytes();
        if (head.length != 296) {
            throw new IllegalStateException("superblock prefix is " + head.length + " bytes, expected 296");
        }
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(fixed(sbMac, 32), 0, out, 296, 32);
        System.arraycopy(fixed(keyslots, 576), 0, out, 3512, 576);

        // §6 of 00-conventions: the checksum is the last field and covers
        // bytes 0..4091 - every byte of the block except its own four.
        int crc = Crc32c.of(out, 0, CHECKSUM_OFFSET);
        out[CHECKSUM_OFFSET] = (byte) crc;
        out[CHECKSUM_OFFSET + 1] = (byte) (crc >>> 8);
        out[CHECKSUM_OFFSET + 2] = (byte) (crc >>> 16);
        out[CHECKSUM_OFFSET + 3] = (byte) (crc >>> 24);
        return out;
    }

    private static byte[] fixed(byte[] src, int n) {
        return src.length == n ? src : Arrays.copyOf(src, n);
    }

    /**
     * Decodes and verifies one 4096-byte slot.
     *
     * <p>This is steps 2, 5 and 6 of §2.1's open procedure. Step 4 — verifying
     * {@code sb_mac} before reading any other field when {@code cipher != 0} —
     * belongs to chapter 14 and is not done here; until it exists, an encrypted
     * superblock is refused rather than trusted.
     */
    public static Superblock decode(byte[] slot) {
        if (slot.length < BYTES) {
            throw new LimitException("superblock slot is " + slot.length + " bytes, need " + BYTES);
        }
        if (!Arrays.equals(Arrays.copyOf(slot, 8), MAGIC)) {
            throw new CorruptionException("not a Cryptand database: magic is "
                    + HexFormat.of().formatHex(slot, 0, 8) + ", expected 4352595054414e44");
        }
        int stored = (slot[CHECKSUM_OFFSET] & 0xFF)
                | ((slot[CHECKSUM_OFFSET + 1] & 0xFF) << 8)
                | ((slot[CHECKSUM_OFFSET + 2] & 0xFF) << 16)
                | ((slot[CHECKSUM_OFFSET + 3] & 0xFF) << 24);
        int actual = Crc32c.of(slot, 0, CHECKSUM_OFFSET);
        if (stored != actual) {
            throw new CorruptionException(String.format(
                    "superblock checksum mismatch: stored %08x, computed %08x", stored, actual));
        }

        Superblock sb = new Superblock();
        ByteReader r = new ByteReader(slot, 8, BYTES - 8);
        sb.versionMajor = r.u16();
        sb.versionMinor = r.u16();
        sb.writeVersionMinor = r.u16();
        sb.pageSizeLog2 = r.u16();
        sb.commitId = r.u64();
        sb.featuresRequired = r.u64();
        sb.featuresOptional = r.u64();
        sb.pageCount = r.u64();
        sb.visibleSeq = r.u64();
        sb.nextSeq = r.u64();
        sb.catalogRoot = r.u64();
        sb.freelistRoot = r.u64();
        sb.attributesRoot = r.u64();
        sb.manifestRoot = r.u64();
        sb.vlogStatsRoot = r.u64();
        sb.minRetainedCommit = r.u64();
        sb.minRetainedSeq = r.u64();
        sb.nextTreeId = r.u64();
        sb.nextSegmentId = r.u64();
        sb.nextVlogSegmentId = r.u64();
        sb.createdUtcMs = r.u64();
        sb.modifiedUtcMs = r.u64();
        sb.databaseUuid = r.bytes(16);
        sb.durabilityAchieved = r.u8();
        sb.pageCodec = r.u8();
        sb.cipher = r.u8();
        sb.levelCount = r.u8();
        sb.fanout = r.u8();
        sb.l0Trigger = r.u8();
        sb.tierWidth = r.u8();
        sb.memtableShards = r.u8();
        sb.vlogMin = r.u32();
        sb.blobThreshold = r.u32();
        sb.vlogSegmentBytes = r.u32();
        sb.vlogSpaceTargetPct = r.u32();
        sb.liveKeyBytes = r.u64();
        sb.liveValueBytes = r.u64();
        sb.profile = r.u8();
        sb.overlapBound = r.u8();
        sb.localityDebtPct = r.u8();
        sb.filterBitsUpper = r.u8();
        sb.filterBitsLast = r.u8();
        r.skip(3);
        sb.readaheadWindow = r.u32();
        sb.segmentTargetBytes = r.u32();
        sb.checkpointRoot = r.u64();
        sb.changefeedRoot = r.u64();
        r.skip(8);
        sb.writerId = trimZeroPadded(r.bytes(32));
        sb.nextNonce = r.u64();
        sb.sbMac = Arrays.copyOfRange(slot, 296, 328);
        sb.keyslots = Arrays.copyOfRange(slot, 3512, 3512 + 576);

        sb.check();
        return sb;
    }

    /** Steps 2, 5, 6 of §2.1, plus the invariants of {@code 00-conventions.md} §8. */
    void check() {
        if (versionMajor != VERSION_MAJOR) {
            throw new UnsupportedFeatureException(
                    "format major version " + versionMajor + " is not 1; refusing to open");
        }
        if (pageSizeLog2 < 12 || pageSizeLog2 > 16) {
            throw new CorruptionException("page_size_log2 " + pageSizeLog2 + " outside 12..16");
        }
        long unknown = featuresRequired & ~Feature.KNOWN_REQUIRED;
        if (unknown != 0) {
            int bit = Long.numberOfTrailingZeros(unknown);
            throw new UnsupportedFeatureException(
                    "required feature bit " + bit + " (" + Feature.name(bit) + ") is not supported; refusing to open");
        }
        if (commitId < 1) {
            throw new CorruptionException("commit_id must be at least 1, got " + commitId);
        }
        // 00-conventions §8: "A writer MUST reject a vlog_min above the cap; a
        // reader MUST treat a file whose superblock violates it as corrupt."
        if (vlogMin != 0 && vlogMin > pageSize() / 4) {
            throw new CorruptionException("vlog_min " + vlogMin + " exceeds page_size/" + 4
                    + " = " + (pageSize() / 4) + "; every value it names would be unstorable inline");
        }
        // 00-conventions §7: 0xFFFFFFFF is the page-header sentinel and is
        // therefore never a valid tree_id.
        if (Long.compareUnsigned(nextTreeId, 0xFFFFFFFEL) > 0) {
            throw new CorruptionException("next_tree_id " + Long.toUnsignedString(nextTreeId)
                    + " would reach the page-header sentinel 0xFFFFFFFF");
        }
    }

    /** True when this file may be modified by an implementation at {@code minor}. */
    public boolean writableBy(int minor) {
        return writeVersionMinor <= minor;
    }

    private static String trimZeroPadded(byte[] b) {
        int n = b.length;
        while (n > 0 && b[n - 1] == 0) {
            n--;
        }
        return Utf8.decode(b, 0, n);
    }

}
