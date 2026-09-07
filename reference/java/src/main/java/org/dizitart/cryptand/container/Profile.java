package org.dizitart.cryptand.container;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.crypto.Argon2id;

/**
 * A device profile — {@code spec/12-profiles.md} §1.
 *
 * <p>A profile is a named set of tuning constants. It is recorded in the
 * superblock, it changes only <em>how a writer behaves</em>, and it changes
 * <strong>nothing about how a file is read</strong>. A file written under
 * {@code MOBILE} and one written under {@code SERVER} are the same format,
 * mutually readable, and either converts to the other by ordinary compaction.
 *
 * <p>Every constant below is written to the superblock as its own field and is
 * <strong>never derived from the profile on read</strong>
 * ({@code spec/01-container.md} §2). A reader uses the stored values; the
 * profile byte is metadata for tooling and for a writer picking defaults. That
 * is what makes a phone-written and a server-written database the same format.
 *
 * <p>The defining choice is {@code vlogMin}. On {@code MOBILE} it sits at its
 * ceiling — a quarter page, 1024 bytes at 4 KiB — so documents stay inline and a
 * point read costs <em>one</em> I/O rather than two. Write amplification is a
 * server problem; a 400 µs random read on every document fetch is a phone
 * problem.
 */
public enum Profile {

    /** 0 — the constants were set individually and match no named profile. */
    CUSTOM(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),

    MOBILE(1, 4096, 1, 1024, 65536, 2, 4, 2, 1, 2 * 1024 * 1024, 4 * 1024 * 1024,
            12, 10, 120, 20, 128, 8),

    TABLET(2, 4096, 2, 1024, 131072, 4, 6, 3, 2, 8 * 1024 * 1024, 16 * 1024 * 1024,
            14, 10, 130, 20, 256, 8),

    DESKTOP(3, 8192, 8, 256, 262144, 4, 8, 4, 2, 32 * 1024 * 1024, 64 * 1024 * 1024,
            16, 10, 150, 20, 256, 25),

    SERVER(4, 16384, 32, 256, 262144, 8, 10, 6, 3, 128 * 1024 * 1024, 256 * 1024 * 1024,
            16, 10, 150, 25, 1024, 100);

    private final int id;
    private final int pageSize;
    private final int memtableShards;
    private final int vlogMin;
    private final int blobThreshold;
    private final int l0Trigger;
    private final int fanout;
    private final int tierWidth;
    private final int overlapBound;
    private final int segmentTargetBytes;
    private final int vlogSegmentBytes;
    private final int filterBitsUpper;
    private final int filterBitsLast;
    private final int vlogSpaceTargetPct;
    private final int localityDebtPct;
    private final int readaheadWindow;
    private final int maxForegroundStallMs;

    Profile(int id, int pageSize, int memtableShards, int vlogMin, int blobThreshold,
            int l0Trigger, int fanout, int tierWidth, int overlapBound,
            int segmentTargetBytes, int vlogSegmentBytes, int filterBitsUpper,
            int filterBitsLast, int vlogSpaceTargetPct, int localityDebtPct,
            int readaheadWindow, int maxForegroundStallMs) {
        this.id = id;
        this.pageSize = pageSize;
        this.memtableShards = memtableShards;
        this.vlogMin = vlogMin;
        this.blobThreshold = blobThreshold;
        this.l0Trigger = l0Trigger;
        this.fanout = fanout;
        this.tierWidth = tierWidth;
        this.overlapBound = overlapBound;
        this.segmentTargetBytes = segmentTargetBytes;
        this.vlogSegmentBytes = vlogSegmentBytes;
        this.filterBitsUpper = filterBitsUpper;
        this.filterBitsLast = filterBitsLast;
        this.vlogSpaceTargetPct = vlogSpaceTargetPct;
        this.localityDebtPct = localityDebtPct;
        this.readaheadWindow = readaheadWindow;
        this.maxForegroundStallMs = maxForegroundStallMs;
    }

    public int id() {
        return id;
    }

    /** Fixed at creation and never changed; {@code page_size_log2} is 12..16. */
    public int pageSize() {
        return pageSize;
    }

    public int memtableShards() {
        return memtableShards;
    }

    /**
     * The inline / value-log cut-off. MUST be at most {@code pageSize / 4}: it
     * is the largest value a leaf cell can hold, so a higher threshold would
     * name values that cannot be stored inline.
     */
    public int vlogMin() {
        return vlogMin;
    }

    public int blobThreshold() {
        return blobThreshold;
    }

    public int l0Trigger() {
        return l0Trigger;
    }

    public int fanout() {
        return fanout;
    }

    public int tierWidth() {
        return tierWidth;
    }

    public int overlapBound() {
        return overlapBound;
    }

    public int segmentTargetBytes() {
        return segmentTargetBytes;
    }

    public int vlogSegmentBytes() {
        return vlogSegmentBytes;
    }

    public int filterBitsUpper() {
        return filterBitsUpper;
    }

    public int filterBitsLast() {
        return filterBitsLast;
    }

    public int vlogSpaceTargetPct() {
        return vlogSpaceTargetPct;
    }

    public int localityDebtPct() {
        return localityDebtPct;
    }

    public int readaheadWindow() {
        return readaheadWindow;
    }

    /**
     * {@code spec/12-profiles.md} §4's foreground stall budget. 8 ms on a phone
     * because a UI thread that blocks for 16 ms drops a frame.
     */
    public int maxForegroundStallMs() {
        return maxForegroundStallMs;
    }

    /**
     * {@code page_codec} — {@code spec/12-profiles.md} §1's row, and
     * {@code 01-container.md} §7: LZ4 is the default and the only codec a
     * Level-0 implementation MUST support.
     *
     * <p>Zstd is feature bit {@code ZSTD}; this build does not set it, so every
     * profile names LZ4 and the heavier last-level codec §7 recommends from
     * {@code TABLET} upward is left to a build that has one.
     */
    public int pageCodec() {
        return Superblock.Codec.LZ4;
    }

    /**
     * Argon2id cost — {@code spec/14-security.md} §3.2, a per-device decision
     * and therefore a profile default. Stored per keyslot, so a file created on
     * a phone still opens on a phone after a desktop has written to it.
     *
     * <p>The memory cost is transient and much larger than the engine's entire
     * steady-state budget: 64 MiB against {@code MOBILE}'s 4 MiB page cache. It
     * is allocated, used and released before opening proceeds.
     */
    public int argon2TCost() {
        return switch (this) {
            case MOBILE, TABLET -> 3;
            case DESKTOP, SERVER -> 4;
            case CUSTOM -> 3;
        };
    }

    public int argon2MCostKib() {
        return switch (this) {
            case MOBILE -> 65536;
            case TABLET -> 131072;
            case DESKTOP, SERVER -> 262144;
            case CUSTOM -> 65536;
        };
    }

    public int argon2Parallelism() {
        return switch (this) {
            case MOBILE -> 1;
            case TABLET -> 2;
            case DESKTOP, SERVER -> 4;
            case CUSTOM -> 1;
        };
    }

    public static Profile byId(int id) {
        for (Profile p : values()) {
            if (p.id == id) {
                return p;
            }
        }
        throw new CorruptionException("unknown profile id " + id);
    }
}
