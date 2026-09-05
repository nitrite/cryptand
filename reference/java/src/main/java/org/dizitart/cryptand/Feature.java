package org.dizitart.cryptand;

/**
 * Feature bits — {@code spec/11-conformance.md} §2.
 *
 * <p>The rule that decides which of the superblock's two words a bit goes in,
 * stated before the constants because an earlier draft's column header and its
 * own following paragraph disagreed:
 *
 * <blockquote>A bit goes in {@code features_required} only when a reader that
 * does not understand it would return <em>wrong data</em>. A bit goes in
 * {@code features_optional} when ignoring it costs a capability and nothing
 * else.</blockquote>
 *
 * <p>Feature bits, not version numbers, gate behaviour. An unknown
 * <em>required</em> bit means refuse to open and name it; an unknown
 * <em>optional</em> bit means open, ignore the structures it governs, and do
 * not delete them.
 */
public final class Feature {

    private Feature() {
    }

    /** Always set. Level 0. Required. */
    public static final int CORE = 0;
    /** Any {@code data} tree exists. Level 1. Required. */
    public static final int DOCUMENTS = 1;
    /** Any {@code postings} tree exists. Level 2. Optional. */
    public static final int TEXT = 2;
    /** Any {@code rtree} tree exists. Level 3. Optional. */
    public static final int SPATIAL = 3;
    /** Any {@code vector_graph} tree exists. Level 4. Optional. */
    public static final int VECTOR = 4;
    /** Any page uses codec 2. Required. */
    public static final int ZSTD = 5;
    /** {@code cipher != 0}. Required. */
    public static final int CIPHER = 6;
    /** A CFH-64 checksum is stored for a blob or value-log body. Required. */
    public static final int HASH64 = 7;
    /** Any {@code DEC128} value stored. Required. */
    public static final int DEC128 = 8;
    /** Multi-process writing. Required. Post-1.0. */
    public static final int MULTIPROC = 9;
    /** Blob deduplication. Required. */
    public static final int DEDUP = 10;
    /** Reader processes coordinate through the lock sidecar. Optional. */
    public static final int MULTIPROC_READ = 11;
    /** Any page or record compressed against a Zstd dictionary. Required. */
    public static final int ZDICT = 12;
    /** Any entry carries an expiry. Required. */
    public static final int TTL = 13;
    /** Tree 9 is in use. Optional. */
    public static final int CHANGEFEED = 14;
    /** Tree 8 holds retained snapshots. Optional. */
    public static final int CHECKPOINTS = 15;

    /**
     * Every required bit this implementation understands. A file whose
     * {@code features_required} has a bit outside this mask cannot be opened.
     */
    public static final long KNOWN_REQUIRED =
            bit(CORE) | bit(DOCUMENTS) | bit(ZSTD) | bit(CIPHER) | bit(HASH64)
                    | bit(DEC128) | bit(DEDUP) | bit(ZDICT) | bit(TTL);

    public static long bit(int n) {
        return 1L << n;
    }

    public static boolean isSet(long word, int n) {
        return (word & bit(n)) != 0;
    }

    /** A name for diagnostics; §9 requires an unknown required bit to be named. */
    public static String name(int n) {
        switch (n) {
            case CORE: return "CORE";
            case DOCUMENTS: return "DOCUMENTS";
            case TEXT: return "TEXT";
            case SPATIAL: return "SPATIAL";
            case VECTOR: return "VECTOR";
            case ZSTD: return "ZSTD";
            case CIPHER: return "CIPHER";
            case HASH64: return "HASH64";
            case DEC128: return "DEC128";
            case MULTIPROC: return "MULTIPROC";
            case DEDUP: return "DEDUP";
            case MULTIPROC_READ: return "MULTIPROC_READ";
            case ZDICT: return "ZDICT";
            case TTL: return "TTL";
            case CHANGEFEED: return "CHANGEFEED";
            case CHECKPOINTS: return "CHECKPOINTS";
            default: return n >= 48 ? "vendor bit " + n : "reserved bit " + n;
        }
    }
}
