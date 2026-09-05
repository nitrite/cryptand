package org.dizitart.cryptand;

/**
 * The hard limits of {@code spec/00-conventions.md} §8.
 *
 * <p>Every one of these is checked <em>before</em> an allocation.
 */
public final class Limits {

    private Limits() {
    }

    /** Legal {@code page_size} values; {@code page_size_log2} is 12..16. */
    public static final int[] PAGE_SIZES = {4096, 8192, 16384, 32768, 65536};

    /** Document nesting depth. A decoder MUST enforce it and MUST NOT recurse unboundedly. */
    public static final int MAX_DEPTH = 100;

    /** Document field count. */
    public static final int MAX_FIELD_COUNT = 65535;

    /** {@code spec/00-conventions.md} §4: a {@code uvar} is at most 10 bytes. */
    public static final int MAX_UVAR_BYTES = 10;

    /** Absolute ceiling on an encoded key, before the page-relative cap applies. */
    public static final int MAX_KEY_BYTES_ABSOLUTE = 4096;

    /** Encoded key length: {@code page_size / 4}, and at most 4 KiB. */
    public static int maxKeyBytes(int pageSize) {
        return Math.min(pageSize / 4, MAX_KEY_BYTES_ABSOLUTE);
    }

    /** Inline value length: {@code page_size / 4}. */
    public static int maxInlineValueBytes(int pageSize) {
        return pageSize / 4;
    }

    public static void checkPageSize(int pageSize) {
        for (int p : PAGE_SIZES) {
            if (p == pageSize) {
                return;
            }
        }
        throw new InvalidArgumentException("page_size " + pageSize + " is not one of 4096, 8192, 16384, 32768, 65536");
    }

    /**
     * {@code vlog_min} MUST be at most {@code page_size / 4}, otherwise the
     * writer's own inline threshold names values that cannot be stored inline.
     */
    public static void checkVlogMin(int vlogMin, int pageSize) {
        int cap = pageSize / 4;
        if (vlogMin < 1 || vlogMin > cap) {
            throw new InvalidArgumentException(
                    "vlog_min " + vlogMin + " outside 1.." + cap + " for page_size " + pageSize);
        }
    }
}
