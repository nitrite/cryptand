package org.dizitart.cryptand;

/**
 * The bytes are not what the format says they should be — accidental damage.
 *
 * <p>Distinct from a failed authentication tag, which is
 * {@code spec/14-security.md} §6.2's <em>tampering</em> and must not be
 * repaired. {@code spec/13-operations.md} §4 requires corruption to name what
 * it affects, hence {@link #pageId()} and {@link #offset()}.
 */
public final class CorruptionException extends CryptandException {

    private final Long pageId;
    private final Long offset;

    public CorruptionException(String message) {
        this(message, null, null);
    }

    public CorruptionException(String message, Long pageId, Long offset) {
        super(where(message, pageId, offset));
        this.pageId = pageId;
        this.offset = offset;
    }

    private static String where(String message, Long pageId, Long offset) {
        if (pageId == null && offset == null) {
            return message;
        }
        StringBuilder sb = new StringBuilder(message).append(" (");
        if (pageId != null) {
            sb.append("page ").append(pageId);
            if (offset != null) {
                sb.append(", ");
            }
        }
        if (offset != null) {
            sb.append("offset ").append(offset);
        }
        return sb.append(')').toString();
    }

    /** The page the damage was found in, or {@code null} when not known. */
    public Long pageId() {
        return pageId;
    }

    /** The byte offset the damage was found at, or {@code null}. */
    public Long offset() {
        return offset;
    }
}
