package org.dizitart.cryptand;

/**
 * An authentication tag did not verify — {@code spec/14-security.md} §6.2.
 *
 * <p><strong>Not corruption.</strong> {@code spec/01-container.md} §9 is
 * emphatic: "your disk has a bad sector" and "someone edited your database"
 * call for different responses. A failed AEAD tag or {@code sb_mac} MUST NOT be
 * repaired, and MUST NOT be reported through {@link CorruptionException}, whose
 * whole contract is that repair is a reasonable next step.
 */
public final class TamperingException extends CryptandException {

    private final Long pageId;

    public TamperingException(String message) {
        this(message, null);
    }

    public TamperingException(String message, Long pageId) {
        super(pageId == null ? message : message + " (page " + pageId + ")");
        this.pageId = pageId;
    }

    /** The page whose tag failed, when one is known. */
    public Long pageId() {
        return pageId;
    }
}
