package org.dizitart.cryptand.crypto;

import org.dizitart.cryptand.TamperingException;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;

/**
 * The page-level cipher — {@code spec/14-security.md} §5.2.
 *
 * <p>Scope is the page <em>payload</em> only. The 40-byte page header, a
 * value-log segment's head page and both superblocks stay in the clear, so
 * structure, checksums, free-space accounting, verification and repair all work
 * without the key ({@code 01-container.md} §8).
 *
 * <p>This is an interface rather than a class because {@link Pager} must be
 * usable — and testable — on a plaintext file without dragging in Argon2id.
 */
public interface PageCrypto {

    /**
     * Allocates a nonce from the superblock's monotonic counter. §4.1 requires
     * the counter to have been durably published <em>before</em> the
     * allocation.
     */
    long allocateNonce();

    /**
     * Encrypts one page payload.
     *
     * <p>{@code header} is the header <strong>as it will be stored</strong> —
     * flags, nonce and {@code stored_len} already set — because §5.2's AAD is
     * "the 40-byte page header with {@code checksum} zeroed", and every field
     * of it. Passing a header that is not yet final produces a page that
     * decrypts under this implementation and under no other, which is the
     * failure mode a single-implementation test cannot see.
     */
    byte[] encryptPage(byte[] payload, PageHeader header, long pageId);

    /**
     * Decrypts one page payload, or throws {@link TamperingException} if the
     * Poly1305 tag does not verify. A failed tag is not corruption and MUST NOT
     * be repaired.
     */
    byte[] decryptPage(byte[] stored, PageHeader header, long pageId);
}
