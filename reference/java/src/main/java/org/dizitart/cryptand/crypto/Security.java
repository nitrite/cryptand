package org.dizitart.cryptand.crypto;

import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.value.Value;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Key derivation and nonces — {@code spec/14-security.md} §3.4 and §4.
 *
 * <p>The realistic attacker on an embedded database has <strong>the file</strong>
 * — a lost phone, a leaked backup, a forensic image — not a socket. Chapter 14
 * starts from that and specifies the bytes; this class is the part of it that
 * SHA-256 and HMAC-SHA256 are enough for, both of which the JDK supplies.
 */
public final class Security {

    private Security() {
    }

    /** {@code info = "cryptand/v1/" || purpose}. */
    public static final String INFO_PREFIX = "cryptand/v1/";

    /** Subkey purposes — §3.4. */
    public static final class Purpose {
        private Purpose() {
        }

        /** Page payloads, §5.2. */
        public static final String PAGE = "page";
        /** Value-log records, §5.3. */
        public static final String VLOG = "vlog";
        /** The superblock MAC, §6. */
        public static final String SB_MAC = "sbmac";
    }

    /** Nonce domains — §4.2. */
    public static final class NonceDomain {
        private NonceDomain() {
        }

        public static final int PAGE = 1;
        public static final int VLOG_RECORD = 2;
        public static final int KEY_WRAP = 3;
    }

    /**
     * §4.1: the gap by which a writer advances the durably published
     * {@code next_nonce} before allocating anything.
     *
     * <p>The counter, not {@code (page_id, commit_id)}, is what makes a nonce
     * unique: a crashed commit reuses its {@code commit_id}, and reusing a
     * stream-cipher nonce is the one failure that is not recoverable. The floor
     * must be <em>published</em>, not derived from {@code next_nonce - GAP} —
     * deriving it once wrapped to a floor that had never been written, silently
     * in release builds and with an arithmetic panic in debug ones.
     */
    public static final long NONCE_GAP = 1L << 20;

    // ==================================================================
    // HKDF-SHA256, RFC 5869
    // ==================================================================

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // An all-zero key of length 0 is legal in HKDF-Extract but not in
            // the JCE, which rejects an empty key.
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmacSha256(salt, ikm);
    }

    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        if (length < 0 || length > 255 * 32) {
            throw new InvalidArgumentException("HKDF output length " + length + " outside 0..8160");
        }
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int filled = 0;
        for (int counter = 1; filled < length; counter++) {
            byte[] input = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, input, 0, t.length);
            System.arraycopy(info, 0, input, t.length, info.length);
            input[input.length - 1] = (byte) counter;
            t = hmacSha256(prk, input);
            int n = Math.min(t.length, length - filled);
            System.arraycopy(t, 0, out, filled, n);
            filled += n;
        }
        return out;
    }

    public static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) {
        return hkdfExpand(hkdfExtract(salt, ikm), info, length);
    }

    /**
     * §3.4: never use the master key directly.
     *
     * <p>Domain separation matters for a concrete reason: pages and value-log
     * records use <em>different</em> nonce spaces, and reusing one key across
     * two independently-constructed nonce spaces is exactly how nonce
     * collisions become possible again. Separate keys make the two spaces
     * independent by construction.
     *
     * <p>Using {@code database_uuid} as the salt means <strong>two files with
     * the same password have different content keys</strong>, so a nonce that
     * repeats across files is harmless. That is why a backup must not copy the
     * source's uuid — a rule that is load-bearing for security, not only for
     * tooling.
     */
    public static byte[] deriveSubkey(byte[] masterKey, byte[] databaseUuid, String purpose) {
        if (masterKey.length != 32) {
            throw new InvalidArgumentException("the master key is 32 bytes, got " + masterKey.length);
        }
        if (databaseUuid.length != 16) {
            throw new InvalidArgumentException("database_uuid is 16 bytes, got " + databaseUuid.length);
        }
        byte[] info = (INFO_PREFIX + purpose).getBytes(StandardCharsets.UTF_8);
        return hkdf(databaseUuid, masterKey, info, 32);
    }

    // ==================================================================
    // nonces, §4.2
    // ==================================================================

    /**
     * The 24-byte nonce: {@code u8 domain || u64 counter || u64 object_id ||
     * u56 offset}, little-endian throughout.
     *
     * <p>{@code object_id} and {@code offset} are redundant given a correct
     * counter, and they are there deliberately: if a counter value were ever
     * reused through an implementation bug, a collision additionally requires
     * the same page, which turns a catastrophic break into an unlikely one.
     * Defence in depth is cheap when the field is already 24 bytes wide.
     */
    public static byte[] buildNonce(int domain, long counter, long objectId, long offset) {
        if (offset < 0 || offset > 0x00FFFFFFFFFFFFFFL) {
            throw new InvalidArgumentException("nonce offset " + offset + " does not fit a u56");
        }
        ByteWriter w = new ByteWriter(24);
        w.u8(domain).u64(counter).u64(objectId);
        for (int i = 0; i < 7; i++) {
            w.u8((int) ((offset >>> (8 * i)) & 0xFF));
        }
        byte[] nonce = w.toBytes();
        if (nonce.length != 24) {
            throw new IllegalStateException("nonce is " + nonce.length + " bytes, expected 24");
        }
        return nonce;
    }

    /**
     * Compares two byte arrays in time independent of their contents.
     *
     * <p>{@link Arrays#equals} returns on the first differing byte, which leaks
     * the length of a matching prefix to anyone who can time it. Use this for
     * anything a caller supplies and the file authenticates.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
