package org.dizitart.cryptand;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * XChaCha20-Poly1305 — {@code spec/14-security.md} §2, {@code cipher = 1}.
 *
 * <p>Chosen for its 24-byte nonce, which is what lets nonces be
 * <em>constructed</em> (§4.2) rather than kept in a table; for needing no AES
 * hardware, which matters on the mid-range ARM devices Nitrite targets; and for
 * being constant-time in software by construction, unlike table-driven AES.
 *
 * <p>XChaCha20 is HChaCha20 plus IETF ChaCha20-Poly1305: the first 16 nonce
 * bytes and the key go through HChaCha20 to produce a subkey, and the remaining
 * 8 bytes become the low half of a 12-byte IETF nonce. The JDK supplies
 * ChaCha20-Poly1305 from Java 11, so only HChaCha20 is written out here.
 */
public final class XChaCha20Poly1305 {

    private XChaCha20Poly1305() {
    }

    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 24;
    public static final int TAG_BYTES = 16;

    /** Ciphertext with the 16-byte Poly1305 tag appended. */
    public static byte[] encrypt(byte[] key, byte[] nonce24, byte[] aad, byte[] plaintext) {
        return run(Cipher.ENCRYPT_MODE, key, nonce24, aad, plaintext);
    }

    /**
     * Plaintext, or {@link TamperingException} if the tag does not verify.
     *
     * <p>A failed tag is not corruption. {@code 01-container.md} §9 is emphatic
     * that the two call for different responses, and this one MUST NOT be
     * repaired.
     */
    public static byte[] decrypt(byte[] key, byte[] nonce24, byte[] aad, byte[] ciphertext, String what) {
        if (ciphertext.length < TAG_BYTES) {
            throw new CorruptionException(what + " is " + ciphertext.length
                    + " bytes, shorter than the " + TAG_BYTES + "-byte tag alone");
        }
        try {
            return run(Cipher.DECRYPT_MODE, key, nonce24, aad, ciphertext);
        } catch (RuntimeException e) {
            if (e instanceof TamperingException t) {
                throw t;
            }
            throw new TamperingException("authentication failed for " + what
                    + "; the bytes were modified after they were written");
        }
    }

    private static byte[] run(int mode, byte[] key, byte[] nonce24, byte[] aad, byte[] input) {
        if (key.length != KEY_BYTES) {
            throw new InvalidArgumentException("key is " + key.length + " bytes, expected " + KEY_BYTES);
        }
        if (nonce24.length != NONCE_BYTES) {
            throw new InvalidArgumentException("nonce is " + nonce24.length + " bytes, expected " + NONCE_BYTES);
        }
        byte[] subkey = hchacha20(key, Arrays.copyOf(nonce24, 16));
        byte[] iv = new byte[12];
        System.arraycopy(nonce24, 16, iv, 4, 8);
        try {
            Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(mode, new SecretKeySpec(subkey, "ChaCha20"), new IvParameterSpec(iv));
            if (aad != null && aad.length > 0) {
                c.updateAAD(aad);
            }
            return c.doFinal(input);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new TamperingException("Poly1305 tag did not verify");
        } catch (GeneralSecurityException e) {
            throw new InvalidArgumentException("XChaCha20-Poly1305 failed: " + e.getMessage());
        } finally {
            Arrays.fill(subkey, (byte) 0);
        }
    }

    /**
     * HChaCha20 (RFC 8439 §2.3's core without the feed-forward addition,
     * returning the first and last rows).
     */
    static byte[] hchacha20(byte[] key, byte[] nonce16) {
        int[] s = new int[16];
        s[0] = 0x61707865;
        s[1] = 0x3320646e;
        s[2] = 0x79622d32;
        s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) {
            s[4 + i] = le32(key, i * 4);
        }
        for (int i = 0; i < 4; i++) {
            s[12 + i] = le32(nonce16, i * 4);
        }
        for (int i = 0; i < 10; i++) {
            quarter(s, 0, 4, 8, 12);
            quarter(s, 1, 5, 9, 13);
            quarter(s, 2, 6, 10, 14);
            quarter(s, 3, 7, 11, 15);
            quarter(s, 0, 5, 10, 15);
            quarter(s, 1, 6, 11, 12);
            quarter(s, 2, 7, 8, 13);
            quarter(s, 3, 4, 9, 14);
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 4; i++) {
            putLe32(out, i * 4, s[i]);
            putLe32(out, 16 + i * 4, s[12 + i]);
        }
        return out;
    }

    private static void quarter(int[] s, int a, int b, int c, int d) {
        s[a] += s[b];
        s[d] = Integer.rotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d];
        s[b] = Integer.rotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b];
        s[d] = Integer.rotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d];
        s[b] = Integer.rotateLeft(s[b] ^ s[c], 7);
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    private static void putLe32(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }
}
