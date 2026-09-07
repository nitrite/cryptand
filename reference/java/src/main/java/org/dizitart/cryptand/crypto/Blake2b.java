package org.dizitart.cryptand.crypto;

import org.dizitart.cryptand.InvalidArgumentException;

/**
 * BLAKE2b (RFC 7693), needed only because Argon2id is defined over it —
 * {@code spec/14-security.md} §2.
 *
 * <p>The JDK has SHA-256 and HMAC, so HKDF and the superblock MAC need nothing
 * new; it has no BLAKE2b, and Argon2id's compression function and its
 * variable-length hash {@code H'} are both defined in terms of one. This is
 * that, written from the RFC — which is what {@code 00-conventions.md} §1.1
 * asks of a named primitive: small enough to write from the standard where the
 * platform does not supply it.
 */
public final class Blake2b {

    private static final long[] IV = {
            0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL, 0x3C6EF372FE94F82BL, 0xA54FF53A5F1D36F1L,
            0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL, 0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
    };

    private static final byte[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };

    private final long[] h = new long[8];
    private final byte[] buffer = new byte[128];
    private int bufferLen;
    private long counter;
    private final int digestLength;

    public Blake2b(int digestLength) {
        this(digestLength, null);
    }

    public Blake2b(int digestLength, byte[] key) {
        if (digestLength < 1 || digestLength > 64) {
            throw new InvalidArgumentException("BLAKE2b digest length " + digestLength + " outside 1..64");
        }
        this.digestLength = digestLength;
        System.arraycopy(IV, 0, h, 0, 8);
        int keyLen = key == null ? 0 : key.length;
        h[0] ^= 0x01010000L ^ ((long) keyLen << 8) ^ digestLength;
        if (keyLen > 0) {
            byte[] block = new byte[128];
            System.arraycopy(key, 0, block, 0, keyLen);
            update(block, 0, 128);
        }
    }

    public Blake2b update(byte[] in) {
        return update(in, 0, in.length);
    }

    public Blake2b update(byte[] in, int off, int len) {
        int i = off;
        int end = off + len;
        while (i < end) {
            if (bufferLen == 128) {
                counter += 128;
                compress(buffer, 0, false);
                bufferLen = 0;
            }
            int n = Math.min(128 - bufferLen, end - i);
            System.arraycopy(in, i, buffer, bufferLen, n);
            bufferLen += n;
            i += n;
        }
        return this;
    }

    public byte[] digest() {
        counter += bufferLen;
        java.util.Arrays.fill(buffer, bufferLen, 128, (byte) 0);
        compress(buffer, 0, true);
        byte[] out = new byte[digestLength];
        for (int i = 0; i < digestLength; i++) {
            out[i] = (byte) (h[i >>> 3] >>> (8 * (i & 7)));
        }
        return out;
    }

    public static byte[] hash(int digestLength, byte[] input) {
        return new Blake2b(digestLength).update(input).digest();
    }

    private void compress(byte[] block, int off, boolean last) {
        long[] m = new long[16];
        for (int i = 0; i < 16; i++) {
            long v = 0;
            for (int j = 7; j >= 0; j--) {
                v = (v << 8) | (block[off + i * 8 + j] & 0xFFL);
            }
            m[i] = v;
        }
        long[] v = new long[16];
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= counter;
        // The high half of the 128-bit counter stays zero: nothing here hashes
        // 2^64 bytes.
        if (last) {
            v[14] = ~v[14];
        }
        for (int r = 0; r < 12; r++) {
            byte[] s = SIGMA[r];
            mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void mix(long[] v, int a, int b, int c, int d, long x, long y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }
}
