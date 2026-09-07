package org.dizitart.cryptand.util;

import org.dizitart.cryptand.CorruptionException;

import java.util.Arrays;

/**
 * LZ4 <strong>block</strong> format — {@code spec/01-container.md} §7, codec
 * id 1.
 *
 * <p>Raw block, no frame header: {@code payload_len} in the page header gives
 * the decompressed size, so the block carries no length of its own. LZ4 is the
 * default codec and the only one a Level-0 implementation must support; Zstd is
 * its own feature bit.
 *
 * <p>A block is a sequence of {@code (literals, match)} sequences:
 *
 * <pre>
 *   u8    token       -- high nibble literal length, low nibble match length-4
 *   [u8]* extra literal length, 255-terminated continuation
 *   bytes literals
 *   u16le offset      -- absent iff this is the last sequence
 *   [u8]* extra match length
 * </pre>
 *
 * <p>The compressor here is a plain single-table hash matcher. It is not fast
 * and does not try to be: page compression is a space decision, the format
 * pins only the <em>bytes</em>, and any conforming LZ4 block decodes to the
 * same output whatever produced it.
 */
public final class Lz4 {

    private Lz4() {
    }

    private static final int MIN_MATCH = 4;

    /**
     * The last five bytes of a block are always literals, and the last match
     * must start at least twelve bytes before the end.
     *
     * <p>These are the LZ4 <em>end-of-block restrictions</em>. A decoder that
     * reads a block safely does not need them, but the widely-deployed fast
     * decoders take a shortcut that does, and the point of writing an LZ4 block
     * is that somebody else's decoder reads it. Honouring them costs a handful
     * of literal bytes on the tail of a page and removes the question.
     */
    private static final int LAST_LITERALS = 5;

    private static final int MATCH_END_GUARD = 12;
    private static final int HASH_BITS = 14;

    /**
     * §7: "a page is stored compressed only if compression saves &ge; 12.5 %".
     *
     * <p>Measured against the payload being compressed, not against the whole
     * page: the 40-byte header is never compressed, so including it would make
     * the threshold depend on the page size.
     */
    public static boolean worthCompressing(int raw, int compressed) {
        return compressed + raw / 8 <= raw;
    }

    public static byte[] decompress(byte[] src, int decompressedLen) {
        byte[] dst = new byte[decompressedLen];
        int s = 0;
        int d = 0;
        while (s < src.length) {
            int token = src[s++] & 0xFF;
            int litLen = token >>> 4;
            if (litLen == 15) {
                int b;
                do {
                    if (s >= src.length) {
                        throw new CorruptionException("LZ4 block ends inside a literal length");
                    }
                    b = src[s++] & 0xFF;
                    litLen += b;
                } while (b == 255);
            }
            if (s + litLen > src.length || d + litLen > dst.length) {
                throw new CorruptionException("LZ4 block: " + litLen + " literals overrun the buffer");
            }
            System.arraycopy(src, s, dst, d, litLen);
            s += litLen;
            d += litLen;
            if (s >= src.length) {
                break;
            }
            if (s + 2 > src.length) {
                throw new CorruptionException("LZ4 block ends inside a match offset");
            }
            int offset = (src[s] & 0xFF) | ((src[s + 1] & 0xFF) << 8);
            s += 2;
            if (offset == 0 || offset > d) {
                throw new CorruptionException("LZ4 match offset " + offset + " points outside the output");
            }
            int matchLen = token & 0x0F;
            if (matchLen == 15) {
                int b;
                do {
                    if (s >= src.length) {
                        throw new CorruptionException("LZ4 block ends inside a match length");
                    }
                    b = src[s++] & 0xFF;
                    matchLen += b;
                } while (b == 255);
            }
            matchLen += MIN_MATCH;
            if (d + matchLen > dst.length) {
                throw new CorruptionException("LZ4 match of " + matchLen + " overruns the output");
            }
            // Byte-at-a-time on purpose: overlapping matches (offset < length)
            // are legal and are how LZ4 encodes runs.
            int m = d - offset;
            for (int i = 0; i < matchLen; i++) {
                dst[d++] = dst[m++];
            }
        }
        if (d != decompressedLen) {
            throw new CorruptionException("LZ4 block decoded to " + d + " bytes, expected " + decompressedLen);
        }
        return dst;
    }

    public static byte[] compress(byte[] src) {
        byte[] dst = new byte[maxCompressedLength(src.length)];
        int n = compressInto(src, dst);
        return Arrays.copyOf(dst, n);
    }

    public static int maxCompressedLength(int n) {
        return n + n / 255 + 16;
    }

    private static int compressInto(byte[] src, byte[] dst) {
        int[] table = new int[1 << HASH_BITS];
        Arrays.fill(table, -1);
        int s = 0;
        int anchor = 0;
        int d = 0;
        // A match may start no later than twelve bytes before the end.
        int limit = src.length - MATCH_END_GUARD;
        while (s <= limit) {
            int h = hash(src, s);
            int candidate = table[h];
            table[h] = s;
            if (candidate < 0 || s - candidate > 0xFFFF || !matches(src, candidate, s)) {
                s++;
                continue;
            }
            int matchLen = MIN_MATCH;
            int max = src.length - LAST_LITERALS;
            while (s + matchLen < max && src[candidate + matchLen] == src[s + matchLen]) {
                matchLen++;
            }
            d = emit(src, dst, d, anchor, s - anchor, s - candidate, matchLen - MIN_MATCH);
            s += matchLen;
            anchor = s;
        }
        // Trailing literals: the last sequence has no match, per the format.
        int litLen = src.length - anchor;
        d = emitToken(dst, d, litLen, 0);
        d = emitLength(dst, d, litLen, 15);
        System.arraycopy(src, anchor, dst, d, litLen);
        return d + litLen;
    }

    private static int emit(byte[] src, byte[] dst, int d, int anchor, int litLen, int offset, int matchExtra) {
        d = emitToken(dst, d, litLen, matchExtra);
        d = emitLength(dst, d, litLen, 15);
        System.arraycopy(src, anchor, dst, d, litLen);
        d += litLen;
        dst[d++] = (byte) offset;
        dst[d++] = (byte) (offset >>> 8);
        return emitLength(dst, d, matchExtra, 15);
    }

    private static int emitToken(byte[] dst, int d, int litLen, int matchExtra) {
        int hi = Math.min(litLen, 15);
        int lo = Math.min(matchExtra, 15);
        dst[d++] = (byte) ((hi << 4) | lo);
        return d;
    }

    private static int emitLength(byte[] dst, int d, int len, int threshold) {
        if (len < threshold) {
            return d;
        }
        int rest = len - threshold;
        while (rest >= 255) {
            dst[d++] = (byte) 255;
            rest -= 255;
        }
        dst[d++] = (byte) rest;
        return d;
    }

    private static boolean matches(byte[] src, int a, int b) {
        return src[a] == src[b] && src[a + 1] == src[b + 1]
                && src[a + 2] == src[b + 2] && src[a + 3] == src[b + 3];
    }

    private static int hash(byte[] src, int i) {
        int v = (src[i] & 0xFF) | ((src[i + 1] & 0xFF) << 8)
                | ((src[i + 2] & 0xFF) << 16) | ((src[i + 3] & 0xFF) << 24);
        return (v * 0x9E3779B1) >>> (32 - HASH_BITS);
    }
}
