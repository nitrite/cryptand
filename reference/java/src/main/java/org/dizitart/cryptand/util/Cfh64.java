package org.dizitart.cryptand.util;

/**
 * CFH-64, the filter hash — {@code spec/04-segments.md} §2.4.1.
 *
 * <p><strong>The hash is specified in the spec in full, rather than named, and
 * that is the whole point of it.</strong> Everything here is a wrapping 64-bit
 * multiply, an XOR, a logical shift or a rotate — no table, no secret, nothing
 * to look up — because a filter that disagrees between languages produces
 * <em>wrong results</em>, not slow ones: a false negative silently loses a key.
 *
 * <p>An earlier draft named XXH3-64: roughly 500 lines, seven length-dependent
 * branches and a 192-byte secret table, which made the single largest and least
 * verifiable primitive in Level 0 the one guarding the most dangerous failure.
 *
 * <p>CRC-32C was the other candidate, and it was already mandatory for every
 * page and would have been free. It is unusable here because <strong>CRC is
 * affine in its initial state</strong>: any pair of CRC-32C evaluations over the
 * same key carries 32 bits of entropy, not 64, and a finalizer spreads those
 * bits but cannot create more. Two keys colliding in 32 bits set identical
 * filter bits, so one is a <em>guaranteed</em> false positive whenever the other
 * is present. Measured over 4 000 000 random keys: the CRC pair produced 1868
 * collisions against 1863 predicted; CFH-64 produced none.
 *
 * <p>CFH-64 is used <strong>only</strong> for filters. It is not a checksum
 * ({@link Crc32c}) and not a MAC, and it MUST NOT be used where either is
 * required.
 */
public final class Cfh64 {

    private Cfh64() {
    }

    private static final long P1 = 0x9E3779B185EBCA87L;
    private static final long P2 = 0xC2B2AE3D27D4EB4FL;
    private static final long P3 = 0x165667B19E3779F9L;
    private static final long M1 = 0xBF58476D1CE4E5B9L;
    private static final long M2 = 0x94D049BB133111EBL;

    /** Unaligned little-endian 64-bit reads over a `byte[]`. */
    private static final java.lang.invoke.VarHandle LE64 =
            java.lang.invoke.MethodHandles.byteArrayViewVarHandle(
                    long[].class, java.nio.ByteOrder.LITTLE_ENDIAN);

    public static long hash(byte[] key) {
        return hash(key, 0, key.length);
    }

    public static long hash(byte[] key, int offset, int length) {
        long h = P1 ^ (length * P2);
        int i = 0;
        while (length - i >= 8) {
            // Little-endian, as everywhere outside CKE. Read as one unaligned
            // load: the eight-shift loop this replaces produces the identical
            // value and was 9 % of the point-read profile, because every filter
            // probe hashes its key. `byteArrayViewVarHandle` is the public,
            // intrinsified way to do it -- the same shape as the byte-at-a-time
            // CRC-32C this project already found once.
            long w = (long) LE64.get(key, offset + i);
            h ^= w * P2;
            h = Long.rotateLeft(h, 31) * P1;
            i += 8;
        }
        // The final 0..7 bytes, folded most-significant byte first.
        long tail = 0;
        while (i < length) {
            tail = (tail << 8) | (key[offset + i] & 0xFFL);
            i++;
        }
        h ^= tail * P3;
        h = Long.rotateLeft(h, 27) * P1;

        h = (h ^ (h >>> 30)) * M1;
        h = (h ^ (h >>> 27)) * M2;
        return h ^ (h >>> 31);
    }
}
