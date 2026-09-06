package org.dizitart.cryptand;

import java.util.Arrays;

/**
 * Argon2id (RFC 9106), the password-stretching primitive of
 * {@code spec/14-security.md} §3.2 — version 0x13, type 2.
 *
 * <p>Named to the parameter rather than described, because a format that said
 * "a memory-hard KDF" would have two SDKs derive different keys from one
 * password and neither able to open the other's file.
 *
 * <p>The memory cost is transient and much larger than the engine's entire
 * steady-state budget — 64 MiB against {@code mobile}'s 4 MiB page cache. It is
 * allocated, used and released before opening proceeds, and never held for the
 * life of the database.
 */
public final class Argon2id {

    private Argon2id() {
    }

    private static final int BLOCK_BYTES = 1024;
    private static final int QWORDS = BLOCK_BYTES / 8;
    private static final int VERSION = 0x13;
    private static final int TYPE_ID = 2;

    /** §3.2's floors, checked when <em>creating</em> a keyslot. */
    public static final int MIN_T_COST = 2;
    public static final int MIN_M_COST_KIB = 16384;

    /**
     * On <em>create</em> a writer must reject weak parameters. On <em>open</em>
     * it MUST use whatever the slot says: the superblock MAC is what prevents
     * an attacker weakening those numbers, and deriving under different ones
     * yields a different KEK and reports "wrong password" for a correct one.
     */
    public static void checkCreateParameters(int tCost, int mCostKib, int parallelism) {
        if (tCost < MIN_T_COST) {
            throw new InvalidArgumentException("Argon2id t_cost " + tCost + " is below the floor of " + MIN_T_COST);
        }
        if (mCostKib < MIN_M_COST_KIB) {
            throw new InvalidArgumentException(
                    "Argon2id m_cost_kib " + mCostKib + " is below the floor of " + MIN_M_COST_KIB);
        }
        if (parallelism < 1) {
            throw new InvalidArgumentException("Argon2id parallelism " + parallelism + " is below 1");
        }
    }

    public static byte[] hash(byte[] password, byte[] salt, int tCost, int mCostKib,
                              int parallelism, int outputLength) {
        return hash(password, salt, new byte[0], new byte[0], tCost, mCostKib, parallelism, outputLength);
    }

    /**
     * The full RFC 9106 parameter set, secret key and associated data included.
     *
     * <p>This format uses neither — §3.2 names only {@code t_cost},
     * {@code m_cost_kib} and {@code parallelism} — but the RFC's own test
     * vector exercises both, and being checkable against the standard rather
     * than against another implementation is the property §2 is chosen for.
     */
    public static byte[] hash(byte[] password, byte[] salt, byte[] secret, byte[] associatedData,
                              int tCost, int mCostKib, int parallelism, int outputLength) {
        if (parallelism < 1 || tCost < 1 || mCostKib < 8 * parallelism) {
            throw new InvalidArgumentException("Argon2id parameters out of range: t=" + tCost
                    + " m=" + mCostKib + " p=" + parallelism);
        }
        int m = (mCostKib / (4 * parallelism)) * (4 * parallelism);
        int laneLength = m / parallelism;
        int segmentLength = laneLength / 4;

        byte[] h0 = initialHash(password, salt, secret, associatedData, tCost, m, parallelism, outputLength);

        long[][] blocks = new long[m][QWORDS];
        for (int lane = 0; lane < parallelism; lane++) {
            blocks[lane * laneLength] = toBlock(variableHash(BLOCK_BYTES, concat(h0, le32(0), le32(lane))));
            blocks[lane * laneLength + 1] = toBlock(variableHash(BLOCK_BYTES, concat(h0, le32(1), le32(lane))));
        }

        for (int pass = 0; pass < tCost; pass++) {
            for (int slice = 0; slice < 4; slice++) {
                for (int lane = 0; lane < parallelism; lane++) {
                    fillSegment(blocks, pass, lane, slice, parallelism, laneLength, segmentLength, tCost);
                }
            }
        }

        long[] finalBlock = blocks[laneLength - 1].clone();
        for (int lane = 1; lane < parallelism; lane++) {
            long[] b = blocks[lane * laneLength + laneLength - 1];
            for (int i = 0; i < QWORDS; i++) {
                finalBlock[i] ^= b[i];
            }
        }
        byte[] out = variableHash(outputLength, fromBlock(finalBlock));
        for (long[] b : blocks) {
            Arrays.fill(b, 0L);
        }
        return out;
    }

    private static byte[] initialHash(byte[] password, byte[] salt, byte[] secret, byte[] ad,
                                      int tCost, int m, int parallelism, int outputLength) {
        Blake2b b = new Blake2b(64);
        b.update(le32(parallelism));
        b.update(le32(outputLength));
        b.update(le32(m));
        b.update(le32(tCost));
        b.update(le32(VERSION));
        b.update(le32(TYPE_ID));
        b.update(le32(password.length));
        b.update(password);
        b.update(le32(salt.length));
        b.update(salt);
        b.update(le32(secret.length));
        b.update(secret);
        b.update(le32(ad.length));
        b.update(ad);
        return b.digest();
    }

    /** RFC 9106's {@code H'}: BLAKE2b for short outputs, and a chain of 64-byte hashes beyond. */
    static byte[] variableHash(int outLen, byte[] input) {
        byte[] lenPrefixed = concat(le32(outLen), input);
        if (outLen <= 64) {
            return new Blake2b(outLen).update(lenPrefixed).digest();
        }
        byte[] out = new byte[outLen];
        byte[] v = new Blake2b(64).update(lenPrefixed).digest();
        System.arraycopy(v, 0, out, 0, 32);
        int pos = 32;
        int remaining = outLen - 32;
        while (remaining > 64) {
            v = new Blake2b(64).update(v).digest();
            System.arraycopy(v, 0, out, pos, 32);
            pos += 32;
            remaining -= 32;
        }
        v = new Blake2b(remaining).update(v).digest();
        System.arraycopy(v, 0, out, pos, remaining);
        return out;
    }

    private static void fillSegment(long[][] blocks, int pass, int lane, int slice, int parallelism,
                                    int laneLength, int segmentLength, int tCost) {
        // Argon2id: the first two slices of the first pass address like
        // Argon2i (data-independent), everything after like Argon2d.
        boolean dataIndependent = pass == 0 && slice < 2;
        long[] addressBlock = null;
        long[] inputBlock = null;
        long[] zeroBlock = null;
        if (dataIndependent) {
            addressBlock = new long[QWORDS];
            inputBlock = new long[QWORDS];
            zeroBlock = new long[QWORDS];
            inputBlock[0] = pass;
            inputBlock[1] = lane;
            inputBlock[2] = slice;
            inputBlock[3] = laneLength * parallelism;
            inputBlock[4] = tCost;
            inputBlock[5] = TYPE_ID;
        }

        int startIndex = (pass == 0 && slice == 0) ? 2 : 0;
        int curOffset = lane * laneLength + slice * segmentLength + startIndex;
        int prevOffset = curOffset % laneLength == 0 ? curOffset + laneLength - 1 : curOffset - 1;

        for (int i = startIndex; i < segmentLength; i++, curOffset++, prevOffset++) {
            if (curOffset % laneLength == 1) {
                prevOffset = curOffset - 1;
            }
            long pseudoRandom;
            if (dataIndependent) {
                if (i % QWORDS == 0) {
                    inputBlock[6]++;
                    fillBlock(zeroBlock, inputBlock, addressBlock, false);
                    fillBlock(zeroBlock, addressBlock, addressBlock, false);
                }
                pseudoRandom = addressBlock[i % QWORDS];
            } else {
                pseudoRandom = blocks[prevOffset][0];
            }
            int refLane = (int) (Long.remainderUnsigned(pseudoRandom >>> 32, parallelism));
            if (pass == 0 && slice == 0) {
                refLane = lane;
            }
            int refIndex = referenceIndex(pass, slice, i, segmentLength, laneLength,
                    refLane == lane, (int) (pseudoRandom & 0xFFFFFFFFL));
            long[] refBlock = blocks[refLane * laneLength + refIndex];
            fillBlock(blocks[prevOffset], refBlock, blocks[curOffset], pass != 0);
        }
    }

    private static int referenceIndex(int pass, int slice, int index, int segmentLength,
                                      int laneLength, boolean sameLane, int random) {
        long referenceAreaSize;
        if (pass == 0) {
            referenceAreaSize = sameLane
                    ? slice * segmentLength + index - 1
                    : slice * segmentLength - (index == 0 ? 1 : 0);
        } else {
            referenceAreaSize = sameLane
                    ? laneLength - segmentLength + index - 1
                    : laneLength - segmentLength - (index == 0 ? 1 : 0);
        }
        long r = random & 0xFFFFFFFFL;
        long relative = (r * r) >>> 32;
        relative = referenceAreaSize - 1 - ((referenceAreaSize * relative) >>> 32);
        long start = pass == 0 ? 0 : (slice == 3 ? 0 : (long) (slice + 1) * segmentLength);
        return (int) ((start + relative) % laneLength);
    }

    private static void fillBlock(long[] prev, long[] ref, long[] next, boolean withXor) {
        long[] r = new long[QWORDS];
        for (int i = 0; i < QWORDS; i++) {
            r[i] = prev[i] ^ ref[i];
        }
        long[] z = r.clone();
        for (int i = 0; i < 8; i++) {
            int o = i * 16;
            permute(z, o, o + 1, o + 2, o + 3, o + 4, o + 5, o + 6, o + 7,
                    o + 8, o + 9, o + 10, o + 11, o + 12, o + 13, o + 14, o + 15);
        }
        for (int i = 0; i < 8; i++) {
            int o = i * 2;
            permute(z, o, o + 1, o + 16, o + 17, o + 32, o + 33, o + 48, o + 49,
                    o + 64, o + 65, o + 80, o + 81, o + 96, o + 97, o + 112, o + 113);
        }
        for (int i = 0; i < QWORDS; i++) {
            long v = r[i] ^ z[i];
            next[i] = withXor ? next[i] ^ v : v;
        }
    }

    private static void permute(long[] v, int... i) {
        blamka(v, i[0], i[4], i[8], i[12]);
        blamka(v, i[1], i[5], i[9], i[13]);
        blamka(v, i[2], i[6], i[10], i[14]);
        blamka(v, i[3], i[7], i[11], i[15]);
        blamka(v, i[0], i[5], i[10], i[15]);
        blamka(v, i[1], i[6], i[11], i[12]);
        blamka(v, i[2], i[7], i[8], i[13]);
        blamka(v, i[3], i[4], i[9], i[14]);
    }

    private static void blamka(long[] v, int a, int b, int c, int d) {
        v[a] = fbla(v[a], v[b]);
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = fbla(v[c], v[d]);
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = fbla(v[a], v[b]);
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = fbla(v[c], v[d]);
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    /** {@code f(x, y) = x + y + 2 * lower32(x) * lower32(y)}. */
    private static long fbla(long x, long y) {
        return x + y + 2 * (x & 0xFFFFFFFFL) * (y & 0xFFFFFFFFL);
    }

    private static long[] toBlock(byte[] bytes) {
        long[] out = new long[QWORDS];
        for (int i = 0; i < QWORDS; i++) {
            long v = 0;
            for (int j = 7; j >= 0; j--) {
                v = (v << 8) | (bytes[i * 8 + j] & 0xFFL);
            }
            out[i] = v;
        }
        return out;
    }

    private static byte[] fromBlock(long[] block) {
        byte[] out = new byte[BLOCK_BYTES];
        for (int i = 0; i < QWORDS; i++) {
            for (int j = 0; j < 8; j++) {
                out[i * 8 + j] = (byte) (block[i] >>> (8 * j));
            }
        }
        return out;
    }

    private static byte[] le32(int v) {
        return new byte[]{(byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24)};
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int i = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, i, p.length);
            i += p.length;
        }
        return out;
    }
}
