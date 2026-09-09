package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.util.Cfh64;

import java.util.Arrays;

/**
 * The segment membership filter — {@code spec/04-segments.md} §2.4.
 *
 * <p>A blocked Bloom filter, 512 bits per block, over every <strong>user
 * key</strong> in a segment: {@code u32be(tree_id) || CKE(key)}, <em>excluding</em>
 * {@code seq} and {@code op}, so all versions of one key share a single entry.
 *
 * <p>Specified to the bit, because a filter that disagrees between languages
 * produces <em>wrong results</em> rather than slow ones. A false positive costs
 * a wasted read; a false <em>negative</em> silently loses a key. That asymmetry
 * is why the bit order is written down — bit {@code b} of a block is bit
 * {@code b mod 8} of byte {@code b div 8}, counting from the least-significant
 * end — and why {@code probes} is stored rather than recomputed.
 *
 * <p>Blocking costs roughly 4.8x the false-positive rate of a classic Bloom
 * filter at the same bits per key (measured: 1.13% at 10 bits, 0.22–0.24% at
 * 16), and buys a probe that touches exactly one 64-byte block. On an
 * unencrypted file the filter therefore need not be resident at all.
 */
public final class BlockedBloom {

    /** {@code "CFP1"}. Stored as a little-endian u32, so the bytes read {@code 31 50 46 43}. */
    public static final int MAGIC = 0x43465031;

    /** 512 bits. */
    public static final int BLOCK_BITS = 512;
    public static final int BLOCK_BYTES = BLOCK_BITS / 8;

    /**
     * The filter page header is <strong>20 bytes</strong>, not 16: u32 magic,
     * u32 block_count, u16 bits_per_key, u16 probes, u64 distinct_keys.
     *
     * <p>The number is called out because a conformance vector once named a
     * 16-byte prefix of it {@code header_bytes} — the label stopped four bytes
     * into {@code distinct_keys}. An SDK trusting that name lays its blocks four
     * bytes early, every probe reads the wrong bits, and the result is false
     * <em>negatives</em>: the one filter failure that loses keys silently. A
     * self-generated vector set cannot contain that fix, because the generator
     * and its test both knew they were writing a prefix.
     */
    public static final int HEADER_BYTES = 20;

    private final int blockCount;
    private final int bitsPerKey;
    private final int probes;
    private final long distinctKeys;
    private final byte[] blocks;

    private BlockedBloom(int blockCount, int bitsPerKey, int probes, long distinctKeys, byte[] blocks) {
        this.blockCount = blockCount;
        this.bitsPerKey = bitsPerKey;
        this.probes = probes;
        this.distinctKeys = distinctKeys;
        this.blocks = blocks;
    }

    /** {@code u32be(tree_id) || CKE(key)} — the bytes the filter and the level order are both defined over. */
    public static byte[] userKey(int treeId, byte[] cke) {
        byte[] out = new byte[4 + cke.length];
        out[0] = (byte) (treeId >>> 24);
        out[1] = (byte) (treeId >>> 16);
        out[2] = (byte) (treeId >>> 8);
        out[3] = (byte) treeId;
        System.arraycopy(cke, 0, out, 4, cke.length);
        return out;
    }

    /** {@code block_count = max(1, ceil(entry_count * bits_per_key / 512))}. */
    public static int blockCountFor(long distinctKeys, int bitsPerKey) {
        long bits = distinctKeys * bitsPerKey;
        long blocks = (bits + BLOCK_BITS - 1) / BLOCK_BITS;
        return (int) Math.max(1, blocks);
    }

    /**
     * {@code k = max(1, min(16, round(bits_per_key * ln 2)))}.
     *
     * <p>Derived on write and <strong>stored</strong>. A reader MUST use the
     * stored value rather than recompute it, so that a future minor version can
     * change this derivation without invalidating existing files.
     */
    public static int probesFor(int bitsPerKey) {
        long k = Math.round(bitsPerKey * Math.log(2));
        return (int) Math.max(1, Math.min(16, k));
    }

    /** Builds a filter over {@code userKeys}, which must already be distinct. */
    public static BlockedBloom build(Iterable<byte[]> userKeys, long distinctKeys, int bitsPerKey) {
        int blockCount = blockCountFor(distinctKeys, bitsPerKey);
        int probes = probesFor(bitsPerKey);
        BlockedBloom f = new BlockedBloom(blockCount, bitsPerKey, probes, distinctKeys,
                new byte[blockCount * BLOCK_BYTES]);
        for (byte[] k : userKeys) {
            f.addHash(Cfh64.hash(k));
        }
        return f;
    }

    /**
     * The same filter from the keys' hashes rather than the keys.
     *
     * <p>A segment's user keys are prefixes of its internal keys, so a builder
     * that keeps them keeps a copy of every key in the segment — 20 000 array
     * allocations for a flush of 20 000 documents, held until the filter is
     * built at the end. {@link org.dizitart.cryptand.util.Cfh64} hashes a range
     * of an array, so the prefix can be hashed where it already is and only the
     * {@code long} kept.
     *
     * @param hashes {@code Cfh64.hash} of each distinct user key
     * @param count  how many of {@code hashes} are populated
     */
    public static BlockedBloom buildFromHashes(long[] hashes, int count, int bitsPerKey) {
        int blockCount = blockCountFor(count, bitsPerKey);
        int probes = probesFor(bitsPerKey);
        BlockedBloom f = new BlockedBloom(blockCount, bitsPerKey, probes, count,
                new byte[blockCount * BLOCK_BYTES]);
        for (int i = 0; i < count; i++) {
            f.addHash(hashes[i]);
        }
        return f;
    }

    private void addHash(long hash) {
        int base = blockOf(hash) * BLOCK_BYTES;
        int h1 = (int) hash;
        int h2 = (int) (hash >>> 32) | 1;
        for (int i = 0; i < probes; i++) {
            int bit = (h1 + i * h2) & (BLOCK_BITS - 1);
            blocks[base + (bit >>> 3)] |= (byte) (1 << (bit & 7));
        }
    }

    /**
     * Whether {@code userKey} may be in the segment.
     *
     * <p>False means it certainly is not. True means it probably is — that is
     * the only direction in which this structure is allowed to be wrong.
     */
    public boolean mayContain(byte[] userKey) {
        long hash = Cfh64.hash(userKey);
        int base = blockOf(hash) * BLOCK_BYTES;
        int h1 = (int) hash;
        int h2 = (int) (hash >>> 32) | 1;
        for (int i = 0; i < probes; i++) {
            int bit = (h1 + i * h2) & (BLOCK_BITS - 1);
            if ((blocks[base + (bit >>> 3)] & (1 << (bit & 7))) == 0) {
                return false;
            }
        }
        return true;
    }

    /** {@code block = (h1 * block_count) >> 32} — a u64 multiply, keeping the high half. */
    private int blockOf(long hash) {
        long h1 = hash & 0xFFFFFFFFL;
        return (int) ((h1 * blockCount) >>> 32);
    }

    public int blockCount() {
        return blockCount;
    }

    public int bitsPerKey() {
        return bitsPerKey;
    }

    public int probes() {
        return probes;
    }

    public long distinctKeys() {
        return distinctKeys;
    }

    public byte[] blocks() {
        return blocks.clone();
    }

    /** The 20-byte filter page header. */
    public byte[] header() {
        return new ByteWriter(HEADER_BYTES)
                .u32(MAGIC)
                .u32(blockCount)
                .u16(bitsPerKey)
                .u16(probes)
                .u64(distinctKeys)
                .toBytes();
    }

    /** The header followed by the blocks — the filter page payload. */
    public byte[] encode() {
        ByteWriter w = new ByteWriter(HEADER_BYTES + blocks.length);
        w.bytes(header()).bytes(blocks);
        return w.toBytes();
    }

    public static BlockedBloom decode(byte[] payload) {
        ByteReader r = new ByteReader(payload);
        int magic = r.u32();
        if (magic != MAGIC) {
            throw new CorruptionException(String.format(
                    "filter page magic is %08x, expected %08x", magic, MAGIC));
        }
        int blockCount = r.u32();
        int bitsPerKey = r.u16();
        int probes = r.u16();
        long distinctKeys = r.u64();
        if (blockCount < 1) {
            throw new CorruptionException("filter block_count is " + blockCount);
        }
        if (probes < 1 || probes > 16) {
            throw new CorruptionException("filter probes is " + probes + ", outside 1..16");
        }
        long needed = (long) blockCount * BLOCK_BYTES;
        if (needed > r.remaining()) {
            throw new LimitException("filter declares " + blockCount + " blocks (" + needed
                    + " bytes) but only " + r.remaining() + " remain");
        }
        return new BlockedBloom(blockCount, bitsPerKey, probes, distinctKeys, r.bytes((int) needed));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof BlockedBloom f
                && f.blockCount == blockCount
                && f.bitsPerKey == bitsPerKey
                && f.probes == probes
                && f.distinctKeys == distinctKeys
                && Arrays.equals(f.blocks, blocks);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(blocks) * 31 + blockCount;
    }
}
