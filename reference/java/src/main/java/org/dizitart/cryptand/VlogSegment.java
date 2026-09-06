package org.dizitart.cryptand;

import java.util.Arrays;

/**
 * A value-log segment — {@code spec/04-segments.md} §6.2.
 *
 * <p>A page-aligned extent whose head page is written <strong>once</strong>,
 * when the extent is allocated, and never rewritten. It therefore holds only
 * the segment's immutable identity; everything that changes as it fills —
 * {@code bytes}, {@code records}, {@code sealed}, {@code clustered},
 * {@code min_key}, {@code max_key} and the liveness counters — lives in the
 * value-log stats tree, tree 7.
 *
 * <p>That split is not bookkeeping taste. {@code 01-container.md} §1 says no
 * page a live superblock references is ever overwritten; a mutable
 * {@code byte_len} in the head page would violate that on every append, and
 * would leave the page's CRC stale between the append and the rewrite — a page
 * that fails its own checksum for most of its life.
 */
public final class VlogSegment {

    /** {@code "CRY_VLG"} + {@code 0x1A}. */
    public static final byte[] MAGIC = {0x43, 0x52, 0x59, 0x5F, 0x56, 0x4C, 0x47, 0x1A};

    /** The head page's own 64-byte header, after the 40-byte page header. */
    public static final int HEAD_BYTES = 64;

    /**
     * {@code data_offset} — the page header plus this header, rounded up to 8.
     * It is written down rather than derived so a future minor version can grow
     * either header without changing how records are addressed.
     */
    public static final int DATA_OFFSET = PageHeader.BYTES + HEAD_BYTES;

    public static final int TIER_HOT = 0;
    public static final int TIER_COLD = 1;

    /** Heat classes, §6.6. A writer with no heat information MUST use {@link #HEAT_FIRST}. */
    public static final int HEAT_FIRST = 0;
    public static final int HEAT_WARM = 1;
    public static final int HEAT_HOT = 2;

    public long segmentId;
    public long createdSeq;
    /** Bytes of record space: {@code extent_pages * page_size - data_offset}. */
    public long capacity;
    public int dataOffset = DATA_OFFSET;
    public int tier;
    public int heatClass;
    public int codec;
    public int encrypted;
    public long nonceBase;

    public long startPage;
    public int pages;

    public byte[] encodeHeadPayload() {
        ByteWriter w = new ByteWriter(HEAD_BYTES);
        w.bytes(MAGIC);
        w.u64(segmentId).u64(createdSeq).u64(capacity);
        w.u32(dataOffset);
        w.u8(tier).u8(heatClass).u8(codec).u8(encrypted);
        w.u64(nonceBase);
        for (int i = 0; i < 16; i++) {
            w.u8(0);
        }
        if (w.length() != HEAD_BYTES) {
            throw new IllegalStateException("value-log head is " + w.length() + " bytes, expected " + HEAD_BYTES);
        }
        return w.toBytes();
    }

    public static VlogSegment decodeHeadPayload(byte[] payload) {
        ByteReader r = new ByteReader(payload);
        byte[] magic = r.bytes(8);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new CorruptionException("value-log head magic is "
                    + java.util.HexFormat.of().formatHex(magic) + ", expected 435259 5f564c471a");
        }
        VlogSegment s = new VlogSegment();
        s.segmentId = r.u64();
        s.createdSeq = r.u64();
        s.capacity = r.u64();
        s.dataOffset = r.u32();
        s.tier = r.u8();
        s.heatClass = r.u8();
        s.codec = r.u8();
        s.encrypted = r.u8();
        s.nonceBase = r.u64();
        return s;
    }

    // ==================================================================
    // records
    // ==================================================================

    /**
     * One value-log record. The key is stored <strong>with</strong> the value,
     * which is what makes garbage collection possible without a reverse index:
     * to test liveness, look the key up and check whether the live entry points
     * at this offset.
     */
    public record Record(int treeId, byte[] key, byte[] value) {

        /**
         * Encodes the record in the clear.
         *
         * <pre>
         *   uvar  record_len   -- bytes that follow, INCLUDING the trailing crc32c
         *   u32   tree_id
         *   uvar  key_len
         *   bytes key_len      -- CKE(key), NOT the internal key: no seq, no op
         *   uvar  value_len
         *   bytes value_len
         *   u32   crc32c       -- over `tree_id ... value`, as STORED
         * </pre>
         */
        public byte[] encode() {
            ByteWriter body = new ByteWriter(key.length + value.length + 16);
            body.u32(treeId);
            body.uvar(key.length).bytes(key);
            body.uvar(value.length).bytes(value);
            byte[] b = body.toBytes();
            int crc = Crc32c.of(b, 0, b.length);
            ByteWriter out = new ByteWriter(b.length + 16);
            out.uvar(b.length + 4L);
            out.bytes(b).u32(crc);
            return out.toBytes();
        }
    }

    /** The total on-disk size of a record encoding {@code key} and {@code value}, in the clear. */
    public static int recordSize(byte[] key, byte[] value) {
        return new Record(0, key, value).encode().length;
    }

    /**
     * The encrypted framing of §5.3.
     *
     * <pre>
     *   uvar  record_len   -- clear
     *   u64   counter      -- clear: this is what lets ONE record be decrypted
     *   u32   tree_id      -- clear, and in the AAD
     *   bytes ciphertext   -- `key_len || key || value_len || value`, plus the tag
     *   u32   crc32c       -- over the stored (ciphertext) bytes
     * </pre>
     *
     * <p>{@code record_len}, the counter and the CRC stay in the clear so a
     * segment can be walked, and its damage bounded, without the key. The CRC
     * covers the stored bytes, so it is computed over ciphertext: integrity
     * comes from the tag, error detection from the CRC, and §9.4 is emphatic
     * that these are not the same thing.
     */
    public static byte[] encodeEncrypted(Record rec, long segmentId, long offset,
                                         FileCipher cipher, long counter) {
        ByteWriter pt = new ByteWriter(rec.key().length + rec.value().length + 8);
        pt.uvar(rec.key().length).bytes(rec.key());
        pt.uvar(rec.value().length).bytes(rec.value());
        byte[] ct = cipher.encryptRecord(segmentId, offset, rec.treeId(), pt.toBytes(), counter);
        // The CRC covers `tree_id ... tag` and NOT the nonce: §5.3's table puts
        // the nonce between `record_len` and `tree_id`, and names the checksum's
        // scope as starting at `tree_id`.
        ByteWriter covered = new ByteWriter(ct.length + 4);
        covered.u32(rec.treeId()).bytes(ct);
        byte[] c = covered.toBytes();
        int crc = Crc32c.of(c, 0, c.length);
        ByteWriter out = new ByteWriter(c.length + 24);
        out.uvar(8L + c.length + 4L).u64(counter).bytes(c).u32(crc);
        return out.toBytes();
    }

    /**
     * The on-disk size an encrypted record will occupy at {@code offset}.
     *
     * <p>Needed before the reservation, because the reservation is what fixes
     * the offset, and the offset is in the nonce.
     */
    public static int encryptedRecordSize(byte[] key, byte[] value) {
        int ptLen = varLen(key.length) + key.length + varLen(value.length) + value.length;
        int bodyLen = 8 + 4 + ptLen + XChaCha20Poly1305.TAG_BYTES;
        return varLen(bodyLen + 4) + bodyLen + 4;
    }

    private static int varLen(long v) {
        int n = 1;
        while (Long.compareUnsigned(v, 0x80L) >= 0) {
            v >>>= 7;
            n++;
        }
        return n;
    }

    public static Record decodeEncryptedRecord(byte[] buf, int off, int limit,
                                               long segmentId, long offsetInExtent, FileCipher cipher) {
        ByteReader r = new ByteReader(buf, off, limit - off);
        long recordLen = r.uvar();
        if (recordLen < 13 || recordLen > r.remaining()) {
            throw new CorruptionException("encrypted value-log record declares " + recordLen
                    + " bytes but only " + r.remaining() + " remain");
        }
        int bodyStart = r.position();
        // The nonce is in the clear and outside the checksum's scope.
        int coveredStart = bodyStart + 8;
        int coveredLen = (int) recordLen - 8 - 4;
        int crcAt = coveredStart + coveredLen;
        int stored = (buf[crcAt] & 0xFF) | ((buf[crcAt + 1] & 0xFF) << 8)
                | ((buf[crcAt + 2] & 0xFF) << 16) | ((buf[crcAt + 3] & 0xFF) << 24);
        int actual = Crc32c.of(buf, coveredStart, coveredLen);
        if (stored != actual) {
            throw new CorruptionException(String.format(
                    "value-log record checksum mismatch: stored %08x, computed %08x", stored, actual));
        }
        long counter = r.u64();
        int treeId = r.u32();
        byte[] ct = r.bytes(coveredLen - 4);
        byte[] pt = cipher.decryptRecord(segmentId, offsetInExtent, treeId, ct, counter);
        ByteReader pr = new ByteReader(pt);
        int keyLen = pr.uvarLength("value-log record key");
        byte[] key = pr.bytes(keyLen);
        int valueLen = pr.uvarLength("value-log record value");
        return new Record(treeId, key, pr.bytes(valueLen));
    }

    /**
     * Decodes one record from {@code buf} at {@code off}, verifying its CRC.
     *
     * <p>The CRC covers the stored bytes, so on an encrypted segment it is
     * computed over ciphertext: integrity comes from the tag, error detection
     * from the CRC, and {@code 14-security.md} §9.4 is emphatic that these are
     * not the same thing.
     */
    public static Record decodeRecord(byte[] buf, int off, int limit) {
        ByteReader r = new ByteReader(buf, off, limit - off);
        long recordLen = r.uvar();
        if (recordLen < 5 || recordLen > r.remaining()) {
            throw new CorruptionException("value-log record declares " + recordLen
                    + " bytes but only " + r.remaining() + " remain");
        }
        int bodyStart = r.position();
        int bodyLen = (int) recordLen - 4;
        int crcAt = bodyStart + bodyLen;
        int stored = (buf[crcAt] & 0xFF) | ((buf[crcAt + 1] & 0xFF) << 8)
                | ((buf[crcAt + 2] & 0xFF) << 16) | ((buf[crcAt + 3] & 0xFF) << 24);
        int actual = Crc32c.of(buf, bodyStart, bodyLen);
        if (stored != actual) {
            throw new CorruptionException(String.format(
                    "value-log record checksum mismatch: stored %08x, computed %08x", stored, actual));
        }
        int treeId = r.u32();
        int keyLen = r.uvarLength("value-log record key");
        byte[] key = r.bytes(keyLen);
        int valueLen = r.uvarLength("value-log record value");
        byte[] value = r.bytes(valueLen);
        return new Record(treeId, key, value);
    }
}
