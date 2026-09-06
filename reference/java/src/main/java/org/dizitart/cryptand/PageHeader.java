package org.dizitart.cryptand;

/**
 * The 40-byte page header — {@code spec/01-container.md} §3.
 *
 * <p>Every page except the two superblocks begins with one, with a single
 * exception that three chapters depend on: <strong>a multi-page extent carries
 * a page header only on its head page</strong>. The interior pages of a
 * value-log segment, a blob and a vector region hold raw payload with no header
 * and no per-page checksum, because their payload is a byte stream that crosses
 * page boundaries. Integrity for those comes from the extent's own mechanism —
 * a per-record CRC for value-log records, the CRC in the blob pointer for a
 * blob, and nothing at all for a vector region, deliberately, because a region
 * is rebuildable from the documents. A verifier MUST NOT report a missing page
 * header on those pages as corruption.
 *
 * <p>The checksum verifies <em>before</em> decompression and <em>before</em>
 * decryption, so a corrupt page is never fed to a codec or a cipher.
 */
public final class PageHeader {

    /** 40 bytes. Every field is naturally aligned within it. */
    public static final int BYTES = 40;

    /** {@code page_type}, offset 4 — §4. */
    public static final class Type {
        private Type() {
        }

        public static final int FREE = 0;
        public static final int BTREE_INTERNAL = 1;
        public static final int BTREE_LEAF = 2;
        public static final int OVERFLOW = 3;
        public static final int BLOB = 4;
        public static final int SEGMENT_HEADER = 5;
        public static final int SEGMENT_FILTER = 6;
        public static final int VLOG_SEGMENT = 7;
        public static final int RTREE_INTERNAL = 8;
        public static final int RTREE_LEAF = 9;
        public static final int VECTOR_REGION = 10;
        public static final int POSTINGS_BLOCK = 11;

        /** 12–191 are reserved for future minor versions. */
        public static final int FIRST_RESERVED = 12;

        /**
         * 192–255 are implementation-private. A reader MUST ignore these pages
         * and MUST NOT reuse their space unless it also owns the feature bit
         * that allocated them.
         */
        public static final int FIRST_PRIVATE = 192;

        public static boolean isPrivate(int type) {
            return type >= FIRST_PRIVATE && type <= 255;
        }
    }

    /** {@code flags}, offset 5. */
    public static final class Flags {
        private Flags() {
        }

        public static final int COMPRESSED = 1;
        public static final int ENCRYPTED = 1 << 1;
        public static final int HAS_OVERFLOW = 1 << 2;
        public static final int EXTENT_HEAD = 1 << 3;
    }

    public int checksum;
    public int pageType;
    public int flags;
    /** Codec id when {@link Flags#COMPRESSED}, otherwise reserved. */
    public int codecOrReserved;
    /** Owning tree; {@link TreeId#NONE} for segment, value-log, blob and vector-region pages. */
    public int treeId = TreeId.NONE;
    /** 1 for an ordinary page; greater than 1 for a multi-page extent head. */
    public int extentPages = 1;
    /** The commit that wrote this page — drives reclamation. */
    public long commitId;
    /** Uncompressed, unencrypted payload length. */
    public int payloadLen;
    /**
     * Payload bytes <strong>as stored</strong>, after compression and after
     * encryption; 0 means "same as {@link #payloadLen}".
     *
     * <p>Both lengths exist because neither is sufficient alone. A decryptor
     * needs the <em>exact</em> stored length, because Poly1305 covers exactly
     * the ciphertext and one byte either way fails the tag; a decompressor needs
     * the <em>plaintext</em> length, because that is the output size it decodes
     * into. Compressed <em>and</em> encrypted needs both at once. An earlier
     * draft left this reserved and defined {@code payload_len} alone while
     * chapter 14 said the AEAD tag was inside it — the two cannot both hold, and
     * both reference implementations hit it the moment either wrote an
     * encrypted page.
     */
    public int storedLen;
    /** The allocated {@code next_nonce} when {@link Flags#ENCRYPTED}; 0 otherwise. */
    public long nonce;

    public boolean isSet(int flag) {
        return (flags & flag) != 0;
    }

    /** The number of payload bytes actually on the page. */
    public int storedBytes() {
        return storedLen == 0 ? payloadLen : storedLen;
    }

    /**
     * Writes this header at offset 0 of {@code page} and computes the checksum
     * over bytes {@code 4 … page.length-1}.
     *
     * <p>The checksum must be computed last and over the page <em>as stored</em>
     * — after compression and after encryption — so verification precedes
     * decoding. Call this once the payload is already in place.
     */
    public void writeInto(byte[] page) {
        writeInto(page, page.length);
    }

    /**
     * As {@link #writeInto(byte[])}, but with the checksum covering only bytes
     * {@code 4 … checksumEnd-1}.
     *
     * <p>Exactly one page needs this: a value-log segment's head page. Its
     * record space begins at {@code data_offset} — byte 104, which is
     * <em>inside</em> the head page — and records are appended there for the
     * life of the segment. A checksum over the whole page would be invalidated
     * by the first append, leaving a page that fails its own checksum for most
     * of its life. That is the same argument {@code spec/04-segments.md} §6.2
     * makes when it moves the mutable {@code bytes} watermark out of the head
     * page and into tree 7, and it applies here verbatim.
     *
     * <p>Nothing is left unprotected by narrowing it: {@code 01-container.md}
     * §3 already says the record bytes take their integrity from the per-record
     * {@code crc32c}, not from any page checksum.
     */
    public void writeInto(byte[] page, int checksumEnd) {
        if (page.length < BYTES) {
            throw new InvalidArgumentException("page is " + page.length + " bytes, header needs " + BYTES);
        }
        ByteWriter w = new ByteWriter(BYTES);
        w.u32(0); // checksum, filled in below
        w.u8(pageType).u8(flags).u16(codecOrReserved);
        w.u32(treeId).u32(extentPages);
        w.u64(commitId);
        w.u32(payloadLen).u32(storedLen);
        w.u64(nonce);
        byte[] h = w.toBytes();
        if (h.length != BYTES) {
            throw new IllegalStateException("page header is " + h.length + " bytes, expected " + BYTES);
        }
        System.arraycopy(h, 0, page, 0, BYTES);

        checksum = Crc32c.of(page, 4, checksumEnd - 4);
        page[0] = (byte) checksum;
        page[1] = (byte) (checksum >>> 8);
        page[2] = (byte) (checksum >>> 16);
        page[3] = (byte) (checksum >>> 24);
    }

    /** The 40 header bytes on their own, with {@link #checksum} written as given. */
    public byte[] toBytes() {
        ByteWriter w = new ByteWriter(BYTES);
        w.u32(checksum);
        w.u8(pageType).u8(flags).u16(codecOrReserved);
        w.u32(treeId).u32(extentPages);
        w.u64(commitId);
        w.u32(payloadLen).u32(storedLen);
        w.u64(nonce);
        return w.toBytes();
    }

    /** Parses a header without verifying the checksum — see {@link #verify}. */
    public static PageHeader parse(byte[] page, int offset) {
        ByteReader r = new ByteReader(page, offset, BYTES);
        PageHeader h = new PageHeader();
        h.checksum = r.u32();
        h.pageType = r.u8();
        h.flags = r.u8();
        h.codecOrReserved = r.u16();
        h.treeId = r.u32();
        h.extentPages = r.u32();
        h.commitId = r.u64();
        h.payloadLen = r.u32();
        h.storedLen = r.u32();
        h.nonce = r.u64();
        return h;
    }

    /**
     * Parses and verifies a whole page.
     *
     * <p>{@code spec/00-conventions.md} §9: a checksum mismatch is corruption,
     * it names the page, and the page is not used. It is <em>not</em> the same
     * as a failed AEAD tag, which is tampering and must not be repaired.
     */
    public static PageHeader verify(byte[] page, long pageId) {
        return verify(page, pageId, page.length);
    }

    /** Verifies with the checksum scope of {@link #writeInto(byte[], int)}. */
    public static PageHeader verify(byte[] page, long pageId, int checksumEnd) {
        PageHeader h = parse(page, 0);
        int actual = Crc32c.of(page, 4, checksumEnd - 4);
        if (actual != h.checksum) {
            throw new CorruptionException(String.format(
                    "page checksum mismatch: stored %08x, computed %08x", h.checksum, actual), pageId, null);
        }
        int limit = page.length - BYTES;
        if (h.payloadLen < 0 || h.payloadLen > limit) {
            throw new CorruptionException(
                    "payload_len " + Integer.toUnsignedString(h.payloadLen) + " does not fit the page", pageId, null);
        }
        if (h.storedLen < 0 || h.storedLen > limit) {
            throw new CorruptionException(
                    "stored_len " + Integer.toUnsignedString(h.storedLen) + " does not fit the page", pageId, null);
        }
        if (h.extentPages < 1) {
            // §3 says extent_pages is "1 for an ordinary page; > 1 for a
            // multi-page extent head", and this implementation always writes 1.
            // On a page that is NOT an extent head the field is pure redundancy
            // - the page is one page by definition - so a 0 there is read as 1
            // rather than refused. The Rust reference writes 0 on every ordinary
            // page, and refusing it would make a file that is otherwise
            // perfectly readable unopenable, which is the opposite of what
            // 00-conventions.md §9 resolves ambiguity toward.
            //
            // On an extent HEAD it stays corruption: there the field is the only
            // record of how far the extent runs, and guessing it would be
            // guessing at the size of something.
            if (h.isSet(Flags.EXTENT_HEAD)) {
                throw new CorruptionException("extent_pages is " + h.extentPages
                        + " on an extent head, which is the only record of the extent's length",
                        pageId, null);
            }
            // Accepted, and deliberately NOT rewritten to 1: §5.2's AAD is "the
            // 40-byte page header with `checksum` zeroed", so every other field
            // has to stay exactly as stored or the tag fails. Normalizing it
            // here made Java unable to decrypt a page Rust wrote while Rust
            // could still decrypt Java's - an asymmetry that only a
            // cross-implementation test can produce.
        }
        return h;
    }
}
