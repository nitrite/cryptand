package org.dizitart.cryptand;

/**
 * A blob extent and its 16-byte pointer — {@code spec/01-container.md} §5.
 *
 * <p>For a value at or above {@code blob_threshold}. A blob is its own extent,
 * so a very large value is reclaimed on its own rather than pinning a shared
 * value-log segment, and it can be memory-mapped directly. A blob is never
 * rewritten by compaction.
 *
 * <pre>
 *   u64 start_page
 *   u32 byte_len     -- the PLAINTEXT length
 *   u32 crc32c
 * </pre>
 */
public record Blob(long startPage, int byteLen, int crc32c) {

    public static final int POINTER_BYTES = 16;

    public byte[] encode() {
        return new ByteWriter(POINTER_BYTES).u64(startPage).u32(byteLen).u32(crc32c).toBytes();
    }

    public static Blob decode(byte[] b) {
        if (b.length != POINTER_BYTES) {
            throw new CorruptionException("a BLOB pointer is " + POINTER_BYTES + " bytes, got " + b.length);
        }
        ByteReader r = new ByteReader(b);
        return new Blob(r.u64(), r.u32(), r.u32());
    }

    /**
     * Writes a blob as one contiguous, page-aligned extent. The head page has
     * {@code page_type = BLOB} and {@code flags.EXTENT_HEAD}; payload begins
     * after its 40-byte header, and the interior pages carry no header at all.
     */
    public static Blob write(Pager pager, byte[] value) {
        if (pager.crypto() instanceof FileCipher cipher) {
            return writeEncrypted(pager, cipher, value);
        }
        int pageSize = pager.pageSize();
        int firstPageRoom = pageSize - PageHeader.BYTES;
        int pages = value.length <= firstPageRoom
                ? 1
                : 1 + (value.length - firstPageRoom + pageSize - 1) / pageSize;
        long start = pager.allocate(pages);

        byte[] extent = new byte[pages * pageSize];
        System.arraycopy(value, 0, extent, PageHeader.BYTES, Math.min(firstPageRoom, value.length));
        if (value.length > firstPageRoom) {
            System.arraycopy(value, firstPageRoom, extent, pageSize, value.length - firstPageRoom);
        }
        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.BLOB;
        h.flags = PageHeader.Flags.EXTENT_HEAD;
        h.extentPages = pages;
        h.payloadLen = Math.min(firstPageRoom, value.length);
        h.commitId = pager.commitId();
        // The header's checksum covers only the head page, and the blob's own
        // integrity is the crc32c in the pointer - which is why the interior
        // pages need no header and no per-page checksum.
        byte[] head = new byte[pageSize];
        System.arraycopy(extent, PageHeader.BYTES, head, PageHeader.BYTES,
                Math.min(firstPageRoom, value.length));
        h.writeInto(head);
        System.arraycopy(head, 0, extent, 0, pageSize);

        pager.file().write(pager.offsetOf(start), extent);
        return new Blob(start, value.length, Crc32c.of(value, 0, value.length));
    }

    public byte[] read(Pager pager) {
        if (pager.crypto() instanceof FileCipher cipher) {
            return readEncrypted(pager, cipher);
        }
        int pageSize = pager.pageSize();
        int firstPageRoom = pageSize - PageHeader.BYTES;
        byte[] out = new byte[byteLen];
        int head = Math.min(firstPageRoom, byteLen);
        pager.file().readFully(pager.offsetOf(startPage) + PageHeader.BYTES, out, 0, head);
        if (byteLen > head) {
            pager.file().readFully(pager.offsetOf(startPage + 1), out, head, byteLen - head);
        }
        int actual = Crc32c.of(out, 0, out.length);
        if (actual != crc32c) {
            throw new CorruptionException(String.format(
                    "blob checksum mismatch: stored %08x, computed %08x", crc32c, actual), startPage, null);
        }
        return out;
    }

    /** Pages the extent occupies, so it can be freed. */
    public int pages(int pageSize) {
        int firstPageRoom = pageSize - PageHeader.BYTES;
        return byteLen <= firstPageRoom ? 1 : 1 + (byteLen - firstPageRoom + pageSize - 1) / pageSize;
    }

    /**
     * §5.4: an encrypted extent is chunked per page, not encrypted as one
     * stream, so a reader can decrypt the chunk it wants. Each chunk costs an
     * 8-byte counter and a 16-byte tag, so the extent needs
     * {@code ceil(len / (page_size - 24))} pages rather than
     * {@code ceil(len / page_size)} - about 0.6 % more space at 4 KiB pages.
     * The head page keeps its own 40-byte header, so its chunk is smaller.
     */
    public static int encryptedPages(int pageSize, int byteLen) {
        int headRoom = FileCipher.chunkPlaintextBytes(pageSize) - PageHeader.BYTES;
        if (byteLen <= headRoom) {
            return 1;
        }
        int rest = byteLen - headRoom;
        return 1 + (rest + FileCipher.chunkPlaintextBytes(pageSize) - 1)
                / FileCipher.chunkPlaintextBytes(pageSize);
    }

    private static Blob writeEncrypted(Pager pager, FileCipher cipher, byte[] value) {
        int pageSize = pager.pageSize();
        int chunk = FileCipher.chunkPlaintextBytes(pageSize);
        int headRoom = chunk - PageHeader.BYTES;
        int pages = encryptedPages(pageSize, value.length);
        long start = pager.allocate(pages);

        byte[] extent = new byte[pages * pageSize];
        int head = Math.min(headRoom, value.length);
        byte[] sealedHead = cipher.encryptChunk(start, 0, java.util.Arrays.copyOf(value, head));
        System.arraycopy(sealedHead, 0, extent, PageHeader.BYTES, sealedHead.length);

        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.BLOB;
        h.flags = PageHeader.Flags.EXTENT_HEAD | PageHeader.Flags.ENCRYPTED;
        h.extentPages = pages;
        h.payloadLen = head;
        h.storedLen = sealedHead.length;
        h.commitId = pager.commitId();
        byte[] headPage = new byte[pageSize];
        System.arraycopy(sealedHead, 0, headPage, PageHeader.BYTES, sealedHead.length);
        h.writeInto(headPage);
        System.arraycopy(headPage, 0, extent, 0, pageSize);

        int pos = head;
        for (int i = 1; i < pages; i++) {
            int n = Math.min(chunk, value.length - pos);
            byte[] sealed = cipher.encryptChunk(start, i, java.util.Arrays.copyOfRange(value, pos, pos + n));
            System.arraycopy(sealed, 0, extent, i * pageSize, sealed.length);
            pos += n;
        }
        pager.file().write(pager.offsetOf(start), extent);
        return new Blob(start, value.length, Crc32c.of(value, 0, value.length));
    }

    private byte[] readEncrypted(Pager pager, FileCipher cipher) {
        int pageSize = pager.pageSize();
        int chunk = FileCipher.chunkPlaintextBytes(pageSize);
        int headRoom = chunk - PageHeader.BYTES;
        int pages = encryptedPages(pageSize, byteLen);
        ByteWriter out = new ByteWriter(byteLen);
        byte[] page = new byte[pageSize];
        pager.file().readFully(pager.offsetOf(startPage), page, 0, pageSize);
        int headStored = 8 + Math.min(headRoom, byteLen) + 16;
        out.bytes(cipher.decryptChunk(startPage, 0,
                java.util.Arrays.copyOfRange(page, PageHeader.BYTES, PageHeader.BYTES + headStored)));
        for (int i = 1; i < pages; i++) {
            pager.file().readFully(pager.offsetOf(startPage + i), page, 0, pageSize);
            int remaining = byteLen - out.length();
            int n = Math.min(chunk, remaining);
            out.bytes(cipher.decryptChunk(startPage, i, java.util.Arrays.copyOf(page, 8 + n + 16)));
        }
        byte[] value = out.toBytes();
        int actual = Crc32c.of(value, 0, value.length);
        if (actual != crc32c) {
            throw new CorruptionException(String.format(
                    "blob checksum mismatch: stored %08x, computed %08x", crc32c, actual), startPage, null);
        }
        return value;
    }
}
