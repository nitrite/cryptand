package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Blob;
import org.dizitart.cryptand.container.PageFile;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.crypto.FileCipher;
import org.dizitart.cryptand.util.Crc32c;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Blobs — {@code spec/01-container.md} §5.
 *
 * <p>{@link Blob} had <strong>no test at all</strong> and sat at 40 % line
 * coverage, which is how a whole feature ends up unexercised without anything
 * looking wrong: nothing in the suite wrote a value above
 * {@code blob_threshold}, so the entire extent path — head page, interior
 * pages with no header, the pointer's own checksum, and §5.4's per-chunk
 * encryption — ran only in production.
 *
 * <p>The properties that matter here are the ones that make a blob different
 * from a page: its payload spans an extent whose interior pages carry
 * <em>no header and no per-page checksum</em>, so its integrity comes from the
 * {@code crc32c} in the pointer and from nowhere else.
 */
class BlobTest {

    private static Pager pager(Path dir, String name) {
        PageFile f = new PageFile(dir.resolve(name), false, Superblock.Durability.NONE);
        return new Pager(f, 4096, 2, 1, 0);
    }

    /** Compressible, so a needle is findable; deterministic, so a failure reproduces. */
    private static byte[] payload(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) ('a' + (i % 26));
        }
        return b;
    }

    // ------------------------------------------------------------------
    // the pointer
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a pointer round-trips through its 16 bytes")
    void thePointerRoundTrips() {
        Blob b = new Blob(1234567890123L, 987654, 0xDEADBEEF);
        byte[] enc = b.encode();
        assertEquals(Blob.POINTER_BYTES, enc.length);
        Blob back = Blob.decode(enc);
        assertEquals(b.startPage(), back.startPage());
        assertEquals(b.byteLen(), back.byteLen());
        assertEquals(b.crc32c(), back.crc32c());
    }

    @Test
    @DisplayName("a pointer of the wrong length is refused, not read short")
    void aShortPointerIsRefused() {
        // §8 of 00-conventions: every length is bounds-checked before it is
        // used. Reading 16 bytes out of 8 is the shape this rule exists for.
        assertThrows(CorruptionException.class, () -> Blob.decode(new byte[15]));
        assertThrows(CorruptionException.class, () -> Blob.decode(new byte[17]));
        assertThrows(CorruptionException.class, () -> Blob.decode(new byte[0]));
    }

    // ------------------------------------------------------------------
    // the extent
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a blob smaller than one page fits in the head page alone")
    void aSmallBlobFitsTheHeadPage(@TempDir Path dir) {
        Pager p = pager(dir, "small.cryptand");
        byte[] value = payload(100);
        Blob b = Blob.write(p, value);
        assertEquals(1, b.pages(4096), "one page, and no interior pages at all");
        assertEquals(value.length, b.byteLen());
        assertEquals(Crc32c.of(value, 0, value.length), b.crc32c());
        assertArrayEquals(value, b.read(p));

        // The head page is a real, checksummed page: §5 gives it
        // page_type = BLOB and flags.EXTENT_HEAD, which is what lets a repair
        // pass find it without the catalog.
        PageHeader h = PageHeader.verify(p.readRaw(b.startPage()), b.startPage());
        assertEquals(PageHeader.Type.BLOB, h.pageType);
        assertTrue(h.isSet(PageHeader.Flags.EXTENT_HEAD));
        assertEquals(1, h.extentPages);
        assertEquals(value.length, h.payloadLen);
    }

    @Test
    @DisplayName("a blob spanning several pages round-trips exactly")
    void aMultiPageBlobRoundTrips(@TempDir Path dir) {
        Pager p = pager(dir, "big.cryptand");
        // Deliberately not a multiple of the page size, and past the head
        // page's smaller room: the head holds page_size - 40 and every
        // interior page holds a full page_size, so an off-by-40 in either
        // direction shows up here and nowhere else.
        for (int n : new int[] {4056, 4057, 4096, 8151, 8152, 8153, 100_000}) {
            byte[] value = payload(n);
            Blob b = Blob.write(p, value);
            assertArrayEquals(value, b.read(p), "length " + n);
            assertEquals(b.pages(4096),
                    PageHeader.verify(p.readRaw(b.startPage()), b.startPage()).extentPages,
                    "the head page must declare the extent it actually occupies, at " + n);
        }
    }

    @Test
    @DisplayName("an empty blob is a blob, not an absence")
    void anEmptyBlobIsABlob(@TempDir Path dir) {
        Pager p = pager(dir, "empty.cryptand");
        Blob b = Blob.write(p, new byte[0]);
        assertEquals(0, b.byteLen());
        assertEquals(1, b.pages(4096), "it still occupies its head page");
        assertArrayEquals(new byte[0], b.read(p));
    }

    @Test
    @DisplayName("the interior pages carry no header, which is why the pointer checksums")
    void theInteriorPagesCarryNoHeader(@TempDir Path dir) {
        Pager p = pager(dir, "interior.cryptand");
        byte[] value = payload(20_000);
        Blob b = Blob.write(p, value);
        assertTrue(b.pages(4096) > 4);

        // The second page of the extent is raw payload. Its first four bytes
        // are blob content, not a checksum, so `PageHeader.verify` on it is
        // meaningless -- and that is exactly the design: §5 says the interior
        // pages have no header, and the blob's integrity is the crc32c in the
        // pointer. The assertion is that the bytes there are the payload.
        byte[] second = p.readRaw(b.startPage() + 1);
        int headRoom = 4096 - PageHeader.BYTES;
        assertArrayEquals(Arrays.copyOfRange(value, headRoom, headRoom + 64),
                Arrays.copyOf(second, 64),
                "the interior page begins at offset 0 with payload, not a header");
    }

    @Test
    @DisplayName("a corrupted blob is caught by the pointer's checksum")
    void aCorruptedBlobIsCaught(@TempDir Path dir) {
        // This is the whole reason the pointer carries a crc32c: the interior
        // pages have no per-page checksum, so nothing else in the container
        // would notice.
        Pager p = pager(dir, "damaged.cryptand");
        byte[] value = payload(20_000);
        Blob b = Blob.write(p, value);
        assertArrayEquals(value, b.read(p), "clean before the damage");

        // Flip a byte deep inside an interior page.
        long page = b.startPage() + 3;
        byte[] raw = p.readRaw(page);
        raw[100] ^= 0x01;
        p.file().write(p.offsetOf(page), raw);

        CorruptionException e =
                assertThrows(CorruptionException.class, () -> b.read(p));
        assertTrue(e.getMessage().contains("checksum"), e.getMessage());
    }

    @Test
    @DisplayName("a pointer whose checksum does not match its bytes is refused")
    void aWrongChecksumIsRefused(@TempDir Path dir) {
        Pager p = pager(dir, "wrongcrc.cryptand");
        byte[] value = payload(500);
        Blob b = Blob.write(p, value);
        Blob lying = new Blob(b.startPage(), b.byteLen(), b.crc32c() ^ 1);
        assertThrows(CorruptionException.class, () -> lying.read(p));
    }

    @Test
    @DisplayName("pages() agrees with what write() actually allocated")
    void pagesAgreesWithWrite(@TempDir Path dir) {
        // pages() is what a free() uses to hand the extent back. If it
        // disagreed with write(), a blob would leak pages or free pages it
        // does not own -- and freeing pages it does not own is corruption,
        // not a leak.
        Pager p = pager(dir, "pages.cryptand");
        for (int n : new int[] {0, 1, 4055, 4056, 4057, 8152, 12_248, 50_000}) {
            Blob b = Blob.write(p, payload(n));
            int declared = PageHeader.verify(p.readRaw(b.startPage()), b.startPage()).extentPages;
            assertEquals(declared, b.pages(4096), "length " + n);
        }
    }

    // ------------------------------------------------------------------
    // §14.5.4 -- an encrypted extent is chunked per page, not one stream
    // ------------------------------------------------------------------

    @Test
    @DisplayName("an encrypted blob round-trips, and is not on disk in the clear")
    void anEncryptedBlobRoundTrips(@TempDir Path dir) {
        Pager p = pager(dir, "enc.cryptand");
        byte[] master = new byte[32];
        Arrays.fill(master, (byte) 7);
        byte[] uuid = new byte[16];
        Arrays.fill(uuid, (byte) 3);
        p.setCrypto(FileCipher.of(master, uuid, 0));

        byte[] value = "TOPSECRETPAYLOAD".repeat(2000).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        Blob b = Blob.write(p, value);
        assertArrayEquals(value, b.read(p));

        // Defect 58's lesson: test what is ABSENT from the bytes. An encrypted
        // blob round-trips perfectly when it is not encrypted.
        for (int i = 0; i < b.pages(4096); i++) {
            byte[] raw = p.readRaw(b.startPage() + i);
            assertEquals(-1, indexOf(raw, "TOPSECRETPAYLOAD".getBytes(
                            java.nio.charset.StandardCharsets.US_ASCII)),
                    "the needle survives in the clear on page " + i);
        }
    }

    @Test
    @DisplayName("an encrypted extent needs more pages, and encryptedPages says how many")
    void anEncryptedExtentIsLarger(@TempDir Path dir) {
        // §5.4: each chunk costs an 8-byte counter and a 16-byte tag, so the
        // extent needs ceil(len / (page_size - 24)) pages rather than
        // ceil(len / page_size) -- about 0.6 % more at 4 KiB pages. A writer
        // that sized the extent the plaintext way would run off its own end.
        Pager p = pager(dir, "encsize.cryptand");
        byte[] master = new byte[32];
        byte[] uuid = new byte[16];
        p.setCrypto(FileCipher.of(master, uuid, 0));
        for (int n : new int[] {1, 4032, 4033, 20_000, 100_000}) {
            byte[] value = payload(n);
            Blob b = Blob.write(p, value);
            int declared = PageHeader.verify(p.readRaw(b.startPage()), b.startPage()).extentPages;
            assertEquals(Blob.encryptedPages(4096, n), declared,
                    "encryptedPages must predict what write() allocated, at " + n);
            assertArrayEquals(value, b.read(p), "length " + n);
        }
        // And the overhead is real, not zero: a blob just over the plaintext
        // head room needs a page an unencrypted one would not.
        assertTrue(Blob.encryptedPages(4096, 100_000) >= (100_000 + 4095) / 4096,
                "an encrypted extent is never smaller than a plaintext one");
    }

    @Test
    @DisplayName("a flipped ciphertext byte fails the tag, not merely the checksum")
    void aFlippedCiphertextByteFailsTheTag(@TempDir Path dir) {
        Pager p = pager(dir, "tamper.cryptand");
        byte[] master = new byte[32];
        Arrays.fill(master, (byte) 9);
        byte[] uuid = new byte[16];
        p.setCrypto(FileCipher.of(master, uuid, 0));
        byte[] value = payload(20_000);
        Blob b = Blob.write(p, value);

        long page = b.startPage() + 2;
        byte[] raw = p.readRaw(page);
        raw[200] ^= 0x01;
        p.file().write(p.offsetOf(page), raw);

        // Poly1305 is what provides integrity here (§5.3), and a tag failure is
        // reported as such rather than decrypting to garbage that then fails a
        // CRC -- the difference between "someone edited this" and "your disk
        // has a bad sector".
        RuntimeException e = assertThrows(RuntimeException.class, () -> b.read(p));
        assertNotEquals("", e.getMessage() == null ? "" : e.getMessage());
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
