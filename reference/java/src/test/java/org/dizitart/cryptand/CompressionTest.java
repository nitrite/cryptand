package org.dizitart.cryptand;

import org.dizitart.cryptand.container.PageFile;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.util.Lz4;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code spec/01-container.md} §7 — per-page compression.
 *
 * <p>This file exists because §7 was implemented in <strong>no write path in
 * any of the three reference implementations</strong>, while
 * {@code 12-profiles.md} §1 names {@code page_codec = LZ4} for every profile
 * and §7 calls LZ4 "the default and the only codec a Level-0 implementation
 * MUST support". This implementation could decompress and never compressed, so
 * {@link Lz4} sat at 0 % coverage; Rust had a correct codec nothing called;
 * Dart had no LZ4 at all and ignored the {@code COMPRESSED} flag entirely.
 *
 * <p>Same shape as defect 58 (page encryption absent from both implementations
 * while every test passed) and the same lesson: <strong>test what is in the
 * bytes, not what the API returns.</strong> A page round-trips perfectly when
 * it is not compressed.
 */
class CompressionTest {

    /** Shaped like the documents this format holds: repeated names, short values. */
    private static byte[] documentish(int n) {
        StringBuilder sb = new StringBuilder(n + 64);
        int i = 0;
        while (sb.length() < n) {
            sb.append("{\"_id\":").append(i++)
                    .append(",\"name\":\"widget\",\"kind\":\"tool\",\"qty\":7}");
        }
        return Arrays.copyOf(sb.toString().getBytes(StandardCharsets.US_ASCII), n);
    }

    /** Bytes no codec can shrink. A deterministic xorshift, so a failure reproduces. */
    private static byte[] incompressible(int n) {
        byte[] out = new byte[n];
        long s = 0x2545F4914F6CDD1DL;
        for (int i = 0; i < n; i++) {
            s ^= s << 13;
            s ^= s >>> 7;
            s ^= s << 17;
            out[i] = (byte) (s >>> 33);
        }
        return out;
    }

    private static int count(byte[] haystack, String needle) {
        byte[] n = needle.getBytes(StandardCharsets.US_ASCII);
        int found = 0;
        outer:
        for (int i = 0; i + n.length <= haystack.length; i++) {
            for (int j = 0; j < n.length; j++) {
                if (haystack[i + j] != n[j]) {
                    continue outer;
                }
            }
            found++;
        }
        return found;
    }

    // ------------------------------------------------------------------
    // the shared vectors of reference/conformance/vectors/codec/lz4.json
    //
    // This is what makes §7 portable rather than merely implemented: a fourth
    // SDK checks itself against these bytes with none of the other three
    // present. Only the DECODER is normative -- any conforming LZ4 block
    // decompresses to the same output whatever produced it, so a reader is
    // checked against these and a writer is not.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("every recorded block decodes to its recorded plaintext")
    void everyRecordedBlockDecodes() {
        JsonNode v = Vectors.load("codec/lz4.json");
        JsonNode cases = v.get("cases");
        assertTrue(cases.size() > 8, "a vector file that shrank silently measures nothing");
        for (JsonNode c : cases) {
            String note = c.get("note").asText();
            byte[] plain = Vectors.hex(c.get("plain").asText());
            assertEquals(c.get("plain_len").asInt(), plain.length,
                    "the vector disagrees with itself: " + note);
            assertArrayEquals(plain,
                    Lz4.decompress(Vectors.hex(c.get("lz4").asText()), plain.length), note);
        }
    }

    @Test
    @DisplayName("this compressor emits blocks the vector can check")
    void thisCompressorEmitsCheckableBlocks() {
        // The writer is free, so the assertion is not byte equality: it is that
        // what this compressor emits decodes to the same plaintext.
        for (JsonNode c : Vectors.load("codec/lz4.json").get("cases")) {
            byte[] plain = Vectors.hex(c.get("plain").asText());
            assertArrayEquals(plain, Lz4.decompress(Lz4.compress(plain), plain.length),
                    c.get("note").asText());
        }
    }

    @Test
    @DisplayName("every block the vector says to refuse is refused")
    void everyRefusedBlockIsRefused() {
        JsonNode cases = Vectors.load("codec/lz4.json").get("refuse").get("cases");
        assertTrue(cases.size() > 0);
        for (JsonNode c : cases) {
            byte[] block = Vectors.hex(c.get("lz4").asText());
            int n = c.get("plain_len").asInt();
            assertThrows(RuntimeException.class, () -> Lz4.decompress(block, n),
                    c.get("why").asText());
        }
    }

    @Test
    @DisplayName("the 12.5 % threshold matches the recorded cases")
    void thresholdMatchesTheRecordedCases() {
        for (JsonNode c : Vectors.load("codec/lz4.json").get("threshold").get("cases")) {
            assertEquals(c.get("worth").asBoolean(),
                    Lz4.worthCompressing(c.get("raw").asInt(), c.get("compressed").asInt()),
                    c.get("raw").asInt() + " -> " + c.get("compressed").asInt());
        }
    }

    // ------------------------------------------------------------------
    // the block codec on its own
    // ------------------------------------------------------------------

    @Test
    @DisplayName("every shape round-trips, including the degenerate lengths")
    void everyShapeRoundTrips() {
        byte[][] shapes = {
                new byte[0],
                {0x41},
                {0x41, 0x41, 0x41, 0x41},
                // 11, 12 and 13 straddle the end-of-block guard, which is where
                // an off-by-one in the compressor's limit lands.
                new byte[11], new byte[12], new byte[13], new byte[17],
                documentish(1),
                documentish(4056),
                incompressible(4056),
                run(4056),
                period(4056),
        };
        for (byte[] src : shapes) {
            byte[] block = Lz4.compress(src);
            assertArrayEquals(src, Lz4.decompress(block, src.length),
                    "length " + src.length);
        }
    }

    private static byte[] run(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) ((i / 64) % 3);
        }
        return b;
    }

    private static byte[] period(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (i % 7);
        }
        return b;
    }

    @Test
    @DisplayName("an overlapping match is a run, and must not be a block copy")
    void anOverlappingMatchIsARun() {
        // LZ4 encodes a run as a match whose offset is smaller than its length,
        // so the copy has to be byte at a time. An arraycopy here decodes to
        // the wrong bytes without failing anything.
        byte[] src = new byte[1000];
        Arrays.fill(src, (byte) 0x5A);
        byte[] block = Lz4.compress(src);
        assertTrue(block.length < 64, "a run must compress hard, got " + block.length);
        assertArrayEquals(src, Lz4.decompress(block, src.length));
    }

    @Test
    @DisplayName("the 12.5 % rule is exactly §7's arithmetic")
    void theTwelveAndAHalfPercentRule() {
        assertTrue(Lz4.worthCompressing(4096, 3584), "saves exactly 1/8");
        assertFalse(Lz4.worthCompressing(4096, 3585), "one byte short");
        assertFalse(Lz4.worthCompressing(4096, 4096));
        assertTrue(Lz4.worthCompressing(0, 0));
    }

    @Test
    @DisplayName("it compresses what it claims to, and declines what it cannot")
    void itCompressesWhatItClaimsTo() {
        byte[] doc = documentish(4056);
        assertTrue(Lz4.compress(doc).length < doc.length / 2);
        assertTrue(Lz4.worthCompressing(doc.length, Lz4.compress(doc).length));
        byte[] rnd = incompressible(4056);
        assertFalse(Lz4.worthCompressing(rnd.length, Lz4.compress(rnd).length));
    }

    // ------------------------------------------------------------------
    // untrusted input -- 14-security.md §9
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a crafted block is refused, never trusted")
    void aCraftedBlockIsRefused() {
        byte[][] crafted = {
                {(byte) 0xF0, (byte) 0xFF},                      // literals overrun the source
                {0x50, 1, 2, 3, 4, 5},                           // literals overrun the output
                {0x0F, 0x10, 0x00, 0x00},                        // offset before the output
                {0x10, 0x41, 0x00, 0x00},                        // offset zero
                {0x1F, 0x41, 0x01, 0x00, (byte) 0xFF, (byte) 0xFF, 0x00},
        };
        for (byte[] b : crafted) {
            assertThrows(CorruptionException.class, () -> Lz4.decompress(b, 64),
                    Arrays.toString(b));
        }
    }

    @Test
    @DisplayName("a block that decodes to the wrong length is refused")
    void theWrongLengthIsRefused() {
        byte[] src = documentish(1000);
        byte[] block = Lz4.compress(src);
        assertThrows(CorruptionException.class, () -> Lz4.decompress(block, 999));
        assertThrows(CorruptionException.class, () -> Lz4.decompress(block, 1001));
    }

    @Test
    @DisplayName("truncation at every length is refused, never silently short")
    void truncationIsAlwaysRefused() {
        byte[] src = documentish(2000);
        byte[] block = Lz4.compress(src);
        for (int cut = 0; cut < block.length; cut++) {
            byte[] part = Arrays.copyOf(block, cut);
            int at = cut;
            assertThrows(RuntimeException.class, () -> Lz4.decompress(part, src.length),
                    "a block truncated at " + at + " decoded");
        }
    }

    @Test
    @DisplayName("a bit flipped anywhere is refused or wrong, never out of bounds")
    void aFlippedBitNeverEscapesTheBuffer() {
        byte[] src = documentish(2000);
        byte[] block = Lz4.compress(src);
        int refused = 0;
        int decoded = 0;
        for (int i = 0; i < block.length; i++) {
            for (int bit : new int[] {0x01, 0x80}) {
                byte[] bad = block.clone();
                bad[i] ^= (byte) bit;
                try {
                    Lz4.decompress(bad, src.length);
                    decoded++;
                } catch (RuntimeException e) {
                    refused++;
                }
            }
        }
        assertEquals(block.length * 2, refused + decoded,
                "every mutation must end in one of the two, and nothing else");
        assertTrue(refused > 0, "if nothing is ever refused the checks are not running");
    }

    // ------------------------------------------------------------------
    // the page seam -- look at the stored bytes
    // ------------------------------------------------------------------

    private static Pager pagerWith(Path dir, int codec) {
        PageFile f = new PageFile(dir.resolve("t.cryptand"), false,
                Superblock.Durability.NONE);
        Pager p = new Pager(f, 4096, 2, 1, 0);
        p.setPageCodec(codec);
        return p;
    }

    private static PageHeader head(int extentPages, int type) {
        PageHeader h = new PageHeader();
        h.pageType = type;
        h.treeId = 17;
        h.extentPages = extentPages;
        return h;
    }

    @Test
    @DisplayName("a compressible page is STORED compressed, and says so")
    void aCompressiblePageIsStoredCompressed(@TempDir Path dir) {
        Pager p = pagerWith(dir, Superblock.Codec.LZ4);
        long id = p.allocate(1);
        byte[] payload = documentish(4000);
        p.writePage(id, head(1, PageHeader.Type.BTREE_LEAF), payload);

        byte[] stored = p.readRaw(id);
        PageHeader h = PageHeader.verify(stored, id);
        assertTrue(h.isSet(PageHeader.Flags.COMPRESSED), "the flag must be set");
        assertEquals(Superblock.Codec.LZ4, h.codecOrReserved, "and it must name the codec");
        assertEquals(payload.length, h.payloadLen,
                "payload_len keeps §3's meaning: the uncompressed length");
        assertTrue(h.storedLen > 0 && h.storedLen < payload.length,
                "stored_len is what the page actually holds: " + h.storedLen);

        // The repetitions are gone. Not all of them: LZ4 emits the first
        // occurrence as *literals* and encodes only the repeats as matches, so
        // exactly one copy survives verbatim. Compression is not
        // confidentiality -- that is §5.2's job -- and asserting the needle is
        // absent would be asserting something false.
        assertEquals(1, count(stored, "\"name\":\"widget\""),
                "the literal survives once; every repeat must be a match");

        assertArrayEquals(payload, p.readPage(id));
    }

    @Test
    @DisplayName("with the codec off, nothing is compressed")
    void withTheCodecOffNothingIsCompressed(@TempDir Path dir) {
        Pager p = pagerWith(dir, Superblock.Codec.NONE);
        long id = p.allocate(1);
        byte[] payload = documentish(4000);
        p.writePage(id, head(1, PageHeader.Type.BTREE_LEAF), payload);
        byte[] stored = p.readRaw(id);
        assertFalse(PageHeader.verify(stored, id).isSet(PageHeader.Flags.COMPRESSED));
        assertTrue(count(stored, "\"name\":\"widget\"") > 50,
                "the control: without the codec every copy IS there, so the test "
                        + "above is measuring the codec and not something else");
    }

    @Test
    @DisplayName("an incompressible page is stored as it is, never larger")
    void anIncompressiblePageIsStoredAsItIs(@TempDir Path dir) {
        Pager p = pagerWith(dir, Superblock.Codec.LZ4);
        long id = p.allocate(1);
        byte[] payload = incompressible(4000);
        p.writePage(id, head(1, PageHeader.Type.BTREE_LEAF), payload);
        assertFalse(PageHeader.verify(p.readRaw(id), id).isSet(PageHeader.Flags.COMPRESSED),
                "§7: only if compression saves >= 12.5 %");
        assertArrayEquals(payload, p.readPage(id));
    }

    @Test
    @DisplayName("a page inside a multi-page extent is never compressed")
    void aPageInsideAnExtentIsNeverCompressed(@TempDir Path dir) {
        // An extent is a contiguous byte range whose reader may hold the whole
        // thing and parse pages at fixed offsets rather than fetching them one
        // at a time -- which the Rust implementation does. Compressing a page
        // inside one moves every byte after its header without telling that
        // reader, and the failure shows up as "segment header magic mismatch"
        // in the other language, several steps later. That is what happened.
        Pager p = pagerWith(dir, Superblock.Codec.LZ4);
        long id = p.allocate(3);
        p.writePage(id, head(3, PageHeader.Type.SEGMENT_HEADER), documentish(4000));
        assertFalse(PageHeader.verify(p.readRaw(id), id).isSet(PageHeader.Flags.COMPRESSED),
                "extent_pages > 1 means the payload is not this page alone");
    }

    @Test
    @DisplayName("buildExtentPage never compresses, whatever the header says")
    void buildExtentPageNeverCompresses(@TempDir Path dir) {
        // The guard above is on the header; this one is on the call path,
        // because an interior segment page carries extent_pages = 1 and the
        // segment builder is what writes it.
        Pager p = pagerWith(dir, Superblock.Codec.LZ4);
        byte[] page = p.buildExtentPage(2, head(1, PageHeader.Type.BTREE_LEAF),
                documentish(4000));
        assertFalse(PageHeader.verify(page, 2).isSet(PageHeader.Flags.COMPRESSED));
    }

    @Test
    @DisplayName("a value-log head page is never compressed")
    void aValueLogHeadPageIsNeverCompressed(@TempDir Path dir) {
        // §6.2 appends records into the head page's own tail, so its bytes are
        // not a payload that can be rewritten.
        Pager p = pagerWith(dir, Superblock.Codec.LZ4);
        long id = p.allocate(1);
        p.writePage(id, head(1, PageHeader.Type.VLOG_SEGMENT), documentish(64));
        assertFalse(PageHeader.verify(p.readRaw(id), id).isSet(PageHeader.Flags.COMPRESSED));
    }

    @Test
    @DisplayName("an unknown codec id on a page is refused, not guessed at")
    void anUnknownCodecIsRefused(@TempDir Path dir) {
        Pager p = pagerWith(dir, Superblock.Codec.LZ4);
        long id = p.allocate(1);
        byte[] payload = documentish(4000);
        p.writePage(id, head(1, PageHeader.Type.BTREE_LEAF), payload);
        byte[] stored = p.readRaw(id);
        PageHeader h = PageHeader.verify(stored, id);
        h.codecOrReserved = 77;
        h.writeInto(stored);
        p.file().write(p.offsetOf(id), stored);
        assertThrows(CryptandException.class, () -> p.readPage(id));
    }

    // ------------------------------------------------------------------
    // the space claim
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a document-shaped page stores in under half a page")
    void aDocumentShapedPageStoresInUnderHalfAPage(@TempDir Path dir) {
        Pager p = pagerWith(dir, Superblock.Codec.LZ4);
        long id = p.allocate(1);
        byte[] payload = documentish(4000);
        p.writePage(id, head(1, PageHeader.Type.BTREE_LEAF), payload);
        int stored = PageHeader.verify(p.readRaw(id), id).storedLen;
        assertTrue(stored < payload.length / 2,
                "stored " + stored + " of " + payload.length + " bytes");
    }
}
