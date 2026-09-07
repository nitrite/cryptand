package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.util.Crc32c;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The container against the shared vectors — {@code spec/01-container.md}.
 */
class ContainerConformanceTest {

    /**
     * Field offsets are a table in the spec, a table in the vector, and a
     * sequence of writes here. Asserting the offsets directly is what catches a
     * field written in the right order at the wrong place — which is how an
     * earlier draft of the page header ended up with {@code commit_id} running
     * into {@code extent_pages}, an overlap no reader could implement that
     * survived three review passes because nobody added the column up.
     */
    @Test
    @DisplayName("the superblock lays its fields at the published offsets")
    void superblockFieldOffsets() {
        JsonNode sb = Vectors.load("container/layout.json").get("superblock");
        byte[] expected = Vectors.hex(sb.get("bytes").asText());
        assertEquals(Superblock.BYTES, expected.length);

        JsonNode offsets = sb.get("field_offsets");
        assertEquals(0, offsets.get("magic").asInt());
        assertEquals(8, offsets.get("version_major").asInt());
        assertEquals(14, offsets.get("page_size_log2").asInt());
        assertEquals(16, offsets.get("commit_id").asInt());
        assertEquals(184, offsets.get("vlog_min").asInt());
        assertEquals(216, offsets.get("profile").asInt());
        assertEquals(288, offsets.get("next_nonce").asInt());
        assertEquals(296, offsets.get("sb_mac").asInt());
        assertEquals(3512, offsets.get("keyslots").asInt());
        assertEquals(Superblock.CHECKSUM_OFFSET, offsets.get("checksum").asInt());
    }

    @Test
    @DisplayName("the published superblock re-encodes byte for byte")
    void superblockRoundTrips() {
        JsonNode node = Vectors.load("container/layout.json").get("superblock");
        byte[] expected = Vectors.hex(node.get("bytes").asText());

        Superblock decoded = Superblock.decode(expected);
        assertArrayEquals(expected, decoded.encode(),
                "a decoded superblock must re-encode to the same bytes");

        // The vector's own claims about what it holds.
        assertEquals(1, decoded.commitId);
        assertEquals(Profile.MOBILE.id(), decoded.profile);
        assertEquals("cryptand-vectors/1.0", decoded.writerId);
        assertArrayEquals(Vectors.hex("000102030405060708090a0b0c0d0e0f"), decoded.databaseUuid);

        JsonNode expectedFields = node.get("expected");
        assertEquals(expectedFields.get("vlog_min").asInt(), decoded.vlogMin);
        assertEquals(expectedFields.get("page_size").asInt(), decoded.pageSize());
    }

    /**
     * {@code spec/01-container.md} §2 and {@code spec/12-profiles.md} §3: every
     * tuning constant is stored as its own field and is <strong>never derived
     * from {@code profile}</strong>. This asserts the two agree for a file the
     * Dart implementation wrote — if they ever diverge, it is the stored value
     * that is authoritative and this test that must change.
     */
    @Test
    @DisplayName("the published mobile superblock carries the mobile constants")
    void mobileConstants() {
        Superblock sb = Superblock.decode(
                Vectors.hex(Vectors.load("container/layout.json").get("superblock").get("bytes").asText()));
        Profile p = Profile.MOBILE;
        assertEquals(p.pageSize(), sb.pageSize());
        assertEquals(p.vlogMin(), sb.vlogMin);
        assertEquals(p.blobThreshold(), sb.blobThreshold);
        assertEquals(p.l0Trigger(), sb.l0Trigger);
        assertEquals(p.fanout(), sb.fanout);
        assertEquals(p.tierWidth(), sb.tierWidth);
        assertEquals(p.overlapBound(), sb.overlapBound);
        assertEquals(p.memtableShards(), sb.memtableShards);
        assertEquals(p.filterBitsUpper(), sb.filterBitsUpper);
        assertEquals(p.filterBitsLast(), sb.filterBitsLast);
        assertEquals(p.vlogSpaceTargetPct(), sb.vlogSpaceTargetPct);
        assertEquals(p.localityDebtPct(), sb.localityDebtPct);
        assertEquals(p.readaheadWindow(), sb.readaheadWindow);
        assertEquals(p.segmentTargetBytes(), sb.segmentTargetBytes);
        assertEquals(p.vlogSegmentBytes(), sb.vlogSegmentBytes);
    }

    /**
     * A superblock this implementation builds from the same profile must be the
     * same bytes as the one the Dart implementation wrote. This is the actual
     * interchange claim at container level, and it is stricter than decoding: a
     * decoder that ignored a field would still round-trip it.
     */
    @Test
    @DisplayName("a mobile superblock built from scratch matches the Dart-written one")
    void buildsTheSameSuperblock() {
        byte[] expected = Vectors.hex(
                Vectors.load("container/layout.json").get("superblock").get("bytes").asText());
        Superblock reference = Superblock.decode(expected);

        Superblock sb = Superblock.forProfile(Profile.MOBILE);
        sb.commitId = 1;
        sb.pageCount = 2;
        sb.nextSeq = 1;
        sb.nextTreeId = TreeId.FIRST_USER_TREE;
        sb.nextSegmentId = 1;
        sb.nextVlogSegmentId = 1;
        sb.levelCount = 1;
        sb.durabilityAchieved = Superblock.Durability.SYNC;
        sb.featuresRequired = Feature.bit(Feature.CORE);
        sb.createdUtcMs = reference.createdUtcMs;
        sb.modifiedUtcMs = reference.modifiedUtcMs;
        sb.databaseUuid = Vectors.hex("000102030405060708090a0b0c0d0e0f");
        sb.writerId = "cryptand-vectors/1.0";

        assertArrayEquals(expected, sb.encode());
    }

    @Test
    @DisplayName("a corrupt superblock checksum is refused, and named as corruption")
    void superblockChecksumIsChecked() {
        byte[] bytes = Vectors.hex(
                Vectors.load("container/layout.json").get("superblock").get("bytes").asText());
        byte[] damaged = bytes.clone();
        damaged[100] ^= 0x01;
        CorruptionException e = assertThrows(CorruptionException.class, () -> Superblock.decode(damaged));
        assertTrue(e.getMessage().contains("checksum"), e.getMessage());
    }

    @Test
    @DisplayName("a file that is not a Cryptand database is refused on the magic")
    void magicIsChecked() {
        byte[] notADatabase = new byte[Superblock.BYTES];
        assertThrows(CorruptionException.class, () -> Superblock.decode(notADatabase));
    }

    /**
     * §2.1 step 5: an unknown <em>required</em> feature bit means refuse to
     * open and name the bit. An unknown <em>optional</em> bit means open and
     * leave the structures it governs alone — every ambiguous case in
     * {@code 00-conventions.md} §9 resolves toward "refuse" or "preserve",
     * never toward "drop".
     */
    @Test
    @DisplayName("an unknown required feature bit refuses the file; an optional one does not")
    void featureBits() {
        Superblock sb = Superblock.forProfile(Profile.DESKTOP);
        sb.featuresRequired = Feature.bit(Feature.CORE) | Feature.bit(40);
        byte[] encoded = sb.encode();
        UnsupportedFeatureException e =
                assertThrows(UnsupportedFeatureException.class, () -> Superblock.decode(encoded));
        assertTrue(e.getMessage().contains("40"), e.getMessage());

        Superblock ok = Superblock.forProfile(Profile.DESKTOP);
        ok.featuresOptional = Feature.bit(41);
        assertEquals(Feature.bit(41), Superblock.decode(ok.encode()).featuresOptional);
    }

    /**
     * {@code 00-conventions.md} §8: "A writer MUST reject a {@code vlog_min}
     * above the cap; a reader MUST treat a file whose superblock violates it as
     * corrupt." An earlier draft put {@code mobile}'s at 4096 with 4 KiB pages,
     * which would have sent every 1–4 KiB value into an overflow chain — two
     * I/Os, the exact cost inlining was chosen to avoid.
     */
    @Test
    @DisplayName("a vlog_min above a quarter page makes the file corrupt, not merely odd")
    void vlogMinCap() {
        Superblock sb = Superblock.forProfile(Profile.MOBILE);
        sb.vlogMin = 4096;
        byte[] encoded = sb.encode();
        CorruptionException e = assertThrows(CorruptionException.class, () -> Superblock.decode(encoded));
        assertTrue(e.getMessage().contains("vlog_min"), e.getMessage());
    }

    /**
     * §1: slots A and B are written alternately, so a crash during a superblock
     * write leaves the previous superblock intact. Odd commits go to A.
     */
    @Test
    @DisplayName("commits alternate between the two superblock slots")
    void slotsAlternate() {
        assertEquals(0, Superblock.slotOffsetFor(1, 4096));
        assertEquals(4096, Superblock.slotOffsetFor(2, 4096));
        assertEquals(0, Superblock.slotOffsetFor(3, 4096));
        assertEquals(8192, Superblock.slotOffsetFor(4, 8192));
    }

    @Test
    @DisplayName("the page header is 40 bytes at the published offsets")
    void pageHeaderFieldOffsets() {
        JsonNode ph = Vectors.load("container/layout.json").get("page_header");
        assertEquals(PageHeader.BYTES, ph.get("size").asInt());
        JsonNode offsets = ph.get("field_offsets");
        int[] expected = {0, 4, 5, 6, 8, 12, 16, 24, 28, 32};
        String[] names = {"checksum", "page_type", "flags", "codec_or_reserved", "tree_id",
                "extent_pages", "commit_id", "payload_len", "stored_len", "nonce"};
        for (int i = 0; i < names.length; i++) {
            assertEquals(expected[i], offsets.get(names[i]).asInt(), names[i]);
        }
        // Every published offset is one this implementation knows about; a
        // field added to the vector must not pass unnoticed.
        int known = 0;
        for (Iterator<String> it = offsets.fieldNames(); it.hasNext(); it.next()) {
            known++;
        }
        assertEquals(names.length, known);
    }

    @Test
    @DisplayName("the published page header re-encodes byte for byte")
    void pageHeaderRoundTrips() {
        JsonNode ph = Vectors.load("container/layout.json").get("page_header");
        byte[] expected = Vectors.hex(ph.get("bytes").asText());
        assertEquals(PageHeader.BYTES, expected.length);

        PageHeader h = PageHeader.parse(expected, 0);
        assertEquals(PageHeader.Type.BTREE_LEAF, h.pageType);
        assertEquals(17, h.treeId);
        assertEquals(1, h.extentPages);
        assertEquals(1, h.commitId);
        assertEquals(4096 - PageHeader.BYTES, h.payloadLen);
        assertEquals(0, h.storedLen);
        assertEquals(0, h.nonce);
        assertArrayEquals(expected, h.toBytes());

        // And the checksum really is over the whole 4 KiB page, not the header.
        byte[] page = new byte[4096];
        PageHeader built = new PageHeader();
        built.pageType = PageHeader.Type.BTREE_LEAF;
        built.treeId = 17;
        built.extentPages = 1;
        built.commitId = 1;
        built.payloadLen = 4096 - PageHeader.BYTES;
        built.writeInto(page);
        assertArrayEquals(expected, java.util.Arrays.copyOf(page, PageHeader.BYTES));
    }

    /**
     * §3: {@code stored_len} of 0 means "same as {@code payload_len}". The field
     * was reserved in an earlier draft, so a page that is neither compressed nor
     * encrypted writes 0 here and is byte-identical to what that draft
     * described. That is the only reason the fix moved nothing.
     */
    @Test
    @DisplayName("stored_len 0 means the payload is stored as-is")
    void storedLenZeroMeansUnchanged() {
        PageHeader h = new PageHeader();
        h.payloadLen = 1000;
        h.storedLen = 0;
        assertEquals(1000, h.storedBytes());
        h.storedLen = 1016;
        assertEquals(1016, h.storedBytes());
    }

    @Test
    @DisplayName("a page whose checksum does not match is corruption, naming the page")
    void pageChecksumIsChecked() {
        byte[] page = new byte[4096];
        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.BTREE_LEAF;
        h.treeId = 17;
        h.payloadLen = 4096 - PageHeader.BYTES;
        h.writeInto(page);
        assertEquals(h.checksum, PageHeader.verify(page, 5).checksum);

        page[2000] ^= 0x40;
        CorruptionException e = assertThrows(CorruptionException.class, () -> PageHeader.verify(page, 5));
        assertTrue(e.getMessage().contains("page 5"), e.getMessage());
        assertEquals(5L, e.pageId());
    }

    @Test
    @DisplayName("a payload_len past the end of the page is refused before it is used")
    void pageLengthsAreBoundsChecked() {
        byte[] page = new byte[4096];
        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.BTREE_LEAF;
        h.payloadLen = 9999;
        h.writeInto(page);
        assertThrows(CorruptionException.class, () -> PageHeader.verify(page, 1));
    }

    @Test
    @DisplayName("CRC-32C matches the vector's own check values")
    void crc32cVectors() {
        JsonNode cases = Vectors.load("container/layout.json").get("crc32c");
        assertNotEquals(0, cases.size());
        for (JsonNode c : cases) {
            byte[] input = Vectors.hex(c.get("input").asText());
            long expected = c.get("crc").asLong();
            assertEquals(expected, Crc32c.of(input) & 0xFFFFFFFFL,
                    () -> "crc32c of " + c.get("input").asText());
        }
    }
}
