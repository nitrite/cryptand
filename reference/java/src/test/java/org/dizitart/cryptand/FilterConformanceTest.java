package org.dizitart.cryptand;

import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.BlockedBloom;
import org.dizitart.cryptand.util.Cfh64;
import org.dizitart.cryptand.value.Value;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The segment filter and its hash — {@code spec/04-segments.md} §2.4 and §2.4.1.
 */
class FilterConformanceTest {

    private static JsonNode vector() {
        return Vectors.load("filter/blocked_bloom.json");
    }

    @Test
    @DisplayName("CFH-64 reproduces every published value")
    void cfh64Vectors() {
        JsonNode v = vector().get("cfh64_vectors");
        int n = 0;
        for (Iterator<String> it = v.fieldNames(); it.hasNext(); ) {
            String inputHex = it.next();
            byte[] input = Vectors.hex(inputHex);
            String expected = v.get(inputHex).asText();
            assertEquals(expected, Long.toHexString(Cfh64.hash(input)),
                    () -> "CFH64(" + (inputHex.isEmpty() ? "<empty>" : inputHex) + ")");
            n++;
        }
        // A loop over an empty object passes; assert it ran.
        assertEquals(6, n);
    }

    @Test
    @DisplayName("the derived probe count matches the published table")
    void probeCounts() {
        JsonNode t = vector().get("structure").get("probes_for_bits_per_key");
        int n = 0;
        for (Iterator<String> it = t.fieldNames(); it.hasNext(); ) {
            String bits = it.next();
            assertEquals(t.get(bits).asInt(), BlockedBloom.probesFor(Integer.parseInt(bits)),
                    () -> bits + " bits per key");
            n++;
        }
        assertEquals(4, n);
        assertEquals(BlockedBloom.BLOCK_BITS, vector().get("structure").get("block_bits").asInt());
    }

    @Test
    @DisplayName("block_count is a ceiling, so 33 keys at 16 bits needs two blocks")
    void blockCounts() {
        assertEquals(1, BlockedBloom.blockCountFor(32, 16));
        assertEquals(2, BlockedBloom.blockCountFor(33, 16));
        assertEquals(32, BlockedBloom.blockCountFor(1000, 16));
        // An empty segment still gets one block, never zero.
        assertEquals(1, BlockedBloom.blockCountFor(0, 16));
    }

    /**
     * The whole filter, rebuilt from the vector's recipe and compared byte for
     * byte against what the Dart implementation produced.
     *
     * <p>The header is <strong>20 bytes</strong>. A vector once labelled a
     * 16-byte prefix of it {@code header_bytes}, stopping four bytes into
     * {@code distinct_keys}; an SDK trusting that name lays its blocks four
     * bytes early and every probe reads the wrong bits, which is a false
     * <em>negative</em> — the one filter failure that loses keys silently.
     */
    @Test
    @DisplayName("the published filter is reproduced byte for byte, header and blocks")
    void filterIsByteExact() {
        JsonNode v = vector();
        JsonNode r = v.get("reproduce");
        int treeId = r.get("tree_id").asInt();
        long firstId = r.get("first_id").asLong();
        int keyCount = r.get("key_count").asInt();
        int bitsPerKey = r.get("bits_per_key").asInt();

        List<byte[]> keys = userKeys(treeId, firstId, keyCount);
        BlockedBloom f = BlockedBloom.build(keys, keyCount, bitsPerKey);

        assertArrayEquals(Vectors.hex(v.get("header_bytes").asText()), f.header(),
                "the 20-byte filter page header");
        assertArrayEquals(Vectors.hex(v.get("blocks").asText()), f.blocks(),
                "the filter blocks");
        assertEquals(20, Vectors.hex(v.get("header_bytes").asText()).length);
        assertEquals(BlockedBloom.HEADER_BYTES, f.header().length);
    }

    @Test
    @DisplayName("every key that was inserted is found, which is the one direction that must hold")
    void noFalseNegatives() {
        List<byte[]> keys = userKeys(17, 1_000_000, 1000);
        BlockedBloom f = BlockedBloom.build(keys, keys.size(), 16);
        for (byte[] k : keys) {
            assertTrue(f.mayContain(k), () -> "false negative for " + Vectors.hex(k));
        }
    }

    /**
     * The false-positive rate is allowed to be non-zero — that is what a filter
     * is — but it has to be in the measured range, or something is wrong with
     * the probe sequence rather than with luck. The published figure at 16 bits
     * is 0.22–0.24% across five key shapes.
     */
    @Test
    @DisplayName("absent keys are mostly rejected, at roughly the published rate")
    void falsePositiveRateIsInRange() {
        List<byte[]> present = userKeys(17, 1_000_000, 20_000);
        BlockedBloom f = BlockedBloom.build(present, present.size(), 16);

        int probes = 200_000;
        int hits = 0;
        for (int i = 0; i < probes; i++) {
            byte[] absent = BlockedBloom.userKey(17, Cke.encode(new Value.NitriteId(5_000_000L + i)));
            if (f.mayContain(absent)) {
                hits++;
            }
        }
        double rate = hits / (double) probes;
        assertTrue(rate < 0.01, "false-positive rate " + rate + " is far above the published ~0.23%");
        // And a filter that says yes to everything is not a filter.
        assertTrue(hits < probes / 2, "the filter matched almost everything: " + hits + "/" + probes);
    }

    @Test
    @DisplayName("a filter round-trips through its page payload")
    void encodeDecodeRoundTrips() {
        List<byte[]> keys = userKeys(17, 1_000_000, 1000);
        BlockedBloom f = BlockedBloom.build(keys, keys.size(), 16);
        BlockedBloom back = BlockedBloom.decode(f.encode());
        assertEquals(f, back);
        assertEquals(32, back.blockCount());
        assertEquals(11, back.probes());
        assertEquals(1000, back.distinctKeys());
        for (byte[] k : keys) {
            assertTrue(back.mayContain(k));
        }
    }

    @Test
    @DisplayName("a filter page with the wrong magic or a short body is refused")
    void decodeRejectsDamage() {
        List<byte[]> keys = userKeys(17, 1_000_000, 100);
        byte[] payload = BlockedBloom.build(keys, keys.size(), 16).encode();

        byte[] badMagic = payload.clone();
        badMagic[0] ^= 0xFF;
        assertThrows(CorruptionException.class, () -> BlockedBloom.decode(badMagic));

        byte[] truncated = java.util.Arrays.copyOf(payload, BlockedBloom.HEADER_BYTES + 8);
        assertThrows(LimitException.class, () -> BlockedBloom.decode(truncated));
    }

    /**
     * The filter is over the user key, {@code u32be(tree_id) || CKE(key)}, so
     * the same document id in two trees is two different entries. Getting this
     * wrong makes one tree's filter answer for another's keys.
     */
    @Test
    @DisplayName("the tree id is part of the key the filter hashes")
    void treeIdIsPartOfTheUserKey() {
        byte[] a = BlockedBloom.userKey(17, Cke.encode(new Value.NitriteId(1)));
        byte[] b = BlockedBloom.userKey(18, Cke.encode(new Value.NitriteId(1)));
        assertNotEquals(Vectors.hex(a), Vectors.hex(b));
        assertNotEquals(Cfh64.hash(a), Cfh64.hash(b));

        BlockedBloom f = BlockedBloom.build(List.of(a), 1, 16);
        assertTrue(f.mayContain(a));
        assertFalse(f.mayContain(b));
    }

    private static List<byte[]> userKeys(int treeId, long firstId, int count) {
        List<byte[]> keys = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            keys.add(BlockedBloom.userKey(treeId, Cke.encode(new Value.NitriteId(firstId + i))));
        }
        return keys;
    }
}
