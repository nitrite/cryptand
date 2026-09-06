package org.dizitart.cryptand;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Level 4 — {@code spec/09-vector.md}. */
class VectorTest {

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static Value.Vector vec(float... values) {
        ByteWriter w = new ByteWriter(values.length * 4);
        for (float v : values) {
            w.f32(v);
        }
        return new Value.Vector(Value.Vector.DTYPE_F32, values.length, w.toBytes());
    }

    private static Value.Doc doc(String name, Value.Vector v) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("name", new Value.Str(name));
        f.put("embedding", v);
        return Value.Doc.of(f);
    }

    @Test
    @DisplayName("a region round-trips vectors at its declared stride")
    void regionRoundTrip(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("a.cryptand"), options())) {
            VectorRegion r = VectorRegion.create(e.pager(), 8, VectorRegion.DTYPE_F32, 100);
            assertTrue(r.stride >= 32, "stride is at least the natural size");
            assertEquals(0, r.stride % 64, "slots land on a 64-byte boundary");
            assertEquals(e.pager().pageSize(), r.dataOffset, "data_offset is page-aligned");
            float[] v = {1, 2, 3, 4, 5, 6, 7, 8};
            r.write(e.pager(), 1, v);
            assertArrayEquals(v, r.read(e.pager(), 1));
            VectorRegion reopened = VectorRegion.open(e.pager(), r.startPage);
            assertArrayEquals(v, reopened.read(e.pager(), 1));
        }
    }

    /**
     * §2: {@code stride} is a {@code u16}, so a model beyond 65535 bytes per
     * vector is served by splitting it across two indexes, not by widening the
     * field — a 64 KiB vector is not an embedding a proximity graph is the right
     * structure for.
     */
    @Test
    @DisplayName("a vector too wide for the u16 stride is refused")
    void strideCeiling(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("b.cryptand"), options())) {
            assertThrows(LimitException.class,
                    () -> VectorRegion.create(e.pager(), 20000, VectorRegion.DTYPE_F32, 4));
            assertNotNull(VectorRegion.create(e.pager(), 16000, VectorRegion.DTYPE_F32, 4));
        }
    }

    @Test
    @DisplayName("adjacency deltas are zigzag and round-trip in distance order")
    void adjacencyRecord() {
        List<Long> neighbours = List.of(100L, 42L, 900L, 7L, 900_000L);
        byte[] record = VectorIndex.encodeAdjacency(neighbours);
        assertEquals(neighbours, VectorIndex.decodeAdjacency(record),
                "a neighbour list is ordered by distance, not by id, so the deltas are signed");
        assertEquals(List.of(), VectorIndex.decodeAdjacency(VectorIndex.encodeAdjacency(List.of())));
    }

    @Test
    @DisplayName("search returns the nearest documents with true distances")
    void search(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("c.cryptand"), options())) {
            Collection c = db.collection("docs");
            VectorIndex index = c.createVectorIndex("embedding", 3, VectorIndex.METRIC_L2, 16);
            long a = c.insert(doc("a", vec(1, 0, 0)));
            long b = c.insert(doc("b", vec(0, 1, 0)));
            long z = c.insert(doc("z", vec(10, 10, 10)));

            List<VectorIndex.Hit> hits = index.search(new float[]{1, 0, 0}, 2);
            assertEquals(2, hits.size());
            assertEquals(a, hits.get(0).nitriteId());
            assertEquals(0.0, hits.get(0).distance(), 1e-9, "the true distance, not a proxy");
            assertEquals(b, hits.get(1).nitriteId());
            assertEquals(Math.sqrt(2), hits.get(1).distance(), 1e-6);
            assertFalse(hits.stream().anyMatch(h -> h.nitriteId() == z));
        }
    }

    @Test
    @DisplayName("cosine and dot rank by their own metric")
    void metrics(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("d.cryptand"), options())) {
            Collection c = db.collection("docs");
            VectorIndex cosine = c.createVectorIndex("embedding", 2, VectorIndex.METRIC_COSINE, 8);
            long sameDirection = c.insert(doc("same", vec(10, 0)));
            long orthogonal = c.insert(doc("orth", vec(0, 1)));
            List<VectorIndex.Hit> hits = cosine.search(new float[]{1, 0}, 2);
            assertEquals(sameDirection, hits.get(0).nitriteId(),
                    "cosine ignores magnitude, so a longer parallel vector is nearest");
            assertEquals(orthogonal, hits.get(1).nitriteId());
        }
    }

    /**
     * §6 and §8: a deleted document's mappings go immediately, and a search MUST
     * skip a slot with no document mapping — which is what makes a delete
     * correct even though the graph is repaired later.
     */
    @Test
    @DisplayName("a deleted document disappears from search immediately")
    void deleteIsImmediate(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("e.cryptand"), options())) {
            Collection c = db.collection("docs");
            VectorIndex index = c.createVectorIndex("embedding", 2, VectorIndex.METRIC_L2, 8);
            long a = c.insert(doc("a", vec(1, 0)));
            c.insert(doc("b", vec(0, 1)));
            assertEquals(2, index.size());
            c.remove(a);
            assertEquals(1, index.size());
            List<VectorIndex.Hit> hits = index.search(new float[]{1, 0}, 5);
            assertFalse(hits.stream().anyMatch(h -> h.nitriteId() == a));
        }
    }

    @Test
    @DisplayName("a filter excludes documents before ranking")
    void filtered(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("f.cryptand"), options())) {
            Collection c = db.collection("docs");
            VectorIndex index = c.createVectorIndex("embedding", 2, VectorIndex.METRIC_L2, 8);
            long a = c.insert(doc("a", vec(1, 0)));
            long b = c.insert(doc("b", vec(2, 0)));
            List<VectorIndex.Hit> hits = index.search(new float[]{1, 0}, 5, id -> id != a);
            assertEquals(1, hits.size());
            assertEquals(b, hits.get(0).nitriteId());
        }
    }

    @Test
    @DisplayName("the index survives a reopen, region and maps included")
    void survivesReopen(@TempDir Path dir) {
        Path f = dir.resolve("g.cryptand");
        long target;
        try (Database db = Database.create(f, options())) {
            Collection c = db.collection("docs");
            c.createVectorIndex("embedding", 4, VectorIndex.METRIC_L2, 8);
            target = c.insert(doc("target", vec(1, 1, 1, 1)));
            Random rnd = new Random(9);
            for (int i = 0; i < 60; i++) {
                c.insert(doc("filler-" + i, vec(rnd.nextFloat() * 100, rnd.nextFloat() * 100,
                        rnd.nextFloat() * 100, rnd.nextFloat() * 100)));
            }
        }
        try (Database db = Database.open(f, options())) {
            Collection c = db.collection("docs");
            List<VectorIndex> indexes = c.vectorIndexes();
            assertEquals(1, indexes.size());
            assertEquals(61, indexes.get(0).size(), "the region grew and the maps followed");
            assertEquals(target, indexes.get(0).search(new float[]{1, 1, 1, 1}, 1).get(0).nitriteId());
        }
    }

    /**
     * §7: a rebuild from the collection is always possible, because the vectors
     * also live in the documents as CVE {@code VECTOR} values.
     */
    @Test
    @DisplayName("the graph rebuilds from the documents alone")
    void rebuild(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("h.cryptand"), options())) {
            Collection c = db.collection("docs");
            VectorIndex index = c.createVectorIndex("embedding", 2, VectorIndex.METRIC_L2, 8);
            for (int i = 0; i < 20; i++) {
                c.insert(doc("d" + i, vec(i, 0)));
            }
            assertEquals(20, index.size());
            index.rebuild();
            assertEquals(20, index.size());
            assertEquals(1, index.search(new float[]{0, 0}, 1).size());
        }
    }

    @Test
    @DisplayName("a vector region round-trips inside an encrypted file")
    void encryptedRegion(@TempDir Path dir) {
        byte[] rawKey = new byte[32];
        new Random(21).nextBytes(rawKey);
        Engine.Options o = options();
        o.encrypt = true;
        o.rawKey = rawKey;
        try (Database db = Database.create(dir.resolve("i.cryptand"), o)) {
            Collection c = db.collection("docs");
            VectorIndex index = c.createVectorIndex("embedding", 4, VectorIndex.METRIC_L2, 32);
            long a = c.insert(doc("a", vec(1, 2, 3, 4)));
            c.insert(doc("b", vec(9, 9, 9, 9)));
            assertEquals(a, index.search(new float[]{1, 2, 3, 4}, 1).get(0).nitriteId());
        }
    }

    @Test
    @DisplayName("a mismatched dimension count is refused on write and on query")
    void dimensionMismatch(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("j.cryptand"), options())) {
            Collection c = db.collection("docs");
            VectorIndex index = c.createVectorIndex("embedding", 3, VectorIndex.METRIC_L2, 8);
            assertThrows(InvalidArgumentException.class, () -> c.insert(doc("bad", vec(1, 2))));
            assertThrows(InvalidArgumentException.class,
                    () -> index.search(new float[]{1, 2}, 1));
        }
    }

    private static void assertArrayEquals(float[] expected, float[] actual) {
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], actual[i], 1e-6, "element " + i);
        }
    }
}
