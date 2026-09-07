package org.dizitart.cryptand;

import org.dizitart.cryptand.ops.IndexStats;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code spec/13-operations.md} §9 — statistics for the query planner.
 *
 * <p>Both the class under test and this file are new. §9 was absent from the
 * Java port entirely: no sketch, no histogram, no {@code params.stats}, and
 * nothing that chose an index on evidence. The Dart implementation had the
 * whole chapter wired; the Rust one had the sketch as dead code with no caller
 * anywhere in the crate.
 *
 * <p>§9's own last paragraph is why this can be tested by result rather than by
 * byte: <strong>statistics are advisory.</strong> A planner MUST produce
 * correct results without them, so every test here also checks the
 * without-them path.
 */
class StatsTest {

    // ------------------------------------------------------------------
    // the sketch -- §9 picks HyperLogLog for one property: it is mergeable and
    // fixed-size, so a compaction accumulates it while streaming
    // ------------------------------------------------------------------

    private static byte[] key(int i) {
        return new byte[] {(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
    }

    @Test
    @DisplayName("the sketch estimates cardinality within its error bound")
    void theSketchEstimatesCardinality() {
        IndexStats.HyperLogLog h = new IndexStats.HyperLogLog(10);
        for (int i = 0; i < 10_000; i++) {
            h.add(key(i));
        }
        double est = h.estimate();
        // p = 10 gives 1024 registers and a standard error of 1.04/sqrt(m) ~
        // 3.25 %. The bound here is deliberately loose: the point is that the
        // estimate tracks reality, not that it reproduces one implementation's
        // rounding.
        assertTrue(Math.abs(est - 10_000) / 10_000 < 0.15,
                "estimated " + est + " for 10 000 distinct keys");
    }

    @Test
    @DisplayName("the sketch is mergeable, which is why it was chosen")
    void theSketchIsMergeable() {
        // §9: "two segments' sketches combine by register-wise maximum".
        // Without that, a compaction could not accumulate one while streaming,
        // and an exact distinct count needs memory proportional to cardinality.
        IndexStats.HyperLogLog a = new IndexStats.HyperLogLog(10);
        IndexStats.HyperLogLog b = new IndexStats.HyperLogLog(10);
        IndexStats.HyperLogLog whole = new IndexStats.HyperLogLog(10);
        for (int i = 0; i < 5_000; i++) {
            a.add(key(i));
            whole.add(key(i));
        }
        for (int i = 5_000; i < 10_000; i++) {
            b.add(key(i));
            whole.add(key(i));
        }
        a.merge(b);
        assertEquals(whole.estimate(), a.estimate(),
                "a merge must give exactly what one pass would have");
    }

    @Test
    @DisplayName("the sketch counts duplicates once, and refuses a mismatched merge")
    void theSketchCountsDuplicatesOnce() {
        IndexStats.HyperLogLog h = new IndexStats.HyperLogLog(10);
        for (int i = 0; i < 1000; i++) {
            h.add("the same key".getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(h.estimate() <= 3, "estimated " + h.estimate() + " for one distinct key");
        assertEquals(0, new IndexStats.HyperLogLog(10).estimate(), "an empty sketch is zero");
        // Merging different precisions would silently corrupt both, because the
        // register arrays have different lengths and different index widths.
        assertThrows(IllegalArgumentException.class,
                () -> new IndexStats.HyperLogLog(10).merge(new IndexStats.HyperLogLog(8)));
    }

    // ------------------------------------------------------------------
    // the descriptor encoding
    // ------------------------------------------------------------------

    @Test
    @DisplayName("stats round-trip through their value encoding")
    void statsRoundTrip() {
        IndexStats.Builder b = new IndexStats.Builder();
        for (int i = 0; i < 200; i++) {
            b.add(key(i), i % 10 == 0);
        }
        IndexStats s = b.build(42, 4096);
        IndexStats back = IndexStats.fromDoc(s.toDoc());
        assertEquals(42, back.updatedSeq);
        assertEquals(s.entries, back.entries);
        assertEquals(s.nullCount, back.nullCount);
        assertEquals(s.distinctEstimate, back.distinctEstimate);
        assertArrayEquals(s.minKey, back.minKey);
        assertArrayEquals(s.maxKey, back.maxKey);
        assertEquals(s.histogram.size(), back.histogram.size());
        for (int i = 0; i < s.histogram.size(); i++) {
            assertArrayEquals(s.histogram.get(i).bound(), back.histogram.get(i).bound());
            assertEquals(s.histogram.get(i).cumulative(), back.histogram.get(i).cumulative());
        }
    }

    @Test
    @DisplayName("an absent or partial value decodes to zeroes rather than failing")
    void anAbsentValueDecodesToZeroes() {
        // §9: statistics "may be stale or absent", so the decoder's job is to
        // give a planner something usable, never to refuse.
        IndexStats s = IndexStats.fromDoc(new Value.Doc(new LinkedHashMap<>()));
        assertEquals(0, s.entries);
        assertEquals(0, s.histogram.size());
        assertNull(s.selectivity(), "no entries means no estimate, not certainty");
        assertEquals(0, IndexStats.fromDoc(Value.NULL).entries, "and a non-doc is not a crash");
    }

    // ------------------------------------------------------------------
    // defect 37: the histogram is bounded in BYTES, not only in buckets, and
    // the byte bound is the binding one
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the histogram is bounded in bytes, not only in buckets")
    void theHistogramIsBoundedInBytes() {
        // Long string keys: 64 buckets of these is several kilobytes, which is
        // the measurement that produced defect 37 -- 4734 B against a 4096 B
        // page, so the descriptor could not be written at all.
        IndexStats.Builder b = new IndexStats.Builder();
        for (int i = 0; i < 500; i++) {
            b.add(String.format("%0200d", i).getBytes(StandardCharsets.US_ASCII), false);
        }
        int budget = 2048;
        IndexStats s = b.build(1, budget);
        assertTrue(s.encodedLen() <= budget,
                "encoded " + s.encodedLen() + " bytes against a " + budget + " byte budget");
        assertTrue(s.histogram.size() < IndexStats.MAX_BUCKETS,
                "with keys this long the bucket count MUST have been reduced, got "
                        + s.histogram.size());
        // §9's remedy is to drop *alternate* buckets, so the range is
        // preserved: the last bound still reaches the maximum key. Truncating
        // would throw away the top of the key space.
        assertArrayEquals(s.maxKey, s.histogram.get(s.histogram.size() - 1).bound(),
                "dropping buckets must keep the range, not truncate it");
    }

    @Test
    @DisplayName("a generous budget keeps the full bucket count")
    void aGenerousBudgetKeepsTheBuckets() {
        // The control for the test above: if the reduction fired regardless of
        // the budget, that test would pass for the wrong reason.
        IndexStats.Builder b = new IndexStats.Builder();
        for (int i = 0; i < 500; i++) {
            b.add(key(i), false);
        }
        IndexStats s = b.build(1, 1 << 20);
        // 500 entries at a quota of ceil(500/64) = 8 gives 63 buckets, not 64:
        // MAX_BUCKETS bounds the count, it does not fix it.
        assertTrue(s.histogram.size() >= IndexStats.MAX_BUCKETS - 1,
                "a generous budget must keep the full bucket count, got " + s.histogram.size());
    }

    @Test
    @DisplayName("the histogram is equi-depth and monotone")
    void theHistogramIsEquiDepth() {
        IndexStats.Builder b = new IndexStats.Builder();
        for (int i = 0; i < 1000; i++) {
            b.add(key(i), false);
        }
        IndexStats s = b.build(1, 1 << 20);
        assertTrue(!s.histogram.isEmpty());
        long prevCum = 0;
        byte[] prevBound = new byte[0];
        List<Long> widths = new ArrayList<>();
        for (IndexStats.Bucket bkt : s.histogram) {
            assertTrue(bkt.cumulative() > prevCum, "cumulative must strictly increase");
            assertTrue(java.util.Arrays.compareUnsigned(bkt.bound(), prevBound) > 0,
                    "bounds must be in key order");
            widths.add(bkt.cumulative() - prevCum);
            prevCum = bkt.cumulative();
            prevBound = bkt.bound();
        }
        assertEquals(s.entries, prevCum, "the last bucket must cover every entry");
        long first = widths.get(0);
        for (int i = 0; i < widths.size() - 1; i++) {
            assertEquals(first, widths.get(i), "buckets must be equal depth: " + widths);
        }
        assertTrue(widths.get(widths.size() - 1) <= first, "the last takes the remainder");
    }

    // ------------------------------------------------------------------
    // the engine seam: analyze writes params.stats, stats() reads it back, and
    // mostSelective decides on it. This is the part that did not exist.
    // ------------------------------------------------------------------

    private static org.dizitart.cryptand.lsm.Engine.Options options() {
        org.dizitart.cryptand.lsm.Engine.Options o =
                new org.dizitart.cryptand.lsm.Engine.Options();
        o.profile = org.dizitart.cryptand.container.Profile.DESKTOP;
        o.memtableEntries = 64;
        // `os` rather than `sync`: these tests are about §9's arithmetic, and
        // an fsync per commit covers no extra branch here.
        o.durability = org.dizitart.cryptand.container.Superblock.Durability.OS;
        return o;
    }

    private static Value.Doc doc(long id, String city, long age) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("_id", new Value.NitriteId(id));
        f.put("city", new Value.Str(city));
        f.put("age", Value.integer(NumType.I64, age));
        return new Value.Doc(f);
    }

    @Test
    @DisplayName("analyze writes statistics that stats() reads back")
    void analyzeWritesStatistics(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("t.cryptand"), options())) {
            Collection c = db.collection("people");
            Collection.IndexBinding byCity = c.createIndex(List.of("city"), false, false);
            for (long i = 0; i < 300; i++) {
                c.insert(doc(i, i % 3 == 0 ? "delhi" : "kolkata", 20 + (i % 50)));
            }
            db.commit();

            // §9: absent until something computes them, and that is not an error.
            assertNull(byCity.stats(), "absent before analyze");

            IndexStats s = byCity.analyze();
            assertEquals(300, s.entries, "one entry per document");
            assertTrue(s.distinctEstimate > 0);
            assertTrue(s.minKey.length > 0 && s.maxKey.length > 0);
            assertTrue(java.util.Arrays.compareUnsigned(s.minKey, s.maxKey) < 0);
            assertTrue(!s.histogram.isEmpty());

            IndexStats back = byCity.stats();
            assertNotNull(back, "written to params.stats");
            assertEquals(s.entries, back.entries);
            assertArrayEquals(s.minKey, back.minKey);
            assertEquals(s.histogram.size(), back.histogram.size());
        }
    }

    @Test
    @DisplayName("mostSelective picks on evidence, not on uniqueness")
    void mostSelectivePicksOnEvidence(@TempDir Path dir) {
        // §7.1's complaint about FindPlan: it chooses "by whether it is unique
        // and how many fields it covers", so it "routinely picks a unique index
        // on a field the query barely constrains over a non-unique index that
        // would eliminate 99 % of the collection". Here `city` has 2 distinct
        // values over 300 rows and `age` has 50, so the selective index is
        // `age` -- the one a descriptor-only planner has no reason to prefer.
        try (Database db = Database.create(dir.resolve("t.cryptand"), options())) {
            Collection c = db.collection("people");
            Collection.IndexBinding byCity = c.createIndex(List.of("city"), false, false);
            Collection.IndexBinding byAge = c.createIndex(List.of("age"), false, false);
            for (long i = 0; i < 300; i++) {
                c.insert(doc(i, i % 2 == 0 ? "delhi" : "kolkata", 20 + (i % 50)));
            }
            db.commit();

            List<Collection.IndexBinding> candidates = List.of(byCity, byAge);
            // Before analysis there is no evidence, and §9 says that is "choose
            // some other way", not an error and not a guess.
            assertNull(c.mostSelective(candidates),
                    "no statistics means no answer, never a guess");

            byCity.analyze();
            byAge.analyze();
            Collection.IndexBinding best = c.mostSelective(candidates);
            assertNotNull(best);
            assertEquals(byAge.name, best.name, "the selective index, not the first one");
            assertTrue(byAge.stats().selectivity() < byCity.stats().selectivity(),
                    "age " + byAge.stats().selectivity()
                            + " must be more selective than city " + byCity.stats().selectivity());
        }
    }

    @Test
    @DisplayName("null entries are counted, and a sparse index holds none")
    void nullEntriesAreCounted(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("t.cryptand"), options())) {
            Collection c = db.collection("people");
            // The catalog name derives from the fields and the index type, so a
            // sparse and a dense index over the *same* field would collide.
            // Two fields carrying the same values keeps the comparison honest.
            Collection.IndexBinding dense = c.createIndex(List.of("nick_d"), false, false);
            Collection.IndexBinding sparse = c.createIndex(List.of("nick_s"), false, true);
            for (long i = 0; i < 60; i++) {
                Map<String, Value> f = new LinkedHashMap<>();
                f.put("_id", new Value.NitriteId(i));
                if (i % 3 == 0) {
                    f.put("nick_d", new Value.Str("n" + i));
                    f.put("nick_s", new Value.Str("n" + i));
                }
                c.insert(new Value.Doc(f));
            }
            db.commit();

            IndexStats d = dense.analyze();
            IndexStats s = sparse.analyze();
            assertEquals(60, d.entries, "a dense index holds an entry for every document");
            assertEquals(40, d.nullCount, "and counts the missing ones as null");
            assertEquals(20, s.entries, "a sparse index holds only the present ones");
            assertEquals(0, s.nullCount, "which is what makes it sparse");
        }
    }

    @Test
    @DisplayName("analyze on an empty index is valid and says nothing")
    void analyzeOnAnEmptyIndex(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("t.cryptand"), options())) {
            Collection c = db.collection("people");
            Collection.IndexBinding idx = c.createIndex(List.of("city"), false, false);
            IndexStats s = idx.analyze();
            assertEquals(0, s.entries);
            assertEquals(0, s.distinctEstimate);
            assertTrue(s.histogram.isEmpty());
            assertNull(s.selectivity());
            // And it is still readable back, so a planner sees "no evidence"
            // rather than "no statistics" -- which are different states.
            assertNotNull(idx.stats());
        }
    }

    @Test
    @DisplayName("statistics are advisory: a stale one never changes an answer")
    void statisticsAreAdvisory(@TempDir Path dir) {
        // §9's closing MUST: "a planner MUST produce correct results without
        // them". The concrete form here is that analysing, then changing the
        // data without re-analysing, leaves the query answers untouched.
        try (Database db = Database.create(dir.resolve("t.cryptand"), options())) {
            Collection c = db.collection("people");
            Collection.IndexBinding idx = c.createIndex(List.of("city"), false, false);
            for (long i = 0; i < 50; i++) {
                c.insert(doc(i, "delhi", 30));
            }
            db.commit();
            idx.analyze();

            List<Value> prefix = List.of(new Value.Str("delhi"));
            assertEquals(50, idx.find(prefix).size());

            for (long i = 50; i < 100; i++) {
                c.insert(doc(i, "delhi", 30));
            }
            db.commit();

            assertEquals(100, idx.find(prefix).size(),
                    "the answer follows the data, not the statistics");
            assertEquals(50, idx.stats().entries, "and the statistics really are stale");
        }
    }
}
