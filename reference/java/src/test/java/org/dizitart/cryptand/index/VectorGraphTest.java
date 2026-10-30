package org.dizitart.cryptand.index;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** F-196: the incremental graph finds the true neighbours, through deletes, early write-backs and a reopen. */
class VectorGraphTest {

    private static Value.Doc doc(float[] v) {
        ByteWriter w = new ByteWriter(v.length * 4);
        for (float f : v) {
            w.f32(f);
        }
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("emb", new Value.Vector(Value.Vector.DTYPE_F32, v.length, w.toBytes()));
        return Value.Doc.of(f);
    }

    private static double recall(VectorIndex index, Map<Long, float[]> live, Random rnd, int dim) {
        int found = 0;
        int queries = 50;
        for (int q = 0; q < queries; q++) {
            float[] query = new float[dim];
            for (int i = 0; i < dim; i++) {
                query[i] = rnd.nextFloat();
            }
            List<Map.Entry<Long, Double>> all = new ArrayList<>();
            live.forEach((id, v) -> all.add(Map.entry(id, VectorIndex.distance("l2", query, v))));
            all.sort(Map.Entry.comparingByValue());
            Set<Long> truth = new HashSet<>();
            for (int i = 0; i < 10; i++) {
                truth.add(all.get(i).getKey());
            }
            List<VectorIndex.Hit> hits = index.search(query, 10);
            assertEquals(10, hits.size());
            for (VectorIndex.Hit h : hits) {
                assertTrue(live.containsKey(h.nitriteId()), "deleted document returned");
                assertEquals(VectorIndex.distance("l2", query, live.get(h.nitriteId())), h.distance(), 1e-9);
                if (truth.contains(h.nitriteId())) {
                    found++;
                }
            }
        }
        return found / (queries * 10.0);
    }

    @Test
    @DisplayName("recall@10 against brute force stays high through deletes and a reopen")
    void recallAgainstBruteForce(@TempDir Path dir) {
        int saved = AdjacencyTree.DIRTY_BUDGET;
        AdjacencyTree.DIRTY_BUDGET = 8;
        try {
            Engine.Options o = new Engine.Options();
            o.profile = Profile.DESKTOP;
            o.memtableEntries = 256;
            o.durability = Superblock.Durability.OS;
            Path f = dir.resolve("v.cryptand");
            int dim = 16;
            Random rnd = new Random(196);
            Map<Long, float[]> live = new HashMap<>();
            List<Long> ids = new ArrayList<>();
            try (Database db = Database.create(f, o)) {
                Collection c = db.collection("c");
                VectorIndex index = c.createVectorIndex("emb", dim, "l2", 16);
                for (int i = 0; i < 4000; i++) {
                    float[] v = new float[dim];
                    for (int k = 0; k < dim; k++) {
                        v[k] = rnd.nextFloat();
                    }
                    long id = c.insert(doc(v));
                    ids.add(id);
                    live.put(id, v);
                    if (i % 1000 == 999) {
                        db.commit();
                    }
                }
                for (int i = 0; i < 400; i++) {
                    long id = ids.get(rnd.nextInt(ids.size()));
                    c.remove(id);
                    live.remove(id);
                }
                double r = recall(index, live, rnd, dim);
                assertTrue(r >= 0.95, "recall " + r);
                assertEquals(0, index.fallbacks, "searches answered by the scan, not the graph");
                db.commit();
                assertTrue(Verify.run(db.engine()).findings().isEmpty(), Verify.run(db.engine()).findings().toString());
            }
            try (Database db = Database.open(f, o)) {
                VectorIndex index = db.collection("c").vectorIndexes().get(0);
                assertEquals(live.size(), index.size());
                double r = recall(index, live, rnd, dim);
                assertTrue(r >= 0.95, "recall after reopen " + r);
                assertEquals(0, index.fallbacks);
                // F-205: a beam as wide as the index is the exact answer.
                float[] q = new float[dim];
                for (int i = 0; i < dim; i++) {
                    q[i] = rnd.nextFloat();
                }
                List<Map.Entry<Long, Double>> all = new ArrayList<>();
                live.forEach((id, v) -> all.add(Map.entry(id, VectorIndex.distance("l2", q, v))));
                all.sort(Map.Entry.comparingByValue());
                List<VectorIndex.Hit> wide = index.search(q, 10, null, live.size());
                for (int i = 0; i < 10; i++) {
                    assertEquals(all.get(i).getKey(), wide.get(i).nitriteId());
                }
                assertTrue(Verify.run(db.engine()).findings().isEmpty());
            }
        } finally {
            AdjacencyTree.DIRTY_BUDGET = saved;
        }
    }

    @Test
    @DisplayName("F-198: clear() empties the spatial and vector indexes of a collection")
    void clearRetractsIndexes(@TempDir Path dir) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;
        try (Database db = Database.create(dir.resolve("c.cryptand"), o)) {
            Collection c = db.collection("c");
            SpatialIndex sp = c.createSpatialIndex("loc", 2, null);
            VectorIndex vx = c.createVectorIndex("emb", 2, "l2", 4);
            for (int i = 1; i <= 50; i++) {
                Map<String, Value> f = new LinkedHashMap<>();
                f.put("loc", new Value.Geometry(org.dizitart.cryptand.geom.Wkb.point(i, 0)));
                f.put("emb", doc(new float[]{i, 0}).fields().get("emb"));
                c.insert(Value.Doc.of(f));
            }
            c.clear();
            assertEquals(0, sp.size());
            assertTrue(vx.search(new float[]{1, 0}, 5).isEmpty(), "a cleared document returned");
            db.commit();
            assertTrue(Verify.run(db.engine()).findings().isEmpty(), Verify.run(db.engine()).findings().toString());
        }
    }

    @Test
    @DisplayName("F-201: a clustered index is navigable beyond the entry point's cluster")
    void clusteredRecall(@TempDir Path dir) {
        // 50 tight clusters of 70 in 128-d: each outgrows m = 32. Without the
        // far slots recall was 0.025: a search never left the entry's cluster.
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;
        int k = 50, p = 70, dim = 128;
        Random rnd = new Random(201);
        float[][] centres = new float[k][dim];
        for (float[] c : centres) {
            for (int d = 0; d < dim; d++) {
                c[d] = rnd.nextFloat();
            }
        }
        try (Database db = Database.create(dir.resolve("k.cryptand"), o)) {
            Collection c = db.collection("c");
            VectorIndex index = c.createVectorIndex("emb", dim, "l2", 64);
            Map<Long, float[]> live = new HashMap<>();
            for (int i = 0; i < k * p; i++) {
                float[] v = new float[dim];
                for (int d = 0; d < dim; d++) {
                    v[d] = centres[i % k][d] + 0.15f * (rnd.nextFloat() - 0.5f);
                }
                live.put(c.insert(doc(v)), v);
            }
            int found = 0;
            for (int q = 0; q < 40; q++) {
                float[] query = new float[dim];
                for (int d = 0; d < dim; d++) {
                    query[d] = centres[q * k / 40][d] + 0.15f * (rnd.nextFloat() - 0.5f);
                }
                List<Map.Entry<Long, Double>> all = new ArrayList<>();
                live.forEach((id, v) -> all.add(Map.entry(id, VectorIndex.distance("l2", query, v))));
                all.sort(Map.Entry.comparingByValue());
                Set<Long> truth = new HashSet<>();
                for (int i = 0; i < 10; i++) {
                    truth.add(all.get(i).getKey());
                }
                for (VectorIndex.Hit h : index.search(query, 10)) {
                    if (truth.contains(h.nitriteId())) {
                        found++;
                    }
                }
            }
            double r = found / 400.0;
            assertTrue(r >= 0.9, "recall " + r);
        }
    }
}
