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
                assertTrue(Verify.run(db.engine()).findings().isEmpty());
            }
        } finally {
            AdjacencyTree.DIRTY_BUDGET = saved;
        }
    }
}
