package org.dizitart.cryptand.index;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.geom.Wkb;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** F-195: the copy-on-write R-tree answers as brute force does through inserts, updates, removes and reopens. */
class RTreeIncrementalTest {

    private static Value.Doc at(double x, double y) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("loc", new Value.Geometry(Wkb.point(x, y)));
        return Value.Doc.of(f);
    }

    private static TreeSet<Long> brute(Map<Long, double[]> live, double x0, double y0, double x1, double y1) {
        TreeSet<Long> out = new TreeSet<>();
        live.forEach((id, p) -> {
            if (p[0] >= x0 && p[0] <= x1 && p[1] >= y0 && p[1] <= y1) {
                out.add(id);
            }
        });
        return out;
    }

    @Test
    @DisplayName("random writes with early write-backs match brute force, before and after reopen")
    void matchesBruteForce(@TempDir Path dir) {
        int saved = RTree.DIRTY_BUDGET;
        RTree.DIRTY_BUDGET = 8; // write back early and often
        try {
            Engine.Options o = new Engine.Options();
            o.profile = Profile.DESKTOP;
            o.memtableEntries = 256;
            o.durability = Superblock.Durability.OS;
            Path f = dir.resolve("r.cryptand");
            Random rnd = new Random(195);
            Map<Long, double[]> live = new HashMap<>();
            List<Long> ids = new ArrayList<>();
            try (Database db = Database.create(f, o)) {
                Collection c = db.collection("c");
                SpatialIndex sp = c.createSpatialIndex("loc", 2, null);
                for (int step = 0; step < 20_000; step++) {
                    int op = rnd.nextInt(10);
                    double x = rnd.nextDouble() * 100, y = rnd.nextDouble() * 100;
                    if (op < 6 || ids.isEmpty()) {
                        long id = c.insert(at(x, y));
                        ids.add(id);
                        live.put(id, new double[]{x, y});
                    } else if (op < 8) {
                        long id = ids.get(rnd.nextInt(ids.size()));
                        if (live.containsKey(id)) {
                            c.update(id, at(x, y));
                            live.put(id, new double[]{x, y});
                        }
                    } else {
                        long id = ids.get(rnd.nextInt(ids.size()));
                        c.remove(id);
                        live.remove(id);
                    }
                    if (step % 2_000 == 1_999) {
                        db.commit();
                    }
                    if (step % 500 == 0) {
                        double qx = rnd.nextDouble() * 90, qy = rnd.nextDouble() * 90;
                        assertEquals(brute(live, qx, qy, qx + 10, qy + 10),
                                new TreeSet<>(sp.intersects(Wkb.rectangle(qx, qy, qx + 10, qy + 10))), "step " + step);
                    }
                }
                assertEquals(live.size(), sp.intersects(Wkb.rectangle(-1, -1, 101, 101)).size(), "all");
                assertEquals(live.size(), sp.size());
                db.commit();
                assertTrue(Verify.run(db.engine()).findings().isEmpty(), Verify.run(db.engine()).findings().toString());
            }
            try (Database db = Database.open(f, o)) {
                SpatialIndex sp = db.collection("c").spatialIndexes().get(0);
                assertEquals(live.size(), sp.size());
                assertEquals(new TreeSet<>(live.keySet()),
                        new TreeSet<>(sp.intersects(Wkb.rectangle(-1, -1, 101, 101))));
                // nearestK: the 10 returned are the 10 nearest by brute force.
                List<Long> knn = sp.nearestK(50, 50, 10);
                List<Double> d = new ArrayList<>();
                live.values().forEach(p -> d.add(Math.hypot(p[0] - 50, p[1] - 50)));
                d.sort(null);
                for (long id : knn) {
                    double[] p = live.get(id);
                    assertTrue(Math.hypot(p[0] - 50, p[1] - 50) <= d.get(9), "knn " + id);
                }
                assertTrue(Verify.run(db.engine()).findings().isEmpty());
            }
        } finally {
            RTree.DIRTY_BUDGET = saved;
        }
    }
}
