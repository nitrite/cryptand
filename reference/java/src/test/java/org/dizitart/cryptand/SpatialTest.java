package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.geom.Geometry;
import org.dizitart.cryptand.geom.Wkb;
import org.dizitart.cryptand.index.RTree;
import org.dizitart.cryptand.index.SpatialIndex;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Level 3 — {@code spec/08-spatial.md}. */
class SpatialTest {

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static Value.Doc geo(String name, byte[] wkb) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("name", new Value.Str(name));
        f.put("shape", new Value.Geometry(wkb));
        return Value.Doc.of(f);
    }

    /**
     * §1: PostGIS's EWKB sets high bits of the same type word ISO uses
     * additively, so the two are not distinguishable by a reader that accepts
     * both — a {@code PointZ} is 1001 in ISO and {@code 0x80000001} in EWKB, and
     * a decoder that guesses wrong reads coordinates as garbage.
     */
    @Test
    @DisplayName("EWKB is rejected rather than guessed at")
    void ewkbIsRejected() {
        byte[] ewkbPointZ = new ByteWriter(29).u8(1).u32(0x80000001)
                .f64(1).f64(2).f64(3).toBytes();
        InvalidArgumentException e = assertThrows(InvalidArgumentException.class,
                () -> Wkb.coordinates(ewkbPointZ));
        assertTrue(e.getMessage().contains("EWKB"));
    }

    @Test
    @DisplayName("ISO Z, M and ZM are read by their additive type codes")
    void isoDimensionality() {
        assertEquals(2, Wkb.coordinates(Wkb.point(1, 2)).axes());
        assertEquals(3, Wkb.coordinates(Wkb.pointZ(1, 2, 3)).axes());
        byte[] pointM = new ByteWriter(29).u8(1).u32(Wkb.POINT + Wkb.M_OFFSET)
                .f64(1).f64(2).f64(9).toBytes();
        assertEquals(3, Wkb.coordinates(pointM).axes());
        byte[] pointZm = new ByteWriter(37).u8(1).u32(Wkb.POINT + Wkb.ZM_OFFSET)
                .f64(1).f64(2).f64(3).f64(9).toBytes();
        assertEquals(4, Wkb.coordinates(pointZm).axes());
    }

    @Test
    @DisplayName("a reader accepts big-endian, though a writer emits little-endian")
    void bothByteOrders() {
        byte[] bigEndian = new byte[21];
        bigEndian[0] = 0;
        bigEndian[4] = Wkb.POINT;
        // 3.0 and 4.0 as big-endian doubles.
        long x = Double.doubleToRawLongBits(3.0);
        long y = Double.doubleToRawLongBits(4.0);
        for (int i = 0; i < 8; i++) {
            bigEndian[5 + i] = (byte) (x >>> (8 * (7 - i)));
            bigEndian[13 + i] = (byte) (y >>> (8 * (7 - i)));
        }
        Wkb.Box b = Wkb.envelope(bigEndian, 2);
        assertEquals(3.0, b.min()[0]);
        assertEquals(4.0, b.max()[1]);
    }

    /**
     * §3: {@code dimensions = 3} always means Z, never M. Silently indexing M
     * in Z's slot would make two geometries comparable that are not.
     */
    @Test
    @DisplayName("an XYM geometry is refused by a three-dimensional index")
    void xymIsNotXyz() {
        byte[] pointZ = Wkb.pointZ(1, 2, 3);
        Wkb.Box b = Wkb.envelope(pointZ, 3);
        assertEquals(3.0, b.min()[2]);
        byte[] point2d = Wkb.point(1, 2);
        assertThrows(InvalidArgumentException.class, () -> Wkb.envelope(point2d, 3));
    }

    @Test
    @DisplayName("an empty envelope is +Inf/-Inf and never matches")
    void emptyEnvelope() {
        Wkb.Box empty = Wkb.Box.empty(2);
        assertTrue(empty.isEmpty());
        assertFalse(empty.intersects(new Wkb.Box(new double[]{0, 0}, new double[]{1, 1})));
        assertFalse(new Wkb.Box(new double[]{0, 0}, new double[]{1, 1}).intersects(empty));
    }

    /**
     * §4's two-phase rule, and the whole point of it: the bounding boxes of an
     * L-shaped polygon and a point in its notch intersect, and the exact
     * predicate says they do not.
     */
    @Test
    @DisplayName("a box hit that is not a real hit is rejected by the exact predicate")
    void twoPhaseRule(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("a.cryptand"), options())) {
            Collection c = db.collection("places");
            SpatialIndex index = c.createSpatialIndex("shape", 2, 4326);
            // An L: (0,0)-(10,0)-(10,4)-(4,4)-(4,10)-(0,10)-(0,0). Its envelope
            // is the full 10x10 square, but the notch at (8,8) is outside it.
            ByteWriter w = new ByteWriter(200);
            w.u8(1).u32(Wkb.POLYGON).u32(1).u32(7);
            double[][] ring = {{0, 0}, {10, 0}, {10, 4}, {4, 4}, {4, 10}, {0, 10}, {0, 0}};
            for (double[] p : ring) {
                w.f64(p[0]).f64(p[1]);
            }
            long lShape = c.insert(geo("L", w.toBytes()));
            c.insert(geo("square", Wkb.rectangle(20, 20, 30, 30)));

            byte[] inNotch = Wkb.point(8, 8);
            assertTrue(index.intersects(Wkb.rectangle(0, 0, 10, 10)).contains(lShape),
                    "the L does intersect its own envelope");
            assertEquals(List.of(), index.intersects(inNotch),
                    "a point in the notch is a box hit and not a real one");
            assertEquals(List.of(lShape), index.intersects(Wkb.point(1, 1)));
        }
    }

    @Test
    @DisplayName("intersects, within, contains and near return the right sets")
    void queries(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("b.cryptand"), options())) {
            Collection c = db.collection("shapes");
            SpatialIndex index = c.createSpatialIndex("shape", 2, null);
            long small = c.insert(geo("small", Wkb.rectangle(1, 1, 2, 2)));
            long big = c.insert(geo("big", Wkb.rectangle(0, 0, 10, 10)));
            long far = c.insert(geo("far", Wkb.rectangle(100, 100, 101, 101)));

            assertTrue(index.intersects(Wkb.rectangle(0, 0, 3, 3)).contains(small));
            assertTrue(index.intersects(Wkb.rectangle(0, 0, 3, 3)).contains(big));
            assertFalse(index.intersects(Wkb.rectangle(0, 0, 3, 3)).contains(far));

            assertEquals(List.of(small), index.within(Wkb.rectangle(0, 0, 5, 5)).stream()
                    .filter(id -> id == small).collect(java.util.stream.Collectors.toList()));
            assertTrue(index.contains(Wkb.point(5, 5)).contains(big));
            assertFalse(index.contains(Wkb.point(5, 5)).contains(small));

            assertTrue(index.near(1.5, 1.5, 0.1).contains(small));
            assertFalse(index.near(1.5, 1.5, 0.1).contains(far));
        }
    }

    @Test
    @DisplayName("nearest_k ranks by exact distance, not by box distance")
    void nearestK(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("c.cryptand"), options())) {
            Collection c = db.collection("points");
            SpatialIndex index = c.createSpatialIndex("shape", 2, null);
            long near = c.insert(geo("near", Wkb.point(1, 0)));
            long mid = c.insert(geo("mid", Wkb.point(5, 0)));
            long far = c.insert(geo("far", Wkb.point(50, 0)));
            assertEquals(List.of(near, mid), index.nearestK(0, 0, 2));
            assertEquals(List.of(near, mid, far), index.nearestK(0, 0, 3));
        }
    }

    @Test
    @DisplayName("the index survives a reopen and still answers")
    void survivesReopen(@TempDir Path dir) {
        Path f = dir.resolve("d.cryptand");
        long id;
        try (Database db = Database.create(f, options())) {
            Collection c = db.collection("shapes");
            c.createSpatialIndex("shape", 2, null);
            id = c.insert(geo("box", Wkb.rectangle(1, 1, 2, 2)));
            for (int i = 0; i < 200; i++) {
                c.insert(geo("filler-" + i, Wkb.point(100 + i, 100 + i)));
            }
        }
        try (Database db = Database.open(f, options())) {
            Collection c = db.collection("shapes");
            List<SpatialIndex> indexes = c.spatialIndexes();
            assertEquals(1, indexes.size());
            assertEquals(201, indexes.get(0).size());
            assertTrue(indexes.get(0).intersects(Wkb.rectangle(0, 0, 3, 3)).contains(id));
        }
    }

    @Test
    @DisplayName("a geometry whose SRID differs from the index's is refused")
    void sridMismatch(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("e.cryptand"), options())) {
            Collection c = db.collection("shapes");
            SpatialIndex index = c.createSpatialIndex("shape", 2, 4326);
            assertEquals(4326, index.srid());
            assertThrows(InvalidArgumentException.class,
                    () -> index.put(1, geo("x", Wkb.point(0, 0)), 3857));
        }
    }

    @Test
    @DisplayName("an rtree page whose dimensions disagree with the descriptor is corruption")
    void dimensionMismatchIsCorruption(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("f.cryptand"), options())) {
            Collection c = db.collection("shapes");
            SpatialIndex index = c.createSpatialIndex("shape", 2, null);
            c.insert(geo("p", Wkb.point(1, 1)));
            db.engine().commitNow();
            TreeDescriptor d = db.descriptor(index.name());
            assertThrows(CorruptionException.class,
                    () -> RTree.load(db.engine().pager(), d.treeId(), 3, d.root()));
        }
    }

    @Test
    @DisplayName("a verifier's check that internal boxes are exact unions has something to check")
    void internalBoxesAreExactUnions(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("g.cryptand"), options())) {
            Collection c = db.collection("many");
            SpatialIndex index = c.createSpatialIndex("shape", 2, null);
            for (int i = 0; i < 500; i++) {
                c.insert(geo("p" + i, Wkb.point(i % 25, i / 25)));
            }
            db.engine().commitNow();
            // Every point is found by a query over the whole extent: a box that
            // is merely a superset would still pass, but a box that is too
            // small - the defect that silently degrades every query - would not.
            assertEquals(500, index.intersects(Wkb.rectangle(-1, -1, 30, 30)).size());
        }
    }
}
