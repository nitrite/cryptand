package org.dizitart.cryptand;

import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.lsm.VlogStats;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code spec/01-container.md} §9's verification pass. */
class VerifyTest {

    private static final int TREE = TreeId.FIRST_USER_TREE;

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        // `os` rather than `sync`: these tests are about semantics, and on a
        // spinning or external volume an fsync per commit turns a 150 ms suite
        // into a 60 s one without covering one extra branch. The durability
        // path itself is covered by DurabilityTest, which uses `sync`.
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static Engine.Options readOnlyOptions() {
        Engine.Options o = options();
        o.readOnly = true;
        return o;
    }

    private static byte[] key(long n) {
        return Cke.encode(Value.i64(n));
    }

    private static byte[] val(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("a freshly written database verifies clean")
    void cleanDatabase(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("a.cryptand"), options())) {
            for (int i = 0; i < 500; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            Verify.Report r = Verify.run(e);
            assertTrue(r.clean(), r.toString());
            assertTrue(r.segments() > 0);
        }
    }

    @Test
    @DisplayName("a database with separated values, blobs and compaction verifies clean")
    void afterCompaction(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("b.cryptand"), options())) {
            Random rnd = new Random(5);
            for (int i = 0; i < 800; i++) {
                byte[] value = new byte[i % 7 == 0 ? 2048 : 40];
                rnd.nextBytes(value);
                e.batch().put(TREE, key(i), value).commit();
            }
            byte[] huge = new byte[300_000];
            rnd.nextBytes(huge);
            e.batch().put(TREE, key(-1), huge).commit();
            e.commitNow();
            e.maintain();
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
            assertTrue(r.of(Verify.Kind.DOUBLE_ALLOCATION).isEmpty(), r.toString());
            assertTrue(r.of(Verify.Kind.LEAK).isEmpty(), r.toString());
        }
    }

    @Test
    @DisplayName("a reopened database verifies clean")
    void afterReopen(@TempDir Path dir) {
        Path f = dir.resolve("c.cryptand");
        for (int session = 0; session < 3; session++) {
            try (Engine e = session == 0 ? Engine.create(f, options()) : Engine.open(f, options())) {
                for (int i = 0; i < 200; i++) {
                    e.batch().put(TREE, key(session * 1000L + i), val("v" + i)).commit();
                }
                e.commitNow();
                e.maintain();
                Verify.Report r = Verify.run(e);
                assertTrue(r.of(Verify.Kind.DOUBLE_ALLOCATION).isEmpty(), "session " + session + ": " + r);
                assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), "session " + session + ": " + r);
            }
        }
    }

    /**
     * The verifier has to be able to fail. Every control here would pass a
     * verifier that only counted pages, which is what most of them do.
     */
    @Test
    @DisplayName("a damaged page is reported as corruption, naming the segment")
    void damagedPageIsFound(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("d.cryptand");
        try (Engine e = Engine.create(f, options())) {
            for (int i = 0; i < 300; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
        }
        // A page a live segment actually reaches. A file holds freed pages that
        // still look like leaves, and damaging one of those proves nothing.
        //
        // Read-only for both of these opens, and not as a nicety: a read-write
        // open starts the compactor, and on a machine busy enough that phase
        // one closed with its level-0 segments unmerged, the compactor catches
        // up during the *verifying* open - between Engine.open returning and
        // Verify.run taking the structure lock. The damaged page is then a
        // freed page, the verifier is right to say nothing about it, and the
        // test fails. Measured at 3 runs in 150 under load; 0 in 150 read-only.
        long target;
        try (Engine e = Engine.open(f, readOnlyOptions())) {
            SegmentMeta m = e.manifest().all().get(0);
            target = m.startPage + m.rootPage;
        }
        byte[] raw = Files.readAllBytes(f);
        int pageSize = 8192;
        int base = (int) (target * pageSize);
        raw[base + PageHeader.BYTES + 3] ^= 0x40;
        Files.write(f, raw);
        try (Engine e = Engine.open(f, readOnlyOptions())) {
            Verify.Report r = Verify.run(e);
            assertFalse(r.clean());
            assertFalse(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
        }
    }

    @Test
    @DisplayName("a page that is neither reachable nor free is reported as a leak")
    void leakIsFound(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("e.cryptand"), options())) {
            e.batch().put(TREE, key(1), val("x")).commit();
            e.commitNow();
            // Grow page_count past what anything references. A leak is exactly
            // that: a page neither reachable nor free.
            e.pager().allocate(3);
            Verify.Report r = Verify.run(e);
            assertEquals(3, r.of(Verify.Kind.LEAK).size(), r.toString());
        }
    }

    @Test
    @DisplayName("an encrypted database verifies without the key, and cleanly with it")
    void encryptedVerification(@TempDir Path dir) {
        Path f = dir.resolve("g.cryptand");
        byte[] rawKey = new byte[32];
        new Random(77).nextBytes(rawKey);
        Engine.Options create = options();
        create.encrypt = true;
        create.rawKey = rawKey;
        try (Engine e = Engine.create(f, create)) {
            for (int i = 0; i < 300; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
            assertTrue(r.of(Verify.Kind.TAMPERING).isEmpty(), r.toString());
        }
    }

    @Test
    @DisplayName("understated value-log liveness is reported")
    void livenessMustNotUnderstate(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("h.cryptand"), options())) {
            byte[] big = new byte[2048];
            for (int i = 0; i < 20; i++) {
                e.batch().put(TREE, key(i), big).commit();
            }
            e.commitNow();
            assertTrue(Verify.run(e).of(Verify.Kind.CORRUPTION).isEmpty());
            // Understating is the direction that loses data: GC would skip live
            // records. Overstating merely skips a segment.
            //
            // The sabotage and the check are both under the structure lock,
            // because maintenance recomputes liveness exactly and would repair
            // it in between - which is the engine doing its job and would make
            // this a test of nothing.
            e.lockStructure();
            try {
                List<VlogStats> stats = e.vlog().allStats();
                assertFalse(stats.isEmpty());
                e.vlog().recordDead(stats.get(0).segmentId, Long.MAX_VALUE / 2, 0);
                Verify.Report r = Verify.runLocked(e);
                assertFalse(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
            } finally {
                e.unlockStructure();
            }
        }
    }
}
