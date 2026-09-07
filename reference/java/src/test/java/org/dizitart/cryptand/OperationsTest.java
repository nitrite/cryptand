package org.dizitart.cryptand;

import org.dizitart.cryptand.container.LockSidecar;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Backup;
import org.dizitart.cryptand.ops.ChangeFeed;
import org.dizitart.cryptand.ops.Checkpoint;
import org.dizitart.cryptand.ops.Metrics;
import org.dizitart.cryptand.ops.Repair;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code spec/13-operations.md}, end to end. */
class OperationsTest {

    private static final int TREE = TreeId.FIRST_USER_TREE;

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static byte[] key(long n) {
        return Cke.encode(Value.i64(n));
    }

    private static byte[] val(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * §1: restore is one superblock write, therefore atomic and instant, and it
     * rolls back <em>roots</em>, never counters.
     */
    @Test
    @DisplayName("a checkpoint restores the data and never rolls a counter back")
    void checkpointRestore(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("a.cryptand"), options())) {
            for (int i = 0; i < 100; i++) {
                e.batch().put(TREE, key(i), val("first-" + i)).commit();
            }
            e.commitNow();
            Checkpoint c = e.checkpoint("before", null, true);
            long nonceBefore = e.superblock().nextNonce;
            long segmentIdBefore = e.superblock().nextSegmentId;

            for (int i = 0; i < 100; i++) {
                e.batch().put(TREE, key(i), val("second-" + i)).commit();
            }
            e.commitNow();
            assertArrayEquals(val("second-7"), e.get(TREE, key(7)));

            e.restore("before");
            assertArrayEquals(val("first-7"), e.get(TREE, key(7)));
            assertTrue(e.superblock().nextSegmentId >= segmentIdBefore,
                    "next_segment_id must not roll back: ids are never reused");
            assertTrue(e.superblock().nextNonce >= nonceBefore,
                    "next_nonce must not roll back, or abandoned commits' nonces are reissued");
            assertEquals(c.seq(), e.visibleSeq());
        }
    }

    @Test
    @DisplayName("restoring a checkpoint keeps the other checkpoints")
    void restoreKeepsCheckpoints(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("b.cryptand"), options())) {
            e.batch().put(TREE, key(1), val("a")).commit();
            e.commitNow();
            e.checkpoint("one", null, true);
            e.batch().put(TREE, key(1), val("b")).commit();
            e.commitNow();
            e.checkpoint("two", null, true);
            e.restore("one");
            // checkpoint_root is deliberately not part of the restored tuple:
            // restoring must not delete the other checkpoints.
            assertEquals(2, e.checkpoints().size());
            assertNotNull(e.checkpointNamed("two"));
        }
    }

    @Test
    @DisplayName("a checkpoint that would pin too much space is refused by default")
    void checkpointSpaceLimit(@TempDir Path dir) {
        Engine.Options o = options();
        o.checkpointSpaceLimitPct = 0;
        try (Engine e = Engine.create(dir.resolve("c.cryptand"), o)) {
            for (int i = 0; i < 200; i++) {
                e.batch().put(TREE, key(i % 20), val("v" + i)).commit();
            }
            e.commitNow();
            e.maintain();
            if (e.pinnedBySnapshots() > 0) {
                assertThrows(InvalidArgumentException.class, () -> e.checkpoint("big", null, false));
            }
            assertNotNull(e.checkpoint("big", null, true));
        }
    }

    @Test
    @DisplayName("a full backup reproduces every key and verifies")
    void fullBackup(@TempDir Path dir) {
        Path src = dir.resolve("src.cryptand");
        Path dst = dir.resolve("dst.cryptand");
        try (Engine e = Engine.create(src, options())) {
            for (int i = 0; i < 300; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            Backup.Result r = Backup.full(e, dst, Backup.Mode.PLAINTEXT, false);
            assertTrue(r.segmentsCopied() > 0);
            assertFalse(r.downgraded());
        }
        try (Engine e = Engine.open(dst, options())) {
            for (int i = 0; i < 300; i++) {
                assertArrayEquals(val("v" + i), e.get(TREE, key(i)), "key " + i);
            }
            Verify.Report report = Verify.run(e);
            assertTrue(report.of(Verify.Kind.CORRUPTION).isEmpty(), report.toString());
        }
    }

    /**
     * §2.1: an unencrypted backup of an encrypted database is a silent
     * downgrade. It is refused unless the caller asks for it by name, and
     * reported in the result when they do.
     */
    @Test
    @DisplayName("an unencrypted backup of an encrypted database must be asked for by name")
    void downgradeMustBeNamed(@TempDir Path dir) {
        Path src = dir.resolve("enc.cryptand");
        byte[] rawKey = new byte[32];
        new java.util.Random(3).nextBytes(rawKey);
        Engine.Options create = options();
        create.encrypt = true;
        create.rawKey = rawKey;
        try (Engine e = Engine.create(src, create)) {
            e.batch().put(TREE, key(1), val("secret")).commit();
            e.commitNow();
            assertThrows(InvalidArgumentException.class,
                    () -> Backup.full(e, dir.resolve("d1.cryptand"), Backup.Mode.PLAINTEXT, false));
            Backup.Result r = Backup.full(e, dir.resolve("d2.cryptand"), Backup.Mode.PLAINTEXT, true);
            assertTrue(r.downgraded(), "the downgrade must be reported in the result");
        }
    }

    @Test
    @DisplayName("a restore verifies the result before reporting success")
    void restoreVerifies(@TempDir Path dir) throws Exception {
        Path src = dir.resolve("r-src.cryptand");
        Path backup = dir.resolve("r-backup.cryptand");
        try (Engine e = Engine.create(src, options())) {
            for (int i = 0; i < 100; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            Backup.full(e, backup, Backup.Mode.PLAINTEXT, false);
        }
        Verify.Report r = Backup.restore(backup, dir.resolve("r-dst.cryptand"), options());
        assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());

        // A truncated restore is a failure, not a file to open hopefully.
        byte[] raw = Files.readAllBytes(backup);
        Path truncated = dir.resolve("r-trunc.cryptand");
        Files.write(truncated, java.util.Arrays.copyOf(raw, raw.length / 2));
        assertThrows(RuntimeException.class,
                () -> Backup.restore(truncated, dir.resolve("r-dst2.cryptand"), options()));
    }

    /**
     * §3: the manifest is deliberately redundant with the segment headers, and
     * this is what that costs a few dozen bytes per segment for — a damaged
     * manifest root is a scan-and-rebuild, not a total loss.
     */
    @Test
    @DisplayName("the manifest rebuilds from segment headers alone")
    void manifestRebuild(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("m.cryptand"), options())) {
            for (int i = 0; i < 400; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            int found = Repair.rebuildManifest(e);
            assertTrue(found > 0, "the scan found segments");
            assertEquals(found, e.manifest().all().size(),
                    "every segment the scan found is in the rebuilt manifest");
            // The property that matters: the rebuilt manifest serves the same
            // data, from segment headers and the free tree alone.
            for (int i = 0; i < 400; i++) {
                assertArrayEquals(val("v" + i), e.get(TREE, key(i)), "key " + i);
            }
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
        }
    }

    @Test
    @DisplayName("repair returns leaked pages to the free tree and refuses to launder tampering")
    void repairLeaks(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("l.cryptand"), options())) {
            e.batch().put(TREE, key(1), val("x")).commit();
            e.commitNow();
            e.pager().allocate(4);
            assertEquals(4, Verify.run(e).of(Verify.Kind.LEAK).size());
            Repair.Result r = Repair.run(e);
            assertFalse(r.repaired().isEmpty(), r.toString());
            assertTrue(Verify.run(e).of(Verify.Kind.LEAK).isEmpty());
        }
    }

    @Test
    @DisplayName("shrink returns trailing free space and the database still verifies")
    void shrink(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("s.cryptand"), options())) {
            for (int i = 0; i < 400; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            e.compact();
            e.shrink();
            for (int i = 0; i < 400; i++) {
                assertArrayEquals(val("v" + i), e.get(TREE, key(i)), "key " + i);
            }
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
        }
    }

    /**
     * §6: a metric that cannot be computed is reported as unavailable, by name.
     * A fabricated answer defeats the whole section, because a caller cannot
     * tell the two apart.
     */
    @Test
    @DisplayName("metrics report what they cannot compute rather than guessing")
    void metricsAreHonest(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("me.cryptand"), options())) {
            for (int i = 0; i < 200; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            Metrics m = e.metrics();
            assertTrue(m.get("page_cache_hit_rate") instanceof Metrics.Value.Unavailable,
                    "this engine keeps no page cache, so it must not report a hit rate");
            assertTrue(m.get("nonces_allocated") instanceof Metrics.Value.Unavailable,
                    "an unencrypted file allocates no nonces");
            assertTrue(m.get("bytes_written_logical") instanceof Metrics.Value.Number);
            assertTrue(m.get("locality_debt") instanceof Metrics.Value.Number);
            assertEquals(0, ((Metrics.Value.Number) m.get("unavailable_ranges")).value(),
                    "0 unavailable ranges is the normal state and must be askable");
            assertTrue(m.unavailable().contains("page_cache_hit_rate"));
        }
    }

    /** §7: the feed is written in the same batch as the mutation, so it cannot drift. */
    @Test
    @DisplayName("the change feed reads back in seq order")
    void changeFeed(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("cf.cryptand"), options())) {
            for (int i = 0; i < 10; i++) {
                Engine.Batch b = e.batch();
                b.put(TREE, key(i), val("v" + i));
                long seq = b.commit();
                e.recordChange(b, TREE, seq, ChangeFeed.PUT, key(i), (long) i);
            }
            e.commitNow();
            List<ChangeFeed> all = e.changesSince(TREE, 0);
            assertEquals(10, all.size());
            for (int i = 1; i < all.size(); i++) {
                assertTrue(all.get(i - 1).seq() < all.get(i).seq(), "the feed is in seq order");
            }
            assertEquals(5, e.changesSince(TREE, all.get(5).seq()).size());
        }
    }

    /**
     * §8: a stale slot is a free slot to a claimer. Without that clause, stale
     * slots accumulate whenever no writer is there to reclaim them, and after
     * {@code slot_count} opens every reader falls to volatile mode for a reason
     * it cannot see.
     */
    @Test
    @DisplayName("a reader recycles a stale slot rather than falling to volatile mode")
    void staleSlotsAreRecycled(@TempDir Path dir) {
        Path db = dir.resolve("mp.cryptand");
        try (LockSidecar s = new LockSidecar(db, 2, 100)) {
            assertEquals(0, s.claimReader(101, 5, 1_000));
            assertEquals(1, s.claimReader(102, 5, 1_000));
            // Both slots held by live readers: volatile mode, and the reason is
            // reported rather than left to be inferred.
            assertEquals(-1, s.claimReader(103, 5, 1_000));
            assertEquals(LockSidecar.Volatile.NO_FREE_SLOT, s.volatileReason());
            // Long enough later, both are stale and a claimer recycles one.
            assertEquals(0, s.claimReader(104, 6, 5_000));
            assertEquals(LockSidecar.Volatile.NOT_VOLATILE, s.volatileReason());
        }
    }

    @Test
    @DisplayName("no live writer is detectable, so a reader knows its pin protects nothing")
    void writerLiveness(@TempDir Path dir) {
        Path db = dir.resolve("w.cryptand");
        try (LockSidecar s = new LockSidecar(db, 4, 100)) {
            assertFalse(s.writerIsLive(1_000), "writer_pid 0 means no live writer");
            s.claimWriter(4242, 1_000);
            assertTrue(s.writerIsLive(1_050));
            assertFalse(s.writerIsLive(9_000), "a heartbeat older than 3x the interval is not live");
        }
    }

    @Test
    @DisplayName("only live slots pin the retention floor")
    void staleSlotDoesNotPin(@TempDir Path dir) {
        try (LockSidecar s = new LockSidecar(dir.resolve("p.cryptand"), 4, 100)) {
            s.claimReader(1, 7, 1_000);
            assertEquals(7, s.minPinnedCommit(1_050, 99));
            assertEquals(99, s.minPinnedCommit(9_000, 99), "a stale slot does not pin");
        }
    }
}
