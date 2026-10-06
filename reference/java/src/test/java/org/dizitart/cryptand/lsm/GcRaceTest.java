package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** F-030: a GC rewrite must not shadow a user write that lands between its liveness check and its insert. */
class GcRaceTest {
    @Test
    void collectionNeverShadowsAConcurrentWrite(@TempDir Path dir) throws Exception {
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        o.vlogMin = 64;
        o.memtableEntries = 64;
        Engine e = Engine.create(dir.resolve("db.cff"), o);
        // Natural timing almost never hits the window (0 in 134k rewrites); this does.
        Engine.rewriteDelayNanos = 200_000;
        int writers = 4, keys = 256, rounds = 10_000;
        int[][] last = new int[writers][keys];
        AtomicBoolean done = new AtomicBoolean();
        Thread gc = new Thread(() -> {
            while (!done.get()) {
                e.compact();
                e.collect();
                e.clusterIfNeeded();
            }
        });
        gc.start();
        Thread[] ws = new Thread[writers];
        for (int w = 0; w < writers; w++) {
            int id = w;
            ws[w] = new Thread(() -> {
                java.util.Random rnd = new java.util.Random(id);
                for (int r = 1; r <= rounds; r++) {
                    // Skewed: hot keys churn, cold ones stay live in old segments for GC to move.
                    int k = (int) (keys * Math.pow(rnd.nextDouble(), 3));
                    e.batch().put(1, key(id, k), value(id, k, r)).commit();
                    last[id][k] = r;
                }
            });
            ws[w].start();
        }
        for (Thread t : ws) {
            t.join();
        }
        done.set(true);
        gc.join();
        Engine.rewriteDelayNanos = 0;
        int stale = 0;
        for (int w = 0; w < writers; w++) {
            for (int k = 0; k < keys; k++) {
                byte[] got = e.get(1, key(w, k));
                int want = last[w][k];
                if (want == 0 ? got != null : got == null || ByteBuffer.wrap(got).getInt(8) != want) {
                    stale++;
                }
            }
        }
        e.close();
        assertEquals(0, stale, "keys whose newest write was shadowed");
    }

    /**
     * F-037: a reader whose seq predates a GC rewrite still resolves the old
     * pointer after the segment is retired. Deterministic stand-in for a
     * snapshot pinned while GC runs: a cursor registered at an older seq.
     */
    @Test
    void aReaderOlderThanTheRewriteStillReadsARetiredSegment(@TempDir Path dir) {
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        o.vlogMin = 64;
        o.backgroundCompaction = false;
        Engine e = Engine.create(dir.resolve("db.cff"), o);
        int keys = 2_000;
        for (int k = 0; k < keys; k++) {
            e.batch().put(1, key(k >> 8, k & 0xFF), new byte[1000]).commit();
        }
        e.close(); // seals the value-log segment, so GC may take it
        e = Engine.open(dir.resolve("db.cff"), o);
        for (int k = 0; k < keys; k++) {
            if (k % 5 != 0) {
                e.batch().put(1, key(k >> 8, k & 0xFF), new byte[1001]).commit();
            }
        }
        e.commitNow(true);
        long before = e.superblock().visibleSeq;
        long gc = e.bytesWrittenGc();
        e.collectIfNeeded();
        assertTrue(e.bytesWrittenGc() > gc, "GC moved nothing; the test needs it to");
        // A cursor registers the old seq, as a snapshot pinned mid-GC would;
        // point reads check the segment's watermark in tree 7.
        try (Engine.Cursor c = e.scan(1, null, null, false, before, 0)) {
            for (int k = 0; k < keys; k += 5) {
                assertEquals(1000, e.get(1, key(k >> 8, k & 0xFF), before, 0).length);
            }
        }
        e.close();
    }

    private static byte[] key(int w, int k) {
        return Cke.encode(new Value.Bytes(new byte[]{(byte) w, (byte) k}));
    }

    private static byte[] value(int w, int k, int r) {
        return ByteBuffer.allocate(200).putInt(w).putInt(k).putInt(r).array();
    }
}
