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
     * F-093: a batch's values are in the value log before its entries are in
     * the memtable. A segment its own append sealed, collected in that window,
     * looked dead and was freed under the batch's pointers.
     */
    @Test
    void collectionWaitsForABatchBetweenItsValuesAndItsEntries(@TempDir Path dir) throws Exception {
        Engine.Options o = new Engine.Options();
        o.profile = org.dizitart.cryptand.container.Profile.MOBILE; // 4 MiB segments
        o.durability = Superblock.Durability.NONE;
        o.vlogMin = 64;
        o.backgroundCompaction = false;
        Engine e = Engine.create(dir.resolve("db.cff"), o);
        int old = 4000; // ~4.09 MB of the open segment's ~4.19 MB
        for (int k = 0; k < old; k++) {
            e.batch().put(1, key(k >> 8, k & 0xFF), new byte[1000]).commit();
        }
        for (int k = old / 8; k < old; k++) { // an eighth stays live, so collection has a reason to run
            e.batch().remove(1, key(k >> 8, k & 0xFF)).commit();
        }
        e.commitNow(true);
        e.compact(); // the old records are dead: the segment is a GC candidate once sealed
        Thread[] gc = new Thread[1];
        Engine first = e;
        Engine.afterValuesHook = () -> {
            Engine.afterValuesHook = null;
            gc[0] = new Thread(first::collectIfNeeded);
            gc[0].start();
            try {
                gc[0].join(2000); // the fix blocks it on this batch; the bug finishes it here
            } catch (InterruptedException x) {
                throw new AssertionError(x);
            }
        };
        Engine.Batch b = e.batch();
        for (int k = 0; k < 200; k++) {
            b.put(1, key(100, k), new byte[1000]); // overflows the segment: this batch seals it
        }
        try {
            b.commit();
        } finally {
            Engine.afterValuesHook = null;
        }
        gc[0].join();
        e.close(); // a retired segment stays readable in-session; the file is what counts
        e = Engine.open(dir.resolve("db.cff"), o);
        for (int k = 0; k < 200; k++) {
            assertEquals(1000, e.get(1, key(100, k)).length);
        }
        e.close();
    }

    /**
     * F-100, M2.2 torture seed 101908: a liveness refresh in the same window
     * walked the batch's records, found no entry naming them, and stored the
     * segment's {@code live_bytes} below what the trees reference.
     */
    @Test
    void livenessRefreshWaitsForABatchBetweenItsValuesAndItsEntries(@TempDir Path dir) throws Exception {
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        o.vlogMin = 64;
        o.backgroundCompaction = false;
        Engine e = Engine.create(dir.resolve("db.cff"), o);
        Thread[] refresh = new Thread[1];
        Engine first = e;
        Engine.afterValuesHook = () -> {
            Engine.afterValuesHook = null;
            refresh[0] = new Thread(first::clusterIfNeeded);
            refresh[0].start();
            try {
                refresh[0].join(2000); // the fix blocks it on this batch; the bug finishes it here
            } catch (InterruptedException x) {
                throw new AssertionError(x);
            }
        };
        Engine.Batch b = e.batch();
        for (int k = 0; k < 400; k++) { // overflows F-096's first 256 KiB segment: this batch seals it
            b.put(1, key(1, k), new byte[1000]);
        }
        try {
            b.commit();
        } finally {
            Engine.afterValuesHook = null;
        }
        refresh[0].join();
        e.commitNow(true);
        e.abandon(); // the kill: close() would recount and hide it
        e = Engine.open(dir.resolve("db.cff"), o);
        org.dizitart.cryptand.ops.Verify.Report r = org.dizitart.cryptand.ops.Verify.run(e);
        e.close();
        assertTrue(r.clean(), r.toString());
    }

    /**
     * F-100, the second half: a refresh judged a durable record dead because
     * an overwrite still only in the memtable shadowed it; a publish then made
     * the count durable without the overwrite, and the crash lost it.
     */
    @Test
    void livenessIgnoresAnOverwriteNotYetFlushed(@TempDir Path dir) {
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        o.vlogMin = 64;
        o.memtableEntries = 100_000;
        o.backgroundCompaction = false;
        Engine e = Engine.create(dir.resolve("db.cff"), o);
        e.batch().put(1, key(1, 1), new byte[1000]).commit();
        for (int k = 0; k < 300; k++) { // overflows F-096's first 256 KiB segment: key(1, 1)'s is sealed
            e.batch().put(1, key(2, k), new byte[1000]).commit();
        }
        e.commitNow(true);
        e.batch().put(1, key(1, 1), new byte[1000]).commit(); // the overwrite, memtable only
        e.clusterIfNeeded(); // refreshes liveness
        e.commitNow(false); // publishes tree 7; the shard is under budget and stays
        e.abandon();
        e = Engine.open(dir.resolve("db.cff"), o);
        org.dizitart.cryptand.ops.Verify.Report r = org.dizitart.cryptand.ops.Verify.run(e);
        e.close();
        assertTrue(r.clean(), r.toString());
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

    /**
     * F-049: §9 says a backwards clock jump resurrects an expired entry. GC
     * freed the value of an entry that was merely expired, so the resurrected
     * entry pointed at nothing.
     */
    @Test
    void anExpiredEntryKeepsItsValueThroughCollection(@TempDir Path dir) {
        long[] clock = {0};
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        o.vlogMin = 64;
        o.backgroundCompaction = false;
        o.clock = () -> clock[0];
        Path path = dir.resolve("db.cff");
        Engine e = Engine.create(path, o);
        int keys = 2_000;
        e.batch().putWithExpiry(1, key(9, 9), new byte[1000], 1000).commit();
        for (int k = 0; k < keys; k++) {
            e.batch().put(1, key(k >> 8, k & 0xFF), new byte[1000]).commit();
        }
        e.close(); // seals the value-log segment, so GC may take it
        e = Engine.open(path, o);
        for (int k = 0; k < keys; k++) {
            e.batch().put(1, key(k >> 8, k & 0xFF), new byte[1001]).commit();
        }
        clock[0] = 2000; // the entry expires
        e.commitNow(true);
        long gc = e.bytesWrittenGc();
        e.collectIfNeeded();
        e.commitNow(true);
        assertTrue(e.vlog().allStats().stream().noneMatch(st -> st.segmentId == 1),
                "segment 1 was not collected; the test needs it to be (GC moved " + (e.bytesWrittenGc() - gc) + " bytes)");
        e.close();
        clock[0] = 0; // §9: a backwards jump resurrects the entry, and its value
        e = Engine.open(path, o);
        byte[] v = e.get(1, key(9, 9));
        e.close();
        assertEquals(1000, v == null ? -1 : v.length);
    }

    /** F-050: 01 §5, a blob "is reclaimed on its own" when compaction drops its entry. */
    @Test
    void aDroppedBlobsExtentIsFreed(@TempDir Path dir) {
        Engine.Options o = new Engine.Options();
        o.backgroundCompaction = false;
        Path path = dir.resolve("db.cff");
        Engine e = Engine.create(path, o);
        e.batch().put(1, key(0, 0), new byte[300_000]).commit(); // above blob_threshold
        e.commitNow(true);
        e.compact();
        e.batch().put(1, key(0, 0), new byte[10]).commit();
        e.commitNow(true);
        e.compact();
        e.commitNow(true);
        e.close();
        e = Engine.open(path, o);
        var leaks = org.dizitart.cryptand.ops.Verify.run(e).findings().stream()
                .filter(f -> f.kind() == org.dizitart.cryptand.ops.Verify.Kind.LEAK).collect(java.util.stream.Collectors.toList());
        e.close();
        assertTrue(leaks.isEmpty(), leaks.toString());
    }

    private static byte[] key(int w, int k) {
        return Cke.encode(new Value.Bytes(new byte[]{(byte) w, (byte) k}));
    }

    private static byte[] value(int w, int k, int r) {
        return ByteBuffer.allocate(200).putInt(w).putInt(k).putInt(r).array();
    }
}
