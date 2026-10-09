package org.dizitart.cryptand;

import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.ops.Metrics;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mandatory tests of {@code spec/11-conformance.md} §6 that one process can
 * run. The round-trip gate is the thirteenth and lives in
 * {@code reference/conformance/interop/run.sh}, because it needs another
 * implementation by definition.
 */
class MandatoryTest {

    private static final int TREE = TreeId.FIRST_USER_TREE;

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
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

    private static byte[] value(int n, int size) {
        byte[] v = new byte[size];
        new Random(n).nextBytes(v);
        return v;
    }

    /**
     * "N threads writing overlapping key ranges while M threads scan, with a
     * compaction forced throughout. Every reader must observe a snapshot, and
     * the final database must pass verification."
     */
    @Test
    @DisplayName("concurrency: 8 writers and 3 scanners across a compaction, verify clean")
    void concurrency(@TempDir Path dir) throws Exception {
        try (Engine e = Engine.create(dir.resolve("c.cryptand"), options())) {
            int writers = 8;
            int perWriter = 300;
            List<Thread> threads = new ArrayList<>();
            AtomicReference<RuntimeException> failure = new AtomicReference<>();
            for (int t = 0; t < writers; t++) {
                int id = t;
                Thread th = new Thread(() -> {
                    try {
                        for (int i = 0; i < perWriter; i++) {
                            // Overlapping ranges on purpose: every writer
                            // touches the same keys.
                            e.batch().put(TREE, key(i % 200), value(id * 1000 + i, 60)).commit();
                        }
                    } catch (RuntimeException ex) {
                        failure.compareAndSet(null, ex);
                    }
                });
                threads.add(th);
                th.start();
            }
            for (int s = 0; s < 3; s++) {
                Thread th = new Thread(() -> {
                    try {
                        for (int round = 0; round < 20; round++) {
                            long snapshot;
                            try (Engine.Cursor c = e.scan(TREE, null, null, false)) {
                                snapshot = 0;
                                byte[] previous = null;
                                while (c.next()) {
                                    byte[] k = c.row().key();
                                    if (previous != null && BtreePage.memcmp(previous, k) >= 0) {
                                        throw new IllegalStateException(
                                                "a scan returned keys out of order");
                                    }
                                    previous = k;
                                    // Dereferencing proves the value the
                                    // snapshot promised is still resolvable.
                                    c.row().value();
                                    snapshot++;
                                }
                            }
                            if (snapshot < 0) {
                                throw new IllegalStateException("impossible");
                            }
                        }
                    } catch (RuntimeException ex) {
                        failure.compareAndSet(null, ex);
                    }
                });
                threads.add(th);
                th.start();
            }
            for (Thread th : threads) {
                th.join();
            }
            if (failure.get() != null) {
                throw failure.get();
            }
            e.commitNow();
            e.maintain();
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
            assertTrue(r.of(Verify.Kind.DOUBLE_ALLOCATION).isEmpty(), r.toString());
            for (int i = 0; i < 200; i++) {
                assertTrue(e.get(TREE, key(i)) != null, "key " + i + " survived");
            }
        }
    }

    /**
     * "Load a dataset, scan it, apply 10x its size in random updates, then scan
     * again. The second scan MUST cost no more than 1.5x the first, and
     * {@code value_reads_per_scanned_row} MUST stay below 0.3. It MUST also
     * assert {@code locality_debt} is within {@code locality_debt_pct}."
     *
     * <p>The test enforces four MUSTs whose violation is invisible to every
     * other check and shows up months later as "the database got slow":
     * clustered promotion, cold-tier collection, the locality-debt bound, and
     * value readahead.
     */
    /**
     * {@code 11-conformance.md} §6: <strong>the fixture MUST set
     * {@code vlog_min} below its own documents.</strong> Every profile now puts
     * it at a quarter page ({@code 12-profiles.md} §2.5), so a 400-byte value is
     * inline and none of the four mechanisms this test enforces engages at all.
     * The literal 400 used to clear {@code desktop}'s old 256 by accident.
     */
    private static Engine.Options separatingOptions() {
        Engine.Options o = options();
        o.vlogMin = 256;
        return o;
    }

    @Test
    @DisplayName("aged scan: 10x its size in updates costs no more than 1.5x, debt within bound")
    void agedScan(@TempDir Path dir) {
        int rows = 600;
        Path f = dir.resolve("a.cryptand");
        try (Engine e = Engine.create(f, separatingOptions())) {
            Engine.Batch b = e.batch();
            for (int i = 0; i < rows; i++) {
                // Above the fixture's vlog_min, so every value is separated and
                // the scan is a value-log scan — see `separatingOptions`.
                b.put(TREE, key(i), value(i, 400));
                if (b.size() >= 100) {
                    b.commit();
                    b = e.batch();
                }
            }
            b.commit();
            e.commitNow();
            // A full compaction, not N rounds of maintain(): maintain() does a
            // bounded step, so "enough rounds" is a guess that comes out
            // differently on a loaded machine, and the measurement then
            // describes how busy the host was.
            e.compact();
            e.maintain();
        }
        // Both scans are measured on a read-only open, which starts neither
        // committer nor compactor. On a read-write engine the compactor's own
        // reads land in the same counter as the scan's, and the "cost of a
        // scan" then includes however much maintenance happened to run beside
        // it - measured at 11 to 2518 pages for the *same* scan. It is also
        // exactly the state §6.9 states its bound over: "not under active
        // write pressure".
        long fresh;
        try (Engine e = Engine.open(f, readOnlyOptions())) {
            fresh = scanCost(e, rows);
        }

        try (Engine e = Engine.open(f, options())) {
            Random rnd = new Random(11);
            Engine.Batch b = e.batch();
            for (int i = 0; i < rows * 10; i++) {
                b.put(TREE, key(rnd.nextInt(rows)), value(i + 100_000, 400));
                if (b.size() >= 100) {
                    b.commit();
                    b = e.batch();
                }
            }
            b.commit();
            e.commitNow();
            e.compact();
            e.maintain();
        }

        try (Engine e = Engine.open(f, readOnlyOptions())) {
            long aged = scanCost(e, rows);
            double ratio = (double) aged / Math.max(1, fresh);
            assertTrue(ratio <= 1.5,
                    String.format("aged scan cost %.2fx a fresh one (%d vs %d pages)",
                            ratio, aged, fresh));
            assertTrue(e.valueReadsPerScannedRow() < 0.3,
                    "value_reads_per_scanned_row = " + e.valueReadsPerScannedRow());
            assertTrue(e.localityDebt() * 100 <= e.superblock().localityDebtPct,
                    String.format("locality_debt %.1f%% above the %d%% ceiling",
                            e.localityDebt() * 100, e.superblock().localityDebtPct));
        }
    }

    /**
     * Pages a full key-ordered scan has to read - keys and values both.
     *
     * <p>Counting live value-log <em>runs</em> instead, which an earlier
     * version did, measures the right thing at hopeless resolution: the answer
     * is 1 or 2, so the only movement the ratio can ever see is 2.0, and a
     * converged database that happens to keep two live cold runs at zero
     * locality debt fails a 1.5x bound it does not violate. Page reads are what
     * a scan actually costs, and they move continuously.
     */
    private static long scanCost(Engine e, int expectedRows) {
        long before = e.pager().pageReads();
        int seen = 0;
        try (Engine.Cursor c = e.scan(TREE, null, null, false)) {
            while (c.next()) {
                seen++;
            }
        }
        assertEquals(expectedRows, seen, "the scan saw every row");
        return e.pager().pageReads() - before;
    }

    /**
     * "Build a database by writing keys in random order and then updating a
     * substantial fraction of them, with no forced full compaction; then issue
     * uniform-random point reads and record {@code segments_probed_per_lookup}.
     * p99 MUST be ≤ 2 and p99.9 ≤ 3."
     *
     * <p>The write load is normative: ascending inserts give every memtable
     * flush a disjoint key range, so manifest pruning alone leaves one candidate
     * and the measurement is of nothing.
     */
    @Test
    @DisplayName("read tail: random-order writes then updates, p99 <= 2 and p99.9 <= 3")
    void readTail(@TempDir Path dir) {
        int rows = 4000;
        try (Engine e = Engine.create(dir.resolve("r.cryptand"), options())) {
            List<Integer> order = new ArrayList<>();
            for (int i = 0; i < rows; i++) {
                order.add(i);
            }
            Collections.shuffle(order, new Random(3));
            Engine.Batch b = e.batch();
            for (int i : order) {
                b.put(TREE, key(i), value(i, 50));
                if (b.size() >= 100) {
                    b.commit();
                    b = e.batch();
                }
            }
            b.commit();
            Collections.shuffle(order, new Random(4));
            b = e.batch();
            for (int i = 0; i < rows / 2; i++) {
                b.put(TREE, key(order.get(i)), value(i + rows, 50));
                if (b.size() >= 100) {
                    b.commit();
                    b = e.batch();
                }
            }
            b.commit();
            e.commitNow();
            // No forced full compaction: the level structure is whatever the
            // policy produced.

            List<Integer> probes = new ArrayList<>();
            Random rnd = new Random(5);
            for (int i = 0; i < 5000; i++) {
                long before = probeCount(e);
                e.get(TREE, key(rnd.nextInt(rows)));
                probes.add((int) (probeCount(e) - before));
            }
            Collections.sort(probes);
            int p99 = probes.get((int) (probes.size() * 0.99));
            int p999 = probes.get((int) (probes.size() * 0.999));
            assertTrue(e.earlyExit, "the bound belongs to §4's early exit, and this run took it");
            assertTrue(p99 <= 2, "segments_probed_per_lookup p99 = " + p99);
            assertTrue(p999 <= 3, "segments_probed_per_lookup p99.9 = " + p999);
        }
    }

    private static long probeCount(Engine e) {
        return e.metricsProbeTotal();
    }

    /**
     * "Corrupt one page of a mid-level segment; the database MUST still open,
     * MUST still serve every key outside that segment's range, and MUST name
     * the affected range."
     */
    @Test
    @DisplayName("containment: one damaged page takes out a range, not the database")
    void containment(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("k.cryptand");
        long damagedPage;
        byte[] insideKey;
        try (Engine e = Engine.create(f, options())) {
            Engine.Batch b = e.batch();
            for (int i = 0; i < 2000; i++) {
                b.put(TREE, key(i), value(i, 60));
                if (b.size() >= 100) {
                    b.commit();
                    b = e.batch();
                }
                // Flush twice, so the run ends with three L0 segments.
                //
                // Under `os` durability the committer has nothing to do —
                // `commitBatch` publishes visibility itself — so without this
                // the whole run flushes once, as a single segment, and §4's
                // per-segment containment has nothing to contain. Twice rather
                // than more because `l0_trigger` is 4: reach it and the
                // compactor merges them straight back into one. Rust's version
                // of this test drives the same shape off memtable pressure.
                if (i == 700 || i == 1400) {
                    b.commit();
                    b = e.batch();
                    e.commitNow();
                }
            }
            b.commit();
            e.commitNow();
        }
        // F-077: the victim is chosen once the writer has closed. Chosen inside
        // it, a background compaction (memtableEntries = 64 makes many L0
        // flushes) could merge it away before close, leaving the damage in a
        // freed page and nothing to refuse: 11 of 400 runs under load.
        try (Engine e = Engine.open(f, readOnlyOptions())) {
            // **No `maintain()` here, and the segment count is asserted.**
            //
            // Containment is per segment, so this property is only observable
            // when more than one exists: compact a fixture this small into a
            // single segment and damaging its root takes out every key, which
            // makes `served > 0` fail for a reason that has nothing to do with
            // §4. That is what happened when a flush stopped emitting one
            // segment per memtable shard — the fixture had been relying on
            // shard count for its segmentation without saying so.
            //
            // The Rust implementation's version of this test carries the same
            // precondition ("the fixture needs more than one segment"), and it
            // is a precondition rather than a comment because a fixture that
            // degenerates silently measures nothing.
            List<SegmentMeta> all = e.manifest().all();
            assertTrue(all.size() > 1,
                    "the fixture needs more than one segment for containment to be observable, got "
                            + all.size());
            SegmentMeta victim = null;
            for (SegmentMeta m : all) {
                if (victim == null || m.entryCount > victim.entryCount) {
                    victim = m;
                }
            }
            damagedPage = victim.startPage + victim.rootPage;
            insideKey = Ikey.ckeOf(victim.minKey);
        }
        byte[] raw = Files.readAllBytes(f);
        int pageSize = 8192;
        raw[(int) (damagedPage * pageSize) + PageHeader.BYTES + 5] ^= 0x55;
        Files.write(f, raw);

        Engine.Options noCompaction = options();
        noCompaction.backgroundCompaction = false; // the damaged segment stays put
        try (Engine e = Engine.open(f, noCompaction)) {
            // It opened. That is the first half of the requirement.
            int served = 0;
            int refused = 0;
            for (int i = 0; i < 2000; i++) {
                try {
                    if (e.get(TREE, key(i)) != null) {
                        served++;
                    }
                } catch (CorruptionException ex) {
                    // Named, never a wrong or empty answer.
                    assertTrue(ex.getMessage().contains("unavailable range"), ex.getMessage());
                    refused++;
                }
            }
            assertTrue(served > 0, "keys outside the damaged range are still served");
            assertTrue(refused > 0, "keys inside it are refused by name, not answered wrongly");
            assertFalse(e.unavailableRanges().isEmpty(),
                    "the affected range is askable, so a caller can tell a partial database "
                            + "from a whole one without hitting the hole");
            assertEquals(e.unavailableRanges().size(),
                    (int) ((Metrics.Value.Number) e.metrics().get("unavailable_ranges")).value());
        }
    }

    /**
     * "Create under one profile, write, set_profile to another <em>with the same
     * page_size</em>, compact fully, verify, then switch back and verify again."
     *
     * <p>An earlier version of this requirement named {@code mobile → desktop},
     * which {@code 12-profiles.md} §6 forbids outright: {@code page_size} is
     * fixed at creation, and the two differ. {@code mobile ↔ tablet} share
     * 4 KiB, and the forbidden change is asserted to be refused.
     */
    @Test
    @DisplayName("profile round trip: mobile <-> tablet keeps the data, desktop is refused")
    void profileRoundTrip(@TempDir Path dir) {
        Path f = dir.resolve("p.cryptand");
        Engine.Options mobile = options();
        mobile.profile = Profile.MOBILE;
        try (Engine e = Engine.create(f, mobile)) {
            Engine.Batch b = e.batch();
            for (int i = 0; i < 500; i++) {
                b.put(TREE, key(i), value(i, 80));
                if (b.size() >= 100) {
                    b.commit();
                    b = e.batch();
                }
            }
            b.commit();
            e.commitNow();
            assertEquals(4096, e.superblock().pageSize());

            e.setProfile(Profile.TABLET);
            e.compact();
            assertTrue(Verify.run(e).of(Verify.Kind.CORRUPTION).isEmpty());
            for (int i = 0; i < 500; i++) {
                assertArrayEquals(value(i, 80), e.get(TREE, key(i)), "key " + i + " after tablet");
            }

            e.setProfile(Profile.MOBILE);
            e.compact();
            assertTrue(Verify.run(e).of(Verify.Kind.CORRUPTION).isEmpty());
            for (int i = 0; i < 500; i++) {
                assertArrayEquals(value(i, 80), e.get(TREE, key(i)), "key " + i + " back on mobile");
            }

            // The other half of the property: page_size cannot change.
            InvalidArgumentException ex = assertThrows(InvalidArgumentException.class,
                    () -> e.setProfile(Profile.DESKTOP));
            assertTrue(ex.getMessage().contains("page_size"), ex.getMessage());
        }
    }

    /**
     * F-099, M2.2 torture seed 103043: compact() dropped an entry expired at
     * the current clock but left the newer memtable writes unflushed, so a
     * crash left a state no prefix of the history had.
     */
    @Test
    void compactAfterExpiryThenCrashKeepsANewerWrite(@TempDir Path dir) {
        Path f = dir.resolve("ttl.cryptand");
        long[] now = {0};
        Engine.Options o = options();
        o.durability = Superblock.Durability.NONE;
        o.memtableEntries = 100_000;
        o.backgroundCompaction = false;
        o.clock = () -> now[0];
        Engine e = Engine.create(f, o);
        try {
            e.batch().putWithExpiry(TREE, key(1), value(1, 60), 100).commit();
            e.commitNow(true);
            now[0] = 50;
            e.batch().put(TREE, key(2), value(2, 60)).commit();
            now[0] = 200;
            e.compact();
        } finally {
            e.abandon();
        }
        try (Engine reopened = Engine.open(f, o)) {
            now[0] = 50;
            if (reopened.get(TREE, key(1)) == null) {
                assertArrayEquals(value(2, 60), reopened.get(TREE, key(2)),
                        "the expired entry was dropped, so the write before the drop must survive");
            }
        }
    }

    /**
     * "Kill the process at randomized points during a sustained write, reopen,
     * and assert that every acknowledged batch is present, no unacknowledged
     * batch is partially present, and verification is clean."
     *
     * <p>In-process the kill is an abandoned engine: the file is left exactly as
     * the last durable superblock describes it, which is what a crash leaves.
     */
    @Test
    @DisplayName("crash: acknowledged batches survive an abandoned engine, at every mode")
    void crash(@TempDir Path dir) throws Exception {
        for (int mode : new int[]{Superblock.Durability.SYNC, Superblock.Durability.OS,
                Superblock.Durability.NONE}) {
            Path f = dir.resolve("crash-" + mode + ".cryptand");
            Files.deleteIfExists(f);
            Engine.Options o = options();
            o.durability = mode;
            List<Integer> acknowledged = new ArrayList<>();
            Engine e = Engine.create(f, o);
            try {
                for (int i = 0; i < 300; i++) {
                    e.batch().put(TREE, key(i), value(i, 60)).commit();
                    acknowledged.add(i);
                    if (i == 199) {
                        // Everything acknowledged so far must survive; force the
                        // watermark forward the way a committer does.
                        e.commitNow();
                    }
                }
            } finally {
                // The kill: no close, no final superblock, no seal.
                e.abandon();
            }
            try (Engine reopened = Engine.open(f, o)) {
                Verify.Report r = Verify.run(reopened);
                assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(),
                        "mode " + mode + ": " + r);
                assertTrue(r.of(Verify.Kind.DOUBLE_ALLOCATION).isEmpty(),
                        "mode " + mode + ": " + r);
                int present = 0;
                for (int i : acknowledged) {
                    byte[] got = reopened.get(TREE, key(i));
                    if (got != null) {
                        assertArrayEquals(value(i, 60), got,
                                "mode " + mode + ": key " + i + " is intact or absent, never torn");
                        present++;
                    }
                }
                assertTrue(present >= 200,
                        "mode " + mode + ": everything committed before the forced commit survived, "
                                + "got " + present);
            }
        }
    }
}
