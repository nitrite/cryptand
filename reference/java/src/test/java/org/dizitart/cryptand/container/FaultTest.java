package org.dizitart.cryptand.container;

import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PLAN M2.1 — crash consistency under injected faults; the port of Rust's
 * {@code tests/fault_test.rs}. Each seed runs random batches (puts, removes,
 * sometimes a compaction), each committed at {@code sync}; loses power at a
 * random write; keeps a random subset of the un-fsynced writes, some torn; and
 * reopens. On reopen the file opens, {@code verify} finds nothing worse than a
 * warning, the state is the last acknowledged batch or that plus the one in
 * flight, and an encrypted file's nonce cursor starts above every nonce that
 * could have been used. A seed that hangs is a failure.
 *
 * <p>{@code -Dcryptand.fault.seeds=a..b} widens the run (default 0..40).
 */
class FaultTest {

    private static final int TREE = TreeId.FIRST_USER_TREE;
    private static final byte[] KEY = filled(32, (byte) 7);

    private static byte[] filled(int n, byte b) {
        byte[] out = new byte[n];
        Arrays.fill(out, b);
        return out;
    }

    private static long[] seeds() {
        String s = System.getProperty("cryptand.fault.seeds", "0..40");
        String[] ab = s.split("\\.\\.");
        return new long[] {Long.parseLong(ab[0]), Long.parseLong(ab[1])};
    }

    private static Engine.Options options(boolean encrypted, boolean create) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.SYNC;
        o.memtableEntries = 64;
        o.backgroundCompaction = false; // seeds must replay
        if (encrypted) {
            o.rawKey = KEY.clone();
            o.encrypt = create;
        }
        return o;
    }

    private static byte[] k(long n) {
        return Cke.encode(Value.i64(n));
    }

    /** The smallest value any page or record of this session may have used. */
    private static long nonceBound(Engine e) throws Exception {
        Field f = Engine.class.getDeclaredField("cipher");
        f.setAccessible(true);
        Object c = f.get(e);
        if (c == null) {
            return 0;
        }
        Field next = c.getClass().getDeclaredField("nextNonce");
        Field floor = c.getClass().getDeclaredField("publishedFloor");
        next.setAccessible(true);
        floor.setAccessible(true);
        return Math.min(((AtomicLong) next.get(c)).get(), floor.getLong(c));
    }

    private static final class Run {
        TreeMap<Long, byte[]> acked = new TreeMap<>();
        TreeMap<Long, byte[]> inflight = new TreeMap<>();
        long nonceBound;
    }

    @SuppressWarnings("unchecked")
    private static Run workload(Engine e, long seed) {
        long[] rng = {seed};
        TreeMap<Long, byte[]> model = new TreeMap<>();
        Run run = new Run();
        for (int batch = 0; batch < 12; batch++) {
            Engine.Batch b = e.batch();
            long n = 1 + Long.remainderUnsigned(Faults.splitmix(rng), 40);
            for (long i = 0; i < n; i++) {
                long r = Faults.splitmix(rng);
                long key = Long.remainderUnsigned(r, 200);
                if (Long.remainderUnsigned(r, 5) == 0) {
                    model.remove(key);
                    b.remove(TREE, k(key));
                } else {
                    int len = Long.remainderUnsigned(r, 7) == 0 ? 3000
                            : 1 + (int) Long.remainderUnsigned(r >>> 20, 60);
                    byte[] v = filled(len, (byte) (r >>> 8));
                    model.put(key, v);
                    b.put(TREE, k(key), v);
                }
            }
            run.inflight = (TreeMap<Long, byte[]>) model.clone();
            long r = Faults.splitmix(rng);
            try {
                b.commit();
                if (Long.remainderUnsigned(r, 4) == 0) {
                    e.compact();
                }
            } catch (RuntimeException ex) {
                return run;
            } finally {
                try {
                    run.nonceBound = Math.max(run.nonceBound, nonceBound(e));
                } catch (Exception ignored) {
                    // reflection on a test-only path
                }
            }
            run.acked = (TreeMap<Long, byte[]>) model.clone();
        }
        return run;
    }

    private static String one(Path dir, String name, long seed,
                              BiFunction<long[], long[], Faults.Plan> planOf) throws Exception {
        boolean encrypted = seed % 2 == 1;
        long[] rng = {seed * 31 + 1};

        Path dry = dir.resolve("dry-" + name + "-" + seed + ".cryptand");
        Engine e = Engine.create(dry, options(encrypted, true));
        Faults.arm(dry, new Faults.Plan());
        workload(e, seed);
        long[] counts = Faults.counts(dry);
        Faults.disarm(dry);
        e.abandon();

        Path p = dir.resolve(name + "-" + seed + ".cryptand");
        Engine live = Engine.create(p, options(encrypted, true));
        Faults.Plan plan = planOf.apply(counts, rng);
        Faults.arm(p, plan);
        Run run = workload(live, seed);
        live.abandon(); // the process dies: no close, no flush
        int dropped = Faults.crash(p, Faults.splitmix(rng));
        String ctx = "seed " + seed + " enc=" + encrypted + " " + plan + " writes=" + counts[0]
                + " dropped=" + dropped;

        Engine back;
        try {
            back = Engine.open(p, options(encrypted, false));
        } catch (RuntimeException ex) {
            return ctx + ": open refused: " + ex;
        }
        try {
            List<String> bad = new ArrayList<>();
            for (Verify.Finding f : Verify.run(back).findings()) {
                if (f.kind() != Verify.Kind.POLICY) { // advisory, not damage
                    bad.add(f.toString());
                }
            }
            if (!bad.isEmpty()) {
                return ctx + ": verify: " + bad;
            }
            TreeMap<Long, byte[]> got = new TreeMap<>();
            for (long i = 0; i < 200; i++) {
                byte[] v = back.get(TREE, k(i));
                if (v != null) {
                    got.put(i, v);
                }
            }
            if (!same(got, run.acked) && !same(got, run.inflight)) {
                return ctx + ": state is neither the acked batch (" + run.acked.size()
                        + " keys) nor the in-flight one (" + run.inflight.size() + "): " + got.size();
            }
            if (encrypted) {
                long start = nonceBound(back);
                if (start < run.nonceBound) {
                    return ctx + ": nonce cursor " + start + " below " + run.nonceBound;
                }
            }
        } finally {
            back.close();
        }
        return null;
    }

    private static boolean same(TreeMap<Long, byte[]> a, TreeMap<Long, byte[]> b) {
        if (!a.keySet().equals(b.keySet())) {
            return false;
        }
        for (Long key : a.keySet()) {
            if (!Arrays.equals(a.get(key), b.get(key))) {
                return false;
            }
        }
        return true;
    }

    private static List<String> sweep(Path dir, String name, long from, long to,
                                      BiFunction<long[], long[], Faults.Plan> planOf) throws Exception {
        List<String> failures = new ArrayList<>();
        ExecutorService ex = Executors.newSingleThreadExecutor();
        try {
            for (long s = from; s < to; s++) {
                final long seed = s;
                Future<String> f = ex.submit(() -> one(dir, name, seed, planOf));
                try {
                    String r = f.get(60, TimeUnit.SECONDS);
                    if (r != null) {
                        failures.add(r);
                    }
                } catch (TimeoutException t) {
                    failures.add("seed " + seed + " " + name + ": hung for 60 s");
                    f.cancel(true);
                    ex.shutdownNow();
                    ex = Executors.newSingleThreadExecutor();
                } catch (java.util.concurrent.ExecutionException t) {
                    failures.add("seed " + seed + " " + name + ": threw " + t.getCause());
                }
            }
        } finally {
            ex.shutdownNow();
        }
        return failures;
    }

    private static void check(Path dir, String name, BiFunction<long[], long[], Faults.Plan> planOf)
            throws Exception {
        long[] r = seeds();
        List<String> failures = sweep(dir, name, r[0], r[1], planOf);
        assertTrue(failures.isEmpty(), name + ": " + failures.size() + " failures:\n"
                + String.join("\n", failures));
    }

    @Test
    @DisplayName("power cut at a random write")
    void powerCut(@TempDir Path dir) throws Exception {
        check(dir, "crash", (c, rng) -> {
            Faults.Plan p = new Faults.Plan();
            p.crashAtWrite = Long.remainderUnsigned(Faults.splitmix(rng), Math.max(1, c[0]));
            return p;
        });
    }

    @Test
    @DisplayName("fsync EIO, then a power cut")
    void fsyncEio(@TempDir Path dir) throws Exception {
        check(dir, "eio", (c, rng) -> {
            Faults.Plan p = new Faults.Plan();
            p.eioAtSync = Long.remainderUnsigned(Faults.splitmix(rng), Math.max(1, c[1]));
            return p;
        });
    }

    @Test
    @DisplayName("ENOSPC at a random write, then a power cut")
    void enospc(@TempDir Path dir) throws Exception {
        check(dir, "enospc", (c, rng) -> {
            Faults.Plan p = new Faults.Plan();
            p.enospcAtWrite = Long.remainderUnsigned(Faults.splitmix(rng), Math.max(1, c[0]));
            return p;
        });
    }

    /**
     * F-095: a publish that fails after numbering its commit must not skip a
     * number. Slots alternate by commit id, so the skipped retry overwrote the
     * last durable superblock; torn, the fallback was an older commit whose
     * freed pages were already reused.
     */
    @Test
    void aFailedPublishDoesNotSkipACommitId(@TempDir Path dir) throws Exception {
        Path path = dir.resolve("db.cff");
        Engine e = Engine.create(path, options(false, true));
        try {
            e.batch().put(TREE, KEY, new byte[8]).commit();
            long before = e.superblock().commitId;
            Faults.Plan p = new Faults.Plan();
            p.eioAtSync = 1; // #0 is the flush (step E); #1 the barrier after the commit is numbered
            Faults.arm(path, p);
            try {
                e.batch().put(TREE, KEY, new byte[9]).commit();
            } catch (RuntimeException expected) {
                // the commit failed; the committer retries on its own
            }
            long[] slots = new long[2];
            long deadline = System.nanoTime() + 5_000_000_000L;
            do {
                Thread.sleep(20);
                slots = slotCommitIds(path, e.superblock().pageSize());
            } while (Math.max(slots[0], slots[1]) <= before && System.nanoTime() < deadline);
            Faults.disarm(path);
            assertTrue(Math.max(slots[0], slots[1]) > before, "the committer never retried");
            org.junit.jupiter.api.Assertions.assertEquals(1, Math.abs(slots[0] - slots[1]),
                    "slots hold commits " + slots[0] + " and " + slots[1]);
        } finally {
            e.close();
        }
    }

    private static long[] slotCommitIds(Path path, int pageSize) throws java.io.IOException {
        byte[] all = java.nio.file.Files.readAllBytes(path);
        return new long[] {
            Superblock.decode(Arrays.copyOfRange(all, 0, pageSize)).commitId,
            Superblock.decode(Arrays.copyOfRange(all, pageSize, 2 * pageSize)).commitId,
        };
    }

    /** The control (PLAN rule 5): when fsync lies, acknowledged batches are lost, and the checks must say so. */
    @Test
    @DisplayName("control: a lying fsync is caught")
    void control(@TempDir Path dir) throws Exception {
        List<String> failures = sweep(dir, "control", 0, 20, (c, rng) -> {
            Faults.Plan p = new Faults.Plan();
            long w = Math.max(4, c[0]);
            p.crashAtWrite = w - 1 - Long.remainderUnsigned(Faults.splitmix(rng), w / 4);
            p.syncLies = true;
            return p;
        });
        assertTrue(!failures.isEmpty(), "a lying fsync went unnoticed in 20 seeds");
    }
}
