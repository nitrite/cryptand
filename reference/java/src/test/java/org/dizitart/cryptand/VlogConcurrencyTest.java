package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.Vlog;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code 10-transactions.md} §2.2's reserve-then-{@code pwrite}, and the
 * watermark-hole protocol that makes it safe.
 *
 * <p>§2.2 is a MUST: value-log appends are routed so "that writers do not
 * serialize on a shared buffer or a lock … each takes a disjoint byte range
 * with one {@code fetch_add} and writes into it directly", and
 * {@code 11-conformance.md} §1.1 adds "an implementation that serializes
 * writers is <strong>not</strong> Level 0".
 *
 * <p>Doing that creates <strong>holes</strong>. {@code visible} progress in the
 * value log is a <em>contiguous</em> watermark (§2.3), so a write that finishes
 * while an earlier reservation is still in flight sits beyond it — written,
 * checksummed, and past the watermark. Judging readability by the watermark
 * alone rejects the writer's own pointer, which is how the first attempt at
 * this failed:
 *
 * <pre>value-log pointer to segment 1 ends at 4163294, past the durable
 * watermark 4161273</pre>
 */
class VlogConcurrencyTest {

    private static final int TREE = 21;

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static byte[] key(int i) {
        return Cke.encode(Value.integer(NumType.I64, i));
    }

    private static byte[] value(int i) {
        // Well above desktop's vlog_min of 256, so every value is separated and
        // the value log is what is being tested.
        byte[] v = new byte[900];
        Arrays.fill(v, (byte) (i % 251));
        v[0] = (byte) (i >>> 24);
        v[1] = (byte) (i >>> 16);
        v[2] = (byte) (i >>> 8);
        v[3] = (byte) i;
        return v;
    }

    @Test
    @DisplayName("concurrent writers interleave in the value log and every record reads back")
    void concurrentAppendsAreReadableAndComplete(@TempDir Path dir) throws Exception {
        int threads = 8;
        int perThread = 1500;
        long holesBefore = Vlog.HOLE_READS.get();

        try (Engine e = Engine.create(dir.resolve("vlogconc.cryptand"), options())) {
            CountDownLatch start = new CountDownLatch(1);
            List<Thread> writers = new ArrayList<>();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            for (int t = 0; t < threads; t++) {
                int base = t * perThread;
                Thread w = new Thread(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < perThread; i++) {
                            int id = base + i;
                            e.batch().put(TREE, key(id), value(id)).commit();
                            // **Read it straight back, while the other writers
                            // still hold reservations.** This is the moment the
                            // hole exists: this record is written and the
                            // contiguous watermark is still behind it, pinned
                            // by an earlier reservation that has not landed.
                            // Reading here is what the first attempt at
                            // reserve-then-pwrite failed on, and it is the only
                            // way to reach that state deliberately.
                            // At `Long.MAX_VALUE` rather than `visibleSeq`:
                            // this isolates the value-log protocol from the
                            // *seq* watermark, which is a separate contiguous
                            // prefix and legitimately lags behind a concurrent
                            // writer's own batch. What is under test here is
                            // whether the pointer resolves, not whether the
                            // entry is visible yet.
                            byte[] back = e.get(TREE, key(id), Long.MAX_VALUE,
                                    System.currentTimeMillis());
                            if (back == null || !Arrays.equals(value(id), back)) {
                                throw new AssertionError("id " + id
                                        + " did not read back immediately after its own append");
                            }
                        }
                    } catch (Throwable ex) {
                        failure.compareAndSet(null, ex);
                    }
                }, "writer-" + t);
                writers.add(w);
                w.start();
            }
            start.countDown();
            for (Thread w : writers) {
                w.join();
            }
            if (failure.get() != null) {
                throw new AssertionError("a writer failed", failure.get());
            }

            e.commitNow();

            // Every record written by every thread reads back, byte for byte.
            // A pointer that the watermark does not cover throws here rather
            // than returning null, so this asserts the protocol and not merely
            // the count.
            for (int id = 0; id < threads * perThread; id++) {
                byte[] got = e.get(TREE, key(id));
                assertNotNull(got, "id " + id + " lost by a concurrent append");
                assertTrue(Arrays.equals(value(id), got), "id " + id + " read back wrong");
            }

            // And it survives the flush and a compaction, which is where a
            // segment gets sealed — the point at which tree 7's `bytes` must
            // already cover every record, or those beyond it become
            // permanently unreadable.
            e.compact();
            e.maintain();
            for (int id = 0; id < threads * perThread; id += 7) {
                assertNotNull(e.get(TREE, key(id)), "id " + id + " lost after compaction");
            }
            assertNull(e.get(TREE, key(threads * perThread + 1)), "a key never written must be absent");

            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
        }

        // **A control that can fail.** If no read ever landed beyond the
        // contiguous watermark then this workload never produced a hole, and
        // the protocol under test was not exercised at all — a green run would
        // then mean nothing.
        assertTrue(Vlog.HOLE_READS.get() > holesBefore,
                "no read landed beyond the contiguous watermark, so the hole "
                        + "protocol was never exercised: raise the thread count or the "
                        + "record size until concurrent appends actually interleave");
    }
}
