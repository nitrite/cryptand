package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

/**
 * 10 §2 writer scaling: puts/s at N threads, single writer (default) or
 * concurrent ({@code -Dcryptand.singleWriter=false}).
 *
 * <p>Args: dir durability(0..3) valueBytes totalOps threads...
 * totalOps is split across the threads (F-180: per-thread ops grew the data
 * with the thread count, and the slowdown was the data, not the threads).
 * Prints one JSON line per thread count.
 */
public final class WriterScaleBench {
    public static void main(String[] a) throws Exception {
        Path dir = Path.of(a[0]);
        int durability = Integer.parseInt(a[1]);
        int valueBytes = Integer.parseInt(a[2]);
        int total = Integer.parseInt(a[3]);
        for (int k = 4; k < a.length; k++) {
            int threads = Integer.parseInt(a[k]);
            int ops = total / threads;
            Path db = dir.resolve("ws-" + threads + ".cryptand");
            Files.deleteIfExists(db);
            Engine.Options o = new Engine.Options();
            o.profile = Profile.DESKTOP;
            o.durability = durability;
            long[] lat = new long[threads * ops];
            long t0, t1;
            try (Engine e = Engine.create(db, o)) {
                CountDownLatch start = new CountDownLatch(1);
                Thread[] ws = new Thread[threads];
                for (int t = 0; t < threads; t++) {
                    int tid = t;
                    ws[t] = new Thread(() -> {
                        byte[] v = new byte[valueBytes];
                        Arrays.fill(v, (byte) tid);
                        try {
                            start.await();
                        } catch (InterruptedException x) {
                            return;
                        }
                        for (int i = 0; i < ops; i++) {
                            int id = tid * ops + i;
                            long s = System.nanoTime();
                            e.batch().put(1, Cke.encode(Value.integer(NumType.I64, id)), v).commit();
                            lat[id] = System.nanoTime() - s;
                        }
                    });
                    ws[t].start();
                }
                t0 = System.nanoTime();
                start.countDown();
                for (Thread w : ws) {
                    w.join();
                }
                t1 = System.nanoTime();
            }
            Files.deleteIfExists(db);
            Arrays.sort(lat);
            double secs = (t1 - t0) / 1e9;
            System.out.printf("{\"single\":%b,\"durability\":%d,\"value\":%d,\"threads\":%d,"
                            + "\"ops_s\":%.0f,\"p50_us\":%.1f,\"p99_us\":%.1f}%n",
                    !"false".equals(System.getProperty("cryptand.singleWriter")), durability, valueBytes, threads,
                    lat.length / secs, lat[lat.length / 2] / 1e3, lat[lat.length * 99 / 100] / 1e3);
        }
    }
}
