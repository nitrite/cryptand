package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The CRUD-under-load matrix — see {@code reference/bench/README.md}.
 *
 * <p>{@link OpsBench} beside this one measures <strong>C</strong> and
 * <strong>R</strong>: a bulk insert, a point read, a scan, an index lookup. It
 * has no <strong>U</strong> and no <strong>D</strong>, and every phase of it
 * runs against a database that has just been compacted and is otherwise idle.
 * That is the best case, and it is not the case a person choosing a database is
 * asking about when they say "under load".
 *
 * <p>This one measures all four operations, and it measures them twice: once
 * each in isolation, and once in a sustained mixed workload with background
 * maintenance running underneath. The difference between the two columns is
 * the point of the benchmark.
 *
 * <p><strong>"Under load" here means a sustained mixed workload, not
 * concurrency.</strong> {@code reference/bench/README.md} explains why the
 * cross-language suite has no concurrency row: Dart has no shared-memory
 * threads, so a multi-writer number would not mean the same thing in each of
 * the three, and {@code 10-transactions.md} §2's scaling has its own
 * single-language harness. Load here is the shape of the work, and that is a
 * definition all three can honour.
 *
 * <p>{@code design/performance-model.md} §8's rule governs the output:
 * <strong>a counter is the primary result and wall time is an
 * observation.</strong>
 *
 * <p>Run it with {@code mvn -q -B compile exec:java
 * -Dexec.mainClass=org.dizitart.cryptand.bench.CrudBench
 * -Dexec.classpathScope=compile}.
 */
public final class CrudBench {

    private CrudBench() {
    }

    private static final int DEFAULT_DOCS = 20_000;

    /** Snowflake-shaped ids: a long shared prefix, as §1 assumes. */
    private static long snowflake(long i) {
        return 1_767_225_600_000L * 4_194_304L + i * 4096L + 1L;
    }

    private static final String[] NAMES = {"custAddr1_ln", "custAddr2_ln", "custCityName",
            "custPostCode", "custCountryX", "custEmailAdr", "custPhoneNum", "ordReference",
            "ordStatusTxt", "ordCurrencyC", "ordNotesText", "whseLocation",
            "carrierName_", "trackingNumb"};
    private static final String[] PREFIXES = {"addr1", "addr2", "city", "post", "ctry", "mail",
            "phon", "ordr", "stat", "curr", "note", "whse", "carr", "trak"};

    /**
     * §1's document shape: 20 fields, names averaging 12 B, values averaging
     * 20 B. {@code rev} varies the value bytes without changing the shape, so
     * an update is a real rewrite rather than a no-op the engine could elide.
     */
    private static Value.Doc doc(long i, long rev) {
        String pad = String.format("%06d", i);
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("_id", new Value.NitriteId(snowflake(i)));
        for (int k = 0; k < NAMES.length; k++) {
            StringBuilder v = new StringBuilder(PREFIXES[k]).append('-').append(pad)
                    .append('-').append(rev % 10);
            while (v.length() < 19) {
                v.append('y');
            }
            f.put(NAMES[k], new Value.Str(v.toString()));
        }
        f.put("ordTotMinorU", Value.integer(NumType.INT_VAR, 1299 + i));
        f.put("ordTaxMinorU", Value.integer(NumType.INT_VAR, 216));
        f.put("ordShipMinor", Value.integer(NumType.INT_VAR, 499));
        f.put("placedAtUtcM", new Value.Timestamp(1_767_225_000_000L));
        f.put("dispatchUtcM", new Value.Timestamp(1_767_225_600_000L));
        return new Value.Doc(f);
    }

    private static void row(String name, Object value, String unit, boolean primary) {
        System.out.println(name + "=" + value + " unit=" + unit
                + " kind=" + (primary ? "counter" : "observation"));
    }

    private static long percentile(List<Long> xs, double p) {
        if (xs.isEmpty()) {
            return 0;
        }
        List<Long> s = new ArrayList<>(xs);
        Collections.sort(s);
        return s.get((int) Math.round((s.size() - 1) * p));
    }

    private static String f(double v, int d) {
        return String.format("%." + d + "f", v);
    }

    private static long next(long seed) {
        seed ^= seed << 13;
        seed ^= seed >>> 7;
        seed ^= seed << 17;
        return seed;
    }

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static Path tmp() throws IOException {
        return Files.createTempDirectory("cryptand-crud-").resolve("db.cryptand");
    }

    /** p50/p99 plus the counters, under the same row names the other two print. */
    private static void report(String name, List<Long> lat, long pageReads, long ops, double secs) {
        row(name + "_ops_per_s", f(ops / Math.max(secs, 1e-9), 0), "ops/s", false);
        row(name + "_us_p50", percentile(lat, 0.50), "us", false);
        row(name + "_us_p99", percentile(lat, 0.99), "us", false);
        row(name + "_us_p999", percentile(lat, 0.999), "us", false);
        row(name + "_page_reads_per_op", f((double) pageReads / Math.max(1, ops), 3),
                "pages/op", true);
    }

    private static long us(long nanos) {
        return nanos / 1000;
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_DOCS;
        int mixedOps = args.length > 1 ? Integer.parseInt(args[1]) : DEFAULT_DOCS;

        System.out.println("# cryptand crud-under-load matrix -- java");
        System.out.println("# implementation=java documents=" + n + " mixed_ops=" + mixedOps
                + " profile=desktop durability=os");

        Path path = tmp();
        try (Database db = Database.create(path, options())) {
            Collection c = db.collection("orders");

            // ----------------------------------------------------------
            // C — create
            // ----------------------------------------------------------
            long logical = 0;
            long deviceBefore = db.engine().bytesWrittenDevice();
            List<Long> lat = new ArrayList<>(n);
            long t0 = System.nanoTime();
            for (long i = 0; i < n; i++) {
                Value.Doc d = doc(i, 0);
                logical += Cve.encode(d).length;
                long t = System.nanoTime();
                c.insert(d);
                lat.add(us(System.nanoTime() - t));
            }
            db.commit();
            report("create", lat, 0, n, (System.nanoTime() - t0) / 1e9);
            row("create_logical_bytes", logical, "bytes", true);
            // An **observation** on this implementation, not a counter: the
            // compactor runs in the background, so what has reached the device
            // at the moment this is read is not a property of the workload.
            // `reference/bench/README.md` records the 2.2x run-to-run swing
            // this row showed.
            row("create_bytes_device_per_op",
                    f((double) (db.engine().bytesWrittenDevice() - deviceBefore) / n, 1),
                    "bytes/op", false);

            db.engine().compact();
            db.commit();

            // ----------------------------------------------------------
            // R — read
            // ----------------------------------------------------------
            long seed = 0x51EDC0DEL;
            // Warm the path. On a JVM the first thousands of reads are the
            // interpreter, not the engine.
            for (int i = 0; i < 2000; i++) {
                seed = next(seed);
                c.get(snowflake(Math.floorMod(seed, n)));
            }
            int reads = Math.min(5000, n);
            long p0 = db.engine().pager().pageReads();
            lat = new ArrayList<>(reads);
            t0 = System.nanoTime();
            for (int i = 0; i < reads; i++) {
                seed = next(seed);
                long id = snowflake(Math.floorMod(seed, n));
                long t = System.nanoTime();
                Value.Doc got = c.get(id);
                lat.add(us(System.nanoTime() - t));
                if (got == null) {
                    throw new IllegalStateException("the fixture must hold every id it reads");
                }
            }
            report("read", lat, db.engine().pager().pageReads() - p0, reads,
                    (System.nanoTime() - t0) / 1e9);

            // ----------------------------------------------------------
            // U — update. An overwrite at the same key: a new version, not an
            // edit in place.
            // ----------------------------------------------------------
            int updates = Math.min(5000, n);
            p0 = db.engine().pager().pageReads();
            lat = new ArrayList<>(updates);
            t0 = System.nanoTime();
            for (int k = 0; k < updates; k++) {
                seed = next(seed);
                long i = Math.floorMod(seed, n);
                Value.Doc d = doc(i, k + 1);
                long t = System.nanoTime();
                c.insert(d);
                lat.add(us(System.nanoTime() - t));
            }
            db.commit();
            report("update", lat, db.engine().pager().pageReads() - p0, updates,
                    (System.nanoTime() - t0) / 1e9);

            db.engine().compact();
            db.commit();

            // ----------------------------------------------------------
            // D — delete. A tombstone, so it is a write and not a reclaim.
            // ----------------------------------------------------------
            int deletes = Math.min(5000, n);
            p0 = db.engine().pager().pageReads();
            lat = new ArrayList<>(deletes);
            t0 = System.nanoTime();
            for (int k = 0; k < deletes; k++) {
                long t = System.nanoTime();
                c.remove(snowflake(k % n));
                lat.add(us(System.nanoTime() - t));
            }
            db.commit();
            report("delete", lat, db.engine().pager().pageReads() - p0, deletes,
                    (System.nanoTime() - t0) / 1e9);

            // A delete must actually have deleted. Benchmarking an operation
            // that did nothing is the easiest way to publish a fast number.
            if (c.get(snowflake(0)) != null) {
                throw new IllegalStateException("the delete phase deleted nothing");
            }

            db.engine().compact();
            db.commit();

            // ----------------------------------------------------------
            // The mixed phase — 70 % read, 20 % update, 5 % insert, 5 %
            // delete, interleaved, with maintenance running underneath rather
            // than drained first.
            // ----------------------------------------------------------
            p0 = db.engine().pager().pageReads();
            long nextNew = n;
            List<Long> mixRead = new ArrayList<>();
            List<Long> mixUpdate = new ArrayList<>();
            List<Long> mixInsert = new ArrayList<>();
            List<Long> mixDelete = new ArrayList<>();
            t0 = System.nanoTime();
            for (int k = 0; k < mixedOps; k++) {
                seed = next(seed);
                int roll = (int) Math.floorMod(seed, 100);
                seed = next(seed);
                long i = Math.floorMod(seed, n);
                long t = System.nanoTime();
                if (roll < 70) {
                    c.get(snowflake(i));
                    mixRead.add(us(System.nanoTime() - t));
                } else if (roll < 90) {
                    c.insert(doc(i, k + 2));
                    mixUpdate.add(us(System.nanoTime() - t));
                } else if (roll < 95) {
                    c.insert(doc(nextNew++, 1));
                    mixInsert.add(us(System.nanoTime() - t));
                } else {
                    c.remove(snowflake(i));
                    mixDelete.add(us(System.nanoTime() - t));
                }
            }
            db.commit();
            double secs = (System.nanoTime() - t0) / 1e9;

            row("mixed_ops_per_s", f(mixedOps / Math.max(secs, 1e-9), 0), "ops/s", false);
            row("mixed_page_reads_per_op",
                    f((double) (db.engine().pager().pageReads() - p0) / Math.max(1, mixedOps), 3),
                    "pages/op", true);
            final class Bucket {
                private final String name;
                private final List<Long> lat;

                Bucket(String name, List<Long> lat) {
                    this.name = name;
                    this.lat = lat;
                }

                public String name() {
                    return name;
                }

                public List<Long> lat() {
                    return lat;
                }

                @Override
                public boolean equals(Object o) {
                    if (this == o) {
                        return true;
                    }
                    if (!(o instanceof Bucket)) {
                        return false;
                    }
                    Bucket that = (Bucket) o;
                    return java.util.Objects.equals(name, that.name)
                            && java.util.Objects.equals(lat, that.lat);
                }

                @Override
                public int hashCode() {
                    return java.util.Objects.hash(name, lat);
                }

                @Override
                public String toString() {
                    return "Bucket[" + "name=" + name + ", " + "lat=" + lat + "]";
                }
            }
            for (Bucket b : new Bucket[] {
                    new Bucket("mixed_read", mixRead),
                    new Bucket("mixed_update", mixUpdate),
                    new Bucket("mixed_insert", mixInsert),
                    new Bucket("mixed_delete", mixDelete)}) {
                row(b.name() + "_us_p50", percentile(b.lat(), 0.50), "us", false);
                row(b.name() + "_us_p99", percentile(b.lat(), 0.99), "us", false);
                row(b.name() + "_count", b.lat().size(), "ops", true);
            }
        } finally {
            Files.deleteIfExists(path);
        }

        System.out.println("# done");
    }
}
