package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

import org.rocksdb.Options;
import org.rocksdb.RocksDB;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The CRUD-under-load matrix, run against <strong>MVStore</strong> and
 * <strong>RocksDB</strong> as well as Cryptand.
 *
 * <p>Both comparators are chosen because they are what Nitrite actually uses or
 * competes with: MVStore is the storage engine Nitrite ships on today, and
 * RocksDB is the LSM everyone benchmarks against.
 * {@code design/performance-model.md} §9 names both.
 *
 * <h2>What this measures, and what it cannot</h2>
 *
 * <p><strong>The three do not do the same amount of work, and the table would
 * lie if that were not said first.</strong> MVStore and RocksDB are key-value
 * stores; Cryptand is a document database. To keep the comparison as close to
 * like-for-like as the shapes allow, every engine is handed the
 * <em>same already-encoded CVE bytes</em> for the same 20-field document, keyed
 * by the same 8-byte big-endian id. So the encode cost is paid by all three and
 * excluded from none.
 *
 * <p>What is still not equal:
 *
 * <ul>
 *   <li>Cryptand maintains a <strong>segment filter, a manifest, liveness
 *       statistics and a value-log GC</strong> — the machinery
 *       {@code 13-operations.md} requires so the engine can say why it is slow.
 *       None of it is free and none of it is optional.</li>
 *   <li>Cryptand computes and stores a <strong>CRC-32C per page</strong> and a
 *       checksum per value-log record, and verifies them on every read.
 *       MVStore checksums pages; RocksDB's block checksums are on by default
 *       too, so this one is roughly even.</li>
 *   <li>MVStore <strong>keeps the whole map in the heap and writes at
 *       commit</strong>. A {@code put} here does not reach the device. That is
 *       most of what its create, read and mixed columns are, and it is not
 *       something an engine that reads its file can match.</li>
 *   <li>RocksDB is <strong>native code</strong> reached through JNI. On the
 *       write path that is an advantage; on a small point read the JNI crossing
 *       is a real cost, which is why its read numbers are less dominant than
 *       its write numbers.</li>
 *   <li>Cryptand separates values at {@code vlog_min}, which
 *       {@code 12-profiles.md} §2.5 now puts at a quarter page in every
 *       profile — so the document this benchmark uses stays <em>inline</em> and
 *       a point read is one fetch. It was 256 here, which separated it, and
 *       that alone cost 2.5x on create and 2x on read.</li>
 * </ul>
 *
 * <p>So: <strong>read this as a sanity check, not as a ranking.</strong> The
 * honest question it answers is "is Cryptand in the same league as the engines
 * it means to replace, on the workload it is designed for" — not "which is
 * fastest"
 *
 * <p>Durability is matched as closely as the three allow: Cryptand {@code os},
 * MVStore's default (it writes in the background and commits on close), RocksDB
 * with the WAL on and {@code sync=false}. All three therefore acknowledge to
 * the OS rather than to the platter.
 *
 * <p>Run with the test classpath:
 * {@code mvn -q -B test-compile && java -cp target/classes:target/test-classes:$CP
 * org.dizitart.cryptand.bench.CompareBench}
 */
public final class CompareBench {

    private CompareBench() {
    }

    private static final String[] NAMES = {"custAddr1_ln", "custAddr2_ln", "custCityName",
            "custPostCode", "custCountryX", "custEmailAdr", "custPhoneNum", "ordReference",
            "ordStatusTxt", "ordCurrencyC", "ordNotesText", "whseLocation",
            "carrierName_", "trackingNumb"};
    private static final String[] PREFIXES = {"addr1", "addr2", "city", "post", "ctry", "mail",
            "phon", "ordr", "stat", "curr", "note", "whse", "carr", "trak"};

    private static long snowflake(long i) {
        return 1_767_225_600_000L * 4_194_304L + i * 4096L + 1L;
    }

    /** `design/performance-model.md` §1's document, identical to `CrudBench`. */
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

    private static byte[] keyOf(long i) {
        long v = snowflake(i);
        byte[] k = new byte[8];
        for (int b = 0; b < 8; b++) {
            k[b] = (byte) (v >>> (56 - 8 * b));
        }
        return k;
    }

    private static long next(long seed) {
        seed ^= seed << 13;
        seed ^= seed >>> 7;
        seed ^= seed << 17;
        return seed;
    }

    private static long percentile(List<Long> xs, double p) {
        if (xs.isEmpty()) {
            return 0;
        }
        List<Long> s = new ArrayList<>(xs);
        Collections.sort(s);
        return s.get((int) Math.round((s.size() - 1) * p));
    }

    private static long us(long nanos) {
        return nanos / 1000;
    }

    /**
     * Whether this pass is the measured one. The first pass of every engine is
     * discarded — see {@link #main}.
     */
    private static boolean measuring = true;

    private static void row(String engine, String op, long ops, double secs, List<Long> lat) {
        if (!measuring) {
            return;
        }
        System.out.printf("%-10s %-8s %10.0f %8d %8d %10d%n",
                engine, op, ops / Math.max(secs, 1e-9),
                percentile(lat, 0.50), percentile(lat, 0.99), percentile(lat, 0.999));
    }

    /** Every engine gets the same encoded bytes, so encoding is not the variable. */
    private static byte[][] encodeAll(int n, int rev) {
        byte[][] out = new byte[n][];
        for (int i = 0; i < n; i++) {
            out[i] = Cve.encode(doc(i, rev));
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 20_000;
        int mixedOps = args.length > 1 ? Integer.parseInt(args[1]) : 20_000;

        System.out.println("# cryptand vs mvstore vs rocksdb -- CRUD under load");
        System.out.println("# documents=" + n + " mixed_ops=" + mixedOps
                + " durability=os-equivalent  (see the class javadoc: this is a sanity check,");
        System.out.println("#  not a ranking -- the three do not do the same amount of work)");
        System.out.println("# every engine runs the whole matrix twice on its own fresh database and the");
        System.out.println("#  first pass is discarded: 5 000 operations on a cold JVM measure the");
        System.out.println("#  interpreter, and they measure it hardest for whichever engine has the");
        System.out.println("#  longest code path. Cryptand read 492k/s at this benchmark's original");
        System.out.println("#  2 000-operation warm-up and 1.4M/s once compiled -- the same engine.");
        System.out.printf("%n%-10s %-8s %10s %8s %8s %10s%n",
                "engine", "op", "ops/s", "p50 us", "p99 us", "p99.9 us");
        System.out.println("-".repeat(58));

        byte[][] v0 = encodeAll(n, 0);
        byte[][] v1 = encodeAll(n, 1);

        for (int pass = 0; pass < 2; pass++) {
            measuring = pass == 1;
            cryptand(n, mixedOps, v0, v1);
            mvstore(n, mixedOps, v0, v1);
            rocksdb(n, mixedOps, v0, v1);
        }

        System.out.println("# done");
    }

    // ==================================================================

    private static void cryptand(int n, int mixedOps, byte[][] v0, byte[][] v1) throws Exception {
        Path path = Files.createTempDirectory("cmp-cryptand-").resolve("db.cryptand");
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;
        int tree = 16;
        try (Engine e = Engine.create(path, o)) {
            List<Long> lat = new ArrayList<>(n);
            long t0 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                long t = System.nanoTime();
                e.batch().put(tree, keyOf(i), v0[i]).commit();
                lat.add(us(System.nanoTime() - t));
            }
            e.commitNow();
            row("cryptand", "create", n, (System.nanoTime() - t0) / 1e9, lat);

            e.compact();
            long seed = 0x51EDC0DEL;
            for (int i = 0; i < 2000; i++) {
                seed = next(seed);
                e.get(tree, keyOf((int) Math.floorMod(seed, n)));
            }
            int reads = Math.min(5000, n);
            lat = new ArrayList<>(reads);
            t0 = System.nanoTime();
            for (int i = 0; i < reads; i++) {
                seed = next(seed);
                long t = System.nanoTime();
                e.get(tree, keyOf((int) Math.floorMod(seed, n)));
                lat.add(us(System.nanoTime() - t));
            }
            row("cryptand", "read", reads, (System.nanoTime() - t0) / 1e9, lat);

            int updates = Math.min(5000, n);
            lat = new ArrayList<>(updates);
            t0 = System.nanoTime();
            for (int k = 0; k < updates; k++) {
                seed = next(seed);
                int i = (int) Math.floorMod(seed, n);
                long t = System.nanoTime();
                e.batch().put(tree, keyOf(i), v1[i]).commit();
                lat.add(us(System.nanoTime() - t));
            }
            e.commitNow();
            row("cryptand", "update", updates, (System.nanoTime() - t0) / 1e9, lat);

            int deletes = Math.min(5000, n);
            lat = new ArrayList<>(deletes);
            t0 = System.nanoTime();
            for (int k = 0; k < deletes; k++) {
                long t = System.nanoTime();
                e.batch().remove(tree, keyOf(k % n)).commit();
                lat.add(us(System.nanoTime() - t));
            }
            e.commitNow();
            row("cryptand", "delete", deletes, (System.nanoTime() - t0) / 1e9, lat);

            List<Long> mix = new ArrayList<>(mixedOps);
            t0 = System.nanoTime();
            for (int k = 0; k < mixedOps; k++) {
                seed = next(seed);
                int roll = (int) Math.floorMod(seed, 100);
                seed = next(seed);
                int i = (int) Math.floorMod(seed, n);
                long t = System.nanoTime();
                if (roll < 70) {
                    e.get(tree, keyOf(i));
                } else if (roll < 95) {
                    e.batch().put(tree, keyOf(i), v1[i]).commit();
                } else {
                    e.batch().remove(tree, keyOf(i)).commit();
                }
                mix.add(us(System.nanoTime() - t));
            }
            e.commitNow();
            row("cryptand", "mixed", mixedOps, (System.nanoTime() - t0) / 1e9, mix);
        }
        size("cryptand", path.getParent());
        deleteTree(path.getParent());
    }

    // ==================================================================

    private static void mvstore(int n, int mixedOps, byte[][] v0, byte[][] v1) throws Exception {
        Path dir = Files.createTempDirectory("cmp-mvstore-");
        Path file = dir.resolve("db.mv");
        MVStore store = new MVStore.Builder().fileName(file.toString()).open();
        try {
            MVMap<byte[], byte[]> map = store.openMap("orders");
            List<Long> lat = new ArrayList<>(n);
            long t0 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                long t = System.nanoTime();
                map.put(keyOf(i), v0[i]);
                lat.add(us(System.nanoTime() - t));
            }
            store.commit();
            row("mvstore", "create", n, (System.nanoTime() - t0) / 1e9, lat);

            long seed = 0x51EDC0DEL;
            for (int i = 0; i < 2000; i++) {
                seed = next(seed);
                map.get(keyOf((int) Math.floorMod(seed, n)));
            }
            int reads = Math.min(5000, n);
            lat = new ArrayList<>(reads);
            t0 = System.nanoTime();
            for (int i = 0; i < reads; i++) {
                seed = next(seed);
                long t = System.nanoTime();
                map.get(keyOf((int) Math.floorMod(seed, n)));
                lat.add(us(System.nanoTime() - t));
            }
            row("mvstore", "read", reads, (System.nanoTime() - t0) / 1e9, lat);

            int updates = Math.min(5000, n);
            lat = new ArrayList<>(updates);
            t0 = System.nanoTime();
            for (int k = 0; k < updates; k++) {
                seed = next(seed);
                int i = (int) Math.floorMod(seed, n);
                long t = System.nanoTime();
                map.put(keyOf(i), v1[i]);
                lat.add(us(System.nanoTime() - t));
            }
            store.commit();
            row("mvstore", "update", updates, (System.nanoTime() - t0) / 1e9, lat);

            int deletes = Math.min(5000, n);
            lat = new ArrayList<>(deletes);
            t0 = System.nanoTime();
            for (int k = 0; k < deletes; k++) {
                long t = System.nanoTime();
                map.remove(keyOf(k % n));
                lat.add(us(System.nanoTime() - t));
            }
            store.commit();
            row("mvstore", "delete", deletes, (System.nanoTime() - t0) / 1e9, lat);

            List<Long> mix = new ArrayList<>(mixedOps);
            t0 = System.nanoTime();
            for (int k = 0; k < mixedOps; k++) {
                seed = next(seed);
                int roll = (int) Math.floorMod(seed, 100);
                seed = next(seed);
                int i = (int) Math.floorMod(seed, n);
                long t = System.nanoTime();
                if (roll < 70) {
                    map.get(keyOf(i));
                } else if (roll < 95) {
                    map.put(keyOf(i), v1[i]);
                } else {
                    map.remove(keyOf(i));
                }
                mix.add(us(System.nanoTime() - t));
            }
            store.commit();
            row("mvstore", "mixed", mixedOps, (System.nanoTime() - t0) / 1e9, mix);
        } finally {
            store.close();
            size("mvstore", dir);
            deleteTree(dir);
        }
    }

    // ==================================================================

    private static void rocksdb(int n, int mixedOps, byte[][] v0, byte[][] v1) throws Exception {
        RocksDB.loadLibrary();
        Path dir = Files.createTempDirectory("cmp-rocks-");
        try (Options opts = new Options().setCreateIfMissing(true);
             RocksDB db = RocksDB.open(opts, dir.toString())) {
            List<Long> lat = new ArrayList<>(n);
            long t0 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                long t = System.nanoTime();
                db.put(keyOf(i), v0[i]);
                lat.add(us(System.nanoTime() - t));
            }
            row("rocksdb", "create", n, (System.nanoTime() - t0) / 1e9, lat);

            long seed = 0x51EDC0DEL;
            for (int i = 0; i < 2000; i++) {
                seed = next(seed);
                db.get(keyOf((int) Math.floorMod(seed, n)));
            }
            int reads = Math.min(5000, n);
            lat = new ArrayList<>(reads);
            t0 = System.nanoTime();
            for (int i = 0; i < reads; i++) {
                seed = next(seed);
                long t = System.nanoTime();
                db.get(keyOf((int) Math.floorMod(seed, n)));
                lat.add(us(System.nanoTime() - t));
            }
            row("rocksdb", "read", reads, (System.nanoTime() - t0) / 1e9, lat);

            int updates = Math.min(5000, n);
            lat = new ArrayList<>(updates);
            t0 = System.nanoTime();
            for (int k = 0; k < updates; k++) {
                seed = next(seed);
                int i = (int) Math.floorMod(seed, n);
                long t = System.nanoTime();
                db.put(keyOf(i), v1[i]);
                lat.add(us(System.nanoTime() - t));
            }
            row("rocksdb", "update", updates, (System.nanoTime() - t0) / 1e9, lat);

            int deletes = Math.min(5000, n);
            lat = new ArrayList<>(deletes);
            t0 = System.nanoTime();
            for (int k = 0; k < deletes; k++) {
                long t = System.nanoTime();
                db.delete(keyOf(k % n));
                lat.add(us(System.nanoTime() - t));
            }
            row("rocksdb", "delete", deletes, (System.nanoTime() - t0) / 1e9, lat);

            List<Long> mix = new ArrayList<>(mixedOps);
            t0 = System.nanoTime();
            for (int k = 0; k < mixedOps; k++) {
                seed = next(seed);
                int roll = (int) Math.floorMod(seed, 100);
                seed = next(seed);
                int i = (int) Math.floorMod(seed, n);
                long t = System.nanoTime();
                if (roll < 70) {
                    db.get(keyOf(i));
                } else if (roll < 95) {
                    db.put(keyOf(i), v1[i]);
                } else {
                    db.delete(keyOf(i));
                }
                mix.add(us(System.nanoTime() - t));
            }
            row("rocksdb", "mixed", mixedOps, (System.nanoTime() - t0) / 1e9, mix);
        }
        size("rocksdb", dir);
        deleteTree(dir);
    }

    /**
     * Bytes on disk.
     *
     * <p>This row used to read 137 MB and be the one most likely to be misread:
     * Cryptand <strong>preallocates</strong> a value-log segment at
     * {@code vlog_segment_bytes} (64 MiB on {@code desktop}), and almost all of
     * that figure was reserved space held for documents that had no business
     * being in a value log at all. With {@code vlog_min} at a quarter page
     * ({@code 12-profiles.md} §2.5) they stay inline and no value-log segment is
     * opened, so the number is now comparable data rather than reservation.
     *
     * <p>It is still the file's length and not its live bytes;
     * {@code 13-operations.md} §6 separates {@code live_bytes} from
     * {@code allocated_bytes} for exactly this reason. It is printed anyway
     * because a user's disk does not care about the distinction.
     */
    private static long sizeOf(Path p) {
        try (var walk = Files.walk(p)) {
            return walk.filter(Files::isRegularFile).mapToLong(x -> {
                try {
                    return Files.size(x);
                } catch (Exception e) {
                    return 0L;
                }
            }).sum();
        } catch (Exception e) {
            return 0L;
        }
    }

    private static void size(String engine, Path dir) {
        if (!measuring) {
            return;
        }
        System.out.printf("%-10s %-8s %10d %8s %8s %10s%n",
                engine, "bytes", sizeOf(dir), "-", "-", "-");
    }

    private static void deleteTree(Path p) {
        try (var walk = Files.walk(p)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(x -> {
                try {
                    Files.deleteIfExists(x);
                } catch (Exception ignored) {
                    // best effort
                }
            });
        } catch (Exception ignored) {
            // best effort
        }
    }
}
