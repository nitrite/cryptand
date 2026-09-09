package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The CRUD matrix at the <strong>engine</strong> level, in the one shape all
 * three implementations can run — the like-for-like cross-language number that
 * {@link CrudBench} and its Rust and Dart siblings do not give, because those
 * drive a {@code Collection} and build and encode a document inside the timed
 * loop.
 *
 * <h2>What is held identical</h2>
 *
 * <ul>
 *   <li>the same document ({@code design/performance-model.md} §1),
 *       <strong>encoded to CVE bytes before the clock starts</strong>, so
 *       encoding is not the variable;</li>
 *   <li>the same key — {@code CKE(NitriteId(snowflake(i)))}, the format's own
 *       encoding, because that is the API all three expose — and
 *       <strong>encoded inside the timed loop</strong>, once per operation.
 *       Java's engine takes CKE bytes directly where Rust's and Dart's take a
 *       {@code Value} and encode it themselves, so hoisting the keys into an
 *       array (which this bench did at first) hands Java a per-operation saving
 *       the other two cannot have. The values are hoisted, because all three
 *       can hoist them;</li>
 *   <li>the same tree id, profile ({@code desktop}) and durability
 *       ({@code os});</li>
 *   <li>the same phase sizes, and the same operation mix in the mixed phase;</li>
 *   <li><strong>the same pseudo-random sequence, bit for bit.</strong> The
 *       xorshift below and its {@code (seed >>> 32) % n} reduction were chosen
 *       so that they are expressible identically in Java, Rust and Dart — a
 *       signed {@code %} and an unsigned one disagree, and the three languages
 *       do not have the same one;</li>
 *   <li>the whole matrix runs twice on a fresh database and the first pass is
 *       discarded.</li>
 * </ul>
 *
 * <h2>What is not, and cannot be</h2>
 *
 * <p><strong>The three do not have the same storage model, and that is the
 * largest term in any difference between their numbers.</strong> It is printed
 * as {@code storage_model} so it cannot be read past:
 *
 * <ul>
 *   <li><strong>java</strong> — {@code file-backed}: a pager over an open file
 *       with a bounded page cache. Segments are read from the file on demand
 *       and written as they are built.</li>
 *   <li><strong>rust</strong> — {@code file-backed, segments resident}: a real
 *       file and incremental extent writes, but whole segment extents are held
 *       in memory under an LRU, so a read rarely reaches the file.</li>
 *   <li><strong>dart</strong> — {@code in-memory page space}: the whole page
 *       space is a list of pages in the heap. A file is read whole on open and
 *       written whole on save, so during a run nothing reaches a disk.</li>
 * </ul>
 *
 * <p>The {@code ops_per_s} rows therefore measure <em>engine work up to the
 * segment build</em>, which is the part all three actually do. Making the
 * result durable is measured separately and once, as {@code persist_ms},
 * because in Dart's model that is a whole-file write and in the other two it is
 * not — and averaging that into a per-operation figure would hide exactly the
 * thing worth seeing.
 *
 * <p>Run:
 * {@code mvn -q -B test-compile -DskipTests && java -cp target/classes:target/test-classes
 * org.dizitart.cryptand.bench.XlangCrudBench [documents] [mixed_ops]}
 */
public final class XlangCrudBench {

    private XlangCrudBench() {
    }

    private static final int TREE = 16;

    private static final String[] NAMES = {"custAddr1_ln", "custAddr2_ln", "custCityName",
            "custPostCode", "custCountryX", "custEmailAdr", "custPhoneNum", "ordReference",
            "ordStatusTxt", "ordCurrencyC", "ordNotesText", "whseLocation",
            "carrierName_", "trackingNumb"};
    private static final String[] PREFIXES = {"addr1", "addr2", "city", "post", "ctry", "mail",
            "phon", "ordr", "stat", "curr", "note", "whse", "carr", "trak"};

    private static long snowflake(long i) {
        return 1_767_225_600_000L * 4_194_304L + i * 4096L + 1L;
    }

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
        return Cke.encode(new Value.NitriteId(snowflake(i)));
    }

    /** xorshift64. Identical in all three; see the class docs. */
    private static long next(long seed) {
        seed ^= seed << 13;
        seed ^= seed >>> 7;
        seed ^= seed << 17;
        return seed;
    }

    /** The reduction, chosen so signed and unsigned `%` cannot disagree. */
    private static int below(long seed, int n) {
        return (int) ((seed >>> 32) % n);
    }

    private static boolean measuring = true;

    private static void row(String name, String value, String unit) {
        if (measuring) {
            System.out.println(name + "=" + value + " unit=" + unit);
        }
    }

    private static void ops(String phase, long count, double secs) {
        row(phase + "_ops_per_s", String.format("%.0f", count / Math.max(secs, 1e-9)), "ops/s");
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 20_000;
        int mixedOps = args.length > 1 ? Integer.parseInt(args[1]) : 20_000;

        System.out.println("# cryptand cross-language CRUD matrix -- java");
        System.out.println("# implementation=java documents=" + n + " mixed_ops=" + mixedOps
                + " profile=desktop durability=os");
        System.out.println("# the first pass is discarded; see the class docs for what is and"
                + " is not held identical");

        byte[][] v0 = new byte[n][];
        byte[][] v1 = new byte[n][];
        for (int i = 0; i < n; i++) {
            v0[i] = Cve.encode(doc(i, 0));
            v1[i] = Cve.encode(doc(i, 1));
        }

        for (int pass = 0; pass < 2; pass++) {
            measuring = pass == 1;
            pass(n, mixedOps, v0, v1);
        }
        System.out.println("# done");
    }

    private static void pass(int n, int mixedOps, byte[][] v0, byte[][] v1)
            throws Exception {
        Path dir = Files.createTempDirectory("xlang-java-");
        Path path = dir.resolve("db.cryptand");
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;

        long persistNanos;
        try (Engine e = Engine.create(path, o)) {
            long t0 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                e.batch().put(TREE, keyOf(i), v0[i]).commit();
            }
            e.commitNow();
            ops("create", n, (System.nanoTime() - t0) / 1e9);

            e.compact();

            long seed = 0x51EDC0DEL;
            for (int i = 0; i < 2000; i++) {
                seed = next(seed);
                e.get(TREE, keyOf(below(seed, n)));
            }
            int reads = Math.min(5000, n);
            t0 = System.nanoTime();
            for (int i = 0; i < reads; i++) {
                seed = next(seed);
                e.get(TREE, keyOf(below(seed, n)));
            }
            ops("read", reads, (System.nanoTime() - t0) / 1e9);

            int updates = Math.min(5000, n);
            t0 = System.nanoTime();
            for (int k = 0; k < updates; k++) {
                seed = next(seed);
                int i = below(seed, n);
                e.batch().put(TREE, keyOf(i), v1[i]).commit();
            }
            e.commitNow();
            ops("update", updates, (System.nanoTime() - t0) / 1e9);

            int deletes = Math.min(5000, n);
            t0 = System.nanoTime();
            for (int k = 0; k < deletes; k++) {
                e.batch().remove(TREE, keyOf(k % n)).commit();
            }
            e.commitNow();
            ops("delete", deletes, (System.nanoTime() - t0) / 1e9);

            t0 = System.nanoTime();
            for (int k = 0; k < mixedOps; k++) {
                seed = next(seed);
                int roll = below(seed, 100);
                seed = next(seed);
                int i = below(seed, n);
                if (roll < 70) {
                    e.get(TREE, keyOf(i));
                } else if (roll < 95) {
                    e.batch().put(TREE, keyOf(i), v1[i]).commit();
                } else {
                    e.batch().remove(TREE, keyOf(i)).commit();
                }
            }
            e.commitNow();
            ops("mixed", mixedOps, (System.nanoTime() - t0) / 1e9);

            // Making it durable, once. In this implementation the segments are
            // already in the file, so this is a barrier and a superblock.
            long p0 = System.nanoTime();
            e.commitNow();
            persistNanos = System.nanoTime() - p0;
        }
        row("persist_ms", String.format("%.1f", persistNanos / 1e6), "ms");
        row("file_bytes", Long.toString(sizeOf(dir)), "bytes");
        row("storage_model", "file-backed", "text");
        deleteTree(dir);
    }

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
