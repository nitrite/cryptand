package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A long single-phase loop, so a sampling profiler sees one operation and not
 * five. Harness only; it prints a rate and is not part of any published table.
 *
 * <pre>ReadProf [documents] [seconds] [read|update|mixed]</pre>
 */
public final class ReadProf {
    private static final String[] NAMES = {
        "custAddr1_ln", "custAddr2_ln", "custCityName", "custPostCode", "custCountryX",
        "custEmailAdr", "custPhoneNum", "ordReference", "ordStatusTxt", "ordCurrencyC",
        "ordNotesText", "whseLocation", "carrierName_", "trackingNumb"
    };
    private static final String[] PREF = {
        "addr1", "addr2", "city", "post", "ctry", "mail", "phon",
        "ordr", "stat", "curr", "note", "whse", "carr", "trak"
    };

    private static long snowflake(long i) {
        return (1_767_225_600_000L * 4_194_304L) + i * 4096L + 1L;
    }

    private static Value doc(int i, int rev) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("_id", new Value.NitriteId(snowflake(i)));
        String pad = String.format("%06d", i);
        for (int k = 0; k < NAMES.length; k++) {
            StringBuilder v = new StringBuilder(PREF[k] + "-" + pad + "-" + (rev % 10));
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

    private static void deleteTree(Path dir) {
        try (var walk = Files.walk(dir)) {
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

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 20_000;
        long secs = args.length > 1 ? Long.parseLong(args[1]) : 10;
        String phase = args.length > 2 ? args[2] : "read";

        byte[][] v0 = new byte[n][];
        for (int i = 0; i < n; i++) {
            v0[i] = Cve.encode(doc(i, 0));
        }
        Path path = Files.createTempDirectory("readprof-").resolve("db.cryptand");
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;
        int tree = 16;

        // A create phase builds a fresh database each round, so the loop
        // measures the write path and the flush rather than a steady state.
        if (phase.equals("create")) {
            long deadline0 = System.nanoTime() + secs * 1_000_000_000L;
            long done = 0;
            long start = System.nanoTime();
            while (System.nanoTime() < deadline0) {
                Path p2 = Files.createTempDirectory("readprof-c-").resolve("db.cryptand");
                try (Engine e2 = Engine.create(p2, o)) {
                    for (int i = 0; i < n; i++) {
                        e2.batch().put(tree, keyOf(i), v0[i]).commit();
                    }
                    e2.commitNow();
                }
                done += n;
                deleteTree(p2.getParent());
            }
            System.out.printf("create_ops_per_s=%.0f%n", done / ((System.nanoTime() - start) / 1e9));
            return;
        }

        try (Engine e = Engine.create(path, o)) {
            for (int i = 0; i < n; i++) {
                e.batch().put(tree, keyOf(i), v0[i]).commit();
            }
            e.commitNow();
            e.compact();
            long seed = 0x51EDC0DEL;
            long deadline = System.nanoTime() + secs * 1_000_000_000L;
            long count = 0;
            long t0 = System.nanoTime();
            while (System.nanoTime() < deadline) {
                for (int k = 0; k < 10_000; k++) {
                    seed = next(seed);
                    int i = (int) Math.floorMod(seed, n);
                    switch (phase) {
                        case "update": e.batch().put(tree, keyOf(i), v0[i]).commit(); break;
                        case "mixed": {
                            int roll = (int) Math.floorMod(next(seed), 100);
                            if (roll < 70) {
                                e.get(tree, keyOf(i));
                            } else if (roll < 95) {
                                e.batch().put(tree, keyOf(i), v0[i]).commit();
                            } else {
                                e.batch().remove(tree, keyOf(i)).commit();
                            }
                        }
                            break;
                        default: e.get(tree, keyOf(i)); break;
                    }
                    count++;
                }
            }
            System.out.printf("%s_ops_per_s=%.0f%n", phase,
                    count / ((System.nanoTime() - t0) / 1e9));
        }
    }
}
