package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.IndexStats;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * F-147: writer memory while building an N-document file, the Java twin of
 * Rust {@code examples/rss_scale.rs} and Dart {@code tool/rss_scale.dart
 * build} (same document, commit per 100k). Run under {@code /usr/bin/time -l}.
 * {@code PATH N read}: open, 10k uniform + 10k zipf gets, a 100k-row scan, verify; {@code PATH N settle}:
 * compact + commit + shrink, as Rust's. {@code PATH N text}: PLAN 6.5 full-text rung.
 */
public final class RssScale {
    /** {@code CRYPTAND_ENC=1}: encrypted file, fixed raw key (kdf 0), as Rust {@code rss_scale}. */
    private static Engine.Options opts() {
        Engine.Options o = new Engine.Options();
        // CRYPTAND_PROFILE=mobile: Java takes the profile (and its cache budget)
        // from the options on every open, not from the file.
        o.profile = "mobile".equals(System.getenv("CRYPTAND_PROFILE")) ? Profile.MOBILE : Profile.DESKTOP;
        // ponytail: fixed bench key, never a real secret.
        if (System.getenv("CRYPTAND_ENC") != null) {
            o.encrypt = true;
            o.rawKey = new byte[32];
            java.util.Arrays.fill(o.rawKey, (byte) 7);
        }
        return o;
    }

    private static long rssMb() throws Exception {
        Process p = new ProcessBuilder("ps", "-o", "rss=", "-p", Long.toString(ProcessHandle.current().pid())).start();
        return Long.parseLong(new String(p.getInputStream().readAllBytes()).trim()) >> 10;
    }

    private static Value city(long i) {
        return new Value.Str(String.format("city-%03d", i % 1000));
    }

    /** PLAN 6.5, Rust {@code rss_scale PATH N index}: same docs, indexes, probes and output line. */
    private static void indexRung(Path path, long n) throws Exception {
        Files.deleteIfExists(path);
        Engine.Options o = opts();
        o.durability = Superblock.Durability.OS;
        try (Database db = Database.create(path, o)) {
            Collection c = db.collection("c");
            Collection.IndexBinding uq = c.createIndex(List.of("ordReference"), true, false);
            Collection.IndexBinding cx = c.createIndex(List.of("custCityName", "ordTotMinorU"), false, false);
            long t = System.nanoTime();
            for (long i = 0; i < n; i++) {
                Map<String, Value> f = new LinkedHashMap<>(XlangCrudBench.doc(i, 0).fields());
                f.put("custCityName", city(i));
                c.insert(new Value.Doc(f));
                if ((i + 1) % 100_000 == 0) {
                    db.commit();
                    System.err.println((i + 1) + " rss_mb=" + rssMb());
                }
            }
            db.commit();
            StringBuilder line = new StringBuilder("built=" + n + " build_s=" + (System.nanoTime() - t) / 1_000_000_000
                    + " bytes=" + Files.size(path) + " rss_build_mb=" + rssMb());
            long s = 0x51EDC0DEL;
            long[] us = new long[10_000];
            long segs0 = org.dizitart.cryptand.lsm.Engine.SCAN_SEGMENTS.get();
            for (int k = 0; k < us.length; k++) {
                s = s * 6364136223846793005L + 1442695040888963407L;
                long i = Long.remainderUnsigned(s >>> 11, n);
                Value v = XlangCrudBench.doc(i, 0).fields().get("ordReference");
                long g = System.nanoTime();
                if (uq.find(List.of(v)).size() != 1) throw new AssertionError("unique probe");
                us[k] = (System.nanoTime() - g) / 1000;
            }
            java.util.Arrays.sort(us);
            line.append(" unique_us p50=" + us[5000] + " p99=" + us[9900]
                    + " segs_per_probe=" + (org.dizitart.cryptand.lsm.Engine.SCAN_SEGMENTS.get() - segs0) / (double) us.length);
            long g = System.nanoTime();
            int hits = cx.find(List.of(city(7))).size();
            line.append(" compound_rows=" + hits + " compound_ms=" + (System.nanoTime() - g) / 1_000_000 + " rss_probe_mb=" + rssMb());
            g = System.nanoTime();
            IndexStats st = cx.analyze();
            line.append(" analyze_ms=" + (System.nanoTime() - g) / 1_000_000 + " rss_analyze_mb=" + rssMb() + " entries=" + st.entries
                    + " distinct=" + st.distinctEstimate + " nulls=" + st.nullCount + " buckets=" + st.histogram.size());
            g = System.nanoTime();
            boolean sound = org.dizitart.cryptand.ops.Verify.run(db.engine()).findings().isEmpty();
            System.out.println(line + " verify_ms=" + (System.nanoTime() - g) / 1_000_000 + " verify_sound=" + sound + " rss_verify_mb=" + rssMb());
        }
    }

    /** PLAN 6.5 full text: word k of document i, from 26^3 three-letter words; same as Dart {@code scale text}. */
    public static String word(long i, int k) {
        long z = i * 8 + k + 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        int w = (int) Long.remainderUnsigned(z ^ (z >>> 31), 17_576);
        return new String(new char[] {(char) ('a' + w / 676), (char) ('a' + w / 26 % 26), (char) ('a' + w % 26)});
    }

    /** PLAN 6.5: a full-text index on {@code ordNotesText}, 8 words per document. */
    private static void textRung(Path path, long n) throws Exception {
        Files.deleteIfExists(path);
        Engine.Options o = opts();
        o.durability = Superblock.Durability.OS;
        try (Database db = Database.create(path, o)) {
            Collection c = db.collection("c");
            org.dizitart.cryptand.index.FullTextIndex ft = c.createTextIndex(List.of("ordNotesText"), List.of(), "none", true);
            long t = System.nanoTime();
            for (long i = 0; i < n; i++) {
                Map<String, Value> f = new LinkedHashMap<>(XlangCrudBench.doc(i, 0).fields());
                StringBuilder w = new StringBuilder();
                for (int k = 0; k < 8; k++) w.append(k == 0 ? "" : " ").append(word(i, k));
                f.put("ordNotesText", new Value.Str(w.toString()));
                c.insert(new Value.Doc(f));
                if ((i + 1) % 100_000 == 0) {
                    db.commit();
                    System.err.println((i + 1) + " t=" + (System.nanoTime() - t) / 1_000_000_000 + " rss_mb=" + rssMb());
                }
            }
            db.commit();
            StringBuilder line = new StringBuilder("built=" + n + " build_s=" + (System.nanoTime() - t) / 1_000_000_000
                    + " bytes=" + Files.size(path) + " rss_build_mb=" + rssMb());
            long s = 0x51EDC0DEL;
            long[] us = new long[1000];
            long rows = 0;
            for (int k = 0; k < us.length; k++) {
                s = s * 6364136223846793005L + 1442695040888963407L;
                long i = Long.remainderUnsigned(s >>> 11, n);
                long g = System.nanoTime();
                int hits = ft.search(word(i, 0) + " " + word(i, 1)).size();
                us[k] = (System.nanoTime() - g) / 1000;
                if (hits < 1) throw new AssertionError("text probe " + i);
                rows += hits;
            }
            java.util.Arrays.sort(us);
            line.append(" and2_us p50=" + us[500] + " p99=" + us[990] + " and2_rows=" + rows);
            // One term against brute force: df, and the search's set size.
            String q = word(n / 2, 3);
            long df = 0;
            for (long i = 0; i < n; i++) {
                for (int k = 0; k < 8; k++) {
                    if (word(i, k).equals(q)) { df++; break; }
                }
            }
            long g = System.nanoTime();
            int got = ft.search(q).size();
            line.append(" term_ms=" + (System.nanoTime() - g) / 1_000_000 + " term_rows=" + got + " brute_df=" + df
                    + " dict_df=" + ft.term(q).df() + " rss_probe_mb=" + rssMb());
            if (got != df || ft.term(q).df() != df) throw new AssertionError("df " + q);
            g = System.nanoTime();
            boolean sound = org.dizitart.cryptand.ops.Verify.run(db.engine()).findings().isEmpty();
            System.out.println(line + " verify_ms=" + (System.nanoTime() - g) / 1_000_000 + " verify_sound=" + sound + " rss_verify_mb=" + rssMb());
        }
    }

    public static void main(String[] args) throws Exception {
        Path path = Path.of(args[0]);
        long n = Long.parseLong(args[1]);
        String mode = args.length > 2 ? args[2] : "build";
        if (mode.equals("read")) {
            long t = System.nanoTime();
            try (Engine e = Engine.open(path, opts())) {
                long openMs = (System.nanoTime() - t) / 1_000_000;
                long[] seed = {0x51EDC0DEL};
                java.util.function.DoubleSupplier rnd = () -> {
                    seed[0] = seed[0] * 6364136223846793005L + 1442695040888963407L;
                    return (seed[0] >>> 11) / (double) (1L << 53);
                };
                StringBuilder line = new StringBuilder("open_ms=" + openMs);
                // Same picks as Dart `tool/scale.dart`: uniform, then zipf by
                // inverse power (ponytail: s~1.2 skew, not an exact Zipf(0.99)).
                for (String name : new String[] {"uniform", "zipf"}) {
                    long[] us = new long[10_000];
                    for (int k = 0; k < us.length; k++) {
                        double u = rnd.getAsDouble();
                        long i = name.equals("zipf") ? (long) (n * Math.pow(u, 6)) % n : (long) (u * n);
                        long g = System.nanoTime();
                        if (e.get(16, XlangCrudBench.keyOf(i)) == null) throw new AssertionError("missing");
                        us[k] = (System.nanoTime() - g) / 1000;
                    }
                    java.util.Arrays.sort(us);
                    line.append(" get_" + name + "_us p50=" + us[5000] + " p99=" + us[9900] + " p999=" + us[9990]);
                }
                long lo = (long) (rnd.getAsDouble() * Math.max(1, n - 100_000));
                long g = System.nanoTime();
                long rows = 0;
                Engine.Cursor c = e.scan(16, XlangCrudBench.keyOf(lo), XlangCrudBench.keyOf(lo + 100_000), false);
                while (c.next()) rows++;
                line.append(String.format(" scan_rows=%d scan_rows_per_s=%.0f", rows, rows * 1e9 / (System.nanoTime() - g)));
                g = System.nanoTime();
                boolean sound = org.dizitart.cryptand.ops.Verify.run(e).findings().isEmpty();
                line.append(" verify_ms=" + (System.nanoTime() - g) / 1_000_000 + " verify_sound=" + sound);
                System.out.println(line);
            }
            return;
        }
        if (mode.equals("index")) {
            indexRung(path, n);
            return;
        }
        if (mode.equals("text")) {
            textRung(path, n);
            return;
        }
        if (mode.equals("settle")) {
            try (Engine e = Engine.open(path, opts())) {
                e.compact();
                e.commitNow();
                e.shrink();
            }
            long b = Files.size(path);
            System.out.printf("settled bytes=%d space_amp=%.2f%n", b, b / (n * 516.0));
            return;
        }
        Files.deleteIfExists(path);
        Engine.Options o = opts();
        o.durability = Superblock.Durability.OS;
        try (Engine e = Engine.create(path, o)) {
            for (long i = 0; i < n; i++) {
                e.batch().put(16, XlangCrudBench.keyOf(i), Cve.encode(XlangCrudBench.doc(i, 0))).commit();
                if ((i + 1) % 100_000 == 0) {
                    e.commitNow();
                    System.out.println(i + 1);
                }
            }
        }
        System.out.println("built " + n + " bytes=" + Files.size(path));
    }
}
