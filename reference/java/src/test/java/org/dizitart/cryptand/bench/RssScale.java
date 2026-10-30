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
 * compact + commit + shrink, as Rust's. {@code PATH N text}: PLAN 6.5 full-text rung;
 * {@code PATH N spatial}: PLAN 6.5 spatial rung; {@code PATH N vector}: PLAN 6.5 vector rung.
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

    /** PLAN 6.5 spatial: point of document i in [0, 1000)^2, about 10 points per unit square at 10^7. */
    public static double[] xy(long i) {
        long z = i * 0x9E3779B97F4A7C15L + 0x51EDC0DEL;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        z ^= z >>> 31;
        return new double[] {(z >>> 40) * 1000.0 / (1 << 24), (z & 0xFFFFFF) * 1000.0 / (1 << 24)};
    }

    /** PLAN 6.5: a spatial index on point field {@code loc}; near and nearestK checked against brute force. */
    private static void spatialRung(Path path, long n) throws Exception {
        Files.deleteIfExists(path);
        Engine.Options o = opts();
        o.durability = Superblock.Durability.OS;
        try (Database db = Database.create(path, o)) {
            Collection c = db.collection("c");
            org.dizitart.cryptand.index.SpatialIndex sp = c.createSpatialIndex("loc", 2, null);
            long t = System.nanoTime();
            for (long i = 0; i < n; i++) {
                Map<String, Value> f = new LinkedHashMap<>(XlangCrudBench.doc(i, 0).fields());
                double[] p = xy(i);
                f.put("loc", new Value.Geometry(org.dizitart.cryptand.geom.Wkb.point(p[0], p[1])));
                c.insert(new Value.Doc(f));
                if ((i + 1) % 100_000 == 0) {
                    db.commit();
                    System.err.println((i + 1) + " t=" + (System.nanoTime() - t) / 1_000_000_000 + " rss_mb=" + rssMb());
                }
            }
            db.commit();
            StringBuilder line = new StringBuilder("built=" + n + " build_s=" + (System.nanoTime() - t) / 1_000_000_000
                    + " bytes=" + Files.size(path) + " rss_build_mb=" + rssMb());
            // 1000 near(r=1) probes around a document's own point, and 1000 nearestK(10).
            long s = 0x51EDC0DEL;
            long[] us = new long[1000];
            long[] kus = new long[1000];
            long rows = 0;
            for (int k = 0; k < us.length; k++) {
                s = s * 6364136223846793005L + 1442695040888963407L;
                double[] p = xy(Long.remainderUnsigned(s >>> 11, n));
                long g = System.nanoTime();
                int hits = sp.near(p[0], p[1], 1).size();
                us[k] = (System.nanoTime() - g) / 1000;
                if (hits < 1) throw new AssertionError("near probe " + k);
                rows += hits;
                g = System.nanoTime();
                if (sp.nearestK(p[0], p[1], 10).size() != Math.min(10, n)) throw new AssertionError("knn probe " + k);
                kus[k] = (System.nanoTime() - g) / 1000;
            }
            java.util.Arrays.sort(us);
            java.util.Arrays.sort(kus);
            line.append(" near_us p50=" + us[500] + " p99=" + us[990] + " near_rows=" + rows
                    + " knn10_us p50=" + kus[500] + " p99=" + kus[990]);
            // One query against brute force: near's count, and nearestK inside the 10th distance.
            double qx = 500.5, qy = 499.5;
            long brute = 0;
            double[] best = new double[10];
            java.util.Arrays.fill(best, Double.MAX_VALUE);
            for (long i = 0; i < n; i++) {
                double[] p = xy(i);
                double d = Math.hypot(p[0] - qx, p[1] - qy);
                if (d <= 1) brute++;
                if (d < best[9]) {
                    int j = 9;
                    while (j > 0 && best[j - 1] > d) { best[j] = best[j - 1]; j--; }
                    best[j] = d;
                }
            }
            int got = sp.near(qx, qy, 1).size();
            List<Long> knn = sp.nearestK(qx, qy, 10);
            boolean knnOk = knn.size() == Math.min(10, n) && sp.near(qx, qy, best[Math.min(10, (int) n) - 1]).containsAll(knn);
            line.append(" near_rows_q=" + got + " brute_near=" + brute + " knn_ok=" + knnOk + " rss_probe_mb=" + rssMb());
            if (got != brute || !knnOk) throw new AssertionError("brute force");
            long g = System.nanoTime();
            boolean sound = org.dizitart.cryptand.ops.Verify.run(db.engine()).findings().isEmpty();
            System.out.println(line + " verify_ms=" + (System.nanoTime() - g) / 1_000_000 + " verify_sound=" + sound + " rss_verify_mb=" + rssMb());
        }
    }

    /** PLAN 6.5 vectors: component k of document i, 128-d around one of 1000 cluster centres. */
    public static float[] vec(long i) {
        float[] v = new float[128];
        long c = i % 1000;
        for (int k = 0; k < 128; k++) {
            v[k] = (float) (unit(c * 128 + k) + 0.15 * (unit((i + 1) * 0x2545F4914F6CDD1DL + k) - 0.5));
        }
        return v;
    }

    private static double unit(long x) {
        long z = x + 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return ((z ^ (z >>> 31)) >>> 11) / (double) (1L << 53);
    }

    /** PLAN 6.5: a 128-d l2 vector index; 100 searches, recall@10 against brute force. */
    private static void vectorRung(Path path, long n) throws Exception {
        Files.deleteIfExists(path);
        Engine.Options o = opts();
        o.durability = Superblock.Durability.OS;
        try (Database db = Database.create(path, o)) {
            Collection c = db.collection("c");
            org.dizitart.cryptand.index.VectorIndex vx = c.createVectorIndex("emb", 128, "l2", 1024);
            long t = System.nanoTime();
            for (long i = 0; i < n; i++) {
                Map<String, Value> f = new LinkedHashMap<>(XlangCrudBench.doc(i, 0).fields());
                float[] v = vec(i);
                org.dizitart.cryptand.util.ByteWriter w = new org.dizitart.cryptand.util.ByteWriter(512);
                for (float x : v) w.f32(x);
                f.put("emb", new Value.Vector(Value.Vector.DTYPE_F32, 128, w.toBytes()));
                c.insert(new Value.Doc(f));
                if ((i + 1) % 100_000 == 0) {
                    db.commit();
                    System.err.println((i + 1) + " t=" + (System.nanoTime() - t) / 1_000_000_000 + " rss_mb=" + rssMb());
                } else if ((i + 1) % 10_000 == 0) {
                    System.err.println((i + 1) + " t=" + (System.nanoTime() - t) / 1_000_000_000);
                }
            }
            db.commit();
            StringBuilder line = new StringBuilder("built=" + n + " build_s=" + (System.nanoTime() - t) / 1_000_000_000
                    + " bytes=" + Files.size(path) + " rss_build_mb=" + rssMb());
            // Queries: a document's own cluster, fresh noise; brute force by regenerating every vector.
            int queries = 100;
            float[][] q = new float[queries][];
            for (int k = 0; k < queries; k++) {
                q[k] = vec(n + 7919L * k);
            }
            long[] us = new long[queries];
            java.util.List<java.util.Set<Long>> got = new java.util.ArrayList<>();
            for (int k = 0; k < queries; k++) {
                long g = System.nanoTime();
                java.util.Set<Long> ids = new java.util.HashSet<>();
                for (org.dizitart.cryptand.index.VectorIndex.Hit h : vx.search(q[k], 10)) ids.add(h.nitriteId());
                us[k] = (System.nanoTime() - g) / 1000;
                got.add(ids);
            }
            java.util.Arrays.sort(us);
            // ids are insertion-ordered: the i-th document's id, by a full scan.
            long[] idOf = new long[(int) n];
            try (Engine.Cursor cur = c.scan(false)) {
                int i = 0;
                while (cur.next()) idOf[i++] = ((Value.NitriteId) org.dizitart.cryptand.key.Cke.decode(cur.row().key())).id();
            }
            long hit = 0;
            double[][] best = new double[queries][10];
            long[][] bestId = new long[queries][10];
            for (double[] b : best) java.util.Arrays.fill(b, Double.MAX_VALUE);
            for (long i = 0; i < n; i++) {
                float[] v = vec(i);
                for (int k = 0; k < queries; k++) {
                    double d = org.dizitart.cryptand.index.VectorIndex.distance("l2", q[k], v);
                    if (d < best[k][9]) {
                        int j = 9;
                        while (j > 0 && best[k][j - 1] > d) { best[k][j] = best[k][j - 1]; bestId[k][j] = bestId[k][j - 1]; j--; }
                        best[k][j] = d;
                        bestId[k][j] = idOf[(int) i];
                    }
                }
            }
            for (int k = 0; k < queries; k++) for (long id : bestId[k]) if (got.get(k).contains(id)) hit++;
            line.append(" search_us p50=" + us[queries / 2] + " p99=" + us[queries * 99 / 100]
                    + String.format(" recall10=%.3f", hit / (queries * 10.0)) + " rss_probe_mb=" + rssMb());
            long g = System.nanoTime();
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
        if (mode.equals("spatial")) {
            spatialRung(path, n);
            return;
        }
        if (mode.equals("vector")) {
            vectorRung(path, n);
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
