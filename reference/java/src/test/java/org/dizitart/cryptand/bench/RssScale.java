package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Cve;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * F-147: writer memory while building an N-document file, the Java twin of
 * Rust {@code examples/rss_scale.rs} and Dart {@code tool/rss_scale.dart
 * build} (same document, commit per 100k). Run under {@code /usr/bin/time -l}.
 * {@code PATH N read}: open, 10k uniform + 10k zipf gets, a 100k-row scan, verify; {@code PATH N settle}:
 * compact + commit + shrink, as Rust's.
 */
public final class RssScale {
    /** {@code CRYPTAND_ENC=1}: encrypted file, fixed raw key (kdf 0), as Rust {@code rss_scale}. */
    private static Engine.Options opts() {
        Engine.Options o = new Engine.Options();
        // ponytail: fixed bench key, never a real secret.
        if (System.getenv("CRYPTAND_ENC") != null) {
            o.encrypt = true;
            o.rawKey = new byte[32];
            java.util.Arrays.fill(o.rawKey, (byte) 7);
        }
        return o;
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
        o.profile = Profile.DESKTOP;
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
