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
 * {@code PATH N read}: open + 10k uniform gets; {@code PATH N settle}:
 * compact + commit + shrink, as Rust's.
 */
public final class RssScale {
    public static void main(String[] args) throws Exception {
        Path path = Path.of(args[0]);
        long n = Long.parseLong(args[1]);
        String mode = args.length > 2 ? args[2] : "build";
        if (mode.equals("read")) {
            long t = System.nanoTime();
            try (Engine e = Engine.open(path, new Engine.Options())) {
                long openMs = (System.nanoTime() - t) / 1_000_000;
                long s = 0x51EDC0DEL;
                long[] us = new long[10_000];
                for (int k = 0; k < us.length; k++) {
                    s = s * 6364136223846793005L + 1442695040888963407L;
                    long g = System.nanoTime();
                    if (e.get(16, XlangCrudBench.keyOf((s >>> 33) % n)) == null) throw new AssertionError("missing");
                    us[k] = (System.nanoTime() - g) / 1000;
                }
                java.util.Arrays.sort(us);
                System.out.println("open_ms=" + openMs + " get_uniform_us p50=" + us[5000] + " p99=" + us[9900] + " p999=" + us[9990]);
            }
            return;
        }
        if (mode.equals("settle")) {
            try (Engine e = Engine.open(path, new Engine.Options())) {
                e.compact();
                e.commitNow();
                e.shrink();
            }
            long b = Files.size(path);
            System.out.printf("settled bytes=%d space_amp=%.2f%n", b, b / (n * 516.0));
            return;
        }
        Files.deleteIfExists(path);
        Engine.Options o = new Engine.Options();
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
