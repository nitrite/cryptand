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
 */
public final class RssScale {
    public static void main(String[] args) throws Exception {
        Path path = Path.of(args[0]);
        long n = Long.parseLong(args[1]);
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
