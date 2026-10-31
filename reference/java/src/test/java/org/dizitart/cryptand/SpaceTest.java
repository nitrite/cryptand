package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** F-150: dead value-log space must come back (04 §6.8). */
class SpaceTest {
    @TempDir
    Path dir;

    @Test
    void f150OverwritingTheSameValuesDoesNotGrowTheFile() throws Exception {
        // 100 x (open, overwrite 256 x 4 KiB, commit, close), as Rust's and
        // Dart's space tests. Java was not affected: ~10 MB, a 1 MB step every
        // ~100 sessions (8.8 MB at 50, 10.9 MB at 300).
        Path path = dir.resolve("f150.cryptand");
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        Engine.create(path, o).close();
        for (int cycle = 0; cycle < 100; cycle++) {
            try (Engine e = Engine.open(path, o)) {
                Engine.Batch b = e.batch();
                for (int i = 0; i < 256; i++) {
                    byte[] v = new byte[4096];
                    Arrays.fill(v, (byte) cycle);
                    b.put(TreeId.FIRST_USER_TREE, Cke.encode(new Value.NitriteId(i)), v);
                }
                b.commit();
            }
        }
        long len = Files.size(path);
        try (Engine e = Engine.open(path, o)) {
            byte[] want = new byte[4096];
            Arrays.fill(want, (byte) 99);
            for (int i = 0; i < 256; i++) {
                assertArrayEquals(want, e.get(TreeId.FIRST_USER_TREE, Cke.encode(new Value.NitriteId(i))));
            }
        }
        assertTrue(len < 16L << 20, "file " + len + " bytes for 1 MiB live");
    }

    @Test
    void f207AFlushOverMoreTreesThanAHeadPageListsSplits() {
        // 2000 trees x 12 B of tree_span[] is 24 KB of header: 04 §2.1 says split.
        Path path = dir.resolve("f207.cryptand");
        Engine.Options o = new Engine.Options();
        Engine.create(path, o).close();
        try (Engine e = Engine.open(path, o)) {
            for (int t = 16; t < 2016; t++) {
                e.batch().put(t, Cke.encode(new Value.NitriteId(1)), new byte[] {(byte) t}).commit();
            }
            e.commitNow(true);
            e.compact();
        }
        try (Engine e = Engine.open(path, o)) {
            for (int t = 16; t < 2016; t++) {
                assertArrayEquals(new byte[] {(byte) t}, e.get(t, Cke.encode(new Value.NitriteId(1))), "tree " + t);
            }
        }
    }
}
