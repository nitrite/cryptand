package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.container.Superblock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/** F-162: a compactor killed by an Error must fail the next write, not stall it forever. */
class DeadCompactorTest {
    @Test
    void writerSeesDeadCompactor(@TempDir Path dir) throws Exception {
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        o.memtableEntries = 16;
        Engine.compactorHook = () -> {
            throw new OutOfMemoryError("F-162 test");
        };
        try (Engine e = Engine.create(dir.resolve("db.cff"), o)) {
            long deadline = System.nanoTime() + 10_000_000_000L;
            for (int i = 0; System.nanoTime() < deadline; i++) {
                try {
                    e.batch().put(1, new byte[] {(byte) (i >> 8), (byte) i}, new byte[] {1}).commit();
                } catch (IllegalStateException x) {
                    assertTrue(x.getCause() instanceof OutOfMemoryError);
                    return;
                }
            }
            fail("writes kept going for 10 s after the compactor died");
        } catch (IllegalStateException closeAlsoFails) {
            // close reports the same failure; the assertion above already ran
        } finally {
            Engine.compactorHook = null;
        }
    }
}
