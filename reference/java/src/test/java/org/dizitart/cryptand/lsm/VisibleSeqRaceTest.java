package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.container.Superblock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-178: under {@code os} the writer advances {@code visible_seq} itself. A
 * publish that read the watermark at its start and stored it at its end put
 * it back over a batch acknowledged in between: that batch read as absent,
 * and {@code completed > visible} re-armed the committer, which then
 * published back to back (2 200 superblocks a minute at mobile 10^8).
 */
class VisibleSeqRaceTest {
    @Test
    void publishNeverMovesVisibleSeqBack(@TempDir Path dir) throws Exception {
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.OS;
        o.backgroundCompaction = false;
        try (Engine e = Engine.create(dir.resolve("db.cff"), o)) {
            e.batch().put(1, new byte[]{1}, new byte[]{1}).commit();
            AtomicBoolean once = new AtomicBoolean();
            AtomicLong acked = new AtomicLong();
            Engine.afterStatsHook = () -> {
                if (!once.compareAndSet(false, true)) {
                    return;
                }
                Thread w = new Thread(() -> {
                    e.batch().put(1, new byte[]{2}, new byte[]{2}).commit();
                    acked.set(e.visibleSeq());
                });
                w.start();
                try {
                    w.join();
                } catch (InterruptedException x) {
                    throw new IllegalStateException(x);
                }
            };
            try {
                e.commitNow();
            } finally {
                Engine.afterStatsHook = null;
            }
            // Read once, at once: the committer sees `completed > visible` and
            // republishes, which hides the regression a moment later.
            long visible = e.visibleSeq();
            assertTrue(once.get(), "the hook ran inside a publish");
            assertTrue(visible >= acked.get(), "visible_seq went back from " + acked.get() + " to " + visible);
            assertNotNull(e.get(1, new byte[]{2}), "an acknowledged write reads as absent");
        }
    }
}
