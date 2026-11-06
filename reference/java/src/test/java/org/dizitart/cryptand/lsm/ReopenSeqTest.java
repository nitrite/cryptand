package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReopenSeqTest {

    /**
     * F-213, 6.7 soak: a kill while a batch held seqs it had not completed left
     * a superblock with next_seq > visible_seq + 1. The reopened engine started
     * its contiguous prefix at visible_seq, the first batch landed above the
     * abandoned seqs, the prefix never reached it, and a sync writer waited forever.
     */
    @Test
    void firstCommitAfterAKillWithSeqsInFlightCompletes(@TempDir Path dir) throws Exception {
        Path path = dir.resolve("db.cff");
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        o.backgroundCompaction = false;
        Engine e = Engine.create(path, o);
        e.batch().put(1, key(0), new byte[8]).commit();
        e.commitNow();
        CountDownLatch inWindow = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Engine.afterEntriesHook = () -> {
            Engine.afterEntriesHook = null;
            inWindow.countDown();
            try {
                release.await();
            } catch (InterruptedException x) {
                Thread.currentThread().interrupt();
            }
        };
        Thread writer = new Thread(() -> {
            try {
                e.batch().put(1, key(1), new byte[8]).commit();
            } catch (RuntimeException ignored) {
                // the engine is gone by the time it resumes
            }
        });
        writer.start();
        try {
            assertTrue(inWindow.await(10, TimeUnit.SECONDS), "the writer never reached the window");
            e.commitNow(); // persists next_seq past the in-flight batch, visible_seq below it
            e.abandon();
        } finally {
            Engine.afterEntriesHook = null;
            release.countDown();
            writer.join();
        }

        Engine.Options s = new Engine.Options();
        s.durability = Superblock.Durability.SYNC;
        s.backgroundCompaction = false;
        try (Engine r = Engine.open(path, s)) {
            assertTimeoutPreemptively(Duration.ofSeconds(10),
                    () -> r.batch().put(1, key(2), new byte[8]).commit());
            assertNotNull(r.get(1, key(0), r.visibleSeq(), Engine.CLOCK_ON_DEMAND));
            assertNull(r.get(1, key(1), r.visibleSeq(), Engine.CLOCK_ON_DEMAND), "the abandoned batch came back");
            assertNotNull(r.get(1, key(2), r.visibleSeq(), Engine.CLOCK_ON_DEMAND));
        }
        try (Engine r = Engine.open(path, s)) {
            assertNotNull(r.get(1, key(2), r.visibleSeq(), Engine.CLOCK_ON_DEMAND));
        }
    }

    private static byte[] key(int k) {
        return Cke.encode(new Value.Bytes(new byte[]{(byte) k}));
    }
}
