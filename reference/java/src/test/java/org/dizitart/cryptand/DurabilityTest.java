package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The durability modes of {@code spec/10-transactions.md} §7, and the committer
 * protocol of §2 — the paths the rest of the suite deliberately avoids so that
 * it is not measuring the host's fsync latency.
 */
class DurabilityTest {

    private static final int TREE = TreeId.FIRST_USER_TREE;

    private static byte[] key(long n) {
        return Cke.encode(Value.i64(n));
    }

    private static byte[] val(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static Engine.Options sync() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.durability = Superblock.Durability.SYNC;
        return o;
    }

    /**
     * §7's second MUST, and the load-bearing one: an implementation records
     * what it <em>performed</em>, never what was requested. The failure is
     * silent — a file whose {@code durability_achieved} says {@code full} when
     * only a page-cache flush happened looks perfect until the power goes out.
     */
    @Test
    @DisplayName("durability_achieved records what was performed, not what was asked for")
    void achievedIsWhatHappened(@TempDir Path dir) {
        Engine.Options o = sync();
        o.durability = Superblock.Durability.FULL;
        try (Engine e = Engine.create(dir.resolve("a.cryptand"), o)) {
            // The JDK's strongest portable flush is FileChannel.force, which is
            // `sync`. Requesting `full` and recording `sync` is correct
            // behaviour on a runtime with no device-level flush.
            assertEquals(Superblock.Durability.SYNC, e.superblock().durabilityAchieved);
        }
    }

    /**
     * §2 step 7: under {@code sync} a writer does not return until
     * {@code visible_seq} has passed its batch, so a read that follows a commit
     * in program order sees it — through a durable segment, not the memtable.
     */
    @Test
    @DisplayName("a sync commit does not return before its batch is visible and durable")
    void syncCommitWaitsForVisibility(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("b.cryptand"), sync())) {
            for (int i = 0; i < 20; i++) {
                long seq = e.batch().put(TREE, key(i), val("v" + i)).commit();
                assertTrue(e.visibleSeq() >= seq,
                        "commit returned at seq " + seq + " with visible_seq " + e.visibleSeq());
                assertArrayEquals(val("v" + i), e.get(TREE, key(i)));
            }
            // Everything is in segments, not in a memtable: the committer
            // flushed before advancing the watermark.
            assertTrue(e.flushCount() > 0);
        }
    }

    /** §2.4: batches arriving in one commit window share the committer's barriers. */
    @Test
    @DisplayName("concurrent writers share one commit's barriers")
    void groupCommit(@TempDir Path dir) throws Exception {
        try (Engine e = Engine.create(dir.resolve("c.cryptand"), sync())) {
            int threads = 8;
            List<Thread> ts = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int id = t;
                Thread th = new Thread(() -> {
                    for (int i = 0; i < 25; i++) {
                        e.batch().put(TREE, key(id * 1000L + i), val(id + ":" + i)).commit();
                    }
                });
                ts.add(th);
                th.start();
            }
            for (Thread th : ts) {
                th.join();
            }
            for (int t = 0; t < threads; t++) {
                for (int i = 0; i < 25; i++) {
                    assertArrayEquals(val(t + ":" + i), e.get(TREE, key(t * 1000L + i)));
                }
            }
            // 200 batches did not each cost their own commit: group commit is
            // what makes a shared barrier over n batches, however many threads
            // produced them.
            assertTrue(e.superblock().commitId < 200,
                    "commits: " + e.superblock().commitId + " for 200 batches");
        }
    }

    /**
     * §4: recovery is reading two superblocks. What a crash loses is batches
     * whose seq range had not reached {@code visible_seq}; what it cannot do,
     * at any setting, is produce a structurally invalid database.
     */
    @Test
    @DisplayName("acknowledged batches survive a reopen, and the file verifies")
    void acknowledgedDataSurvives(@TempDir Path dir) {
        Path f = dir.resolve("d.cryptand");
        try (Engine e = Engine.create(f, sync())) {
            for (int i = 0; i < 40; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
        }
        try (Engine e = Engine.open(f, sync())) {
            for (int i = 0; i < 40; i++) {
                assertArrayEquals(val("v" + i), e.get(TREE, key(i)), "key " + i);
            }
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
            assertTrue(r.of(Verify.Kind.DOUBLE_ALLOCATION).isEmpty(), r.toString());
        }
    }

    /**
     * §7: {@code none} and {@code os} acknowledge immediately, so an
     * acknowledged batch is visible immediately. They risk losing recent
     * batches, never structural validity.
     */
    @Test
    @DisplayName("os acknowledges immediately and the write is visible immediately")
    void osAcknowledgesImmediately(@TempDir Path dir) {
        Engine.Options o = sync();
        o.durability = Superblock.Durability.OS;
        try (Engine e = Engine.create(dir.resolve("e.cryptand"), o)) {
            long seq = e.batch().put(TREE, key(1), val("x")).commit();
            assertTrue(e.visibleSeq() >= seq);
            assertArrayEquals(val("x"), e.get(TREE, key(1)));
        }
    }

    /**
     * F-069: slot B sits at offset {@code page_size}, which a reader cannot know
     * when slot A is invalid. Rust's {@code create} leaves slot A blank until the
     * first close, so a crash before it lost an 8 KiB file in all three readers.
     */
    @Test
    @DisplayName("F-069: a file whose slot A is invalid opens from slot B at any page size")
    void slotBAloneOpens(@TempDir Path dir) throws Exception {
        Path p = dir.resolve("b.cryptand");
        try (Engine e = Engine.create(p, sync())) {
            e.batch().put(TREE, key(1), val("one")).commit();
        }
        try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(p,
                java.nio.file.StandardOpenOption.WRITE)) {
            ch.write(java.nio.ByteBuffer.allocate(Superblock.BYTES), 0);
        }
        try (Engine e = Engine.open(p, sync())) {
            assertTrue(e.superblock().pageSize() != 4096, "the case needs a non-4 KiB page");
            assertTrue(Verify.run(e).findings().isEmpty(), "verify: " + Verify.run(e).findings());
        }
    }

    /**
     * F-080: tree 1 is rebuilt into end-of-file pages every commit, and the
     * pages it leaves behind must come back, or a sync file grows with every
     * commit rather than with its data.
     */
    @Test
    @DisplayName("F-080: 1000 single-put sync commits keep the file bounded")
    void syncCommitsDoNotGrowTheFile(@TempDir Path dir) throws Exception {
        Path p = dir.resolve("g.cryptand");
        long pages;
        try (Engine e = Engine.create(p, sync())) {
            for (int i = 0; i < 1000; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            pages = e.superblock().pageCount;
            assertTrue(Verify.run(e).findings().isEmpty(), "verify: " + Verify.run(e).findings());
        }
        System.out.println("F-080 java pages=" + pages + " bytes=" + java.nio.file.Files.size(p));
        assertTrue(pages < 200, "1000 commits of ~10 bytes made " + pages + " pages");
    }
}
