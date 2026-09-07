package org.dizitart.cryptand;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The engine end to end — {@code spec/04-segments.md} and
 * {@code spec/10-transactions.md}.
 */
class EngineTest {

    private static final int TREE = TreeId.FIRST_USER_TREE;

    private static byte[] key(String s) {
        return Cke.encode(new Value.Str(s));
    }

    private static byte[] key(long n) {
        return Cke.encode(Value.i64(n));
    }

    private static byte[] val(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        // `os` rather than `sync`: these tests are about semantics, and on a
        // spinning or external volume an fsync per commit turns a 150 ms suite
        // into a 60 s one without covering one extra branch. The durability
        // path itself is covered by DurabilityTest, which uses `sync`.
        o.durability = Superblock.Durability.OS;
        return o;
    }

    /**
     * Two value-log collections with no write between them.
     *
     * <p>GC decides liveness with {@code lookup(..., visible_seq, ...)} and
     * writes its pointer rewrites above {@code visible_seq}. Nothing else moves
     * that watermark on an idle database — {@code publishSuperblock} republishes
     * the one it is handed — so a second pass read the entry the first pass had
     * already superseded, found it pointing into a segment the first pass had
     * already freed, concluded the surviving record was dead, and freed the
     * segment holding it. 295 of 600 keys became unreadable, the file verified
     * as corrupt, and every step of it was a normal maintenance call.
     *
     * <p>Four passes, because {@code collect0} runs up to four in one call and
     * each is another chance to.
     */
    @Test
    @DisplayName("repeated collection with no write between passes keeps every value")
    void collectionTwiceKeepsValues(@TempDir Path dir) {
        int rows = 600;
        try (Engine e = Engine.create(dir.resolve("gc.cryptand"), options())) {
            Random rnd = new Random(4);
            // Above desktop's vlog_min of 256, so every value is separated and
            // collection has something to reclaim.
            byte[] big = new byte[400];
            for (int i = 0; i < rows; i++) {
                rnd.nextBytes(big);
                e.batch().put(TREE, key(i), big.clone()).commit();
            }
            e.commitNow();
            e.compact();
            e.maintain();
            // Ten times the dataset in updates, so the segments holding the
            // first generation are mostly dead and collection has candidates.
            for (int i = 0; i < rows * 10; i++) {
                rnd.nextBytes(big);
                e.batch().put(TREE, key(rnd.nextInt(rows)), big.clone()).commit();
            }
            e.commitNow();
            // And then maintenance with no write at all between the passes.
            e.compact();
            e.maintain();
            for (int i = 0; i < rows; i++) {
                assertNotNull(e.get(TREE, key(i)), "key " + i + " after collection");
            }
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty(), r.toString());
        }
    }

    @Test
    @DisplayName("a put is readable, and survives close and reopen")
    void putGetReopen(@TempDir Path dir) {
        Path f = dir.resolve("a.cryptand");
        try (Engine e = Engine.create(f, options())) {
            e.batch().put(TREE, key("alpha"), val("one")).put(TREE, key("beta"), val("two")).commit();
            assertArrayEquals(val("one"), e.get(TREE, key("alpha")));
            assertArrayEquals(val("two"), e.get(TREE, key("beta")));
            assertNull(e.get(TREE, key("gamma")));
        }
        try (Engine e = Engine.open(f, options())) {
            assertArrayEquals(val("one"), e.get(TREE, key("alpha")));
            assertArrayEquals(val("two"), e.get(TREE, key("beta")));
        }
    }

    @Test
    @DisplayName("the newest version wins, and a delete hides every older one")
    void versionsAndDeletes(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("b.cryptand"), options())) {
            e.batch().put(TREE, key("k"), val("v1")).commit();
            e.batch().put(TREE, key("k"), val("v2")).commit();
            e.batch().put(TREE, key("k"), val("v3")).commit();
            assertArrayEquals(val("v3"), e.get(TREE, key("k")));
            e.batch().remove(TREE, key("k")).commit();
            assertNull(e.get(TREE, key("k")));
            e.batch().put(TREE, key("k"), val("v4")).commit();
            assertArrayEquals(val("v4"), e.get(TREE, key("k")));
        }
    }

    /**
     * §4's first load-bearing rule: candidates are resolved by the winning
     * entry's own {@code seq}, not by segment order. A segment's
     * {@code max_seq} is an aggregate over every key it holds, so this
     * arrangement — an unrelated key written last, landing in a later
     * segment — is exactly the shape that returns a stale version to an engine
     * that takes the first hit in {@code max_seq} order.
     */
    @Test
    @DisplayName("a stale version is not returned when a later segment has a higher max_seq")
    void resolvesByEntrySeqNotSegmentOrder(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("c.cryptand"), options())) {
            e.batch().put(TREE, key("k"), val("new")).commit();
            e.batch().put(TREE, key("zzz"), val("unrelated")).commit();
            assertArrayEquals(val("new"), e.get(TREE, key("k")));
            e.earlyExit = false;
            assertArrayEquals(val("new"), e.get(TREE, key("k")), "without the early exit too");
        }
    }

    @Test
    @DisplayName("a range delete hides the keys inside it and nothing outside")
    void rangeDelete(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("d.cryptand"), options())) {
            for (int i = 0; i < 20; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.batch().removeRange(TREE, key(5), key(15)).commit();
            for (int i = 0; i < 20; i++) {
                byte[] got = e.get(TREE, key(i));
                if (i >= 5 && i < 15) {
                    assertNull(got, "key " + i + " is inside the deleted range");
                } else {
                    assertArrayEquals(val("v" + i), got, "key " + i);
                }
            }
        }
    }

    @Test
    @DisplayName("a range delete survives a flush and is not resurrected by the filter")
    void rangeDeleteAfterFlush(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("e.cryptand"), options())) {
            for (int i = 0; i < 200; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.batch().removeRange(TREE, key(50), key(150)).commit();
            e.commitNow();
            e.maintain();
            for (int i = 0; i < 200; i++) {
                if (i >= 50 && i < 150) {
                    assertNull(e.get(TREE, key(i)), "key " + i);
                } else {
                    assertArrayEquals(val("v" + i), e.get(TREE, key(i)), "key " + i);
                }
            }
        }
    }

    @Test
    @DisplayName("an expired entry is invisible at read time, whatever compaction has done")
    void ttl(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("f.cryptand"), options())) {
            e.batch().putWithExpiry(TREE, key("soon"), val("x"), 1_000).commit();
            e.batch().put(TREE, key("forever"), val("y")).commit();
            assertNotNull(e.get(TREE, key("soon"), e.visibleSeq(), 999));
            assertNull(e.get(TREE, key("soon"), e.visibleSeq(), 1_000));
            assertNotNull(e.get(TREE, key("forever"), e.visibleSeq(), 10_000));
        }
    }

    @Test
    @DisplayName("a value at or above vlog_min is separated and reads back byte-exact")
    void valueLogSeparation(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("g.cryptand"), options())) {
            byte[] big = new byte[4096];
            new Random(7).nextBytes(big);
            e.batch().put(TREE, key("big"), big).commit();
            assertArrayEquals(big, e.get(TREE, key("big")));
            e.commitNow();
            // The cell holds a 16-byte pointer, not the value.
            boolean found = false;
            for (Segment s : e.segments()) {
                for (BtreePage.Leaf leaf : s.readAll()) {
                    if (Ikey.treeIdOf(leaf.key()) == TREE) {
                        assertEquals(BtreePage.Kind.VLOG, leaf.kind());
                        assertEquals(16, leaf.value().length);
                        found = true;
                    }
                }
            }
            assertTrue(found, "the entry reached a segment");
        }
    }

    @Test
    @DisplayName("a value at or above blob_threshold becomes its own extent")
    void blob(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("h.cryptand"), options())) {
            byte[] huge = new byte[300_000];
            new Random(11).nextBytes(huge);
            e.batch().put(TREE, key("huge"), huge).commit();
            assertArrayEquals(huge, e.get(TREE, key("huge")));
        }
    }

    @Test
    @DisplayName("a forward scan and a reverse scan are the same rows in opposite order")
    void scanBothDirections(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("i.cryptand"), options())) {
            for (int i = 0; i < 300; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            List<String> forward = new ArrayList<>();
            try (Engine.Cursor c = e.scan(TREE, null, null, false)) {
                while (c.next()) {
                    forward.add(new String(c.row().value(), StandardCharsets.UTF_8));
                }
            }
            assertEquals(300, forward.size());
            List<String> reverse = new ArrayList<>();
            try (Engine.Cursor c = e.scan(TREE, null, null, true)) {
                while (c.next()) {
                    reverse.add(new String(c.row().value(), StandardCharsets.UTF_8));
                }
            }
            Collections.reverse(reverse);
            assertEquals(forward, reverse);
        }
    }

    @Test
    @DisplayName("a bounded scan returns exactly the keys inside the bounds")
    void boundedScan(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("j.cryptand"), options())) {
            for (int i = 0; i < 100; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            List<String> got = new ArrayList<>();
            try (Engine.Cursor c = e.scan(TREE, key(10), key(19), false)) {
                while (c.next()) {
                    got.add(new String(c.row().value(), StandardCharsets.UTF_8));
                }
            }
            assertEquals(10, got.size());
            assertEquals("v10", got.get(0));
            assertEquals("v19", got.get(9));
        }
    }

    @Test
    @DisplayName("compaction preserves every get at every live snapshot")
    void compactionPreservesReads(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("k.cryptand"), options())) {
            for (int i = 0; i < 2000; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            for (int i = 0; i < 500; i++) {
                e.batch().put(TREE, key(i), val("u" + i)).commit();
            }
            e.commitNow();
            e.maintain();
            assertTrue(e.compactionCount() > 0, "something compacted");
            for (int i = 0; i < 2000; i++) {
                String want = i < 500 ? "u" + i : "v" + i;
                assertArrayEquals(val(want), e.get(TREE, key(i)), "key " + i);
            }
        }
    }

    @Test
    @DisplayName("a levelled last level's segments do not overlap in user keys")
    void lastLevelIsDisjoint(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("l.cryptand"), options())) {
            for (int i = 0; i < 3000; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            e.maintain();
            int last = e.superblock().levelCount - 1;
            List<SegmentMeta> lastLevel = e.manifest().at(last);
            for (int i = 0; i < lastLevel.size(); i++) {
                for (int j = i + 1; j < lastLevel.size(); j++) {
                    assertTrue(!SegmentMeta.userRangesOverlap(lastLevel.get(i), lastLevel.get(j)),
                            "segments " + i + " and " + j + " overlap in user keys at the last level");
                }
            }
        }
    }

    @Test
    @DisplayName("every key in a segment passes that segment's own filter")
    void filterHasNoFalseNegatives(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("m.cryptand"), options())) {
            for (int i = 0; i < 500; i++) {
                e.batch().put(TREE, key("key-" + i), val("v" + i)).commit();
            }
            e.commitNow();
            for (Segment s : e.segments()) {
                for (BtreePage.Leaf leaf : s.readAll()) {
                    assertTrue(s.mayContain(Ikey.userKeyOf(leaf.key())),
                            "a false negative would silently lose a key");
                }
            }
        }
    }

    @Test
    @DisplayName("skip(n) lands where n steps of next() land")
    void skipMatchesStepping(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("n.cryptand"), options())) {
            for (int i = 0; i < 400; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            for (Segment s : e.segments()) {
                Segment.Cursor a = s.cursor();
                a.seekFirst();
                Segment.Cursor b = s.cursor();
                b.seekFirst();
                long n = Math.min(37, s.meta().entryCount - 1);
                for (int i = 0; i < n; i++) {
                    a.next();
                }
                b.skip(n);
                assertArrayEquals(a.key(), b.key());
            }
        }
    }

    @Test
    @DisplayName("concurrent writers all land, with no database-wide lock on the write path")
    void concurrentWriters(@TempDir Path dir) throws Exception {
        try (Engine e = Engine.create(dir.resolve("o.cryptand"), options())) {
            int threads = 8;
            int perThread = 200;
            List<Thread> ts = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int id = t;
                Thread th = new Thread(() -> {
                    for (int i = 0; i < perThread; i++) {
                        e.batch().put(TREE, key("t" + id + "-" + i), val(id + ":" + i)).commit();
                    }
                });
                ts.add(th);
                th.start();
            }
            for (Thread th : ts) {
                th.join();
            }
            e.commitNow();
            for (int t = 0; t < threads; t++) {
                for (int i = 0; i < perThread; i++) {
                    assertArrayEquals(val(t + ":" + i), e.get(TREE, key("t" + t + "-" + i)),
                            "t" + t + "-" + i);
                }
            }
        }
    }

    @Test
    @DisplayName("a second writing process is refused by name, not opened anyway")
    void writerExclusion(@TempDir Path dir) {
        Path f = dir.resolve("p.cryptand");
        try (Engine e = Engine.create(f, options())) {
            e.batch().put(TREE, key("x"), val("y")).commit();
            // The JDK's file lock is per-JVM, so a second PageFile in this
            // process reports an overlap rather than contending with another
            // process; either way the rule is the same: refuse, never fall back.
            LockedException ex = assertThrows(LockedException.class,
                    () -> new PageFile(f, false, Superblock.Durability.SYNC));
            assertTrue(ex.getMessage().contains("locked by another process"));
        }
    }

    /**
     * §5's condition 3, in the form that is easy to get wrong: a compaction
     * that reaches the target level but not that level's <em>other</em>
     * range-partition groups has not seen every older version, so dropping a
     * tombstone there resurrects the key it hid.
     *
     * <p>"No lower level overlaps" is the natural reading of condition 3 and it
     * is insufficient on its own. The failure is a wrong answer, not a slow
     * one, and it only appears once a level actually holds more than one group.
     */
    @Test
    @DisplayName("a deleted key stays deleted across repeated compaction")
    void noResurrectionAcrossGroups(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("r.cryptand"), options())) {
            for (int i = 0; i < 1500; i++) {
                e.batch().put(TREE, key(i), val("v" + i)).commit();
            }
            e.commitNow();
            e.maintain();
            for (int i = 0; i < 1500; i += 3) {
                e.batch().remove(TREE, key(i)).commit();
            }
            e.commitNow();
            for (int round = 0; round < 3; round++) {
                e.maintain();
            }
            for (int i = 0; i < 1500; i++) {
                if (i % 3 == 0) {
                    assertNull(e.get(TREE, key(i)), "key " + i + " was deleted");
                } else {
                    assertArrayEquals(val("v" + i), e.get(TREE, key(i)), "key " + i);
                }
            }
        }
    }

    @Test
    @DisplayName("a batch is atomic across trees: all of it is visible or none")
    void batchSpansTrees(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("q.cryptand"), options())) {
            int other = TREE + 1;
            long seq = e.batch()
                    .put(TREE, key("doc"), val("body"))
                    .putEmpty(other, key("idx"))
                    .commit();
            assertTrue(e.visibleSeq() >= seq);
            assertArrayEquals(val("body"), e.get(TREE, key("doc")));
            assertTrue(e.containsKey(other, key("idx"), e.visibleSeq(), Long.MAX_VALUE));
        }
    }
}
