package org.dizitart.cryptand;

import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.PageFile;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.Segment;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

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
    /**
     * {@code 13-operations.md} §5: {@code compact()} is a compaction "to the
     * last level". It pushed each level down one step instead, so data in L0
     * was rewritten into L1, L2 and then L3: three copies, each allocated
     * while its inputs were still named by the live superblock, and the page
     * cache kept the intermediate copies after they were freed. On the
     * cross-language CRUD matrix the file went from 1 684 pages to 5 364
     * inside the call and the cache held 33 MB of which 14 MB was live.
     */
    @Test
    @DisplayName("compact() writes the data once, and the cache drops what it freed")
    void compactWritesOnce(@TempDir Path dir) {
        Engine.Options o = options();
        o.memtableEntries = 1 << 20;
        try (Engine e = Engine.create(dir.resolve("once.cryptand"), o)) {
            byte[] doc = new byte[600];
            for (int i = 0; i < 4000; i++) {
                e.batch().put(TREE, key(i), doc).commit();
            }
            e.commitNow();
            long before = e.bytesWrittenKeyIndex();
            e.compact();
            // Bytes, not the file's growth: in a fixture this small each step
            // of the old cascade fitted exactly into the extent the step before
            // it had freed, so the file hid the two extra copies.
            long written = (e.bytesWrittenKeyIndex() - before) / e.superblock().pageSize();
            long live = 0;
            for (SegmentMeta m : e.manifest().all()) {
                assertEquals(e.superblock().levelCount - 1, m.level, "everything reached the last level");
                live += m.pages;
            }
            assertEquals(live, written, "compact() wrote " + written
                    + " pages for a " + live + "-page result");
            long residentPages = e.pager().pageCacheResidentBytes() / e.superblock().pageSize();
            assertTrue(residentPages <= live + 16, "the cache holds " + residentPages
                    + " pages with " + live + " live");
        }
    }

    /**
     * {@code 13-operations.md} §5: {@code shrink()} relocates live extents
     * downward and truncates. It only trimmed trailing free space, and a full
     * compaction leaves the free space <em>below</em> the live data, so it
     * reclaimed nothing: 820 of 3 371 pages on the cross-language CRUD matrix.
     */
    @Test
    @DisplayName("shrink() moves live extents down and ends the file at them")
    void shrinkRelocates(@TempDir Path dir) {
        shrinkRelocates(dir.resolve("shrink.cryptand"), options(), 600);
    }

    /**
     * Inline values, so the whole last level is one segment, and no hole below
     * it fits it: it goes to the end of the file and comes back down.
     */
    @Test
    @DisplayName("shrink() hops a segment that stands on a hole too small for it")
    void shrinkHops(@TempDir Path dir) {
        shrinkRelocates(dir.resolve("shrink-hop.cryptand"), options(), 200);
    }

    /**
     * A key-index page's nonce binds its page id ({@code 14-security.md} §5.2),
     * so a moved page is sealed again under a fresh nonce; a value-log record's
     * binds its segment id and offset, so it moves as it is.
     */
    @Test
    @DisplayName("shrink() re-seals what it moves in an encrypted file")
    void shrinkRelocatesEncrypted(@TempDir Path dir) {
        byte[] k = new byte[32];
        new Random(7).nextBytes(k);
        Engine.Options o = options();
        o.encrypt = true;
        o.rawKey = k;
        shrinkRelocates(dir.resolve("shrink-enc.cryptand"), o, 600);
    }

    private static long freePages(Engine e) {
        long n = 0;
        for (var x : e.pager().freeList()) {
            n += x.pages();
        }
        return n;
    }

    /**
     * The cross-language matrix's shape: a full compaction's output standing
     * on the run its inputs left, part of that run then taken by a later flush.
     */
    private static void shrinkRelocates(Path path, Engine.Options o, int size) {
        o.memtableEntries = 1 << 20;
        try (Engine e = Engine.create(path, o)) {
            for (int i = 0; i < 4000; i++) {
                e.batch().put(TREE, key(i), doc(0, size)).commit();
            }
            e.commitNow();
            e.compact();
            for (int i = 0; i < 1500; i++) {
                e.batch().put(TREE, key(i), doc(1, size)).commit();
            }
            e.commitNow();
            long before = e.pager().pageCount();
            long freeBefore = freePages(e);
            e.shrink();
            long pages = e.pager().pageCount();
            System.out.println("shrink: " + before + " pages (" + freeBefore + " free) -> "
                    + pages + " (" + freePages(e) + " free)");
            assertTrue(freeBefore > before / 5, "the fixture left no free run to reclaim");
            assertTrue(freePages(e) * 20 < pages, freePages(e) + " free pages left in " + pages);
            Verify.Report r = Verify.run(e);
            assertTrue(r.of(Verify.Kind.CORRUPTION).isEmpty() && r.of(Verify.Kind.LEAK).isEmpty(), r.toString());
        }
        o.encrypt = false;
        try (Engine e = Engine.open(path, o)) {
            for (int i = 0; i < 4000; i++) {
                assertArrayEquals(doc(i < 1500 ? 1 : 0, size), e.get(TREE, key(i)), "key " + i);
            }
            assertTrue(Verify.run(e).of(Verify.Kind.CORRUPTION).isEmpty());
        }
    }

    private static byte[] doc(int fill, int size) {
        byte[] d = new byte[size];
        java.util.Arrays.fill(d, (byte) fill);
        return d;
    }

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

    /**
     * The other half of the test above. That one asserts collection is
     * <em>safe</em> — every value survives. This one asserts it makes
     * <em>progress</em>, and the two fail in opposite directions: a GC that
     * collects nothing passes every safety check ever written.
     *
     * <p>It exists because {@code Vlog.recomputeLiveness} now scans without
     * holding the value-log monitor, and adds back everything appended while it
     * scanned. That correction is deliberately conservative — {@code
     * 04-segments.md} §6.7 lets statistics overstate liveness and never
     * understate it — and the risk it carries is exactly this: liveness that is
     * always overstated is liveness that never falls below the collection
     * threshold. The correction applies only to the <strong>open</strong>
     * segment, which is the one being appended to and the one GC would not pick
     * anyway, but "would not" is an argument and this is a measurement.
     */
    @Test
    @DisplayName("collection reclaims value-log space, not merely preserves it")
    void collectionReclaimsSpace(@TempDir Path dir) {
        // `mobile`, because its `vlog_segment_bytes` is 4 MiB against
        // `desktop`'s 64. A collection candidate is a **sealed** segment that
        // is mostly dead, so the workload has to fill and seal several — with
        // 64 MiB segments this fixture writes one partial segment that never
        // seals, and measures nothing at all.
        Engine.Options o = options();
        o.profile = Profile.MOBILE;
        int rows = 150;
        try (Engine e = Engine.create(dir.resolve("gcspace.cryptand"), o)) {
            Random rnd = new Random(11);
            // Above `mobile`'s `vlog_min` of 1024, or the value is inlined and
            // the value log stays empty — which is a fixture that measures
            // nothing while looking like it measures collection.
            byte[] big = new byte[2000];
            for (int i = 0; i < rows; i++) {
                rnd.nextBytes(big);
                e.batch().put(TREE, key(i), big.clone()).commit();
            }
            e.commitNow();
            e.compact();
            e.maintain();

            // Twenty generations of the same keys: the early value-log
            // segments end up almost entirely dead.
            for (int gen = 0; gen < 24; gen++) {
                for (int i = 0; i < rows; i++) {
                    rnd.nextBytes(big);
                    e.batch().put(TREE, key(i), big.clone()).commit();
                }
            }
            e.commitNow();
            e.compact();

            // Recompute, then ask what it concluded. **A counter, not a
            // reclaim**: whether the collector has actually freed a segment by
            // the time this line runs depends on the background compactor, and
            // an assertion on that measures the scheduler
            // (`design/performance-model.md` §8). What is deterministic is the
            // liveness it computes, and that is the thing the correction above
            // could break.
            e.maintain();
            long live = 0;
            long total = 0;
            for (org.dizitart.cryptand.lsm.VlogStats st : e.vlog().allStats()) {
                live += st.liveBytes;
                total += st.bytes;
            }

            // A control that can fail: there has to be dead space to find, or
            // this measures nothing. 150 keys of 2 000 B are live; 24
            // generations of them were written.
            assertTrue(total > 8 * rows * 2000L,
                    "the fixture wrote too little to have superseded anything: " + total + " B");

            // Overstating is allowed and understating is not (§6.7), so the
            // bound is one-sided and generous. What it rules out is liveness
            // pinned near 100 %, which is what a correction that adds back too
            // much would produce — and which no collector would ever act on.
            assertTrue(live < total / 4,
                    "liveness is overstated to uselessness: " + live + " B live of " + total
                            + " B written, with only " + (rows * 2000L) + " B actually live");

            // And it is still safe.
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
    @DisplayName("the point index answers exactly what the descent does")
    void pointIndexMatchesTheDescent(@TempDir Path dir) {
        // `Segment.pointLookup` is only built after a segment has served one
        // lookup per 32 entries, so no small test ever reaches it. This one
        // reads every key several times over segments holding superseded
        // versions (pinned by a snapshot), tombstones, and a range delete whose
        // start cell is the newest cell of a live key -- the three cases where
        // a key's first cell is not its answer -- and checks every answer,
        // current and at the snapshot, against a model.
        try (Engine e = Engine.create(dir.resolve("pi.cryptand"), options())) {
            int n = 1000;
            for (int i = 0; i < n; i++) {
                e.batch().put(TREE, key(i), val("a" + i)).commit();
            }
            e.commitNow();
            Snapshot snap = e.pin();
            for (int i = 0; i < n; i += 2) {
                e.batch().put(TREE, key(i), val("b" + i)).commit();
            }
            for (int i = 0; i < n; i += 7) {
                e.batch().remove(TREE, key(i)).commit();
            }
            e.batch().removeRange(TREE, key(100), key(120)).commit();
            for (int i = 500; i < 600; i++) {
                e.batch().put(TREE, key(i), val("c" + i)).commit();
            }
            e.commitNow();
            e.compact();
            for (int pass = 0; pass < 3; pass++) {
                for (int i = 0; i < n + 50; i++) {
                    String now = i >= 500 && i < 600 ? "c" + i
                            : i >= n || (i >= 100 && i < 120) || i % 7 == 0 ? null
                            : i % 2 == 0 ? "b" + i : "a" + i;
                    byte[] got = e.get(TREE, key(i));
                    assertEquals(now, got == null ? null : new String(got, StandardCharsets.UTF_8),
                            "key " + i + ", pass " + pass);
                    byte[] then = e.get(TREE, key(i), snap.seq(), Engine.CLOCK_ON_DEMAND);
                    assertEquals(i < n ? "a" + i : null,
                            then == null ? null : new String(then, StandardCharsets.UTF_8),
                            "key " + i + " at the snapshot, pass " + pass);
                }
            }
            assertTrue(!e.segments().isEmpty());
            for (Segment s : e.segments()) {
                assertTrue(s.pointIndexed(), "segment " + s.meta().segmentId + " was never read through its index");
            }
            e.unpin(snap);
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
