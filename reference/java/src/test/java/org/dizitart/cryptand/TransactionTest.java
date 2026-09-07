package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Transactions — {@code spec/10-transactions.md} §3 — and the one creation rule
 * that costs a database when it is missing.
 *
 * <p>{@link Transaction} sat at 66 % line coverage: the suite created one,
 * committed it, and never exercised a savepoint, a rollback, a read-only
 * refusal, or the isolation levels' differing conflict rules. Those are not
 * decoration — §3 makes each of them a distinct MUST, and an implementation
 * can satisfy "a transaction commits" while getting every one of them wrong.
 */
class TransactionTest {

    private static final int T = 16;

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static byte[] k(long id) {
        return Cke.encode(new Value.NitriteId(id));
    }

    private static byte[] v(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // §2 of 01-container: create must not destroy what is already there
    // ------------------------------------------------------------------

    @Test
    @DisplayName("create refuses to overwrite a database that is already there")
    void createRefusesToOverwrite(@TempDir Path dir) throws Exception {
        // This implementation already refused, and nothing tested it — while
        // the Rust and Dart ones silently truncated. It is a plausible thing
        // for an operator or a deploy script to do, and there is no undo, so
        // the guard is worth a test in every implementation that has it.
        Path path = dir.resolve("keep.cryptand");
        try (Database db = Database.create(path, options())) {
            Collection c = db.collection("people");
            c.insert(doc(1));
            db.commit();
        }
        long before = Files.size(path);
        assertTrue(before > 0);

        assertThrows(InvalidArgumentException.class, () -> Database.create(path, options()));
        assertEquals(before, Files.size(path), "the refusal must not have touched the file");

        try (Database db = Database.open(path, options())) {
            assertNotNull(db.collection("people"), "the original data must still be there");
        }
    }

    private static Value.Doc doc(long id) {
        java.util.Map<String, Value> f = new java.util.LinkedHashMap<>();
        f.put("_id", new Value.NitriteId(id));
        f.put("n", Value.integer(NumType.I64, id));
        return new Value.Doc(f);
    }

    // ------------------------------------------------------------------
    // §3 -- savepoints, rollback, and the isolation levels
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a savepoint discards the entries written after it, and nothing before")
    void aSavepointDiscardsWhatFollowsIt(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("sp.cryptand"), options())) {
            try (Transaction tx = db.begin()) {
                tx.put(T, k(1), v("one"));
                int mark = tx.savepoint();
                tx.put(T, k(2), v("two"));
                tx.put(T, k(3), v("three"));
                // Visible inside the transaction before the rollback...
                assertArrayEquals(v("two"), tx.get(T, k(2)));
                tx.rollbackTo(mark);
                // ...and gone after it, while the write before the mark stays.
                assertNull(tx.get(T, k(2)), "an entry after the savepoint survived");
                assertNull(tx.get(T, k(3)));
                assertArrayEquals(v("one"), tx.get(T, k(1)),
                        "the savepoint discarded a write that preceded it");
                tx.commit();
            }
            Engine e = db.engine();
            assertArrayEquals(v("one"), e.get(T, k(1)));
            assertNull(e.get(T, k(2)));
        }
    }

    @Test
    @DisplayName("nested savepoints unwind in order, and the newest may be re-taken")
    void nestedSavepointsUnwindInOrder(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("sp2.cryptand"), options())) {
            try (Transaction tx = db.begin()) {
                tx.put(T, k(1), v("a"));
                int s1 = tx.savepoint();
                tx.put(T, k(2), v("b"));
                int s2 = tx.savepoint();
                tx.put(T, k(3), v("c"));
                tx.rollbackTo(s2);
                assertNull(tx.get(T, k(3)));
                assertArrayEquals(v("b"), tx.get(T, k(2)), "s2 must not have unwound past itself");
                // A savepoint taken after an unwind is a fresh mark, and
                // rolling back to the older one still discards everything
                // after it.
                tx.put(T, k(4), v("d"));
                tx.rollbackTo(s1);
                assertNull(tx.get(T, k(2)));
                assertNull(tx.get(T, k(4)));
                assertArrayEquals(v("a"), tx.get(T, k(1)));
                tx.commit();
            }
        }
    }

    @Test
    @DisplayName("rollback is free and leaves no trace")
    void rollbackLeavesNoTrace(@TempDir Path dir) {
        // §3: an aborted transaction writes nothing, so a rollback costs
        // nothing on the device -- there is no undo log to replay because
        // there was never anything written to undo.
        try (Database db = Database.create(dir.resolve("rb.cryptand"), options())) {
            long pagesBefore = db.engine().pager().pageCount();
            try (Transaction tx = db.begin()) {
                for (int i = 0; i < 500; i++) {
                    tx.put(T, k(i), v("value " + i));
                }
                tx.rollback();
            }
            assertEquals(pagesBefore, db.engine().pager().pageCount(),
                    "an aborted transaction grew the file");
            Engine e = db.engine();
            assertNull(e.get(T, k(0)));
            assertNull(e.get(T, k(499)));
        }
    }

    @Test
    @DisplayName("a read-only transaction cannot write and never conflicts")
    void aReadOnlyTransactionCannotWrite(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("ro.cryptand"), options())) {
            db.engine().batch().put(T, k(1), v("committed")).commit();
            db.commit();
            try (Transaction tx = db.begin(Transaction.Isolation.READ_ONLY)) {
                assertEquals(Transaction.Isolation.READ_ONLY, tx.isolation());
                assertArrayEquals(v("committed"), tx.get(T, k(1)));
                // Every mutating entry point refuses, rather than buffering a
                // write that is then dropped at commit -- which would be a
                // silent data loss dressed as an isolation level.
                assertThrows(RuntimeException.class, () -> tx.put(T, k(2), v("no")));
                assertThrows(RuntimeException.class, () -> tx.remove(T, k(1)));
                assertThrows(RuntimeException.class, () -> tx.removeRange(T, k(0), k(9)));
                // And it commits, because a transaction that wrote nothing has
                // nothing to conflict with.
                tx.commit();
            }
        }
    }

    @Test
    @DisplayName("a snapshot transaction does not see writes committed after it began")
    void aSnapshotDoesNotSeeLaterWrites(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("snap.cryptand"), options())) {
            db.engine().batch().put(T, k(1), v("before")).commit();
            db.commit();
            try (Transaction tx = db.begin(Transaction.Isolation.SNAPSHOT)) {
                assertArrayEquals(v("before"), tx.get(T, k(1)));
                // Someone else commits underneath it.
                db.engine().batch().put(T, k(2), v("after")).commit();
                db.commit();
                assertNull(tx.get(T, k(2)),
                        "a snapshot saw a write committed after it began");
                assertNotNull(tx.snapshot(), "and it holds the snapshot that pins it");
                tx.commit();
            }
        }
    }

    @Test
    @DisplayName("a read-committed transaction does see them, which is the difference")
    void aReadCommittedTransactionSeesLaterWrites(@TempDir Path dir) {
        // The control for the test above. Without it, the snapshot assertion
        // would also pass on an implementation where nothing is ever visible.
        try (Database db = Database.create(dir.resolve("rc.cryptand"), options())) {
            try (Transaction tx = db.begin(Transaction.Isolation.READ_COMMITTED)) {
                db.engine().batch().put(T, k(2), v("after")).commit();
                db.commit();
                assertArrayEquals(v("after"), tx.get(T, k(2)),
                        "read-committed must see a commit that has landed");
                tx.commit();
            }
        }
    }

    @Test
    @DisplayName("a transaction reads its own uncommitted writes")
    void aTransactionReadsItsOwnWrites(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("own.cryptand"), options())) {
            try (Transaction tx = db.begin()) {
                tx.put(T, k(1), v("mine"));
                assertArrayEquals(v("mine"), tx.get(T, k(1)),
                        "a transaction that cannot read its own write is unusable");
                tx.remove(T, k(1));
                assertNull(tx.get(T, k(1)), "and its own delete");
                tx.commit();
            }
        }
    }

    @Test
    @DisplayName("close without commit rolls back, so a leaked transaction loses nothing committed")
    void closeWithoutCommitRollsBack(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("leak.cryptand"), options())) {
            db.engine().batch().put(T, k(1), v("committed")).commit();
            db.commit();
            Transaction tx = db.begin();
            tx.put(T, k(2), v("never committed"));
            tx.close();
            Engine e = db.engine();
            assertArrayEquals(v("committed"), e.get(T, k(1)),
                    "closing a transaction must not disturb committed data");
            assertNull(e.get(T, k(2)));
        }
    }

    @Test
    @DisplayName("a range delete inside a transaction is visible to it and lands on commit")
    void aRangeDeleteInsideATransaction(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("rd.cryptand"), options())) {
            Engine.Batch b = db.engine().batch();
            for (long i = 0; i < 20; i++) {
                b.put(T, k(i), v("v" + i));
            }
            b.commit();
            db.commit();
            try (Transaction tx = db.begin()) {
                tx.removeRange(T, k(5), k(15));
                assertNull(tx.get(T, k(7)), "the range delete is not visible to its own writer");
                assertArrayEquals(v("v4"), tx.get(T, k(4)), "and it did not reach past its start");
                assertArrayEquals(v("v15"), tx.get(T, k(15)), "the upper bound is exclusive");
                tx.commit();
            }
            Engine e = db.engine();
            assertNull(e.get(T, k(7)));
            assertArrayEquals(v("v4"), e.get(T, k(4)));
            assertArrayEquals(v("v15"), e.get(T, k(15)));
        }
    }
}
