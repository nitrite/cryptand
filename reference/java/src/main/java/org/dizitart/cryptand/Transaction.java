package org.dizitart.cryptand;

import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A transaction over the engine — {@code spec/10-transactions.md} §3.
 *
 * <p>Writes are buffered and sequenced at commit, so <strong>rollback is free
 * and leaves no trace</strong> — unlike the undo-log approach all three SDKs
 * use above the store today, which writes and then reverses. Value-log records
 * written by a transaction that then aborts are garbage, not corruption:
 * nothing points at them, and GC reclaims them.
 *
 * <p>Conflict detection compares this transaction's written key set against the
 * keys written by batches sequenced in {@code (start_seq, commit_seq)}. On
 * conflict the transaction aborts; the format deliberately does not define
 * automatic retry, because whether a retry is safe depends on what the caller
 * was doing, and an engine that retries silently turns a lost update into a
 * duplicated one.
 */
public final class Transaction implements AutoCloseable {

    public enum Isolation {
        /** Reads at the start snapshot; writes are sequenced at commit. The default. */
        SNAPSHOT,
        /** Each statement takes a fresh snapshot. */
        READ_COMMITTED,
        /** Additionally records the read set and validates it at commit. */
        SERIALIZABLE,
        /** Pins a snapshot; cannot conflict, never blocks and is never blocked. */
        READ_ONLY
    }

    private record Staged(int treeId, byte[] key, byte[] value, int op, Long expiry, byte[] rangeEnd) {
    }

    private final Database db;
    private final Engine engine;
    private final Isolation isolation;
    private final Snapshot start;
    private final List<Staged> staged = new ArrayList<>();
    private final Set<String> writeSet = new HashSet<>();
    private final Set<String> readSet = new HashSet<>();
    private boolean finished;

    Transaction(Database db, Isolation isolation) {
        this.db = db;
        this.engine = db.engine();
        this.isolation = isolation;
        this.start = engine.pin();
    }

    public Isolation isolation() {
        return isolation;
    }

    public Snapshot snapshot() {
        return start;
    }

    private long readSeq() {
        return isolation == Isolation.READ_COMMITTED ? engine.visibleSeq() : start.seq();
    }

    public byte[] get(int treeId, byte[] cke) {
        String k = fingerprint(treeId, cke);
        if (isolation == Isolation.SERIALIZABLE) {
            readSet.add(k);
        }
        // Newest first, so a later write wins over an earlier one -- and so a
        // point write after a range delete resurrects its key, which is what
        // the same two operations do when the batch reaches the engine.
        for (int i = staged.size() - 1; i >= 0; i--) {
            Staged s = staged.get(i);
            if (s.treeId() != treeId) {
                continue;
            }
            if (s.op() == BtreePage.Op.RANGE_DELETE) {
                // A range delete this transaction buffered covers this key.
                // Without this branch a transaction could not see its own
                // range delete: `removeRange` then `get` inside the range
                // returned the *old value*, so application code decided the
                // row still existed and acted on it. A point `remove` was
                // visible and a range delete was not, which is the worst
                // shape -- the difference is invisible until it matters.
                if (BtreePage.memcmp(s.key(), cke) <= 0
                        && BtreePage.memcmp(cke, s.rangeEnd()) < 0) {
                    return null;
                }
                continue;
            }
            if (BtreePage.memcmp(s.key(), cke) == 0) {
                return s.op() == BtreePage.Op.DELETE ? null : s.value();
            }
        }
        return engine.get(treeId, cke, readSeq(), engine.options().clock.getAsLong());
    }

    public Transaction put(int treeId, byte[] cke, byte[] value) {
        requireWritable();
        staged.add(new Staged(treeId, cke, value, BtreePage.Op.PUT, null, null));
        writeSet.add(fingerprint(treeId, cke));
        return this;
    }

    public Transaction remove(int treeId, byte[] cke) {
        requireWritable();
        staged.add(new Staged(treeId, cke, new byte[0], BtreePage.Op.DELETE, null, null));
        writeSet.add(fingerprint(treeId, cke));
        return this;
    }

    public Transaction removeRange(int treeId, byte[] startCke, byte[] endCke) {
        requireWritable();
        staged.add(new Staged(treeId, startCke, new byte[0], BtreePage.Op.RANGE_DELETE, null, endCke));
        return this;
    }

    /**
     * A savepoint. Discarding buffered entries after a mark costs nothing,
     * because nothing durable is written before sequencing.
     */
    public int savepoint() {
        return staged.size();
    }

    public void rollbackTo(int savepoint) {
        while (staged.size() > savepoint) {
            staged.remove(staged.size() - 1);
        }
    }

    public long commit() {
        // Not `requireWritable`: committing is not writing. A read-only
        // transaction has nothing staged and commits trivially, and refusing
        // it forced callers to remember which isolation level needs `rollback`
        // instead of `commit` -- a distinction no other implementation makes.
        // `detectConflicts` already has a READ_ONLY early return, which was
        // unreachable while this line threw first.
        if (finished) {
            throw new IllegalStateException("the transaction is already committed or rolled back");
        }
        finished = true;
        try {
            if (staged.isEmpty()) {
                return start.seq();
            }
            detectConflicts();
            Engine.Batch b = engine.batch();
            for (Staged s : staged) {
                switch (s.op()) {
                    case BtreePage.Op.PUT -> b.put(s.treeId(), s.key(), s.value());
                    case BtreePage.Op.DELETE -> b.remove(s.treeId(), s.key());
                    case BtreePage.Op.RANGE_DELETE -> b.removeRange(s.treeId(), s.key(), s.rangeEnd());
                    default -> throw new IllegalStateException("unreachable op " + s.op());
                }
            }
            return b.commit();
        } finally {
            engine.unpin(start);
        }
    }

    /**
     * Compares the written key set — and, at {@code SERIALIZABLE}, the read set
     * too — against what became visible after this transaction began.
     *
     * <p>The comparison is on keys rather than on values: a write-write
     * conflict is a conflict whatever the values were, and the engine has no
     * way to know the two writers meant the same thing.
     */
    private void detectConflicts() {
        if (isolation == Isolation.READ_ONLY) {
            return;
        }
        long visible = engine.visibleSeq();
        if (visible <= start.seq()) {
            return;
        }
        Set<String> check = new HashSet<>(writeSet);
        if (isolation == Isolation.SERIALIZABLE) {
            check.addAll(readSet);
        }
        for (String k : check) {
            int sep = k.indexOf(':');
            int treeId = Integer.parseInt(k.substring(0, sep));
            byte[] cke = java.util.HexFormat.of().parseHex(k.substring(sep + 1));
            BtreePage.Leaf now = engine.newestVersion(treeId, cke, visible);
            if (now != null && Ikey.seqOf(now.key()) > start.seq()) {
                throw new ConflictException("transaction conflict on tree " + treeId
                        + ": the key was written at seq " + Ikey.seqOf(now.key())
                        + ", after this transaction began at " + start.seq());
            }
        }
    }

    public void rollback() {
        if (!finished) {
            finished = true;
            staged.clear();
            engine.unpin(start);
        }
    }

    @Override
    public void close() {
        rollback();
    }

    private void requireWritable() {
        if (finished) {
            throw new IllegalStateException("the transaction is already committed or rolled back");
        }
        if (isolation == Isolation.READ_ONLY) {
            throw new InvalidArgumentException("a read-only transaction cannot write");
        }
    }

    private static String fingerprint(int treeId, byte[] cke) {
        return treeId + ":" + java.util.HexFormat.of().formatHex(cke);
    }
}
