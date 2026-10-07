package org.dizitart.cryptand.container;

import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * The multi-process reader sidecar — {@code spec/13-operations.md} §8, feature
 * bit {@code MULTIPROC_READ}.
 *
 * <p>One writing process, any number of reading processes. Immutability makes
 * reading from another process nearly free: every extent a reader holds is one
 * nothing will modify. The only coordination needed is retention.
 *
 * <pre>
 *   header:  u32 magic, u32 slot_count, u64 writer_pid, u64 writer_heartbeat_ms
 *   slots:   slot_count × { u64 pid, u64 commit_id, u64 heartbeat_ms }
 * </pre>
 *
 * <p><strong>A stale slot is a free slot to a claimer</strong>, and that clause
 * is normative rather than an optimization. When the writing process dies — or
 * was never there, as for two inspection sessions against a file no application
 * has open — nothing reclaims stale slots. They accumulate, and after
 * {@code slot_count} opens every subsequent reader falls to volatile mode, for
 * a reason it cannot see, against a database where volatile mode is not even
 * necessary.
 */
public final class LockSidecar implements AutoCloseable {

    public static final int MAGIC = 0x43524C4B;
    public static final int HEADER_BYTES = 24;
    public static final int SLOT_BYTES = 24;
    public static final int DEFAULT_SLOTS = 16;
    public static final long DEFAULT_HEARTBEAT_MS = 2000;

    /** Why a reader could not claim a slot. §8 rule 4 requires saying which. */
    public enum Volatile {
        NOT_VOLATILE,
        /** The sidecar cannot be written — a read-only filesystem. */
        SIDECAR_UNWRITABLE,
        /** Every slot is held by a live reader. */
        NO_FREE_SLOT
    }

    public static final class Slot {
        private final int index;
        private final long pid;
        private final long commitId;
        private final long heartbeatMs;

        public Slot(int index, long pid, long commitId, long heartbeatMs) {
            this.index = index;
            this.pid = pid;
            this.commitId = commitId;
            this.heartbeatMs = heartbeatMs;
        }

        public int index() {
            return index;
        }

        public long pid() {
            return pid;
        }

        public long commitId() {
            return commitId;
        }

        public long heartbeatMs() {
            return heartbeatMs;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Slot)) {
                return false;
            }
            Slot that = (Slot) o;
            return index == that.index
                    && pid == that.pid
                    && commitId == that.commitId
                    && heartbeatMs == that.heartbeatMs;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(index, pid, commitId, heartbeatMs);
        }

        @Override
        public String toString() {
            return "Slot[" + "index=" + index + ", " + "pid=" + pid + ", " + "commitId=" + commitId + ", " + "heartbeatMs=" + heartbeatMs + "]";
        }
    }

    private final Path path;
    private final FileChannel channel;
    private final int slotCount;
    private final long heartbeatMs;
    private int mySlot = -1;
    private Volatile volatileReason = Volatile.NOT_VOLATILE;

    public LockSidecar(Path databasePath, int slotCount, long heartbeatMs) {
        this.path = databasePath.resolveSibling(databasePath.getFileName() + "-lock");
        this.slotCount = slotCount;
        this.heartbeatMs = heartbeatMs;
        try {
            this.channel = FileChannel.open(this.path, StandardOpenOption.CREATE,
                    StandardOpenOption.READ, StandardOpenOption.WRITE);
            if (channel.size() < HEADER_BYTES + (long) slotCount * SLOT_BYTES) {
                initialize();
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open the lock sidecar " + this.path, e);
        }
    }

    public static LockSidecar of(Path databasePath) {
        return new LockSidecar(databasePath, DEFAULT_SLOTS, DEFAULT_HEARTBEAT_MS);
    }

    public Path path() {
        return path;
    }

    public Volatile volatileReason() {
        return volatileReason;
    }

    private void initialize() {
        byte[] image = new byte[HEADER_BYTES + slotCount * SLOT_BYTES];
        ByteWriter w = new ByteWriter(HEADER_BYTES);
        w.u32(MAGIC).u32(slotCount).u64(0).u64(0);
        System.arraycopy(w.toBytes(), 0, image, 0, HEADER_BYTES);
        write(0, image);
    }

    /** The writing process publishes its pid and refreshes its heartbeat here. */
    public void claimWriter(long pid, long nowMs) {
        withLock(() -> {
            ByteWriter w = new ByteWriter(HEADER_BYTES);
            w.u32(MAGIC).u32(slotCount).u64(pid).u64(nowMs);
            write(0, w.toBytes());
            return null;
        });
    }

    /**
     * Rule 5: a {@code writer_pid} of 0, or a heartbeat older than
     * {@code 3 × reader_heartbeat_ms}, means <strong>no live writer</strong> —
     * nothing will reclaim extents, so a reader's own pin protects nothing, and
     * an implementation should say so.
     */
    public boolean writerIsLive(long nowMs) {
        byte[] header = read(0, HEADER_BYTES);
        ByteReader r = new ByteReader(header);
        r.u32();
        r.u32();
        long pid = r.u64();
        long beat = r.u64();
        return pid != 0 && nowMs - beat <= 3 * heartbeatMs;
    }

    /**
     * Claims a slot, recycling a stale one. Returns the slot index, or
     * {@code -1} for volatile mode with {@link #volatileReason} set.
     */
    public int claimReader(long pid, long commitId, long nowMs) {
        return withLock(() -> {
            for (int i = 0; i < slotCount; i++) {
                Slot s = slot(i);
                boolean freeSlot = s.pid() == 0;
                boolean stale = !freeSlot && nowMs - s.heartbeatMs() > 3 * heartbeatMs;
                if (freeSlot || stale) {
                    writeSlot(i, pid, commitId, nowMs);
                    mySlot = i;
                    volatileReason = Volatile.NOT_VOLATILE;
                    return i;
                }
            }
            volatileReason = Volatile.NO_FREE_SLOT;
            return -1;
        });
    }

    public void heartbeat(long commitId, long nowMs) {
        if (mySlot < 0) {
            return;
        }
        withLock(() -> {
            writeSlot(mySlot, slot(mySlot).pid(), commitId, nowMs);
            return null;
        });
    }

    /**
     * Rule 3: a reader whose slot was reclaimed MUST detect it — its own pid is
     * no longer there — and MUST reopen rather than continue against
     * possibly-freed extents.
     */
    public boolean stillHoldsSlot(long pid) {
        return mySlot >= 0 && slot(mySlot).pid() == pid;
    }

    /** Rule 2: the writer's retention floor is the minimum over every live slot. */
    public long minPinnedCommit(long nowMs, long fallback) {
        long min = fallback;
        for (int i = 0; i < slotCount; i++) {
            Slot s = slot(i);
            if (s.pid() == 0 || nowMs - s.heartbeatMs() > 3 * heartbeatMs) {
                // A stale slot does not pin.
                continue;
            }
            min = Math.min(min, s.commitId());
        }
        return min;
    }

    public List<Slot> slots() {
        List<Slot> out = new ArrayList<>();
        for (int i = 0; i < slotCount; i++) {
            out.add(slot(i));
        }
        return out;
    }

    public void release(long pid) {
        if (mySlot < 0) {
            return;
        }
        withLock(() -> {
            if (slot(mySlot).pid() == pid) {
                writeSlot(mySlot, 0, 0, 0);
            }
            mySlot = -1;
            return null;
        });
    }

    private Slot slot(int index) {
        byte[] b = read(HEADER_BYTES + (long) index * SLOT_BYTES, SLOT_BYTES);
        ByteReader r = new ByteReader(b);
        return new Slot(index, r.u64(), r.u64(), r.u64());
    }

    private void writeSlot(int index, long pid, long commitId, long heartbeat) {
        write(HEADER_BYTES + (long) index * SLOT_BYTES,
                new ByteWriter(SLOT_BYTES).u64(pid).u64(commitId).u64(heartbeat).toBytes());
    }

    private byte[] read(long offset, int len) {
        byte[] b = new byte[len];
        ByteBuffer buf = ByteBuffer.wrap(b);
        try {
            long pos = offset;
            while (buf.hasRemaining()) {
                int n = channel.read(buf, pos);
                if (n < 0) {
                    break;
                }
                pos += n;
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return b;
    }

    private void write(long offset, byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        try {
            long pos = offset;
            while (buf.hasRemaining()) {
                pos += channel.write(buf, pos);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private <T> T withLock(java.util.function.Supplier<T> body) {
        try (FileLock lock = channel.lock()) {
            return body.get();
        } catch (IOException e) {
            volatileReason = Volatile.SIDECAR_UNWRITABLE;
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException ignored) {
            // Nothing a caller can act on.
        }
    }
}
