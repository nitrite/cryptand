package org.dizitart.cryptand.container;

import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import java.util.Set;

/**
 * The multi-process reader sidecar — {@code spec/13-operations.md} §8, feature
 * bit {@code MULTIPROC_READ}. One writing process, any number of reading
 * processes; the only coordination is retention.
 *
 * <pre>
 *   header:  u32 magic, u32 slot_count, u64 writer_pid, u64 writer_heartbeat_ms
 *   slots:   slot_count × { u64 pid, u64 commit_id, u64 heartbeat_ms }
 * </pre>
 *
 * <p>Every slot read-modify-write holds an exclusive lock on the byte at
 * {@link #CLAIM_LOCK_BYTE}: the same byte Rust and Dart lock, which is what
 * makes the claim a cross-language compare-and-swap. A slot belongs to a reader
 * only while both its pid and its commit id are the ones it wrote.
 */
public final class LockSidecar implements AutoCloseable {
    /** {@code "CLK1"} little-endian. */
    public static final int MAGIC = 0x314B4C43;
    public static final int HEADER_BYTES = 24;
    public static final int SLOT_BYTES = 24;
    public static final int DEFAULT_SLOTS = 64;
    public static final long DEFAULT_HEARTBEAT_MS = 2000;
    public static final long STALE_MULTIPLIER = 3;
    public static final long CLAIM_LOCK_BYTE = 1L << 40;

    /**
     * {@code FileChannel.lock} throws when this JVM already holds an
     * overlapping lock, and closing any channel on the file drops the
     * process's POSIX locks; both are serialized here.
     */
    private static final Object JVM_LOCK = new Object();

    /** Rule 4: which of the two ways a reader is volatile. */
    public enum Volatile { SIDECAR_READ_ONLY, SIDECAR_FULL }

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

        public boolean isFree() {
            return pid == 0;
        }

        public boolean isStale(long nowMs, long intervalMs) {
            return !isFree() && nowMs - heartbeatMs > STALE_MULTIPLIER * intervalMs;
        }

        @Override
        public String toString() {
            return "Slot{index=" + index + ", pid=" + pid + ", commitId=" + commitId + "}";
        }
    }

    private final Path path;
    private final FileChannel channel;
    private final long intervalMs;
    private final boolean readOnly;
    private int slotCount;

    private LockSidecar(Path path, FileChannel channel, long intervalMs, boolean readOnly) {
        this.path = path;
        this.channel = channel;
        this.intervalMs = intervalMs;
        this.readOnly = readOnly;
    }

    public static Path pathFor(Path database) {
        return database.resolveSibling(database.getFileName() + "-lock");
    }

    public static long pid() {
        return ProcessHandle.current().pid();
    }

    /** The writer: keep live readers' slots, (re)create when absent or invalid, publish the pid. */
    public static LockSidecar openWriter(Path database, long intervalMs) {
        LockSidecar s = openRw(database, intervalMs, pid());
        s.withLock(() -> {
            s.write(8, new ByteWriter(16).u64(pid()).u64(System.currentTimeMillis()).toBytes());
            return null;
        });
        return s;
    }

    /**
     * A reader: read-write, creating it with {@code writer_pid} 0 when absent;
     * read-only when it cannot be written; {@code null} when it cannot be read.
     */
    public static LockSidecar openReader(Path database, long intervalMs) {
        try {
            return openRw(database, intervalMs, 0);
        } catch (UncheckedIOException e) {
            try {
                FileChannel ch = FileChannel.open(pathFor(database), Set.of(StandardOpenOption.READ,
                        LinkOption.NOFOLLOW_LINKS));
                LockSidecar s = new LockSidecar(pathFor(database), ch, intervalMs, true);
                int n = s.readHeader();
                if (n <= 0) {
                    s.close();
                    return null;
                }
                s.slotCount = n;
                return s;
            } catch (IOException | UncheckedIOException x) {
                return null;
            }
        }
    }

    private static LockSidecar openRw(Path database, long intervalMs, long writerPid) {
        Path p = pathFor(database);
        FileChannel ch;
        try {
            // PLAN 4.7: the sidecar path is predictable; never follow a planted symlink.
            ch = FileChannel.open(p, Set.of(StandardOpenOption.CREATE, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS), PageFile.ownerOnly(p));
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open the lock sidecar " + p, e);
        }
        LockSidecar s = new LockSidecar(p, ch, intervalMs, false);
        try {
            s.slotCount = s.withLock(() -> {
                int n = s.readHeader();
                if (n > 0) {
                    return n;
                }
                byte[] image = new byte[HEADER_BYTES + DEFAULT_SLOTS * SLOT_BYTES];
                System.arraycopy(new ByteWriter(HEADER_BYTES).u32(MAGIC).u32(DEFAULT_SLOTS)
                        .u64(writerPid).u64(System.currentTimeMillis()).toBytes(), 0, image, 0, HEADER_BYTES);
                try {
                    s.channel.truncate(0);
                    s.write(0, image);
                    s.channel.force(false);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                return DEFAULT_SLOTS;
            });
        } catch (RuntimeException e) {
            s.close();
            throw e;
        }
        return s;
    }

    /** The slot count of a valid header whose slots are all present, else 0. */
    private int readHeader() {
        try {
            if (channel.size() < HEADER_BYTES) {
                return 0;
            }
            ByteReader r = new ByteReader(read(0, HEADER_BYTES));
            int magic = (int) r.u32();
            int n = (int) r.u32();
            boolean ok = magic == MAGIC && n > 0 && channel.size() >= HEADER_BYTES + (long) n * SLOT_BYTES;
            return ok ? n : 0;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Path path() {
        return path;
    }

    public boolean readOnly() {
        return readOnly;
    }

    public int slotCount() {
        return slotCount;
    }

    public long writerPid() {
        return new ByteReader(read(8, 8)).u64();
    }

    /** Rule 5: the writer refreshes on the schedule it asks of readers. */
    public void refreshWriter(long nowMs) {
        write(16, new ByteWriter(8).u64(nowMs).toBytes());
    }

    /** Writer close: {@code writer_pid} 0 is "no live writer". */
    public void clearWriter() {
        write(8, new ByteWriter(8).u64(0).toBytes());
    }

    /** Rule 5: pid 0 or an aged writer heartbeat is no live writer. */
    public boolean writerAlive(long nowMs) {
        ByteReader r = new ByteReader(read(8, 16));
        long wpid = r.u64();
        long beat = r.u64();
        return wpid != 0 && nowMs - beat <= STALE_MULTIPLIER * intervalMs;
    }

    /** Rule 1: claim a free or stale slot; {@code null} when none is (or read-only). */
    public Slot claim(long commitId, long nowMs) {
        if (readOnly) {
            return null;
        }
        return withLock(() -> {
            for (int i = 0; i < slotCount; i++) {
                Slot s = slot(i);
                if (s.isFree() || s.isStale(nowMs, intervalMs)) {
                    writeSlot(i, pid(), commitId, nowMs);
                    return new Slot(i, pid(), commitId, nowMs);
                }
            }
            return null;
        });
    }

    private boolean owns(Slot s) {
        Slot cur = slot(s.index());
        return cur.pid() == s.pid() && cur.commitId() == s.commitId();
    }

    /** Moves a held slot to a newer superblock; {@code null} if it was reclaimed. */
    public Slot repin(Slot s, long commitId, long nowMs) {
        return withLock(() -> {
            if (!owns(s)) {
                return null;
            }
            writeSlot(s.index(), s.pid(), commitId, nowMs);
            return new Slot(s.index(), s.pid(), commitId, nowMs);
        });
    }

    /** Rule 1's refresh, rule 3's detection: {@code false} means reclaimed, reopen. */
    public boolean heartbeat(Slot s, long nowMs) {
        return withLock(() -> {
            if (!owns(s)) {
                return false;
            }
            writeSlot(s.index(), s.pid(), s.commitId(), nowMs);
            return true;
        });
    }

    public void release(Slot s) {
        withLock(() -> {
            if (owns(s)) {
                writeSlot(s.index(), 0, 0, 0);
            }
            return null;
        });
    }

    /** Rules 2 and 3 for the writer: reclaim stale slots, return the lowest live pin. */
    public OptionalLong reclaimAndMinPinned(long nowMs) {
        return withLock(() -> {
            long min = Long.MAX_VALUE;
            for (int i = 0; i < slotCount; i++) {
                Slot s = slot(i);
                if (s.isStale(nowMs, intervalMs)) {
                    writeSlot(i, 0, 0, 0);
                } else if (!s.isFree()) {
                    min = Math.min(min, s.commitId());
                }
            }
            return min == Long.MAX_VALUE ? OptionalLong.empty() : OptionalLong.of(min);
        });
    }

    public List<Slot> slots() {
        List<Slot> out = new ArrayList<>();
        for (int i = 0; i < slotCount; i++) {
            out.add(slot(i));
        }
        return out;
    }

    private Slot slot(int index) {
        ByteReader r = new ByteReader(read(HEADER_BYTES + (long) index * SLOT_BYTES, SLOT_BYTES));
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
                    throw new IOException("lock sidecar truncated at " + pos);
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
        synchronized (JVM_LOCK) {
            try (FileLock lock = channel.lock(CLAIM_LOCK_BYTE, 1, false)) {
                return body.get();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    @Override
    public void close() {
        synchronized (JVM_LOCK) {
            try {
                channel.close();
            } catch (IOException ignored) {
                // Nothing a caller can act on.
            }
        }
    }
}
