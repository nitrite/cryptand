package org.dizitart.cryptand.container;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PLAN M2.1 — the fault-injecting layer under {@link PageFile}; Java's port of
 * Rust's {@code src/fault.rs}. A test arms a path with a {@link Plan}; every
 * write and fsync on that path is counted and may fail. A write is remembered
 * with the bytes it replaced until the next successful fsync, so
 * {@link #crash} can model a power cut: undo every un-fsynced write, then
 * replay a random subset in order, some torn at a 512-byte boundary.
 */
public final class Faults implements PageFile.Hook {

    public static final class Plan {
        /** Power is lost at this write (0-based): it and all later I/O fail. */
        public long crashAtWrite = -1;
        /** This fsync fails with EIO; what it covered stays un-fsynced. */
        public long eioAtSync = -1;
        /** This write fails with ENOSPC, writing nothing. */
        public long enospcAtWrite = -1;
        /** Every fsync reports success and persists nothing: the control. */
        public boolean syncLies;

        @Override
        public String toString() {
            return "Plan{crash=" + crashAtWrite + " eio=" + eioAtSync + " enospc=" + enospcAtWrite
                    + (syncLies ? " syncLies" : "") + "}";
        }
    }

    private static final class Pending {
        final long offset;
        final byte[] old;
        final byte[] fresh;

        Pending(long offset, byte[] old, byte[] fresh) {
            this.offset = offset;
            this.old = old;
            this.fresh = fresh;
        }
    }

    private static final class State {
        final Plan plan;
        long writes;
        long syncs;
        boolean dead;
        final List<Pending> pending = new ArrayList<>();

        State(Plan plan) {
            this.plan = plan;
        }
    }

    private static final Faults INSTANCE = new Faults();
    private static final Map<Path, State> ARMED = new ConcurrentHashMap<>();

    private Faults() {
    }

    private static Path key(Path p) {
        return p.toAbsolutePath().normalize();
    }

    public static void arm(Path path, Plan plan) {
        ARMED.put(key(path), new State(plan));
        PageFile.hook = INSTANCE;
    }

    public static void disarm(Path path) {
        ARMED.remove(key(path));
    }

    /** {writes, syncs} since arming. */
    public static long[] counts(Path path) {
        State s = ARMED.get(key(path));
        if (s == null) {
            return new long[] {0, 0};
        }
        synchronized (s) {
            return new long[] {s.writes, s.syncs};
        }
    }

    private static IOException dead() {
        return new IOException("fault: power lost");
    }

    @Override
    public void beforeWrite(PageFile f, long offset, byte[] src, int srcOff, int len) throws IOException {
        State s = ARMED.get(key(f.path()));
        if (s == null) {
            return;
        }
        synchronized (s) {
            if (s.dead) {
                throw dead();
            }
            long n = s.writes++;
            if (s.plan.crashAtWrite == n) {
                s.dead = true;
                throw dead();
            }
            if (s.plan.enospcAtWrite == n) {
                throw new IOException("fault: ENOSPC (No space left on device)");
            }
            byte[] old = new byte[len];
            long size = f.size();
            if (offset < size) {
                f.readFully(offset, old, 0, (int) Math.min(len, size - offset));
            }
            byte[] fresh = new byte[len];
            System.arraycopy(src, srcOff, fresh, 0, len);
            s.pending.add(new Pending(offset, old, fresh));
        }
    }

    @Override
    public void beforeSync(PageFile f) throws IOException {
        State s = ARMED.get(key(f.path()));
        if (s == null) {
            return;
        }
        synchronized (s) {
            if (s.dead) {
                throw dead();
            }
            long n = s.syncs++;
            if (s.plan.eioAtSync == n) {
                throw new IOException("fault: EIO (Input/output error)");
            }
            if (!s.plan.syncLies) {
                s.pending.clear();
            }
        }
    }

    @Override
    public void beforeTruncate(PageFile f) throws IOException {
        State s = ARMED.get(key(f.path()));
        if (s != null && s.dead) {
            throw dead();
        }
    }

    /**
     * Disarms {@code path} and rewrites the file as a power cut now could have
     * left it. Call after every handle on the file is closed. Returns the number
     * of un-fsynced writes dropped.
     */
    public static int crash(Path path, long seed) throws IOException {
        State s = ARMED.remove(key(path));
        if (s == null) {
            return 0;
        }
        long[] rng = {seed ^ 0x9e3779b97f4a7c15L};
        int dropped = 0;
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.WRITE)) {
            for (int i = s.pending.size() - 1; i >= 0; i--) {
                Pending p = s.pending.get(i);
                writeAt(ch, p.old, p.old.length, p.offset);
            }
            for (Pending p : s.pending) {
                long r = splitmix(rng);
                if ((r & 1) == 0) {
                    dropped++;
                    continue;
                }
                int blocks = p.fresh.length / 512;
                int keep = (r & 6) == 0 && blocks > 1
                        ? (int) (1 + Long.remainderUnsigned(r >>> 8, blocks - 1)) * 512
                        : p.fresh.length;
                writeAt(ch, p.fresh, keep, p.offset);
            }
            ch.force(true);
        }
        return dropped;
    }

    private static void writeAt(FileChannel ch, byte[] b, int len, long pos) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(b, 0, len);
        while (buf.hasRemaining()) {
            pos += ch.write(buf, pos);
        }
    }

    public static long splitmix(long[] s) {
        s[0] += 0x9e3779b97f4a7c15L;
        long z = s[0];
        z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
        z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
        return z ^ (z >>> 31);
    }
}
