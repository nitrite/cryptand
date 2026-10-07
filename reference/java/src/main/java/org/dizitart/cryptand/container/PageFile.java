package org.dizitart.cryptand.container;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.LockedException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * The file underneath everything — positional reads and writes, the durability
 * barriers of {@code spec/10-transactions.md} §7, and the writer lock of
 * {@code spec/01-container.md} §10.
 *
 * <p><strong>What this class does not do is claim a durability it did not
 * reach.</strong> §7's second MUST is the load-bearing one, because the failure
 * is silent: a file whose {@code durability_achieved} says {@code full} when
 * only a page-cache flush happened looks perfect until the power goes out.
 * {@link #achieved()} therefore reports what {@link #sync()} actually performs,
 * which on the JDK is {@code FileChannel.force} — {@code fdatasync} on Linux and
 * {@code fsync} on macOS. The JDK exposes no {@code F_FULLFSYNC}, so requesting
 * {@code full} here yields {@code sync}, and that is <em>correct behaviour</em>
 * rather than a conformance failure.
 */
public final class PageFile implements AutoCloseable {

    private final Path path;
    private final FileChannel channel;
    private final boolean readOnly;
    private final int requestedDurability;
    private final int achievedDurability;
    private static final long LOCK_BYTE = 1L << 62;
    private FileLock writerLock;

    public PageFile(Path path, boolean readOnly, int requestedDurability) {
        this.path = path;
        this.readOnly = readOnly;
        this.requestedDurability = requestedDurability;
        // Rule 2 of §7: record what was performed, never what was requested.
        // The JDK's strongest portable flush is FileChannel.force, which is
        // `sync`; there is no device-level flush to reach for.
        this.achievedDurability = Math.min(requestedDurability, Superblock.Durability.SYNC);
        try {
            this.channel = readOnly
                    ? FileChannel.open(path, StandardOpenOption.READ)
                    : FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE,
                            StandardOpenOption.CREATE);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open " + path, e);
        }
        if (!readOnly) {
            acquireWriterLock();
        }
    }

    /**
     * §10: one writing process per database. A second writer MUST fail with a
     * clear error and MUST NOT fall back to opening anyway. The lock is the
     * single byte at 2^62 (F-067), the byte Rust and Dart take, so writers in
     * any two languages exclude each other and a Windows reader's reads are not
     * blocked by a whole-file lock.
     */
    private void acquireWriterLock() {
        try {
            writerLock = channel.tryLock(LOCK_BYTE, 1, false);
        } catch (OverlappingFileLockException e) {
            writerLock = null;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot lock " + path, e);
        }
        if (writerLock == null) {
            closeQuietly();
            throw new LockedException(path + " is locked by another process; "
                    + "only one writing process per database is supported in format version 1.0");
        }
    }

    public Path path() {
        return path;
    }

    public boolean readOnly() {
        return readOnly;
    }

    public int requested() {
        return requestedDurability;
    }

    /** What {@link #sync()} actually performs — the value for {@code durability_achieved}. */
    public int achieved() {
        return achievedDurability;
    }

    public long size() {
        try {
            return channel.size();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void readFully(long offset, byte[] dst, int dstOff, int len) {
        ByteBuffer b = ByteBuffer.wrap(dst, dstOff, len);
        long pos = offset;
        try {
            while (b.hasRemaining()) {
                int n = channel.read(b, pos);
                if (n < 0) {
                    throw new CorruptionException("short read at offset " + pos + " of " + path
                            + ": wanted " + len + " bytes, file ends at " + channel.size());
                }
                pos += n;
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void write(long offset, byte[] src, int srcOff, int len) {
        ByteBuffer b = ByteBuffer.wrap(src, srcOff, len);
        long pos = offset;
        try {
            while (b.hasRemaining()) {
                pos += channel.write(b, pos);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void write(long offset, byte[] src) {
        write(offset, src, 0, src.length);
    }

    /**
     * The durability barrier. {@code none} and {@code os} do nothing — they
     * never risk structural corruption, only recent batches, which is a
     * property of append-only plus copy-on-write and is worth stating to
     * applications because it is not true of every embedded store.
     */
    public void sync() {
        if (achievedDurability < Superblock.Durability.SYNC) {
            return;
        }
        try {
            channel.force(false);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Cuts the file, forcing what was written first whatever the durability
     * mode: the superblock that names the new end has to reach the device
     * before the pages past it leave.
     */
    public void truncate(long bytes) {
        try {
            if (channel.size() > bytes) {
                channel.force(false);
                channel.truncate(bytes);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void close() {
        try {
            if (writerLock != null && writerLock.isValid()) {
                writerLock.release();
            }
        } catch (IOException ignored) {
            // Releasing a lock on a channel that is already going away is not a
            // condition a caller can act on.
        }
        closeQuietly();
    }

    private void closeQuietly() {
        try {
            channel.close();
        } catch (IOException ignored) {
            // as above
        }
    }
}
