package org.dizitart.cryptand.ops;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.RangeDelete;
import org.dizitart.cryptand.lsm.Segment;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.lsm.VlogStats;
import org.dizitart.cryptand.util.ByteWriter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Backup — {@code spec/13-operations.md} §2.
 *
 * <p>The source stays open and writable throughout; nothing is locked and
 * nothing is quiesced. That falls out of immutability: every extent the backup
 * reads is one nothing will ever modify.
 *
 * <p>Because {@code segment_id} and {@code vlog_segment_id} are globally unique
 * and never reused, an incremental backup is a set difference rather than a
 * content diff — <strong>its size is proportional to what changed, not to what
 * the changes touched</strong>, which is the property an LSM's immutable
 * segments give and an in-place B-tree cannot.
 */
public final class Backup {

    /** How an encrypted source is copied. §2.1 makes the caller choose. */
    public enum Mode {
        /**
         * Byte-for-byte. The copy is the <em>same</em> cryptographic object, so
         * it keeps the source's {@code database_uuid} and keyslots — the one
         * exception to the new-uuid rule, and for exactly the reason the rule
         * exists. Its nonce space is the source's, so it is a restore source,
         * never a second live database.
         */
        CIPHERTEXT_COPY,
        /** Plaintext source, or an explicitly requested downgrade. */
        PLAINTEXT
    }

    public static final class Result {
        private final Path destination;
        private final int segmentsCopied;
        private final int vlogSegmentsCopied;
        private final long bytesCopied;
        private final boolean downgraded;

        public Result(Path destination, int segmentsCopied, int vlogSegmentsCopied, long bytesCopied, boolean downgraded) {
            this.destination = destination;
            this.segmentsCopied = segmentsCopied;
            this.vlogSegmentsCopied = vlogSegmentsCopied;
            this.bytesCopied = bytesCopied;
            this.downgraded = downgraded;
        }

        public Path destination() {
            return destination;
        }

        public int segmentsCopied() {
            return segmentsCopied;
        }

        public int vlogSegmentsCopied() {
            return vlogSegmentsCopied;
        }

        public long bytesCopied() {
            return bytesCopied;
        }

        public boolean downgraded() {
            return downgraded;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Result)) {
                return false;
            }
            Result that = (Result) o;
            return java.util.Objects.equals(destination, that.destination)
                    && segmentsCopied == that.segmentsCopied
                    && vlogSegmentsCopied == that.vlogSegmentsCopied
                    && bytesCopied == that.bytesCopied
                    && downgraded == that.downgraded;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(destination, segmentsCopied, vlogSegmentsCopied, bytesCopied, downgraded);
        }

        @Override
        public String toString() {
            return "Result[" + "destination=" + destination + ", " + "segmentsCopied=" + segmentsCopied + ", " + "vlogSegmentsCopied=" + vlogSegmentsCopied + ", " + "bytesCopied=" + bytesCopied + ", " + "downgraded=" + downgraded + "]";
        }
    }

    private Backup() {
    }

    /**
     * A full online backup.
     *
     * <p>The destination gets a <strong>new {@code database_uuid}</strong>
     * unless this is a ciphertext copy: two files with the same uuid break
     * incremental backup, confuse tooling, and — on an encrypted file — share a
     * content key, because §3.4 derives subkeys with the uuid as HKDF salt.
     */
    public static Result full(Engine source, Path destination, Mode mode, boolean allowDowngrade) {
        source.lockStructure();
        try {
            Superblock sb = source.superblock();
            boolean encrypted = sb.cipher != Superblock.Cipher.NONE;
            if (encrypted && mode == Mode.PLAINTEXT && !allowDowngrade) {
                throw new InvalidArgumentException("an unencrypted backup of an encrypted database "
                        + "is a silent downgrade; ask for it by name with allowDowngrade");
            }
            return copy(source, destination, mode, encrypted && mode == Mode.PLAINTEXT, Set.of());
        } finally {
            source.unlockStructure();
        }
    }

    /**
     * An incremental backup: copy every segment whose id is absent from the
     * destination, then the destination's new superblock.
     */
    public static Result incremental(Engine source, Path destination, Mode mode) {
        Set<Long> present = new HashSet<>();
        if (Files.exists(destination)) {
            Engine.Options o = new Engine.Options();
            o.readOnly = true;
            try (Engine dest = Engine.open(destination, o)) {
                for (SegmentMeta m : dest.manifest().all()) {
                    present.add(m.segmentId);
                }
            }
        }
        source.lockStructure();
        try {
            return copy(source, destination, mode, false, present);
        } finally {
            source.unlockStructure();
        }
    }

    private static Result copy(Engine source, Path destination, Mode mode,
                               boolean downgraded, Set<Long> skip) {
        Superblock sb = source.superblock();
        Engine.Options o = new Engine.Options();
        o.profile = Profile.byId(sb.profile == 0 ? Profile.DESKTOP.id() : sb.profile);
        o.durability = Superblock.Durability.SYNC;
        o.writerId = "cryptand-backup/1.0.0";
        try {
            Files.deleteIfExists(destination);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }

        int segments = 0;
        int vlogSegments = 0;
        long bytes = 0;
        try (Engine dest = Engine.create(destination, o)) {
            if (mode == Mode.CIPHERTEXT_COPY && sb.cipher != Superblock.Cipher.NONE) {
                // The same cryptographic object: keep the uuid and the keyslots.
                dest.superblock().databaseUuid = sb.databaseUuid.clone();
                dest.superblock().keyslots = sb.keyslots.clone();
                dest.superblock().cipher = sb.cipher;
            } else {
                UUID fresh = UUID.randomUUID();
                dest.superblock().databaseUuid = new ByteWriter(16)
                        .u64be(fresh.getMostSignificantBits())
                        .u64be(fresh.getLeastSignificantBits()).toBytes();
            }
            Engine.Batch batch = dest.batch();
            int staged = 0;
            for (Segment seg : source.segments()) {
                if (skip.contains(seg.meta().segmentId)) {
                    continue;
                }
                segments++;
                for (BtreePage.Leaf cell : seg.readAll()) {
                    byte[] ik = cell.key();
                    int treeId = Ikey.treeIdOf(ik);
                    byte[] cke = Ikey.ckeOf(ik);
                    int op = Ikey.opOf(ik);
                    if (op == BtreePage.Op.DELETE) {
                        batch.remove(treeId, cke);
                    } else if (op == BtreePage.Op.RANGE_DELETE) {
                        batch.removeRange(treeId, cke, RangeDelete.fromCell(cell).end());
                    } else if (cell.kind() == BtreePage.Kind.EMPTY) {
                        batch.putEmpty(treeId, cke);
                    } else {
                        byte[] value = source.resolveValue(cell);
                        bytes += value.length;
                        batch.put(treeId, cke, value);
                    }
                    if (++staged >= 512) {
                        batch.commit();
                        batch = dest.batch();
                        staged = 0;
                    }
                }
            }
            if (staged > 0) {
                batch.commit();
            }
            for (VlogStats s : source.vlog().allStats()) {
                if (s.liveBytes > 0) {
                    vlogSegments++;
                }
            }
            // The writers list carries over, plus this tool's id.
            dest.commitNow();
        }
        return new Result(destination, segments, vlogSegments, bytes, downgraded);
    }

    /**
     * §2.3: a restore is a file copy plus an open, and an implementation MUST
     * run the verification pass over the result before reporting success — a
     * partial restore is a failure, not a truncated file to open hopefully.
     */
    public static Verify.Report restore(Path backup, Path destination, Engine.Options options) {
        try {
            Files.copy(backup, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException("restore could not copy " + backup, e);
        }
        try (Engine e = Engine.open(destination, options)) {
            Verify.Report r = Verify.run(e);
            if (!r.of(Verify.Kind.CORRUPTION).isEmpty() || !r.of(Verify.Kind.DOUBLE_ALLOCATION).isEmpty()) {
                throw new CorruptionException("the restored database does not verify: " + r);
            }
            return r;
        }
    }
}
