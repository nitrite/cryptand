package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

/**
 * The 16-byte value-log pointer — {@code spec/04-segments.md} §6.4.
 *
 * <pre>
 *   u64  vlog_segment_id
 *   u32  offset   -- byte offset, from the START OF THE EXTENT, of the record's
 *                 --   `record_len` varint
 *   u32  len      -- the record's total size, varint included, so a reader
 *                 --   issues exactly one sized read
 * </pre>
 *
 * <p>{@code offset} is extent-relative rather than {@code data_offset}-relative,
 * so resolving a pointer is one addition against the extent's
 * {@code start_page} and needs nothing from the head page.
 *
 * <p>Both are {@code u32}, so a value-log segment MUST NOT exceed 4 GiB. That
 * is not a new constraint: {@code vlog_segment_bytes} is a {@code u32}
 * superblock field.
 */
public final class VlogPointer {
    private final long segmentId;
    private final long offset;
    private final long len;

    public VlogPointer(long segmentId, long offset, long len) {
        this.segmentId = segmentId;
        this.offset = offset;
        this.len = len;
    }

    public long segmentId() {
        return segmentId;
    }

    public long offset() {
        return offset;
    }

    public long len() {
        return len;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof VlogPointer)) {
            return false;
        }
        VlogPointer that = (VlogPointer) o;
        return segmentId == that.segmentId
                && offset == that.offset
                && len == that.len;
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(segmentId, offset, len);
    }

    @Override
    public String toString() {
        return "VlogPointer[" + "segmentId=" + segmentId + ", " + "offset=" + offset + ", " + "len=" + len + "]";
    }

    public static final int BYTES = 16;

    public byte[] encode() {
        return new ByteWriter(BYTES).u64(segmentId).u32((int) offset).u32((int) len).toBytes();
    }

    public static VlogPointer decode(byte[] b) {
        if (b.length != BYTES) {
            throw new CorruptionException("a VLOG pointer is " + BYTES + " bytes, got " + b.length);
        }
        ByteReader r = new ByteReader(b);
        return new VlogPointer(r.u64(), r.u32() & 0xFFFFFFFFL, r.u32() & 0xFFFFFFFFL);
    }
}
