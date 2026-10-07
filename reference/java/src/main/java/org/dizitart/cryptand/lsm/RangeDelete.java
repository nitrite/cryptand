package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

/**
 * A half-open interval {@code [start, end)} marked deleted at {@code seq} —
 * {@code spec/04-segments.md} §2.5.
 *
 * <p>This is what makes {@code clear()}, {@code drop()} and rollback of a bulk
 * insert O(1) writes rather than O(n) tombstones. A reader MUST apply them: an
 * entry at {@code seq' < seq} whose key falls in the interval is invisible.
 */
public final class RangeDelete {
    private final int treeId;
    private final byte[] start;
    private final byte[] end;
    private final long seq;

    public RangeDelete(int treeId, byte[] start, byte[] end, long seq) {
        this.treeId = treeId;
        this.start = start;
        this.end = end;
        this.seq = seq;
    }

    public int treeId() {
        return treeId;
    }

    public byte[] start() {
        return start;
    }

    public byte[] end() {
        return end;
    }

    public long seq() {
        return seq;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RangeDelete)) {
            return false;
        }
        RangeDelete that = (RangeDelete) o;
        return treeId == that.treeId
                && java.util.Objects.equals(start, that.start)
                && java.util.Objects.equals(end, that.end)
                && seq == that.seq;
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(treeId, start, end, seq);
    }

    @Override
    public String toString() {
        return "RangeDelete[" + "treeId=" + treeId + ", " + "start=" + start + ", " + "end=" + end + ", " + "seq=" + seq + "]";
    }

    /** The value payload of a {@code RANGE_DELETE} cell: {@code uvar end_key_len || end_key}. */
    public byte[] encodePayload() {
        return new ByteWriter(end.length + 4).uvar(end.length).bytes(end).toBytes();
    }

    public static RangeDelete fromCell(BtreePage.Leaf cell) {
        byte[] ik = cell.key();
        ByteReader r = new ByteReader(cell.value());
        int n = r.uvarLength("range delete end key");
        return new RangeDelete(Ikey.treeIdOf(ik), Ikey.ckeOf(ik), r.bytes(n), Ikey.seqOf(ik));
    }

    public boolean covers(int tree, byte[] cke) {
        return tree == treeId
                && BtreePage.memcmp(start, cke) <= 0
                && BtreePage.memcmp(cke, end) < 0;
    }
}
