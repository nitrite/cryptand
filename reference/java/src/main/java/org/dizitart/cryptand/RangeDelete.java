package org.dizitart.cryptand;

/**
 * A half-open interval {@code [start, end)} marked deleted at {@code seq} —
 * {@code spec/04-segments.md} §2.5.
 *
 * <p>This is what makes {@code clear()}, {@code drop()} and rollback of a bulk
 * insert O(1) writes rather than O(n) tombstones. A reader MUST apply them: an
 * entry at {@code seq' < seq} whose key falls in the interval is invisible.
 */
public record RangeDelete(int treeId, byte[] start, byte[] end, long seq) {

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
