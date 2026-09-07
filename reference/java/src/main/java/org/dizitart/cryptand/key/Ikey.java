package org.dizitart.cryptand.key;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.lsm.BlockedBloom;

import java.util.Arrays;

/**
 * The internal key — {@code spec/04-segments.md} §1.
 *
 * <pre>
 *   internal_key := u32be(tree_id) || CKE(key) || u64be(seq XOR 0xFFFF_FFFF_FFFF_FFFF) || u8(op)
 * </pre>
 *
 * <p>Every part of that is load-bearing. {@code tree_id} first makes a tree's
 * entries one contiguous range of the global key space, so a scan of one tree
 * never steps through another's. {@code CKE(key)} is prefix-free by
 * construction, so the concatenation is unambiguous and order-preserving.
 * {@code seq} is <strong>inverted</strong>, so the newest version of a key sorts
 * first and a read at snapshot <em>S</em> seeks the key and walks forward to the
 * first entry with {@code seq <= S}.
 */
public final class Ikey {

    private Ikey() {
    }

    /** {@code u32be(tree_id) || CKE(key)} — the user key, which is what the filter and level order use. */
    public static byte[] userKey(int treeId, byte[] cke) {
        return BlockedBloom.userKey(treeId, cke);
    }

    public static byte[] of(int treeId, byte[] cke, long seq, int op) {
        byte[] out = new byte[4 + cke.length + 9];
        out[0] = (byte) (treeId >>> 24);
        out[1] = (byte) (treeId >>> 16);
        out[2] = (byte) (treeId >>> 8);
        out[3] = (byte) treeId;
        System.arraycopy(cke, 0, out, 4, cke.length);
        long inv = ~seq;
        int p = 4 + cke.length;
        for (int i = 7; i >= 0; i--) {
            out[p++] = (byte) (inv >>> (8 * i));
        }
        out[p] = (byte) op;
        return out;
    }

    /** The {@code u32be(tree_id) || CKE(key)} prefix of a whole internal key. */
    public static byte[] userKeyOf(byte[] ik) {
        checkLength(ik);
        return Arrays.copyOf(ik, ik.length - 9);
    }

    public static int treeIdOf(byte[] ik) {
        checkLength(ik);
        return treeIdOfUserKey(ik);
    }

    /**
     * The tree id of a <em>user</em> key — {@code u32be(tree_id) || CKE(key)},
     * which is only four bytes plus the key and so does not satisfy an internal
     * key's length check.
     */
    public static int treeIdOfUserKey(byte[] uk) {
        if (uk.length < 4) {
            throw new CorruptionException("user key is " + uk.length + " bytes; the tree id alone is 4");
        }
        return ((uk[0] & 0xFF) << 24) | ((uk[1] & 0xFF) << 16) | ((uk[2] & 0xFF) << 8) | (uk[3] & 0xFF);
    }

    public static byte[] ckeOf(byte[] ik) {
        checkLength(ik);
        return Arrays.copyOfRange(ik, 4, ik.length - 9);
    }

    public static long seqOf(byte[] ik) {
        checkLength(ik);
        int p = ik.length - 9;
        long inv = 0;
        for (int i = 0; i < 8; i++) {
            inv = (inv << 8) | (ik[p + i] & 0xFF);
        }
        return ~inv;
    }

    public static int opOf(byte[] ik) {
        checkLength(ik);
        return ik[ik.length - 1] & 0xFF;
    }

    /**
     * The least internal key with this user key — the seek target. Sequence
     * numbers are inverted, so the greatest {@code seq} comes first and this is
     * the user key followed by eight zero bytes and {@code op = 0}.
     */
    public static byte[] seekFloor(byte[] userKey) {
        byte[] out = Arrays.copyOf(userKey, userKey.length + 9);
        return out;
    }

    /**
     * The least internal key for this user key at or below {@code snapshotSeq}
     * — {@code seq} inverted means seeking this lands directly on the newest
     * visible version, with no forward walk over invisible ones.
     */
    public static byte[] seekAt(byte[] userKey, long snapshotSeq) {
        byte[] out = new byte[userKey.length + 9];
        System.arraycopy(userKey, 0, out, 0, userKey.length);
        long inv = ~snapshotSeq;
        int p = userKey.length;
        for (int i = 7; i >= 0; i--) {
            out[p++] = (byte) (inv >>> (8 * i));
        }
        return out;
    }

    /** The first internal key strictly above every version of {@code userKey}. */
    public static byte[] seekCeiling(byte[] userKey) {
        byte[] out = new byte[userKey.length + 9];
        System.arraycopy(userKey, 0, out, 0, userKey.length);
        Arrays.fill(out, userKey.length, out.length, (byte) 0xFF);
        return out;
    }

    /** True when {@code ik} is a version of {@code userKey}. */
    public static boolean hasUserKey(byte[] ik, byte[] userKey) {
        return ik.length == userKey.length + 9
                && Arrays.equals(ik, 0, userKey.length, userKey, 0, userKey.length);
    }

    private static void checkLength(byte[] ik) {
        if (ik.length < 13) {
            throw new CorruptionException("internal key is " + ik.length
                    + " bytes; the tree id, seq and op alone are 13");
        }
    }
}
