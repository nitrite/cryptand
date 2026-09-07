package org.dizitart.cryptand.container;

import org.dizitart.cryptand.value.Value;

/**
 * Reserved tree ids — {@code spec/05-catalog.md} §2.
 *
 * <p>Trees are addressed by numeric id and their names live in the catalog as
 * plain UTF-8. That is what retires, permanently, Fjall's {@code | -> _P_}
 * substitution, Hive's base64 box keys, and every "reserved character" rule: a
 * collection may be named {@code "orders|2026+eu"} and nothing downstream cares.
 *
 * <p>Reserved trees are plain copy-on-write B+trees, not levelled segment sets.
 * They are small, hot and almost entirely cached; levelling them would mean the
 * manifest needed a manifest.
 */
public final class TreeId {

    private TreeId() {
    }

    /** {@code CKE(STR name)} to a CVE tree descriptor. Always exists. */
    public static final int CATALOG = 0;
    /** {@code CKE([U64 commit_id, U64 start_page])} to {@code {"pages": u32}}. Always exists. */
    public static final int FREE_SPACE = 1;
    /** {@code CKE(STR tree_name)} to an attributes document. Created on first use. */
    public static final int ATTRIBUTES = 2;
    /** {@code CKE(U32 tree_id)} to {@code CVE STR name} — the reverse of the catalog. */
    public static final int TREE_INDEX = 3;
    /** Pending index mutations. Created on first use. */
    public static final int REPAIR_LOG = 4;
    /** {@code CKE(STR username)} to a credential record. Created on first use. */
    public static final int USERS = 5;
    /** The segment manifest the read path prunes with. Always exists. */
    public static final int MANIFEST = 6;
    /** Value-log liveness. Always exists. */
    public static final int VLOG_STATS = 7;
    /** Named retained snapshots. Created on first use. */
    public static final int CHECKPOINTS = 8;
    /** The change feed. Created on first use. */
    public static final int CHANGE_FEED = 9;

    /** Ids 0–15 are reserved; user trees start here. */
    public static final int FIRST_USER_TREE = 16;

    /**
     * The page-header value meaning "no owning tree" — segment, value-log, blob
     * and vector-region pages. {@code 0xFFFFFFFF} is therefore never a valid
     * {@code tree_id}, which is why {@code next_tree_id} must stop at
     * {@code 0xFFFFFFFE}.
     */
    public static final int NONE = 0xFFFFFFFF;

    public static boolean isReserved(int treeId) {
        return treeId >= 0 && treeId < FIRST_USER_TREE;
    }
}
