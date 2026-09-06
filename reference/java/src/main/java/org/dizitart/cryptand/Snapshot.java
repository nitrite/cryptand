package org.dizitart.cryptand;

/**
 * A sequence number plus the structural state at one commit —
 * {@code spec/10-transactions.md} §1.
 *
 * <p><strong>All nine superblock roots, not a subset.</strong> A snapshot that
 * omits one is not a consistent view of the database: a reader restored to it
 * would see the current change feed against an older manifest.
 * {@code 13-operations.md} §1 stores exactly this tuple for a checkpoint, for
 * the same reason.
 *
 * <p>Because segments are immutable and every version carries its own seq, a
 * snapshot needs no locks, no copying and no coordination with writers.
 */
public record Snapshot(long seq, long commitId,
                       long catalogRoot, long freelistRoot, long attributesRoot,
                       long manifestRoot, long vlogStatsRoot,
                       long checkpointRoot, long changefeedRoot) {

    public static Snapshot of(Superblock sb) {
        return new Snapshot(sb.visibleSeq, sb.commitId,
                sb.catalogRoot, sb.freelistRoot, sb.attributesRoot,
                sb.manifestRoot, sb.vlogStatsRoot,
                sb.checkpointRoot, sb.changefeedRoot);
    }

    /** Writes these roots back into a superblock — {@code 13-operations.md} §1's restore. */
    public void applyTo(Superblock sb) {
        sb.visibleSeq = seq;
        sb.catalogRoot = catalogRoot;
        sb.freelistRoot = freelistRoot;
        sb.attributesRoot = attributesRoot;
        sb.manifestRoot = manifestRoot;
        sb.vlogStatsRoot = vlogStatsRoot;
        sb.checkpointRoot = checkpointRoot;
        sb.changefeedRoot = changefeedRoot;
    }
}
