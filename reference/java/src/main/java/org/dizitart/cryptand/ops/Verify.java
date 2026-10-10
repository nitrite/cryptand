package org.dizitart.cryptand.ops;

import org.dizitart.cryptand.TamperingException;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.container.Blob;
import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.lsm.BlockedBloom;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Value;
import org.dizitart.cryptand.lsm.Segment;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.lsm.VlogPointer;
import org.dizitart.cryptand.lsm.VlogSegment;
import org.dizitart.cryptand.lsm.VlogStats;
import org.dizitart.cryptand.util.ByteReader;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The verification pass — {@code spec/01-container.md} §9 and
 * {@code spec/04-segments.md} §11.
 *
 * <p>Verification <strong>reports</strong>; {@code spec/13-operations.md} §3
 * specifies repair. The distinction is load-bearing for one class of finding: a
 * failed AEAD tag or {@code sb_mac} is neither corruption nor a leak, it is
 * tampering, and repairing tampered data is laundering it.
 *
 * <p>Steps 1–7 run on an encrypted file <em>without</em> a key. That is the
 * payoff for leaving page headers in the clear, and it is why
 * {@code 14-security.md} §7 is willing to pay the metadata leak.
 */
public final class Verify {

    /** What a finding is, so that a caller can respond differently to each. */
    public enum Kind {
        /** Accidental damage. Repairable. */
        CORRUPTION,
        /** Someone edited the file. MUST NOT be repaired. */
        TAMPERING,
        /** A page that is neither reachable nor free. Repairable. */
        LEAK,
        /** One page claimed twice. Not repairable; report precisely what is affected. */
        DOUBLE_ALLOCATION,
        /** A bound the format states as a MUST that this file is outside. */
        POLICY
    }

    public static final class Finding {
        private final Kind kind;
        private final String message;

        public Finding(Kind kind, String message) {
            this.kind = kind;
            this.message = message;
        }

        public Kind kind() {
            return kind;
        }

        public String message() {
            return message;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Finding)) {
                return false;
            }
            Finding that = (Finding) o;
            return java.util.Objects.equals(kind, that.kind)
                    && java.util.Objects.equals(message, that.message);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(kind, message);
        }

        @Override
        public String toString() {
            return kind + ": " + message;
        }
    }

    public static final class Report {
        private final List<Finding> findings;
        private final long pagesReachable;
        private final long pagesFree;
        private final long segments;

        public Report(List<Finding> findings, long pagesReachable, long pagesFree, long segments) {
            this.findings = findings;
            this.pagesReachable = pagesReachable;
            this.pagesFree = pagesFree;
            this.segments = segments;
        }

        public List<Finding> findings() {
            return findings;
        }

        public long pagesReachable() {
            return pagesReachable;
        }

        public long pagesFree() {
            return pagesFree;
        }

        public long segments() {
            return segments;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Report)) {
                return false;
            }
            Report that = (Report) o;
            return java.util.Objects.equals(findings, that.findings)
                    && pagesReachable == that.pagesReachable
                    && pagesFree == that.pagesFree
                    && segments == that.segments;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(findings, pagesReachable, pagesFree, segments);
        }

        public boolean clean() {
            return findings.isEmpty();
        }

        public List<Finding> of(Kind kind) {
            List<Finding> out = new ArrayList<>();
            for (Finding f : findings) {
                if (f.kind() == kind) {
                    out.add(f);
                }
            }
            return out;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(segments).append(" segments, ").append(pagesReachable)
                    .append(" pages reachable, ").append(pagesFree).append(" free");
            for (Finding f : findings) {
                sb.append("\n  ").append(f);
            }
            return sb.toString();
        }
    }

    private final Engine engine;
    private final Pager pager;
    private final List<Finding> findings = new ArrayList<>();
    private final Map<Long, String> owners = new HashMap<>();
    private long reachable;

    private Verify(Engine engine) {
        this.engine = engine;
        this.pager = engine.pager();
    }

    /**
     * Runs the pass against a consistent view.
     *
     * <p>The structure lock is held throughout, because the checks that matter
     * most are cross-structural: a page is a leak only relative to the free
     * tree, and a double allocation only relative to the manifest. A compaction
     * publishing between two of those reads produces findings that describe no
     * state the database was ever in.
     */
    public static Report run(Engine engine) {
        engine.lockStructure();
        try {
            return new Verify(engine).go();
        } finally {
            engine.unlockStructure();
        }
    }

    /** As {@link #run}, for a caller that already holds the structure lock. */
    public static Report runLocked(Engine engine) {
        return new Verify(engine).go();
    }

    private Report go() {
        Superblock sb = engine.superblock();
        claim(0, 1, "superblock slot A");
        claim(1, 1, "superblock slot B");

        List<SegmentMeta> segments = engine.manifest().all();
        for (SegmentMeta m : segments) {
            verifySegment(m);
        }
        verifyDisjointness(segments);
        verifyInternalTrees(sb);
        verifyValueLog();
        verifyFreeSpace(sb);
        verifyLocalityDebt(sb);

        long free = 0;
        for (Pager.FreeExtent e : pager.freeList()) {
            free += e.pages();
        }
        return new Report(List.copyOf(findings), reachable, free, segments.size());
    }

    // ==================================================================
    // §9 step 2 and 04 §11 invariants 1–7
    // ==================================================================

    private void verifySegment(SegmentMeta m) {
        Segment seg;
        try {
            seg = Segment.open(pager, m.startPage);
        } catch (RuntimeException e) {
            report(e, "segment " + m.segmentId + " at page " + m.startPage);
            return;
        }
        claim(m.startPage, m.pages, "segment " + m.segmentId);

        // Invariant 5: the header must agree with the manifest on every
        // duplicated field. The duplication is what turns a damaged manifest
        // into a scan-and-rebuild rather than a total loss, and it rots
        // unnoticed unless something checks it.
        SegmentMeta h = seg.meta();
        if (h.segmentId != m.segmentId || h.level != m.level || h.group != m.group) {
            findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId
                    + " header says (id " + h.segmentId + ", level " + h.level + ", group " + h.group
                    + "), manifest says (id " + m.segmentId + ", level " + m.level
                    + ", group " + m.group + ")"));
        }
        if (BtreePage.memcmp(h.minKey, m.minKey) != 0 || BtreePage.memcmp(h.maxKey, m.maxKey) != 0) {
            findings.add(new Finding(Kind.CORRUPTION,
                    "segment " + m.segmentId + "'s key bounds differ between header and manifest"));
        }

        byte[] previous = null;
        long entries = 0;
        long minSeq = Long.MAX_VALUE;
        long maxSeq = 0;
        long minExpiry = 0;
        BlockedBloom filter = seg.filter();
        try {
            Segment.Cursor c = seg.cursor();
            c.seekFirst();
            while (c.isValid()) {
                byte[] ik = c.key();
                // Invariant 1: internal keys strictly increase within and across
                // pages.
                if (previous != null && BtreePage.memcmp(previous, ik) >= 0) {
                    findings.add(new Finding(Kind.CORRUPTION,
                            "segment " + m.segmentId + " has non-increasing internal keys"));
                    break;
                }
                previous = ik;
                entries++;
                long seq = Ikey.seqOf(ik);
                minSeq = Math.min(minSeq, seq);
                maxSeq = Math.max(maxSeq, seq);
                BtreePage.Leaf cell = c.entry();
                if (cell.hasExpiry()) {
                    minExpiry = minExpiry == 0 ? cell.expiryMs() : Math.min(minExpiry, cell.expiryMs());
                }
                // Invariant 7: every key in a segment passes that segment's own
                // filter. A false negative silently loses a key, which is the
                // one direction this structure may never be wrong in.
                if (filter != null && !filter.mayContain(Ikey.userKeyOf(ik))) {
                    findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId
                            + " holds a key its own filter rejects"));
                    break;
                }
                // Invariant 5: min_key and max_key BOUND the contents. §2.1
                // permits shortening, so equality is not required.
                if (BtreePage.memcmp(ik, h.minKey) < 0 || BtreePage.memcmp(h.maxKey, ik) < 0) {
                    findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId
                            + " holds a key outside its declared bounds"));
                    break;
                }
                verifyValuePointer(m, cell);
                if (!c.next()) {
                    break;
                }
            }
        } catch (RuntimeException e) {
            report(e, "segment " + m.segmentId);
            return;
        }

        if (entries != h.entryCount) {
            findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId + " holds " + entries
                    + " entries, its header declares " + h.entryCount));
        }
        if (entries > 0 && (minSeq != h.minSeq || maxSeq != h.maxSeq)) {
            findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId + " spans seq "
                    + minSeq + ".." + maxSeq + ", its header declares " + h.minSeq + ".." + h.maxSeq));
        }
        if (minExpiry != h.minExpiry) {
            findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId + "'s min_expiry is "
                    + h.minExpiry + ", its contents give " + minExpiry));
        }
        verifySubtreeEntries(seg, m);
    }

    /**
     * Whether an entry is already logically gone: superseded by a newer version
     * and below {@code min_retained_seq}, so no reader and no snapshot can
     * reach it.
     *
     * <p>§9 step 4 says "every {@code VLOG} pointer", and taking that at face
     * value makes the check unsatisfiable: {@code 04-segments.md} §6.8 frees a
     * record as soon as the tree's <em>current</em> entry stops pointing at it,
     * and the entry that used to point at it stays in its segment until a
     * compaction happens to drop it. GC's own pointer rewrite creates one such
     * entry per surviving record, so a verifier that follows those reports
     * every healthy database that has ever collected as corrupt - and a
     * verifier that is wrong about the common case is worse than none.
     *
     * <p>Only genuinely unreachable entries are exempted. A superseded version
     * at or above {@code min_retained_seq} is still readable through a snapshot,
     * so its pointer MUST resolve and is still checked.
     */
    private boolean isDead(BtreePage.Leaf cell) {
        byte[] ik = cell.key();
        long seq = Ikey.seqOf(ik);
        if (seq >= engine.superblock().minRetainedSeq) {
            return false;
        }
        BtreePage.Leaf newest = engine.newestVersion(
                Ikey.treeIdOf(ik), Ikey.ckeOf(ik), engine.visibleSeq());
        if (newest != null && Ikey.seqOf(newest.key()) > seq) {
            return true;
        }
        // F-043: the newest version, but range-deleted or expired. No reader
        // resolves it, so GC (§6.8 step 2) may already have freed its record.
        return !engine.containsKey(Ikey.treeIdOf(ik), Ikey.ckeOf(ik));
    }

    /** Invariant 3: {@code subtree_entries} sums correctly and every leaf is at one depth. */
    private void verifySubtreeEntries(Segment seg, SegmentMeta m) {
        Set<Integer> depths = new HashSet<>();
        long counted = walk(seg, m, m.rootPage, 0, depths);
        if (counted >= 0 && counted != m.entryCount) {
            findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId
                    + "'s subtree_entries sum to " + counted + ", its header declares " + m.entryCount));
        }
        if (depths.size() > 1) {
            findings.add(new Finding(Kind.CORRUPTION,
                    "segment " + m.segmentId + " has leaves at depths " + depths));
        }
    }

    private long walk(Segment seg, SegmentMeta m, long relativePage, int depth, Set<Integer> depths) {
        // F-119: F-111's bound, here too; a child that points back up recursed until the stack overflowed.
        if (depth > 64) {
            findings.add(new Finding(Kind.CORRUPTION,
                    "segment " + m.segmentId + "'s tree is deeper than 64 levels"));
            return -1;
        }
        byte[] payload;
        try {
            payload = pager.readPage(m.startPage + relativePage);
        } catch (RuntimeException e) {
            report(e, "segment " + m.segmentId + " page " + relativePage);
            return -1;
        }
        BtreePage p = BtreePage.parse(payload, 0, payload.length);
        if (p.isLeaf()) {
            depths.add(depth);
            return p.cellCount();
        }
        long total = 0;
        byte[] previousSeparator = null;
        for (int i = 0; i < p.cellCount(); i++) {
            BtreePage.Internal cell = p.internal(i);
            // Invariant 2: separators are ordered.
            if (previousSeparator != null && BtreePage.memcmp(previousSeparator, cell.separator()) >= 0) {
                findings.add(new Finding(Kind.CORRUPTION,
                        "segment " + m.segmentId + " has non-increasing separators"));
            }
            previousSeparator = cell.separator();
            long child = walk(seg, m, cell.childPage(), depth + 1, depths);
            if (child < 0) {
                return -1;
            }
            if (child != cell.childSubtreeEntries()) {
                findings.add(new Finding(Kind.CORRUPTION, "segment " + m.segmentId
                        + " declares " + cell.childSubtreeEntries() + " entries under page "
                        + cell.childPage() + ", which holds " + child));
            }
            total += child;
        }
        return total;
    }

    /**
     * Invariant 6 and §9 step 3: a levelled level's segments MUST NOT overlap
     * <strong>in user keys</strong>.
     *
     * <p>Testing whole internal keys is wrong and the error is invisible: an
     * internal key carries {@code seq}, so two segments holding different
     * versions of the same key occupy disjoint internal-key ranges and an
     * overlap test on them reports two overlapping segments as disjoint. The
     * consequence is a wrong answer, not a slow one — §4's early exit rests on
     * at most one segment per group covering a key.
     */
    private void verifyDisjointness(List<SegmentMeta> segments) {
        int last = Math.max(1, engine.superblock().levelCount - 1);
        Map<String, List<SegmentMeta>> groups = new HashMap<>();
        for (SegmentMeta m : segments) {
            if (m.level == 0) {
                continue;
            }
            groups.computeIfAbsent(m.level + "/" + m.group, k -> new ArrayList<>()).add(m);
        }
        for (Map.Entry<String, List<SegmentMeta>> e : groups.entrySet()) {
            List<SegmentMeta> group = e.getValue();
            for (int i = 0; i < group.size(); i++) {
                for (int j = i + 1; j < group.size(); j++) {
                    if (SegmentMeta.userRangesOverlap(group.get(i), group.get(j))) {
                        findings.add(new Finding(Kind.CORRUPTION, "segments "
                                + group.get(i).segmentId + " and " + group.get(j).segmentId
                                + " overlap in user keys at level-group " + e.getKey()
                                + (group.get(i).level == last ? " (the levelled last level)" : "")));
                    }
                }
            }
        }
    }

    // ==================================================================
    // §9 steps 4, 5 and 6
    // ==================================================================

    private void verifyValuePointer(SegmentMeta m, BtreePage.Leaf cell) {
        switch (cell.kind()) {
            case BtreePage.Kind.VLOG: {
                VlogPointer p = VlogPointer.decode(cell.value());
                try {
                    VlogSegment.Record rec = engine.vlog().read(p);
                    byte[] cke = Ikey.ckeOf(cell.key());
                    // A dead cell may point into a collected segment whose
                    // extent has since been reused (F-037 keeps it readable
                    // for old snapshots); no reader resolves it.
                    if (BtreePage.memcmp(rec.key(), cke) != 0 && !isDead(cell)) {
                        findings.add(new Finding(Kind.CORRUPTION, "a VLOG pointer in segment "
                                + m.segmentId + " resolves to a record with a different key"));
                    }
                } catch (RuntimeException e) {
                    if (!isDead(cell)) {
                        report(e, "VLOG pointer in segment " + m.segmentId);
                    }
                }
            }
                break;
            case BtreePage.Kind.BLOB: {
                Blob b = Blob.decode(cell.value());
                claim(b.startPage(), b.extentPages(pager), "blob");
                try {
                    b.read(pager);
                } catch (RuntimeException e) {
                    report(e, "blob at page " + b.startPage());
                }
            }
                break;
            default: {
            }
                break;
        }
    }

    /**
     * §9 steps 4 and 5, plus {@code 04-segments.md} §11 invariants 8b, 9 and 10.
     */
    private void verifyValueLog() {
        java.util.Set<Long> named = new java.util.HashSet<>();
        for (VlogStats s : engine.vlog().allStats()) {
            named.add(s.segmentId);
        }
        for (VlogSegment open : engine.vlog().openSegments()) {
            if (!named.contains(open.segmentId)) { // live engine: not yet published
                claim(open.startPage, open.pages, "open value-log segment " + open.segmentId);
            }
        }
        for (VlogStats s : engine.vlog().allStats()) {
            claim(s.startPage, s.pages, "value-log segment " + s.segmentId);
            VlogSegment head;
            try {
                head = engine.vlog().segment(s.segmentId);
            } catch (RuntimeException e) {
                report(e, "value-log segment " + s.segmentId);
                continue;
            }
            // Invariant 8b: a head page and a tree-7 entry that disagree on
            // identity is corruption, not a discrepancy to reconcile.
            if (head.segmentId != s.segmentId || head.tier != s.tier || head.heatClass != s.heat
                    || head.createdSeq != s.createdSeq) {
                findings.add(new Finding(Kind.CORRUPTION, "value-log segment " + s.segmentId
                        + "'s head page and tree-7 entry disagree on immutable identity: head("
                        + head.segmentId + ", tier " + head.tier + ", heat " + head.heatClass
                        + ", created " + head.createdSeq + ") tree7(" + s.segmentId + ", tier "
                        + s.tier + ", heat " + s.heat + ", created " + s.createdSeq + ")"));
            }
            long trueLive = 0;
            long offset = head.dataOffset;
            long end = head.dataOffset + s.bytes;
            byte[] lastSortKey = null;
            boolean sorted = true;
            while (offset < end) {
                VlogSegment.Record rec;
                int total;
                try {
                    byte[] lead = new byte[(int) Math.min(16, end - offset)];
                    pager.file().readFully(pager.offsetOf(head.startPage) + offset, lead, 0, lead.length);
                    ByteReader r = new ByteReader(lead);
                    total = (int) (r.uvar() + r.consumed());
                    if (offset + total > end) {
                        findings.add(new Finding(Kind.CORRUPTION, "value-log segment " + s.segmentId
                                + " has a record running past its durable watermark"));
                        break;
                    }
                    byte[] buf = new byte[total];
                    pager.file().readFully(pager.offsetOf(head.startPage) + offset, buf, 0, total);
                    rec = engine.vlog().decodeAt(head, buf, offset);
                } catch (RuntimeException e) {
                    report(e, "value-log segment " + s.segmentId + " at " + offset);
                    break;
                }
                byte[] sortKey = Ikey.userKey(rec.treeId(), rec.key());
                if (lastSortKey != null && BtreePage.memcmp(lastSortKey, sortKey) > 0) {
                    sorted = false;
                }
                lastSortKey = sortKey;
                BtreePage.Leaf live = engine.newestVersion(rec.treeId(), rec.key(), engine.visibleSeq());
                if (live != null && live.kind() == BtreePage.Kind.VLOG) {
                    VlogPointer lp = VlogPointer.decode(live.value());
                    if (lp.segmentId() == s.segmentId && lp.offset() == offset) {
                        trueLive += total;
                    }
                }
                offset += total;
            }
            // Invariant 9: a segment marked `clustered` really is in
            // (tree_id, CKE(key)) order.
            if (s.clustered && !sorted) {
                findings.add(new Finding(Kind.CORRUPTION, "value-log segment " + s.segmentId
                        + " is marked clustered but its records are not in key order"));
            }
            // Invariant 10: live_bytes is conservative. Overstating is always
            // safe - GC merely skips the segment - and understating would have
            // GC skip live data, which is the one failure this format cannot
            // detect after the fact.
            if (s.liveBytes < trueLive) {
                findings.add(new Finding(Kind.CORRUPTION, "value-log segment " + s.segmentId
                        + " declares " + s.liveBytes + " live bytes but holds " + trueLive
                        + "; liveness statistics MUST NOT understate"));
            }
        }
    }

    // ==================================================================
    // §9 step 7
    // ==================================================================

    private void verifyInternalTrees(Superblock sb) {
        claimTree(sb.catalogRoot, "catalog");
        claimTree(sb.freelistRoot, "free tree");
        claimTree(sb.attributesRoot, "attributes");
        claimTree(sb.manifestRoot, "manifest");
        claimTree(sb.vlogStatsRoot, "value-log stats");
        claimTree(sb.checkpointRoot, "checkpoints");
        claimTree(sb.changefeedRoot, "change feed");
        for (Map.Entry<byte[], byte[]> e : engine.catalogTree().map().entrySet()) {
            TreeDescriptor d = TreeDescriptor.decode(e.getValue(), null);
            Long root = d.root();
            if (root != null && root != 0) {
                if (TreeDescriptor.IndexType.SPATIAL.equals(d.indexType())) {
                    // F-079: an R-tree is not a B+tree; walk it in its own format.
                    try {
                        for (long p : Engine.indexTreePages(pager, d)) {
                            claim(p, 1, "R-tree " + d.treeId());
                        }
                    } catch (RuntimeException ex) {
                        report(ex, "R-tree " + d.treeId());
                    }
                } else {
                    claimTree(root, "tree " + d.treeId());
                }
            }
            // F-079: a vector region owns its whole extent (09-vector §2).
            Value.Doc params = d.params();
            Value at = params == null ? null : params.field("vector_region");
            if (at != null && SegmentMeta.longOf(at) != 0) {
                long start = SegmentMeta.longOf(at);
                try {
                    PageHeader h = PageHeader.parse(pager.readRaw(start), 0);
                    claim(start, Math.max(1, h.extentPages), "vector region of tree " + d.treeId());
                } catch (RuntimeException ex) {
                    report(ex, "vector region at page " + start);
                }
            }
        }
        // Trees 3, 4 and 5 are reached through their catalog descriptors above,
        // like every other non-superblock tree. Claiming them again here would
        // report the same page twice and call it a double allocation.
    }

    private void claimTree(long root, String what) {
        if (root == 0) {
            return;
        }
        byte[] payload;
        try {
            payload = pager.readPage(root);
        } catch (RuntimeException e) {
            report(e, what + " page " + root);
            return;
        }
        claim(root, 1, what);
        BtreePage p = BtreePage.parse(payload, 0, payload.length);
        if (!p.isLeaf()) {
            for (int i = 0; i < p.cellCount(); i++) {
                claimTree(p.internal(i).childPage(), what);
            }
        }
    }

    /**
     * §9 step 7: reachable pages, value-log extents and free extents partition
     * {@code page_count} with no overlaps and no leaks.
     *
     * <p>A leak is repairable. A double allocation is corruption, and the
     * report names precisely what is affected rather than only counting.
     */
    private void verifyFreeSpace(Superblock sb) {
        Map<Long, String> free = new HashMap<>();
        for (Pager.FreeExtent e : pager.freeList()) {
            // F-114: the free list is the file's word; an extent past the page
            // space is a finding, not four billion map entries.
            if (e.startPage() < 0 || e.pages() < 0 || e.startPage() + e.pages() > pager.pageCount()) {
                findings.add(new Finding(Kind.CORRUPTION, "free extent of " + e.pages() + " pages from "
                        + e.startPage() + " runs past the " + pager.pageCount() + "-page file"));
                continue;
            }
            for (long p = e.startPage(); p < e.startPage() + e.pages(); p++) {
                if (owners.containsKey(p)) {
                    findings.add(new Finding(Kind.DOUBLE_ALLOCATION, "page " + p
                            + " is both free (from commit " + e.commitId() + ") and in use by "
                            + owners.get(p)));
                }
                String previous = free.put(p, "free@" + e.commitId());
                if (previous != null) {
                    findings.add(new Finding(Kind.DOUBLE_ALLOCATION,
                            "page " + p + " appears in the free tree twice"));
                }
            }
        }
        // The pager's count, not the superblock's: a verifier run on a live
        // engine must see pages allocated since the last superblock write, or
        // it reports a database as whole while an allocation is in flight.
        for (long p = 2; p < pager.pageCount(); p++) {
            if (!owners.containsKey(p) && !free.containsKey(p)) {
                findings.add(new Finding(Kind.LEAK,
                        "page " + p + " is neither reachable nor free"));
            }
        }
    }

    /**
     * §6.9's bound, as a finding rather than an error: an implementation MUST
     * keep {@code locality_debt} at or below {@code locality_debt_pct} whenever
     * the database is not under active write pressure.
     */
    private void verifyLocalityDebt(Superblock sb) {
        double debt = engine.localityDebt();
        if (debt * 100 > sb.localityDebtPct) {
            findings.add(new Finding(Kind.POLICY, String.format(
                    "locality_debt is %.1f%%, above the profile's ceiling of %d%%; "
                            + "a scan over separated values will decay",
                    debt * 100, sb.localityDebtPct)));
        }
    }

    private void claim(long start, int pages, String what) {
        // `start` and `pages` come out of the file and are untrusted. This loop
        // puts one map entry per page in the range, so an extent claiming two
        // billion pages is two billion entries and an OutOfMemoryError —
        // `14-security.md` §9.1's "MUST bounds-check ... **before allocating**"
        // applies to the verifier's own working set, not only to its decoders.
        long limit = pager.pageCount();
        if (pages < 0 || start < 0 || pages > limit || start > limit || start + pages > limit) {
            findings.add(new Finding(Kind.CORRUPTION,
                    what + " claims " + Integer.toUnsignedString(pages) + " pages from " + start
                            + ", but the file holds " + limit));
            return;
        }
        for (long p = start; p < start + pages; p++) {
            String previous = owners.put(p, what);
            if (previous != null && !previous.equals(what)) {
                findings.add(new Finding(Kind.DOUBLE_ALLOCATION,
                        "page " + p + " is claimed by both " + previous + " and " + what));
            } else if (previous == null) {
                reachable++;
            }
        }
    }

    /**
     * Sorts a thrown exception into the taxonomy. Tampering is reported as its
     * own class: "your disk has a bad sector" and "someone edited your database"
     * call for different responses, and repairing the second is laundering it.
     */
    private void report(RuntimeException e, String where) {
        Kind kind = e instanceof TamperingException ? Kind.TAMPERING : Kind.CORRUPTION;
        findings.add(new Finding(kind, where + ": " + e.getMessage()));
    }
}
