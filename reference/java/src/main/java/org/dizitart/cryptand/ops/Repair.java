package org.dizitart.cryptand.ops;

import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.Manifest;
import org.dizitart.cryptand.lsm.SegmentMeta;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Repair — {@code spec/13-operations.md} §3.
 *
 * <p>Verification reports; repair fixes. Two classes are deliberately outside
 * it. A <strong>double allocation</strong> is not repairable, and repair says so
 * precisely rather than guessing. And a failed AEAD tag or {@code sb_mac} is
 * not corruption at all — it is tampering, and repairing tampered data is
 * laundering it.
 *
 * <p>The manifest is deliberately redundant with the segment headers, and this
 * is what that redundancy is for: a damaged manifest root becomes a
 * scan-and-rebuild rather than a total loss. Every field the manifest holds —
 * {@code group} included, which is part of the manifest key and which nothing
 * else would recover — is in the header for no other reason.
 */
public final class Repair {

    public record Result(List<String> repaired, List<String> unrepairable) {

        public boolean clean() {
            return repaired.isEmpty() && unrepairable.isEmpty();
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            for (String r : repaired) {
                sb.append("repaired: ").append(r).append('\n');
            }
            for (String u : unrepairable) {
                sb.append("UNREPAIRABLE: ").append(u).append('\n');
            }
            return sb.isEmpty() ? "nothing to repair" : sb.toString();
        }
    }

    private Repair() {
    }

    /**
     * Repairs what is repairable and reports what is not.
     *
     * <p>Leaks join the free tree; a lost manifest is rebuilt from segment
     * headers. A double allocation is reported by name and left alone.
     */
    public static Result run(Engine engine) {
        engine.lockStructure();
        try {
            List<String> repaired = new ArrayList<>();
            List<String> unrepairable = new ArrayList<>();
            Verify.Report report = Verify.runLocked(engine);

            for (Verify.Finding f : report.of(Verify.Kind.DOUBLE_ALLOCATION)) {
                unrepairable.add(f.message());
            }
            for (Verify.Finding f : report.of(Verify.Kind.TAMPERING)) {
                // Not corruption, and MUST NOT be repaired.
                unrepairable.add("tampering, not repaired: " + f.message());
            }

            List<Verify.Finding> leaks = report.of(Verify.Kind.LEAK);
            if (!leaks.isEmpty()) {
                for (Verify.Finding f : leaks) {
                    long page = Long.parseLong(f.message().split(" ")[1]);
                    engine.pager().freeExtent(page, 1);
                }
                repaired.add(leaks.size() + " leaked page(s) added to the free tree");
                engine.commitNow();
            }
            return new Result(repaired, unrepairable);
        } finally {
            engine.unlockStructure();
        }
    }

    /**
     * Rebuilds the manifest by scanning the file for {@code SEGMENT_HEADER}
     * pages — §3's answer to a corrupt or stale manifest.
     *
     * <p>Every field the manifest holds is duplicated in the segment header for
     * exactly this reason, so the rebuild needs nothing but the file.
     */
    public static int rebuildManifest(Engine engine) {
        engine.lockStructure();
        try {
            Pager pager = engine.pager();
            Manifest manifest = engine.manifest();
            for (SegmentMeta m : manifest.all()) {
                manifest.remove(m);
            }
            // A freed extent's head page still reads as a SEGMENT_HEADER: its
            // bytes are not overwritten until the space is reallocated. The
            // free tree is what distinguishes them, so a rebuild consults it
            // and recovers the live set exactly. With the free tree lost too, a
            // scan alone recovers a SUPERSET - every version resolves by seq, so
            // the result is correct and merely larger, but the levelled level's
            // disjointness no longer holds and §4's early exit has to be off.
            Set<Long> freed = new HashSet<>();
            for (Pager.FreeExtent e : pager.freeList()) {
                for (long p = e.startPage(); p < e.startPage() + e.pages(); p++) {
                    freed.add(p);
                }
            }
            Set<Long> seen = new HashSet<>();
            int found = 0;
            for (long page = 2; page < pager.pageCount(); page++) {
                if (seen.contains(page) || freed.contains(page)) {
                    continue;
                }
                PageHeader h;
                try {
                    h = PageHeader.verify(pager.readRaw(page), page);
                } catch (RuntimeException e) {
                    continue;
                }
                if (h.pageType != PageHeader.Type.SEGMENT_HEADER
                        || !h.isSet(PageHeader.Flags.EXTENT_HEAD)) {
                    continue;
                }
                try {
                    SegmentMeta m = SegmentMeta.decodeHeadPayload(pager.readPage(page));
                    m.startPage = page;
                    m.pages = h.extentPages;
                    manifest.add(m);
                    for (long p = page; p < page + h.extentPages; p++) {
                        seen.add(p);
                    }
                    found++;
                } catch (RuntimeException e) {
                    // A head page that does not decode is not a segment; the
                    // scan is over untrusted bytes by construction.
                }
            }
            engine.commitNow();
            return found;
        } finally {
            engine.unlockStructure();
        }
    }
}
