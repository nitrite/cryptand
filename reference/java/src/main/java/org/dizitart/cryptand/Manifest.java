package org.dizitart.cryptand;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The segment manifest — {@code spec/04-segments.md} §3.2, reserved tree 6.
 *
 * <p>Keyed by {@code (level, group, min_internal_key)}, so "find the segments
 * at level <em>L</em> covering key <em>k</em>" is {@code overlap_bound} seeks,
 * each returning at most one segment. There is no run list in the superblock;
 * the manifest is where segments live, so their number is unbounded by the
 * superblock's size and a compaction publishes by writing one small
 * copy-on-write path plus one superblock.
 */
public final class Manifest {

    private final PageTree tree;
    /**
     * The decoded entries, rebuilt when the tree changes.
     *
     * <p>Decoding is a CKE and a CVE parse per segment, and the read path, the
     * compaction picker and the verifier all ask for the whole list. Re-parsing
     * it per call makes a commit O(segments) and a session O(segments^2).
     */
    private List<SegmentMeta> cached;

    public Manifest(PageTree tree) {
        this.tree = tree;
    }

    public PageTree tree() {
        return tree;
    }

    public void add(SegmentMeta m) {
        tree.put(m.manifestKey(), Cve.encode(m.manifestValue()));
        cached = null;
    }

    public void remove(SegmentMeta m) {
        tree.remove(m.manifestKey());
        cached = null;
    }

    public boolean contains(SegmentMeta m) {
        return tree.containsKey(m.manifestKey());
    }

    /** Every segment, in {@code (level, group, min_key)} order. */
    public List<SegmentMeta> all() {
        List<SegmentMeta> out = cached;
        if (out == null) {
            out = new ArrayList<>();
            for (Map.Entry<byte[], byte[]> e : tree.map().entrySet()) {
                out.add(SegmentMeta.fromManifest(e.getKey(), Cve.decode(e.getValue())));
            }
            out = List.copyOf(out);
            cached = out;
        }
        return out;
    }

    public List<SegmentMeta> at(int level) {
        List<SegmentMeta> out = new ArrayList<>();
        for (SegmentMeta m : all()) {
            if (m.level == level) {
                out.add(m);
            }
        }
        return out;
    }

    public List<SegmentMeta> at(int level, int group) {
        List<SegmentMeta> out = new ArrayList<>();
        for (SegmentMeta m : all()) {
            if (m.level == level && m.group == group) {
                out.add(m);
            }
        }
        return out;
    }

    public int highestLevel() {
        int max = 0;
        for (SegmentMeta m : all()) {
            max = Math.max(max, m.level);
        }
        return max;
    }
}
