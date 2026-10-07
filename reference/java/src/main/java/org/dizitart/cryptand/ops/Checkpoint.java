package org.dizitart.cryptand.ops;

import org.dizitart.cryptand.Snapshot;
import org.dizitart.cryptand.container.PageTree;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A named, retained snapshot — {@code spec/13-operations.md} §1, tree 8.
 *
 * <p>Creating one is a single small write; it costs nothing until data
 * diverges. Restoring one rewrites the superblock to its roots, which makes
 * restore one superblock write and therefore atomic and instant.
 *
 * <p>The stored tuple is the full {@link Snapshot} <strong>less
 * {@code checkpoint_root}</strong>, deliberately: restoring a checkpoint must
 * not delete the other checkpoints, so a restore keeps the current
 * {@code checkpoint_root} and replaces the other eight.
 */
public final class Checkpoint {
    private final String name;
    private final long commitId;
    private final long seq;
    private final long createdUtcMs;
    private final long catalogRoot;
    private final long freelistRoot;
    private final long attributesRoot;
    private final long manifestRoot;
    private final long vlogStatsRoot;
    private final long changefeedRoot;
    private final Long expiresUtcMs;

    public Checkpoint(String name, long commitId, long seq, long createdUtcMs, long catalogRoot, long freelistRoot, long attributesRoot, long manifestRoot, long vlogStatsRoot, long changefeedRoot, Long expiresUtcMs) {
        this.name = name;
        this.commitId = commitId;
        this.seq = seq;
        this.createdUtcMs = createdUtcMs;
        this.catalogRoot = catalogRoot;
        this.freelistRoot = freelistRoot;
        this.attributesRoot = attributesRoot;
        this.manifestRoot = manifestRoot;
        this.vlogStatsRoot = vlogStatsRoot;
        this.changefeedRoot = changefeedRoot;
        this.expiresUtcMs = expiresUtcMs;
    }

    public String name() {
        return name;
    }

    public long commitId() {
        return commitId;
    }

    public long seq() {
        return seq;
    }

    public long createdUtcMs() {
        return createdUtcMs;
    }

    public long catalogRoot() {
        return catalogRoot;
    }

    public long freelistRoot() {
        return freelistRoot;
    }

    public long attributesRoot() {
        return attributesRoot;
    }

    public long manifestRoot() {
        return manifestRoot;
    }

    public long vlogStatsRoot() {
        return vlogStatsRoot;
    }

    public long changefeedRoot() {
        return changefeedRoot;
    }

    public Long expiresUtcMs() {
        return expiresUtcMs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Checkpoint)) {
            return false;
        }
        Checkpoint that = (Checkpoint) o;
        return java.util.Objects.equals(name, that.name)
                && commitId == that.commitId
                && seq == that.seq
                && createdUtcMs == that.createdUtcMs
                && catalogRoot == that.catalogRoot
                && freelistRoot == that.freelistRoot
                && attributesRoot == that.attributesRoot
                && manifestRoot == that.manifestRoot
                && vlogStatsRoot == that.vlogStatsRoot
                && changefeedRoot == that.changefeedRoot
                && java.util.Objects.equals(expiresUtcMs, that.expiresUtcMs);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(name, commitId, seq, createdUtcMs, catalogRoot, freelistRoot, attributesRoot, manifestRoot, vlogStatsRoot, changefeedRoot, expiresUtcMs);
    }

    @Override
    public String toString() {
        return "Checkpoint[" + "name=" + name + ", " + "commitId=" + commitId + ", " + "seq=" + seq + ", " + "createdUtcMs=" + createdUtcMs + ", " + "catalogRoot=" + catalogRoot + ", " + "freelistRoot=" + freelistRoot + ", " + "attributesRoot=" + attributesRoot + ", " + "manifestRoot=" + manifestRoot + ", " + "vlogStatsRoot=" + vlogStatsRoot + ", " + "changefeedRoot=" + changefeedRoot + ", " + "expiresUtcMs=" + expiresUtcMs + "]";
    }

    public static byte[] key(String name) {
        return Cke.encode(new Value.Str(name));
    }

    public Value toValue() {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("commit_id", Value.integer(NumType.U64, commitId));
        f.put("seq", Value.integer(NumType.U64, seq));
        f.put("created", new Value.Timestamp(createdUtcMs));
        f.put("catalog_root", Value.integer(NumType.U64, catalogRoot));
        f.put("freelist_root", Value.integer(NumType.U64, freelistRoot));
        f.put("attributes_root", Value.integer(NumType.U64, attributesRoot));
        f.put("manifest_root", Value.integer(NumType.U64, manifestRoot));
        f.put("vlog_stats_root", Value.integer(NumType.U64, vlogStatsRoot));
        f.put("changefeed_root", Value.integer(NumType.U64, changefeedRoot));
        if (expiresUtcMs != null) {
            f.put("expires", new Value.Timestamp(expiresUtcMs));
        }
        return Value.Doc.of(f);
    }

    public static Checkpoint fromValue(String name, Value value) {
        Value.Doc d = (Value.Doc) value;
        Value expires = d.field("expires");
        return new Checkpoint(name,
                SegmentMeta.longOf(d.field("commit_id")),
                SegmentMeta.longOf(d.field("seq")),
                ((Value.Timestamp) d.field("created")).millis(),
                SegmentMeta.longOf(d.field("catalog_root")),
                SegmentMeta.longOf(d.field("freelist_root")),
                SegmentMeta.longOf(d.field("attributes_root")),
                SegmentMeta.longOf(d.field("manifest_root")),
                SegmentMeta.longOf(d.field("vlog_stats_root")),
                SegmentMeta.longOf(d.field("changefeed_root")),
                expires == null ? null : ((Value.Timestamp) expires).millis());
    }

    /** The eight roots this checkpoint replaces, over the current checkpoint root. */
    public Snapshot asSnapshot(long currentCheckpointRoot) {
        return new Snapshot(seq, commitId, catalogRoot, freelistRoot, attributesRoot,
                manifestRoot, vlogStatsRoot, currentCheckpointRoot, changefeedRoot);
    }

    public static List<Checkpoint> all(PageTree tree) {
        List<Checkpoint> out = new ArrayList<>();
        for (Map.Entry<byte[], byte[]> e : tree.map().entrySet()) {
            String name = ((Value.Str) Cke.decode(e.getKey())).value();
            out.add(fromValue(name, Cve.decode(e.getValue())));
        }
        return out;
    }
}
