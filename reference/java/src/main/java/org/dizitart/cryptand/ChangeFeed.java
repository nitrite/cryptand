package org.dizitart.cryptand;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The change feed — {@code spec/13-operations.md} §7, tree 9.
 *
 * <p>Entries are appended in the same batch as the mutation, so the feed is
 * exactly consistent with the data. Because the key is {@code (tree_id, seq)},
 * {@code read_changes(tree, from_seq)} is a sequential range scan.
 *
 * <p><strong>Optional and off by default</strong>, per tree, via
 * {@code params.change_feed}: it costs a write per mutation and most databases
 * do not sync. It exists because the alternative — a full scan comparing
 * {@code _revision} fields — is the thing every sync implementation does badly,
 * and a monotonic per-record {@code seq} is already in the format.
 */
public record ChangeFeed(int treeId, long seq, String op, byte[] key, Long nitriteId) {

    public static final String PUT = "put";
    public static final String DELETE = "delete";
    public static final String RANGE_DELETE = "range_delete";

    public static byte[] key(int treeId, long seq) {
        return Cke.encode(new Value.Array(List.of(
                Value.integer(NumType.U32, treeId),
                Value.integer(NumType.U64, seq))));
    }

    public Value toValue() {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("op", new Value.Str(op));
        f.put("key", new Value.Bytes(key));
        if (nitriteId != null) {
            f.put("id", new Value.NitriteId(nitriteId));
        }
        return Value.Doc.of(f);
    }

    public static ChangeFeed fromEntry(byte[] cke, Value value) {
        List<Value> parts = ((Value.Array) Cke.decode(cke)).items();
        Value.Doc d = (Value.Doc) value;
        Value id = d.field("id");
        return new ChangeFeed(
                (int) SegmentMeta.longOf(parts.get(0)),
                SegmentMeta.longOf(parts.get(1)),
                ((Value.Str) d.field("op")).value(),
                ((Value.Bytes) d.field("key")).value(),
                id == null ? null : ((Value.NitriteId) id).id());
    }

    /** Changes to one tree at or after {@code fromSeq}, in seq order. */
    public static List<ChangeFeed> read(PageTree tree, int treeId, long fromSeq) {
        List<ChangeFeed> out = new ArrayList<>();
        byte[] from = key(treeId, fromSeq);
        for (Map.Entry<byte[], byte[]> e : tree.map().tailMap(from, true).entrySet()) {
            ChangeFeed c = fromEntry(e.getKey(), Cve.decode(e.getValue()));
            if (c.treeId() != treeId) {
                break;
            }
            out.add(c);
        }
        return out;
    }
}
