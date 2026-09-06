package org.dizitart.cryptand;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One entry of the value-log stats tree, tree 7 —
 * {@code spec/04-segments.md} §6.7.
 *
 * <p>This tree is the <strong>authority</strong> for everything mutable about a
 * value-log segment. The head page carries only immutable identity, so an entry
 * here and a head page can never disagree about a value that changes.
 *
 * <p>{@code liveBytes} is an <strong>estimate that MUST be conservative</strong>:
 * it may overstate liveness, in which case GC merely skips a segment, and MUST
 * NOT understate it, in which case GC would skip live data. Because overstating
 * is always safe, an implementation that never updates it is still correct — it
 * simply never collects, which is what lets a reduced-profile implementation
 * participate in a database it does not fully manage.
 */
public final class VlogStats {

    public long segmentId;
    /** The durable contiguous watermark: only records entirely below it may be referenced. */
    public long bytes;
    public long records;
    public boolean sealed;
    /** Records appear in non-decreasing {@code (tree_id, CKE(key))} order. Known only at seal. */
    public boolean clustered;
    public byte[] minKey;
    public byte[] maxKey;
    public long startPage;
    public int pages;
    public long liveBytes;
    public long liveRecords;
    public int tier;
    public int heat;
    public long createdSeq;
    public long lastGcSeq;

    public byte[] key() {
        return key(segmentId);
    }

    public static byte[] key(long segmentId) {
        return Cke.encode(Value.integer(NumType.U64, segmentId));
    }

    public Value toValue() {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("bytes", Value.integer(NumType.U64, bytes));
        f.put("records", Value.integer(NumType.U64, records));
        f.put("sealed", new Value.Bool(sealed));
        f.put("clustered", new Value.Bool(clustered));
        if (clustered && minKey != null) {
            f.put("min_key", new Value.Bytes(minKey));
            f.put("max_key", new Value.Bytes(maxKey));
        }
        f.put("start_page", Value.integer(NumType.U64, startPage));
        f.put("pages", Value.integer(NumType.U32, pages));
        f.put("live_bytes", Value.integer(NumType.U64, liveBytes));
        f.put("live_records", Value.integer(NumType.U64, liveRecords));
        f.put("tier", Value.integer(NumType.U8, tier));
        f.put("heat", Value.integer(NumType.U8, heat));
        f.put("created_seq", Value.integer(NumType.U64, createdSeq));
        f.put("last_gc_seq", Value.integer(NumType.U64, lastGcSeq));
        return Value.Doc.of(f);
    }

    public static VlogStats fromValue(byte[] key, Value v) {
        VlogStats s = new VlogStats();
        s.segmentId = SegmentMeta.longOf(Cke.decode(key));
        Value.Doc d = (Value.Doc) v;
        s.bytes = SegmentMeta.longOf(d.field("bytes"));
        s.records = SegmentMeta.longOf(d.field("records"));
        s.sealed = ((Value.Bool) d.field("sealed")).value();
        s.clustered = ((Value.Bool) d.field("clustered")).value();
        Value min = d.field("min_key");
        if (min != null) {
            s.minKey = ((Value.Bytes) min).value();
            s.maxKey = ((Value.Bytes) d.field("max_key")).value();
        }
        s.startPage = SegmentMeta.longOf(d.field("start_page"));
        s.pages = (int) SegmentMeta.longOf(d.field("pages"));
        s.liveBytes = SegmentMeta.longOf(d.field("live_bytes"));
        s.liveRecords = SegmentMeta.longOf(d.field("live_records"));
        s.tier = (int) SegmentMeta.longOf(d.field("tier"));
        s.heat = (int) SegmentMeta.longOf(d.field("heat"));
        s.createdSeq = SegmentMeta.longOf(d.field("created_seq"));
        s.lastGcSeq = SegmentMeta.longOf(d.field("last_gc_seq"));
        return s;
    }
}
