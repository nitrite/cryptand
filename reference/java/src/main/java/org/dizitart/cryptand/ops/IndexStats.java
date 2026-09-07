package org.dizitart.cryptand.ops;

import org.dizitart.cryptand.util.Cfh64;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Planner statistics — {@code spec/13-operations.md} §9.
 *
 * <p>Maintained at compaction and stored in each index tree's catalog
 * descriptor under {@code params.stats}. §9 puts them there because the
 * last-level compaction that produces a segment already touches every key, so
 * the sketch is free.
 *
 * <p><strong>Statistics are advisory.</strong> They may be stale or absent; a
 * planner MUST produce correct results without them and MUST NOT refuse to run
 * because they are missing. That is the one reason §9's byte bound is safe: a
 * coarser histogram is a worse estimate and never a wrong answer.
 *
 * <p>This class and its wiring were absent from the Java port entirely, while
 * the Dart implementation had them and the Rust one had the sketch as dead
 * code with no caller.
 */
public final class IndexStats {

    /**
     * §9's maximum. <strong>64 buckets is a maximum, not a target</strong>, and
     * the <em>byte</em> bound is the binding one — see {@link #fitTo}.
     */
    public static final int MAX_BUCKETS = 64;

    public long updatedSeq;
    public long entries;
    public long distinctEstimate;
    public long nullCount;
    public byte[] minKey = new byte[0];
    public byte[] maxKey = new byte[0];
    public final List<Bucket> histogram = new ArrayList<>();

    /** One equi-depth bucket. The bound is a CKE key, so a planner compares it without decoding. */
    public record Bucket(byte[] bound, long cumulative) {
    }

    // ------------------------------------------------------------------
    // the sketch
    // ------------------------------------------------------------------

    /**
     * A mergeable, fixed-size distinct-count sketch.
     *
     * <p>Chosen for exactly that property: a compaction accumulates it in a few
     * hundred bytes while streaming, and two segments' sketches combine by
     * register-wise maximum. An exact distinct count needs memory proportional
     * to cardinality, which a compaction cannot afford.
     */
    public static final class HyperLogLog {
        public final byte[] registers;
        public final int p;

        public HyperLogLog(int p) {
            this.p = p;
            this.registers = new byte[1 << p];
        }

        public void add(byte[] key) {
            long h = Cfh64.hash(key);
            int idx = (int) (h >>> (64 - p));
            long w = (h << p) | (1L << (p - 1));
            int rank = Long.numberOfLeadingZeros(w) + 1;
            if (rank > (registers[idx] & 0xFF)) {
                registers[idx] = (byte) rank;
            }
        }

        /** §9's "two segments' sketches combine by register-wise maximum". */
        public void merge(HyperLogLog other) {
            if (other.p != p) {
                throw new IllegalArgumentException(
                        "cannot merge sketches of different precision: " + p + " and " + other.p);
            }
            for (int i = 0; i < registers.length; i++) {
                if ((other.registers[i] & 0xFF) > (registers[i] & 0xFF)) {
                    registers[i] = other.registers[i];
                }
            }
        }

        public long estimate() {
            double m = registers.length;
            double alpha = switch (registers.length) {
                case 16 -> 0.673;
                case 32 -> 0.697;
                case 64 -> 0.709;
                default -> 0.7213 / (1.0 + 1.079 / m);
            };
            double sum = 0;
            int zeros = 0;
            for (byte r : registers) {
                int v = r & 0xFF;
                sum += Math.pow(2.0, -v);
                if (v == 0) {
                    zeros++;
                }
            }
            double raw = alpha * m * m / sum;
            // Linear counting below the small-range threshold, where the raw
            // estimator is biased.
            if (raw <= 2.5 * m && zeros > 0) {
                return Math.round(m * Math.log(m / zeros));
            }
            return Math.round(raw);
        }
    }

    // ------------------------------------------------------------------
    // the descriptor encoding
    // ------------------------------------------------------------------

    private static Value u(long v) {
        return Value.integer(NumType.U64, v);
    }

    public Value.Doc toDoc() {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("updated_seq", u(updatedSeq));
        f.put("entries", u(entries));
        f.put("distinct_estimate", u(distinctEstimate));
        f.put("null_count", u(nullCount));
        f.put("min_key", new Value.Bytes(minKey));
        f.put("max_key", new Value.Bytes(maxKey));
        List<Value> buckets = new ArrayList<>(histogram.size());
        for (Bucket b : histogram) {
            Map<String, Value> e = new LinkedHashMap<>();
            e.put("bound", new Value.Bytes(b.bound()));
            e.put("cumulative", u(b.cumulative()));
            buckets.add(new Value.Doc(e));
        }
        f.put("histogram", new Value.Array(buckets));
        return new Value.Doc(f);
    }

    /**
     * Decodes {@code params.stats}.
     *
     * <p>Never throws on a missing or partial field: §9 says statistics "may be
     * stale or absent", so a decoder's job is to give a planner something
     * usable, and a zero here means "no evidence", which
     * {@link #selectivity()} reports as absent rather than as certainty.
     */
    public static IndexStats fromDoc(Value v) {
        IndexStats s = new IndexStats();
        if (!(v instanceof Value.Doc d)) {
            return s;
        }
        s.updatedSeq = uint(d, "updated_seq");
        s.entries = uint(d, "entries");
        s.distinctEstimate = uint(d, "distinct_estimate");
        s.nullCount = uint(d, "null_count");
        s.minKey = bytes(d, "min_key");
        s.maxKey = bytes(d, "max_key");
        if (d.fields().get("histogram") instanceof Value.Array a) {
            for (Value item : a.items()) {
                if (item instanceof Value.Doc b) {
                    s.histogram.add(new Bucket(bytes(b, "bound"), uint(b, "cumulative")));
                }
            }
        }
        return s;
    }

    private static long uint(Value.Doc d, String name) {
        return d.fields().get(name) instanceof Value.Int i
                ? i.magnitude().lo()
                : 0L;
    }

    private static byte[] bytes(Value.Doc d, String name) {
        return d.fields().get(name) instanceof Value.Bytes b ? b.value() : new byte[0];
    }

    public int encodedLen() {
        return Cve.encode(toDoc()).length;
    }

    /**
     * §9 — reduce the bucket count until the encoded {@code params.stats} fits
     * the descriptor's page budget, by <strong>dropping alternate
     * buckets</strong>.
     *
     * <p>Dropping alternates keeps the histogram equi-depth at twice the width
     * and <em>keeps its range</em>; truncating would throw away the top of the
     * key space, which is a worse answer than a coarser one.
     *
     * <p>The bound is in bytes, not buckets, and the byte bound is the binding
     * one: {@code params.stats} lives inside a catalog descriptor, a descriptor
     * is one cell of a copy-on-write B+tree, and a CKE key runs to kilobytes.
     * 64 bounds over 300 string keys measured 4734 B against a 4096 B page —
     * defect 37, found because a bound was stated over the quantity that is
     * easy to count rather than the one that is scarce.
     */
    public void fitTo(int budgetBytes) {
        while (encodedLen() > budgetBytes && histogram.size() > 1) {
            List<Bucket> kept = new ArrayList<>((histogram.size() + 1) / 2);
            for (int i = 0; i < histogram.size(); i++) {
                // Keep every second bucket, and always the last one, so the
                // range still reaches max_key.
                if (i % 2 == 1 || i + 1 == histogram.size()) {
                    kept.add(histogram.get(i));
                }
            }
            if (kept.size() == histogram.size()) {
                kept.remove(kept.size() - 1);
            }
            histogram.clear();
            histogram.addAll(kept);
        }
        if (encodedLen() > budgetBytes) {
            histogram.clear();
        }
    }

    /**
     * The fraction of the index a single-key lookup is expected to return, or
     * {@code null} when there is no evidence.
     *
     * <p>{@code null} is not zero and is not one: §9 requires a planner to
     * treat "no statistics" as "choose some other way", never as a number.
     */
    public Double selectivity() {
        if (entries == 0 || distinctEstimate == 0) {
            return null;
        }
        return 1.0 / distinctEstimate;
    }

    // ------------------------------------------------------------------
    // the builder
    // ------------------------------------------------------------------

    /**
     * Accumulates statistics over a key-ordered stream — which is what a
     * last-level compaction already is, so §9 gets these for free.
     */
    public static final class Builder {
        private final HyperLogLog hll = new HyperLogLog(10);
        private final List<byte[]> samples = new ArrayList<>();
        private long entries;
        private long nullCount;
        private byte[] minKey;
        private byte[] maxKey;

        /** Keys MUST arrive in key order; the histogram's equi-depth property depends on it. */
        public void add(byte[] key, boolean isNull) {
            hll.add(key);
            entries++;
            if (isNull) {
                nullCount++;
            }
            if (minKey == null) {
                minKey = key.clone();
            }
            maxKey = key.clone();
            samples.add(key.clone());
        }

        public IndexStats build(long updatedSeq, int budgetBytes) {
            IndexStats s = new IndexStats();
            s.updatedSeq = updatedSeq;
            s.entries = entries;
            s.nullCount = nullCount;
            s.distinctEstimate = entries == 0 ? 0 : hll.estimate();
            s.minKey = minKey == null ? new byte[0] : minKey;
            s.maxKey = maxKey == null ? new byte[0] : maxKey;
            if (!samples.isEmpty()) {
                int n = samples.size();
                int buckets = Math.min(MAX_BUCKETS, n);
                int step = (n + buckets - 1) / buckets;
                long cumulative = 0;
                for (int i = 0; i < n; ) {
                    int end = Math.min(i + step, n);
                    cumulative += end - i;
                    s.histogram.add(new Bucket(samples.get(end - 1), cumulative));
                    i = end;
                }
            }
            s.fitTo(budgetBytes);
            return s;
        }
    }
}
