package org.dizitart.cryptand.ops;

import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.lsm.VlogStats;
import org.dizitart.cryptand.value.Value;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The required metrics of {@code spec/13-operations.md} §6.
 *
 * <p>They are normative because every one of them answers a question that is
 * otherwise unanswerable from outside.
 *
 * <p><strong>A metric an implementation cannot compute is reported as
 * unavailable, by name, and is never given a plausible-looking value.</strong>
 * A fabricated answer defeats this section more thoroughly than a missing one,
 * because a caller cannot tell the two apart: {@code page_cache_hit_rate: 1.0}
 * from an engine with no page-cache accounting reads exactly like a perfect
 * cache. {@code Value.unavailable(why)} is how this implementation says so.
 */
public final class Metrics {

    /** A metric value, or the explicit absence of one. */
    public interface Value {

        /** Reported by name rather than guessed at. */
        final class Unavailable implements Value {
            private final String why;

            public Unavailable(String why) {
                this.why = why;
            }

            public String why() {
                return why;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) {
                    return true;
                }
                if (!(o instanceof Unavailable)) {
                    return false;
                }
                Unavailable that = (Unavailable) o;
                return java.util.Objects.equals(why, that.why);
            }

            @Override
            public int hashCode() {
                return java.util.Objects.hash(why);
            }

            @Override
            public String toString() {
                return "unavailable (" + why + ")";
            }
        }

        final class Number implements Value {
            private final double value;

            public Number(double value) {
                this.value = value;
            }

            public double value() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) {
                    return true;
                }
                if (!(o instanceof Number)) {
                    return false;
                }
                Number that = (Number) o;
                return Double.compare(value, that.value) == 0;
            }

            @Override
            public int hashCode() {
                return java.util.Objects.hash(value);
            }

            @Override
            public String toString() {
                return value == Math.rint(value) && Math.abs(value) < 1e15
                        ? String.valueOf((long) value)
                        : String.valueOf(value);
            }
        }

        final class Text implements Value {
            private final String value;

            public Text(String value) {
                this.value = value;
            }

            public String value() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) {
                    return true;
                }
                if (!(o instanceof Text)) {
                    return false;
                }
                Text that = (Text) o;
                return java.util.Objects.equals(value, that.value);
            }

            @Override
            public int hashCode() {
                return java.util.Objects.hash(value);
            }

            @Override
            public String toString() {
                return value;
            }
        }

        static Value of(double v) {
            return new Number(v);
        }

        static Value unavailable(String why) {
            return new Unavailable(why);
        }
    }

    private final Map<String, Value> values = new LinkedHashMap<>();

    private Metrics() {
    }

    public static Metrics of(Engine engine) {
        engine.lockStructure();
        try {
            return build(engine);
        } finally {
            engine.unlockStructure();
        }
    }

    private static Metrics build(Engine engine) {
        Metrics m = new Metrics();
        Superblock sb = engine.superblock();

        // --- write path ---
        m.put("bytes_written_logical", engine.bytesWrittenLogical());
        m.put("bytes_written_device", engine.bytesWrittenDevice());
        long logical = engine.bytesWrittenLogical();
        m.values.put("write_amp_value", logical == 0
                ? Value.unavailable("nothing has been written")
                : Value.of((double) engine.bytesWrittenValue() / logical));
        m.values.put("write_amp_key_index", logical == 0
                ? Value.unavailable("nothing has been written")
                : Value.of((double) engine.bytesWrittenKeyIndex() / logical));
        m.values.put("write_amp_gc", logical == 0
                ? Value.unavailable("nothing has been written")
                : Value.of((double) engine.bytesWrittenGc() / logical));
        m.put("backpressure_delay_ms", engine.appliedDelayMs());
        m.values.put("backpressure_cause", new Value.Text(
                engine.backpressureCause().isEmpty() ? "none" : engine.backpressureCause()));
        m.put("stall_events", engine.stallEvents());
        m.put("stall_total_ms", engine.stallTotalMs());

        // --- space ---
        long allocated = engine.pager().pageCount() * (long) sb.pageSize();
        m.put("allocated_bytes", allocated);
        long liveValue = 0;
        long vlogAllocated = 0;
        for (VlogStats s : engine.vlog().allStats()) {
            liveValue += s.liveBytes;
            vlogAllocated += (long) s.pages * sb.pageSize();
        }
        m.put("live_bytes", engine.liveBytes());
        m.put("vlog_live_bytes", liveValue);
        m.put("vlog_allocated_bytes", vlogAllocated);
        m.put("locality_debt", engine.localityDebt());
        m.put("vlog_live_runs", engine.vlogLiveRuns());
        m.put("vlog_ideal_runs", engine.vlogIdealRuns());
        // Not derivable as allocated - live: a live snapshot's effect is to stop
        // superseded versions from BECOMING dead, so the bytes it pins never
        // enter that difference and the obvious derivation reads 0 on a
        // database holding a large pinned set. Accumulated where the retention
        // decision is made instead.
        m.put("pinned_by_snapshots", engine.pinnedBySnapshots());
        m.put("pinned_by_checkpoints", engine.pinnedByCheckpoints());
        m.put("unencrypted_pages", engine.unencryptedPages());
        if (sb.cipher == Superblock.Cipher.NONE) {
            m.values.put("nonces_allocated", Value.unavailable("the file is not encrypted"));
            m.values.put("nonce_floor", Value.unavailable("the file is not encrypted"));
        } else {
            m.put("nonces_allocated", engine.noncesAllocated());
            m.put("nonce_floor", sb.nextNonce);
        }

        // --- read path ---
        m.values.put("page_cache_hit_rate", Value.unavailable(
                "this implementation reads through to the file and keeps no page cache"));
        m.put("segments_probed_per_lookup", engine.segmentsProbedPerLookup());
        m.put("filter_false_positive_rate", engine.filterFalsePositiveRate());
        m.put("value_reads_per_scanned_row", engine.valueReadsPerScannedRow());

        // --- structure ---
        int[] perLevel = new int[Math.max(2, sb.levelCount)];
        long[] bytesPerLevel = new long[perLevel.length];
        for (SegmentMeta s : engine.manifest().all()) {
            if (s.level < perLevel.length) {
                perLevel[s.level]++;
                bytesPerLevel[s.level] += (long) s.pages * sb.pageSize();
            }
        }
        for (int l = 0; l < perLevel.length; l++) {
            m.put("segments_at_L" + l, perLevel[l]);
            m.put("bytes_at_L" + l, bytesPerLevel[l]);
        }
        m.put("oldest_snapshot_age_ms", engine.oldestSnapshotAgeMs());
        m.put("compaction_backlog_bytes", engine.compactionBacklogBytes());
        // 0 is the normal state, and it has to be askable: without it, §4's
        // containment is observable only by hitting it, so a partially
        // available database looks identical to a healthy one until a read
        // happens to land in the hole.
        m.put("unavailable_ranges", engine.unavailableRanges().size());
        return m;
    }

    private void put(String name, double v) {
        values.put(name, Value.of(v));
    }

    public Value get(String name) {
        Value v = values.get(name);
        return v == null ? Value.unavailable("no such metric") : v;
    }

    public Map<String, Value> all() {
        return Map.copyOf(values);
    }

    public List<String> unavailable() {
        return values.entrySet().stream()
                .filter(e -> e.getValue() instanceof Value.Unavailable)
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toUnmodifiableList());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Value> e : values.entrySet()) {
            sb.append(e.getKey()).append(" = ").append(e.getValue()).append('\n');
        }
        return sb.toString();
    }
}
