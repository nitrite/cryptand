package org.dizitart.cryptand;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * What stops an extent being reallocated under a reader —
 * {@code spec/01-container.md} §6.
 *
 * <p>"An extent freed at {@code commit_id = N} may be reallocated once
 * {@code N <= min_retained_commit}, the greatest commit id such that no live
 * reader holds a snapshot at or below it." A cursor is an obvious live reader
 * and pins explicitly. <strong>A point read is one too</strong>, for the
 * duration of the read: it resolves the manifest into a set of segments and
 * then reads their pages, and a compaction that publishes and frees in between
 * can hand those pages to the next allocation.
 *
 * <p>The failure is a wrong answer under concurrency and nothing else — the
 * pages verify, because they are a perfectly good <em>different</em> segment.
 *
 * <p>One slot per reading thread, registered once and then written without
 * contention, because a shared list would put an allocation and a scan on the
 * hottest path in the engine.
 */
final class ReadPins {

    private static final long UNPINNED = 0;

    private final Map<Thread, AtomicLong> slots = new ConcurrentHashMap<>();
    private final ThreadLocal<AtomicLong> mine = ThreadLocal.withInitial(() -> {
        AtomicLong slot = new AtomicLong(UNPINNED);
        slots.put(Thread.currentThread(), slot);
        return slot;
    });
    private final ThreadLocal<int[]> depth = ThreadLocal.withInitial(() -> new int[1]);

    /** Pins the current commit for this thread. Reentrant: only the outermost pin counts. */
    void acquire(long commitId) {
        int[] d = depth.get();
        if (d[0]++ == 0) {
            mine.get().set(commitId);
        }
    }

    void release() {
        int[] d = depth.get();
        if (--d[0] <= 0) {
            d[0] = 0;
            mine.get().set(UNPINNED);
        }
    }

    /** The oldest commit any reader is holding, or {@code fallback} when none is. */
    long oldest(long fallback) {
        long min = fallback;
        for (Map.Entry<Thread, AtomicLong> e : slots.entrySet()) {
            if (!e.getKey().isAlive()) {
                slots.remove(e.getKey());
                continue;
            }
            long v = e.getValue().get();
            if (v != UNPINNED && v < min) {
                min = v;
            }
        }
        return min;
    }
}
