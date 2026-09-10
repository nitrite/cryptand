package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.container.BtreePage;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.PriorityQueue;

/**
 * One stream of entries in internal-key order — a segment cursor or a memtable
 * shard — and the bounded merge heap over them that {@code spec/04-segments.md}
 * §8 requires a cursor to be.
 *
 * <p>Because the last level is disjoint and tiers are range-partitioned, a scan
 * merges at most {@code l0_trigger + overlap_bound × (level_count − 2) + 1}
 * sources: a small bounded heap rather than an unbounded N-way merge.
 */
public interface EntrySource {

    boolean isValid();

    byte[] key();

    BtreePage.Leaf entry();

    boolean next();

    /** A source over an already-sorted in-memory map. */
    final class OfMap implements EntrySource {
        private final Iterator<Map.Entry<byte[], BtreePage.Leaf>> it;
        private Map.Entry<byte[], BtreePage.Leaf> current;

        public OfMap(NavigableMap<byte[], BtreePage.Leaf> map) {
            this.it = map.entrySet().iterator();
            advance();
        }

        private void advance() {
            current = it.hasNext() ? it.next() : null;
        }

        @Override
        public boolean isValid() {
            return current != null;
        }

        @Override
        public byte[] key() {
            return current.getKey();
        }

        @Override
        public BtreePage.Leaf entry() {
            return current.getValue();
        }

        @Override
        public boolean next() {
            advance();
            return current != null;
        }
    }

    /**
     * A source over two parallel lists already in internal-key order — what a
     * memtable shard yields when it is drained in its own iteration order.
     */
    final class OfLists implements EntrySource {
        private final List<byte[]> keys;
        private final List<BtreePage.Leaf> cells;
        private int i;

        public OfLists(List<byte[]> keys, List<BtreePage.Leaf> cells) {
            this.keys = keys;
            this.cells = cells;
        }

        @Override
        public boolean isValid() {
            return i < keys.size();
        }

        @Override
        public byte[] key() {
            return keys.get(i);
        }

        @Override
        public BtreePage.Leaf entry() {
            return cells.get(i);
        }

        @Override
        public boolean next() {
            i++;
            return isValid();
        }
    }

    /** A source over an already-sorted in-memory map, iterated backwards. */
    final class OfMapReverse implements EntrySource {
        private final Iterator<Map.Entry<byte[], BtreePage.Leaf>> it;
        private Map.Entry<byte[], BtreePage.Leaf> current;

        public OfMapReverse(NavigableMap<byte[], BtreePage.Leaf> map) {
            this.it = map.descendingMap().entrySet().iterator();
            current = it.hasNext() ? it.next() : null;
        }

        @Override
        public boolean isValid() {
            return current != null;
        }

        @Override
        public byte[] key() {
            return current.getKey();
        }

        @Override
        public BtreePage.Leaf entry() {
            return current.getValue();
        }

        @Override
        public boolean next() {
            current = it.hasNext() ? it.next() : null;
            return current != null;
        }
    }

    /** A source over a segment, from the first entry. */
    final class OfSegment implements EntrySource {
        private final Segment.Cursor cursor;

        public OfSegment(Segment segment) {
            this.cursor = segment.cursor();
            cursor.seekFirst();
        }

        public OfSegment(Segment segment, byte[] from) {
            this.cursor = segment.cursor();
            cursor.seek(from);
        }

        @Override
        public boolean isValid() {
            return cursor.isValid();
        }

        @Override
        public byte[] key() {
            return cursor.key();
        }

        @Override
        public BtreePage.Leaf entry() {
            return cursor.entry();
        }

        @Override
        public boolean next() {
            return cursor.next();
        }
    }

    /**
     * A source over a segment, walked backwards from the last entry at or
     * below {@code to}. Reverse iteration is a first-class direction in this
     * format (§8), not {@code next} collected and reversed.
     */
    final class OfSegmentReverse implements EntrySource {
        private final Segment.Cursor cursor;

        public OfSegmentReverse(Segment segment, byte[] to) {
            this.cursor = segment.cursor();
            if (to == null) {
                cursor.seekLast();
                return;
            }
            cursor.seek(to);
            if (cursor.isValid()) {
                if (BtreePage.memcmp(cursor.key(), to) > 0) {
                    cursor.prev();
                }
            } else {
                cursor.seekLast();
            }
        }

        @Override
        public boolean isValid() {
            return cursor.isValid();
        }

        @Override
        public byte[] key() {
            return cursor.key();
        }

        @Override
        public BtreePage.Leaf entry() {
            return cursor.entry();
        }

        @Override
        public boolean next() {
            return cursor.prev();
        }
    }

    /**
     * A heap merge over several sources.
     *
     * <p>Ties — the same internal key from two sources, which happens only when
     * a compaction's inputs overlap in {@code seq} as well as key — are broken
     * by source order, and the caller passes its sources newest-first.
     */
    final class Merge {

        /**
         * Mutable on purpose: {@link Merge#next()} takes the head out of the
         * heap, re-points it at its source's next key and puts it back. As a
         * record it was **one allocation per merged entry** -- 20 000 per flush
         * of a 20 000-document memtable, and the same again for every entry of
         * every compaction.
         */
        private static final class Head {
            private byte[] key;
            private final int source;

            Head(byte[] key, int source) {
                this.key = key;
                this.source = source;
            }

            byte[] key() {
                return key;
            }

            int source() {
                return source;
            }
        }

        private final List<EntrySource> sources;
        private final PriorityQueue<Head> heap;

        public Merge(List<EntrySource> sources) {
            this(sources, false);
        }

        /** {@code descending} merges the reverse sources of a reverse scan. */
        public Merge(List<EntrySource> sources, boolean descending) {
            this.sources = new ArrayList<>(sources);
            int dir = descending ? -1 : 1;
            this.heap = new PriorityQueue<>((a, b) -> {
                int c = dir * BtreePage.memcmp(a.key(), b.key());
                return c != 0 ? c : Integer.compare(a.source(), b.source());
            });
            for (int i = 0; i < this.sources.size(); i++) {
                EntrySource s = this.sources.get(i);
                if (s.isValid()) {
                    heap.add(new Head(s.key(), i));
                }
            }
        }

        public boolean isValid() {
            return !heap.isEmpty();
        }

        public byte[] key() {
            return heap.peek().key();
        }

        public BtreePage.Leaf entry() {
            return sources.get(heap.peek().source()).entry();
        }

        public void next() {
            Head h = heap.poll();
            EntrySource s = sources.get(h.source());
            if (s.next()) {
                // `h` is out of the heap here, so re-pointing it cannot disturb
                // the heap's ordering; it goes back in through `add` and is
                // sifted into place like any other element.
                h.key = s.key();
                heap.add(h);
            }
        }
    }
}
