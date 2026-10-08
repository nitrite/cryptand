package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.PageTree;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.crypto.FileCipher;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.value.Cve;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The two-tier value log — {@code spec/04-segments.md} §6.
 *
 * <p>Writers <strong>reserve, then write directly</strong>: a writer takes a
 * byte range with one {@code fetch_add} on the open segment's tail counter and
 * writes its whole batch at that offset. There is no shared write buffer and no
 * writer lock, so the number of open segments is bounded by the number of
 * <em>heat classes</em> rather than by the number of writer threads, and
 * concurrent writers never touch the same bytes.
 *
 * <p>A crash can leave a reserved-but-unwritten hole below the tail. That is
 * safe because durability is defined by a <strong>contiguous</strong>
 * watermark: {@link #durableBytes} advances only over a prefix in which every
 * reservation has completed, and only records entirely below it may be
 * referenced by a pointer.
 */
/**
 * <strong>Every mutating entry point is {@code synchronized} on this
 * instance.</strong>
 *
 * <p>Two threads reach the value log. The committer calls {@link #append} from
 * {@code Engine.commitBatch}, which takes <em>no</em> structural lock; the
 * compactor calls {@link #appendCold} from {@code Engine.compactOnce}, which
 * holds {@code structure}. So the shared state here — the {@code hot} and
 * {@code known} maps, each {@code Open}'s watermark bookkeeping, and its
 * {@code completed} {@code TreeMap} — was mutated concurrently with no lock at
 * all.
 *
 * <p>The symptom was
 * {@code NullPointerException: Cannot assign field "color" because "this.root"
 * is null} — {@code java.util.TreeMap.fixAfterInsertion} on a tree two threads
 * had corrupted — surfacing in about one run in six of
 * {@code reference/conformance/interop/run.sh} and in none of the 300 unit
 * tests, which do not run long enough for the two threads to overlap on the
 * same log.
 *
 * <p>An NPE is the <em>lucky</em> outcome. The same race silently loses a
 * `completed` entry, which leaves the durable watermark short of what was
 * written, which is a value-log record that no longer resolves.
 *
 * <p>There is no lock-order inversion: {@code commitBatch} never takes
 * {@code structure}, so the only nesting is {@code structure} then this
 * monitor, always in that order.
 */
public final class Vlog {

    /** An open, appendable segment. */
    /**
     * Reads that resolved a record lying beyond the contiguous watermark —
     * behind a hole left by an append still in flight.
     *
     * <p>A counter rather than a comment, because it is the only way to tell a
     * working watermark-hole protocol from one that is never reached. A test
     * that exercises concurrent appends and sees this stay at zero has not
     * tested the protocol at all, whatever else it asserts.
     */
    public static final java.util.concurrent.atomic.AtomicLong HOLE_READS =
            new java.util.concurrent.atomic.AtomicLong();

    private static final class Open {
        final VlogSegment seg;
        final AtomicLong tail;
        /** Completed reservations not yet folded into {@link #watermark}, keyed by start offset. */
        final NavigableMap<Long, Long> completed = new TreeMap<>();
        long watermark;
        long records;
        long liveBytes;
        long liveRecords;
        /** What the last publish already folded into tree 7, so a republish adds a delta. */
        long publishedLiveBytes;
        long publishedLiveRecords;
        byte[] minKey;
        byte[] maxKey;
        boolean sorted = true;
        byte[] lastSortKey;

        Open(VlogSegment seg) {
            this.seg = seg;
            this.tail = new AtomicLong(seg.dataOffset);
            this.watermark = seg.dataOffset;
        }

        /**
         * Whether {@code [offset, offset+len)} is written and therefore
         * readable — <strong>the read half of the watermark-hole protocol</strong>.
         *
         * <p>{@code watermark} is the <em>contiguous</em> durable prefix
         * ({@code 10-transactions.md} §2.3), and under concurrent appends a
         * finished write can sit beyond it behind an earlier reservation that
         * has not landed yet. Such a record is written and perfectly readable;
         * it is only not yet <em>recoverable</em>. Judging readability by the
         * watermark alone rejects it:
         *
         * <pre>value-log pointer to segment 1 ends at 4163294, past the durable
         * watermark 4161273</pre>
         *
         * <p>So readability consults the contiguous prefix and, failing that,
         * the completed-but-not-yet-folded ranges. Recoverability still uses
         * the watermark alone, which is what {@link Vlog#publish} records.
         */
        boolean covers(long offset, long len) {
            long end = offset + len;
            if (end <= watermark) {
                return true;
            }
            HOLE_READS.incrementAndGet();
            Map.Entry<Long, Long> e = completed.floorEntry(offset);
            return e != null && e.getKey() <= offset && e.getValue() >= end;
        }

        /** Whether every reservation has landed: no holes, nothing in flight. */
        boolean quiesced() {
            return watermark >= tail.get();
        }
    }

    private final Pager pager;
    private final PageTree statsTree;
    private final int segmentBytes;
    private final AtomicLong nextSegmentId;
    private final Map<Integer, Open> hot = new HashMap<>();
    private Open cold;
    private final Map<Long, VlogSegment> known = new HashMap<>();
    private long createdSeq;
    /** Whether anything has been appended since the committer's last barrier. */
    private volatile boolean appendedSinceBarrier;
    private volatile FileCipher cipher;
    /**
     * The ciphers decrypts dropped, kept while a snapshot may still read a
     * retired encrypted segment. Never used to write.
     */
    // ponytail: held until the engine closes; release it once pruneRetired
    // empties the retired set if key lifetime after decrypt matters.
    final List<FileCipher> readOnlyCiphers = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** Installs the record cipher. Null means the value log is written in the clear. */
    public synchronized void setCipher(FileCipher cipher) {
        this.cipher = cipher;
    }

    /** {@code decrypt()}'s mode: records still read under the key, new segments are plaintext. */
    private volatile boolean writeClear;

    private boolean seals() {
        return cipher != null && !writeClear;
    }

    /**
     * F-072: switches the write mode. Every open segment is sealed first, so
     * no segment ever holds records of both framings.
     */
    public synchronized void switchMode(FileCipher cipher, boolean writeClear) {
        sealAll();
        this.cipher = cipher;
        this.writeClear = writeClear;
    }

    public Vlog(Pager pager, PageTree statsTree, int segmentBytes, long nextSegmentId) {
        this.pager = pager;
        this.statsTree = statsTree;
        this.segmentBytes = segmentBytes;
        this.nextSegmentId = new AtomicLong(nextSegmentId);
    }

    public synchronized long nextSegmentId() {
        return nextSegmentId.get();
    }

    public synchronized void setCurrentSeq(long seq) {
        this.createdSeq = seq;
    }

    /**
     * Seals every unsealed segment a previous session left open, per
     * {@code 10-transactions.md} §4 and {@code 14-security.md} §4.3.
     *
     * <p>A writer MUST NOT append to a segment it did not itself open in the
     * current session. Unencrypted, re-appending after a crash would be
     * harmless — nothing references the debris. Encrypted, it writes different
     * plaintext at the same segment and offset, which is a nonce collision and a
     * total loss of confidentiality for both records. The rule is unconditional
     * rather than encryption-only, because a rule that applies sometimes is a
     * rule that gets implemented wrong.
     */
    public synchronized void sealOrphans() {
        for (Map.Entry<byte[], byte[]> e : new ArrayList<>(statsTree.map().entrySet())) {
            VlogStats s = VlogStats.fromValue(e.getKey(), Cve.decode(e.getValue()));
            if (!s.sealed) {
                s.sealed = true;
                statsTree.put(s.key(), Cve.encode(s.toValue()));
            }
        }
    }

    // ==================================================================
    // appending
    // ==================================================================

    /**
     * A reserved byte range and the bytes to put in it. The record is written
     * <strong>outside</strong> the monitor — see {@link #write}.
     */
    private static final class Reservation {
        private final Open open;
        private final long offset;
        private final long end;
        private final int size;
        private final byte[] record;

        public Reservation(Open open, long offset, long end, int size, byte[] record) {
            this.open = open;
            this.offset = offset;
            this.end = end;
            this.size = size;
            this.record = record;
        }

        public Open open() {
            return open;
        }

        public long offset() {
            return offset;
        }

        public long end() {
            return end;
        }

        public int size() {
            return size;
        }

        public byte[] record() {
            return record;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Reservation)) {
                return false;
            }
            Reservation that = (Reservation) o;
            return java.util.Objects.equals(open, that.open)
                    && offset == that.offset
                    && end == that.end
                    && size == that.size
                    && java.util.Objects.equals(record, that.record);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(open, offset, end, size, record);
        }

        @Override
        public String toString() {
            return "Reservation[" + "open=" + open + ", " + "offset=" + offset + ", " + "end=" + end + ", " + "size=" + size + ", " + "record=" + record + "]";
        }
    }

    /** Appends one record to the hot tier, routed by heat class. */
    public VlogPointer append(int treeId, byte[] cke, byte[] value, int heatClass) {
        return write(reserve(true, heatClass, treeId, cke, value));
    }

    /**
     * Appends to the cold tier. Used by promotion during last-level compaction
     * (§6.3) and by a bulk writer with a sorted batch (§6.3's last bullet),
     * which may skip the hot tier and the promotion write entirely.
     */
    public VlogPointer appendCold(int treeId, byte[] cke, byte[] value) {
        return write(reserve(false, 0, treeId, cke, value));
    }

    /**
     * The {@code pwrite} half of {@code 04-segments.md} §6.2's
     * <strong>reserve-then-{@code pwrite}</strong>, and it runs with
     * <strong>no lock held</strong>.
     *
     * <p>{@code 10-transactions.md} §2.2 states it as a MUST: appends are
     * routed this way "so that writers do not serialize on a shared buffer or a
     * lock … Writers do not contend even while sharing a segment, because each
     * takes a disjoint byte range with one {@code fetch_add} and writes into it
     * directly". {@code 11-conformance.md} §1.1: "An implementation that
     * serializes writers is <strong>not</strong> Level 0."
     *
     * <p>Writing outside the monitor is safe because the range is
     * <strong>disjoint by construction</strong> — no two reservations overlap,
     * so no two writers touch the same bytes — and because a pointer that lands
     * beyond the contiguous watermark is still readable through
     * {@link Open#covers}. That is the piece this needed and did not have the
     * first time it was tried: without it a completed write behind an earlier
     * in-flight one was rejected by its own reader.
     */
    private VlogPointer write(Reservation r) {
        try {
            pager.writeAt(pager.offsetOf(r.open().seg.startPage) + r.offset(), r.record());
        } catch (RuntimeException x) {
            abandon(r);
            throw x;
        }
        completeWrite(r);
        return new VlogPointer(r.open().seg.segmentId, r.offset(), r.size());
    }

    /**
     * Takes back a reservation whose write failed (ENOSPC, M2.3) while it is
     * still the tail; left in flight, the next seal refused the segment as
     * corrupt. One behind a later reservation cannot be taken back.
     */
    // ponytail: tail-only rollback; mark mid-segment debris if concurrent
    // writers ever meet a full device.
    private synchronized void abandon(Reservation r) {
        Open o = r.open();
        if (o.tail.compareAndSet(r.end(), r.offset())) {
            o.records--;
            o.liveBytes -= r.size();
            o.liveRecords--;
        }
    }

    /**
     * Folds a finished write into the contiguous watermark — after the
     * {@code pwrite}, never before, because §2.3's watermark advances only over
     * reservations that are actually written.
     */
    private synchronized void completeWrite(Reservation r) {
        appendedSinceBarrier = true;
        complete(r.open(), r.offset(), r.end());
    }

    /**
     * The reservation half: pick the segment, take a disjoint byte range, and
     * do every piece of bookkeeping that touches shared state. Encoding is here
     * too, because §5.3 puts the reserved offset in the nonce and
     * {@code allocateNonce} is shared state of its own.
     */
    private synchronized Reservation reserve(
            boolean hotTier, int heatClass, int treeId, byte[] cke, byte[] value) {
        Open open = hotTier ? openHot(heatClass) : openCold();
        VlogSegment.Record rec = new VlogSegment.Record(treeId, cke, value);
        // The size has to be known before the reservation, because the
        // reservation fixes the offset and §5.3 puts the offset in the nonce.
        // The segment's own framing, never the key in hand (14 §5.2).
        boolean enc = open.seg.encrypted != 0;
        int size = !enc
                ? VlogSegment.recordSize(cke, value)
                : VlogSegment.encryptedRecordSize(cke, value);
        long offset = open.tail.getAndAdd(size);
        long end = offset + size;
        if (end > open.seg.dataOffset + open.seg.capacity) {
            // The reservation did not fit; retire the segment and retry once on
            // a fresh one. The over-reservation is debris, which is what the
            // contiguous watermark exists to tolerate.
            open.tail.addAndGet(-size);
            seal(open);
            boolean cold = open.seg.tier == VlogSegment.TIER_COLD;
            if (cold) {
                openCold(true);
            } else {
                openHot(open.seg.heatClass, true);
            }
            return reserve(!cold, open.seg.heatClass, treeId, cke, value);
        }
        byte[] record = !enc
                ? rec.encode()
                : VlogSegment.encodeEncrypted(rec, open.seg.segmentId, offset, cipher, cipher.allocateNonce());
        if (record.length != size) {
            throw new IllegalStateException("value-log record sized " + size
                    + " but encoded to " + record.length);
        }
        open.records++;
        open.liveBytes += size;
        open.liveRecords++;

        byte[] sortKey = Ikey.userKey(treeId, cke);
        if (open.lastSortKey != null && BtreePage.memcmp(open.lastSortKey, sortKey) > 0) {
            open.sorted = false;
        }
        open.lastSortKey = sortKey;
        if (open.minKey == null || BtreePage.memcmp(sortKey, open.minKey) < 0) {
            open.minKey = sortKey;
        }
        if (open.maxKey == null || BtreePage.memcmp(sortKey, open.maxKey) > 0) {
            open.maxKey = sortKey;
        }
        return new Reservation(open, offset, end, size, record);
    }

    /** Folds a completed reservation into the contiguous watermark. */
    private void complete(Open open, long start, long end) {
        open.completed.put(start, end);
        Map.Entry<Long, Long> first;
        while ((first = open.completed.firstEntry()) != null && first.getKey() <= open.watermark) {
            open.completed.pollFirstEntry();
            open.watermark = Math.max(open.watermark, first.getValue());
        }
        // Wakes a `drain` waiting for this segment to quiesce. Cheap: nothing
        // waits unless a seal is in progress.
        notifyAll();
    }

    private Open openHot(int heatClass) {
        return openHot(heatClass, false);
    }

    private Open openHot(int heatClass, boolean fresh) {
        Open o = hot.get(heatClass);
        if (o == null || fresh) {
            o = allocate(VlogSegment.TIER_HOT, heatClass);
            hot.put(heatClass, o);
        }
        return o;
    }

    private Open openCold() {
        return openCold(false);
    }

    private Open openCold(boolean fresh) {
        if (cold == null || fresh) {
            cold = allocate(VlogSegment.TIER_COLD, VlogSegment.HEAT_FIRST);
        }
        return cold;
    }

    private Open allocate(int tier, int heatClass) {
        int pageSize = pager.pageSize();
        int pages = Math.max(2, (int) (((long) segmentBytes + pageSize - 1) / pageSize));
        long start = pager.allocate(pages);
        VlogSegment s = new VlogSegment();
        s.segmentId = nextSegmentId.getAndIncrement();
        s.createdSeq = createdSeq;
        s.dataOffset = VlogSegment.DATA_OFFSET;
        s.capacity = (long) pages * pageSize - s.dataOffset;
        s.tier = tier;
        s.heatClass = heatClass;
        s.encrypted = seals() ? 1 : 0;
        s.nonceBase = seals() ? cipher.nextNonceWatermark() : 0;
        s.startPage = start;
        s.pages = pages;

        try {
            writeHead(pager, start, pages, s);
        } catch (RuntimeException x) {
            // ENOSPC (M2.3): owned by nothing, the extent would leak.
            pager.abandonExtent(start, pages);
            throw x;
        }
        known.put(s.segmentId, s);
        return new Open(s);
    }

    /**
     * Writes a value-log head page. It stays <strong>in the clear</strong>
     * ({@code 14-security.md} §5.1) and its checksum stops at
     * {@code data_offset}, because record space begins inside this very page.
     */
    static void writeHead(Pager pager, long start, int pages, VlogSegment seg) {
        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.VLOG_SEGMENT;
        h.flags = PageHeader.Flags.EXTENT_HEAD;
        h.extentPages = pages;
        h.commitId = pager.commitId();
        byte[] payload = seg.encodeHeadPayload();
        h.payloadLen = payload.length;
        byte[] page = new byte[pager.pageSize()];
        System.arraycopy(payload, 0, page, PageHeader.BYTES, payload.length);
        h.writeInto(page, seg.dataOffset);
        pager.writeAt(pager.offsetOf(start), page);
    }

    static VlogSegment readHead(Pager pager, long start) {
        byte[] page = pager.readRaw(start);
        PageHeader h = PageHeader.verify(page, start, VlogSegment.DATA_OFFSET);
        if (h.pageType != PageHeader.Type.VLOG_SEGMENT) {
            throw new CorruptionException("page " + start + " has type " + h.pageType
                    + ", expected VLOG_SEGMENT", start, null);
        }
        byte[] payload = new byte[VlogSegment.HEAD_BYTES];
        System.arraycopy(page, PageHeader.BYTES, payload, 0, VlogSegment.HEAD_BYTES);
        return VlogSegment.decodeHeadPayload(payload);
    }

    // ==================================================================
    // reading
    // ==================================================================

    /**
     * F-037: segments GC retired (tree-7 entry removed), with the commit that
     * retired them. A reader pinned before that commit can still hold a pointer
     * into one, and the pager keeps the bytes for it; this keeps the head and
     * watermark readable until {@link #pruneRetired} says no such reader is left.
     */
    private static final class Retired {
        private final VlogStats stats;
        private final long commit;

        public Retired(VlogStats stats, long commit) {
            this.stats = stats;
            this.commit = commit;
        }

        public VlogStats stats() {
            return stats;
        }

        public long commit() {
            return commit;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Retired)) {
                return false;
            }
            Retired that = (Retired) o;
            return java.util.Objects.equals(stats, that.stats)
                    && commit == that.commit;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(stats, commit);
        }

        @Override
        public String toString() {
            return "Retired[" + "stats=" + stats + ", " + "commit=" + commit + "]";
        }
    }

    private final Map<Long, Retired> retired = new HashMap<>();

    public synchronized void retire(VlogStats st, long commit) {
        statsTree.remove(VlogStats.key(st.segmentId));
        retired.put(st.segmentId, new Retired(st, commit));
    }

    /** Forgets segments retired at or before {@code oldestReaderCommit}. */
    public synchronized void pruneRetired(long oldestReaderCommit) {
        retired.values().removeIf(r -> {
            if (r.commit() > oldestReaderCommit) {
                return false;
            }
            known.remove(r.stats().segmentId);
            return true;
        });
    }

    private VlogStats statsOf(long id) {
        byte[] raw = statsTree.get(VlogStats.key(id));
        if (raw != null) {
            return VlogStats.fromValue(VlogStats.key(id), Cve.decode(raw));
        }
        Retired r = retired.get(id);
        if (r == null) {
            throw new CorruptionException("value-log segment " + id + " has no entry in tree 7");
        }
        return r.stats();
    }

    /** Whether segment {@code id} is open or still has its tree-7 entry (not retired by GC). */
    public synchronized boolean exists(long id) {
        return openOf(id) != null || statsTree.get(VlogStats.key(id)) != null;
    }

    public synchronized VlogSegment segment(long id) {
        VlogSegment s = known.get(id);
        if (s != null) {
            return s;
        }
        VlogStats st = statsOf(id);
        VlogSegment seg = readHead(pager, st.startPage);
        // §11 invariant 8b: a head page and a tree-7 entry that disagree on
        // identity is corruption, not a discrepancy to reconcile.
        if (seg.segmentId != id) {
            throw new CorruptionException("value-log head at page " + st.startPage + " says segment "
                    + seg.segmentId + ", tree 7 says " + id);
        }
        seg.startPage = st.startPage;
        seg.pages = st.pages;
        known.put(id, seg);
        return seg;
    }

    /** Resolves a pointer. One sized read, because the pointer carries the record's total length. */
    public synchronized VlogSegment.Record read(VlogPointer p) {
        Open open = openOf(p.segmentId());
        VlogSegment s = open != null ? open.seg : segment(p.segmentId());
        // §6.4: `offset + len` must be at most `data_offset + bytes`.
        //
        // For an **open** segment the authority is the in-memory state, and it
        // is deliberately not the contiguous watermark alone — see
        // `Open.covers`. For a **closed** one there are no in-flight writes
        // left, so tree 7's `bytes` is the whole truth; `seal` guarantees it
        // covers every record by draining first.
        if (open != null) {
            if (!open.covers(p.offset(), p.len())) {
                throw new CorruptionException("value-log pointer to segment " + p.segmentId()
                        + " ends at " + (p.offset() + p.len())
                        + ", past the written extent of the open segment (watermark "
                        + open.watermark + ", tail " + open.tail.get() + ")");
            }
        } else {
            long watermark = s.dataOffset + durableBytesOf(p.segmentId());
            if (p.offset() + p.len() > watermark) {
                throw new CorruptionException("value-log pointer to segment " + p.segmentId()
                        + " ends at " + (p.offset() + p.len())
                        + ", past the durable watermark " + watermark);
            }
        }
        byte[] buf = new byte[(int) p.len()];
        if (open == null) {
            // A **sealed** segment through the page cache — see
            // `Pager.readExtentInto`. This was a bare `pread` per record, so
            // every point read of a separated value cost a syscall even when
            // the page it lived in had just been read.
            //
            // Only sealed. An open segment's pages are still being filled by
            // other writers, and a reader that caches one holds a page with a
            // hole in it where an in-flight reservation has not landed yet;
            // the next read of a neighbouring record in that page then decodes
            // zeros. `VlogConcurrencyTest` catches it in about a third of a
            // second. Sealing is what makes an extent immutable, and immutable
            // is what the cache requires.
            pager.readExtentInto(pager.offsetOf(s.startPage) + p.offset(), buf, 0, buf.length);
        } else {
            pager.file().readFully(pager.offsetOf(s.startPage) + p.offset(), buf, 0, buf.length);
        }
        pager.countReads(pagesSpanned(p.offset(), buf.length));
        return decodeAt(s, buf, p.offset());
    }

    /**
     * Resolves many pointers with as few reads as the layout allows —
     * {@code spec/04-segments.md} §8.1's "MUST coalesce reads of records that
     * fall in the same page".
     *
     * <p>Sorting turns scattered reads into mostly-sequential ones and, over a
     * {@code clustered} cold segment, into strictly sequential ones. Coalescing
     * is what turns a scan of separated values from one I/O per row into one
     * per page — the difference between {@code value_reads_per_scanned_row} of
     * 1.0 and of 0.1, which is the number §6 makes mandatory.
     *
     * @return the records in the order the pointers were given, and the number
     *         of physical reads issued
     */
    public synchronized Resolved readMany(List<VlogPointer> pointers) {
        List<Integer> order = new ArrayList<>(pointers.size());
        for (int i = 0; i < pointers.size(); i++) {
            order.add(i);
        }
        order.sort(java.util.Comparator
                .comparingLong((Integer i) -> pointers.get(i).segmentId())
                .thenComparingLong(i -> pointers.get(i).offset()));

        VlogSegment.Record[] out = new VlogSegment.Record[pointers.size()];
        int reads = 0;
        int pageSize = pager.pageSize();
        int at = 0;
        while (at < order.size()) {
            VlogPointer first = pointers.get(order.get(at));
            Open open = openOf(first.segmentId());
            VlogSegment seg = open != null ? open.seg : segment(first.segmentId());
            long from = first.offset() / pageSize * (long) pageSize;
            long to = from + pageSize;
            int end = at;
            // Everything in the same segment whose record starts inside the
            // window joins this read; the window grows for a record that
            // straddles a page boundary, because a record spans pages with no
            // interior header.
            while (end < order.size()) {
                VlogPointer p = pointers.get(order.get(end));
                if (p.segmentId() != first.segmentId() || p.offset() >= to) {
                    break;
                }
                to = Math.max(to, (p.offset() + p.len() + pageSize - 1) / pageSize * (long) pageSize);
                end++;
            }
            to = Math.min(to, (long) seg.pages * pageSize);
            // The open segment's extent is reserved, not written: rounding the
            // window up to a page read past the end of the file (F-026).
            to = Math.min(to, pager.file().size() - pager.offsetOf(seg.startPage));
            byte[] window = new byte[(int) (to - from)];
            pager.file().readFully(pager.offsetOf(seg.startPage) + from, window, 0, window.length);
            // `reads` is §6's metric - one per physical read, however wide.
            // The pager's counter is pages, because that is what a scan's cost
            // is measured in and a window is not one page.
            reads++;
            pager.countReads(pagesSpanned(from, window.length));
            for (int i = at; i < end; i++) {
                VlogPointer p = pointers.get(order.get(i));
                int local = (int) (p.offset() - from);
                byte[] buf = java.util.Arrays.copyOfRange(window, local, local + (int) p.len());
                out[order.get(i)] = decodeAt(seg, buf, p.offset());
            }
            at = end;
        }
        return new Resolved(java.util.Arrays.asList(out), reads);
    }

    /** Records in the order asked for, and the number of physical reads it took. */
    public static final class Resolved {
        private final List<VlogSegment.Record> records;
        private final int reads;

        public Resolved(List<VlogSegment.Record> records, int reads) {
            this.records = records;
            this.reads = reads;
        }

        public List<VlogSegment.Record> records() {
            return records;
        }

        public int reads() {
            return reads;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Resolved)) {
                return false;
            }
            Resolved that = (Resolved) o;
            return java.util.Objects.equals(records, that.records)
                    && reads == that.reads;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(records, reads);
        }

        @Override
        public String toString() {
            return "Resolved[" + "records=" + records + ", " + "reads=" + reads + "]";
        }
    }

    /** Pages a byte range starting at {@code offset} covers. */
    private int pagesSpanned(long offset, int length) {
        int pageSize = pager.pageSize();
        long first = offset / pageSize;
        long last = (offset + Math.max(1, length) - 1) / pageSize;
        return (int) (last - first + 1);
    }

    /**
     * Decodes a record read from {@code seg} at {@code offset}.
     *
     * <p>The framing is the segment's head byte 39 (14 §5.2, F-073), never
     * whether the database has a key: a file converted in place (§8.3) holds
     * segments of both kinds.
     */
    public VlogSegment.Record decodeAt(VlogSegment seg, byte[] buf, long offset) {
        return decodeAt(seg, buf, offset, false);
    }

    /**
     * {@code keysOnly} skips materialising the value — see
     * {@code VlogSegment.decodeRecordKeyOnly}. It is honoured only in the clear:
     * an encrypted record is one AEAD unit, so its value cannot be left
     * undecrypted without also leaving it unauthenticated.
     */
    public VlogSegment.Record decodeAt(VlogSegment seg, byte[] buf, long offset, boolean keysOnly) {
        if (seg.encrypted != 0 && cipher != null && readOnlyCiphers.isEmpty()) {
            return VlogSegment.decodeEncryptedRecord(buf, 0, buf.length, seg.segmentId, offset, cipher);
        }
        if (seg.encrypted != 0) {
            List<FileCipher> rings = new ArrayList<>();
            if (cipher != null) {
                rings.add(cipher);
            }
            rings.addAll(readOnlyCiphers);
            if (rings.isEmpty()) {
                throw new org.dizitart.cryptand.CannotUnlockException(
                        "value-log segment " + seg.segmentId + " is encrypted and no key is available");
            }
            // Re-encrypted after a decrypt that a snapshot outlived: the
            // segment may be sealed under a retained master. The tag decides,
            // so trying each is safe.
            org.dizitart.cryptand.TamperingException first = null;
            for (FileCipher c : rings) {
                try {
                    return VlogSegment.decodeEncryptedRecord(buf, 0, buf.length, seg.segmentId, offset, c);
                } catch (org.dizitart.cryptand.TamperingException x) {
                    first = first == null ? x : first;
                }
            }
            throw first;
        }
        if (cipher != null) {
            // ponytail: F-076, Dart writes head byte 0 on encrypted segments,
            // so with a key in hand a byte-0 segment may be either. A clear
            // record whose CRC fails is tried as encrypted, whose tag is the
            // authority. Drop the fallback once Dart writes the byte (M5).
            try {
                return VlogSegment.decodeRecord(buf, 0, buf.length);
            } catch (RuntimeException clearFailed) {
                return VlogSegment.decodeEncryptedRecord(buf, 0, buf.length, seg.segmentId, offset, cipher);
            }
        }
        return keysOnly
                ? VlogSegment.decodeRecordKeyOnly(buf, 0, buf.length)
                : VlogSegment.decodeRecord(buf, 0, buf.length);
    }

    private Open openOf(long id) {
        for (Open o : hot.values()) {
            if (o.seg.segmentId == id) {
                return o;
            }
        }
        return cold != null && cold.seg.segmentId == id ? cold : null;
    }

    private long durableBytesOf(long id) {
        return statsOf(id).bytes;
    }

    // ==================================================================
    // tree 7
    // ==================================================================

    /**
     * Writes every open segment's watermark and counters into tree 7. Called by
     * the committer, in the ordinary commit path — which is precisely what
     * {@code 10-transactions.md} §2.3 requires of the watermark.
     */
    /**
     * Whether the committer's value-log barrier (§2 step C) has anything to
     * cover. Skipping it when nothing was appended is not a shortcut: §2.3's
     * first ordering invariant is that a superblock must not name a segment
     * whose value-log records are not already durable, and a commit that
     * appended none has none to make durable.
     */
    public synchronized boolean consumeAppendFlag() {
        boolean any = appendedSinceBarrier;
        appendedSinceBarrier = false;
        return any;
    }

    public synchronized void publishStats() {
        for (Open o : hot.values()) {
            publish(o, false);
        }
        if (cold != null) {
            publish(cold, false);
        }
    }

    private void publish(Open o, boolean sealNow) {
        // **The publish half of the watermark-hole protocol.** `bytes` below is
        // the contiguous watermark, which is the right answer for recovery and
        // the wrong one for a segment that is about to stop being open: once
        // `completed` is gone, `Open.covers` is gone with it and tree 7's
        // `bytes` is the only thing a read can consult. Sealing with a hole
        // still open would leave every record beyond it permanently
        // unreadable — written, checksummed, and unreachable.
        //
        // So a seal drains first. It is rare — once per `vlog_segment_bytes` —
        // and a hole is one `pwrite` wide, so this waits for microseconds or,
        // as long as appends are serialized, not at all.
        if (sealNow) {
            drain(o);
        }
        VlogStats s = existing(o.seg.segmentId);
        s.segmentId = o.seg.segmentId;
        s.bytes = o.watermark - o.seg.dataOffset;
        s.records = o.records;
        s.sealed = sealNow;
        s.startPage = o.seg.startPage;
        s.pages = o.seg.pages;
        // The delta since the last publish, not the maximum. Taking the maximum
        // re-raises a count that a compaction has just decremented, which is
        // "overstating" - safe by §6.7, and it also means an open segment can
        // never be collected, because its liveness never falls.
        s.liveBytes += o.liveBytes - o.publishedLiveBytes;
        s.liveRecords += o.liveRecords - o.publishedLiveRecords;
        o.publishedLiveBytes = o.liveBytes;
        o.publishedLiveRecords = o.liveRecords;
        s.tier = o.seg.tier;
        s.heat = o.seg.heatClass;
        s.createdSeq = o.seg.createdSeq;
        if (sealNow) {
            // §6.2: `clustered` is known only at seal, and an implementation
            // MUST set it only when the ordering actually holds.
            s.clustered = o.sorted && o.seg.tier == VlogSegment.TIER_COLD;
            if (s.clustered) {
                s.minKey = o.minKey;
                s.maxKey = o.maxKey;
            }
        }
        statsTree.put(s.key(), Cve.encode(s.toValue()));
    }

    /**
     * Waits until every reservation in {@code o} has landed, so
     * {@code watermark == tail} and the contiguous prefix covers the whole
     * segment. Called before a seal — see {@link #publish}.
     *
     * <p>It <strong>waits rather than spins</strong>, and that is not a style
     * choice: this runs holding the monitor, and the appender it is waiting for
     * needs that same monitor to fold its range in. A spin here deadlocks the
     * moment appends stop being serialized, which is the exact change this
     * protocol exists to allow. {@link Object#wait} releases the monitor;
     * {@code completeWrite} signals.
     */
    private void drain(Open o) {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
        while (!o.quiesced()) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                throw new CorruptionException("value-log segment " + o.seg.segmentId
                        + " still has writes in flight at seal: watermark " + o.watermark
                        + ", tail " + o.tail.get());
            }
            try {
                wait(Math.max(1, left / 1_000_000), (int) (left % 1_000_000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CorruptionException("interrupted draining value-log segment "
                        + o.seg.segmentId + " at seal");
            }
        }
    }

    private VlogStats existing(long id) {
        byte[] raw = statsTree.get(VlogStats.key(id));
        if (raw == null) {
            VlogStats s = new VlogStats();
            s.segmentId = id;
            return s;
        }
        return VlogStats.fromValue(VlogStats.key(id), Cve.decode(raw));
    }

    /**
     * {@code 13-operations.md} §5's {@code shrink()}: sealed segments, the only
     * ones that can move. An open one is still being appended to at its
     * current place, without the lock the mover holds.
     */
    public synchronized List<VlogStats> movable() {
        List<VlogStats> out = new ArrayList<>();
        for (VlogStats s : allStats()) {
            if (s.sealed && openOf(s.segmentId) == null) {
                out.add(s);
            }
        }
        return out;
    }

    /**
     * Moves a sealed segment's extent to {@code to}. Its head page is in the
     * clear and its records are sealed by segment id and offset
     * ({@code 14-security.md} §5.3), so the bytes move as they are; tree 7 is
     * the only thing that names the page.
     */
    public synchronized void relocate(VlogStats s, long to) {
        int pageSize = pager.pageSize();
        long from = pager.offsetOf(s.startPage);
        long end = Math.min(from + (long) s.pages * pageSize, pager.file().size());
        byte[] buf = new byte[(int) Math.min(end - from, 256L * pageSize)];
        for (long at = from; at < end; at += buf.length) {
            int n = (int) Math.min(buf.length, end - at);
            byte[] chunk = n == buf.length ? buf : new byte[n];
            pager.file().readFully(at, chunk, 0, n);
            pager.writeAt(pager.offsetOf(to) + (at - from), chunk);
        }
        s.startPage = to;
        statsTree.put(s.key(), Cve.encode(s.toValue()));
        VlogSegment seg = known.get(s.segmentId);
        if (seg != null) {
            seg.startPage = to;
        }
    }

    /** The tree-7 view of every segment the database knows about. */
    /**
     * Gives back every open segment that holds no record and that tree 7 never
     * named (M2.3). Its extent is reserved in full at allocation, and on a
     * full device the next publish, which extends the file to
     * {@code page_count}, can then never succeed: the engine stayed wedged
     * after space was freed. The next append opens a fresh one.
     */
    public synchronized void abandonEmptyOpen() {
        List<Open> empty = new ArrayList<>();
        for (Open o : hot.values()) {
            if (o.tail.get() == o.seg.dataOffset && statsTree.get(VlogStats.key(o.seg.segmentId)) == null) {
                empty.add(o);
            }
        }
        if (cold != null && cold.tail.get() == cold.seg.dataOffset
                && statsTree.get(VlogStats.key(cold.seg.segmentId)) == null) {
            empty.add(cold);
        }
        empty.sort((a, b) -> Long.compare(b.seg.startPage, a.seg.startPage)); // the tail unwinds
        for (Open o : empty) {
            hot.values().remove(o);
            if (cold == o) {
                cold = null;
            }
            known.remove(o.seg.segmentId);
            pager.abandonExtent(o.seg.startPage, o.seg.pages);
        }
    }

    /**
     * Open segments: owned since allocation, though tree 7 names them only from
     * the next publish (and on a full device that publish may keep failing).
     */
    public synchronized List<VlogSegment> openSegments() {
        List<VlogSegment> out = new ArrayList<>();
        hot.values().forEach(o -> out.add(o.seg));
        if (cold != null) {
            out.add(cold.seg);
        }
        return out;
    }

    public synchronized List<VlogStats> allStats() {
        List<VlogStats> out = new ArrayList<>();
        for (Map.Entry<byte[], byte[]> e : statsTree.map().entrySet()) {
            out.add(VlogStats.fromValue(e.getKey(), Cve.decode(e.getValue())));
        }
        return out;
    }

    /**
     * Recomputes every segment's liveness exactly, by walking its records and
     * asking the trees.
     *
     * <p>§6.7 allows this explicitly — "a verifier can recompute it exactly" —
     * and it is used here in preference to an incremental counter. An
     * incremental one has to be decremented once and only once per record, from
     * three places (compaction dropping a version, promotion retiring a hot
     * copy, GC retiring a whole run), and a double decrement clamps the count to
     * zero, which makes a fully live run look collectable and a healthy database
     * look 100 % in debt. It was wrong twice before this replaced it.
     *
     * <p><em>ponytail: one pass over the value log per maintenance cycle.</em>
     * The ceiling is the live value-log size; an incremental counter is the
     * upgrade if a maintenance pass ever cannot afford the scan, and it needs
     * the exact version to check itself against.
     */
    /** One record of a walk: where it starts, how long it is, and what it holds. */
    public static final class Walked {
        private final long offset;
        private final int length;
        private final VlogSegment.Record record;

        public Walked(long offset, int length, VlogSegment.Record record) {
            this.offset = offset;
            this.length = length;
            this.record = record;
        }

        public long offset() {
            return offset;
        }

        public int length() {
            return length;
        }

        public VlogSegment.Record record() {
            return record;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Walked)) {
                return false;
            }
            Walked that = (Walked) o;
            return offset == that.offset
                    && length == that.length
                    && java.util.Objects.equals(record, that.record);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(offset, length, record);
        }

        @Override
        public String toString() {
            return "Walked[" + "offset=" + offset + ", " + "length=" + length + ", " + "record=" + record + "]";
        }
    }

    /**
     * Walks a segment's records from {@code data_offset} to its durable
     * watermark, stopping at the first one that does not decode.
     *
     * <p>Stopping rather than throwing is the whole point. A value-log segment
     * another implementation wrote may end in bytes this one cannot frame — a
     * reserved-but-unwritten hole below the tail (§6.2), or a watermark
     * measured from a different origin — and none of the three callers here is
     * doing anything that a short walk makes wrong: liveness may overstate,
     * GC skips what it did not see, and clustering merges what it did.
     *
     * @return whether the walk reached the watermark
     */
    public synchronized boolean walk(VlogStats stats, java.util.function.Consumer<Walked> consumer) {
        VlogSegment seg;
        try {
            seg = segment(stats.segmentId);
        } catch (RuntimeException e) {
            return false;
        }
        Open open = openOf(stats.segmentId);
        long end = open != null ? open.watermark : seg.dataOffset + stats.bytes;
        return walkTo(seg, end, consumer);
    }

    /**
     * The body of {@link #walk}, with the end offset supplied and
     * <strong>no lock held</strong>.
     *
     * <p>Everything below {@code end} is already written and never changes, so
     * reading it needs no exclusion. That is what lets
     * {@link #recomputeLiveness} scan a whole database without holding the
     * monitor every foreground append needs.
     */
    private boolean walkTo(VlogSegment seg, long end, java.util.function.Consumer<Walked> consumer) {
        return walkRange(seg, seg.dataOffset, end, consumer, false);
    }

    /** {@link #walkTo} that does not decode record values. */
    private boolean walkKeysTo(VlogSegment seg, long end, java.util.function.Consumer<Walked> consumer) {
        return walkRange(seg, seg.dataOffset, end, consumer, true);
    }

    /**
     * {@link #walkTo} from an arbitrary record boundary, so a scan can stop and
     * resume. {@code from} MUST be a record start — every caller gets one by
     * stopping only after a whole record.
     *
     * @return whether the walk reached {@code end}
     */
    private boolean walkRange(VlogSegment seg, long from, long end,
            java.util.function.Consumer<Walked> consumer) {
        return walkRange(seg, from, end, consumer, false);
    }

    private boolean walkRange(VlogSegment seg, long from, long end,
            java.util.function.Consumer<Walked> consumer, boolean keysOnly) {
        long offset = from;
        long base = pager.offsetOf(seg.startPage);

        // Read in windows rather than per record. The straightforward version
        // did **two** `readFully` calls for every record — 16 bytes to frame
        // it, then the record — and this method holds the value-log monitor
        // that every foreground append needs. At 20 000 documents that is
        // ~40 000 syscalls inside the lock, and it is what made a `put` wait
        // for a value-log GC pass: `10-transactions.md` §2.2's "An
        // implementation MUST NOT make a `put` wait for a compaction except
        // through explicit backpressure".
        //
        // ponytail: a fixed window, refilled when the next record does not fit
        // whole. A record larger than the window is read on its own, so the
        // window size is a throughput knob and never a limit.
        final int windowSize = 1 << 16;
        byte[] window = null;
        long windowAt = -1;
        int windowLen = 0;

        while (offset < end) {
            int total;
            VlogSegment.Record rec;
            try {
                if (window == null || offset < windowAt || offset + 16 > windowAt + windowLen) {
                    windowAt = offset;
                    windowLen = (int) Math.min(windowSize, end - offset);
                    window = new byte[windowLen];
                    pager.file().readFully(base + windowAt, window, 0, windowLen);
                }
                int at = (int) (offset - windowAt);
                ByteReader r = new ByteReader(java.util.Arrays.copyOfRange(
                        window, at, Math.min(at + 16, windowLen)));
                total = (int) (r.uvar() + r.consumed());
                if (total <= 0 || offset + total > end) {
                    return false;
                }
                byte[] buf;
                if (at + total <= windowLen) {
                    buf = java.util.Arrays.copyOfRange(window, at, at + total);
                } else {
                    // Straddles the window end, or is larger than it: read it
                    // directly and let the next iteration refill.
                    buf = new byte[total];
                    pager.file().readFully(base + offset, buf, 0, total);
                    window = null;
                }
                rec = decodeAt(seg, buf, offset, keysOnly);
            } catch (RuntimeException e) {
                return false;
            }
            consumer.accept(new Walked(offset, total, rec));
            offset += total;
        }
        return true;
    }

    /**
     * Answers whether a value-log record is still referenced by any tree entry
     * a reader can reach. See {@code Engine.livenessSeqs} for why "any" rather
     * than "the current one".
     */
    @FunctionalInterface
    public interface Liveness {
        boolean referenced(int treeId, byte[] key, long segmentId, long offset);
    }

    /**
     * Recomputes every value-log segment's live bytes and records.
     *
     * <p><strong>This is the foreground's worst stall, and it is still here.</strong>
     * It reads every record of every value-log segment while holding the
     * monitor every append needs, so a {@code put} waits for the whole scan —
     * against {@code 10-transactions.md} §2.2 ("An implementation MUST NOT make
     * a {@code put} wait for a compaction except through explicit
     * backpressure") and {@code 13-operations.md} §5 ("None may block longer
     * than {@code max_foreground_stall_ms} per step"). Sampling the CRUD matrix
     * found the main thread {@code BLOCKED} on this monitor with the compactor
     * holding it here, and it is what puts Java's p99.9 in the hundreds of
     * milliseconds against {@code desktop}'s 25 ms.
     *
     * <p>Two fixes were built and both were reverted, because each bought the
     * stall back with a correctness violation that a test caught:
     *
     * <ul>
     *   <li><strong>Scanning without the monitor</strong> (snapshot, scan,
     *       apply) measured ~30x on the mixed workload and raced: it published a
     *       durable watermark below records the tree already pointed at —
     *       "value-log pointer to segment 1 ends at 4163294, past the durable
     *       watermark 4161273", from the compactor.</li>
     *   <li><strong>A byte-budgeted resumable sweep</strong>, which is what §5
     *       actually asks for, <em>understated</em> liveness on a segment whose
     *       extent was not yet published when its sweep began — "value-log
     *       segment 15 declares 0 live bytes but holds 212346; liveness
     *       statistics MUST NOT understate" ({@code 04-segments.md} §6.7).
     *       Understating is the direction that frees a segment still holding
     *       live data.</li>
     * </ul>
     *
     * <p>A correct incremental version needs a segment's true extent before its
     * first publish, and needs partial counts to leave the previous value
     * standing rather than replace it. That is the fix; it is not this one, and
     * a stall is better than silent data loss.
     */
    /** One segment's state at the moment the scan below snapshotted it. */
    private static final class LivenessSnapshot {
        private final long segmentId;
        private final VlogSegment seg;
        private final long end;
        private final long records;

        public LivenessSnapshot(long segmentId, VlogSegment seg, long end, long records) {
            this.segmentId = segmentId;
            this.seg = seg;
            this.end = end;
            this.records = records;
        }

        public long segmentId() {
            return segmentId;
        }

        public VlogSegment seg() {
            return seg;
        }

        public long end() {
            return end;
        }

        public long records() {
            return records;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof LivenessSnapshot)) {
                return false;
            }
            LivenessSnapshot that = (LivenessSnapshot) o;
            return segmentId == that.segmentId
                    && java.util.Objects.equals(seg, that.seg)
                    && end == that.end
                    && records == that.records;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(segmentId, seg, end, records);
        }

        @Override
        public String toString() {
            return "LivenessSnapshot[" + "segmentId=" + segmentId + ", " + "seg=" + seg + ", " + "end=" + end + ", " + "records=" + records + "]";
        }
    }

    public void recomputeLiveness(Liveness live) {
        List<LivenessSnapshot> snapshot = new ArrayList<>();
        synchronized (this) {
            for (VlogStats s : allStats()) {
                VlogSegment seg;
                try {
                    seg = segment(s.segmentId);
                } catch (RuntimeException e) {
                    continue;
                }
                Open open = openOf(s.segmentId);
                long end = open != null ? open.watermark : seg.dataOffset + s.bytes;
                snapshot.add(new LivenessSnapshot(s.segmentId, seg, end,
                        open != null ? open.records : s.records));
            }
        }

        Map<Long, long[]> counted = new java.util.LinkedHashMap<>();
        for (LivenessSnapshot snap : snapshot) {
            long[] counts = new long[2];
            walkKeysTo(snap.seg(), snap.end(), w -> {
                if (live.referenced(w.record().treeId(), w.record().key(),
                        snap.segmentId(), w.offset())) {
                    counts[0] += w.length();
                    counts[1]++;
                }
            });
            counted.put(snap.segmentId(), counts);
        }

        synchronized (this) {
            Map<Long, VlogStats> current = new java.util.LinkedHashMap<>();
            for (VlogStats st : allStats()) {
                current.put(st.segmentId, st);
            }
            for (LivenessSnapshot snap : snapshot) {
                long[] counts = counted.get(snap.segmentId());
                VlogStats s = current.get(snap.segmentId());
                if (counts == null || s == null) {
                    continue;
                }
                long liveBytes = counts[0];
                long liveRecords = counts[1];
                Open open = openOf(snap.segmentId());
                if (open != null) {
                    // F-051: to the reserved tail, not the watermark. `append`
                    // counts a record live when it reserves it; one reserved
                    // before the snapshot and completed after was neither
                    // walked nor credited, and this overwrite lost it for good.
                    liveBytes += Math.max(0, open.tail.get() - snap.end());
                    liveRecords += Math.max(0, open.records - snap.records());
                } else {
                    // F-052: sealed during the walk (a foreground append overflowed
                    // it). Its records past the snapshot were not walked either;
                    // the seal fixed its extent, so credit them all.
                    liveBytes += Math.max(0, snap.seg().dataOffset + s.bytes - snap.end());
                    liveRecords += Math.max(0, s.records - snap.records());
                }
                s.liveBytes = liveBytes;
                s.liveRecords = liveRecords;
                statsTree.put(s.key(), Cve.encode(s.toValue()));
                if (open != null) {
                    open.liveBytes = liveBytes;
                    open.liveRecords = liveRecords;
                    open.publishedLiveBytes = liveBytes;
                    open.publishedLiveRecords = liveRecords;
                }
            }
        }
    }

    /**
     * Adjusts a segment's live counters downward. Never upward: §6.7 forbids
     * understating.
     *
     * <p>A segment with no tree-7 entry has been collected and its extent
     * freed, so there is nothing to decrement. Creating one here would write a
     * record of default fields — tier HOT, start page 0 — over an id whose head
     * page says otherwise, which §11 invariant 8b classes as corruption.
     */
    public void recordDead(long segmentId, long bytes, long records) {
        if (statsTree.get(VlogStats.key(segmentId)) == null) {
            return;
        }
        VlogStats s = existing(segmentId);
        s.liveBytes = Math.max(0, s.liveBytes - bytes);
        s.liveRecords = Math.max(0, s.liveRecords - records);
        statsTree.put(s.key(), Cve.encode(s.toValue()));
    }

    private void seal(Open o) {
        publish(o, true);
    }

    /**
     * Seals the open cold segment, if any.
     *
     * <p>Called at the end of a last-level compaction, because that is when a
     * promoted <em>generation</em> is complete. §6.2 says {@code clustered} is
     * known only at seal, so a cold run that is never sealed reads as
     * unclustered and its live bytes count as surplus — which puts a healthy
     * database above §6.9's bound for no reason a collection could fix.
     */
    public synchronized void sealCold() {
        if (cold != null) {
            seal(cold);
            cold = null;
        }
    }

    /** Seals every open segment — {@code 10-transactions.md} §10 step 2. */
    public synchronized void sealAll() {
        for (Open o : hot.values()) {
            seal(o);
        }
        hot.clear();
        if (cold != null) {
            seal(cold);
            cold = null;
        }
    }

    /**
     * {@code locality_debt} — {@code spec/04-segments.md} §6.9.
     *
     * <p>Over the <strong>cold tier only</strong>. An earlier draft of the spec
     * omitted that qualifier, and both reference implementations then read
     * 100 % on a freshly loaded database: a hot run is unclustered by
     * construction, because §6.3 clusters a generation when it is
     * <em>promoted</em>. The denominator stays all live value-log bytes.
     */
    public double localityDebt() {
        List<VlogStats> cold = new ArrayList<>();
        long totalLive = 0;
        for (VlogStats s : allStats()) {
            if (s.liveBytes == 0) {
                continue;
            }
            totalLive += s.liveBytes;
            if (s.tier == VlogSegment.TIER_COLD) {
                cold.add(s);
            }
        }
        if (totalLive == 0) {
            return 0;
        }
        long coldLive = 0;
        for (VlogStats s : cold) {
            coldLive += s.liveBytes;
        }
        int idealRuns = (int) Math.max(1, (coldLive + segmentBytes - 1) / segmentBytes);
        cold.sort((a, b) -> Long.compare(b.liveBytes, a.liveBytes));
        long surplus = 0;
        for (int i = 0; i < cold.size(); i++) {
            VlogStats s = cold.get(i);
            // Live bytes in a cold run that is not key-clustered are surplus
            // regardless of where it sorts.
            if (i >= idealRuns || !s.clustered) {
                surplus += s.liveBytes;
            }
        }
        return (double) surplus / totalLive;
    }
}
