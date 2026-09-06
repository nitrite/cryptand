package org.dizitart.cryptand;

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
public final class Vlog {

    /** An open, appendable segment. */
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
    private FileCipher cipher;

    /** Installs the record cipher. Null means the value log is written in the clear. */
    public void setCipher(FileCipher cipher) {
        this.cipher = cipher;
    }

    public Vlog(Pager pager, PageTree statsTree, int segmentBytes, long nextSegmentId) {
        this.pager = pager;
        this.statsTree = statsTree;
        this.segmentBytes = segmentBytes;
        this.nextSegmentId = new AtomicLong(nextSegmentId);
    }

    public long nextSegmentId() {
        return nextSegmentId.get();
    }

    public void setCurrentSeq(long seq) {
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
    public void sealOrphans() {
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

    /** Appends one record to the hot tier, routed by heat class. */
    public VlogPointer append(int treeId, byte[] cke, byte[] value, int heatClass) {
        return appendTo(openHot(heatClass), treeId, cke, value);
    }

    /**
     * Appends to the cold tier. Used by promotion during last-level compaction
     * (§6.3) and by a bulk writer with a sorted batch (§6.3's last bullet),
     * which may skip the hot tier and the promotion write entirely.
     */
    public VlogPointer appendCold(int treeId, byte[] cke, byte[] value) {
        return appendTo(openCold(), treeId, cke, value);
    }

    private VlogPointer appendTo(Open open, int treeId, byte[] cke, byte[] value) {
        VlogSegment.Record rec = new VlogSegment.Record(treeId, cke, value);
        // The size has to be known before the reservation, because the
        // reservation fixes the offset and §5.3 puts the offset in the nonce.
        int size = cipher == null
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
            Open fresh = open.seg.tier == VlogSegment.TIER_COLD
                    ? openCold(true)
                    : openHot(open.seg.heatClass, true);
            return appendTo(fresh, treeId, cke, value);
        }
        byte[] record = cipher == null
                ? rec.encode()
                : VlogSegment.encodeEncrypted(rec, open.seg.segmentId, offset, cipher, cipher.allocateNonce());
        if (record.length != size) {
            throw new IllegalStateException("value-log record sized " + size
                    + " but encoded to " + record.length);
        }
        pager.file().write(pager.offsetOf(open.seg.startPage) + offset, record);
        appendedSinceBarrier = true;
        complete(open, offset, end);
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
        return new VlogPointer(open.seg.segmentId, offset, size);
    }

    /** Folds a completed reservation into the contiguous watermark. */
    private void complete(Open open, long start, long end) {
        open.completed.put(start, end);
        Map.Entry<Long, Long> first;
        while ((first = open.completed.firstEntry()) != null && first.getKey() <= open.watermark) {
            open.completed.pollFirstEntry();
            open.watermark = Math.max(open.watermark, first.getValue());
        }
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
        s.encrypted = cipher == null ? 0 : 1;
        s.nonceBase = cipher == null ? 0 : cipher.nextNonceWatermark();
        s.startPage = start;
        s.pages = pages;

        writeHead(pager, start, pages, s);
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
        pager.file().write(pager.offsetOf(start), page);
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

    public VlogSegment segment(long id) {
        VlogSegment s = known.get(id);
        if (s != null) {
            return s;
        }
        byte[] raw = statsTree.get(VlogStats.key(id));
        if (raw == null) {
            throw new CorruptionException("value-log segment " + id + " has no entry in tree 7");
        }
        VlogStats st = VlogStats.fromValue(VlogStats.key(id), Cve.decode(raw));
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
    public VlogSegment.Record read(VlogPointer p) {
        Open open = openOf(p.segmentId());
        VlogSegment s = open != null ? open.seg : segment(p.segmentId());
        // §6.4: `offset + len` must be at most `data_offset + bytes`. Tree 7's
        // `bytes` counts record space, so the extent-relative watermark the
        // pointer is checked against is `data_offset` plus it.
        long watermark = open != null ? open.watermark : s.dataOffset + durableBytesOf(p.segmentId());
        if (p.offset() + p.len() > watermark) {
            throw new CorruptionException("value-log pointer to segment " + p.segmentId() + " ends at "
                    + (p.offset() + p.len()) + ", past the durable watermark " + watermark);
        }
        byte[] buf = new byte[(int) p.len()];
        pager.file().readFully(pager.offsetOf(s.startPage) + p.offset(), buf, 0, buf.length);
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
    public Resolved readMany(List<VlogPointer> pointers) {
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
            byte[] window = new byte[(int) (to - from)];
            pager.file().readFully(pager.offsetOf(seg.startPage) + from, window, 0, window.length);
            reads++;
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
    public record Resolved(List<VlogSegment.Record> records, int reads) {
    }

    /**
     * Decodes a record read from {@code seg} at {@code offset}.
     *
     * <p>The framing is chosen by whether <em>the database</em> has a key, not
     * by the head page's {@code encrypted} byte. §6.2 makes that byte the
     * per-segment truth and this implementation writes it correctly, but the
     * Dart reference writes 0 on an encrypted file, and refusing to read those
     * segments would fail the round-trip gate over a file whose records are
     * perfectly well formed. There is no ambiguity to resolve either way: the
     * per-page mixture {@code 14-security.md} §8.3 allows during a conversion is
     * about pages, and no writer produces a value log with both framings in one
     * database.
     */
    public VlogSegment.Record decodeAt(VlogSegment seg, byte[] buf, long offset) {
        return cipher == null
                ? VlogSegment.decodeRecord(buf, 0, buf.length)
                : VlogSegment.decodeEncryptedRecord(buf, 0, buf.length, seg.segmentId, offset, cipher);
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
        byte[] raw = statsTree.get(VlogStats.key(id));
        if (raw == null) {
            throw new CorruptionException("value-log segment " + id + " has no entry in tree 7");
        }
        VlogStats st = VlogStats.fromValue(VlogStats.key(id), Cve.decode(raw));
        return st.bytes;
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
    public boolean consumeAppendFlag() {
        boolean any = appendedSinceBarrier;
        appendedSinceBarrier = false;
        return any;
    }

    public void publishStats() {
        for (Open o : hot.values()) {
            publish(o, false);
        }
        if (cold != null) {
            publish(cold, false);
        }
    }

    private void publish(Open o, boolean sealNow) {
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

    private VlogStats existing(long id) {
        byte[] raw = statsTree.get(VlogStats.key(id));
        if (raw == null) {
            VlogStats s = new VlogStats();
            s.segmentId = id;
            return s;
        }
        return VlogStats.fromValue(VlogStats.key(id), Cve.decode(raw));
    }

    /** The tree-7 view of every segment the database knows about. */
    public List<VlogStats> allStats() {
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
    public record Walked(long offset, int length, VlogSegment.Record record) {
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
    public boolean walk(VlogStats stats, java.util.function.Consumer<Walked> consumer) {
        VlogSegment seg;
        try {
            seg = segment(stats.segmentId);
        } catch (RuntimeException e) {
            return false;
        }
        Open open = openOf(stats.segmentId);
        long end = open != null ? open.watermark : seg.dataOffset + stats.bytes;
        long offset = seg.dataOffset;
        while (offset < end) {
            int total;
            VlogSegment.Record rec;
            try {
                byte[] head = new byte[(int) Math.min(16, end - offset)];
                pager.file().readFully(pager.offsetOf(seg.startPage) + offset, head, 0, head.length);
                ByteReader r = new ByteReader(head);
                total = (int) (r.uvar() + r.consumed());
                if (total <= 0 || offset + total > end) {
                    return false;
                }
                byte[] buf = new byte[total];
                pager.file().readFully(pager.offsetOf(seg.startPage) + offset, buf, 0, total);
                rec = decodeAt(seg, buf, offset);
            } catch (RuntimeException e) {
                return false;
            }
            consumer.accept(new Walked(offset, total, rec));
            offset += total;
        }
        return true;
    }

    public void recomputeLiveness(java.util.function.BiFunction<Integer, byte[], VlogPointer> live) {
        for (VlogStats s : allStats()) {
            long[] counts = new long[2];
            walk(s, w -> {
                // §6.8's first invariant: a record is live ONLY if the tree's
                // current entry for its key is a VLOG pointer to this exact
                // (segment_id, offset). A key match alone is not sufficient,
                // because a superseded record carries the same key.
                VlogPointer p = live.apply(w.record().treeId(), w.record().key());
                if (p != null && p.segmentId() == s.segmentId && p.offset() == w.offset()) {
                    counts[0] += w.length();
                    counts[1]++;
                }
            });
            s.liveBytes = counts[0];
            s.liveRecords = counts[1];
            statsTree.put(s.key(), Cve.encode(s.toValue()));
            Open open = openOf(s.segmentId);
            if (open != null) {
                open.liveBytes = counts[0];
                open.liveRecords = counts[1];
                open.publishedLiveBytes = counts[0];
                open.publishedLiveRecords = counts[1];
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
    public void sealCold() {
        if (cold != null) {
            seal(cold);
            cold = null;
        }
    }

    /** Seals every open segment — {@code 10-transactions.md} §10 step 2. */
    public void sealAll() {
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
