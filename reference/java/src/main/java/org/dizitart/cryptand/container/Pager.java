package org.dizitart.cryptand.container;

import org.dizitart.cryptand.CannotUnlockException;
import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.UnsupportedFeatureException;
import org.dizitart.cryptand.crypto.PageCrypto;
import org.dizitart.cryptand.crypto.XChaCha20Poly1305;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.util.Lz4;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Space management — {@code spec/01-container.md} §6.
 *
 * <p>The allocation unit is the <strong>extent</strong>: one or more contiguous
 * pages. Allocation is best-fit from the free tree among extents freed at or
 * below {@code min_retained_commit}, and failing that the file is extended at
 * {@code page_count}.
 *
 * <p>The free tree (tree 1) is the durable record; this class holds the same
 * set in memory and the committer writes it back. That is deliberate: an
 * allocation may be needed <em>while</em> the free tree itself is being written,
 * and a structure that must allocate in order to record an allocation has a
 * cycle in it.
 *
 * <p>Nothing here ever overwrites a page a live superblock references. That
 * single rule is what makes recovery O(1) and torn pages impossible, and every
 * method below is written so that it holds without a special case.
 */
public final class Pager {

    /** An extent on the free list: {@code pages} pages at {@code startPage}, freed at {@code commitId}. */
    public static final class FreeExtent {
        private final long commitId;
        private final long startPage;
        private final int pages;

        public FreeExtent(long commitId, long startPage, int pages) {
            this.commitId = commitId;
            this.startPage = startPage;
            this.pages = pages;
        }

        public long commitId() {
            return commitId;
        }

        public long startPage() {
            return startPage;
        }

        public int pages() {
            return pages;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof FreeExtent)) {
                return false;
            }
            FreeExtent that = (FreeExtent) o;
            return commitId == that.commitId
                    && startPage == that.startPage
                    && pages == that.pages;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(commitId, startPage, pages);
        }

        @Override
        public String toString() {
            return "FreeExtent[" + "commitId=" + commitId + ", " + "startPage=" + startPage + ", " + "pages=" + pages + "]";
        }
    }

    private final PageFile file;
    private final int pageSize;
    private long pageCount;
    private long commitId;
    private long minRetainedCommit;

    private final List<FreeExtent> free = new ArrayList<>();
    /** Extents freed during the commit in progress; they join {@link #free} when it publishes. */
    private final List<FreeExtent> pendingFree = new ArrayList<>();
    // Allocation and freeing are synchronized. 01 §10 permits exactly this
    // shape: "the only serialization point is a fetch_add on next_seq, plus a
    // short critical section when the manifest edit is published" - taking a
    // byte range in the value log and inserting into a memtable shard, which
    // is the whole of the write path, take no lock here.

    private PageCrypto crypto;

    /**
     * {@code 01-container.md} §7's {@code page_codec}: the <strong>default</strong>
     * for newly written pages, never a property of the file. A page's own state
     * is in its {@code flags.COMPRESSED} and {@code codec_or_reserved}, so a
     * file may hold a mixture and the default may change without a rewrite.
     */
    private int pageCodec = Superblock.Codec.NONE;

    /**
     * Pages this pager has read from the file — {@code spec/11-conformance.md}
     * §6's aged-scan test measures a scan's cost with it, and there is no other
     * way to state that cost as a number. Value-log record reads are added by
     * {@link Engine} at the same point it counts a value read, so the counter
     * is the whole read cost of a scan and not only its key half.
     */
    private final java.util.concurrent.atomic.AtomicLong pageReads =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * {@code 12-profiles.md} §1's page cache, in access order so the eldest
     * entry is the least recently used. Guarded by its own monitor rather than
     * the pager's, because reads must not serialize against the write path.
     */
    private final java.util.LinkedHashMap<Long, byte[]> cache =
            new java.util.LinkedHashMap<>(64, 0.75f, true);
    /**
     * Decoded page payloads, guarded by the same monitor as {@link #cache} and
     * sharing its budget. See {@link #readPage}.
     */
    private final java.util.LinkedHashMap<Long, byte[]> payloads =
            new java.util.LinkedHashMap<>(64, 0.75f, true);
    /** One parsed page in {@link #treeSlots}. Immutable, so publishing it publishes the page. */
    private static final class Cached {
        private final long pageId;
        private final BtreePage page;

        public Cached(long pageId, BtreePage page) {
            this.pageId = pageId;
            this.page = page;
        }

        public long pageId() {
            return pageId;
        }

        public BtreePage page() {
            return page;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Cached)) {
                return false;
            }
            Cached that = (Cached) o;
            return pageId == that.pageId
                    && java.util.Objects.equals(page, that.page);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(pageId, page);
        }

        @Override
        public String toString() {
            return "Cached[" + "pageId=" + pageId + ", " + "page=" + page + "]";
        }
    }

    /**
     * Parsed B+tree pages — {@link #readTreePage} — in a
     * <strong>direct-mapped</strong> cache: slot {@code pageId & treeMask},
     * one entry per slot, replacement on collision.
     *
     * <p>Not an LRU, and deliberately. This is the read path's innermost loop:
     * a point lookup descends three levels, so an LRU costs three monitor
     * enters and three access-order restructures of a {@code LinkedHashMap}
     * keyed by a boxed {@code Long} — {@code Long.equals} showed up in the read
     * profile by name. A direct-mapped hit is one volatile array load and one
     * {@code long} compare, with no lock at all, so readers never meet.
     *
     * <p>What it gives up is conflict misses: two hot pages that collide evict
     * each other. A B+tree descent touches a root, an internal page and a leaf,
     * and the array is sized from the profile's own budget, so collisions are
     * rare and a miss costs a re-read that was already the uncached price.
     *
     * <p>ponytail: direct-mapped, and the upgrade path if a workload ever shows
     * conflict thrash is 2-way set associativity — two slots per index and the
     * older of the pair replaced — which does not change the accounting below.
     */
    private static final class Slots {
        private final java.util.concurrent.atomic.AtomicReferenceArray<Cached> a;
        private final int mask;

        public Slots(java.util.concurrent.atomic.AtomicReferenceArray<Cached> a, int mask) {
            this.a = a;
            this.mask = mask;
        }

        public java.util.concurrent.atomic.AtomicReferenceArray<Cached> a() {
            return a;
        }

        public int mask() {
            return mask;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Slots)) {
                return false;
            }
            Slots that = (Slots) o;
            return java.util.Objects.equals(a, that.a)
                    && mask == that.mask;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(a, mask);
        }

        @Override
        public String toString() {
            return "Slots[" + "a=" + a + ", " + "mask=" + mask + "]";
        }

        Slots(int size) {
            this(new java.util.concurrent.atomic.AtomicReferenceArray<>(size), size - 1);
        }
    }

    /** Volatile and replaced whole, so a resize can never pair one array with another's mask. */
    private volatile Slots treeSlots = new Slots(1024);
    /** Occupied slots of {@link #treeSlots}, for {@link #enforceBudget}. */
    private final java.util.concurrent.atomic.AtomicInteger treeResident =
            new java.util.concurrent.atomic.AtomicInteger();
    private long pageCacheBytes = 64L * 1024 * 1024;
    private final java.util.concurrent.atomic.AtomicLong cacheHits =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong cacheMisses =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong cacheEvictions =
            new java.util.concurrent.atomic.AtomicLong();

    public Pager(PageFile file, int pageSize, long pageCount, long commitId, long minRetainedCommit) {
        Limits.checkPageSize(pageSize);
        this.file = file;
        this.pageSize = pageSize;
        this.pageCount = Math.max(2, pageCount);
        this.commitId = commitId;
        this.minRetainedCommit = minRetainedCommit;
    }

    public int pageSize() {
        return pageSize;
    }

    public long pageReads() {
        return pageReads.get();
    }

    /** Counts reads this class did not perform - value-log record reads. */
    public void countReads(long n) {
        pageReads.addAndGet(n);
    }

    /**
     * Payload bytes a page builder may lay out.
     *
     * <p>On an encrypted file this is 16 bytes shorter, and
     * {@code 14-security.md} §5.2 makes that a MUST rather than an
     * optimization: "a page builder MUST reserve the 16 bytes before it lays
     * out its payload", because a page filled to {@code page_size - 40} has
     * nowhere to put a tag, and a builder that discovers this at write time has
     * produced a page that cannot be written at all.
     */
    public int payloadSize() {
        return pageSize - PageHeader.BYTES - (crypto != null ? XChaCha20Poly1305.TAG_BYTES : 0);
    }

    /**
     * §7 — compress a payload if the default codec is set and it is worth it.
     *
     * <p>{@code null} means "store it as it is", which is the answer both for
     * {@code page_codec = 0} and for a payload that does not compress by §7's
     * 12.5 % margin: the two are the same decision to the caller, which is why
     * they are one return value.
     */
    private byte[] compress(PageHeader h, byte[] raw) {
        if (pageCodec == Superblock.Codec.NONE || raw.length == 0) {
            return null;
        }
        // A page belonging to a multi-page extent is never independently
        // compressed: an extent is a contiguous byte range (§3 gives its
        // interior pages no header at all) and its reader addresses it by
        // offset rather than through the page seam, so compressing its head
        // page moves every byte after the header without telling anyone. A
        // value-log segment's head page is appended into after it is written
        // (§6.2), so its bytes are not a payload that can be rewritten either.
        if (h.extentPages > 1 || h.pageType == PageHeader.Type.VLOG_SEGMENT) {
            return null;
        }
        if (pageCodec == Superblock.Codec.ZSTD) {
            throw new UnsupportedFeatureException(
                    "codec 2 (Zstd) needs feature bit ZSTD, which this build does not set");
        }
        if (pageCodec != Superblock.Codec.LZ4) {
            throw new CorruptionException("unknown codec id " + pageCodec);
        }
        byte[] out = Lz4.compress(raw);
        if (!Lz4.worthCompressing(raw.length, out.length)) {
            return null;
        }
        // Compressing then encrypting still has to leave room for the tag,
        // which is the whole of §5.2's reservation rule. Compression only ever
        // helps there, but the check is cheap and the alternative is a page
        // that cannot be written.
        return out.length <= payloadSize() ? out : null;
    }

    /** The whole payload area of a page, tag reservation included. */
    public int rawPayloadSize() {
        return pageSize - PageHeader.BYTES;
    }

    public long pageCount() {
        return pageCount;
    }

    public long commitId() {
        return commitId;
    }

    public void setCommitId(long id) {
        this.commitId = id;
    }

    public void setMinRetainedCommit(long c) {
        this.minRetainedCommit = c;
    }

    public long minRetainedCommit() {
        return minRetainedCommit;
    }

    public PageFile file() {
        return file;
    }

    /**
     * The default codec for newly written pages.
     *
     * <p>It comes from the file, not from this build's profile, so a desktop
     * that opens a phone's database keeps writing the codec the phone chose.
     */
    public void setPageCodec(int codec) {
        this.pageCodec = codec;
    }

    public int pageCodec() {
        return pageCodec;
    }

    /** Installs the page-level cipher. Null means the file is written in the clear. */
    public void setCrypto(PageCrypto crypto) {
        this.crypto = crypto;
    }

    public PageCrypto crypto() {
        return crypto;
    }

    public long offsetOf(long pageId) {
        return pageId * (long) pageSize;
    }

    // ==================================================================
    // allocation
    // ==================================================================

    /** Replaces the free list — used once, when the free tree is loaded at open. */
    public synchronized void loadFreeList(List<FreeExtent> extents) {
        free.clear();
        free.addAll(extents);
    }

    /** The durable free list, for the committer to write back into tree 1. */
    public synchronized List<FreeExtent> freeList() {
        List<FreeExtent> all = new ArrayList<>(free);
        all.addAll(pendingFree);
        all.sort(Comparator.comparingLong(FreeExtent::commitId).thenComparingLong(FreeExtent::startPage));
        return all;
    }

    /**
     * Allocates a contiguous extent of {@code pages} pages.
     *
     * <p>Best-fit first, among extents whose freeing commit has passed
     * {@code min_retained_commit} — an extent freed at commit {@code N} may be
     * reallocated only once no live reader holds a snapshot at or below
     * {@code N}. Failing that, the file grows at {@code page_count}.
     */
    public synchronized long allocate(int pages) {
        if (pages < 1) {
            throw new InvalidArgumentException("an extent is at least one page, asked for " + pages);
        }
        if (lowFirst) {
            long low = allocateBelow(pages, Long.MAX_VALUE);
            if (low >= 0) {
                return low;
            }
        }
        int best = -1;
        for (int i = 0; i < free.size(); i++) {
            FreeExtent e = free.get(i);
            if (e.commitId() > minRetainedCommit || e.pages() < pages) {
                continue;
            }
            if (best < 0 || e.pages() < free.get(best).pages()) {
                best = i;
            }
        }
        if (best >= 0) {
            FreeExtent e = free.remove(best);
            if (e.pages() > pages) {
                free.add(new FreeExtent(e.commitId(), e.startPage() + pages, e.pages() - pages));
            }
            return e.startPage();
        }
        long start = pageCount;
        pageCount += pages;
        return start;
    }

    /**
     * {@code shrink()}'s allocation order: the lowest-addressed fit rather than
     * the best fit, so everything written while it is set moves down.
     */
    private boolean lowFirst;

    public synchronized void setLowFirst(boolean on) {
        lowFirst = on;
    }

    /**
     * The lowest-addressed reclaimable extent that fits and starts below
     * {@code limit}, allocated; {@code -1} when there is none.
     */
    public synchronized long allocateBelow(int pages, long limit) {
        int best = -1;
        for (int i = 0; i < free.size(); i++) {
            FreeExtent e = free.get(i);
            if (e.commitId() > minRetainedCommit || e.pages() < pages || e.startPage() >= limit) {
                continue;
            }
            if (best < 0 || e.startPage() < free.get(best).startPage()) {
                best = i;
            }
        }
        if (best < 0) {
            return -1;
        }
        FreeExtent e = free.remove(best);
        if (e.pages() > pages) {
            free.add(new FreeExtent(e.commitId(), e.startPage() + pages, e.pages() - pages));
        }
        return e.startPage();
    }

    /** Whether a reclaimable extent ends exactly at {@code page}. */
    public synchronized boolean freeEndsAt(long page) {
        for (FreeExtent e : free) {
            if (e.commitId() <= minRetainedCommit && e.startPage() + e.pages() == page) {
                return true;
            }
        }
        return false;
    }

    /**
     * Merges adjacent reclaimable extents, so a run freed piecemeal (one
     * compaction input each) can take an extent bigger than any one piece. The
     * merged run keeps the newest {@code commit_id}, still reclaimable.
     */
    public synchronized void coalesceReclaimable() {
        List<FreeExtent> runs = new ArrayList<>();
        free.removeIf(e -> e.commitId() <= minRetainedCommit && runs.add(e));
        runs.sort(Comparator.comparingLong(FreeExtent::startPage));
        FreeExtent at = null;
        for (FreeExtent e : runs) {
            if (at != null && at.startPage() + at.pages() == e.startPage()
                    && (long) at.pages() + e.pages() <= Integer.MAX_VALUE) {
                at = new FreeExtent(Math.max(at.commitId(), e.commitId()), at.startPage(), at.pages() + e.pages());
                continue;
            }
            if (at != null) {
                free.add(at);
            }
            at = e;
        }
        if (at != null) {
            free.add(at);
        }
    }

    /**
     * Moves the end of the file down to {@code end}: reclaimable extents at or
     * past it leave the list, one straddling it is clipped. The file itself is
     * cut by {@link #truncateFile} once a superblock naming the new end is
     * durable.
     */
    public synchronized void cutAt(long end) {
        List<FreeExtent> clipped = new ArrayList<>();
        free.removeIf(e -> {
            if (e.commitId() > minRetainedCommit || e.startPage() + e.pages() <= end) {
                return false;
            }
            if (e.startPage() < end) {
                clipped.add(new FreeExtent(e.commitId(), e.startPage(), (int) (end - e.startPage())));
            }
            return true;
        });
        free.addAll(clipped);
        pageCount = end;
    }

    /**
     * Allocates by extending the file, never from the free list.
     *
     * <p>The free tree itself must be written this way. Its content is a
     * snapshot of the free list taken just before it is built, so an allocation
     * <em>out of</em> that list while building it would produce a page that the
     * tree records as free and the tree itself occupies — a double allocation,
     * which {@code 01-container.md} §9 classes as corruption rather than as a
     * repairable leak.
     */
    public synchronized long allocateFresh(int pages) {
        if (pages < 1) {
            throw new InvalidArgumentException("an extent is at least one page, asked for " + pages);
        }
        long start = pageCount;
        pageCount += pages;
        return start;
    }

    /**
     * Returns an extent to the free tree at the committing {@code commit_id}.
     *
     * <p>It does not become allocatable until {@code min_retained_commit}
     * reaches that id, which is what protects a long-running reader's pages.
     */
    public synchronized void freeExtent(long startPage, int pages) {
        // Past `page_count` is not the file's any more: `shrink()` lets the
        // old tree 1 go after moving the end below it.
        if (pages < 1 || startPage >= pageCount) {
            return;
        }
        pendingFree.add(new FreeExtent(commitId, startPage, pages));
        // {@link #readTreePage} says this path invalidates, and it did not: a
        // compacted-away segment stayed in the cache until LRU pressure found
        // it, so after one full compaction the cache held 33 MB of which 14 MB
        // was live. Nothing but a pinned snapshot reads a freed page, and the
        // bytes stay on the device until `min_retained_commit` passes them, so
        // that reader simply misses.
        for (long p = startPage; p < startPage + pages; p++) {
            invalidate(p);
        }
    }

    /** Called by the committer once the superblock naming this commit is durable. */
    public synchronized void publishFrees() {
        free.addAll(pendingFree);
        pendingFree.clear();
    }

    // ==================================================================
    // page I/O
    // ==================================================================

    /**
     * Reads one page and verifies its checksum, then decrypts and decompresses.
     *
     * <p>The order is normative ({@code 01-container.md} §7, §8): verify the
     * checksum, decrypt, then decompress — so a corrupt page is never fed to a
     * codec or a cipher.
     */
    public byte[] readPage(long pageId) {
        // **The cache holds decoded payloads, not raw pages.** A hit on a raw
        // page still had to be cloned, CRC-verified over the whole page, then
        // decrypted, decompressed and copied again — so a B+tree descent paid a
        // checksum per node on bytes that had already been checked and could
        // not have changed, because every write invalidates. A JFR profile of
        // the CRUD matrix put `Segment$Cursor.page` second only to `resolve`
        // for exactly that reason.
        //
        // A cached payload is verified once, at the miss that read it.
        //
        // <p><strong>The array is copied, and it must be.</strong> Returning
        // the cached array directly is tempting — a B+tree descent visits a
        // page per level and a compaction merges page after page, so the copy
        // is real — and it was measured at roughly 10% on the mixed workload.
        // It was also wrong: with the array shared, the CRUD matrix began
        // failing "the delete phase deleted nothing" about once in fifteen
        // runs, where the committed baseline was clean in thirty. Reverting
        // this single line, and nothing else, took it back to clean in thirty.
        //
        // Some caller mutates or otherwise takes ownership of what `readPage`
        // hands back; a read of every call site did not find it, which is
        // exactly why the copy stays until one does. A cache that is shared
        // needs the ownership rule enforced at the callers, not assumed here.
        byte[] hit;
        synchronized (cache) {
            hit = payloads.get(pageId);
        }
        if (hit != null) {
            cacheHits.incrementAndGet();
            return hit.clone();
        }
        cacheMisses.incrementAndGet();
        pageReads.incrementAndGet();
        byte[] page = new byte[pageSize];
        file.readFully(offsetOf(pageId), page, 0, pageSize);
        PageHeader h = PageHeader.verify(page, pageId);
        byte[] payload = decodePayload(page, h, pageId);
        admitPayload(pageId, payload);
        return payload.clone();
    }

    /**
     * Caches a decoded payload, evicting to stay inside
     * {@code 12-profiles.md} §1's budget. Pages 0 and 1 are excluded for the
     * same reason as in {@link #admit}: the engine writes the superblock slots
     * straight to the {@code PageFile}.
     */
    private void admitPayload(long pageId, byte[] payload) {
        if (pageId < 2) {
            return;
        }
        synchronized (cache) {
            payloads.put(pageId, payload);
            enforceBudget();
        }
    }

    /**
     * One B+tree page, <strong>parsed once and shared</strong>.
     *
     * <p>{@link #readPage} hands back a private copy because a caller owns what
     * it is given. A B+tree descent does not want one: it visits a page per
     * level, reads a header and runs a binary search, and never writes. Paying
     * an 8 KiB {@code clone} and a re-parse per level made
     * {@code Segment.Cursor.seek} the top frame of the read profile by a
     * factor of three.
     *
     * <p>Sharing is safe here and only here, because {@link BtreePage} is a
     * read-only view: every accessor copies out of the payload
     * ({@code key}, {@code leaf}, {@code internal}, {@code prefix}) and none
     * writes into it. The bytes stay valid because every path that changes a
     * page on the device — {@link #writePage}, {@link #writeAt},
     * {@link #freeExtent} — invalidates the page id here as well.
     */
    public BtreePage readTreePage(long pageId) {
        Slots slots = treeSlots;
        int slot = (int) (pageId & slots.mask());
        Cached hit = slots.a().get(slot);
        if (hit != null && hit.pageId() == pageId) {
            cacheHits.incrementAndGet();
            return hit.page();
        }
        cacheMisses.incrementAndGet();
        pageReads.incrementAndGet();
        byte[] page = new byte[pageSize];
        file.readFully(offsetOf(pageId), page, 0, pageSize);
        PageHeader h = PageHeader.verify(page, pageId);
        byte[] payload = decodePayload(page, h, pageId);
        BtreePage parsed = BtreePage.parse(payload, 0, payload.length);
        if (pageId >= 2 && slots == treeSlots
                && slots.a().getAndSet(slot, new Cached(pageId, parsed)) == null) {
            treeResident.incrementAndGet();
            synchronized (cache) {
                enforceBudget();
            }
        }
        return parsed;
    }

    /**
     * Admits a B+tree page the caller has just written at {@code pageId}, so
     * the next read of it does not have to fetch back bytes that were in memory
     * a moment ago.
     *
     * <p>{@link #writeAt} invalidates every page an extent write covers, which
     * is correct and necessary — an extent is freed, reallocated and rewritten,
     * and a stale cached page is a wrong answer. But a freshly built segment is
     * about to be read: a flush or a compaction hands the read path a segment
     * whose every page it just had, discards all of it, and then pays a
     * {@code pread} per page on first touch. Measured on the CRUD matrix, that
     * was <strong>0.34 page reads per point lookup</strong> on a dataset that
     * fits the cache several times over — the misses were all first touches of
     * pages the builder had just written.
     *
     * <p>Admitting the payload the builder already holds is not a cache warm-up
     * heuristic; it is declining to throw away what it has.
     */
    public void admitTreePage(long pageId, byte[] payload) {
        if (pageId < 2) {
            return;
        }
        Slots slots = treeSlots;
        int slot = (int) (pageId & slots.mask());
        if (slots.a().getAndSet(slot, new Cached(pageId, BtreePage.parse(payload, 0, payload.length)))
                == null) {
            treeResident.incrementAndGet();
            synchronized (cache) {
                enforceBudget();
            }
        }
    }

    /** Drops a parsed page, if the slot it maps to is holding it. */
    private void invalidateTree(long pageId) {
        Slots slots = treeSlots;
        int slot = (int) (pageId & slots.mask());
        Cached held = slots.a().get(slot);
        if (held != null && held.pageId() == pageId && slots.a().compareAndSet(slot, held, null)) {
            treeResident.decrementAndGet();
        }
    }

    /**
     * Copies {@code len} bytes starting at {@code offset} bytes into the file
     * out of the page cache, reading only the pages the range actually spans.
     *
     * <p>This is what a value-log record read wants. {@code Vlog} read its
     * records with a bare {@code readFully} on the {@code PageFile}: one
     * {@code pread} per document fetched, with the page cache — sitting right
     * there, holding the very page the record is in — bypassed entirely. A
     * value log is append-only and its records cluster by write order, so a
     * point read of a recently written document almost always lands in a page
     * some earlier read already brought in.
     *
     * <p>Extent bytes carry no page header of their own ({@code 04-segments.md}
     * §5): a value-log segment is a raw extent, so the unit cached here is the
     * raw page, the same one {@link #readRaw} serves, and no checksum is
     * implied by this call. The record's own checksum is still verified by the
     * caller, which is where {@code 04-segments.md} §5.1 puts it.
     */
    public void readExtentInto(long offset, byte[] dst, int dstOff, int len) {
        int copied = 0;
        while (copied < len) {
            long abs = offset + copied;
            long pageId = abs / pageSize;
            int within = (int) (abs - pageId * pageSize);
            int n = Math.min(len - copied, pageSize - within);
            byte[] page;
            synchronized (cache) {
                page = cache.get(pageId);
            }
            if (page != null) {
                cacheHits.incrementAndGet();
                System.arraycopy(page, within, dst, dstOff + copied, n);
            } else if (pageId * (long) pageSize + pageSize > file.size()) {
                // The last page of a growing extent is not there yet. A
                // value-log segment is preallocated logically but the file ends
                // at the last byte actually written, so the page holding the
                // newest record can be short. Read exactly what was asked for
                // and cache nothing: the page is still being filled.
                pageReads.incrementAndGet();
                file.readFully(abs, dst, dstOff + copied, n);
            } else {
                cacheMisses.incrementAndGet();
                pageReads.incrementAndGet();
                page = new byte[pageSize];
                file.readFully(pageId * (long) pageSize, page, 0, pageSize);
                admit(pageId, page);
                System.arraycopy(page, within, dst, dstOff + copied, n);
            }
            copied += n;
        }
    }

    /** The whole page as stored, checksum unverified. */
    public byte[] readRaw(long pageId) {
        if (pageId < 0) {
            throw new CorruptionException("negative page id " + pageId);
        }
        byte[] hit;
        synchronized (cache) {
            hit = cache.get(pageId);
        }
        if (hit != null) {
            cacheHits.incrementAndGet();
            // A copy, because callers own what they are handed and some of them
            // decode in place. The uncached path allocated a page per read too,
            // so this is not a new cost.
            return hit.clone();
        }
        cacheMisses.incrementAndGet();
        pageReads.incrementAndGet();
        byte[] page = new byte[pageSize];
        file.readFully(offsetOf(pageId), page, 0, pageSize);
        admit(pageId, page);
        return page;
    }

    /**
     * Caches a page and evicts until the resident set is inside
     * {@code 12-profiles.md} §1's budget.
     *
     * <p>This implementation had <strong>no page cache at all</strong>: every
     * {@code readRaw} was a real {@code readFully}, so a point lookup that
     * walks a segment's B+tree paid one I/O per node. Measured on the CRUD
     * matrix at 20 000 documents: <strong>228 page reads per point lookup</strong>,
     * 716 per update and 808 per delete, against 1 and 0 for the other two.
     *
     * <p>ponytail: a {@code LinkedHashMap} in access order is the eviction
     * policy, which is LRU and nothing more. Its ceiling is that it is one
     * global lock; if a profile ever wants a cache large enough for that to
     * show, shard it by {@code pageId} and the accounting below does not
     * change.
     */
    /**
     * Evicts from whichever of the two caches is larger until their combined
     * residency is inside {@code 12-profiles.md} §1's budget.
     *
     * <p>They share one budget because the profile states one. Giving each the
     * full figure would hold twice what {@code mobile} says it holds, which is
     * the decoration this budget stopped being.
     */
    private void enforceBudget() {
        while (resident() > 1 && (long) resident() * pageSize > pageCacheBytes) {
            java.util.LinkedHashMap<Long, byte[]> from =
                    payloads.size() >= cache.size() ? payloads : cache;
            java.util.Iterator<java.util.Map.Entry<Long, byte[]>> it = from.entrySet().iterator();
            if (!it.hasNext()) {
                // Only parsed pages are left, and those are bounded by the slot
                // array rather than evicted one at a time — `treeSlots` is
                // sized so that a full array is inside the budget.
                return;
            }
            it.next();
            it.remove();
            cacheEvictions.incrementAndGet();
        }
    }

    private int resident() {
        return cache.size() + payloads.size() + treeResident.get();
    }

    private void admit(long pageId, byte[] page) {
        // **Pages 0 and 1 are never cached.** They are the two superblock slots
        // ({@code 01-container.md} §2), and {@link
        // org.dizitart.cryptand.lsm.Engine} writes them straight to the
        // {@code PageFile} rather than through {@link #writePage} — so a cached
        // copy would go stale behind this class's back on every commit.
        // Excluding them is two pages of lost caching and one fewer invariant
        // to remember at a call site that is not in this file.
        if (pageId < 2) {
            return;
        }
        synchronized (cache) {
            cache.put(pageId, page);
            enforceBudget();
        }
    }

    /**
     * Drops a page from the cache. Called wherever the bytes on the device
     * change, so the cache can never serve a stale page.
     */
    private void invalidate(long pageId) {
        synchronized (cache) {
            cache.remove(pageId);
            payloads.remove(pageId);
        }
        invalidateTree(pageId);
    }

    /**
     * Writes bytes at a byte offset and invalidates every page they cover.
     *
     * <p><strong>Use this rather than {@code pager.file().write(...)}.</strong>
     * Whole extents are written in one I/O by {@code SegmentBuilder},
     * {@code Vlog}, {@code Blob} and {@code VectorRegion}, all of which reach
     * past {@link #writePage}. With a page cache in place that is a
     * correctness bug rather than a style one: a page freed, reallocated and
     * rewritten through one of those paths leaves the old bytes cached, and the
     * next read of that page id returns them. It showed up as
     * "subtree_entries sum to 11, its header declares 8" — a verifier finding
     * on a database that was written correctly and read stale.
     */
    public void writeAt(long offset, byte[] bytes) {
        file.write(offset, bytes);
        long first = offset / pageSize;
        long last = (offset + Math.max(1, bytes.length) - 1) / pageSize;
        synchronized (cache) {
            for (long p = first; p <= last; p++) {
                cache.remove(p);
                payloads.remove(p);
            }
        }
        for (long p = first; p <= last; p++) {
            invalidateTree(p);
        }
    }

    /** {@code 13-operations.md} §6's {@code page_cache_hit_rate}, as a count. */
    public long pageCacheHits() {
        return cacheHits.get();
    }

    public long pageCacheMisses() {
        return cacheMisses.get();
    }

    public long pageCacheEvictions() {
        return cacheEvictions.get();
    }

    /** Bytes of page currently resident. */
    public long pageCacheResidentBytes() {
        synchronized (cache) {
            return (long) resident() * pageSize;
        }
    }

    /** {@code 12-profiles.md} §1's budget for this pager. */
    public long pageCacheBudgetBytes() {
        return pageCacheBytes;
    }

    /** Sets the budget from the profile. Evicts immediately if it shrank. */
    public void pageCacheBytes(long bytes) {
        this.pageCacheBytes = Math.max(bytes, (long) pageSize * 4);
        // Half the budget's worth of slots for parsed pages, so a full slot
        // array can never take the budget on its own and the byte[] caches
        // always have room. Power of two, because the index is a mask.
        int want = (int) Math.min(1 << 20, Math.max(64, pageCacheBytes / pageSize / 2));
        int size = Integer.highestOneBit(want);
        if (size != treeSlots.a().length()) {
            treeSlots = new Slots(size);
            treeResident.set(0);
        }
        synchronized (cache) {
            enforceBudget();
        }
    }

    public PageHeader readHeader(long pageId) {
        byte[] page = readRaw(pageId);
        return PageHeader.verify(page, pageId);
    }

    /** The decoded payload of an already-read page. */
    public byte[] decodePayload(byte[] page, PageHeader h, long pageId) {
        int stored = h.storedBytes();
        byte[] body = new byte[stored];
        System.arraycopy(page, PageHeader.BYTES, body, 0, Math.min(stored, page.length - PageHeader.BYTES));
        if (h.isSet(PageHeader.Flags.ENCRYPTED)) {
            if (crypto == null) {
                throw new CannotUnlockException("page " + pageId + " is encrypted and no key is available");
            }
            body = crypto.decryptPage(body, h, pageId);
        }
        if (h.isSet(PageHeader.Flags.COMPRESSED)) {
            if (h.codecOrReserved == Superblock.Codec.ZSTD) {
                throw new UnsupportedFeatureException(
                        "this build cannot decompress Zstd (feature bit ZSTD)");
            }
            if (h.codecOrReserved != Superblock.Codec.LZ4) {
                throw new CorruptionException(
                        "unknown codec id " + h.codecOrReserved, pageId, null);
            }
            body = Lz4.decompress(body, h.payloadLen);
        }
        if (body.length != h.payloadLen) {
            throw new CorruptionException("page payload decoded to " + body.length
                    + " bytes, header declares " + h.payloadLen, pageId, null);
        }
        return body;
    }

    /**
     * Writes one page: compress, then encrypt, then checksum — the write-side
     * order of {@code 01-container.md} §8.
     */
    public synchronized void writePage(long pageId, PageHeader h, byte[] payload) {
        byte[] page = buildPage(pageId, h, payload);
        file.write(offsetOf(pageId), page);
        invalidate(pageId);
        if (pageId >= pageCount) {
            pageCount = pageId + 1;
        }
    }

    /**
     * A page that belongs to a multi-page extent: encrypted like any other, and
     * <strong>never compressed</strong>.
     *
     * <p>An extent is a contiguous byte range. {@code 01-container.md} §3 gives
     * its interior pages no header at all, and a reader may hold the whole
     * extent and parse pages at fixed offsets rather than fetching them one at
     * a time — which one of the three implementations does. Compressing a page
     * inside one moves every byte after its header without telling that reader,
     * and the failure surfaces as "segment header magic mismatch" in the
     * <em>other</em> language, several steps later.
     */
    public byte[] buildExtentPage(long pageId, PageHeader h, byte[] payload) {
        int saved = pageCodec;
        pageCodec = Superblock.Codec.NONE;
        try {
            return buildPage(pageId, h, payload);
        } finally {
            pageCodec = saved;
        }
    }

    /**
     * {@link #buildExtentPage}, written straight into {@code dst} at
     * {@code dstOff} rather than into an array of its own.
     *
     * <p>A segment is assembled in one buffer and written with one I/O, so
     * every page it holds was being allocated, filled, and then copied into
     * that buffer: one {@code page_size} allocation and two {@code page_size}
     * copies per page, or 13 MB allocated and 26 MB copied for a 13 MB flush,
     * on top of the checksum that has to run anyway.
     */
    public void buildExtentPageInto(long pageId, PageHeader h, byte[] payload,
            byte[] dst, int dstOff) {
        int saved = pageCodec;
        pageCodec = Superblock.Codec.NONE;
        try {
            byte[] body = prepareBody(pageId, h, payload);
            System.arraycopy(body, 0, dst, dstOff + PageHeader.BYTES, body.length);
            java.util.Arrays.fill(dst, dstOff + PageHeader.BYTES + body.length,
                    dstOff + pageSize, (byte) 0);
            h.writeInto(dst, dstOff, pageSize, pageSize);
        } finally {
            pageCodec = saved;
        }
    }

    /** The page bytes, exactly as they will be stored. */
    public byte[] buildPage(long pageId, PageHeader h, byte[] payload) {
        byte[] body = prepareBody(pageId, h, payload);
        byte[] page = new byte[pageSize];
        System.arraycopy(body, 0, page, PageHeader.BYTES, body.length);
        h.writeInto(page);
        return page;
    }

    /** Settles every header field and returns the bytes to store after it. */
    private byte[] prepareBody(long pageId, PageHeader h, byte[] payload) {
        if (payload.length > payloadSize()) {
            throw new InvalidArgumentException("payload is " + payload.length
                    + " bytes, a " + pageSize + "-byte page holds " + payloadSize());
        }
        h.payloadLen = payload.length;
        h.commitId = commitId;
        byte[] body = payload;
        h.flags &= ~(PageHeader.Flags.COMPRESSED | PageHeader.Flags.ENCRYPTED);
        h.codecOrReserved = 0;
        h.storedLen = 0;
        h.nonce = 0;
        // §7's order, and §5.2 restates it: compress, then encrypt. The other
        // order compresses ciphertext, which does not compress. `payload_len`
        // keeps the meaning §3 gives it -- the uncompressed length -- and
        // `stored_len` becomes what the page actually holds.
        byte[] compressed = compress(h, body);
        if (compressed != null) {
            body = compressed;
            h.flags |= PageHeader.Flags.COMPRESSED;
            h.codecOrReserved = pageCodec;
            h.storedLen = body.length;
        }
        if (crypto != null) {
            // Every field of the header is settled BEFORE the encryption,
            // because §5.2's AAD is the header as stored. `stored_len` is
            // `payload_len` plus the tag, so it is known in advance.
            h.flags |= PageHeader.Flags.ENCRYPTED;
            h.nonce = crypto.allocateNonce();
            h.storedLen = body.length + XChaCha20Poly1305.TAG_BYTES;
            if (h.storedLen > rawPayloadSize()) {
                throw new LimitException("encrypted payload is " + h.storedLen
                        + " bytes and does not fit a " + pageSize + "-byte page");
            }
            body = crypto.encryptPage(body, h, pageId);
        }
        return body;
    }

    /**
     * Grows the file so that {@code pageCount} pages exist on disk.
     *
     * <p>{@code page_count}, not the file length, defines what is in use, so
     * this is an optimization: keeping segment extents physically contiguous is
     * what lets a segment be written with one sequential I/O.
     */
    public void reserveTo(long pages) {
        long want = pages * (long) pageSize;
        if (file.size() < want) {
            byte[] zero = new byte[pageSize];
            file.write(want - pageSize, zero);
        }
    }

    public void sync() {
        file.sync();
    }

    /** Returns the space past {@code page_count} to the filesystem. */
    public synchronized void truncateFile() {
        file.truncate(pageCount * (long) pageSize);
    }
}
