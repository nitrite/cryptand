package org.dizitart.cryptand;

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
    public record FreeExtent(long commitId, long startPage, int pages) {
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
        if (pages < 1) {
            return;
        }
        pendingFree.add(new FreeExtent(commitId, startPage, pages));
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
        byte[] page = readRaw(pageId);
        PageHeader h = PageHeader.verify(page, pageId);
        return decodePayload(page, h, pageId);
    }

    /** The whole page as stored, checksum unverified. */
    public byte[] readRaw(long pageId) {
        if (pageId < 0) {
            throw new CorruptionException("negative page id " + pageId);
        }
        byte[] page = new byte[pageSize];
        file.readFully(offsetOf(pageId), page, 0, pageSize);
        return page;
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
        if (pageId >= pageCount) {
            pageCount = pageId + 1;
        }
    }

    /** The page bytes, exactly as they will be stored. */
    public byte[] buildPage(long pageId, PageHeader h, byte[] payload) {
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
        byte[] page = new byte[pageSize];
        System.arraycopy(body, 0, page, PageHeader.BYTES, body.length);
        h.writeInto(page);
        return page;
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

    /**
     * Drops the tail past {@code pages} — {@code 13-operations.md} §5's
     * {@code shrink()}. {@code page_count}, not the file length, defines what is
     * in use, so this only returns space to the filesystem.
     */
    public synchronized void truncateTo(long pages) {
        pageCount = Math.max(2, pages);
        free.removeIf(e -> e.startPage() >= pageCount);
        pendingFree.removeIf(e -> e.startPage() >= pageCount);
        file.truncate(pageCount * (long) pageSize);
    }
}
