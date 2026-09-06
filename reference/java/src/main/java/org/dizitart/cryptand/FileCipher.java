package org.dizitart.cryptand;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Everything the file does with a key — {@code spec/14-security.md} §3, §4, §5
 * and §6.
 *
 * <p>The file is encrypted under a <strong>master key</strong>: 32 random bytes
 * from a cryptographic RNG, never derived from anything the user types. A
 * password derives only a key-encryption key, used to wrap the master key
 * inside a keyslot. One level would be simpler and is wrong for three reasons,
 * each a real operation an application performs: a password change would rewrite
 * the database instead of 32 bytes; only one credential could ever unlock a
 * file; and crypto-erase — the only erase that means anything on flash — would
 * be impossible.
 *
 * <p>Subkeys are derived per purpose, never used as the master key. Domain
 * separation matters here for a concrete reason: pages and value-log records
 * use <em>different</em> nonce spaces, and reusing one key across two
 * independently-constructed nonce spaces is exactly how nonce collisions become
 * possible again.
 */
public final class FileCipher implements PageCrypto, AutoCloseable {

    /**
     * Publishes a new {@code next_nonce} floor durably. §4.1's first MUST: on
     * open, and again on reaching the published value, a writer publishes
     * {@code floor + 2^20} <em>before</em> allocating anything at or above it.
     */
    public interface NoncePublisher {
        void publishNonceFloor(long floor);
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] masterKey;
    private final byte[] databaseUuid;
    private final byte[] pageKey;
    private final byte[] vlogKey;
    private final byte[] macKey;
    private final AtomicLong nextNonce;
    private volatile long publishedFloor;
    private final AtomicLong allocated = new AtomicLong();
    private NoncePublisher publisher;
    private boolean closed;

    private FileCipher(byte[] masterKey, byte[] databaseUuid, long persistedNextNonce) {
        this.masterKey = masterKey.clone();
        this.databaseUuid = databaseUuid.clone();
        this.pageKey = Security.deriveSubkey(this.masterKey, this.databaseUuid, Security.Purpose.PAGE);
        this.vlogKey = Security.deriveSubkey(this.masterKey, this.databaseUuid, Security.Purpose.VLOG);
        this.macKey = Security.deriveSubkey(this.masterKey, this.databaseUuid, Security.Purpose.SB_MAC);
        this.nextNonce = new AtomicLong(persistedNextNonce);
        this.publishedFloor = persistedNextNonce;
    }

    public static byte[] randomMasterKey() {
        byte[] k = new byte[XChaCha20Poly1305.KEY_BYTES];
        RANDOM.nextBytes(k);
        return k;
    }

    public static FileCipher of(byte[] masterKey, byte[] databaseUuid, long persistedNextNonce) {
        return new FileCipher(masterKey, databaseUuid, persistedNextNonce);
    }

    /**
     * Installs the publisher and performs §4.1's opening publish.
     *
     * <p>Without the publish half, a crashed session leaves the watermark
     * unmoved and the next session reissues its nonces — a stream cipher
     * reusing a nonce discloses both plaintexts and the authentication key, and
     * no checksum and no tag catches it, because every affected page verifies
     * perfectly.
     */
    public void attach(NoncePublisher publisher) {
        this.publisher = publisher;
        long floor = nextNonce.get() + Security.NONCE_GAP;
        publisher.publishNonceFloor(floor);
        publishedFloor = floor;
    }

    /** §4.1's rules 2 and 3: allocate below the published floor, and publish before crossing it. */
    public long allocateNonce() {
        while (true) {
            long v = nextNonce.getAndIncrement();
            if (v < publishedFloor) {
                allocated.incrementAndGet();
                return v;
            }
            synchronized (this) {
                if (v >= publishedFloor && publisher != null) {
                    long floor = Math.max(v, publishedFloor) + Security.NONCE_GAP;
                    publisher.publishNonceFloor(floor);
                    publishedFloor = floor;
                }
            }
            if (publisher == null) {
                // No publisher yet - creating the file, before the first
                // superblock exists. The floor advances with the counter and is
                // published by the create path's own first commit.
                publishedFloor = v + Security.NONCE_GAP;
                allocated.incrementAndGet();
                return v;
            }
        }
    }

    /** How many nonces this session has handed out — §6's headroom metric. */
    public long allocatedCount() {
        return allocated.get();
    }

    public long nextNonceWatermark() {
        return Math.max(nextNonce.get(), publishedFloor);
    }

    public byte[] databaseUuid() {
        return databaseUuid.clone();
    }

    // ==================================================================
    // §5.2 pages
    // ==================================================================

    @Override
    public byte[] encryptPage(byte[] payload, PageHeader header, long pageId) {
        byte[] nonce = Security.buildNonce(Security.NonceDomain.PAGE, header.nonce, pageId, 0);
        return XChaCha20Poly1305.encrypt(pageKey, nonce, pageAad(header), payload);
    }

    @Override
    public byte[] decryptPage(byte[] stored, PageHeader header, long pageId) {
        byte[] nonce = Security.buildNonce(Security.NonceDomain.PAGE, header.nonce, pageId, 0);
        return XChaCha20Poly1305.decrypt(pageKey, nonce, pageAad(header), stored, "page " + pageId);
    }

    /**
     * §5.2's AAD: the 40-byte page header with {@code checksum} zeroed, and
     * <strong>nothing else</strong> zeroed.
     *
     * <p>{@code stored_len} is part of it, which is why the caller must set it
     * before encrypting rather than after: it is derivable —
     * {@code payload_len + 16} — so there is no chicken and egg, only an
     * ordering constraint. Leaving it out authenticates one field fewer and,
     * far worse, makes the tag depend on which implementation computed it.
     *
     * <p>The AAD pins {@code page_type}, {@code flags}, {@code tree_id},
     * {@code commit_id}, {@code extent_pages}, {@code payload_len},
     * {@code stored_len} and {@code nonce}, so an attacker cannot relabel an
     * index page as a data page or move a page between trees.
     */
    private static byte[] pageAad(PageHeader h) {
        PageHeader c = new PageHeader();
        c.checksum = 0;
        c.pageType = h.pageType;
        c.flags = h.flags;
        c.codecOrReserved = h.codecOrReserved;
        c.treeId = h.treeId;
        c.extentPages = h.extentPages;
        c.commitId = h.commitId;
        c.payloadLen = h.payloadLen;
        c.storedLen = h.storedLen;
        c.nonce = h.nonce;
        return c.toBytes();
    }

    // ==================================================================
    // §5.3 value-log records
    // ==================================================================

    /** {@code aad = u64le(vlog_segment_id) || u64le(record_offset) || u32le(tree_id)}. */
    public static byte[] vlogAad(long segmentId, long recordOffset, int treeId) {
        return new ByteWriter(20).u64(segmentId).u64(recordOffset).u32(treeId).toBytes();
    }

    public byte[] encryptRecord(long segmentId, long recordOffset, int treeId, byte[] plaintext, long counter) {
        byte[] nonce = Security.buildNonce(Security.NonceDomain.VLOG_RECORD, counter, segmentId, recordOffset);
        return XChaCha20Poly1305.encrypt(vlogKey, nonce, vlogAad(segmentId, recordOffset, treeId), plaintext);
    }

    public byte[] decryptRecord(long segmentId, long recordOffset, int treeId, byte[] ciphertext, long counter) {
        byte[] nonce = Security.buildNonce(Security.NonceDomain.VLOG_RECORD, counter, segmentId, recordOffset);
        return XChaCha20Poly1305.decrypt(vlogKey, nonce, vlogAad(segmentId, recordOffset, treeId),
                ciphertext, "value-log record at " + segmentId + "+" + recordOffset);
    }

    // ==================================================================
    // §5.4 extents without page headers
    // ==================================================================

    /**
     * One chunk of a blob or vector extent.
     *
     * <p>The counter is <strong>per chunk and per write</strong>, and stored in
     * the clear at the head of the chunk. An earlier draft made it the extent's
     * single allocated value, stored in the head page — correct only if every
     * chunk is written exactly once, which a vector region breaks on its first
     * ordinary use. Rewriting a chunk under a fixed per-extent counter is the
     * same key and the same nonce over different plaintext.
     */
    public byte[] encryptChunk(long headPageId, long chunkIndex, byte[] plaintext) {
        long counter = allocateNonce();
        byte[] nonce = Security.buildNonce(Security.NonceDomain.PAGE, counter, headPageId, chunkIndex);
        byte[] ct = XChaCha20Poly1305.encrypt(pageKey, nonce, chunkAad(headPageId, chunkIndex), plaintext);
        return new ByteWriter(8 + ct.length).u64(counter).bytes(ct).toBytes();
    }

    public byte[] decryptChunk(long headPageId, long chunkIndex, byte[] stored) {
        ByteReader r = new ByteReader(stored);
        long counter = r.u64();
        byte[] ct = r.bytes(r.remaining());
        byte[] nonce = Security.buildNonce(Security.NonceDomain.PAGE, counter, headPageId, chunkIndex);
        return XChaCha20Poly1305.decrypt(pageKey, nonce, chunkAad(headPageId, chunkIndex), ct,
                "extent chunk " + chunkIndex + " at page " + headPageId);
    }

    private static byte[] chunkAad(long headPageId, long chunkIndex) {
        return new ByteWriter(16).u64(headPageId).u64(chunkIndex).toBytes();
    }

    /** Plaintext bytes per encrypted chunk: a page less the 8-byte counter and the 16-byte tag. */
    public static int chunkPlaintextBytes(int pageSize) {
        return pageSize - 24;
    }

    // ==================================================================
    // §6 the superblock MAC
    // ==================================================================

    public byte[] macKey() {
        return macKey.clone();
    }

    /** {@code HMAC-SHA256(subkey("sbmac"), superblock[0..4091] with 296..327 zeroed)}. */
    public static byte[] superblockMac(byte[] macKey, byte[] image) {
        byte[] msg = Arrays.copyOf(image, Superblock.CHECKSUM_OFFSET);
        Arrays.fill(msg, 296, 328, (byte) 0);
        return Security.hmacSha256(macKey, msg);
    }

    // ==================================================================
    // §3.3 keyslots
    // ==================================================================

    /** Wraps {@code masterKey} into a fresh Argon2id keyslot. */
    public static Keyslot wrapWithPassword(byte[] masterKey, byte[] databaseUuid, int slotIndex,
                                           byte[] password, String label,
                                           int tCost, int mCostKib, int parallelism) {
        Argon2id.checkCreateParameters(tCost, mCostKib, parallelism);
        Keyslot k = new Keyslot();
        k.state = Keyslot.STATE_OCCUPIED;
        k.kdf = Keyslot.KDF_ARGON2ID;
        k.tCost = tCost;
        k.mCostKib = mCostKib;
        k.parallelism = parallelism;
        k.salt = new byte[32];
        RANDOM.nextBytes(k.salt);
        k.label = label;
        byte[] kek = Argon2id.hash(password, k.salt, tCost, mCostKib, parallelism, 32);
        try {
            seal(k, masterKey, databaseUuid, slotIndex, kek);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
        return k;
    }

    /** Wraps under a key the host already holds — an OS keychain item, a hardware-backed key. */
    public static Keyslot wrapWithRawKey(byte[] masterKey, byte[] databaseUuid, int slotIndex,
                                         byte[] kek32, String label) {
        if (kek32.length != 32) {
            throw new InvalidArgumentException("a raw keyslot KEK is 32 bytes, got " + kek32.length);
        }
        Keyslot k = new Keyslot();
        k.state = Keyslot.STATE_OCCUPIED;
        k.kdf = Keyslot.KDF_RAW;
        k.label = label;
        seal(k, masterKey, databaseUuid, slotIndex, kek32);
        return k;
    }

    private static void seal(Keyslot k, byte[] masterKey, byte[] databaseUuid, int slotIndex, byte[] kek) {
        k.wrapNonce = new byte[24];
        RANDOM.nextBytes(k.wrapNonce);
        byte[] sealed = XChaCha20Poly1305.encrypt(kek, k.wrapNonce,
                Keyslot.wrapAad(databaseUuid, slotIndex), masterKey);
        k.wrappedKey = Arrays.copyOf(sealed, 32);
        k.wrapTag = Arrays.copyOfRange(sealed, 32, 48);
    }

    /**
     * Tries each occupied slot in order and stops at the first whose tag
     * verifies.
     *
     * <p>A failure across all slots is "wrong key". An implementation MUST NOT
     * distinguish "no such slot" from "bad password" in what it reports:
     * telling them apart tells an attacker which of the two they got wrong, and
     * nothing in the format has a use for the distinction.
     */
    public static byte[] unwrap(Keyslot[] slots, byte[] databaseUuid, byte[] password, byte[] rawKey) {
        for (int i = 0; i < slots.length; i++) {
            Keyslot k = slots[i];
            if (k == null || !k.occupied()) {
                continue;
            }
            byte[] kek;
            if (k.kdf == Keyslot.KDF_RAW) {
                if (rawKey == null) {
                    continue;
                }
                kek = rawKey.clone();
            } else if (k.kdf == Keyslot.KDF_ARGON2ID) {
                if (password == null) {
                    continue;
                }
                // On open the parameters come from the file and are used as
                // they are. The superblock MAC is what stops an attacker
                // weakening them; deriving under different ones would yield a
                // different KEK and report "wrong password" for a correct one.
                kek = Argon2id.hash(password, k.salt, k.tCost, k.mCostKib, k.parallelism, 32);
            } else {
                continue;
            }
            byte[] sealed = new byte[48];
            System.arraycopy(k.wrappedKey, 0, sealed, 0, 32);
            System.arraycopy(k.wrapTag, 0, sealed, 32, 16);
            try {
                return XChaCha20Poly1305.decrypt(kek, k.wrapNonce,
                        Keyslot.wrapAad(databaseUuid, i), sealed, "keyslot " + i);
            } catch (TamperingException ignored) {
                // Not tampering here, just the wrong credential for this slot -
                // which is indistinguishable from an absent one by design.
            } finally {
                Arrays.fill(kek, (byte) 0);
            }
        }
        throw new CannotUnlockException("cannot unlock: no keyslot accepted the supplied credential");
    }

    /**
     * §11: keys are held in mutable arrays and zeroed when no longer needed.
     * Java's {@code String} is immutable and interned, which is why every
     * password parameter here is a {@code byte[]}.
     */
    @Override
    public void close() {
        if (!closed) {
            closed = true;
            Arrays.fill(masterKey, (byte) 0);
            Arrays.fill(pageKey, (byte) 0);
            Arrays.fill(vlogKey, (byte) 0);
            Arrays.fill(macKey, (byte) 0);
        }
    }
}
