package org.dizitart.cryptand.lsm;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.Snapshot;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.UnsupportedFeatureException;
import org.dizitart.cryptand.container.Blob;
import org.dizitart.cryptand.container.BtreePage;
import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.container.PageFile;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.PageTree;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.ReadPins;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.crypto.FileCipher;
import org.dizitart.cryptand.crypto.Keyslot;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.key.Ikey;
import org.dizitart.cryptand.ops.ChangeFeed;
import org.dizitart.cryptand.ops.Checkpoint;
import org.dizitart.cryptand.ops.Metrics;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.util.Cfh64;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The storage engine — {@code spec/04-segments.md} and
 * {@code spec/10-transactions.md}.
 *
 * <p>Trees are addressed here by numeric id and keys by their CKE bytes; names,
 * documents and indexes are {@link Database}'s business. What lives at this
 * level is the LSM: sharded memtables, a committer, immutable segments, the
 * two-tier value log, compaction and garbage collection.
 *
 * <p>The write path takes no database-wide lock. A writer buffers its batch,
 * reserves value-log space with one {@code fetch_add}, takes its sequence range
 * with one {@code fetch_add} on {@code next_seq}, inserts into a memtable shard
 * and hands the range to the committer — which runs on its own thread, as
 * {@code 10-transactions.md} §2.2 requires.
 */
public final class Engine implements AutoCloseable {

    /** Everything a caller may set that is not already a superblock field. */
    public static final class Options {
        public Profile profile = Profile.DESKTOP;
        public int durability = Superblock.Durability.SYNC;
        public boolean readOnly;
        public int levelCount = 4;
        /** Entries a memtable shard holds before the committer flushes it. */
        public int memtableEntries = 4096;
        /** §5.2's step bound; the profile's value on mobile. */
        public long compactionStepBytes = 256 * 1024;
        public String writerId = "nitrite-java/1.0.0";
        /** §1's default ceiling on the space one checkpoint may pin. */
        public int checkpointSpaceLimitPct = 25;
        /**
         * The password, as a mutable byte array — §11: Java's {@code String} is
         * immutable and interned, so a password held in one survives until
         * collection and may persist in a heap dump indefinitely, which no
         * amount of care at the call site can undo.
         */
        public byte[] password;
        /** 32 bytes the host already holds — an OS keychain item, a hardware-backed key. */
        public byte[] rawKey;
        /** On create: encrypt the file. On open it is inferred from {@code cipher}. */
        public boolean encrypt;
        /** A supplier for {@code created_utc_ms} and {@code modified_utc_ms}, injectable for tests. */
        public java.util.function.LongSupplier clock = System::currentTimeMillis;
    }

    /**
     * The manifest, resolved into open segments — an immutable snapshot the
     * read path consults with no lock at all. The committer publishes a new one
     * after every manifest edit.
     */
    record LevelState(List<Segment> segments, int levelCount) {

        List<Segment> covering(byte[] internalKeyFloor) {
            List<Segment> out = new ArrayList<>();
            for (Segment s : segments) {
                if (s.meta().covers(internalKeyFloor)) {
                    out.add(s);
                }
            }
            return out;
        }
    }

    private final PageFile file;
    private final Pager pager;
    private final Superblock sb;
    private final Options options;

    private FileCipher cipher;
    private PageTree catalogTree;
    private PageTree freeTree;
    private PageTree attributesTree;
    private PageTree treeIndexTree;
    private PageTree repairTree;
    private PageTree usersTree;
    private PageTree manifestTree;
    private PageTree vlogStatsTree;
    private PageTree checkpointTree;
    private PageTree changefeedTree;
    private Manifest manifest;
    private Vlog vlog;

    private final ConcurrentSkipListMap<byte[], BtreePage.Leaf>[] shards;
    private final CopyOnWriteArrayList<RangeDelete> pendingRangeDeletes = new CopyOnWriteArrayList<>();
    private final AtomicLong nextSeq;
    private volatile long visibleSeq;
    private volatile LevelState levels = new LevelState(List.of(), 1);

    /** Guards the pager's trees, the manifest and the superblock. Held by the committer and by compaction. */
    private final ReentrantLock structure = new ReentrantLock();
    /**
     * Completed sequence ranges not yet folded into {@link #completedThrough}.
     *
     * <p>A batch takes its seq range with one {@code fetch_add} and only then
     * publishes into the memtable, so at any instant a higher range may be
     * complete while a lower one is not. The committer may only advance
     * {@code visible_seq} over a <strong>contiguous</strong> prefix - the same
     * discipline §2.3 requires of the value log's {@code bytes} watermark, and
     * for the same reason: publishing past a hole makes a batch that was never
     * written look committed.
     */
    private final java.util.TreeMap<Long, Long> completedRanges = new java.util.TreeMap<>();
    private long completedThrough;
    /**
     * Guards {@link #completedRanges} and carries {@link #visibleChanged}.
     *
     * <p>Separate from the committer's own wake-up path on purpose. An earlier
     * version used one monitor for both, and with eight writer threads each
     * notifying and re-waiting on it the committer never won the entry set: the
     * write path starved the one thread it was waiting for. Waking the
     * committer is now an unpark, which takes no lock at all.
     */
    private final ReentrantLock seqLock = new ReentrantLock();
    private final java.util.concurrent.locks.Condition visibleChanged = seqLock.newCondition();
    private Thread committer;
    private volatile boolean closing;
    private volatile RuntimeException committerFailure;
    private volatile long appliedDelayMs;
    private volatile double lastLocalityDebt;
    private volatile String backpressureCause = "";

    // §6's counters. Every one of them is accumulated where the fact is known,
    // never derived after the event from a difference that cannot see it.
    private final AtomicLong bytesLogical = new AtomicLong();
    private final AtomicLong bytesDevice = new AtomicLong();
    private final AtomicLong bytesValue = new AtomicLong();
    private final AtomicLong bytesKeyIndex = new AtomicLong();
    private final AtomicLong bytesGc = new AtomicLong();
    private final AtomicLong stallEvents = new AtomicLong();
    private final AtomicLong stallTotalMs = new AtomicLong();
    private final AtomicLong filterProbes = new AtomicLong();
    private final AtomicLong filterFalsePositives = new AtomicLong();
    private final AtomicLong pinnedBySnapshots = new AtomicLong();
    private final AtomicLong liveBytes = new AtomicLong();
    private final List<String> unavailableRanges = new CopyOnWriteArrayList<>();
    private volatile long oldestSnapshotOpenedAtMs;
    private final AtomicLong flushes = new AtomicLong();
    private final AtomicLong compactions = new AtomicLong();
    private final AtomicLong segmentsProbed = new AtomicLong();
    private final AtomicLong lookups = new AtomicLong();
    private final AtomicLong valueReads = new AtomicLong();
    private final AtomicLong scannedRows = new AtomicLong();

    @SuppressWarnings("unchecked")
    private Engine(PageFile file, Pager pager, Superblock sb, Options options) {
        this.file = file;
        this.pager = pager;
        this.sb = sb;
        this.options = options;
        // `01-container.md` §7 -- the codec is a *default* for newly written
        // pages and comes from the file, not from this build's profile, so a
        // desktop that opens a phone's database keeps writing the codec the
        // phone chose. Set before the first read, because an already-compressed
        // page is decompressed on the way out.
        pager.setPageCodec(sb.pageCodec);
        this.shards = new ConcurrentSkipListMap[Math.max(1, sb.memtableShards)];
        for (int i = 0; i < shards.length; i++) {
            shards[i] = new ConcurrentSkipListMap<>(BtreePage::memcmp);
        }
        this.nextSeq = new AtomicLong(sb.nextSeq);
        this.visibleSeq = sb.visibleSeq;
        // A reopened database has already published everything up to
        // `visible_seq`. Starting the contiguous-prefix tracker at zero would
        // make the first commit of the new session publish `visible_seq = 0`
        // and lose every key the file already holds.
        this.completedThrough = sb.visibleSeq;
    }

    // ==================================================================
    // open and create
    // ==================================================================

    public static Engine create(Path path, Options options) {
        if (Files.exists(path) && sizeOf(path) > 0) {
            throw new InvalidArgumentException(path + " already exists; use open");
        }
        Superblock sb = Superblock.forProfile(options.profile);
        sb.commitId = 1;
        sb.pageCount = 2;
        sb.nextSeq = 1;
        sb.visibleSeq = 0;
        sb.levelCount = options.levelCount;
        sb.writerId = options.writerId;
        sb.createdUtcMs = options.clock.getAsLong();
        sb.modifiedUtcMs = sb.createdUtcMs;
        UUID uuid = UUID.randomUUID();
        sb.databaseUuid = new ByteWriter(16).u64be(uuid.getMostSignificantBits())
                .u64be(uuid.getLeastSignificantBits()).toBytes();

        PageFile file = new PageFile(path, false, options.durability);
        sb.durabilityAchieved = file.achieved();
        Pager pager = new Pager(file, sb.pageSize(), sb.pageCount, sb.commitId, 0);
        Engine e = new Engine(file, pager, sb, options);
        if (options.encrypt) {
            e.enableEncryption();
        }
        e.loadTrees();
        e.startCommitter();
        e.commitNow();
        if (e.cipher != null) {
            // §4.1 rule 1: on open, before allocating anything, publish a
            // superblock whose next_nonce is persisted + 2^20. The create path
            // has already used nonces for its first pages, so the publish
            // happens once the superblock exists to carry it.
            e.cipher.attach(e::publishNonceFloor);
        }
        return e;
    }

    /** §8.3: enabling encryption sets {@code cipher = 1} and writes a keyslot; no data is touched. */
    private void enableEncryption() {
        byte[] master = FileCipher.randomMasterKey();
        try {
            Keyslot[] slots = new Keyslot[Keyslot.COUNT];
            if (options.password != null) {
                slots[0] = FileCipher.wrapWithPassword(master, sb.databaseUuid, 0, options.password,
                        "password", options.profile.argon2TCost(), options.profile.argon2MCostKib(),
                        options.profile.argon2Parallelism());
            } else if (options.rawKey != null) {
                slots[0] = FileCipher.wrapWithRawKey(master, sb.databaseUuid, 0, options.rawKey, "keyring");
            } else {
                throw new InvalidArgumentException("encryption was requested with no password and no raw key");
            }
            for (int i = 1; i < Keyslot.COUNT; i++) {
                slots[i] = new Keyslot();
            }
            sb.keyslots = Keyslot.encodeAll(slots);
            sb.cipher = Superblock.Cipher.XCHACHA20_POLY1305;
            sb.featuresRequired |= Feature.bit(Feature.CIPHER);
            sb.nextNonce = 0;
            installCipher(FileCipher.of(master, sb.databaseUuid, 0));
        } finally {
            java.util.Arrays.fill(master, (byte) 0);
        }
    }

    private void installCipher(FileCipher c) {
        this.cipher = c;
        pager.setCrypto(c);
    }

    public static Engine open(Path path, Options options) {
        PageFile file = new PageFile(path, options.readOnly, options.durability);
        try {
            return openLocked(file, options);
        } catch (RuntimeException e) {
            // The writer lock is held from the moment the file opens. Letting it
            // leak on a failed unlock turns "wrong password" into "locked by
            // another process" for every subsequent attempt in this process.
            file.close();
            throw e;
        }
    }

    private static Engine openLocked(PageFile file, Options options) {
        byte[][] image = new byte[1][];
        Superblock sb = chooseSuperblock(file, image);
        FileCipher cipher = null;
        if (sb.cipher != Superblock.Cipher.NONE) {
            if (sb.cipher != Superblock.Cipher.XCHACHA20_POLY1305) {
                throw new UnsupportedFeatureException("cipher " + sb.cipher
                        + " is not defined; cipher = 1 is the only defined value");
            }
            // §2.1 step 4 and §6.2: unwrap a keyslot, then verify sb_mac BEFORE
            // acting on any other field. The four KDF parameters are read from
            // the slot first because the derivation needs them; nothing else is
            // trusted until the MAC verifies.
            byte[] master = FileCipher.unwrap(Keyslot.decodeAll(sb.keyslots), sb.databaseUuid,
                    options.password, options.rawKey);
            try {
                cipher = FileCipher.of(master, sb.databaseUuid, sb.nextNonce);
                byte[] macKey = cipher.macKey();
                try {
                    Superblock.verifyMac(macKey, image[0]);
                } finally {
                    java.util.Arrays.fill(macKey, (byte) 0);
                }
            } finally {
                java.util.Arrays.fill(master, (byte) 0);
            }
        } else if (options.password != null || options.rawKey != null) {
            throw new InvalidArgumentException("a key was supplied but the file is not encrypted");
        }
        if (!options.readOnly) {
            sb.durabilityAchieved = file.achieved();
            // `writer_id` names the SDK that created the file and is left
            // alone here. Who has since modified it is `05-catalog.md` §7's
            // `writers` list, which accumulates rather than replaces - and
            // which is the field worth looking at first when a file handed
            // between SDKs misbehaves. Overwriting the superblock field on
            // every open would destroy the only record of where the file came
            // from and give the accumulating list nothing to accumulate.
        }
        Pager pager = new Pager(file, sb.pageSize(), sb.pageCount, sb.commitId, sb.minRetainedCommit);
        Engine e = new Engine(file, pager, sb, options);
        if (cipher != null) {
            e.installCipher(cipher);
        }
        e.loadTrees();
        if (!options.readOnly) {
            // 10 §4: a value-log segment a previous session left open is sealed
            // at its last durable watermark and new writes go to a fresh
            // segment. Encrypted, re-appending would reuse a nonce; the rule is
            // unconditional because a rule that applies sometimes gets
            // implemented wrong.
            e.vlog.sealOrphans();
            e.startCommitter();
            if (e.cipher != null) {
                e.cipher.attach(e::publishNonceFloor);
            }
            e.commitNow();
        }
        return e;
    }

    /**
     * §4.1's durable publish. It is a superblock write and nothing else, and it
     * happens <em>before</em> any nonce at or above {@code floor} is allocated.
     */
    private void publishNonceFloor(long floor) {
        structure.lock();
        try {
            sb.nextNonce = floor;
            sb.commitId += 1;
            long offset = Superblock.slotOffsetFor(sb.commitId, sb.pageSize());
            file.write(offset, sealSuperblock());
            pager.setCommitId(sb.commitId);
            pager.sync();
        } finally {
            structure.unlock();
        }
    }

    /** The superblock image, MAC'd when the file is encrypted and plain when it is not. */
    private byte[] sealSuperblock() {
        if (cipher == null) {
            return sb.encode();
        }
        byte[] macKey = cipher.macKey();
        try {
            return sb.encodeSealed(macKey);
        } finally {
            java.util.Arrays.fill(macKey, (byte) 0);
        }
    }

    /** §2.1's steps 1–3: read both slots, discard the invalid, take the greater {@code commit_id}. */
    private static Superblock chooseSuperblock(PageFile file, byte[][] chosenImage) {
        byte[] a = new byte[Superblock.BYTES];
        file.readFully(0, a, 0, Superblock.BYTES);
        Superblock sbA = null;
        RuntimeException failA = null;
        try {
            sbA = Superblock.decode(a);
        } catch (RuntimeException ex) {
            failA = ex;
        }
        int pageSize = sbA != null ? sbA.pageSize() : 4096;
        Superblock sbB = null;
        byte[] b = new byte[Superblock.BYTES];
        if (file.size() >= (long) pageSize + Superblock.BYTES) {
            file.readFully(pageSize, b, 0, Superblock.BYTES);
            try {
                sbB = Superblock.decode(b);
            } catch (RuntimeException ignored) {
                // A slot that fails is simply not a candidate; that is the whole
                // of recovery, and it is why the two slots alternate.
            }
        }
        if (sbA == null && sbB == null) {
            throw failA != null ? failA : new CorruptionException("neither superblock slot is valid");
        }
        if (sbA == null) {
            chosenImage[0] = b;
            return sbB;
        }
        if (sbB == null) {
            chosenImage[0] = a;
            return sbA;
        }
        boolean takeA = Long.compareUnsigned(sbA.commitId, sbB.commitId) >= 0;
        chosenImage[0] = takeA ? a : b;
        return takeA ? sbA : sbB;
    }

    private static long sizeOf(Path p) {
        try {
            return Files.size(p);
        } catch (Exception e) {
            return 0;
        }
    }

    private void loadTrees() {
        catalogTree = PageTree.load(pager, TreeId.CATALOG, sb.catalogRoot);
        freeTree = PageTree.load(pager, TreeId.FREE_SPACE, sb.freelistRoot);
        attributesTree = PageTree.load(pager, TreeId.ATTRIBUTES, sb.attributesRoot);
        treeIndexTree = PageTree.load(pager, TreeId.TREE_INDEX, sideTreeRoot("$tree_index"));
        repairTree = PageTree.load(pager, TreeId.REPAIR_LOG, sideTreeRoot("$repair_log"));
        usersTree = PageTree.load(pager, TreeId.USERS, sideTreeRoot("$users"));
        manifestTree = PageTree.load(pager, TreeId.MANIFEST, sb.manifestRoot);
        vlogStatsTree = PageTree.load(pager, TreeId.VLOG_STATS, sb.vlogStatsRoot);
        checkpointTree = PageTree.load(pager, TreeId.CHECKPOINTS, sb.checkpointRoot);
        changefeedTree = PageTree.load(pager, TreeId.CHANGE_FEED, sb.changefeedRoot);
        manifest = new Manifest(manifestTree);
        vlog = new Vlog(pager, vlogStatsTree, sb.vlogSegmentBytes, sb.nextVlogSegmentId);
        vlog.setCipher(cipher);

        List<Pager.FreeExtent> extents = new ArrayList<>();
        for (Map.Entry<byte[], byte[]> e : freeTree.map().entrySet()) {
            Value.Array k = (Value.Array) Cke.decode(e.getKey());
            long commit = SegmentMeta.longOf(k.items().get(0));
            long start = SegmentMeta.longOf(k.items().get(1));
            Value.Doc d = (Value.Doc) Cve.decode(e.getValue());
            extents.add(new Pager.FreeExtent(commit, start, (int) SegmentMeta.longOf(d.field("pages"))));
        }
        pager.loadFreeList(extents);
        republishLevels();
    }

    /**
     * Open segments, by start page. A segment is immutable and its extent is
     * never rewritten, so an open one stays valid until its extent is freed —
     * which is what makes this cache correct rather than merely fast. Reopening
     * every segment on every commit reads a head page per segment per commit,
     * and turns a session into O(segments^2) I/O.
     */
    private final Map<Long, Segment> segmentCache = new java.util.concurrent.ConcurrentHashMap<>();

    /** The root a catalog descriptor records for one of the non-superblock trees. */
    private long sideTreeRoot(String name) {
        byte[] raw = catalogTree.get(TreeDescriptor.catalogKey(name));
        if (raw == null) {
            return 0;
        }
        Long root = TreeDescriptor.decode(raw, null).root();
        return root == null ? 0 : root;
    }

    private void republishLevels() {
        List<Segment> open = new ArrayList<>();
        Set<Long> live = new HashSet<>();
        for (SegmentMeta m : manifest.all()) {
            live.add(m.startPage);
            Segment cached = segmentCache.get(m.startPage);
            // Keyed by start page, but validated by segment id. An extent is
            // freed and reallocated, so a later segment can land on a page an
            // earlier one used - and a cache that trusted the page alone would
            // hand out the OLD segment, which reads perfectly and holds the
            // wrong keys. Segment ids are never reused, which is what makes
            // them the safe half of the key.
            if (cached == null || cached.meta().segmentId != m.segmentId) {
                cached = Segment.open(pager, m.startPage);
                segmentCache.put(m.startPage, cached);
            }
            open.add(cached);
        }
        segmentCache.keySet().retainAll(live);
        // L0 newest first, then strictly increasing level - the level discipline
        // that §4's early exit is proved by.
        open.sort(Comparator.<Segment>comparingInt(s -> s.meta().level)
                .thenComparing(s -> -s.meta().segmentId));
        levels = new LevelState(List.copyOf(open), Math.max(1, manifest.highestLevel() + 1));
    }

    // ==================================================================
    // the write path — 10 §2
    // ==================================================================

    /** One writer's buffered batch. Nothing durable is written before it is sequenced. */
    public final class Batch {
        private final List<Object[]> staged = new ArrayList<>();
        private final Set<Long> written = new HashSet<>();

        /** {@code treeId, cke, value, kind, expiryMs|null} */
        public Batch put(int treeId, byte[] cke, byte[] value) {
            staged.add(new Object[]{treeId, cke, value, BtreePage.Op.PUT, null, null});
            written.add(hashOf(treeId, cke));
            return this;
        }

        public Batch putWithExpiry(int treeId, byte[] cke, byte[] value, long expiryMs) {
            staged.add(new Object[]{treeId, cke, value, BtreePage.Op.PUT, expiryMs, null});
            written.add(hashOf(treeId, cke));
            return this;
        }

        /** An index-tree entry: the key carries the information, so the value is {@code EMPTY}. */
        public Batch putEmpty(int treeId, byte[] cke) {
            staged.add(new Object[]{treeId, cke, new byte[0], BtreePage.Op.PUT, null, BtreePage.Kind.EMPTY});
            written.add(hashOf(treeId, cke));
            return this;
        }

        public Batch remove(int treeId, byte[] cke) {
            staged.add(new Object[]{treeId, cke, new byte[0], BtreePage.Op.DELETE, null, null});
            written.add(hashOf(treeId, cke));
            return this;
        }

        /**
         * Marks {@code [start, end)} deleted — §2.5. This is what makes
         * {@code clear()}, {@code drop()} and rollback of a bulk insert O(1)
         * writes rather than O(n) tombstones.
         */
        public Batch removeRange(int treeId, byte[] startCke, byte[] endCke) {
            staged.add(new Object[]{treeId, startCke, endCke, BtreePage.Op.RANGE_DELETE, null, null});
            return this;
        }

        public int size() {
            return staged.size();
        }

        public Set<Long> writtenKeys() {
            return written;
        }

        /** Discards everything staged after this point — §3's savepoint, which is free. */
        public void truncateTo(int mark) {
            while (staged.size() > mark) {
                staged.remove(staged.size() - 1);
            }
        }

        public int mark() {
            return staged.size();
        }

        /** Steps 3–7 of §2. Returns the last seq this batch was assigned. */
        public long commit() {
            return Engine.this.commitBatch(staged);
        }
    }

    public Batch batch() {
        return new Batch();
    }

    private static long hashOf(int treeId, byte[] cke) {
        return Cfh64.hash(Ikey.userKey(treeId, cke));
    }

    private long commitBatch(List<Object[]> staged) {
        checkCommitter();
        if (staged.isEmpty()) {
            return visibleSeq;
        }
        applyBackpressure();

        // Step 3: values. Every record is written to its final location before
        // any sequence number is taken, so a batch that dies here leaves debris
        // that nothing points at - never a dangling pointer.
        List<Object[]> resolved = new ArrayList<>(staged.size());
        for (Object[] s : staged) {
            int treeId = (int) s[0];
            byte[] cke = (byte[]) s[1];
            int op = (int) s[3];
            Integer forcedKind = (Integer) s[5];
            if (op == BtreePage.Op.RANGE_DELETE || op == BtreePage.Op.DELETE) {
                resolved.add(new Object[]{treeId, cke, s[2], op, s[4], BtreePage.Kind.EMPTY});
                continue;
            }
            byte[] value = (byte[]) s[2];
            bytesLogical.addAndGet(cke.length + value.length);
            liveBytes.addAndGet(cke.length + value.length);
            int kind;
            byte[] stored;
            if (forcedKind != null && forcedKind == BtreePage.Kind.EMPTY) {
                kind = BtreePage.Kind.EMPTY;
                stored = new byte[0];
            } else if (sb.blobThreshold > 0 && value.length >= sb.blobThreshold) {
                kind = BtreePage.Kind.BLOB;
                stored = Blob.write(pager, value).encode();
            } else if (sb.vlogMin > 0 && value.length >= sb.vlogMin) {
                kind = BtreePage.Kind.VLOG;
                stored = vlog.append(treeId, cke, value, VlogSegment.HEAT_FIRST).encode();
                bytesValue.addAndGet(VlogSegment.recordSize(cke, value));
            } else {
                kind = BtreePage.Kind.INLINE;
                stored = value;
            }
            resolved.add(new Object[]{treeId, cke, stored, op, s[4], kind});
        }

        // Step 4: one fetch_add on next_seq. The only serialization point on
        // the write path.
        long base = nextSeq.getAndAdd(resolved.size());

        // Step 5: publish into the memtable shards.
        long seq = base;
        for (Object[] r : resolved) {
            int treeId = (int) r[0];
            byte[] cke = (byte[]) r[1];
            int op = (int) r[3];
            Long expiry = (Long) r[4];
            int kind = (int) r[5];
            byte[] ik = Ikey.of(treeId, cke, seq, op);
            BtreePage.Leaf cell;
            if (op == BtreePage.Op.RANGE_DELETE) {
                byte[] endCke = (byte[]) r[2];
                RangeDelete rd = new RangeDelete(treeId, cke, endCke, seq);
                cell = BtreePage.Leaf.inline(ik, rd.encodePayload());
                pendingRangeDeletes.add(rd);
            } else {
                cell = new BtreePage.Leaf(ik, kind, expiry == null ? 0 : expiry, expiry != null,
                        (byte[]) r[2], 0);
            }
            shardFor(treeId, cke).put(ik, cell);
            seq++;
        }
        long end = seq - 1;

        // Step 6: register the range with the committer.
        completeRange(base, end);
        wake(committer);
        // Step 7. `none` and `os` acknowledge here, so their writes must be
        // visible here: the batch is acknowledged, and §7 says acknowledged
        // data survives a process crash under `none`. Waiting for the
        // committer's barrier would make those modes unreadable rather than
        // merely less durable.
        if (options.durability <= Superblock.Durability.OS) {
            seqLock.lock();
            try {
                visibleSeq = Math.max(visibleSeq, completedThrough);
            } finally {
                seqLock.unlock();
            }
        } else {
            awaitVisible(end);
        }
        return end;
    }

    /** Folds a finished batch into the contiguous prefix of completed sequence numbers. */
    private void completeRange(long start, long end) {
        seqLock.lock();
        try {
            completedRanges.put(start, end);
            Map.Entry<Long, Long> first;
            while ((first = completedRanges.firstEntry()) != null && first.getKey() <= completedThrough + 1) {
                completedRanges.pollFirstEntry();
                completedThrough = Math.max(completedThrough, first.getValue());
            }
        } finally {
            seqLock.unlock();
        }
    }

    private long completedThrough() {
        seqLock.lock();
        try {
            return completedThrough;
        } finally {
            seqLock.unlock();
        }
    }

    private void wake(Thread t) {
        if (t != null) {
            java.util.concurrent.locks.LockSupport.unpark(t);
        }
    }

    private ConcurrentSkipListMap<byte[], BtreePage.Leaf> shardFor(int treeId, byte[] cke) {
        long h = hashOf(treeId, cke);
        return shards[(int) Long.remainderUnsigned(h, shards.length)];
    }

    private void awaitVisible(long seq) {
        seqLock.lock();
        try {
            while (visibleSeq < seq && !closing && committerFailure == null) {
                try {
                    visibleChanged.await(20, java.util.concurrent.TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } finally {
            seqLock.unlock();
        }
        checkCommitter();
    }

    private void checkCommitter() {
        RuntimeException f = committerFailure;
        if (f != null) {
            throw f;
        }
    }

    // ==================================================================
    // the committer — 10 §2
    // ==================================================================

    private void startCommitter() {
        committer = new Thread(this::committerLoop, "cryptand-committer");
        committer.setDaemon(true);
        committer.start();
        compactor = new Thread(this::compactorLoop, "cryptand-compactor");
        compactor.setDaemon(true);
        compactor.start();
    }

    private Thread compactor;

    private void committerLoop() {
        while (!closing) {
            if (completedThrough() <= visibleSeq) {
                java.util.concurrent.locks.LockSupport.parkNanos(2_000_000L);
                continue;
            }
            try {
                commitNow();
            } catch (RuntimeException e) {
                committerFailure = e;
                signalVisible();
                return;
            }
        }
    }

    private void signalVisible() {
        seqLock.lock();
        try {
            visibleChanged.signalAll();
        } finally {
            seqLock.unlock();
        }
    }

    /**
     * Advances {@code visible_seq} to a target whose ranges are all complete.
     *
     * <p>Value-log GC needs this and it is not a nicety. GC decides liveness
     * with {@code lookup(..., visibleSeq, ...)}: a record is live only if the
     * tree's <em>current</em> entry points at it. Its own pointer rewrites are
     * written at seqs above {@code visible_seq}, and {@code publishSuperblock}
     * republishes the watermark it is handed, so nothing moved it. The next GC
     * pass then looked past the rewrite, saw the entry it had just superseded
     * pointing into a segment it had already freed, judged the surviving record
     * dead, and freed the segment holding it. Two passes with no intervening
     * write - a compaction on an idle database is exactly that - lose data,
     * and every one of the four passes {@code collect0} runs in a row is
     * another chance to.
     */
    private void makeVisible(long target) {
        seqLock.lock();
        try {
            if (target > visibleSeq) {
                visibleSeq = target;
            }
            visibleChanged.signalAll();
        } finally {
            seqLock.unlock();
        }
    }

    /**
     * Steps A–G of §2's committer.
     *
     * <p>The two ordering invariants of §2.3 are what the barrier placement is
     * for, and violating either produces a database that opens cleanly and is
     * wrong: a superblock MUST NOT name a segment whose value-log records are
     * not already durable, and the {@code bytes} watermark MUST advance only
     * over a contiguous prefix of completed reservations.
     */
    public void commitNow() {
        structure.lock();
        try {
            // A: collect - every batch whose records are fully written, which
            // is the contiguous prefix and not simply `next_seq - 1`.
            long target = Math.max(visibleSeq, completedThrough());

            // B, C: a durability barrier over every byte appended since the
            // last commit. This precedes the segment write and the superblock,
            // because §2.3's first ordering invariant is that a superblock MUST
            // NOT name a segment whose value-log records are not already
            // durable - reversing them yields a key index pointing into bytes
            // that were never written, which no checksum catches because the
            // key side is intact.
            if (vlog.consumeAppendFlag()) {
                pager.sync();
            }

            // D: flush memtable shards into L0 segments and edit the manifest.
            boolean flushed = flushShards(target);

            // E.
            if (flushed) {
                pager.sync();
            }

            // F, G.
            publishSuperblock(target);
        } finally {
            structure.unlock();
        }
        signalVisible();
        wake(compactor);
    }

    private final List<Runnable> commitHooks = new CopyOnWriteArrayList<>();

    /**
     * Registers work the committer runs just before it seals a superblock.
     *
     * <p>This is what puts a copy-on-write index tree — an R-tree, a vector
     * graph — in the <em>same</em> commit as the document write that changed it.
     * Without it those trees would publish a root of their own on some later
     * superblock, and an index would be durably out of step with its
     * collection, which {@code 06-indexes.md} §8 forbids.
     */
    public void addCommitHook(Runnable hook) {
        commitHooks.add(hook);
    }

    /** Requires {@link #structure}. Writes the inactive slot and advances {@code visible_seq}. */
    private void publishSuperblock(long visible) {
        publishSuperblock(visible, false);
    }

    /**
     * {@code allowRegression} is for {@code restore()} alone.
     *
     * <p>Everywhere else {@code visible_seq} is monotonic, and enforcing that
     * here rather than trusting the caller is what fixes a real race: under
     * {@code os} durability a writer advances the watermark itself, so a
     * committer that assigns the target it computed a moment earlier can put it
     * <em>back</em> — and every batch acknowledged in between becomes invisible
     * while its data sits perfectly intact on disk.
     */
    private void publishSuperblock(long visible, boolean allowRegression) {
        long published = allowRegression ? visible : Math.max(visibleSeq, visible);
        for (Runnable hook : commitHooks) {
            hook.run();
        }
        vlog.publishStats();

        // §2: roots for trees 0, 1, 2, 6, 7, 8 and 9 are in the superblock, and
        // EVERY OTHER TREE'S root is in its catalog descriptor. Trees 3, 4 and 5
        // are the other trees, so they commit first and their roots go into the
        // catalog before the catalog itself is written. Committing them and
        // dropping the root on the floor - which is what happens if they are
        // treated as superblock-rooted - leaks a page per session and loses the
        // tree.
        publishSideTree(TreeId.TREE_INDEX, "$tree_index", "u32", treeIndexTree);
        publishSideTree(TreeId.REPAIR_LOG, "$repair_log", "array", repairTree);
        publishSideTree(TreeId.USERS, "$users", "string", usersTree);

        sb.catalogRoot = catalogTree.commit();
        sb.attributesRoot = attributesTree.commit();
        sb.manifestRoot = manifestTree.commit();
        sb.vlogStatsRoot = vlogStatsTree.commit();
        sb.checkpointRoot = checkpointTree.commit();
        sb.changefeedRoot = changefeedTree.commit();
        // Tree 1 is written last, and the order inside is load-bearing. Every
        // tree above frees pages as it rebuilds, and those frees belong to this
        // commit; the free tree's own current pages likewise. So: release, then
        // snapshot the list, then build with file-extending allocations only.
        // An allocation out of the list while writing the tree that records it
        // yields a page that is both free and in use, and 01 §9 calls a double
        // allocation corruption rather than a repairable leak.
        freeTree.releaseOldPages();
        writeFreeTree();
        sb.freelistRoot = freeTree.commitFresh();

        sb.commitId += 1;
        sb.visibleSeq = published;
        sb.nextSeq = nextSeq.get();
        sb.nextVlogSegmentId = vlog.nextSegmentId();
        sb.pageCount = pager.pageCount();
        sb.levelCount = Math.max(sb.levelCount, levels.levelCount());
        sb.modifiedUtcMs = options.clock.getAsLong();
        // 10 §8: with no live snapshot the retention floor is visible_seq, and
        // that watermark has to keep moving or retention is unbounded -
        // compaction could never satisfy §5's condition 2 and the key index
        // would grow without bound while the value side looked healthy.
        sb.minRetainedSeq = oldestLiveSnapshot(published);
        sb.minRetainedCommit = minRetainedCommit();
        lastLocalityDebt = vlog.localityDebt();
        pager.setCommitId(sb.commitId);
        pager.setMinRetainedCommit(sb.minRetainedCommit);

        sb.nextNonce = cipher == null ? 0 : cipher.nextNonceWatermark();
        long offset = Superblock.slotOffsetFor(sb.commitId, sb.pageSize());
        file.write(offset, sealSuperblock());
        pager.sync();
        pager.publishFrees();
        visibleSeq = published;
    }

    /** {@code {seq, commit_id}} per live snapshot. Both watermarks are computed from it. */
    private final CopyOnWriteArrayList<long[]> liveSnapshots = new CopyOnWriteArrayList<>();
    private final ReadPins readPins = new ReadPins();

    private long oldestLiveSnapshot(long visible) {
        long floor = visible;
        for (long[] s : liveSnapshots) {
            floor = Math.min(floor, s[0]);
        }
        return floor;
    }

    /**
     * The greatest commit id such that no live reader holds a snapshot at or
     * below it — {@code 01-container.md} §6's reclamation rule. An extent freed
     * at commit {@code N} may be reallocated only once {@code N} is at or below
     * this, which is what stops a compaction from handing a live cursor's pages
     * to the next allocation.
     */
    private long minRetainedCommit() {
        long floor = sb.commitId;
        for (long[] s : liveSnapshots) {
            floor = Math.min(floor, s[1]);
        }
        floor = Math.min(floor, readPins.oldest(floor));
        return Math.max(0, floor - 1);
    }

    /** Pins a snapshot against version collapsing and page reuse. It MUST be released. */
    public Snapshot pin() {
        Snapshot s = Snapshot.of(sb);
        liveSnapshots.add(new long[]{s.seq(), s.commitId()});
        return s;
    }

    public void unpin(Snapshot s) {
        for (long[] e : liveSnapshots) {
            if (e[0] == s.seq() && e[1] == s.commitId()) {
                liveSnapshots.remove(e);
                return;
            }
        }
    }

    /**
     * Commits a tree whose root lives in its catalog descriptor, creating,
     * updating or dropping that descriptor as the tree gains or loses content.
     */
    private void publishSideTree(int treeId, String name, String keyKind, PageTree tree) {
        long root = tree.commit();
        byte[] key = TreeDescriptor.catalogKey(name);
        if (tree.size() == 0) {
            catalogTree.remove(key);
            return;
        }
        byte[] existing = catalogTree.get(key);
        if (existing != null) {
            Long recorded = TreeDescriptor.decode(existing, null).root();
            if (recorded != null && recorded == root) {
                return;
            }
        }
        catalogTree.put(key, new TreeDescriptor.Builder()
                .treeId(treeId)
                .kind(TreeDescriptor.Kind.INTERNAL)
                .levelled(false)
                .root(root)
                .entries(tree.size())
                .created(sb.createdUtcMs)
                .keyKind(keyKind)
                .build()
                .encode(null));
    }

    private void writeFreeTree() {
        // Rebuild tree 1 from the pager's list. Keying by commit_id first means
        // a scan from the beginning yields the oldest, most-reclaimable extents.
        for (byte[] k : new ArrayList<>(freeTree.map().keySet())) {
            freeTree.remove(k);
        }
        for (Pager.FreeExtent e : pager.freeList()) {
            byte[] key = Cke.encode(new Value.Array(List.of(
                    Value.integer(NumType.U64, e.commitId()),
                    Value.integer(NumType.U64, e.startPage()))));
            freeTree.put(key, Cve.encode(Value.Doc.of(Map.of(
                    "pages", Value.integer(NumType.U32, e.pages())))));
        }
    }

    /** Requires {@link #structure}. Returns whether anything was written. */
    private boolean flushShards(long target) {
        boolean any = false;
        for (ConcurrentSkipListMap<byte[], BtreePage.Leaf> shard : shards) {
            if (shard.isEmpty()) {
                continue;
            }
            List<Map.Entry<byte[], BtreePage.Leaf>> take = new ArrayList<>();
            for (Map.Entry<byte[], BtreePage.Leaf> e : shard.entrySet()) {
                if (Ikey.seqOf(e.getKey()) <= target) {
                    take.add(e);
                }
            }
            if (take.isEmpty()) {
                continue;
            }
            SegmentBuilder b = new SegmentBuilder(pager, sb.nextSegmentId++, 0, 0, sb.filterBitsUpper);
            for (Map.Entry<byte[], BtreePage.Leaf> e : take) {
                b.add(e.getValue());
            }
            SegmentMeta built = b.finish();
            bytesKeyIndex.addAndGet((long) built.pages * sb.pageSize());
            bytesDevice.addAndGet((long) built.pages * sb.pageSize());
            manifest.add(built);
            // The new segment is published BEFORE the entries leave the shard,
            // so a concurrent reader sees the entry in both places rather than
            // in neither. Removing first opens a window in which a committed
            // key is invisible - a wrong answer, and one that only appears
            // under a durability mode that lets a reader run during the flush.
            republishLevels();
            for (Map.Entry<byte[], BtreePage.Leaf> e : take) {
                shard.remove(e.getKey());
            }
            pendingRangeDeletes.removeIf(rd -> rd.seq() <= target);
            flushes.incrementAndGet();
            any = true;
        }
        return any;
    }

    // ==================================================================
    // the read path — 04 §4
    // ==================================================================

    /** Whether a lookup may stop at the first candidate level discipline proves is newest. */
    public boolean earlyExit = true;

    public long visibleSeq() {
        return visibleSeq;
    }

    public byte[] get(int treeId, byte[] cke) {
        return get(treeId, cke, visibleSeq, options.clock.getAsLong());
    }

    /** The resolved entry, or null when the key is absent, deleted or expired at {@code now}. */
    public byte[] get(int treeId, byte[] cke, long snapshotSeq, long nowMs) {
        BtreePage.Leaf best = lookup(treeId, cke, snapshotSeq, nowMs);
        return best == null ? null : resolveValue(best);
    }

    public boolean containsKey(int treeId, byte[] cke, long snapshotSeq, long nowMs) {
        return lookup(treeId, cke, snapshotSeq, nowMs) != null;
    }

    /**
     * §4's resolution, with the two things the spec calls load-bearing.
     *
     * <p>Candidates are resolved by the winning entry's own {@code seq}, never
     * by segment order: a segment's {@code max_seq} is an aggregate over every
     * key it holds, so a segment at a lower level can carry a higher
     * {@code max_seq} — from some unrelated key — than one above it.
     *
     * <p>And a segment that may hold a covering range delete is never pruned by
     * its filter: the filter contains the segment's <em>point</em> keys, a
     * {@code RANGE_DELETE} covers keys that are not in it, and filtering such a
     * segment out resurrects a deleted key.
     */
    private BtreePage.Leaf lookup(int treeId, byte[] cke, long snapshotSeq, long nowMs) {
        BtreePage.Leaf best = lookupRaw(treeId, cke, snapshotSeq);
        if (best == null) {
            return null;
        }
        int op = Ikey.opOf(best.key());
        if (op == BtreePage.Op.DELETE || op == BtreePage.Op.RANGE_DELETE) {
            return null;
        }
        if (best.hasExpiry() && best.expiryMs() <= nowMs) {
            // §9: expiry is evaluated at read time, so it is exact regardless of
            // when compaction runs.
            return null;
        }
        return best;
    }

    /** §4's resolution up to the point where visibility is decided. */
    private BtreePage.Leaf lookupRaw(int treeId, byte[] cke, long snapshotSeq) {
        readPins.acquire(sb.commitId);
        try {
            return resolve(treeId, cke, snapshotSeq);
        } finally {
            readPins.release();
        }
    }

    private BtreePage.Leaf resolve(int treeId, byte[] cke, long snapshotSeq) {
        lookups.incrementAndGet();
        byte[] uk = Ikey.userKey(treeId, cke);
        byte[] from = Ikey.seekAt(uk, snapshotSeq);

        BtreePage.Leaf best = null;
        long bestSeq = -1;

        Map.Entry<byte[], BtreePage.Leaf> m = shardFor(treeId, cke).ceilingEntry(from);
        if (m != null && Ikey.hasUserKey(m.getKey(), uk)) {
            best = m.getValue();
            bestSeq = Ikey.seqOf(m.getKey());
        }

        long rd = greatestRangeDelete(treeId, cke, snapshotSeq);

        LevelState state = levels;
        boolean stop = false;
        for (Segment seg : state.segments()) {
            // Range deletes are gathered BEFORE the key-range prune, not after.
            // A RANGE_DELETE entry is keyed by its interval's START, so the
            // segment holding it need not cover - and routinely does not cover
            // - the keys the interval hides. Pruning first loses the delete and
            // resurrects every key in the interval; the filter would do the
            // same, which is why §4 forbids that too. The summary is in memory,
            // so this costs no I/O, and `HAS_RANGE_DELETES` keeps it to the few
            // segments that have one at all.
            if (seg.meta().hasRangeDeletes()) {
                rd = Math.max(rd, greatestRangeDelete(seg.rangeDeletes(), treeId, cke, snapshotSeq));
            }
            if (!coversUserKey(seg.meta(), uk)) {
                continue;
            }
            if (stop || !seg.mayContain(uk)) {
                continue;
            }
            segmentsProbed.incrementAndGet();
            filterProbes.incrementAndGet();
            Segment.Cursor c = seg.cursor();
            try {
                c.seek(from);
            } catch (CorruptionException e) {
                // §4 of 13-operations: a single damaged page MUST NOT make the
                // whole database unreadable. The segment's key range comes out
                // of service by name, every key outside it keeps being served,
                // and a read that lands inside fails with an error that says
                // which range - never with a wrong or empty answer.
                takeOutOfService(seg, e);
                throw new CorruptionException("key is inside an unavailable range: "
                        + rangeOf(seg) + " (" + e.getMessage() + ")");
            }
            if (!c.isValid() || !Ikey.hasUserKey(c.key(), uk)) {
                // The filter said maybe and the segment does not hold the key:
                // a false positive, which is what §2.4's bit allocation is
                // measured against.
                filterFalsePositives.incrementAndGet();
            }
            if (c.isValid() && Ikey.hasUserKey(c.key(), uk)) {
                long seq = Ikey.seqOf(c.key());
                // Resolved by the winning entry's OWN seq, never by segment
                // order: a segment's max_seq is an aggregate over every key it
                // holds, so a segment at a lower level can carry a higher
                // max_seq - from some unrelated key - than one above it.
                if (seq > bestSeq) {
                    bestSeq = seq;
                    best = c.entry();
                }
                // The early exit, and its proof. `levels.segments()` is ordered
                // L0 newest-flush-first then strictly increasing level, and
                // within a level newest run first, so the first candidate that
                // hits holds the newest version of THIS key. Absent that proof
                // §4 requires every candidate to be examined, which is what
                // `earlyExit = false` restores.
                stop = earlyExit;
            }
        }

        if (best == null || rd > bestSeq) {
            return null;
        }
        return best;
    }

    /**
     * The newest entry for a key at or below {@code snapshotSeq}, tombstones
     * and expiry included — what {@code 10-transactions.md} §3's conflict
     * detection needs, which {@link #get} cannot answer because it collapses a
     * delete to "absent" and so cannot tell a conflicting delete from no write
     * at all.
     */
    public BtreePage.Leaf newestVersion(int treeId, byte[] cke, long snapshotSeq) {
        return lookupRaw(treeId, cke, snapshotSeq);
    }

    /**
     * Records a segment's key range as unavailable and names it.
     *
     * <p>Exposed through {@code unavailable_ranges} so a caller can ask whether
     * the database is whole. Without that, containment is observable only by
     * hitting it, and a partially available database looks identical to a
     * healthy one until a read happens to land in the hole.
     */
    private void takeOutOfService(Segment seg, CorruptionException cause) {
        String range = rangeOf(seg);
        if (!unavailableRanges.contains(range)) {
            unavailableRanges.add(range);
        }
    }

    private static String rangeOf(Segment seg) {
        SegmentMeta m = seg.meta();
        return "segment " + m.segmentId + " [" + java.util.HexFormat.of().formatHex(m.minKey)
                + ", " + java.util.HexFormat.of().formatHex(m.maxKey) + "]";
    }

    static boolean coversUserKey(SegmentMeta m, byte[] uk) {
        return BtreePage.memcmp(m.minKey, Ikey.seekCeiling(uk)) <= 0
                && BtreePage.memcmp(Ikey.seekFloor(uk), m.maxKey) <= 0;
    }

    private long greatestRangeDelete(int treeId, byte[] cke, long snapshotSeq) {
        return greatestRangeDelete(pendingRangeDeletes, treeId, cke, snapshotSeq);
    }

    /** Dereferences a value: inline, one value-log read, one blob read, or an overflow chain. */
    public byte[] resolveValue(BtreePage.Leaf cell) {
        switch (cell.kind()) {
            case BtreePage.Kind.INLINE -> {
                return cell.value();
            }
            case BtreePage.Kind.VLOG -> {
                valueReads.incrementAndGet();
                return vlog.read(VlogPointer.decode(cell.value())).value();
            }
            case BtreePage.Kind.BLOB -> {
                valueReads.incrementAndGet();
                return Blob.decode(cell.value()).read(pager);
            }
            case BtreePage.Kind.OVERFLOW -> {
                ByteWriter w = new ByteWriter(cell.value().length * 2);
                w.bytes(cell.value());
                long next = cell.overflowPage();
                while (next != 0) {
                    byte[] payload = pager.readPage(next);
                    ByteReader r = new ByteReader(payload);
                    next = r.u64();
                    int n = r.u32();
                    w.bytes(r.bytes(n));
                }
                return w.toBytes();
            }
            default -> {
                return new byte[0];
            }
        }
    }


    // ==================================================================
    // cursors — 04 §8
    // ==================================================================

    /** One visible entry of a scan: the user key, and its value dereferenced lazily. */
    public final class Row {
        private final int treeId;
        private final byte[] cke;
        private final BtreePage.Leaf cell;
        private byte[] cached;

        Row(int treeId, byte[] cke, BtreePage.Leaf cell) {
            this.treeId = treeId;
            this.cke = cke;
            this.cell = cell;
        }

        public int treeId() {
            return treeId;
        }

        public byte[] key() {
            return cke;
        }

        public BtreePage.Leaf cell() {
            return cell;
        }

        /**
         * Lazy — §8 makes that a requirement, not an optimization: a key-only
         * scan (an index scan, a count, a covering query) must never touch the
         * value log.
         */
        public byte[] value() {
            if (cached == null) {
                cached = resolveValue(cell);
            }
            return cached;
        }

        void preload(byte[] v) {
            cached = v;
        }
    }

    /**
     * A snapshot-bound merge cursor — {@code spec/04-segments.md} §8.
     *
     * <p>A merge heap over one iterator per candidate source, a path stack
     * inside each segment, the snapshot watermark, and dedup that collapses
     * versions of a user key while honouring range deletes and TTL. Because the
     * last level is disjoint and tiers are range-partitioned, the heap merges at
     * most {@code l0_trigger + overlap_bound × (level_count − 2) + 1} sources.
     *
     * <p>Reverse is a first-class direction. {@link #close} is mandatory: a
     * cursor pins segments and value-log segments against reclamation (§8.2).
     */
    public final class Cursor implements AutoCloseable {

        private final int treeId;
        private final byte[] lowUk;
        private final byte[] highUk;
        private final boolean reverse;
        private final long snapshotSeq;
        private final long nowMs;
        private final EntrySource.Merge merge;
        private final List<RangeDelete> rangeDeletes = new ArrayList<>();
        private final List<Row> window = new ArrayList<>();
        private int windowPos;
        private Row current;
        private boolean closed;
        private final long pinnedCommit;

        Cursor(int treeId, byte[] lowCke, byte[] highCke, boolean reverse, long snapshotSeq, long nowMs) {
            this.treeId = treeId;
            this.reverse = reverse;
            this.snapshotSeq = snapshotSeq;
            this.nowMs = nowMs;
            this.lowUk = lowCke == null ? Ikey.userKey(treeId, new byte[0]) : Ikey.userKey(treeId, lowCke);
            this.highUk = highCke == null ? treeCeiling(treeId) : Ikey.userKey(treeId, highCke);
            this.pinnedCommit = sb.commitId;
            if (liveSnapshots.isEmpty()) {
                oldestSnapshotOpenedAtMs = nowMs;
            }
            liveSnapshots.add(new long[]{snapshotSeq, pinnedCommit});
            readPins.acquire(pinnedCommit);

            byte[] from = Ikey.seekFloor(lowUk);
            byte[] to = Ikey.seekCeiling(highUk);

            // The memtable is copied FIRST and the segment list read second,
            // and the order is the whole of the correctness argument. The
            // committer publishes a flushed segment before it removes the
            // entries from the shard, so a reader that takes the memtable and
            // then the levels sees each entry in one place or in both - never in
            // neither. Taking the levels first opens exactly that window: the
            // flush publishes and removes in between, and the entry is in the
            // segment list this cursor did not take and the shard it no longer
            // occupies.
            java.util.TreeMap<byte[], BtreePage.Leaf> resident = new java.util.TreeMap<>(BtreePage::memcmp);
            for (ConcurrentSkipListMap<byte[], BtreePage.Leaf> shard : shards) {
                for (Map.Entry<byte[], BtreePage.Leaf> e : shard.subMap(from, true, to, true).entrySet()) {
                    if (Ikey.seqOf(e.getKey()) <= snapshotSeq) {
                        resident.put(e.getKey(), e.getValue());
                    }
                }
            }
            LevelState state = levels;
            for (RangeDelete rd : pendingRangeDeletes) {
                if (rd.treeId() == treeId && rd.seq() <= snapshotSeq) {
                    rangeDeletes.add(rd);
                }
            }

            List<EntrySource> sources = new ArrayList<>();
            sources.add(reverse ? new EntrySource.OfMapReverse(resident) : new EntrySource.OfMap(resident));
            for (Segment seg : state.segments()) {
                // As in `lookup`: the range-delete summary is consulted before
                // the key-range prune, because a RANGE_DELETE is keyed by its
                // interval's start and hides keys the segment does not cover.
                if (seg.meta().hasRangeDeletes()) {
                    for (RangeDelete rd : seg.rangeDeletes()) {
                        if (rd.treeId() == treeId && rd.seq() <= snapshotSeq) {
                            rangeDeletes.add(rd);
                        }
                    }
                }
                if (BtreePage.memcmp(seg.meta().minKey, to) > 0
                        || BtreePage.memcmp(from, seg.meta().maxKey) > 0) {
                    continue;
                }
                sources.add(reverse
                        ? new EntrySource.OfSegmentReverse(seg, to)
                        : new EntrySource.OfSegment(seg, from));
            }
            this.merge = new EntrySource.Merge(sources, reverse);
        }

        public boolean next() {
            if (windowPos < window.size()) {
                current = window.get(windowPos++);
                scannedRows.incrementAndGet();
                return true;
            }
            fill();
            if (window.isEmpty()) {
                current = null;
                return false;
            }
            current = window.get(windowPos++);
            scannedRows.incrementAndGet();
            return true;
        }

        public Row row() {
            if (current == null) {
                throw new IllegalStateException("cursor is not positioned on a row");
            }
            return current;
        }

        /** Advances {@code n} visible rows. */
        public boolean skip(long n) {
            for (long i = 0; i < n; i++) {
                if (!next()) {
                    return false;
                }
            }
            return true;
        }

        private void fill() {
            window.clear();
            windowPos = 0;
            int want = Math.max(1, sb.readaheadWindow);
            while (window.size() < want && merge.isValid()) {
                byte[] uk = Ikey.userKeyOf(merge.key());
                // Gather the whole run of versions of this user key: they are
                // contiguous in the merged stream in either direction.
                List<BtreePage.Leaf> versions = new ArrayList<>();
                while (merge.isValid() && Ikey.hasUserKey(merge.key(), uk)) {
                    versions.add(merge.entry());
                    merge.next();
                }
                if (Ikey.treeIdOfUserKey(uk) != treeId || outOfRange(uk)) {
                    continue;
                }
                BtreePage.Leaf best = null;
                long bestSeq = -1;
                for (BtreePage.Leaf v : versions) {
                    long seq = Ikey.seqOf(v.key());
                    if (seq <= snapshotSeq && seq > bestSeq) {
                        bestSeq = seq;
                        best = v;
                    }
                }
                if (best == null) {
                    continue;
                }
                byte[] cke = Ikey.ckeOf(best.key());
                long rd = greatestRangeDelete(rangeDeletes, treeId, cke, snapshotSeq);
                if (rd > bestSeq) {
                    continue;
                }
                int op = Ikey.opOf(best.key());
                if (op == BtreePage.Op.DELETE || op == BtreePage.Op.RANGE_DELETE) {
                    continue;
                }
                if (best.hasExpiry() && best.expiryMs() <= nowMs) {
                    continue;
                }
                window.add(new Row(treeId, cke, best));
            }
            readAhead(window);
        }

        private boolean outOfRange(byte[] uk) {
            return BtreePage.memcmp(uk, lowUk) < 0 || BtreePage.memcmp(uk, highUk) > 0;
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                readPins.release();
                for (long[] e : liveSnapshots) {
                    if (e[0] == snapshotSeq && e[1] == pinnedCommit) {
                        liveSnapshots.remove(e);
                        break;
                    }
                }
            }
        }
    }

    public Cursor scan(int treeId, byte[] lowCke, byte[] highCke, boolean reverse) {
        return new Cursor(treeId, lowCke, highCke, reverse, visibleSeq, options.clock.getAsLong());
    }

    public Cursor scan(int treeId, byte[] lowCke, byte[] highCke, boolean reverse,
                       long snapshotSeq, long nowMs) {
        return new Cursor(treeId, lowCke, highCke, reverse, snapshotSeq, nowMs);
    }

    /** Everything above {@code u32be(tree_id)}, so a scan of one tree never steps into another's. */
    static byte[] treeCeiling(int treeId) {
        byte[] out = new byte[5];
        out[0] = (byte) (treeId >>> 24);
        out[1] = (byte) (treeId >>> 16);
        out[2] = (byte) (treeId >>> 8);
        out[3] = (byte) treeId;
        out[4] = (byte) 0xFF;
        return out;
    }

    /**
     * §8.1's MUST: a cursor that dereferences values issues its value-log reads
     * in non-decreasing {@code (segment_id, offset)} order within the window.
     *
     * <p>Sorting a window of pointers turns scattered reads into
     * mostly-sequential ones, and over a {@code clustered} cold segment into
     * strictly sequential ones. It is a MUST for the same reason §6.9 is: a
     * conforming-but-slow implementation here is indistinguishable from a broken
     * one to the user, and the effect grows with data age.
     */
    private void readAhead(List<Row> rows) {
        List<Row> separated = new ArrayList<>();
        List<VlogPointer> pointers = new ArrayList<>();
        for (Row r : rows) {
            if (r.cell().kind() == BtreePage.Kind.VLOG) {
                separated.add(r);
                pointers.add(VlogPointer.decode(r.cell().value()));
            }
        }
        if (separated.isEmpty()) {
            return;
        }
        Vlog.Resolved resolved = vlog.readMany(pointers);
        for (int i = 0; i < separated.size(); i++) {
            separated.get(i).preload(resolved.records().get(i).value());
        }
        // One count per physical read, not per row: §8.1's coalescing is the
        // whole point, and counting dereferences instead would report 1.0
        // however well the values were clustered.
        valueReads.addAndGet(resolved.reads());
    }

    static long greatestRangeDelete(List<RangeDelete> from, int treeId, byte[] cke, long snapshotSeq) {
        long best = 0;
        for (RangeDelete rd : from) {
            if (rd.seq() <= snapshotSeq && rd.covers(treeId, cke)) {
                best = Math.max(best, rd.seq());
            }
        }
        return best;
    }

    // ==================================================================
    // compaction — 04 §5
    // ==================================================================

    private void compactorLoop() {
        while (!closing) {
            java.util.concurrent.locks.LockSupport.parkNanos(5_000_000L);
            try {
                maintain();
            } catch (RuntimeException e) {
                committerFailure = e;
                return;
            }
        }
    }

    /** One round of compaction and value-log maintenance. Safe to call from a test. */
    public void maintain() {
        while (compactOnce()) {
            if (closing) {
                return;
            }
        }
        collectIfNeeded();
        clusterIfNeeded();
    }

    /**
     * The level policy of §3.1 — lazy levelling with range-partitioned tiers.
     *
     * <p>L0 overlaps; L1…Lmax−1 are tiered and partitioned into
     * {@code overlap_bound} groups of mutually disjoint segments; Lmax is
     * levelled and disjoint. A reader MUST NOT depend on any of it — it reads
     * the manifest and resolves by {@code seq} — but a writer that picks output
     * sizes freely cannot satisfy both bounds, so §3.1's sizing rule is a
     * writer rule and is implemented in {@link #segmentEntries}.
     */
    private boolean compactOnce() {
        structure.lock();
        try {
            int last = lastLevel();
            if (manifest.at(0).size() >= Math.max(1, sb.l0Trigger)) {
                compactLevel(0);
                return true;
            }
            for (int l = 1; l < last; l++) {
                if (manifest.at(l).size() > Math.max(1, sb.tierWidth)) {
                    compactLevel(l);
                    return true;
                }
            }
            return false;
        } finally {
            structure.unlock();
        }
    }

    private int lastLevel() {
        return Math.max(1, sb.levelCount - 1);
    }

    /**
     * {@code run_entries(1) = l0_trigger × memtable_entries};
     * {@code run_entries(L) = overlap_bound × run_entries(L−1)};
     * {@code segment_entries(L) = ceil(run_entries(L) ÷ (tier_width ÷ overlap_bound))}.
     *
     * <p>Stated in the spec because the reference implementation's first
     * version used one fixed output size at every level, so every tiered level
     * crossed {@code tier_width} after its <em>second</em> run and compacted
     * immediately. No level ever held more than one run, and range partitioning
     * had no opportunity to do anything.
     */
    long segmentEntries(int level) {
        long overlap = Math.max(1, sb.overlapBound);
        long run = (long) Math.max(1, sb.l0Trigger) * Math.max(1, options.memtableEntries);
        for (int l = 2; l <= level; l++) {
            run *= overlap;
        }
        long runsPerLevel = Math.max(1, Math.max(1, sb.tierWidth) / overlap);
        return Math.max(1, (run + runsPerLevel - 1) / runsPerLevel);
    }

    /** Requires {@link #structure}. Merges every segment at {@code level} into {@code level + 1}. */
    private void compactLevel(int level) {
        int target = level + 1;
        int last = lastLevel();
        List<SegmentMeta> inputs = new ArrayList<>(manifest.at(level));
        if (inputs.isEmpty()) {
            return;
        }
        byte[] lo = inputs.get(0).minKey;
        byte[] hi = inputs.get(0).maxKey;
        for (SegmentMeta m : inputs) {
            if (BtreePage.memcmp(m.minKey, lo) < 0) {
                lo = m.minKey;
            }
            if (BtreePage.memcmp(m.maxKey, hi) > 0) {
                hi = m.maxKey;
            }
        }

        int group = 0;
        if (target < last) {
            // The group with the least data; its overlapping segments join the
            // inputs so that the group stays mutually disjoint afterwards,
            // which is what bounds the read tail at `overlap_bound` per level.
            long bestBytes = Long.MAX_VALUE;
            for (int g = 0; g < Math.max(1, sb.overlapBound); g++) {
                long bytes = 0;
                for (SegmentMeta m : manifest.at(target, g)) {
                    bytes += m.entryCount;
                }
                if (bytes < bestBytes) {
                    bestBytes = bytes;
                    group = g;
                }
            }
        }
        for (SegmentMeta m : manifest.at(target, group)) {
            if (BtreePage.memcmp(m.minKey, hi) <= 0 && BtreePage.memcmp(lo, m.maxKey) <= 0) {
                inputs.add(m);
            }
        }

        // Condition 3 of §5: an entry may be dropped only if the compaction
        // includes every segment that could hold an older version.
        //
        // "No lower level overlaps" is not sufficient on its own, and the gap is
        // a resurrection: the TARGET level's other range-partition groups can
        // hold an older version of the same key, and they are not inputs. Drop a
        // tombstone as bottommost while the version it hides sits in a sibling
        // group, and the key comes back.
        boolean bottommost = target >= last || !anyOlderSegmentOverlaps(inputs, target, lo, hi);

        List<EntrySource> sources = new ArrayList<>();
        List<Segment> open = new ArrayList<>();
        // Newest first, so that a tie on the internal key resolves to the
        // newest source. Level order is the proof: L0 newest-flush-first, then
        // strictly increasing level.
        inputs.sort(Comparator.<SegmentMeta>comparingInt(m -> m.level)
                .thenComparing(m -> -m.segmentId));
        for (SegmentMeta m : inputs) {
            Segment s = Segment.open(pager, m.startPage);
            open.add(s);
            sources.add(new EntrySource.OfSegment(s));
        }
        EntrySource.Merge merge = new EntrySource.Merge(sources);

        long floor = sb.minRetainedSeq;
        long nowMs = options.clock.getAsLong();
        long targetEntries = segmentEntries(target);
        List<SegmentMeta> outputs = new ArrayList<>();
        SegmentBuilder builder = null;
        byte[] lastUserKey = null;
        boolean sawNewerVisible = false;
        // Range deletes encountered so far. A RANGE_DELETE's internal key is
        // its interval's START, so a forward merge always meets one before the
        // entries it hides.
        List<RangeDelete> activeDeletes = new ArrayList<>();
        byte[] maxUserKey = Ikey.userKeyOf(hi);

        while (merge.isValid()) {
            byte[] ik = merge.key();
            BtreePage.Leaf cell = merge.entry();
            merge.next();
            byte[] uk = Ikey.userKeyOf(ik);
            long seq = Ikey.seqOf(ik);
            int op = Ikey.opOf(ik);

            boolean newUserKey = lastUserKey == null || BtreePage.memcmp(lastUserKey, uk) != 0;
            if (newUserKey) {
                sawNewerVisible = false;
                lastUserKey = uk;
            }

            if (op == BtreePage.Op.RANGE_DELETE) {
                activeDeletes.add(RangeDelete.fromCell(cell));
            }

            boolean drop = false;
            if (!newUserKey && sawNewerVisible && bottommost) {
                // Conditions 1 and 2: a newer version exists in this compaction
                // and its seq is at or below the oldest live snapshot.
                drop = true;
            }
            if (!drop && bottommost && op != BtreePage.Op.RANGE_DELETE) {
                // A range delete makes an entry at a lower seq invisible to
                // every live snapshot, so the entry may be dropped - and it MUST
                // be dropped before the tombstone is, or the tombstone's
                // removal resurrects it. The versions a RANGE_DELETE hides live
                // under OTHER user keys, so `sawNewerVisible` never reaches
                // them: each is the newest version of its own key.
                long cover = greatestRangeDelete(activeDeletes, Ikey.treeIdOf(ik),
                        Ikey.ckeOf(ik), floor);
                if (cover > seq) {
                    drop = true;
                }
            }
            if (!drop && bottommost && cell.hasExpiry() && cell.expiryMs() <= nowMs && seq <= floor) {
                drop = true;
            }
            if (!drop && bottommost && seq <= floor && op == BtreePage.Op.DELETE) {
                // A tombstone may be dropped only when its own seq is at or
                // below the floor. The second half is not optional: if a
                // snapshot older than the tombstone is live, the versions it
                // hides cannot be dropped either, so dropping it alone would
                // resurrect them for every reader at or after the delete.
                drop = true;
            }
            if (!drop && bottommost && seq <= floor && op == BtreePage.Op.RANGE_DELETE) {
                // And a RANGE_DELETE only once its whole interval is inside
                // what this compaction merged. An interval reaching past the
                // inputs' key range hides entries in segments that were not
                // inputs, and dropping it would bring every one of them back.
                RangeDelete rd = RangeDelete.fromCell(cell);
                byte[] end = Ikey.userKey(Ikey.treeIdOf(ik), rd.end());
                drop = BtreePage.memcmp(end, maxUserKey) <= 0;
            }
            if (seq <= floor) {
                sawNewerVisible = true;
            }
            if (drop) {
                liveBytes.addAndGet(-(Ikey.ckeOf(ik).length + cell.value().length));
                continue;
            }
            if (!newUserKey && !bottommost) {
                // Kept solely because §5's condition 2 or 3 was not met: this is
                // what `pinned_by_snapshots` counts, and the only place the fact
                // is visible.
                pinnedBySnapshots.addAndGet(Ikey.ckeOf(ik).length + cell.value().length);
            }

            BtreePage.Leaf out = cell;
            if (target >= last && cell.kind() == BtreePage.Kind.VLOG) {
                // §6.3: during a compaction that outputs the last level, a
                // surviving HOT-tier value MUST be promoted into a COLD segment
                // or re-inlined. Because the merge emits entries in
                // internal-key order, appending them in that order yields a
                // cold segment that is key-clustered BY CONSTRUCTION, at no
                // extra cost - the sort had to happen anyway.
                VlogPointer p = VlogPointer.decode(cell.value());
                VlogSegment src = vlog.segment(p.segmentId());
                if (src.tier == VlogSegment.TIER_HOT) {
                    VlogSegment.Record rec = vlog.read(p);
                    VlogPointer moved = vlog.appendCold(rec.treeId(), rec.key(), rec.value());
                    bytesValue.addAndGet(p.len());
                    bytesDevice.addAndGet(p.len());
                    out = new BtreePage.Leaf(ik, BtreePage.Kind.VLOG, cell.expiryMs(),
                            cell.hasExpiry(), moved.encode(), 0);
                }
            }

            // §3.1.1: a levelled level's segments must not overlap in USER
            // keys, and an output boundary in the middle of a key's versions
            // breaks that while every checksum, key range and subtree count
            // stays perfectly valid. The consequence is a wrong answer - §4's
            // early exit stops at whichever of the two it reaches first - and it
            // is invisible until a live snapshot keeps versions the compaction
            // would otherwise have collapsed, which is exactly what the
            // concurrency test creates. So a segment rolls over only on a user
            // key boundary.
            if (builder != null && newUserKey && builder.entryCount() >= targetEntries) {
                outputs.add(builder.finish());
                builder = null;
            }
            if (builder == null) {
                builder = newBuilder(target, group);
            }
            builder.add(out);
        }
        if (builder != null) {
            outputs.add(builder.finish());
        }

        if (target >= last) {
            // The promoted generation is complete, so the cold run it produced
            // can be sealed - and only a sealed run may claim `clustered`.
            vlog.sealCold();
        }
        for (SegmentMeta m : inputs) {
            manifest.remove(m);
            pager.freeExtent(m.startPage, m.pages);
        }
        for (SegmentMeta m : outputs) {
            bytesKeyIndex.addAndGet((long) m.pages * sb.pageSize());
            bytesDevice.addAndGet((long) m.pages * sb.pageSize());
            manifest.add(m);
        }
        sb.levelCount = Math.max(sb.levelCount, target + 1);
        republishLevels();
        compactions.incrementAndGet();
        publishSuperblock(visibleSeq);
    }

    private SegmentBuilder newBuilder(int level, int group) {
        int bits = level >= lastLevel() ? sb.filterBitsLast : sb.filterBitsUpper;
        return new SegmentBuilder(pager, sb.nextSegmentId++, level, group, bits)
                .yieldEvery(options.compactionStepBytes, this::compactionStep);
    }

    /**
     * §5.2's step boundary. A step is any point between two output leaf pages,
     * and the partially built output is just a prefix — abandoning it costs the
     * work done and nothing else, and no reader can see it.
     */
    private void compactionStep() {
        Thread.onSpinWait();
    }

    /**
     * Whether any segment that could hold an older version of a key in
     * {@code [lo, hi]} is outside this compaction — at the target level or
     * below it.
     */
    private boolean anyOlderSegmentOverlaps(List<SegmentMeta> inputs, int target, byte[] lo, byte[] hi) {
        Set<Long> included = new HashSet<>();
        for (SegmentMeta m : inputs) {
            included.add(m.segmentId);
        }
        for (SegmentMeta m : manifest.all()) {
            if (m.level < target || included.contains(m.segmentId)) {
                continue;
            }
            if (BtreePage.memcmp(m.minKey, hi) <= 0 && BtreePage.memcmp(lo, m.maxKey) <= 0) {
                return true;
            }
        }
        return false;
    }

    // ==================================================================
    // value-log garbage collection — 04 §6.8
    // ==================================================================

    /**
     * §6.8's collection, triggered by {@code locality_debt} <em>as well as</em>
     * by {@code vlog_space_target_pct}.
     *
     * <p>The two bounds share a cause — surplus runs — but they are not the same
     * quantity, and a value log can sit comfortably inside its space target
     * while a key-ordered scan interleaves nineteen runs. Measured on the
     * reference implementation, a space-only trigger left an aged scan at 1.58×
     * where a debt trigger held it at 1.00×.
     */
    public void collectIfNeeded() {
        structure.lock();
        try {
            collectIfNeeded0();
        } finally {
            structure.unlock();
        }
    }

    private void collectIfNeeded0() {
        {
            refreshLiveness();
            double debt = vlog.localityDebt();
            long live = 0;
            long total = 0;
            for (VlogStats s : vlog.allStats()) {
                live += s.liveBytes;
                total += s.bytes;
            }
            boolean overSpace = live > 0 && total * 100 > live * (long) Math.max(100, sb.vlogSpaceTargetPct);
            if (debt * 100 <= sb.localityDebtPct && !overSpace) {
                return;
            }
            collect0();
        }
    }

    /**
     * §6.8 and §6.9: merges the surplus cold runs into one, in key order.
     *
     * <p>This is the half of the bound that a space-driven collector never
     * performs. Promotion clusters each <em>generation</em> of surviving values
     * as it passes; only collection merges the generations, and a cold run at
     * 100 % liveness is never picked by "lowest {@code live_bytes / bytes}". An
     * implementation that promotes but never collects has a cold tier that is
     * <em>individually</em> sorted and <em>collectively</em> fragmented, which
     * is the state §6.9 measures and which an earlier draft's flag-based metric
     * could not see.
     */
    public void clusterIfNeeded() {
        structure.lock();
        try {
            refreshLiveness();
            if (vlog.localityDebt() * 100 <= sb.localityDebtPct) {
                return;
            }
            // An open run cannot be clustered - §6.2 says the flag is known only
            // at seal - so it is retired first and joins the merge.
            vlog.sealCold();
            List<VlogStats> surplus = new ArrayList<>();
            for (VlogStats s : vlog.allStats()) {
                if (s.tier == VlogSegment.TIER_COLD && s.liveBytes > 0) {
                    surplus.add(s);
                }
            }
            if (surplus.size() < 2 && surplus.stream().allMatch(s -> s.clustered)) {
                return;
            }
            mergeColdRuns(surplus);
            publishSuperblock(visibleSeq);
        } finally {
            structure.unlock();
        }
    }

    /** Requires {@link #structure}. Recomputes tree 7's liveness against the trees. */
    private void refreshLiveness() {
        long now = options.clock.getAsLong();
        vlog.recomputeLiveness((treeId, cke) -> {
            BtreePage.Leaf entry = lookup(treeId, cke, visibleSeq, now);
            return entry != null && entry.kind() == BtreePage.Kind.VLOG
                    ? VlogPointer.decode(entry.value()) : null;
        });
    }

    /** Requires {@link #structure}. One merge, in {@code (tree_id, CKE(key))} order. */
    private void mergeColdRuns(List<VlogStats> runs) {
        record Survivor(int treeId, byte[] key, byte[] value, BtreePage.Leaf entry) {
        }
        List<Survivor> survivors = new ArrayList<>();
        List<VlogStats> merged = new ArrayList<>();
        long now = options.clock.getAsLong();
        for (VlogStats stats : runs) {
            int before = survivors.size();
            boolean complete = vlog.walk(stats, w -> {
                BtreePage.Leaf live = lookup(w.record().treeId(), w.record().key(), visibleSeq, now);
                if (live != null && live.kind() == BtreePage.Kind.VLOG) {
                    VlogPointer p = VlogPointer.decode(live.value());
                    if (p.segmentId() == stats.segmentId && p.offset() == w.offset()) {
                        survivors.add(new Survivor(w.record().treeId(), w.record().key(),
                                w.record().value(), live));
                    }
                }
            });
            if (complete) {
                merged.add(stats);
            } else {
                // A run this pass could not read to the end stays where it is,
                // survivors and all.
                while (survivors.size() > before) {
                    survivors.remove(survivors.size() - 1);
                }
            }
        }
        if (merged.isEmpty()) {
            return;
        }
        // "Since every input run is already sorted, this is a merge, not a
        // sort" - but sorting the survivors is what makes the output clustered
        // whatever shape the inputs were in, and the set is bounded by what one
        // maintenance pass reclaims.
        survivors.sort(java.util.Comparator
                .comparingInt(Survivor::treeId)
                .thenComparing(Survivor::key, BtreePage::memcmp));
        for (Survivor s : survivors) {
            VlogPointer moved = vlog.appendCold(s.treeId(), s.key(), s.value());
            bytesGc.addAndGet(moved.len());
            long seq = nextSeq.getAndIncrement();
            byte[] ik = Ikey.of(s.treeId(), s.key(), seq, BtreePage.Op.PUT);
            shardFor(s.treeId(), s.key()).put(ik, new BtreePage.Leaf(ik, BtreePage.Kind.VLOG,
                    s.entry().expiryMs(), s.entry().hasExpiry(), moved.encode(), 0));
            completeRange(seq, seq);
        }
        vlog.sealCold();
        long visible = Math.max(visibleSeq, completedThrough());
        flushShards(visible);
        makeVisible(visible);
        for (VlogStats stats : merged) {
            pager.freeExtent(stats.startPage, stats.pages);
            vlogStatsTree.remove(VlogStats.key(stats.segmentId));
        }
    }

    /**
     * Requires {@link #structure}. Rewrites the least-live value-log segments.
     *
     * <p>Three invariants, all MUST, because GC is the most dangerous code in
     * the format — a liveness mistake loses data silently and nothing else in
     * the design has that property:
     *
     * <ol>
     *   <li>a record is live <strong>only</strong> if the tree's current entry
     *       for its key is a {@code VLOG} pointer to this exact
     *       {@code (segment_id, offset)}; a key match alone is not sufficient,
     *       because a superseded record carries the same key;
     *   <li>a segment's extent is not freed until the pointer-rewrite commit is
     *       durable;
     *   <li>{@code live_bytes} may overstate liveness and MUST NOT understate it.
     * </ol>
     */
    private void collect0() {
        List<VlogStats> candidates = new ArrayList<>();
        for (VlogStats s : vlog.allStats()) {
            if (s.sealed && s.bytes > 0) {
                candidates.add(s);
            }
        }
        // §6.8 step 1: "choose segments with the LOWEST live_bytes / bytes".
        // A fully live run is the worst candidate there is - collecting it
        // rewrites every byte and reclaims nothing - so the ratio is a filter
        // and not only an ordering.
        candidates.removeIf(s -> (double) s.liveBytes / Math.max(1, s.bytes) > 0.5);
        candidates.sort(Comparator.comparingDouble(s -> (double) s.liveBytes / Math.max(1, s.bytes)));
        int budget = Math.min(4, candidates.size());
        for (int i = 0; i < budget; i++) {
            collectSegment(candidates.get(i));
        }
        if (budget > 0) {
            republishLevels();
            publishSuperblock(visibleSeq);
        }
    }

    private void collectSegment(VlogStats stats) {
        record Survivor(VlogSegment.Record record, BtreePage.Leaf entry) {
        }
        List<Survivor> survivors = new ArrayList<>();
        long now = options.clock.getAsLong();
        boolean complete = vlog.walk(stats, w -> {
            BtreePage.Leaf live = lookup(w.record().treeId(), w.record().key(), visibleSeq, now);
            if (live != null && live.kind() == BtreePage.Kind.VLOG) {
                VlogPointer p = VlogPointer.decode(live.value());
                if (p.segmentId() == stats.segmentId && p.offset() == w.offset()) {
                    survivors.add(new Survivor(w.record(), live));
                }
            }
        });
        if (!complete) {
            // The walk stopped early, so records past that point were never
            // examined. Freeing the extent would drop whatever they held:
            // §6.8's second invariant is that a segment's extent is not freed
            // until the pointer-rewrite commit is durable, and a rewrite that
            // never saw a record is not one.
            return;
        }

        // Step 4: the updated pointers go through the normal commit path, which
        // is what makes GC crash-safe by construction. A partly finished GC
        // leaves duplicate value records, which are garbage, not corruption.
        for (Survivor s : survivors) {
            VlogSegment.Record rec = s.record();
            BtreePage.Leaf old = s.entry();
            VlogPointer moved = stats.tier == VlogSegment.TIER_COLD
                    ? vlog.appendCold(rec.treeId(), rec.key(), rec.value())
                    : vlog.append(rec.treeId(), rec.key(), rec.value(), stats.heat);
            bytesGc.addAndGet(moved.len());
            bytesDevice.addAndGet(moved.len());
            long seq = nextSeq.getAndIncrement();
            byte[] ik = Ikey.of(rec.treeId(), rec.key(), seq, BtreePage.Op.PUT);
            BtreePage.Leaf cell = new BtreePage.Leaf(ik, BtreePage.Kind.VLOG, old.expiryMs(),
                    old.hasExpiry(), moved.encode(), 0);
            shardFor(rec.treeId(), rec.key()).put(ik, cell);
            completeRange(seq, seq);
        }
        long visible = Math.max(visibleSeq, completedThrough());
        flushShards(visible);
        // The rewrites have to be visible before the next pass computes
        // liveness against them - see makeVisible.
        makeVisible(visible);
        // Step 5: the extent is freed at this commit id, and does not become
        // allocatable until min_retained_commit passes it - which is exactly
        // "no live snapshot predates it".
        pager.freeExtent(stats.startPage, stats.pages);
        vlogStatsTree.remove(VlogStats.key(stats.segmentId));
    }

    // ==================================================================
    // backpressure — 10 §6
    // ==================================================================

    /**
     * The normative backpressure curve:
     * {@code x = max over bounds of (current − soft) / (hard − soft)} clamped to
     * {@code [0, 1]}, and {@code delay_ms = max_delay_ms × x²}.
     *
     * <p>Quadratic, so it is imperceptible while the engine is merely busy and
     * firm before it is in trouble. An implementation MUST NOT stall at the hard
     * threshold without having applied increasing delay before it: a cliff turns
     * a throughput problem into a hang, and that is the failure users report.
     */
    private void applyBackpressure() {
        double worst = 0;
        String cause = "";

        // Counted from the published level snapshot, never from the manifest
        // tree: this runs on a writer thread, and the internal trees belong to
        // whoever holds `structure`. Reading a plain TreeMap while the
        // committer rewrites it does not merely give a stale count - it loses
        // entries, and the manifest is what the read path prunes with.
        LevelState state = levels;
        int[] perLevel = new int[Math.max(2, sb.levelCount + 1)];
        for (Segment seg : state.segments()) {
            int l = seg.meta().level;
            if (l < perLevel.length) {
                perLevel[l]++;
            }
        }
        double x = overshoot(perLevel[0], Math.max(1, sb.l0Trigger), Math.max(1, sb.l0Trigger) * 4);
        if (x > worst) {
            worst = x;
            cause = "l0_segments";
        }
        for (int l = 1; l < Math.min(lastLevel(), perLevel.length); l++) {
            x = overshoot(perLevel[l], Math.max(1, sb.tierWidth), Math.max(1, sb.tierWidth) * 2);
            if (x > worst) {
                worst = x;
                cause = "tier_width@L" + l;
            }
        }
        int resident = 0;
        for (ConcurrentSkipListMap<byte[], BtreePage.Leaf> s : shards) {
            resident += s.size();
        }
        int budget = options.memtableEntries * shards.length;
        x = overshoot(resident, budget, budget * 2);
        if (x > worst) {
            worst = x;
            cause = "memtable_bytes";
        }
        x = overshoot((int) Math.round(lastLocalityDebt * 100), Math.max(1, sb.localityDebtPct),
                Math.max(2, sb.localityDebtPct * 2));
        if (x > worst) {
            worst = x;
            cause = "locality_debt";
        }

        long delay = Math.round(MAX_DELAY_MS * worst * worst);
        appliedDelayMs = delay;
        backpressureCause = delay > 0 ? cause : "";
        if (delay > 0) {
            stallEvents.incrementAndGet();
            stallTotalMs.addAndGet(delay);
            wake(compactor);
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static final long MAX_DELAY_MS = 100;

    private static double overshoot(int current, int soft, int hard) {
        if (current <= soft || hard <= soft) {
            return 0;
        }
        return Math.min(1.0, (double) (current - soft) / (hard - soft));
    }

    /** The applied write delay and the bound that caused it — {@code 13-operations.md} §6. */
    public long appliedDelayMs() {
        return appliedDelayMs;
    }

    public String backpressureCause() {
        return backpressureCause;
    }

    // ==================================================================
    // accessors and metrics
    // ==================================================================

    public Superblock superblock() {
        return sb;
    }

    public Pager pager() {
        return pager;
    }

    public Manifest manifest() {
        return manifest;
    }

    public Vlog vlog() {
        return vlog;
    }

    public PageTree catalogTree() {
        return catalogTree;
    }

    public PageTree attributesTree() {
        return attributesTree;
    }

    public PageTree treeIndexTree() {
        return treeIndexTree;
    }

    public PageTree usersTree() {
        return usersTree;
    }

    public PageTree repairTree() {
        return repairTree;
    }

    public PageTree checkpointTree() {
        return checkpointTree;
    }

    public PageTree changefeedTree() {
        return changefeedTree;
    }

    public List<Segment> segments() {
        return levels.segments();
    }

    public long flushCount() {
        return flushes.get();
    }

    public long bytesWrittenLogical() {
        return bytesLogical.get();
    }

    public long bytesWrittenDevice() {
        return bytesDevice.get();
    }

    public long bytesWrittenValue() {
        return bytesValue.get();
    }

    public long bytesWrittenKeyIndex() {
        return bytesKeyIndex.get();
    }

    public long bytesWrittenGc() {
        return bytesGc.get();
    }

    public long stallEvents() {
        return stallEvents.get();
    }

    public long stallTotalMs() {
        return stallTotalMs.get();
    }

    public long noncesAllocated() {
        return cipher == null ? 0 : cipher.allocatedCount();
    }

    public long liveBytes() {
        return liveBytes.get();
    }

    /**
     * Bytes a compaction kept solely because §5's condition 2 was not met —
     * accumulated where the retention decision is made, because the obvious
     * derivation reads 0.
     */
    public long pinnedBySnapshots() {
        return pinnedBySnapshots.get();
    }

    public long pinnedByCheckpoints() {
        long bytes = 0;
        for (Map.Entry<byte[], byte[]> e : checkpointTree.map().entrySet()) {
            Value.Doc d = (Value.Doc) Cve.decode(e.getValue());
            long seq = SegmentMeta.longOf(d.field("seq"));
            if (seq < visibleSeq) {
                bytes += pinnedBySnapshots.get();
                break;
            }
        }
        return bytes;
    }

    /** 0 on a fully encrypted file; non-zero mid-conversion (§8.3). */
    public long unencryptedPages() {
        if (sb.cipher == Superblock.Cipher.NONE) {
            return pager.pageCount();
        }
        long plain = 0;
        for (long p = 2; p < pager.pageCount(); p++) {
            try {
                PageHeader h = PageHeader.parse(pager.readRaw(p), 0);
                if (h.pageType != PageHeader.Type.VLOG_SEGMENT
                        && !h.isSet(PageHeader.Flags.ENCRYPTED)) {
                    plain++;
                }
            } catch (RuntimeException ignored) {
                // A page that cannot even be parsed is the verifier's business,
                // not this counter's.
            }
        }
        return plain;
    }

    public double filterFalsePositiveRate() {
        long n = filterProbes.get();
        return n == 0 ? 0 : (double) filterFalsePositives.get() / n;
    }

    public long oldestSnapshotAgeMs() {
        if (liveSnapshots.isEmpty()) {
            return 0;
        }
        return Math.max(0, options.clock.getAsLong() - oldestSnapshotOpenedAtMs);
    }

    public long compactionBacklogBytes() {
        long backlog = 0;
        for (SegmentMeta m : manifest.all()) {
            if (m.level == 0) {
                backlog += (long) m.pages * sb.pageSize();
            }
        }
        return backlog;
    }

    /**
     * Key ranges §4 has taken out of service after a checksum failure. 0 is the
     * normal state, and it has to be askable: without it a partially available
     * database looks identical to a healthy one until a read lands in the hole.
     */
    public List<String> unavailableRanges() {
        return List.copyOf(unavailableRanges);
    }

    public int vlogLiveRuns() {
        int runs = 0;
        for (VlogStats s : vlog.allStats()) {
            if (s.liveBytes > 0) {
                runs++;
            }
        }
        return runs;
    }

    public int vlogIdealRuns() {
        long coldLive = 0;
        for (VlogStats s : vlog.allStats()) {
            if (s.tier == VlogSegment.TIER_COLD) {
                coldLive += s.liveBytes;
            }
        }
        return (int) Math.max(1, (coldLive + sb.vlogSegmentBytes - 1) / Math.max(1, sb.vlogSegmentBytes));
    }

    public Metrics metrics() {
        return Metrics.of(this);
    }

    /** The raw probe counter, for a test that measures a distribution rather than a mean. */
    public long metricsProbeTotal() {
        return segmentsProbed.get();
    }

    /**
     * {@code set_profile} — {@code spec/12-profiles.md} §6.
     *
     * <p>Writes the new constants into the superblock; from that commit onward
     * new writes follow them, and existing data converts <strong>lazily,
     * through ordinary compaction</strong>. {@code page_size} is the one
     * constant that cannot change: it is fixed at creation, and moving it needs
     * a full copy through {@code 13-operations.md} §2.
     */
    public void setProfile(Profile p) {
        structure.lock();
        try {
            if (p.pageSize() != sb.pageSize()) {
                throw new InvalidArgumentException("profile " + p + " has page_size " + p.pageSize()
                        + " and this file has " + sb.pageSize()
                        + "; page_size is fixed at creation and changing it requires a full copy "
                        + "(spec/12-profiles.md §6)");
            }
            sb.profile = p.id();
            sb.memtableShards = p.memtableShards();
            sb.vlogMin = p.vlogMin();
            sb.blobThreshold = p.blobThreshold();
            sb.l0Trigger = p.l0Trigger();
            sb.fanout = p.fanout();
            sb.tierWidth = p.tierWidth();
            sb.overlapBound = p.overlapBound();
            sb.segmentTargetBytes = p.segmentTargetBytes();
            sb.vlogSegmentBytes = p.vlogSegmentBytes();
            sb.filterBitsUpper = p.filterBitsUpper();
            sb.filterBitsLast = p.filterBitsLast();
            sb.vlogSpaceTargetPct = p.vlogSpaceTargetPct();
            sb.localityDebtPct = p.localityDebtPct();
            sb.readaheadWindow = p.readaheadWindow();
            // §7: a profile change moves the *default* for newly written
            // pages. Existing pages keep their own flags, which is what makes
            // the mixture §7 permits legal rather than a repair job.
            sb.pageCodec = p.pageCodec();
            pager.setPageCodec(sb.pageCodec);
            publishSuperblock(visibleSeq);
        } finally {
            structure.unlock();
        }
    }

    /**
     * Stops the engine <strong>without</strong> a final superblock, a seal or a
     * flush — what a killed process leaves behind.
     *
     * <p>{@code 10-transactions.md} §4: what a crash loses is batches whose seq
     * range had not reached {@code visible_seq}; what it cannot do, at any
     * durability setting, is produce a structurally invalid database.
     */
    public void abandon() {
        closing = true;
        signalVisible();
        wake(committer);
        wake(compactor);
        join(committer);
        join(compactor);
        if (cipher != null) {
            cipher.close();
        }
        file.close();
    }

    public long compactionCount() {
        return compactions.get();
    }

    public double segmentsProbedPerLookup() {
        long n = lookups.get();
        return n == 0 ? 0 : (double) segmentsProbed.get() / n;
    }

    public double valueReadsPerScannedRow() {
        long n = scannedRows.get();
        return n == 0 ? 0 : (double) valueReads.get() / n;
    }

    public double localityDebt() {
        return vlog.localityDebt();
    }

    public Options options() {
        return options;
    }

    /** Allocates a fresh user tree id. */
    public int allocateTreeId() {
        structure.lock();
        try {
            long id = sb.nextTreeId;
            sb.nextTreeId = id + 1;
            return (int) id;
        } finally {
            structure.unlock();
        }
    }

    public void lockStructure() {
        structure.lock();
    }

    public void unlockStructure() {
        structure.unlock();
    }

    // ==================================================================
    // checkpoints, the change feed and the space API — 13
    // ==================================================================

    /**
     * Creates a named checkpoint — {@code 13-operations.md} §1.
     *
     * <p>A checkpoint pins space, exactly as a live reader does, so the default
     * refusal above {@code checkpointSpaceLimitPct} is normative rather than
     * cautious: the space it holds is invisible from outside and is the usual
     * reason a database stops shrinking.
     */
    public Checkpoint checkpoint(String name, Long expiresUtcMs, boolean overrideSpaceLimit) {
        structure.lock();
        try {
            long pinned = pinnedBySnapshots();
            long live = Math.max(1, liveBytes());
            if (!overrideSpaceLimit && pinned * 100 > live * (long) options.checkpointSpaceLimitPct) {
                throw new InvalidArgumentException("checkpoint '" + name + "' would pin " + pinned
                        + " bytes against " + live + " live, above the "
                        + options.checkpointSpaceLimitPct + "% limit; pass overrideSpaceLimit to accept it");
            }
            Checkpoint c = new Checkpoint(name, sb.commitId, visibleSeq,
                    options.clock.getAsLong(), sb.catalogRoot, sb.freelistRoot, sb.attributesRoot,
                    sb.manifestRoot, sb.vlogStatsRoot, sb.changefeedRoot, expiresUtcMs);
            checkpointTree.put(Checkpoint.key(name), Cve.encode(c.toValue()));
            liveSnapshots.add(new long[]{c.seq(), c.commitId()});
            publishSuperblock(visibleSeq);
            return c;
        } finally {
            structure.unlock();
        }
    }

    public List<Checkpoint> checkpoints() {
        structure.lock();
        try {
            return Checkpoint.all(checkpointTree);
        } finally {
            structure.unlock();
        }
    }

    public Checkpoint checkpointNamed(String name) {
        structure.lock();
        try {
            byte[] raw = checkpointTree.get(Checkpoint.key(name));
            return raw == null ? null : Checkpoint.fromValue(name, Cve.decode(raw));
        } finally {
            structure.unlock();
        }
    }

    /**
     * Restores a checkpoint. One superblock write, therefore atomic and instant.
     *
     * <p><strong>Restore rolls back roots, never counters.</strong>
     * {@code next_seq}, {@code next_tree_id}, {@code next_segment_id},
     * {@code next_vlog_segment_id} and — critically — {@code next_nonce} keep
     * their current values. Rolling {@code next_nonce} back would hand out
     * values the abandoned commits already used, and the pages that used them
     * are still in the file until they are reclaimed: same key, same nonce, two
     * plaintexts.
     */
    public void restore(String name) {
        structure.lock();
        try {
            Checkpoint c = checkpointNamed(name);
            if (c == null) {
                throw new InvalidArgumentException("no checkpoint named '" + name + "'");
            }
            for (var shard : shards) {
                shard.clear();
            }
            pendingRangeDeletes.clear();
            c.asSnapshot(sb.checkpointRoot).applyTo(sb);
            reloadTrees();
            visibleSeq = c.seq();
            completeAll(c.seq());
            publishSuperblock(c.seq(), true);
        } finally {
            structure.unlock();
        }
    }

    private void completeAll(long through) {
        seqLock.lock();
        try {
            completedRanges.clear();
            completedThrough = Math.max(completedThrough, through);
        } finally {
            seqLock.unlock();
        }
    }

    /** Re-reads every internal tree from the superblock's roots. */
    private void reloadTrees() {
        segmentCache.clear();
        loadTrees();
    }

    /** §7: appends a change record in the same batch as the mutation it describes. */
    public void recordChange(Engine.Batch batch, int treeId, long seq, String op, byte[] cke, Long id) {
        structure.lock();
        try {
            ChangeFeed c = new ChangeFeed(treeId, seq, op, cke, id);
            changefeedTree.put(ChangeFeed.key(treeId, seq), Cve.encode(c.toValue()));
        } finally {
            structure.unlock();
        }
    }

    public List<ChangeFeed> changesSince(int treeId, long fromSeq) {
        structure.lock();
        try {
            return ChangeFeed.read(changefeedTree, treeId, fromSeq);
        } finally {
            structure.unlock();
        }
    }

    /** §5: full or ranged compaction to the last level. Incremental and resumable. */
    public void compact() {
        int guard = 0;
        while (compactOnce() && guard++ < 1000) {
            // Each call is one job and takes the structure lock for its own
            // duration only, so a foreground write can interleave.
        }
        structure.lock();
        try {
            int last = lastLevel();
            for (int l = 0; l < last; l++) {
                if (!manifest.at(l).isEmpty()) {
                    compactLevel(l);
                }
            }
        } finally {
            structure.unlock();
        }
    }

    /** §5: a value-log GC pass. */
    public void collect() {
        structure.lock();
        try {
            collect0();
        } finally {
            structure.unlock();
        }
    }

    /** §5: drive {@code locality_debt} back under its bound. */
    public void cluster() {
        compact();
        collectIfNeeded();
    }

    /**
     * §5: relocate live extents downward and truncate.
     *
     * <p><em>ponytail: this truncates trailing free space rather than relocating
     * live extents.</em> It reclaims everything a compaction has already moved
     * out of the tail, which is the common case after {@code compact()}, and
     * needs no extent rewriting at all. A live extent below a free one keeps
     * its place; add relocation when a workload shows the tail is not where the
     * free space ends up.
     */
    public long shrink() {
        structure.lock();
        try {
            long before = pager.pageCount();
            long tail = before;
            java.util.Set<Long> free = new HashSet<>();
            for (Pager.FreeExtent e : pager.freeList()) {
                if (e.commitId() <= sb.minRetainedCommit) {
                    for (long p = e.startPage(); p < e.startPage() + e.pages(); p++) {
                        free.add(p);
                    }
                }
            }
            while (tail > 2 && free.contains(tail - 1)) {
                tail--;
            }
            if (tail == before) {
                return 0;
            }
            pager.truncateTo(tail);
            publishSuperblock(visibleSeq);
            return before - tail;
        } finally {
            structure.unlock();
        }
    }

    /** §5: add a keyslot. One superblock write; the master key is unchanged. */
    public void addKey(byte[] password, byte[] rawKey, String label) {
        requireEncrypted();
        structure.lock();
        try {
            Keyslot[] slots = Keyslot.decodeAll(sb.keyslots);
            int free = -1;
            for (int i = 0; i < slots.length; i++) {
                if (!slots[i].occupied()) {
                    free = i;
                    break;
                }
            }
            if (free < 0) {
                throw new InvalidArgumentException("all " + Keyslot.COUNT + " keyslots are occupied");
            }
            byte[] master = currentMasterKey();
            try {
                slots[free] = password != null
                        ? FileCipher.wrapWithPassword(master, sb.databaseUuid, free, password, label,
                                options.profile.argon2TCost(), options.profile.argon2MCostKib(),
                                options.profile.argon2Parallelism())
                        : FileCipher.wrapWithRawKey(master, sb.databaseUuid, free, rawKey, label);
            } finally {
                java.util.Arrays.fill(master, (byte) 0);
            }
            sb.keyslots = Keyslot.encodeAll(slots);
            publishSuperblock(visibleSeq);
        } finally {
            structure.unlock();
        }
    }

    /**
     * §5: drop a keyslot. Removing the <em>last</em> occupied one is
     * crypto-erase and MUST be asked for by name, so it is refused here.
     */
    public void removeKey(int slotIndex) {
        requireEncrypted();
        structure.lock();
        try {
            Keyslot[] slots = Keyslot.decodeAll(sb.keyslots);
            int occupied = 0;
            for (Keyslot k : slots) {
                if (k.occupied()) {
                    occupied++;
                }
            }
            if (occupied <= 1 && slots[slotIndex].occupied()) {
                throw new InvalidArgumentException(
                        "removing the last occupied keyslot is crypto-erase; call cryptoErase() by name");
            }
            slots[slotIndex] = new Keyslot();
            sb.keyslots = Keyslot.encodeAll(slots);
            publishSuperblock(visibleSeq);
        } finally {
            structure.unlock();
        }
    }

    /**
     * §5 and {@code 14-security.md} §8.2: zero every keyslot in <strong>both</strong>
     * superblock slots. Irreversible, in the time of one write, without touching
     * a byte of data — the only erase that means anything on flash, where
     * overwriting is a lie the controller tells you.
     */
    public void cryptoErase() {
        requireEncrypted();
        structure.lock();
        try {
            sb.keyslots = new byte[Keyslot.COUNT * Keyslot.BYTES];
            // Both slots, since either may hold an intact keyslot copy.
            publishSuperblock(visibleSeq);
            publishSuperblock(visibleSeq);
        } finally {
            structure.unlock();
        }
    }

    private void requireEncrypted() {
        if (cipher == null || sb.cipher == Superblock.Cipher.NONE) {
            throw new InvalidArgumentException("the file is not encrypted");
        }
    }

    private byte[] currentMasterKey() {
        return FileCipher.unwrap(Keyslot.decodeAll(sb.keyslots), sb.databaseUuid,
                options.password, options.rawKey);
    }

    // ==================================================================
    // close — 10 §10
    // ==================================================================

    @Override
    public void close() {
        if (closing) {
            return;
        }
        closing = true;
        signalVisible();
        wake(committer);
        wake(compactor);
        join(committer);
        join(compactor);
        if (!file.readOnly()) {
            structure.lock();
            try {
                long target = Math.max(visibleSeq, completedThrough());
                flushShards(target);
                vlog.sealAll();
                publishSuperblock(target);
            } finally {
                structure.unlock();
            }
        }
        if (cipher != null) {
            cipher.close();
        }
        file.close();
    }

    private static void join(Thread t) {
        if (t == null) {
            return;
        }
        try {
            t.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
