package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.crypto.Argon2id;
import org.dizitart.cryptand.crypto.Security;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The logical Nitrite model over the engine — {@code spec/05-catalog.md}.
 *
 * <p>A tree is addressed by {@code tree_id : u32}; its <em>name</em> is an
 * arbitrary UTF-8 string in the catalog, subject to no escaping, mangling or
 * charset restriction whatsoever. That retires, permanently, Fjall's
 * {@code | -> _P_} partition-name substitution, Hive's base64 box keys, and
 * every "reserved character" rule that constrains what an application may call
 * a collection. A collection may be named {@code "orders|2026+eu"} and nothing
 * downstream cares.
 *
 * <p>There is no registry of collections. Enumerating them is a scan of the
 * catalog filtered on {@code kind} and {@code params.type}, so there is no
 * second place where the list is written and it cannot drift.
 */
public final class Database implements AutoCloseable {

    /** The attributes entry for the reserved name — {@code spec/05-catalog.md} §7. */
    public static final String STORE_ATTRIBUTES = "$store";

    public static final String FORMAT_VERSION = "1.0";
    public static final String NITRITE_VERSION = "1.0.0";

    private final Engine engine;
    private final Map<String, Collection> open = new ConcurrentHashMap<>();

    private Database(Engine engine) {
        this.engine = engine;
    }

    public static Database create(Path path, Engine.Options options) {
        Database db = new Database(Engine.create(path, options));
        db.initStoreMetadata(options);
        return db;
    }

    public static Database open(Path path, Engine.Options options) {
        Database db = new Database(Engine.open(path, options));
        if (!options.readOnly) {
            db.recordWriter(options.writerId);
        }
        return db;
    }

    public Engine engine() {
        return engine;
    }

    // ==================================================================
    // §7 store metadata
    // ==================================================================

    private void initStoreMetadata(Engine.Options options) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("created", new Value.Timestamp(engine.superblock().createdUtcMs));
        f.put("format_version", new Value.Str(FORMAT_VERSION));
        f.put("nitrite_version", new Value.Str(NITRITE_VERSION));
        f.put("schema_version", Value.integer(NumType.U32, 1));
        f.put("writers", new Value.Array(List.of(new Value.Str(options.writerId))));
        putAttributes(STORE_ATTRIBUTES, Value.Doc.of(f));
    }

    /**
     * §7: {@code writers} accumulates each distinct {@code writer_id} that has
     * modified the file — genuinely useful the moment a file is handed between
     * SDKs, and the first thing to look at when one misbehaves.
     */
    private void recordWriter(String writerId) {
        Value.Doc store = attributes(STORE_ATTRIBUTES);
        if (store == null) {
            return;
        }
        List<Value> writers = new ArrayList<>();
        Value existing = store.field("writers");
        if (existing instanceof Value.Array a) {
            for (Value v : a.items()) {
                if (v instanceof Value.Str s && s.value().equals(writerId)) {
                    return;
                }
                writers.add(v);
            }
        }
        writers.add(new Value.Str(writerId));
        Map<String, Value> f = new LinkedHashMap<>(store.fields());
        f.put("writers", new Value.Array(writers));
        putAttributes(STORE_ATTRIBUTES, Value.Doc.of(f));
    }

    // ==================================================================
    // §6 attributes
    // ==================================================================

    public Value.Doc attributes(String treeName) {
        engine.lockStructure();
        try {
            byte[] raw = engine.attributesTree().get(Cke.encode(new Value.Str(treeName)));
            return raw == null ? null : (Value.Doc) Cve.decode(raw);
        } finally {
            engine.unlockStructure();
        }
    }

    public void putAttributes(String treeName, Value.Doc doc) {
        engine.lockStructure();
        try {
            engine.attributesTree().put(Cke.encode(new Value.Str(treeName)), Cve.encode(doc));
        } finally {
            engine.unlockStructure();
        }
    }

    // ==================================================================
    // §1, §3 the catalog
    // ==================================================================

    /**
     * The internal trees are plain copy-on-write B+trees held in memory and
     * rewritten by the committer, so every read of one takes the structure lock.
     * They are small, hot and almost entirely cached — which is why
     * {@code 04-segments.md} §3.3 makes them plain trees in the first place — so
     * the lock is short and uncontended, and without it a reader iterating the
     * catalog while the committer republishes a root gets a
     * {@code ConcurrentModificationException} rather than an answer.
     */
    public TreeDescriptor descriptor(String name) {
        engine.lockStructure();
        try {
            byte[] raw = engine.catalogTree().get(TreeDescriptor.catalogKey(name));
            return raw == null ? null : TreeDescriptor.decode(raw, null);
        } finally {
            engine.unlockStructure();
        }
    }

    public void putDescriptor(String name, TreeDescriptor d) {
        engine.lockStructure();
        try {
            engine.catalogTree().put(TreeDescriptor.catalogKey(name), d.encode(null));
            // Tree 3 is the reverse of the catalog. It is a second copy, but a
            // derived one that the same commit writes, so it cannot drift the
            // way a hand-maintained registry does - and §2 says it may be
            // rebuilt by scanning the catalog if it is ever missing.
            engine.treeIndexTree().put(Cke.encode(Value.integer(NumType.U32, d.treeId())),
                    Cve.encode(new Value.Str(name)));
        } finally {
            engine.unlockStructure();
        }
    }

    /** Every catalog entry, name and descriptor. */
    public Map<String, TreeDescriptor> catalog() {
        engine.lockStructure();
        try {
            Map<String, TreeDescriptor> out = new LinkedHashMap<>();
            for (Map.Entry<byte[], byte[]> e : engine.catalogTree().map().entrySet()) {
                String name = ((Value.Str) Cke.decode(e.getKey())).value();
                out.put(name, TreeDescriptor.decode(e.getValue(), null));
            }
            return out;
        } finally {
            engine.unlockStructure();
        }
    }

    /** §11: what collections exist — {@code kind == "data"}, {@code params.type == "collection"}. */
    public List<String> collectionNames() {
        return dataNamesOfType("collection", false);
    }

    /** §11: repositories are {@code params.type == "repository"} with no {@code params.key}. */
    public List<String> repositoryNames() {
        return dataNamesOfType("repository", false);
    }

    public List<String> keyedRepositoryNames() {
        return dataNamesOfType("repository", true);
    }

    private List<String> dataNamesOfType(String type, boolean keyed) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, TreeDescriptor> e : catalog().entrySet()) {
            TreeDescriptor d = e.getValue();
            if (!TreeDescriptor.Kind.DATA.equals(d.kind())) {
                continue;
            }
            Value t = d.params().field("type");
            if (!(t instanceof Value.Str s) || !s.value().equals(type)) {
                continue;
            }
            if ((d.params().field("key") != null) != keyed) {
                continue;
            }
            out.add(e.getKey());
        }
        return out;
    }

    /** §11: what indexes {@code owner} has. */
    public List<String> indexNames(String owner) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, TreeDescriptor> e : catalog().entrySet()) {
            TreeDescriptor d = e.getValue();
            if (owner.equals(d.owner()) && isIndexKind(d.kind())) {
                out.add(e.getKey());
            }
        }
        return out;
    }

    static boolean isIndexKind(String kind) {
        return TreeDescriptor.Kind.INDEX.equals(kind)
                || TreeDescriptor.Kind.TERM_DICT.equals(kind)
                || TreeDescriptor.Kind.TERM_INDEX.equals(kind)
                || TreeDescriptor.Kind.POSTINGS.equals(kind)
                || TreeDescriptor.Kind.RTREE.equals(kind)
                || TreeDescriptor.Kind.VECTOR_GRAPH.equals(kind);
    }

    /** §11: any descriptor carrying {@code stale_from}. */
    public List<String> staleIndexNames() {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, TreeDescriptor> e : catalog().entrySet()) {
            if (e.getValue().staleFrom() != null) {
                out.add(e.getKey());
            }
        }
        return out;
    }

    /** §11: the superblock's {@code features_required} plus the union of every tree's. */
    public long featuresRequired() {
        long features = engine.superblock().featuresRequired;
        for (TreeDescriptor d : catalog().values()) {
            features |= d.features();
        }
        return features;
    }

    // ==================================================================
    // §5 collections and repositories
    // ==================================================================

    public Collection collection(String name) {
        return open.computeIfAbsent(name, n -> openOrCreateData(n, collectionParams()));
    }

    public Collection repository(String entity) {
        return open.computeIfAbsent(entity, n -> openOrCreateData(n, repositoryParams(entity, null)));
    }

    /**
     * §5: the {@code +} in a keyed repository name is retained for continuity
     * with existing Nitrite names, but it is now just a character in a string,
     * not a separator any layer has to escape. {@code params} carries the
     * structured truth; the name is for humans.
     */
    public Collection keyedRepository(String entity, String key) {
        String name = entity + "+" + key;
        return open.computeIfAbsent(name, n -> openOrCreateData(n, repositoryParams(entity, key)));
    }

    private static Value.Doc collectionParams() {
        return Value.Doc.of(Map.of("type", new Value.Str("collection")));
    }

    private static Value.Doc repositoryParams(String entity, String key) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("type", new Value.Str("repository"));
        f.put("entity", new Value.Str(entity));
        if (key != null) {
            f.put("key", new Value.Str(key));
        }
        return Value.Doc.of(f);
    }

    private Collection openOrCreateData(String name, Value.Doc params) {
        TreeDescriptor d = descriptor(name);
        if (d == null) {
            engine.lockStructure();
            try {
                d = descriptor(name);
                if (d == null) {
                    int dataId = engine.allocateTreeId();
                    int dictId = engine.allocateTreeId();
                    long now = engine.options().clock.getAsLong();
                    TreeDescriptor dict = new TreeDescriptor.Builder()
                            .treeId(dictId)
                            .kind(TreeDescriptor.Kind.NAME_DICT)
                            .levelled(true)
                            .created(now)
                            .keyKind("u32")
                            .owner(name)
                            .build();
                    d = new TreeDescriptor.Builder()
                            .treeId(dataId)
                            .kind(TreeDescriptor.Kind.DATA)
                            .levelled(true)
                            .created(now)
                            .keyKind("nitrite_id")
                            .nameDict(dictId)
                            .features(Feature.bit(Feature.DOCUMENTS))
                            .params(params.fields())
                            .build();
                    putDescriptor(name + ":names", dict);
                    putDescriptor(name, d);
                    Map<String, Value> attrs = new LinkedHashMap<>();
                    attrs.put("name", new Value.Str(name));
                    attrs.put("created_at", new Value.Timestamp(now));
                    attrs.put("last_modified_at", new Value.Timestamp(now));
                    putAttributes(name, Value.Doc.of(attrs));
                }
            } finally {
                engine.unlockStructure();
            }
        }
        return new Collection(this, name, d);
    }

    /** Drops a data tree and every index that names it as {@code owner}. */
    public void drop(String name) {
        TreeDescriptor d = descriptor(name);
        if (d == null) {
            return;
        }
        Collection c = collection(name);
        c.clear();
        for (String index : indexNames(name)) {
            TreeDescriptor id = descriptor(index);
            if (id != null) {
                Engine.Batch b = engine.batch();
                b.removeRange(id.treeId(), Cke.UNBOUNDED_BELOW, new byte[]{(byte) 0xFE});
                b.commit();
            }
            removeCatalogEntry(index);
        }
        removeCatalogEntry(name);
        open.remove(name);
    }

    private void removeCatalogEntry(String name) {
        TreeDescriptor d = descriptor(name);
        engine.lockStructure();
        try {
            engine.catalogTree().remove(TreeDescriptor.catalogKey(name));
            if (d != null) {
                engine.treeIndexTree().remove(Cke.encode(Value.integer(NumType.U32, d.treeId())));
            }
        } finally {
            engine.unlockStructure();
        }
    }

    // ==================================================================
    // §8 users
    // ==================================================================

    /**
     * Adds a credential record to tree 5.
     *
     * <p>{@code 14-security.md} §10 is normative on what this is and is not: a
     * password-protected but <em>unencrypted</em> database protects nothing
     * against an attacker holding the file — tree 5 is in the file, beside
     * plaintext data — so this warns rather than pretending otherwise. On an
     * encrypted database it is application-level role separation, not a second
     * confidentiality boundary: whoever opened the file has the master key.
     */
    public void addUser(String username, byte[] password, Profile costProfile) {
        if (engine.superblock().cipher == Superblock.Cipher.NONE) {
            System.getLogger(Database.class.getName()).log(System.Logger.Level.WARNING,
                    "a user was created on an unencrypted database; this is role separation, "
                            + "not protection - anyone holding the file can read all of it "
                            + "(spec/14-security.md §10)");
        }
        byte[] salt = new byte[32];
        new java.security.SecureRandom().nextBytes(salt);
        int t = costProfile.argon2TCost();
        int m = costProfile.argon2MCostKib();
        int p = costProfile.argon2Parallelism();
        byte[] hash = Argon2id.hash(password, salt, t, m, p, 32);
        Map<String, Value> params = new LinkedHashMap<>();
        params.put("t_cost", Value.integer(NumType.U32, t));
        params.put("m_cost_kib", Value.integer(NumType.U32, m));
        params.put("parallelism", Value.integer(NumType.U32, p));
        Map<String, Value> record = new LinkedHashMap<>();
        record.put("username", new Value.Str(username));
        record.put("kdf", new Value.Str("argon2id"));
        record.put("params", Value.Doc.of(params));
        record.put("salt", new Value.Bytes(salt));
        record.put("hash", new Value.Bytes(hash));
        engine.lockStructure();
        try {
            engine.usersTree().put(Cke.encode(new Value.Str(username)),
                    Cve.encode(Value.Doc.of(record)));
        } finally {
            engine.unlockStructure();
        }
    }

    /** Constant-time comparison — §8 requires it, and a byte-by-byte compare is an oracle. */
    public boolean authenticate(String username, byte[] password) {
        byte[] raw;
        engine.lockStructure();
        try {
            raw = engine.usersTree().get(Cke.encode(new Value.Str(username)));
        } finally {
            engine.unlockStructure();
        }
        if (raw == null) {
            return false;
        }
        // Everything below this line came out of the file.
        //
        // A **keyslot's** KDF parameters are deliberately obeyed as stored —
        // §3.2: "on open it MUST use whatever the slot says — the superblock MAC
        // (§6) is what prevents an attacker weakening those numbers". That
        // reasoning does not reach here. `sb_mac` covers the superblock, not a
        // tree's contents, and §10 explicitly contemplates users on an
        // *unencrypted* database, where nothing authenticates this record at
        // all. So §9.1 governs instead, and it "applies to every implementation,
        // whether or not it supports encryption, because T5 does not require the
        // attacker to have a key".
        Value decoded = Cve.decode(raw);
        if (!(decoded instanceof Value.Doc d)) {
            throw new CorruptionException(
                    "tree 5 holds a " + decoded.getClass().getSimpleName()
                            + " for user '" + username + "', not a credential record");
        }
        // §8: "`kdf` MUST be \"argon2id\"". A record naming another KDF is not a
        // record to verify with this one; it is a record this implementation
        // cannot check. §9.2 forbids resolving the name to anything, so the only
        // conforming answer is to refuse.
        if (!(d.field("kdf") instanceof Value.Str kdf) || !"argon2id".equals(kdf.value())) {
            throw new UnsupportedFeatureException(
                    "user '" + username + "' has kdf "
                            + (d.field("kdf") == null ? "absent" : d.field("kdf"))
                            + "; §8 requires argon2id");
        }
        if (!(d.field("params") instanceof Value.Doc params)) {
            throw new CorruptionException("user '" + username + "' has no params document");
        }
        if (!(d.field("salt") instanceof Value.Bytes saltV)
                || !(d.field("hash") instanceof Value.Bytes hashV)) {
            throw new CorruptionException(
                    "user '" + username + "' is missing salt or hash");
        }
        long t = kdfParam(params, "t_cost", username);
        long m = kdfParam(params, "m_cost_kib", username);
        long p = kdfParam(params, "parallelism", username);
        // §8 requires "the parameters of §3.2", and §3.2's floor is t_cost 2,
        // m_cost_kib 16384, parallelism 1 — below every profile in its table, so
        // no conforming record trips this. Accepting a record beneath the floor
        // is accepting a hash an attacker has already made cheap to grind.
        if (t < 2 || m < 16384 || p < 1) {
            throw new CorruptionException("user '" + username + "' declares t_cost=" + t
                    + " m_cost_kib=" + m + " parallelism=" + p
                    + ", below §3.2's floor of 2 / 16384 / 1");
        }
        // And a ceiling, which §3.2 does not state because it is describing a
        // writer's choice rather than a reader's exposure. §12 budgets "64–256
        // MiB transient" at open; 1 GiB is four times the largest profile and
        // still a bounded allocation, where `m_cost_kib` straight from the file
        // is not.
        if (t > MAX_USER_T_COST || m > MAX_USER_M_COST_KIB || p > MAX_USER_PARALLELISM) {
            throw new LimitException("user '" + username + "' declares t_cost=" + t
                    + " m_cost_kib=" + m + " parallelism=" + p
                    + ", above the ceiling this reader will allocate for");
        }
        byte[] salt = saltV.value();
        byte[] expected = hashV.value();
        byte[] actual = Argon2id.hash(password, salt, (int) t, (int) m, (int) p, expected.length);
        return Security.constantTimeEquals(expected, actual);
    }

    /** §3.2's floor for a credential record, below every profile in its table. */
    private static final long MAX_USER_T_COST = 64;
    /** 1 GiB — four times `desktop`'s 256 MiB, and still bounded. */
    private static final long MAX_USER_M_COST_KIB = 1024L * 1024L;
    private static final long MAX_USER_PARALLELISM = 64;

    private static long kdfParam(Value.Doc params, String name, String username) {
        Value v = params.field(name);
        if (v == null) {
            throw new CorruptionException(
                    "user '" + username + "' has no " + name + " in its params");
        }
        try {
            return SegmentMeta.longOf(v);
        } catch (RuntimeException e) {
            throw new CorruptionException(
                    "user '" + username + "' has a non-numeric " + name);
        }
    }

    // ==================================================================

    public Transaction begin() {
        return new Transaction(this, Transaction.Isolation.SNAPSHOT);
    }

    public Transaction begin(Transaction.Isolation isolation) {
        return new Transaction(this, isolation);
    }

    public void commit() {
        engine.commitNow();
    }

    @Override
    public void close() {
        engine.close();
    }
}
