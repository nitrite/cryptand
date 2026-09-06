package org.dizitart.cryptand;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The Java half of {@code spec/11-conformance.md} §6's mandatory round-trip
 * gate.
 *
 * <blockquote>"for each golden file, open it in implementation A, mutate it,
 * close it, open it in B, verify, mutate, close, reopen in A. <strong>This is
 * the actual product claim and it must be tested as such.</strong>"</blockquote>
 *
 * <p>The other halves are {@code reference/rust/cryptand/src/bin/interop.rs} and
 * {@code reference/dart/cryptand/tool/interop.dart}. All three implement the
 * same four commands over the same fixture; what they share is the fixture and
 * the digest, not an implementation.
 *
 * <p>Commands: {@code write}, {@code read}, {@code mutate <tag>},
 * {@code verify}, each taking a file path and an optional {@code --key <hex>}.
 */
public final class Interop {

    public static final String COLLECTION = "orders";
    public static final String NAME_DICT = "orders$names";
    public static final String INDEX = "idx:orders:country:non_unique";
    public static final int N = 400;
    public static final String[] COUNTRIES = {"de", "fr", "uk", "in", "us"};

    private Interop() {
    }

    /**
     * A document is {@code {_id, seq, country, note}}. Every tenth {@code note}
     * is 900 bytes, above {@code desktop}'s {@code vlog_min} of 256, so the
     * fixture exercises both the inline and the separated value path.
     */
    static Value.Doc document(long i, byte[] note) {
        byte[] body = note;
        if (body == null) {
            int len = i % 10 == 0 ? 900 : 40;
            body = new byte[len];
            Arrays.fill(body, (byte) (i % 251));
        }
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("_id", new Value.NitriteId(i));
        f.put("seq", Value.integer(NumType.I32, i));
        f.put("country", new Value.Str(COUNTRIES[(int) (i % 5)]));
        f.put("note", new Value.Bytes(body));
        return Value.Doc.of(f);
    }

    /** One visible row, as the digest sees it. */
    record Row(long id, String country, byte[] note) {
    }

    /**
     * The canonical digest over the visible state. CRC-32C because
     * {@code 00-conventions.md} §6 already makes it mandatory everywhere, so no
     * side needs a primitive another lacks.
     */
    static int digest(List<Row> rows) {
        ByteWriter w = new ByteWriter(rows.size() * 24);
        for (Row r : rows) {
            w.u64(r.id());
            w.u32(r.country().length());
            w.bytes(r.country().getBytes(StandardCharsets.UTF_8));
            w.u32(r.note().length);
            w.bytes(r.note(), 0, Math.min(8, r.note().length));
        }
        byte[] b = w.toBytes();
        return Crc32c.of(b, 0, b.length);
    }

    // ==================================================================

    private static final class Db implements AutoCloseable {
        final Database db;
        final Engine engine;
        final int data;
        final int dict;
        final int index;
        final NameDict names = new NameDict();

        Db(Database db, int data, int dict, int index) {
            this.db = db;
            this.engine = db.engine();
            this.data = data;
            this.dict = dict;
            this.index = index;
        }

        @Override
        public void close() {
            db.close();
        }
    }

    private static byte[] keyArg(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals("--key")) {
                return java.util.HexFormat.of().parseHex(args[i + 1]);
            }
        }
        return null;
    }

    private static Engine.Options options(byte[] key) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.writerId = "nitrite-java/1.0.0";
        o.durability = Superblock.Durability.SYNC;
        o.rawKey = key;
        return o;
    }

    private static Db open(String path, byte[] key) {
        Database db = Database.open(Path.of(path), options(key));
        TreeDescriptor data = db.descriptor(COLLECTION);
        TreeDescriptor dict = db.descriptor(NAME_DICT);
        if (data == null || dict == null) {
            db.close();
            throw new CorruptionException("no collection " + COLLECTION + " in " + path);
        }
        TreeDescriptor index = db.descriptor(INDEX);
        Db handle = new Db(db, data.treeId(), dict.treeId(), index == null ? 0 : index.treeId());
        loadDict(handle);
        return handle;
    }

    /** §5.3 — the per-tree field-name dictionary, read back from its own tree. */
    private static void loadDict(Db db) {
        try (Engine.Cursor c = db.engine.scan(db.dict, null, null, false)) {
            while (c.next()) {
                int id = (int) SegmentMeta.longOf(Cke.decode(c.row().key()));
                db.names.put(id, ((Value.Str) Cve.decode(c.row().value())).value());
            }
        }
    }

    /**
     * §5.3: a writer MUST write new dictionary entries in the <strong>same
     * commit</strong> as the document that first uses them.
     */
    private static int intern(Db db, String name, Engine.Batch batch) {
        Integer existing = db.names.idOf(name);
        if (existing != null) {
            return existing;
        }
        int id = db.names.intern(name);
        batch.put(db.dict, Cke.encode(Value.integer(NumType.U32, id)),
                Cve.encode(new Value.Str(name)));
        return id;
    }

    private static void put(Db db, Value.Doc doc, Engine.Batch batch) {
        long id = ((Value.NitriteId) doc.field("_id")).id();
        for (String name : doc.fields().keySet()) {
            intern(db, name, batch);
        }
        if (db.index != 0) {
            Value.Doc previous = readOne(db, id);
            if (previous != null) {
                for (byte[] k : IndexKeys.forDocument(List.of("country"), previous, false, id)) {
                    batch.remove(db.index, k);
                }
            }
            for (byte[] k : IndexKeys.forDocument(List.of("country"), doc, false, id)) {
                batch.putEmpty(db.index, k);
            }
        }
        batch.put(db.data, Cke.encode(new Value.NitriteId(id)), Cve.encode(doc, db.names));
    }

    private static Value.Doc readOne(Db db, long id) {
        byte[] raw = db.engine.get(db.data, Cke.encode(new Value.NitriteId(id)));
        return raw == null ? null : (Value.Doc) Cve.decode(raw, db.names);
    }

    private static List<Row> rows(Db db) {
        List<Row> out = new ArrayList<>();
        try (Engine.Cursor c = db.engine.scan(db.data, null, null, false)) {
            while (c.next()) {
                long id = ((Value.NitriteId) Cke.decode(c.row().key())).id();
                Value.Doc doc = (Value.Doc) Cve.decode(c.row().value(), db.names);
                Value country = doc.field("country");
                Value note = doc.field("note");
                // §5.4: `_id` MUST equal the tree key of the entry.
                Value declared = doc.field("_id");
                if (!(declared instanceof Value.NitriteId n) || n.id() != id) {
                    throw new CorruptionException("document at key " + id + " carries _id " + declared);
                }
                out.add(new Row(id,
                        country instanceof Value.Str s ? s.value() : "",
                        note instanceof Value.Bytes b ? b.value() : new byte[0]));
            }
        }
        out.sort(java.util.Comparator.comparingLong(Row::id));
        return out;
    }

    // ==================================================================
    // commands
    // ==================================================================

    private static void write(String path, byte[] key) throws Exception {
        Files.deleteIfExists(Path.of(path));
        Engine.Options o = options(key);
        o.encrypt = key != null;
        Database database = Database.create(Path.of(path), o);
        long now = database.engine().options().clock.getAsLong();

        int dictId = database.engine().allocateTreeId();
        int dataId = database.engine().allocateTreeId();
        int indexId = database.engine().allocateTreeId();
        database.putDescriptor(NAME_DICT, new TreeDescriptor.Builder()
                .treeId(dictId).kind(TreeDescriptor.Kind.NAME_DICT).levelled(true)
                .created(now).keyKind("u32").owner(COLLECTION).build());
        database.putDescriptor(COLLECTION, new TreeDescriptor.Builder()
                .treeId(dataId).kind(TreeDescriptor.Kind.DATA).levelled(true)
                .created(now).keyKind("nitrite_id").nameDict(dictId)
                .features(Feature.bit(Feature.DOCUMENTS))
                .params(Map.of("type", new Value.Str("collection"))).build());
        Map<String, Value> indexParams = new LinkedHashMap<>();
        indexParams.put("index_type", new Value.Str(TreeDescriptor.IndexType.NON_UNIQUE));
        indexParams.put("data_tree", Value.integer(NumType.U32, dataId));
        indexParams.put("fields", new Value.Array(List.of(new Value.Str("country"))));
        indexParams.put("sparse", new Value.Bool(false));
        database.putDescriptor(INDEX, new TreeDescriptor.Builder()
                .treeId(indexId).kind(TreeDescriptor.Kind.INDEX).levelled(true)
                .created(now).keyKind("array").owner(COLLECTION)
                .params(indexParams).build());
        database.engine().superblock().featuresRequired |= Feature.bit(Feature.DOCUMENTS);

        Db db = new Db(database, dataId, dictId, indexId);
        Engine.Batch batch = db.engine.batch();
        // §5.4: the reserved names SHOULD occupy name_id 1..5 in every data tree.
        for (String n : NameDict.RESERVED_FIELDS) {
            intern(db, n, batch);
        }
        for (int i = 0; i < N; i++) {
            put(db, document(i, null), batch);
            if (i % 120 == 119) {
                batch.commit();
                batch = db.engine.batch();
            }
        }
        if (batch.size() > 0) {
            batch.commit();
        }
        db.engine.commitNow();
        db.close();
        System.out.println("wrote " + N + " documents to " + path);
    }

    private static void read(String path, byte[] key) {
        try (Db db = open(path, key)) {
            List<Row> rows = rows(db);
            System.out.println("docs=" + rows.size());
            System.out.printf("digest=%08x%n", digest(rows));
            System.out.println("dict=" + db.names.size());
            System.out.println("writer=" + db.engine.superblock().writerId);
            System.out.println("page_size=" + db.engine.superblock().pageSize());
            System.out.println("commit_id=" + db.engine.superblock().commitId);
            System.out.println("segments=" + db.engine.manifest().all().size());
            System.out.println("vlog_segments=" + db.engine.vlog().allStats().size());
            List<String> names = new ArrayList<>(new TreeMap<>(db.db.catalog()).keySet());
            System.out.println("trees=" + String.join(",", names));
            if (db.index != 0) {
                // §7 — the index must answer a prefix scan over what the other
                // side wrote, or the two SDKs disagree about the same bytes.
                IndexKeys.Scan scan = IndexKeys.equalsPrefix(List.of(new Value.Str("de")));
                int hits = 0;
                try (Engine.Cursor c = db.engine.scan(db.index, scan.lower(), scan.upper(), false)) {
                    while (c.next()) {
                        if (!scan.contains(c.row().key())) {
                            break;
                        }
                        hits++;
                    }
                }
                System.out.println("index_de=" + hits);
            }
        }
    }

    private static void mutate(String path, String tag, byte[] key) {
        try (Db db = open(path, key)) {
            int updated = 0;
            int deleted = 0;
            Engine.Batch batch = db.engine.batch();
            for (int i = 0; i < N; i++) {
                if (i % 13 == 0) {
                    Value.Doc previous = readOne(db, i);
                    if (previous != null) {
                        if (db.index != 0) {
                            for (byte[] k : IndexKeys.forDocument(
                                    List.of("country"), previous, false, i)) {
                                batch.remove(db.index, k);
                            }
                        }
                        batch.remove(db.data, Cke.encode(new Value.NitriteId(i)));
                        deleted++;
                    }
                } else if (i % 7 == 0) {
                    byte[] note = Arrays.copyOf(tag.getBytes(StandardCharsets.UTF_8), 300);
                    Arrays.fill(note, tag.length(), 300, (byte) '.');
                    put(db, document(i, note), batch);
                    updated++;
                }
                if (batch.size() >= 100) {
                    batch.commit();
                    batch = db.engine.batch();
                }
            }
            if (batch.size() > 0) {
                batch.commit();
            }
            // New documents, so the other side sees ids it never wrote.
            batch = db.engine.batch();
            for (int i = N; i < N + 50; i++) {
                put(db, document(i, null), batch);
            }
            // A field name neither the fixture nor the other side has seen,
            // which exercises §5.3's "on encountering an unknown name_id a
            // reader MUST re-read the dictionary tree".
            intern(db, "touched_by_" + tag, batch);
            batch.commit();
            db.engine.commitNow();
            System.out.println("mutated by " + tag + ": " + updated + " updated, "
                    + deleted + " deleted, 50 inserted");
        }
    }

    private static int verify(String path, byte[] key) {
        try (Engine e = Engine.open(Path.of(path), options(key))) {
            Verify.Report r = Verify.run(e);
            System.out.println("verify: " + r.segments() + " segments, "
                    + r.pagesReachable() + " pages, " + r.findings().size() + " findings");
            for (Verify.Finding f : r.findings()) {
                System.out.println("  " + f.kind() + ": " + f.message());
            }
            return r.of(Verify.Kind.CORRUPTION).isEmpty() && r.of(Verify.Kind.TAMPERING).isEmpty()
                    ? 0 : 1;
        }
    }

    public static void main(String[] args) {
        byte[] key = keyArg(args);
        try {
            if (args.length >= 2 && args[0].equals("write")) {
                write(args[1], key);
            } else if (args.length >= 2 && args[0].equals("read")) {
                read(args[1], key);
            } else if (args.length >= 3 && args[0].equals("mutate")) {
                mutate(args[1], args[2], key);
            } else if (args.length >= 2 && args[0].equals("verify")) {
                System.exit(verify(args[1], key));
            } else {
                System.err.println("interop write|read|mutate <tag>|verify <file> [--key <hex>]");
                System.exit(2);
            }
        } catch (Exception e) {
            System.err.println(e);
            System.exit(1);
        }
    }
}
