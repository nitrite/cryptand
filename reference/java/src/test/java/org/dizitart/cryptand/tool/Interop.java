package org.dizitart.cryptand.tool;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.key.IndexKeys;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.util.Crc32c;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NameDict;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

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
    static final class Row {
        private final long id;
        private final String country;
        private final byte[] note;

        public Row(long id, String country, byte[] note) {
            this.id = id;
            this.country = country;
            this.note = note;
        }

        public long id() {
            return id;
        }

        public String country() {
            return country;
        }

        public byte[] note() {
            return note;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Row)) {
                return false;
            }
            Row that = (Row) o;
            return id == that.id
                    && java.util.Objects.equals(country, that.country)
                    && java.util.Objects.equals(note, that.note);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(id, country, note);
        }

        @Override
        public String toString() {
            return "Row[" + "id=" + id + ", " + "country=" + country + ", " + "note=" + note + "]";
        }
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
                return org.dizitart.cryptand.util.Hex.parse(args[i + 1]);
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

    /** As {@link #open}, but the handle may not write. See the caller. */
    private static Db openReadOnly(String path, byte[] key) {
        Engine.Options o = options(key);
        o.readOnly = true;
        return open(path, o);
    }

    private static Db open(String path, byte[] key) {
        return open(path, options(key));
    }

    private static Db open(String path, Engine.Options opts) {
        Database db = Database.open(Path.of(path), opts);
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
                if (!(declared instanceof Value.NitriteId) || ((Value.NitriteId) declared).id() != id) {
                    throw new CorruptionException("document at key " + id + " carries _id " + declared);
                }
                out.add(new Row(id,
                        country instanceof Value.Str ? ((Value.Str) country).value() : "",
                        note instanceof Value.Bytes ? ((Value.Bytes) note).value() : new byte[0]));
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
            // So the other side reads, verifies and allocates from a file whose
            // extents `shrink()` moved.
            db.engine.compact();
            db.engine.shrink();
            System.out.println("mutated by " + tag + ": " + updated + " updated, "
                    + deleted + " deleted, 50 inserted");
        }
    }

    /**
     * F-072: {@code encrypt <plaintext file> --key K [--half]}; {@code --half}
     * stops before converting anything, so plaintext and encrypted objects
     * sit side by side.
     */
    private static void encrypt(String path, byte[] key, boolean half) {
        try (Engine e = Engine.open(Path.of(path), options(null))) {
            e.encrypt(null, key);
            while (!half && e.convertStep()) {
                // until nothing plaintext remains
            }
            Engine.Conversion c = e.conversion();
            System.out.println("encrypted " + path + ": converted=" + c.converted + " remaining=" + c.remaining);
        }
    }

    /** {@code decrypt <encrypted file> --key K [--half]}: {@code --half} stops after one step. */
    private static void decrypt(String path, byte[] key, boolean half) {
        try (Engine e = Engine.open(Path.of(path), options(key))) {
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            boolean more = e.convertStep();
            while (!half && more) {
                more = e.convertStep();
            }
            System.out.println("decrypted " + path + ": cipher=" + e.superblock().cipher);
        }
    }

    private static final int INDEXED = 400;

    /**
     * F-079: a file whose indexes keep their own structures (an R-tree, a
     * vector graph and region), for the conversion and rotation steps.
     * {@code os} durability: {@code sync} grows the file per commit (F-080).
     */
    private static void writeIndexed(String path, byte[] key) {
        Engine.Options o = options(key);
        o.durability = Superblock.Durability.OS;
        o.encrypt = key != null;
        try (Database db = Database.create(Path.of(path), o)) {
            org.dizitart.cryptand.Collection c = db.collection("places");
            c.createSpatialIndex("at", 2, null);
            c.createVectorIndex("embedding", 4, org.dizitart.cryptand.index.VectorIndex.METRIC_L2, 16);
            for (int i = 0; i < INDEXED; i++) {
                ByteWriter v = new ByteWriter(16);
                v.f32(i).f32(-i).f32(i * 0.5f).f32(1);
                Map<String, Value> f = new LinkedHashMap<>();
                f.put("n", Value.i64(i));
                f.put("at", new Value.Geometry(new ByteWriter(21).u8(1).u32(1).f64(i).f64(-i).toBytes()));
                f.put("embedding", new Value.Vector(Value.Vector.DTYPE_F32, 4, v.toBytes()));
                c.insert(Value.Doc.of(f));
            }
        }
        System.out.println("wrote " + INDEXED + " indexed documents to " + path);
    }

    /** Every 7th document found again through both indexes. */
    private static int checkIndexed(String path, byte[] key) {
        Engine.Options o = options(key);
        o.durability = Superblock.Durability.OS;
        try (Database db = Database.open(Path.of(path), o)) {
            org.dizitart.cryptand.Collection c = db.collection("places");
            int bad = 0;
            for (int i = 0; i < INDEXED; i += 7) {
                long viaVector = c.vectorIndexes().get(0).search(new float[] {i, -i, i * 0.5f, 1}, 1).get(0).nitriteId();
                long viaSpatial = c.spatialIndexes().get(0).nearestK(i, -i, 1).get(0);
                for (long id : new long[] {viaVector, viaSpatial}) {
                    Value n = c.get(id).field("n");
                    if (n == null || SegmentMeta.longOf(n) != i) {
                        bad++;
                    }
                }
            }
            System.out.println("indexed: " + (bad == 0 ? "ok" : bad + " wrong answers"));
            return bad == 0 ? 0 : 1;
        }
    }

    /** F-072: {@code rotate <encrypted file> <new key hex> --key K}, copy-and-swap. */
    private static void rotate(String path, byte[] key, byte[] newKey) {
        Engine e = Engine.rotateMasterKey(Engine.open(Path.of(path), options(key)), null, newKey);
        e.close();
        System.out.println("rotated " + path);
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

    // =================================================================
    // The shared conformance corpus, 11 section 6 and 14 section 13
    // =================================================================

    /**
     * Runs {@code reference/conformance/files/} against this reader — <strong>
     * bytes this implementation did not write</strong>.
     *
     * <p>That is the whole point of it. Every implementation already has
     * thorough negative tests, and every one of them builds its own broken file
     * with its own writer and checks that its own reader refuses it. Such a
     * test can agree with itself and disagree with everyone else; phase 15
     * recorded the shape — "a self-generated vector set cannot contain this
     * fix: the generator and its test both knew they were writing a prefix".
     *
     * <p>Its first run against the Rust implementation produced two
     * disagreements, both in Rust: a {@code payload_len} of {@code 0xFFFFFFFC}
     * read cleanly, and the section 6.1 cipher downgrade reported as corruption
     * rather than tampering.
     */
    public static int corpus(String dir) throws java.io.IOException {
        String manifest = Files.readString(Path.of(dir, "manifest.json"));
        List<Map<String, String>> entries = parseManifest(manifest);
        if (entries.isEmpty()) {
            throw new CorruptionException("the manifest names no files");
        }
        int failed = 0;
        for (Map<String, String> e : entries) {
            String name = e.get("name");
            byte[] key = e.get("key") == null || e.get("key").equals("null")
                    ? null : unhex(e.get("key"));
            String line;
            try {
                long[] r = readCorpusFile(Path.of(dir, name), key);
                long findings = r[0];
                long documents = r[1];
                String dig = String.format("%08x", (int) r[2]);
                if (e.get("expect").equals("read")) {
                    if (findings != 0) {
                        failed++;
                        line = "FAIL  a golden file must verify clean, " + findings + " findings";
                    } else if (documents != Long.parseLong(e.get("documents"))) {
                        failed++;
                        line = "FAIL  " + documents + " documents, manifest says " + e.get("documents");
                    } else if (!dig.equals(e.get("digest"))) {
                        failed++;
                        line = "FAIL  digest " + dig + ", manifest says " + e.get("digest");
                    } else {
                        line = "ok    " + documents + " documents, digest " + dig;
                    }
                } else if (findings > 0) {
                    line = "ok    opened, " + findings + " finding(s) from verify";
                } else if ("true".equals(e.get("tolerated_clean"))) {
                    line = "ok    accepted cleanly (tolerated; the mechanism did not run)";
                } else {
                    failed++;
                    line = "FAIL  opened, read and verified with nothing reported";
                }
            } catch (org.dizitart.cryptand.CryptandException ex) {
                if (e.get("expect").equals("read")) {
                    failed++;
                    line = "FAIL  a golden file must open: " + ex;
                } else {
                    String got = classOf(ex);
                    if (got.equals(e.get("error_class"))) {
                        line = "ok    refused as " + got;
                    } else {
                        failed++;
                        line = "FAIL  refused as " + got + ", manifest says "
                                + e.get("error_class") + ": " + ex;
                    }
                }
            }
            System.out.printf("  %-38s %s%n", name, line);
        }
        System.out.println();
        System.out.println(entries.size() + " files, " + failed + " failed");
        return failed == 0 ? 0 : 1;
    }

    /**
     * Opens, verifies and <strong>reads every document</strong>. All three: the
     * manifest's {@code at_open_or_read} exists because some breakages surface
     * only on a read, and a runner that stops at {@code verify()} reports those
     * as accepted.
     *
     * @return {findings, documents, digest}
     */
    private static long[] readCorpusFile(Path path, byte[] key) {
        // **Read-only, and that is not a detail.** The corpus is the fixture
        // `11-conformance.md` §6 defines conformance *by* — "conformance is
        // defined as passing the vectors, not as matching the reference
        // implementation's source" — so a runner that writes to it redefines
        // the standard on every run.
        //
        // This one did. `Database.open` records the writer id when the handle
        // is writable (`05-catalog.md` §7), so reading the corpus committed to
        // it: 12 of the 18 files came back modified, superblock `commit_id`
        // advanced and a page appended, `v1.0-corrupt-*` and
        // `v1.0-security-*` among them. Two consequences, the second worse
        // than the first — it took a write lock, so a parallel run of another
        // implementation's suite failed against files it was only reading;
        // and it **wrote to a file it was about to report as corrupt**, which
        // is a write to storage the runner itself has not yet accepted.
        try (Db db = openReadOnly(path.toString(), key)) {
            // Corruption and tampering only. {@code spec/01-container.md} §9:
            // "A leak is repairable" — it is wasted space in a sound file, not
            // damage, and a copy-on-write container leaks tree 1's own pages by
            // one commit as a property of the format. Counting leaks made this
            // runner report nine findings on every golden file in the corpus,
            // all of them the ordinary state of a file this format produces.
            long findings = Verify.run(db.engine).findings().stream()
                    // DOUBLE_ALLOCATION counts: §9 says "A double-allocation
                    // is corruption" in the same breath as "a leak is
                    // repairable", and this implementation gives it its own
                    // kind. Two live structures naming one page means a write
                    // to either overwrites the other.
                    .filter(f -> f.kind() == Verify.Kind.CORRUPTION
                            || f.kind() == Verify.Kind.TAMPERING
                            || f.kind() == Verify.Kind.DOUBLE_ALLOCATION)
                    .count();
            List<Row> rows = rows(db);
            return new long[] {findings, rows.size(), digest(rows) & 0xFFFFFFFFL};
        }
    }

    private static String classOf(org.dizitart.cryptand.CryptandException e) {
        if (e instanceof org.dizitart.cryptand.TamperingException
                || e instanceof org.dizitart.cryptand.CannotUnlockException) {
            return "tampering";
        }
        if (e instanceof org.dizitart.cryptand.UnsupportedFeatureException) {
            return "unsupported";
        }
        return "corruption";
    }

    private static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    /**
     * A deliberately small JSON reader for a file this repository generates.
     *
     * <p>It is not a JSON parser and does not try to be: it pulls the fields the
     * corpus defines out of a pretty-printed object per entry. A wrong answer
     * here shows up as a missing field, which fails loudly, rather than as a
     * misinterpreted one — and a JSON dependency added for a test harness is a
     * dependency every adopter of this SDK inherits.
     */
    private static List<Map<String, String>> parseManifest(String text) {
        List<Map<String, String>> out = new ArrayList<>();
        String[] blocks = text.split("\"name\": \"");
        for (int i = 1; i < blocks.length; i++) {
            String block = blocks[i];
            Map<String, String> m = new LinkedHashMap<>();
            m.put("name", block.substring(0, block.indexOf('"')));
            for (String k : new String[] {"expect", "error_class", "documents", "digest",
                    "key", "tolerated_clean"}) {
                int at = block.indexOf("\"" + k + "\": ");
                if (at < 0) {
                    continue;
                }
                String rest = block.substring(at + k.length() + 4);
                int end = rest.indexOf(',');
                int nl = rest.indexOf('\n');
                if (end < 0 || (nl >= 0 && nl < end)) {
                    end = nl;
                }
                if (end < 0) {
                    continue;
                }
                String v = rest.substring(0, end).trim();
                if (v.startsWith("\"") && v.endsWith("\"")) {
                    v = v.substring(1, v.length() - 1);
                }
                m.put(k, v.equals("null") ? null : v);
            }
            out.add(m);
        }
        return out;
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
            } else if (args.length >= 2 && args[0].equals("encrypt")) {
                encrypt(args[1], key, java.util.Arrays.asList(args).contains("--half"));
            } else if (args.length >= 2 && args[0].equals("decrypt")) {
                decrypt(args[1], key, java.util.Arrays.asList(args).contains("--half"));
            } else if (args.length >= 2 && args[0].equals("write-indexed")) {
                writeIndexed(args[1], key);
            } else if (args.length >= 2 && args[0].equals("check-indexed")) {
                System.exit(checkIndexed(args[1], key));
            } else if (args.length >= 3 && args[0].equals("rotate")) {
                rotate(args[1], key, org.dizitart.cryptand.util.Hex.parse(args[2]));
            } else if (args.length >= 2 && args[0].equals("corpus")) {
                System.exit(corpus(args[1]));
            } else {
                System.err.println(
                        "interop write|read|mutate <tag>|verify|encrypt|decrypt <file>|rotate <file> <new key hex>|corpus <dir> [--key <hex>] [--half]");
                System.exit(2);
            }
        } catch (Exception e) {
            System.err.println(e);
            if (System.getenv("CRYPTAND_TRACE") != null) {
                e.printStackTrace();
            }
            System.exit(1);
        }
    }
}
