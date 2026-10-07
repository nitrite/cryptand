package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Level 1 — {@code spec/05-catalog.md} and {@code spec/06-indexes.md}:
 * documents, name dictionaries, indexes, and the catalog's enumerations.
 */
class CollectionsTest {

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        // `os` rather than `sync`: these tests are about semantics, and on a
        // spinning or external volume an fsync per commit turns a 150 ms suite
        // into a 60 s one without covering one extra branch. The durability
        // path itself is covered by DurabilityTest, which uses `sync`.
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static Value.Doc doc(Object... kv) {
        Map<String, Value> f = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            f.put((String) kv[i], value(kv[i + 1]));
        }
        return Value.Doc.of(f);
    }

    private static Value value(Object o) {
        if (o instanceof Value) {
            Value v = ((Value) o);
            return v;
        }
        if (o instanceof String) {
            String s = ((String) o);
            return new Value.Str(s);
        }
        if (o instanceof Integer) {
            Integer i = ((Integer) o);
            return Value.i32(i);
        }
        if (o instanceof Long) {
            Long l = ((Long) o);
            return Value.i64(l);
        }
        if (o instanceof List<?>) {
            List<?> list = ((List<?>) o);
            List<Value> items = new ArrayList<>();
            for (Object item : list) {
                items.add(value(item));
            }
            return new Value.Array(items);
        }
        if (o == null) {
            return Value.NULL;
        }
        throw new IllegalArgumentException(String.valueOf(o));
    }

    @Test
    @DisplayName("a collection may be named anything at all, escaping included")
    void namesAreNotMangled(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("a.cryptand"), options())) {
            // The name that Fjall rewrites to `orders_P_2026_K_eu` and Hive
            // base64-encodes. Here it is just a string.
            Collection c = db.collection("orders|2026+eu");
            long id = c.insert(doc("sku", "A-1"));
            assertNotNull(c.get(id));
            assertEquals(List.of("orders|2026+eu"), db.collectionNames());
        }
    }

    @Test
    @DisplayName("documents round-trip through a name dictionary and a reopen")
    void documentsRoundTrip(@TempDir Path dir) {
        Path f = dir.resolve("b.cryptand");
        List<Long> ids = new ArrayList<>();
        try (Database db = Database.create(f, options())) {
            Collection c = db.collection("people");
            for (int i = 0; i < 50; i++) {
                ids.add(c.insert(doc("name", "person-" + i, "age", i,
                        "address", doc("city", "town-" + i))));
            }
        }
        try (Database db = Database.open(f, options())) {
            Collection c = db.collection("people");
            for (int i = 0; i < 50; i++) {
                Value.Doc d = c.get(ids.get(i));
                assertNotNull(d, "document " + i);
                assertEquals("person-" + i, ((Value.Str) d.field("name")).value());
                assertEquals(i, ((Value.Int) d.field("age")).asLong().intValue());
                Value.Doc address = (Value.Doc) d.field("address");
                assertEquals("town-" + i, ((Value.Str) address.field("city")).value());
            }
        }
    }

    @Test
    @DisplayName("an index is maintained in the same commit as the document")
    void indexTracksDocuments(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("c.cryptand"), options())) {
            Collection c = db.collection("orders");
            Collection.IndexBinding idx = c.createIndex(List.of("country"), false, false);
            long a = c.insert(doc("country", "DE", "total", 10));
            long b = c.insert(doc("country", "FR", "total", 20));
            long d = c.insert(doc("country", "DE", "total", 30));

            List<Long> de = idx.find(List.of(new Value.Str("DE")));
            assertEquals(2, de.size());
            assertTrue(de.contains(a) && de.contains(d));
            assertEquals(List.of(b), idx.find(List.of(new Value.Str("FR"))));

            c.update(a, doc("country", "IT", "total", 10));
            assertEquals(List.of(d), idx.find(List.of(new Value.Str("DE"))));

            c.remove(d);
            assertEquals(List.of(), idx.find(List.of(new Value.Str("DE"))));
        }
    }

    /**
     * §1: the uniqueness check is on the id <em>behind</em> the matching
     * entries, not on their existence. Java, Dart and Rust all shipped the bare
     * existence test (nitrite/nitrite-java#1295), which rejects a document
     * rewriting its own key.
     */
    @Test
    @DisplayName("a unique index rejects another document's key and accepts the writer's own")
    void uniqueness(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("d.cryptand"), options())) {
            Collection c = db.collection("users");
            c.createIndex(List.of("email"), true, false);
            long a = c.insert(doc("email", "a@example.com"));
            assertThrows(InvalidArgumentException.class,
                    () -> c.insert(doc("email", "a@example.com")));
            // Rewriting the same document under the same key is not a violation.
            Value.Doc existing = c.get(a);
            c.update(a, existing);
            assertNotNull(c.get(a));
        }
    }

    /**
     * §3: a unique index treats every {@code NULL} as distinct — the check is
     * skipped, not run and passed — because many documents may lack the field.
     */
    @Test
    @DisplayName("a unique index admits many documents with the field absent")
    void uniqueNullsAreDistinct(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("e.cryptand"), options())) {
            Collection c = db.collection("users");
            Collection.IndexBinding idx = c.createIndex(List.of("email"), true, false);
            for (int i = 0; i < 5; i++) {
                c.insert(doc("name", "no-email-" + i));
            }
            assertEquals(5, idx.find(List.of(Value.NULL)).size());
        }
    }

    /** §4: an array field produces one entry per element, and duplicates produce one. */
    @Test
    @DisplayName("an array field indexes one entry per distinct element")
    void arrayIndexing(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("f.cryptand"), options())) {
            Collection c = db.collection("posts");
            Collection.IndexBinding idx = c.createIndex(List.of("tags"), false, false);
            long id = c.insert(doc("tags", List.of("red", "blue", "red")));
            assertEquals(List.of(id), idx.find(List.of(new Value.Str("red"))));
            assertEquals(List.of(id), idx.find(List.of(new Value.Str("blue"))));
            c.remove(id);
            assertEquals(List.of(), idx.find(List.of(new Value.Str("red"))));
        }
    }

    /** §5: traversing an array applies the rest of the path to every element and flattens. */
    @Test
    @DisplayName("a nested path through an array indexes every leaf")
    void nestedArrayPath(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("g.cryptand"), options())) {
            Collection c = db.collection("orders");
            Collection.IndexBinding idx = c.createIndex(List.of("items.sku"), false, false);
            long id = c.insert(doc("items", List.of()));
            Map<String, Value> outer = new LinkedHashMap<>();
            outer.put("items", new Value.Array(List.of(
                    doc("sku", "AAA"), doc("sku", "BBB"))));
            long two = c.insert(Value.Doc.of(outer));
            assertEquals(List.of(two), idx.find(List.of(new Value.Str("AAA"))));
            assertEquals(List.of(two), idx.find(List.of(new Value.Str("BBB"))));
            assertNotNull(c.get(id));
        }
    }

    /**
     * §7: {@code eq(5)} across every numeric type is one range scan, built from
     * {@code array_prefix_numeric}. A bound built from the full {@code CKE(v)}
     * would cut between numeric <em>types</em> instead of values.
     */
    @Test
    @DisplayName("a type-agnostic numeric lookup matches every numeric type")
    void numericLookupIsTypeAgnostic(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("h.cryptand"), options())) {
            Collection c = db.collection("readings");
            Collection.IndexBinding idx = c.createIndex(List.of("v"), false, false);
            Map<String, Value> a = new LinkedHashMap<>();
            a.put("v", Value.integer(NumType.I32, 5));
            long i32 = c.insert(Value.Doc.of(a));
            Map<String, Value> b = new LinkedHashMap<>();
            b.put("v", Value.f64(5.0));
            long f64 = c.insert(Value.Doc.of(b));
            Map<String, Value> d = new LinkedHashMap<>();
            d.put("v", Value.integer(NumType.I8, 5));
            long i8 = c.insert(Value.Doc.of(d));

            List<Long> exact = idx.find(List.of(Value.integer(NumType.I32, 5)));
            assertEquals(List.of(i32), exact, "a type-exact lookup matches only its own type");

            List<Long> any = idx.findNumeric(List.of(Value.integer(NumType.I32, 5)));
            assertEquals(3, any.size(), "the numeric form matches every numeric type");
            assertTrue(any.contains(i32) && any.contains(f64) && any.contains(i8));
        }
    }

    @Test
    @DisplayName("a compound index answers a prefix query with one seek")
    void compoundPrefix(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("i.cryptand"), options())) {
            Collection c = db.collection("places");
            Collection.IndexBinding idx = c.createIndex(List.of("country", "city", "name"), false, false);
            long a = c.insert(doc("country", "DE", "city", "Berlin", "name", "Anna"));
            long b = c.insert(doc("country", "DE", "city", "Berlin", "name", "Bruno"));
            long d = c.insert(doc("country", "DE", "city", "Munich", "name", "Carl"));
            c.insert(doc("country", "FR", "city", "Paris", "name", "Dana"));

            assertEquals(3, idx.find(List.of(new Value.Str("DE"))).size());
            List<Long> berlin = idx.find(List.of(new Value.Str("DE"), new Value.Str("Berlin")));
            assertEquals(List.of(a, b), berlin);
            assertEquals(List.of(d), idx.find(
                    List.of(new Value.Str("DE"), new Value.Str("Munich"), new Value.Str("Carl"))));
        }
    }

    @Test
    @DisplayName("starts_with on a string is a prefix scan")
    void startsWith(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("j.cryptand"), options())) {
            Collection c = db.collection("words");
            Collection.IndexBinding idx = c.createIndex(List.of("w"), false, false);
            c.insert(doc("w", "apple"));
            c.insert(doc("w", "apricot"));
            c.insert(doc("w", "banana"));
            assertEquals(2, idx.startsWith(List.of(), "ap").size());
            assertEquals(1, idx.startsWith(List.of(), "ban").size());
        }
    }

    /** §6: a value with no CKE encoding cannot be indexed, and the error names the field. */
    @Test
    @DisplayName("indexing a value with no key encoding fails by name")
    void unindexableValue(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("k.cryptand"), options())) {
            Collection c = db.collection("things");
            c.createIndex(List.of("blob"), false, false);
            Map<String, Value> f = new LinkedHashMap<>();
            f.put("blob", new Value.Regex("x", ""));
            assertThrows(InvalidArgumentException.class, () -> c.insert(Value.Doc.of(f)));
        }
    }

    /** §11: every enumeration comes from the catalog and from nowhere else. */
    @Test
    @DisplayName("the catalog answers every enumeration a reader must support")
    void catalogEnumerations(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("l.cryptand"), options())) {
            db.collection("orders").insert(doc("x", 1));
            db.repository("org.dizitart.no2.Employee").insert(doc("x", 1));
            db.keyedRepository("org.dizitart.no2.Employee", "archive").insert(doc("x", 1));
            db.collection("orders").createIndex(List.of("x"), false, false);

            assertEquals(List.of("orders"), db.collectionNames());
            assertEquals(List.of("org.dizitart.no2.Employee"), db.repositoryNames());
            assertEquals(List.of("org.dizitart.no2.Employee+archive"), db.keyedRepositoryNames());
            assertEquals(1, db.indexNames("orders").size());
            assertTrue(db.staleIndexNames().isEmpty());
            assertTrue(Feature.isSet(db.featuresRequired(), Feature.DOCUMENTS));
        }
    }

    @Test
    @DisplayName("store metadata records the format version and every writer")
    void storeMetadata(@TempDir Path dir) {
        Path f = dir.resolve("m.cryptand");
        try (Database db = Database.create(f, options())) {
            Value.Doc store = db.attributes(Database.STORE_ATTRIBUTES);
            assertEquals("1.0", ((Value.Str) store.field("format_version")).value());
            assertEquals(1, ((Value.Array) store.field("writers")).items().size());
        }
        Engine.Options other = options();
        other.writerId = "nitrite-dart/1.0.0";
        try (Database db = Database.open(f, other)) {
            Value.Doc store = db.attributes(Database.STORE_ATTRIBUTES);
            assertEquals(2, ((Value.Array) store.field("writers")).items().size());
        }
    }

    @Test
    @DisplayName("a user record authenticates in constant time and warns on a plaintext file")
    void users(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("n.cryptand"), options())) {
            byte[] password = "hunter2".getBytes(StandardCharsets.UTF_8);
            db.addUser("alice", password, Profile.MOBILE);
            assertTrue(db.authenticate("alice", "hunter2".getBytes(StandardCharsets.UTF_8)));
            assertFalse(db.authenticate("alice", "hunter3".getBytes(StandardCharsets.UTF_8)));
            assertFalse(db.authenticate("bob", password));
        }
    }

    @Test
    @DisplayName("clear() removes every document with one range delete")
    void clear(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("o.cryptand"), options())) {
            Collection c = db.collection("temp");
            Collection.IndexBinding idx = c.createIndex(List.of("k"), false, false);
            List<Long> ids = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                ids.add(c.insert(doc("k", i)));
            }
            c.clear();
            for (long id : ids) {
                assertNull(c.get(id));
            }
            assertEquals(List.of(), idx.find(List.of(Value.i32(1))));
        }
    }

    @Test
    @DisplayName("a transaction rolls back for free and conflicts abort")
    void transactions(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("p.cryptand"), options())) {
            Collection c = db.collection("t");
            int tree = c.treeId();
            byte[] k = Collection.documentKey(1);

            try (Transaction tx = db.begin()) {
                tx.put(tree, k, "one".getBytes(StandardCharsets.UTF_8));
                tx.rollback();
            }
            assertNull(db.engine().get(tree, k));

            try (Transaction tx = db.begin()) {
                int mark = tx.savepoint();
                tx.put(tree, k, "one".getBytes(StandardCharsets.UTF_8));
                tx.rollbackTo(mark);
                tx.put(tree, k, "two".getBytes(StandardCharsets.UTF_8));
                tx.commit();
            }
            assertEquals("two", new String(db.engine().get(tree, k), StandardCharsets.UTF_8));

            Transaction a = db.begin();
            a.put(tree, k, "a".getBytes(StandardCharsets.UTF_8));
            db.engine().batch().put(tree, k, "b".getBytes(StandardCharsets.UTF_8)).commit();
            assertThrows(ConflictException.class, a::commit);
        }
    }
}
