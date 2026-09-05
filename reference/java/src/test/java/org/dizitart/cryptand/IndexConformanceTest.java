package org.dizitart.cryptand;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Secondary indexes against the shared vectors — {@code spec/06-indexes.md}.
 */
class IndexConformanceTest {

    @Test
    @DisplayName("every index/entries.json case derives exactly the published keys")
    void indexEntries() {
        JsonNode doc = Vectors.load("index/entries.json");
        int n = 0;
        for (JsonNode c : doc.get("cases")) {
            List<String> fields = new ArrayList<>();
            for (JsonNode f : c.get("fields")) {
                fields.add(f.asText());
            }
            Value document = Vectors.value(c.get("document"));
            long id = Long.parseLong(c.get("nitrite_id").get("v").asText());
            boolean sparse = c.get("sparse").asBoolean();

            List<String> expected = new ArrayList<>();
            for (JsonNode k : c.get("keys")) {
                expected.add(k.asText());
            }
            List<String> actual = new ArrayList<>();
            for (byte[] k : IndexKeys.forDocument(fields, document, sparse, id)) {
                actual.add(Vectors.hex(k));
            }
            assertEquals(expected, actual, () -> c.path("note").asText());
            n++;
        }
        assertEquals(9, n, "index/entries.json should hold nine cases");
    }

    @Test
    @DisplayName("the only escaping in the format is inside a field path")
    void fieldPathEscapes() {
        JsonNode escapes = Vectors.load("index/entries.json").get("field_path_escapes");
        int n = 0;
        for (Iterator<String> it = escapes.fieldNames(); it.hasNext(); ) {
            String path = it.next();
            if (path.equals("note")) {
                continue;
            }
            List<String> expected = new ArrayList<>();
            for (JsonNode part : escapes.get(path)) {
                expected.add(part.asText());
            }
            assertEquals(expected, IndexKeys.splitFieldPath(path), path);
            n++;
        }
        assertEquals(3, n);
        assertThrows(InvalidArgumentException.class, () -> IndexKeys.splitFieldPath("trailing\\"));
        assertEquals("a\\.b", IndexKeys.escapeComponent("a.b"));
        assertEquals("a\\\\b", IndexKeys.escapeComponent("a\\b"));
    }

    /**
     * An index key is self-describing: a scan yields the indexed values
     * <em>and</em> the document id by decoding the key, so a covering query
     * never touches the data tree.
     */
    @Test
    @DisplayName("an index key decodes back to its values and its document id")
    void keysAreSelfDescribing() {
        byte[] key = IndexKeys.forDocument(List.of("country", "city"),
                new Value.Doc(java.util.Map.of(
                        "country", new Value.Str("fr"),
                        "city", new Value.Str("paris"))),
                false, 12).get(0);
        assertEquals(List.of(new Value.Str("fr"), new Value.Str("paris")), IndexKeys.valuesOf(key));
        assertEquals(12, IndexKeys.idOf(key));
    }

    /**
     * §1: the uniqueness check is on the {@code NitriteId} behind the matching
     * entries, not on their existence. A unique index over a multi-valued field
     * reaches the same key twice for {@code ["a", "b", "a"]}, and a rebuild or
     * a replayed write reaches keys the document already owns — a bare
     * existence test rejects all of these, and Java, Dart and Rust all shipped
     * that bare test (nitrite/nitrite-java#1295).
     *
     * <p>§3: and the check is <em>skipped</em> whenever any element is null,
     * rather than run and passed, because a unique index treats every
     * {@code NULL} as distinct.
     */
    @Test
    @DisplayName("uniqueness does not apply to a tuple containing null")
    void uniquenessSkipsNulls() {
        assertTrue(IndexKeys.uniquenessApplies(List.of(new Value.Str("fr"))));
        assertFalse(IndexKeys.uniquenessApplies(List.of(Value.NULL)));
        assertFalse(IndexKeys.uniquenessApplies(List.of(new Value.Str("fr"), Value.NULL)));
    }

    @Test
    @DisplayName("the cartesian product is capped, and the cap is reported not exceeded")
    void cartesianProductIsCapped() {
        int cap = Vectors.load("index/entries.json").get("cap_per_document").asInt();
        assertEquals(IndexKeys.MAX_ENTRIES_PER_DOCUMENT, cap);

        List<Value> many = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            many.add(Value.of(i));
        }
        Value doc = new Value.Doc(java.util.Map.of("a", new Value.Array(many), "b", new Value.Array(many)));
        // 40 x 40 = 1600 > 1024.
        assertThrows(LimitException.class,
                () -> IndexKeys.forDocument(List.of("a", "b"), doc, false, 1));
    }

    @Test
    @DisplayName("a value with no CKE encoding cannot be indexed, and says so")
    void unindexableValues() {
        Value doc = new Value.Doc(java.util.Map.of("d", new Value.Dec128(new byte[16])));
        InvalidArgumentException e = assertThrows(InvalidArgumentException.class,
                () -> IndexKeys.forDocument(List.of("d"), doc, false, 1));
        assertTrue(e.getMessage().contains("Dec128"), e.getMessage());
    }

    // ------------------------------------------------------------------
    // §7's query planning contract, against index/layout.json
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the published single-value index keys are byte-exact")
    void layoutEntries() {
        JsonNode doc = Vectors.load("index/layout.json");
        int n = 0;
        for (JsonNode e : doc.get("entries")) {
            Value v = Vectors.value(e.get("indexed_value"));
            long id = e.get("nitrite_id").asLong();
            byte[] key = Cke.encode(new Value.Array(List.of(v, new Value.NitriteId(id))));
            assertEquals(e.get("key").asText(), Vectors.hex(key), () -> "key for " + v);
            n++;
        }
        assertEquals(5, n);
    }

    /**
     * The row that decides whether "one numeric domain" is real on an actual
     * index. {@code eq(5)} must match {@code I32(5)}, {@code F64(5.0)},
     * {@code I8(5)} and {@code U128(5)} alike, and that is only true if the
     * bound leaves the type code off.
     */
    @Test
    @DisplayName("eq(5) built from N(v) spans every numeric type, as published")
    void numericRangeConstruction() {
        JsonNode rc = Vectors.load("index/layout.json").get("range_construction");
        JsonNode eq = rc.get("eq_5_any_numeric_type");

        byte[] lower = Cke.numericPrefix(Value.i32(5));
        byte[] upper = Cke.successor(lower);
        assertEquals(eq.get("lower").asText(), Vectors.hex(lower));
        assertEquals(eq.get("upper").asText(), Vectors.hex(upper));

        int n = 0;
        for (JsonNode c : eq.get("contains")) {
            byte[] key = Vectors.hex(c.asText());
            assertTrue(Cke.compare(lower, key) <= 0 && Cke.compare(key, upper) < 0,
                    () -> c.asText() + " should fall inside [N(5), successor(N(5)))");
            n++;
        }
        assertEquals(4, n);

        assertEquals(rc.get("array_prefix_numeric_5").asText(),
                Vectors.hex(Cke.arrayPrefixNumeric(List.of(Value.i32(5)))));

        JsonNode sw = rc.get("starts_with_abc");
        byte[] swLower = Cke.stringPrefix("abc");
        assertEquals(sw.get("lower").asText(), Vectors.hex(swLower));
        assertEquals(sw.get("upper").asText(), Vectors.hex(Cke.successor(swLower)));
    }

    /**
     * The failure §8.2 spells out, reproduced as a test rather than trusted:
     * a bound built from the full {@code CKE(v)} cuts between numeric
     * <em>types</em>, so {@code field >= 5} misses the narrower ones.
     */
    @Test
    @DisplayName("a bound built from CKE(v) instead of N(v) really does lose rows")
    void theWrongBoundLosesRows() {
        byte[] wrong = Cke.encode(Value.i32(5));
        byte[] right = Cke.numericPrefix(Value.i32(5));

        byte[] i8 = Cke.encode(Value.integer(NumType.I8, 5));
        byte[] u8 = Cke.encode(Value.integer(NumType.U8, 5));

        // ">= 5" from CKE(I32(5)) misses I8(5), whose type code sorts below.
        assertTrue(Cke.compare(i8, wrong) < 0, "I8(5) sorts below CKE(I32(5))");
        assertTrue(Cke.compare(i8, right) >= 0, "I8(5) is inside [N(5), ...)");

        // "> 5" from successor(CKE(I32(5))) wrongly admits U8(5).
        byte[] wrongUpper = Cke.successor(wrong);
        assertTrue(Cke.compare(u8, wrongUpper) >= 0, "U8(5) is admitted by the wrong bound");
        assertTrue(Cke.compare(u8, Cke.successor(right)) < 0, "U8(5) is correctly excluded by N(5)");
    }

    @Test
    @DisplayName("a prefix scan on a compound index answers each prefix with one seek")
    void compoundPrefixScans() {
        List<byte[]> keys = new ArrayList<>();
        String[][] rows = {{"fr", "paris"}, {"fr", "lyon"}, {"de", "berlin"}, {"fr", "nice"}};
        for (int i = 0; i < rows.length; i++) {
            keys.add(IndexKeys.forDocument(List.of("country", "city"),
                    new Value.Doc(java.util.Map.of(
                            "country", new Value.Str(rows[i][0]),
                            "city", new Value.Str(rows[i][1]))),
                    false, i).get(0));
        }

        IndexKeys.Scan fr = IndexKeys.equalsPrefix(List.of(new Value.Str("fr")));
        int matched = 0;
        for (byte[] k : keys) {
            if (fr.contains(k)) {
                matched++;
            }
        }
        assertEquals(3, matched);

        IndexKeys.Scan frParis = IndexKeys.equalsPrefix(
                List.of(new Value.Str("fr"), new Value.Str("paris")));
        matched = 0;
        for (byte[] k : keys) {
            if (frParis.contains(k)) {
                matched++;
            }
        }
        assertEquals(1, matched);
    }

    @Test
    @DisplayName("the reserved tree ids and portable index type names match the catalog vector")
    void catalogConstants() {
        JsonNode doc = Vectors.load("catalog/trees.json");
        JsonNode ids = doc.get("reserved_tree_ids");
        assertEquals(TreeId.CATALOG, ids.get("catalog").asInt());
        assertEquals(TreeId.FREE_SPACE, ids.get("free_space").asInt());
        assertEquals(TreeId.ATTRIBUTES, ids.get("attributes").asInt());
        assertEquals(TreeId.TREE_INDEX, ids.get("tree_index").asInt());
        assertEquals(TreeId.REPAIR_LOG, ids.get("repair_log").asInt());
        assertEquals(TreeId.USERS, ids.get("users").asInt());
        assertEquals(TreeId.MANIFEST, ids.get("manifest").asInt());
        assertEquals(TreeId.VLOG_STATS, ids.get("vlog_stats").asInt());
        assertEquals(TreeId.CHECKPOINTS, ids.get("checkpoints").asInt());
        assertEquals(TreeId.CHANGE_FEED, ids.get("change_feed").asInt());
        assertEquals(TreeId.FIRST_USER_TREE, ids.get("first_user_tree").asInt());

        List<String> names = new ArrayList<>();
        for (JsonNode v : doc.get("index_type_names").get("values")) {
            names.add(v.asText());
        }
        assertEquals(List.of("full_text", "non_unique", "spatial", "unique", "vector"), names);
    }
}
