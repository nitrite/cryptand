package org.dizitart.cryptand;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The catalog against the shared vectors — {@code spec/05-catalog.md}.
 */
class CatalogConformanceTest {

    private static JsonNode catalog() {
        return Vectors.load("catalog/trees.json");
    }

    /**
     * §1 retires, permanently, Fjall's {@code | -> _P_} substitution, Hive's
     * base64 box keys, and every "reserved character" rule. A collection may be
     * named {@code "orders|2026+eu"} and nothing downstream cares, because trees
     * are addressed by numeric id and names live in the catalog as plain UTF-8.
     */
    @Test
    @DisplayName("a tree name needs no escaping at all, whatever is in it")
    void namesNeedNoEscaping() {
        int n = 0;
        for (JsonNode t : catalog().get("trees")) {
            String name = t.get("name").asText();
            assertEquals(t.get("name_key").asText(),
                    Vectors.hex(TreeDescriptor.catalogKey(name)),
                    () -> "catalog key for " + name);
            n++;
        }
        assertEquals(3, n);

        // The two that would have needed escaping in the SDKs as they stand.
        assertTrue(catalogNames().contains("orders|2026+eu"));
        assertTrue(catalogNames().contains("org.dizitart.no2.Employee+archive"));
    }

    @Test
    @DisplayName("the store metadata key is CKE(STR \"$store\")")
    void storeMetadataKey() {
        assertEquals(catalog().get("store_metadata_key").asText(),
                Vectors.hex(Cke.encode(new Value.Str("$store"))));
    }

    /**
     * Each published descriptor is a CVE document. Decoding and re-encoding it
     * byte for byte is a stronger CVE test than the synthetic vectors, because
     * these are production-shaped: nested {@code params} documents, mixed
     * widths, and a field set that spans the whole of §3.
     */
    @Test
    @DisplayName("every published tree descriptor re-encodes byte for byte")
    void descriptorsRoundTrip() {
        int n = 0;
        for (JsonNode t : catalog().get("trees")) {
            byte[] expected = Vectors.hex(t.get("descriptor_without_created").asText());
            TreeDescriptor d = TreeDescriptor.decode(expected, null);
            assertArrayEquals(expected, d.encode(null),
                    () -> "descriptor for " + t.get("name").asText());

            assertEquals(t.get("tree_id").asInt(), d.treeId());
            assertEquals(t.get("kind").asText(), d.kind());
            assertEquals(t.get("levelled").asBoolean(), d.levelled());
            n++;
        }
        assertEquals(3, n);
    }

    /**
     * §3: a levelled tree has <strong>no {@code root}</strong> — its segments
     * are in the manifest. A reader that invented one would be reading a page id
     * that means nothing.
     */
    @Test
    @DisplayName("a levelled tree carries no root page")
    void levelledTreesHaveNoRoot() {
        for (JsonNode t : catalog().get("trees")) {
            TreeDescriptor d = TreeDescriptor.decode(
                    Vectors.hex(t.get("descriptor_without_created").asText()), null);
            if (d.levelled()) {
                assertNull(d.root(), () -> d.kind() + " tree " + d.treeId() + " should have no root");
            }
        }
    }

    @Test
    @DisplayName("the levelled kinds are the published set")
    void levelledKinds() {
        List<String> published = new ArrayList<>();
        for (JsonNode k : catalog().get("levelled_kinds")) {
            published.add(k.asText());
        }
        assertEquals(List.of("data", "index", "kv", "name_dict", "postings",
                "term_dict", "term_index", "vector_graph"), published);
        // rtree is deliberately not levelled: it is a copy-on-write tree of its
        // own page types, rooted at `root`.
        assertFalse(published.contains(TreeDescriptor.Kind.RTREE));
    }

    /**
     * §2: uniqueness is {@code params.index_type == "unique"} and nothing else.
     * An earlier draft carried a {@code "unique": BOOL} alongside it — two
     * records of one fact drift, and nothing said which wins.
     */
    @Test
    @DisplayName("uniqueness is index_type and nothing else")
    void uniquenessIsIndexType() {
        TreeDescriptor index = null;
        for (JsonNode t : catalog().get("trees")) {
            if (TreeDescriptor.Kind.INDEX.equals(t.get("kind").asText())) {
                index = TreeDescriptor.decode(
                        Vectors.hex(t.get("descriptor_without_created").asText()), null);
            }
        }
        assertNotNull(index, "the vector should hold an index tree");
        assertEquals(TreeDescriptor.IndexType.UNIQUE, index.indexType());
        assertTrue(index.unique());
        assertEquals("orders|2026+eu", index.owner());
        assertNotNull(index.params().field("data_tree"));
        assertNotNull(index.params().field("fields"));
    }

    /**
     * {@code spec/11-conformance.md} §4: unknown fields in a descriptor MUST be
     * preserved on rewrite. A typed record with a fixed field list silently
     * drops them, and the first symptom is a newer SDK's data disappearing when
     * an older one rewrites the descriptor — so the test is that a descriptor
     * carrying a field this implementation has never heard of comes back out
     * unchanged.
     */
    @Test
    @DisplayName("a descriptor field from the future survives a decode and re-encode")
    void unknownDescriptorFieldsSurvive() {
        TreeDescriptor built = new TreeDescriptor.Builder()
                .treeId(42)
                .kind(TreeDescriptor.Kind.DATA)
                .levelled(true)
                .entries(7)
                .build();

        java.util.Map<String, Value> withFuture =
                new java.util.LinkedHashMap<>(built.document().fields());
        withFuture.put("from_the_future", new Value.Str("keep me"));
        byte[] encoded = Cve.encode(new Value.Doc(withFuture));

        TreeDescriptor read = TreeDescriptor.decode(encoded, null);
        assertEquals(42, read.treeId());
        assertEquals(new Value.Str("keep me"), read.document().field("from_the_future"));
        assertArrayEquals(encoded, read.encode(null));
    }

    @Test
    @DisplayName("a tree descriptor built here matches the shape the vector publishes")
    void builderProducesTheSameShape() {
        JsonNode t = null;
        for (JsonNode candidate : catalog().get("trees")) {
            if (candidate.get("tree_id").asInt() == 16) {
                t = candidate;
            }
        }
        assertNotNull(t);
        TreeDescriptor published = TreeDescriptor.decode(
                Vectors.hex(t.get("descriptor_without_created").asText()), null);

        TreeDescriptor built = new TreeDescriptor.Builder()
                .treeId(published.treeId())
                .kind(published.kind())
                .levelled(published.levelled())
                .entries(published.entries())
                .keyKind(published.keyKind())
                .features(published.features())
                .params(published.params().fields())
                .build();

        assertArrayEquals(published.encode(null), built.encode(null),
                "field order is by resolved name bytes, so builder order must not matter");
    }

    private List<String> catalogNames() {
        List<String> names = new ArrayList<>();
        for (JsonNode t : catalog().get("trees")) {
            names.add(t.get("name").asText());
        }
        return names;
    }
}
