package org.dizitart.cryptand;

import org.dizitart.cryptand.text.Porter2;
import org.dizitart.cryptand.text.Unicode;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How many cases each vector file holds.
 *
 * <p>Every other test in this module is a loop over a vector file, and a loop
 * over an empty list passes. This project has already produced five benchmarks
 * and controls that could not fail — the phrase in its report is "a control
 * that cannot fail measures nothing" — so the counts are asserted here rather
 * than assumed there.
 *
 * <p>If a vector file grows a case, this test fails and the number is updated
 * deliberately. That is the point: a silently shrinking vector set would
 * otherwise turn every conformance test in this module green.
 */
class VectorCoverageTest {

    @Test
    @DisplayName("the vector files hold the cases the other tests assume")
    void vectorCounts() {
        assertCount("cke/values.json", "cases", 30);
        assertCount("cke/values.json", "rejects", 8);
        assertCount("cve/values.json", "cases", 17);
        assertCount("cve/values.json", "rejects", 6);
        assertCount("documents/cases.json", "cases", 2);
        assertCount("documents/cases.json", "dictionary", 7);
        assertCount("strings/cases.json", "cases", 10);
        assertCount("strings/cases.json", "rejects_on_write", 2);
        assertCount("strings/cases.json", "rejects_on_read", 2);
        assertCount("numbers/torture.json", "entries", 170);
        assertCount("numbers/torture.json", "sorted_by_cke", 170);
        assertCount("numbers/torture.json", "lossy_decodings", 3);
        assertCount("container/layout.json", "crc32c", 2);
        assertCount("filter/blocked_bloom.json", "cfh64_vectors", 6);
        assertCount("index/entries.json", "cases", 9);
        assertCount("index/layout.json", "entries", 5);
        assertCount("catalog/trees.json", "trees", 3);
        assertCount("catalog/trees.json", "levelled_kinds", 8);
        assertCount("security/derivation.json", "nonces", 2);
        assertCount("analyzer/std_v1.json", "cases", 14);
    }

    /**
     * Which vector groups this implementation consumes.
     *
     * <p>A group with no test is not a failure — it is a chapter not yet built —
     * but it must be visible rather than inferred from an absence. Every group
     * on disk is consumed now; {@code analyzer} was the last, because it needed
     * Unicode 15.1 segmentation and Porter2, and {@link FullTextTest} is where
     * it is spent.
     */
    @Test
    @DisplayName("every vector group on disk is consumed")
    void groupsConsumed() {
        String[] consumed = {"cke", "cve", "numbers", "strings", "documents",
                "container", "filter", "index", "catalog", "security", "analyzer"};
        for (String group : consumed) {
            assertTrue(java.nio.file.Files.isDirectory(Vectors.root().resolve(group)),
                    group + " vectors should exist");
        }
        assertEquals(11, consumed.length, "every vector group has a test");
    }

    private static void assertCount(String file, String field, int expected) {
        JsonNode n = Vectors.load(file).get(field);
        assertEquals(expected, n == null ? 0 : n.size(), file + " -> " + field);
    }
}
