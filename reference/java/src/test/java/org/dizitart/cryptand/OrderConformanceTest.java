package org.dizitart.cryptand;

import com.fasterxml.jackson.databind.JsonNode;
import org.dizitart.cryptand.value.Compare;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code spec/02-value-encoding.md} §8 — equality and comparison, against the
 * shared vector corpus.
 *
 * <p>§8 opens "defined here once, for all SDKs, ending the current divergence",
 * and then records that a divergence survived inside it — two implementations
 * filled a hole in <b>opposite</b> directions — "and no test could see it
 * because nothing tested this section at all".
 *
 * <p>The cross-language round-trip gate cannot see this section either, and not
 * by oversight: §8's order is consumed <b>in memory</b>. Three implementations
 * can disagree completely about how values sort and every direction of the file
 * gate still passes, because the bytes never differ.
 *
 * <p>The result checked is a <b>matrix</b>, not a sorted permutation. §8 makes
 * many of these values equal — every numeric tag holding 5 is one value, a
 * {@code TIMESTAMP} of 1000 ms equals a {@code TIMESTAMP_NS} of (1 s, 0),
 * {@code -0.0} equals {@code +0.0} — and equal elements have no defined
 * relative position in an unstable sort. A permutation would encode the sort
 * algorithm; the matrix encodes the order.
 */
class OrderConformanceTest {

    private record Corpus(List<Value> values, List<String> notes, JsonNode doc) {}

    private static Corpus corpus() throws IOException {
        JsonNode doc = Vectors.load("order/values.json");
        List<Value> values = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        for (JsonNode e : doc.get("entries")) {
            values.add(Vectors.value(e.get("value")));
            notes.add(e.path("note").asText(""));
        }
        return new Corpus(values, notes, doc);
    }

    private static List<String> matrix(List<Value> values) {
        List<String> rows = new ArrayList<>(values.size());
        for (Value a : values) {
            StringBuilder row = new StringBuilder(values.size());
            for (Value b : values) {
                int r = Compare.compare(a, b);
                row.append(r < 0 ? '-' : (r == 0 ? '0' : '+'));
            }
            rows.add(row.toString());
        }
        return rows;
    }

    @Test
    @DisplayName("the shared order corpus matches the published matrix")
    void matchesPublishedMatrix() throws IOException {
        Corpus c = corpus();
        List<String> rows = matrix(c.values());

        String dump = System.getProperty("cryptand.order.out");
        if (dump != null) {
            Files.writeString(Path.of(dump), String.join("\n", rows) + "\n");
            System.err.println("wrote " + dump);
        }

        JsonNode want = c.doc().get("matrix");
        assertTrue(want != null && want.isArray(),
                "order/values.json carries no `matrix` — regenerate it");
        assertEquals(want.size(), rows.size(), "the corpus and the matrix disagree in size");
        for (int i = 0; i < rows.size(); i++) {
            assertEquals(want.get(i).asText(), rows.get(i),
                    "row " + i + " of the order matrix differs from the published vector"
                            + " (" + c.notes().get(i) + ")");
        }
    }

    @Test
    @DisplayName("the order is a total order over the corpus")
    void totalOrder() throws IOException {
        Corpus c = corpus();
        List<Value> v = c.values();
        int n = v.size();
        int[][] s = new int[n][n];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                s[i][j] = Integer.signum(Compare.compare(v.get(i), v.get(j)));
            }
        }
        for (int i = 0; i < n; i++) {
            assertEquals(0, s[i][i],
                    "value " + i + " (" + c.notes().get(i) + ") is not equal to itself");
            for (int j = 0; j < n; j++) {
                assertEquals(s[i][j], -s[j][i],
                        "antisymmetry fails for " + i + " (" + c.notes().get(i) + ") and "
                                + j + " (" + c.notes().get(j) + ")");
            }
        }
        // Transitivity over every triple — the property a comparator built out
        // of per-type special cases is most likely to violate.
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                if (s[i][j] > 0) {
                    continue;
                }
                for (int k = 0; k < n; k++) {
                    if (s[j][k] <= 0) {
                        assertTrue(s[i][k] <= 0,
                                "transitivity fails: " + i + " <= " + j + " <= " + k
                                        + " but " + i + " > " + k
                                        + "\n  " + c.notes().get(i)
                                        + "\n  " + c.notes().get(j)
                                        + "\n  " + c.notes().get(k));
                    }
                }
            }
        }
    }

    /**
     * The corpus's <b>named</b> rules, each naming two indices and the sign §8
     * requires between them.
     *
     * <p>The matrix proves the three implementations agree. It cannot prove
     * they are right: all three produced an identical matrix while all three
     * compared MAP entries in <em>stored</em> rather than sorted order, which
     * §8 rule 8 forbids in the same sentence that covers DOC. Agreement is not
     * conformance, and these rules are the half that reads the spec rather than
     * the neighbours.
     */
    @Test
    @DisplayName("the named rules of section 8 hold")
    void namedRules() throws IOException {
        Corpus c = corpus();
        JsonNode rules = c.doc().get("rules");
        assertTrue(rules != null && rules.isArray(),
                "order/values.json carries no `rules`");
        assertTrue(rules.size() > 100,
                "the rule set is suspiciously small: " + rules.size());
        for (JsonNode r : rules) {
            int a = r.get("a").asInt();
            int b = r.get("b").asInt();
            int s = Integer.signum(Compare.compare(c.values().get(a), c.values().get(b)));
            String got = s < 0 ? "-" : (s == 0 ? "0" : "+");
            assertEquals(r.get("expect").asText(), got,
                    "\u00a78 rule " + r.path("rule").asText("?") + " \u2014 "
                            + r.path("note").asText("")
                            + "\n  a[" + a + "] = " + c.notes().get(a)
                            + "\n  b[" + b + "] = " + c.notes().get(b));
        }
    }
}
