package org.dizitart.cryptand;

import com.fasterxml.jackson.databind.JsonNode;
import org.dizitart.cryptand.geom.Geometry;
import org.dizitart.cryptand.geom.Wkb;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code spec/08-spatial.md} §§1, 3 and 4, against the shared vector corpus.
 *
 * <p>§2.3 says what a spatial conformance test may compare: "two
 * implementations inserting the same documents will produce different (equally
 * valid) trees. A conformance test therefore compares <b>query results</b>,
 * never tree shape." So this corpus carries no tree — geometries, envelopes,
 * the pairwise predicate matrices and §1's reject list, all properties of the
 * geometry rather than of anybody's R-tree.
 */
class SpatialConformanceTest {

    private static final class Corpus {
        private final List<byte[]> wkb;
        private final List<String> names;
        private final JsonNode doc;

        public Corpus(List<byte[]> wkb, List<String> names, JsonNode doc) {
            this.wkb = wkb;
            this.names = names;
            this.doc = doc;
        }

        public List<byte[]> wkb() {
            return wkb;
        }

        public List<String> names() {
            return names;
        }

        public JsonNode doc() {
            return doc;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Corpus)) {
                return false;
            }
            Corpus that = (Corpus) o;
            return java.util.Objects.equals(wkb, that.wkb)
                    && java.util.Objects.equals(names, that.names)
                    && java.util.Objects.equals(doc, that.doc);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(wkb, names, doc);
        }

        @Override
        public String toString() {
            return "Corpus[" + "wkb=" + wkb + ", " + "names=" + names + ", " + "doc=" + doc + "]";
        }
    }

    private static Corpus corpus() {
        JsonNode doc = Vectors.load("spatial/geometries.json");
        List<byte[]> wkb = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (JsonNode g : doc.get("geometries")) {
            wkb.add(Vectors.hex(g.get("wkb").asText()));
            names.add(g.get("name").asText());
        }
        return new Corpus(wkb, names, doc);
    }

    private static List<String> matrix(String kind, List<byte[]> gs) {
        List<String> rows = new ArrayList<>();
        for (byte[] a : gs) {
            StringBuilder row = new StringBuilder();
            for (byte[] b : gs) {
                boolean r;
                switch (kind) {
                    case "intersects": r = Geometry.intersects(a, b); break;
                    case "contains": r = Geometry.contains(a, b); break;
                    default: r = Geometry.within(a, b); break;
                }
                row.append(r ? '1' : '0');
            }
            rows.add(row.toString());
        }
        return rows;
    }

    @Test
    @DisplayName("every published envelope is reproduced")
    void envelopes() {
        Corpus c = corpus();
        int i = 0;
        for (JsonNode g : c.doc().get("geometries")) {
            Wkb.Box b = Wkb.envelope(c.wkb().get(i), 2);
            JsonNode want = g.get("envelope");
            assertEquals(want.get(0).asDouble(), b.min()[0], c.names().get(i));
            assertEquals(want.get(1).asDouble(), b.min()[1], c.names().get(i));
            assertEquals(want.get(2).asDouble(), b.max()[0], c.names().get(i));
            assertEquals(want.get(3).asDouble(), b.max()[1], c.names().get(i));
            i++;
        }
    }

    /** §1: "EWKB MUST NOT be written and MUST be rejected on read", and the rest. */
    @Test
    @DisplayName("every published reject is refused")
    void rejects() {
        Corpus c = corpus();
        for (JsonNode r : c.doc().get("rejects")) {
            byte[] b = Vectors.hex(r.get("wkb").asText());
            try {
                Wkb.envelope(b, 2);
                fail(r.get("name").asText() + " was ACCEPTED: " + r.get("why").asText());
            } catch (CryptandException expected) {
                // A typed refusal is the contract.
            }
        }
    }

    /**
     * §1: "a writer MUST emit little-endian; a reader MUST accept both."
     * The negative control for {@link #rejects()} — a reader that refused
     * everything would pass that test and fail this one.
     */
    @Test
    @DisplayName("a big-endian geometry is accepted")
    void bigEndian() {
        JsonNode be = corpus().doc().get("accept_big_endian");
        Wkb.Box b = Wkb.envelope(Vectors.hex(be.get("wkb").asText()), 2);
        assertEquals(1.0, b.min()[0]);
        assertEquals(1.0, b.max()[1]);
    }

    @Test
    @DisplayName("the predicate matrices match the published vectors")
    void matrices() throws IOException {
        Corpus c = corpus();
        String dump = System.getProperty("cryptand.spatial.out");
        if (dump != null) {
            StringBuilder s = new StringBuilder();
            for (String kind : List.of("intersects", "contains", "within")) {
                s.append(kind).append('\n');
                for (String row : matrix(kind, c.wkb())) {
                    s.append(row).append('\n');
                }
            }
            Files.writeString(Path.of(dump), s.toString());
            System.err.println("wrote " + dump);
        }
        JsonNode m = c.doc().get("matrix");
        assertTrue(m != null, "spatial/geometries.json carries no `matrix` — regenerate it");
        for (String kind : List.of("intersects", "contains", "within")) {
            List<String> rows = matrix(kind, c.wkb());
            for (int i = 0; i < rows.size(); i++) {
                assertEquals(m.get(kind).get(i).asText(), rows.get(i),
                        kind + " row " + i + " (" + c.names().get(i) + ")");
            }
        }
    }

    /**
     * The corpus's <b>named</b> rules, each citing a §4.1 rule number, a
     * predicate and two indices.
     *
     * <p>The matrix proves the three implementations agree; it cannot prove
     * they are right, and here it could not have. Before §4.1 was written the
     * three disagreed on <b>32</b> of these pairs while each was internally
     * consistent — this one treated an inner geometry sharing an edge with the
     * outer one as not contained.
     */
    @Test
    @DisplayName("the named rules of section 4.1 hold")
    void namedRules() {
        Corpus c = corpus();
        JsonNode rules = c.doc().get("rules");
        assertTrue(rules != null && rules.isArray(), "no `rules` in the vector");
        assertTrue(rules.size() > 10, "the rule set is suspiciously small");
        for (JsonNode r : rules) {
            int a = r.get("a").asInt();
            int b = r.get("b").asInt();
            String kind = r.get("predicate").asText();
            boolean got;
            switch (kind) {
                case "intersects": got = Geometry.intersects(c.wkb().get(a), c.wkb().get(b)); break;
                case "contains": got = Geometry.contains(c.wkb().get(a), c.wkb().get(b)); break;
                default: got = Geometry.within(c.wkb().get(a), c.wkb().get(b)); break;
            }
            assertEquals(r.get("expect").asBoolean(), got,
                    "\u00a7" + r.path("rule").asText("?") + " \u2014 " + r.path("note").asText("")
                            + "\n  " + kind + "(" + c.names().get(a) + ", " + c.names().get(b) + ")");
        }
    }
}
