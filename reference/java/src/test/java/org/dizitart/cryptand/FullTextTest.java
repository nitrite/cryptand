package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.index.FullTextIndex;
import org.dizitart.cryptand.index.Postings;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.text.Analyzer;
import org.dizitart.cryptand.text.Porter2;
import org.dizitart.cryptand.text.Unicode;
import org.dizitart.cryptand.value.Value;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Level 2 — {@code spec/07-fulltext.md}. */
class FullTextTest {

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static Value.Doc doc(String body) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("body", new Value.Str(body));
        return Value.Doc.of(f);
    }

    /**
     * The tenth vector group. It needs Unicode 15.1 and Porter2, which is why
     * it is the one group a byte-layer implementation deliberately leaves
     * alone.
     */
    @Test
    @DisplayName("the analyzer reproduces every published std_v1 case")
    void analyzerVectors() {
        JsonNode root = Vectors.load("analyzer/std_v1.json");
        assertEquals("cryptand.std.v1", root.get("analyzer").asText());
        assertEquals(Unicode.VERSION, root.get("unicode_version").asText(),
                "the analyzer name pins the Unicode release");
        int cases = 0;
        List<String> failures = new ArrayList<>();
        for (JsonNode c : root.get("cases")) {
            cases++;
            List<String> stopwords = new ArrayList<>();
            for (JsonNode s : c.get("stopwords")) {
                stopwords.add(codePoints(s));
            }
            String stemmer = c.has("stemmer") ? c.get("stemmer").asText() : "none";
            Analyzer analyzer = Analyzer.of(Analyzer.STD_V1, stopwords, stemmer);
            String input = codePoints(c.get("input_cps"));
            List<Analyzer.Token> got = analyzer.analyze(input);
            List<String> expected = new ArrayList<>();
            for (JsonNode t : c.get("tokens")) {
                expected.add(codePoints(t.get("text_cps")) + "@" + t.get("position").asInt());
            }
            List<String> actual = new ArrayList<>();
            for (Analyzer.Token t : got) {
                actual.add(t.text() + "@" + t.position());
            }
            if (!expected.equals(actual)) {
                failures.add((c.has("note") ? c.get("note").asText() : "case " + cases)
                        + ": expected " + expected + " got " + actual);
            }
        }
        assertTrue(cases >= 14, "every published case ran: " + cases);
        assertEquals(List.of(), failures);
    }

    private static String codePoints(JsonNode node) {
        if (node.isTextual()) {
            return node.asText();
        }
        StringBuilder sb = new StringBuilder();
        for (JsonNode cp : node) {
            sb.appendCodePoint(cp.asInt());
        }
        return sb.toString();
    }

    /** The chapter's opening example, which is where implementations diverge. */
    @Test
    @DisplayName("Bäckerei-Straße 12 tokenizes the same way every time")
    void openingExample() {
        List<Analyzer.Token> tokens = Analyzer.standard().analyze("Bäckerei-Straße 12");
        assertEquals(List.of("bäckerei", "straße", "12"),
                tokens.stream().map(Analyzer.Token::text).collect(java.util.stream.Collectors.toList()));
        assertEquals(List.of(0, 1, 2), tokens.stream().map(Analyzer.Token::position).collect(java.util.stream.Collectors.toList()));
    }

    @Test
    @DisplayName("simple lowercasing keeps the sharp s that full folding would split")
    void simpleLowercasing() {
        assertEquals(List.of("straße"),
                Analyzer.standard().analyze("STRAẞE").stream().map(Analyzer.Token::text).collect(java.util.stream.Collectors.toList()));
    }

    /**
     * §2.4: an unpinned {@code porter2:<lang>} cannot be made to mean one thing,
     * and guessing a release is how two SDKs come to disagree without either
     * being able to detect it.
     */
    @Test
    @DisplayName("an unpinned or unknown stemmer release is refused")
    void stemmerMustPinARelease() {
        assertThrows(InvalidArgumentException.class,
                () -> Analyzer.of(Analyzer.STD_V1, List.of(), "porter2:en"));
        assertThrows(UnsupportedFeatureException.class,
                () -> Analyzer.of(Analyzer.STD_V1, List.of(), "porter2:en:2.2.0"));
        assertEquals("porter2:en:3.1.0",
                Analyzer.of(Analyzer.STD_V1, List.of(), Porter2.NAME).stemmer());
    }

    @Test
    @DisplayName("an analyzer this implementation does not have is refused, loudly")
    void unknownAnalyzer() {
        assertThrows(UnsupportedFeatureException.class,
                () -> Analyzer.of("myapp.analyzer.v1", List.of(), "none"));
    }

    @Test
    @DisplayName("positions are the pre-filter segment index, so a stopword does not shift a phrase")
    void positionsSurviveStopwords() {
        Analyzer a = Analyzer.of(Analyzer.STD_V1, List.of("the"), "none");
        List<Analyzer.Token> tokens = a.analyze("jump over the lazy dog");
        assertEquals(List.of("jump", "over", "lazy", "dog"),
                tokens.stream().map(Analyzer.Token::text).collect(java.util.stream.Collectors.toList()));
        assertEquals(List.of(0, 1, 3, 4), tokens.stream().map(Analyzer.Token::position).collect(java.util.stream.Collectors.toList()));
    }

    @Test
    @DisplayName("a postings block round-trips with and without positions")
    void postingsBlock() {
        List<Postings.Posting> block = List.of(
                new Postings.Posting(10, 2, new int[]{0, 5}),
                new Postings.Posting(40, 1, new int[]{3}),
                new Postings.Posting(9_000_000_000L, 3, new int[]{1, 2, 9}));
        byte[] encoded = Postings.encode(block, true);
        List<Postings.Posting> decoded = Postings.decode(encoded);
        assertEquals(3, decoded.size());
        assertEquals(9_000_000_000L, decoded.get(2).nitriteId());
        assertArrayEquals(new int[]{1, 2, 9}, decoded.get(2).positions());

        List<Postings.Posting> noPositions = Postings.decode(Postings.encode(block, false));
        assertEquals(3, noPositions.size());
        assertEquals(3, noPositions.get(2).frequency());
        assertTrue(Postings.encode(block, false).length < encoded.length,
                "positions are what doubles the index");
    }

    @Test
    @DisplayName("a block holds at most 128 documents")
    void blockCeiling() {
        List<Postings.Posting> tooMany = new ArrayList<>();
        for (int i = 0; i <= Postings.MAX_PER_BLOCK; i++) {
            tooMany.add(new Postings.Posting(i, 1));
        }
        assertThrows(InvalidArgumentException.class, () -> Postings.encode(tooMany, false));
    }

    @Test
    @DisplayName("search finds documents holding every term, and updates track")
    void searchAndUpdate(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("a.cryptand"), options())) {
            Collection c = db.collection("posts");
            FullTextIndex index = c.createTextIndex(List.of("body"), List.of(), "none", true);
            long a = c.insert(doc("the quick brown fox"));
            long b = c.insert(doc("the lazy brown dog"));
            c.insert(doc("nothing in common"));

            assertEquals(List.of(a, b).size(), index.search("brown").size());
            assertTrue(index.search("brown").contains(a));
            assertEquals(List.of(a), index.search("quick brown"));
            assertEquals(List.of(), index.search("quick lazy"));

            c.update(a, doc("the quick brown cat"));
            assertEquals(List.of(a), index.search("cat"));
            assertEquals(List.of(), index.search("fox"));
            c.remove(b);
            assertEquals(List.of(a), index.search("brown"));
        }
    }

    @Test
    @DisplayName("df and ttf are accurate, and a verifier can rebuild and compare")
    void statisticsAndVerification(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("b.cryptand"), options())) {
            Collection c = db.collection("posts");
            FullTextIndex index = c.createTextIndex(List.of("body"), List.of(), "none", true);
            c.insert(doc("alpha alpha beta"));
            c.insert(doc("alpha gamma"));

            FullTextIndex.Term alpha = index.term("alpha");
            assertEquals(2, alpha.df(), "two documents hold it");
            assertEquals(3, alpha.ttf(), "three occurrences in total");
            assertEquals(1, index.term("beta").df());
            assertEquals(List.of(), index.verify());
        }
    }

    /**
     * §4.3: a phrase query against an index without positions is rejected, not
     * approximated with a conjunction.
     */
    @Test
    @DisplayName("phrase queries need positions, and are refused without them")
    void phraseQueries(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("c.cryptand"), options())) {
            Collection c = db.collection("posts");
            FullTextIndex withPositions = c.createTextIndex(List.of("body"), List.of(), "none", true);
            long a = c.insert(doc("the quick brown fox"));
            c.insert(doc("brown the quick fox"));
            assertEquals(List.of(a), withPositions.phrase("quick brown"));
            assertEquals(2, withPositions.search("quick brown").size(),
                    "a conjunction matches both; a phrase matches one");

            Collection other = db.collection("nopos");
            FullTextIndex none = other.createTextIndex(List.of("body"), List.of(), "none", false);
            other.insert(doc("the quick brown fox"));
            assertThrows(InvalidArgumentException.class, () -> none.phrase("quick brown"));
        }
    }

    @Test
    @DisplayName("the stopword list stored in the file is the one that is used")
    void stopwordsComeFromTheFile(@TempDir Path dir) {
        Path f = dir.resolve("d.cryptand");
        try (Database db = Database.create(f, options())) {
            Collection c = db.collection("posts");
            c.createTextIndex(List.of("body"), List.of("the", "a"), "none", false);
            c.insert(doc("the quick fox"));
        }
        try (Database db = Database.open(f, options())) {
            Collection c = db.collection("posts");
            FullTextIndex index = c.textIndexes().get(0);
            assertEquals(List.of("a", "the"), index.analyzer().stopwords());
            assertFalse(index.terms().containsKey("the"), "the stopword never became a term");
            assertTrue(index.terms().containsKey("quick"));
        }
    }

    @Test
    @DisplayName("stemming collapses inflections when the index declares it")
    void stemmedIndex(@TempDir Path dir) {
        try (Database db = Database.create(dir.resolve("e.cryptand"), options())) {
            Collection c = db.collection("posts");
            FullTextIndex index =
                    c.createTextIndex(List.of("body"), List.of(), Porter2.NAME, false);
            long a = c.insert(doc("running quickly"));
            assertEquals(List.of(a), index.search("run"));
            assertEquals(List.of(a), index.search("runs"));
            assertEquals(List.of(), index.search("walk"));
        }
    }

    private static void assertArrayEquals(int[] expected, int[] actual) {
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], actual[i], "element " + i);
        }
    }
}
