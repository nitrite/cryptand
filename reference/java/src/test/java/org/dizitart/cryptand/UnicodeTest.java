package org.dizitart.cryptand;

import org.dizitart.cryptand.text.Unicode;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two Unicode steps of {@code cryptand.std.v1}, against Unicode 15.1's own
 * conformance suites.
 *
 * <p>Reproducing them is the evidence that {@code 00-conventions.md} §1.1's
 * claim holds — naming an algorithm to the parameter makes a format portable —
 * and it is stronger than comparing a version string, because a JDK whose data
 * moved would fail here rather than silently tokenize differently.
 */
class UnicodeTest {

    private static Path data(String name) {
        return Path.of("..", "conformance", "unicode", name);
    }

    @Test
    @DisplayName("NFKC reproduces NormalizationTest-15.1.0 in full")
    void normalization() throws IOException {
        Path file = data("NormalizationTest-15.1.0.txt");
        assertTrue(Files.exists(file), "the Unicode conformance data is present");
        int cases = 0;
        List<String> failures = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("@")) {
                continue;
            }
            String[] parts = line.split(";");
            if (parts.length < 5) {
                continue;
            }
            // Columns are source; NFC; NFD; NFKC; NFKD. The invariant checked
            // here is the one the analyzer relies on: NFKC(source) == NFKC of
            // every column.
            String[] columns = new String[5];
            for (int i = 0; i < 5; i++) {
                columns[i] = decode(parts[i]);
            }
            String nfkc = columns[3];
            for (int i = 0; i < 5; i++) {
                cases++;
                String got = Unicode.nfkc(columns[i]);
                if (!got.equals(nfkc) && failures.size() < 5) {
                    failures.add("line '" + line.split("#")[0].trim() + "' column " + i);
                }
            }
        }
        assertTrue(cases > 90_000, "the whole suite ran: " + cases + " checks");
        assertEquals(List.of(), failures);
    }

    /**
     * Every sample character in {@code WordBreakTest} is annotated with its
     * Word_Break value, so the derivation can be checked character by character
     * rather than only through the segmentation it feeds.
     */
    @Test
    @DisplayName("the derived Word_Break property matches Unicode 15.1's own annotations")
    void wordBreakProperty() throws IOException {
        java.util.Map<Integer, String> expected = new java.util.LinkedHashMap<>();
        for (String line : Files.readAllLines(data("WordBreakTest-15.1.0.txt"), StandardCharsets.UTF_8)) {
            int hash = line.indexOf('#');
            if (hash < 0 || line.startsWith("#")) {
                continue;
            }
            String comment = line.substring(hash + 1);
            String codes = line.substring(0, hash);
            List<Integer> cps = new ArrayList<>();
            for (String token : codes.trim().split("\\s+")) {
                if (token.matches("[0-9A-Fa-f]{4,6}")) {
                    cps.add(Integer.parseInt(token, 16));
                }
            }
            // Annotations read "NAME (Property)" in the same order as the code
            // points.
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\\(([A-Za-z_]+)\\)").matcher(comment);
            int i = 0;
            while (m.find() && i < cps.size()) {
                expected.putIfAbsent(cps.get(i), m.group(1));
                i++;
            }
        }
        assertTrue(expected.size() > 50, "annotations were found: " + expected.size());
        List<String> mismatches = new ArrayList<>();
        for (java.util.Map.Entry<Integer, String> e : expected.entrySet()) {
            String want = normalizeName(e.getValue());
            String got = Unicode.wordBreak(e.getKey()).name().replace("_", "");
            if (!want.equalsIgnoreCase(got)) {
                mismatches.add(String.format("U+%04X expected %s, derived %s",
                        e.getKey(), e.getValue(), Unicode.wordBreak(e.getKey())));
            }
        }
        assertEquals(List.of(), mismatches);
    }

    private static String normalizeName(String annotated) {
        // The file writes Extend_FE for Extend characters that are also Format
        // or ZWJ-adjacent; both resolve to Extend for the rules.
        String s = annotated.replace("_FE", "").replace("_", "");
        switch (s) {
            case "RI": return "REGIONALINDICATOR";
            case "ExtendNumLet": return "EXTENDNUMLET";
            case "ExtPict": return "OTHER";
            default: return s;
        }
    }

    @Test
    @DisplayName("word segmentation reproduces WordBreakTest-15.1.0 in full")
    void wordBreakSegmentation() throws IOException {
        int cases = 0;
        List<String> failures = new ArrayList<>();
        for (String line : Files.readAllLines(data("WordBreakTest-15.1.0.txt"), StandardCharsets.UTF_8)) {
            int hash = line.indexOf('#');
            String body = (hash < 0 ? line : line.substring(0, hash)).trim();
            if (body.isEmpty()) {
                continue;
            }
            cases++;
            StringBuilder text = new StringBuilder();
            List<Integer> expectedBreaks = new ArrayList<>();
            int index = 0;
            for (String token : body.split("\\s+")) {
                if (token.equals("÷")) {
                    expectedBreaks.add(index);
                } else if (token.equals("×")) {
                    // no break here
                } else {
                    int cp = Integer.parseInt(token, 16);
                    text.appendCodePoint(cp);
                    index++;
                }
            }
            List<int[]> words = Unicode.words(text.toString());
            List<Integer> actualBreaks = new ArrayList<>();
            int at = 0;
            actualBreaks.add(0);
            for (int[] w : words) {
                at += w.length;
                actualBreaks.add(at);
            }
            if (text.length() == 0) {
                continue;
            }
            if (!actualBreaks.equals(expectedBreaks) && failures.size() < 8) {
                failures.add(body + "  expected " + expectedBreaks + " got " + actualBreaks);
            }
        }
        assertEquals(1826, cases, "every published case ran");
        assertEquals(List.of(), failures);
    }

    @Test
    @DisplayName("simple lowercasing is not full folding and is not locale-sensitive")
    void simpleLowercase() {
        // Full folding maps the capital sharp S to "ss"; the spec says simple.
        assertEquals("ß", Unicode.simpleLowercase("ẞ"));
        // Turkish would map I to a dotless i; the mapping here is invariant.
        assertEquals("i", Unicode.simpleLowercase("I"));
        assertEquals("straße", Unicode.simpleLowercase("STRAẞE").substring(0, 6));
    }

    private static String decode(String hex) {
        StringBuilder sb = new StringBuilder();
        for (String token : hex.trim().split("\\s+")) {
            if (!token.isEmpty()) {
                sb.appendCodePoint(Integer.parseInt(token, 16));
            }
        }
        return sb.toString();
    }
}
