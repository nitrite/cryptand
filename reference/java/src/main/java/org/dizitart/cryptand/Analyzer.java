package org.dizitart.cryptand;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * {@code cryptand.std.v1} — {@code spec/07-fulltext.md} §2.2.
 *
 * <p>Every Level-2 implementation must implement this exactly. It is
 * deliberately small, because every step is a step that can differ between
 * languages — and two implementations that tokenize {@code "Bäckerei-Straße 12"}
 * differently produce two indexes that disagree about what documents exist,
 * which no checksum catches.
 *
 * <p>The rule around it is §2.1's: an implementation that cannot reproduce the
 * named analyzer exactly MUST NOT write to the index, and cannot query it
 * either — queries are analyzed with the same analyzer — so it reports that
 * rather than guessing.
 */
public final class Analyzer {

    public static final String STD_V1 = "cryptand.std.v1";

    /** Step 5's cap, in code points. */
    public static final int MAX_TOKEN_CODE_POINTS = 64;

    /** A surviving segment and its <em>pre-filter</em> index among the segments of step 3. */
    public record Token(String text, int position) {
    }

    private final String name;
    private final Set<String> stopwords;
    private final String stemmer;

    private Analyzer(String name, Set<String> stopwords, String stemmer) {
        this.name = name;
        this.stopwords = stopwords;
        this.stemmer = stemmer;
    }

    public static Analyzer standard() {
        return new Analyzer(STD_V1, Set.of(), "none");
    }

    /**
     * @param stopwords the list as it is stored in the file — sorted, NFKC and
     *                  lowercased. Nitrite ships per-language lists in all three
     *                  SDKs today and they are not identical, so the file's copy
     *                  is authoritative and the implementation's is not consulted.
     * @param stemmer   {@code "none"} or {@code porter2:<lang>:<release>}. An
     *                  unpinned {@code porter2:<lang>} is rejected: it cannot be
     *                  made to mean one thing, and guessing a release is how two
     *                  SDKs come to disagree without either being able to detect it.
     */
    public static Analyzer of(String name, List<String> stopwords, String stemmer) {
        if (!STD_V1.equals(name)) {
            throw new UnsupportedFeatureException("analyzer '" + name + "' is not registered here; "
                    + "an index it wrote is unwritable and unqueryable by this implementation "
                    + "(spec/07-fulltext.md §2.5)");
        }
        if (stemmer != null && stemmer.startsWith("porter2")) {
            String[] parts = stemmer.split(":");
            if (parts.length != 3) {
                throw new InvalidArgumentException("stemmer '" + stemmer
                        + "' does not pin a Snowball release; an unpinned porter2:<lang> cannot be "
                        + "made to mean one thing (spec/07-fulltext.md §2.4)");
            }
            if (!"en".equals(parts[1]) || !Porter2.RELEASE.equals(parts[2])) {
                throw new UnsupportedFeatureException("this implementation has porter2:en:"
                        + Porter2.RELEASE + " and will not write an index pinning '" + stemmer + "'");
            }
        }
        return new Analyzer(name, new LinkedHashSet<>(stopwords),
                stemmer == null ? "none" : stemmer);
    }

    public String name() {
        return name;
    }

    public String stemmer() {
        return stemmer;
    }

    public List<String> stopwords() {
        return List.copyOf(stopwords);
    }

    /** The Unicode release this analyzer's segmentation and case data pin. */
    public String unicodeVersion() {
        return Unicode.VERSION;
    }

    /**
     * Steps 1 to 8.
     *
     * <p>The positions are the indices of the surviving segments among the
     * segments of <strong>step 3</strong> — before stopword and length
     * filtering — so a phrase query still lines up across a dropped stopword.
     */
    public List<Token> analyze(String text) {
        if (text == null) {
            return List.of();
        }
        String normalized = Unicode.nfkc(text);
        List<Token> out = new ArrayList<>();
        int position = 0;
        for (int[] segment : Unicode.words(normalized)) {
            if (!Unicode.isWordLike(segment)) {
                continue;
            }
            int at = position++;
            if (segment.length > MAX_TOKEN_CODE_POINTS) {
                continue;
            }
            StringBuilder sb = new StringBuilder(segment.length);
            for (int cp : segment) {
                sb.appendCodePoint(cp);
            }
            String term = Unicode.simpleLowercase(sb.toString());
            if (stopwords.contains(term)) {
                continue;
            }
            if (!"none".equals(stemmer)) {
                term = Porter2.stem(term);
            }
            out.add(new Token(term, at));
        }
        return out;
    }

    /** §3: a query string is analyzed with the same analyzer and params as the index. */
    public List<String> analyzeQuery(String text) {
        List<String> terms = new ArrayList<>();
        for (Token t : analyze(text)) {
            terms.add(t.text());
        }
        return terms;
    }
}
