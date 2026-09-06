package org.dizitart.cryptand;

import java.util.Map;
import java.util.Set;

/**
 * The Snowball English stemmer (Porter2) — {@code spec/07-fulltext.md} §2.4.
 *
 * <p><strong>The release is part of the name.</strong> An earlier draft of the
 * spec wrote {@code porter2:<lang>} and justified it with "an unambiguous
 * published algorithm", which is true of a given Snowball <em>release</em> and
 * not of the family name: Snowball's own change log records behavioural changes
 * at 3.0.0 and again at 3.1.0, and one 3.1.0 entry reverses a 3.0.0 one — the
 * exception for {@code skis} was removed and then restored. Two SDKs on
 * different releases stem the same word to different terms, which is an index
 * that disagrees about what documents exist.
 *
 * <p>This implementation is <strong>3.1.0</strong>, and it is checked against
 * Snowball's own 42 649-word vocabulary for that release rather than against
 * another implementation.
 */
public final class Porter2 {

    /** The release this implements. A writer stores it; a reader refuses anything else. */
    public static final String RELEASE = "3.1.0";

    /** The full stemmer name for {@code analyzer_params.stemmer}. */
    public static final String NAME = "porter2:en:" + RELEASE;

    private Porter2() {
    }

    private static final Set<Character> VOWELS = Set.of('a', 'e', 'i', 'o', 'u', 'y');

    private static final String[] DOUBLES = {"bb", "dd", "ff", "gg", "mm", "nn", "pp", "rr", "tt"};

    private static final Set<Character> LI_ENDINGS =
            Set.of('c', 'd', 'e', 'g', 'h', 'k', 'm', 'n', 'r', 't');

    /**
     * Whole-word exceptions, applied before anything else.
     *
     * <p>{@code skis} is here because 3.1.0 restored it: 3.0.0 removed the
     * exception on the grounds that the algorithm gave the same stem without
     * it, and 3.1.0 put it back because it does not.
     */
    private static final Map<String, String> EXCEPTIONS = Map.ofEntries(
            Map.entry("skis", "ski"),
            Map.entry("skies", "sky"),
            Map.entry("dying", "die"),
            Map.entry("lying", "lie"),
            Map.entry("tying", "tie"),
            Map.entry("idly", "idl"),
            Map.entry("gently", "gentl"),
            Map.entry("ugly", "ugli"),
            Map.entry("early", "earli"),
            Map.entry("only", "onli"),
            Map.entry("singly", "singl"),
            Map.entry("sky", "sky"),
            Map.entry("news", "news"),
            Map.entry("howe", "howe"),
            Map.entry("atlas", "atlas"),
            Map.entry("cosmos", "cosmos"),
            Map.entry("bias", "bias"),
            Map.entry("andes", "andes"),
            // Added at 3.0.0. Each is a word the region rules alone reduce to a
            // stem it shares with an unrelated word: `evening` with `even`, and
            // `paste` with `past`.
            Map.entry("evening", "evening"),
            Map.entry("evenings", "evening"),
            Map.entry("paste", "paste"),
            Map.entry("pasted", "paste"),
            Map.entry("pasting", "paste"),
            Map.entry("hying", "hie"),
            Map.entry("vying", "vie"));

    /** Words that reach step 1a looking like plurals or gerunds and are not. */
    private static final Set<String> INVARIANT_AFTER_1A = Set.of(
            "inning", "outing", "canning", "herring", "earring",
            "proceed", "exceed", "succeed");

    public static String stem(String word) {
        if (word.length() <= 2) {
            return word;
        }
        for (int i = 0; i < word.length(); i++) {
            char c = word.charAt(i);
            if (c < 'a' || c > 'z') {
                // Snowball English is defined over lowercase ASCII. Anything
                // else is returned unchanged rather than mangled.
                if (c != '\'') {
                    return word;
                }
            }
        }
        String exception = EXCEPTIONS.get(word);
        if (exception != null) {
            return exception;
        }

        StringBuilder w = new StringBuilder(word);
        // A leading apostrophe goes before anything else, and step 0's trailing
        // ones go whatever the length: `'a'` is three characters and stems to
        // `a`, so a length guard placed before step 0 leaves the apostrophe on.
        if (w.charAt(0) == '\'') {
            w.deleteCharAt(0);
        }
        step0(w);
        if (w.length() <= 2) {
            return w.toString();
        }
        markConsonantY(w);

        int r1 = r1Of(w);
        int r2 = regionAfter(w, r1);

        step1a(w);
        if (INVARIANT_AFTER_1A.contains(unmark(w))) {
            return unmark(w);
        }
        r1 = Math.min(r1, w.length());
        r2 = Math.min(r2, w.length());
        step1b(w, r1);
        r1 = Math.min(r1, w.length());
        r2 = Math.min(r2, w.length());
        step1c(w);
        step2(w, r1);
        r1 = Math.min(r1, w.length());
        r2 = Math.min(r2, w.length());
        step3(w, r1, r2);
        r1 = Math.min(r1, w.length());
        r2 = Math.min(r2, w.length());
        step4(w, r2);
        r2 = Math.min(r2, w.length());
        r1 = Math.min(r1, w.length());
        step5(w, r1, r2);
        return unmark(w);
    }

    // ==================================================================
    // regions and shapes
    // ==================================================================

    /** {@code Y} marks a consonantal y; the rest of the algorithm treats it as one. */
    private static void markConsonantY(StringBuilder w) {
        if (w.charAt(0) == 'y') {
            w.setCharAt(0, 'Y');
        }
        for (int i = 1; i < w.length(); i++) {
            if (w.charAt(i) == 'y' && isVowel(w.charAt(i - 1))) {
                w.setCharAt(i, 'Y');
            }
        }
    }

    private static String unmark(StringBuilder w) {
        return w.toString().replace('Y', 'y');
    }

    private static boolean isVowel(char c) {
        return VOWELS.contains(c);
    }

    /**
     * R1, with the three prefixes the algorithm special-cases: a word beginning
     * {@code gener}, {@code commun} or {@code arsen} has R1 at the remainder.
     */
    private static int r1Of(StringBuilder w) {
        String s = w.toString();
        for (String prefix : R1_PREFIXES) {
            if (s.startsWith(prefix)) {
                return prefix.length();
            }
        }
        return regionAfter(w, 0);
    }

    /**
     * Prefixes after which R1 starts, rather than at the first vowel-consonant
     * boundary.
     *
     * <p>{@code gener}, {@code commun} and {@code arsen} are the original
     * three. The rest were added at Snowball 3.0.0, and they are precisely the
     * pairs §2.4 lists as having changed: without them {@code organic} collapses
     * onto {@code organ}, {@code university} onto {@code universe},
     * {@code lateral} onto {@code later}, {@code emergency} onto {@code emerge},
     * and every {@code inter-} word onto {@code intern}.
     */
    private static final String[] R1_PREFIXES = {
            "commun", "univers", "gener", "arsen", "emerg", "organ", "later", "inter"
    };

    /** The position after the first non-vowel following a vowel, from {@code from}. */
    private static int regionAfter(StringBuilder w, int from) {
        for (int i = from; i < w.length() - 1; i++) {
            if (isVowel(w.charAt(i)) && !isVowel(w.charAt(i + 1))) {
                return i + 2;
            }
        }
        return w.length();
    }

    /**
     * A short syllable: a vowel followed by a non-vowel other than
     * {@code w}, {@code x} or {@code Y} and preceded by a non-vowel, or a vowel
     * at the start of the word followed by a non-vowel.
     */
    private static boolean endsShortSyllable(StringBuilder w) {
        int n = w.length();
        if (n == 2) {
            return isVowel(w.charAt(0)) && !isVowel(w.charAt(1));
        }
        if (n < 3) {
            return false;
        }
        char c1 = w.charAt(n - 3);
        char c2 = w.charAt(n - 2);
        char c3 = w.charAt(n - 1);
        return !isVowel(c1) && isVowel(c2) && !isVowel(c3)
                && c3 != 'w' && c3 != 'x' && c3 != 'Y';
    }

    private static boolean isShort(StringBuilder w, int r1) {
        return r1 >= w.length() && endsShortSyllable(w);
    }

    private static boolean endsWith(StringBuilder w, String suffix) {
        int n = w.length();
        int m = suffix.length();
        if (n < m) {
            return false;
        }
        for (int i = 0; i < m; i++) {
            if (w.charAt(n - m + i) != suffix.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static boolean endsDouble(StringBuilder w) {
        for (String d : DOUBLES) {
            if (endsWith(w, d)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsVowel(StringBuilder w, int end) {
        for (int i = 0; i < end; i++) {
            if (isVowel(w.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static void replace(StringBuilder w, int suffixLength, String with) {
        w.setLength(w.length() - suffixLength);
        w.append(with);
    }

    // ==================================================================
    // the steps
    // ==================================================================

    /** Step 0: remove {@code '}, {@code 's} and {@code 's'}, longest first. */
    private static void step0(StringBuilder w) {
        if (endsWith(w, "'s'")) {
            w.setLength(w.length() - 3);
        } else if (endsWith(w, "'s")) {
            w.setLength(w.length() - 2);
        } else if (endsWith(w, "'")) {
            w.setLength(w.length() - 1);
        }
    }

    private static void step1a(StringBuilder w) {
        if (endsWith(w, "sses")) {
            replace(w, 4, "ss");
            return;
        }
        if (endsWith(w, "ied") || endsWith(w, "ies")) {
            // "i" when preceded by more than one letter, "ie" otherwise.
            replace(w, 3, w.length() > 4 ? "i" : "ie");
            return;
        }
        if (endsWith(w, "us") || endsWith(w, "ss")) {
            return;
        }
        if (endsWith(w, "s") && containsVowel(w, w.length() - 2)) {
            // Delete only if the part before the s holds a vowel that is not
            // immediately before it.
            w.setLength(w.length() - 1);
        }
    }

    private static void step1b(StringBuilder w, int r1) {
        if (endsWith(w, "eedly")) {
            if (w.length() - 5 >= r1) {
                replace(w, 5, "ee");
            }
            return;
        }
        if (endsWith(w, "eed")) {
            if (w.length() - 3 >= r1) {
                replace(w, 3, "ee");
            }
            return;
        }
        int cut = -1;
        for (String suffix : new String[]{"ingly", "edly", "ing", "ed"}) {
            if (endsWith(w, suffix)) {
                cut = suffix.length();
                break;
            }
        }
        if (cut < 0) {
            return;
        }
        if (!containsVowel(w, w.length() - cut)) {
            return;
        }
        w.setLength(w.length() - cut);
        if (endsWith(w, "at") || endsWith(w, "bl") || endsWith(w, "iz")) {
            w.append('e');
        } else if (endsDouble(w) && w.length() > 3) {
            // `hopp` -> `hop`, but `add` and `off` keep their double: the letter
            // is removed only when three characters survive it. Snowball 3.1.0's
            // own vocabulary is what pins this - `added`, `ebbed`, `erred` and
            // `offing` are the four words in 42 649 that show it.
            w.setLength(w.length() - 1);
        } else if (isShort(w, r1)) {
            w.append('e');
        }
    }

    /** Step 1c: {@code y} or {@code Y} becomes {@code i} after a non-vowel that is not the first letter. */
    private static void step1c(StringBuilder w) {
        int n = w.length();
        if (n < 3) {
            return;
        }
        char last = w.charAt(n - 1);
        if ((last == 'y' || last == 'Y') && !isVowel(w.charAt(n - 2))) {
            w.setCharAt(n - 1, 'i');
        }
    }

    private static void step2(StringBuilder w, int r1) {
        String[][] rules = {
                {"ization", "ize"}, {"ational", "ate"}, {"fulness", "ful"},
                {"ousness", "ous"}, {"iveness", "ive"}, {"tional", "tion"},
                {"biliti", "ble"}, {"lessli", "less"}, {"entli", "ent"},
                {"ation", "ate"}, {"alism", "al"}, {"aliti", "al"},
                {"ousli", "ous"}, {"iviti", "ive"}, {"fulli", "ful"},
                {"enci", "ence"}, {"anci", "ance"}, {"abli", "able"},
                {"izer", "ize"}, {"ator", "ate"}, {"alli", "al"},
                {"bli", "ble"},
        };
        for (String[] rule : rules) {
            if (endsWith(w, rule[0])) {
                if (w.length() - rule[0].length() >= r1) {
                    replace(w, rule[0].length(), rule[1]);
                }
                return;
            }
        }
        // 3.0.0 added -ogist to the -ogi rule's family: both reduce to -og, and
        // only after an l.
        if (endsWith(w, "ogist")) {
            if (w.length() - 5 >= r1 && w.length() >= 6 && w.charAt(w.length() - 6) == 'l') {
                replace(w, 5, "og");
            }
            return;
        }
        if (endsWith(w, "ogi")) {
            if (w.length() - 3 >= r1 && w.length() >= 4 && w.charAt(w.length() - 4) == 'l') {
                replace(w, 3, "og");
            }
            return;
        }
        if (endsWith(w, "li")) {
            if (w.length() - 2 >= r1 && w.length() >= 3 && LI_ENDINGS.contains(w.charAt(w.length() - 3))) {
                w.setLength(w.length() - 2);
            }
        }
    }

    private static void step3(StringBuilder w, int r1, int r2) {
        String[][] rules = {
                {"ational", "ate"}, {"tional", "tion"}, {"alize", "al"},
                {"icate", "ic"}, {"iciti", "ic"}, {"ical", "ic"},
                {"ness", ""}, {"ful", ""},
        };
        for (String[] rule : rules) {
            if (endsWith(w, rule[0])) {
                if (w.length() - rule[0].length() >= r1) {
                    replace(w, rule[0].length(), rule[1]);
                }
                return;
            }
        }
        if (endsWith(w, "ative")) {
            if (w.length() - 5 >= r2) {
                w.setLength(w.length() - 5);
            }
        }
    }

    private static void step4(StringBuilder w, int r2) {
        String[] suffixes = {
                "ement", "ance", "ence", "able", "ible", "ment",
                "ant", "ent", "ism", "ate", "iti", "ous", "ive", "ize",
                "al", "er", "ic",
        };
        for (String suffix : suffixes) {
            if (endsWith(w, suffix)) {
                if (w.length() - suffix.length() >= r2) {
                    w.setLength(w.length() - suffix.length());
                }
                return;
            }
        }
        if (endsWith(w, "ion")) {
            int at = w.length() - 3;
            if (at >= r2 && at > 0) {
                char before = w.charAt(at - 1);
                if (before == 's' || before == 't') {
                    w.setLength(at);
                }
            }
        }
    }

    private static void step5(StringBuilder w, int r1, int r2) {
        int n = w.length();
        if (n == 0) {
            return;
        }
        if (w.charAt(n - 1) == 'e') {
            if (n - 1 >= r2) {
                w.setLength(n - 1);
            } else if (n - 1 >= r1) {
                StringBuilder without = new StringBuilder(w).deleteCharAt(n - 1);
                if (!endsShortSyllable(without)) {
                    w.setLength(n - 1);
                }
            }
            return;
        }
        if (w.charAt(n - 1) == 'l' && n - 1 >= r2 && n >= 2 && w.charAt(n - 2) == 'l') {
            w.setLength(n - 1);
        }
    }
}
