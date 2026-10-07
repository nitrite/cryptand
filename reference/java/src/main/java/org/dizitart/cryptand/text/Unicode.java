package org.dizitart.cryptand.text;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The Unicode operations {@code spec/07-fulltext.md} §2.2 requires, at the
 * version it pins — NFKC, UAX #29 word segmentation, the step-3 keep test and
 * {@code Simple_Lowercase_Mapping}.
 *
 * <p>Full text is the hardest thing in this format to make portable: two
 * implementations that tokenize {@code "Bäckerei-Straße 12"} differently
 * produce two indexes that disagree about what documents exist. So nothing
 * here is delegated to the JDK, whose Unicode data is whatever version the
 * running JDK shipped (F-062: JDK 17's {@code Normalizer} is Unicode 13 and
 * does not know U+A7F2). The tables are Unicode 15.1, the same data Rust and
 * Dart use, generated into {@code unicode-15.1.0.bin} by
 * {@code tools/gen_java_unicode.py}; this class is a port of Rust's
 * {@code unicode.rs}. Checked against {@code NormalizationTest} and
 * {@code WordBreakTest} in {@code UnicodeTest}.
 */
public final class Unicode {

    private Unicode() {
    }

    /** The Unicode release {@code cryptand.std.v1} pins. */
    public static final String VERSION = "15.1.0";

    /** Word_Break property values — UAX #29 Table 3. */
    public enum WordBreak {
        OTHER, CR, LF, NEWLINE, EXTEND, ZWJ, REGIONAL_INDICATOR, FORMAT,
        KATAKANA, HEBREW_LETTER, ALETTER, SINGLE_QUOTE, DOUBLE_QUOTE,
        MID_NUM_LET, MID_LETTER, MID_NUM, NUMERIC, EXTEND_NUM_LET, WSEG_SPACE
    }

    /** The table's property indices (Rust's {@code WB_NAMES} order). */
    private static final WordBreak[] WB_BY_INDEX = {
            WordBreak.ALETTER, WordBreak.CR, WordBreak.DOUBLE_QUOTE, WordBreak.EXTEND,
            WordBreak.EXTEND_NUM_LET, WordBreak.FORMAT, WordBreak.HEBREW_LETTER,
            WordBreak.KATAKANA, WordBreak.LF, WordBreak.MID_LETTER, WordBreak.MID_NUM,
            WordBreak.MID_NUM_LET, WordBreak.NEWLINE, WordBreak.NUMERIC,
            WordBreak.REGIONAL_INDICATOR, WordBreak.SINGLE_QUOTE, WordBreak.WSEG_SPACE,
            WordBreak.ZWJ
    };

    private static final int[] WB_RANGES;
    private static final int[] EXTENDED_PICTOGRAPHIC;
    private static final int[] ALPHABETIC;
    private static final int[] NUMERIC_TYPE;
    private static final int[] CCC_MAP;
    private static final int[] SIMPLE_LOWERCASE;
    private static final int[] DECOMP_FLAT;
    private static final int[] COMPOSITION_EXCLUSIONS;
    /** Code point → its entry's offset in {@link #DECOMP_FLAT}. */
    private static final Map<Integer, Integer> DECOMP_OFFSETS = new HashMap<>();
    /** {@code (first << 21) | second} → composed, UAX #15's composition pairs. */
    private static final Map<Long, Integer> COMPOSITIONS = new HashMap<>();

    static {
        try (InputStream raw = Unicode.class.getResourceAsStream("unicode-" + VERSION + ".bin")) {
            if (raw == null) {
                throw new IllegalStateException("unicode-" + VERSION + ".bin is missing from the jar");
            }
            DataInputStream in = new DataInputStream(new java.io.BufferedInputStream(raw));
            if (in.readInt() != 0x43525955) { // "CRYU"
                throw new IllegalStateException("unicode-" + VERSION + ".bin has the wrong magic");
            }
            WB_RANGES = table(in);
            EXTENDED_PICTOGRAPHIC = table(in);
            ALPHABETIC = table(in);
            NUMERIC_TYPE = table(in);
            CCC_MAP = table(in);
            SIMPLE_LOWERCASE = table(in);
            DECOMP_FLAT = table(in);
            COMPOSITION_EXCLUSIONS = table(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        for (int i = 0; i < DECOMP_FLAT.length; i += 3 + DECOMP_FLAT[i + 2]) {
            int cp = DECOMP_FLAT[i];
            DECOMP_OFFSETS.put(cp, i);
            boolean compat = DECOMP_FLAT[i + 1] == 1;
            if (!compat && DECOMP_FLAT[i + 2] == 2) {
                int a = DECOMP_FLAT[i + 3];
                int b = DECOMP_FLAT[i + 4];
                if (lookupMap(COMPOSITION_EXCLUSIONS, cp, 0) == 0 && combiningClass(a) == 0) {
                    COMPOSITIONS.put(((long) a << 21) | b, cp);
                }
            }
        }
    }

    private static int[] table(DataInputStream in) throws IOException {
        int[] t = new int[in.readInt()];
        for (int i = 0; i < t.length; i++) {
            t[i] = in.readInt();
        }
        return t;
    }

    private static int lookup3(int[] table, int cp, int fallback) {
        int lo = 0;
        int hi = table.length / 3 - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (cp < table[mid * 3]) {
                hi = mid - 1;
            } else if (cp > table[mid * 3 + 1]) {
                lo = mid + 1;
            } else {
                return table[mid * 3 + 2];
            }
        }
        return fallback;
    }

    private static boolean inRanges(int[] table, int cp) {
        int lo = 0;
        int hi = table.length / 2 - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (cp < table[mid * 2]) {
                hi = mid - 1;
            } else if (cp > table[mid * 2 + 1]) {
                lo = mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    private static int lookupMap(int[] table, int cp, int fallback) {
        int lo = 0;
        int hi = table.length / 2 - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            int k = table[mid * 2];
            if (cp < k) {
                hi = mid - 1;
            } else if (cp > k) {
                lo = mid + 1;
            } else {
                return table[mid * 2 + 1];
            }
        }
        return fallback;
    }

    public static WordBreak wordBreak(int cp) {
        int i = lookup3(WB_RANGES, cp, -1);
        return i < 0 ? WordBreak.OTHER : WB_BY_INDEX[i];
    }

    static boolean isExtendedPictographic(int cp) {
        return inRanges(EXTENDED_PICTOGRAPHIC, cp);
    }

    static int combiningClass(int cp) {
        return lookupMap(CCC_MAP, cp, 0);
    }

    // ==================================================================
    // normalization, UAX #15
    // ==================================================================

    private static final int S_BASE = 0xAC00;
    private static final int L_BASE = 0x1100;
    private static final int V_BASE = 0x1161;
    private static final int T_BASE = 0x11A7;
    private static final int L_COUNT = 19;
    private static final int V_COUNT = 21;
    private static final int T_COUNT = 28;
    private static final int N_COUNT = V_COUNT * T_COUNT;
    private static final int S_COUNT = L_COUNT * N_COUNT;

    /** A growable code-point buffer, so normalization does not box. */
    private static final class Cps {
        int[] a = new int[16];
        int n;

        void add(int cp) {
            if (n == a.length) {
                a = Arrays.copyOf(a, n * 2);
            }
            a[n++] = cp;
        }
    }

    private static void decompose(int cp, boolean compat, Cps out) {
        // Hangul is algorithmic, not tabular.
        if (cp >= S_BASE && cp < S_BASE + S_COUNT) {
            int s = cp - S_BASE;
            out.add(L_BASE + s / N_COUNT);
            out.add(V_BASE + (s % N_COUNT) / T_COUNT);
            int t = s % T_COUNT;
            if (t != 0) {
                out.add(T_BASE + t);
            }
            return;
        }
        Integer idx = DECOMP_OFFSETS.get(cp);
        if (idx == null || (DECOMP_FLAT[idx + 1] == 1 && !compat)) {
            out.add(cp);
            return;
        }
        int len = DECOMP_FLAT[idx + 2];
        for (int k = 0; k < len; k++) {
            decompose(DECOMP_FLAT[idx + 3 + k], compat, out);
        }
    }

    /** Canonical ordering: a stable sort of each run of non-starters by class. */
    private static void canonicalOrder(int[] cps, int n) {
        for (int i = 1; i < n; i++) {
            int ccc = combiningClass(cps[i]);
            if (ccc == 0) {
                continue;
            }
            for (int j = i; j > 0; j--) {
                int prev = combiningClass(cps[j - 1]);
                if (prev == 0 || prev <= ccc) {
                    break;
                }
                int t = cps[j];
                cps[j] = cps[j - 1];
                cps[j - 1] = t;
            }
        }
    }

    /** The composite of {@code a} and {@code b}, or -1. */
    private static int composePair(int a, int b) {
        if (a >= L_BASE) {
            int l = a - L_BASE;
            if (l < L_COUNT && b >= V_BASE) {
                int v = b - V_BASE;
                if (v < V_COUNT) {
                    return S_BASE + (l * V_COUNT + v) * T_COUNT;
                }
            }
        }
        if (a >= S_BASE) {
            int s = a - S_BASE;
            if (s < S_COUNT && s % T_COUNT == 0 && b > T_BASE) {
                int t = b - T_BASE;
                if (t < T_COUNT) {
                    return a + t;
                }
            }
        }
        Integer c = COMPOSITIONS.get(((long) a << 21) | b);
        return c == null ? -1 : c;
    }

    /** Canonical composition: compose into the last starter unless blocked. */
    private static int compose(int[] buf, int n) {
        if (n == 0) {
            return 0;
        }
        int starterPos = 0;
        int starterCh = buf[0];
        int lastClass = combiningClass(starterCh) != 0 ? 256 : 0;
        int compPos = 1;
        for (int d = 1; d < n; d++) {
            int ch = buf[d];
            int chClass = combiningClass(ch);
            int composite = composePair(starterCh, ch);
            if (composite >= 0 && (lastClass < chClass || lastClass == 0)) {
                buf[starterPos] = composite;
                starterCh = composite;
            } else {
                if (chClass == 0) {
                    starterPos = compPos;
                    starterCh = ch;
                }
                lastClass = chClass;
                buf[compPos++] = ch;
            }
        }
        return compPos;
    }

    private static String normalize(String s, boolean compat) {
        Cps cps = new Cps();
        s.codePoints().forEach(cp -> decompose(cp, compat, cps));
        canonicalOrder(cps.a, cps.n);
        int n = compose(cps.a, cps.n);
        return new String(cps.a, 0, n);
    }

    /** NFKC — {@code spec/07-fulltext.md} §2.2 step 2. */
    public static String nfkc(String s) {
        return normalize(s, true);
    }

    /** NFC, because the conformance suite exercises both. */
    public static String nfc(String s) {
        return normalize(s, false);
    }

    // ==================================================================
    // UAX #29 word segmentation
    // ==================================================================

    private static boolean ignorable(WordBreak p) {
        return p == WordBreak.EXTEND || p == WordBreak.FORMAT || p == WordBreak.ZWJ;
    }

    private static boolean ahLetter(WordBreak p) {
        return p == WordBreak.ALETTER || p == WordBreak.HEBREW_LETTER;
    }

    private static boolean midNumLetQ(WordBreak p) {
        return p == WordBreak.MID_NUM_LET || p == WordBreak.SINGLE_QUOTE;
    }

    private static boolean lineBreak(WordBreak p) {
        return p == WordBreak.NEWLINE || p == WordBreak.CR || p == WordBreak.LF;
    }

    /** The nearest non-ignorable index at or before {@code i}; stops at a line break. */
    private static int prevSignificant(WordBreak[] p, int i) {
        for (int j = i; j >= 0; j--) {
            if (!ignorable(p[j]) || lineBreak(p[j])) {
                return j;
            }
        }
        return -1;
    }

    private static int nextSignificant(WordBreak[] p, int i) {
        for (int j = i; j < p.length; j++) {
            if (!ignorable(p[j])) {
                return j;
            }
        }
        return -1;
    }

    private static boolean isBreak(int[] cps, WordBreak[] p, int i) {
        WordBreak a = p[i - 1];
        WordBreak b = p[i];
        if (a == WordBreak.CR && b == WordBreak.LF) {
            return false; // WB3
        }
        if (lineBreak(a) || lineBreak(b)) {
            return true; // WB3a, WB3b
        }
        if (a == WordBreak.ZWJ && isExtendedPictographic(cps[i])) {
            return false; // WB3c
        }
        if (a == WordBreak.WSEG_SPACE && b == WordBreak.WSEG_SPACE) {
            return false; // WB3d
        }
        if (ignorable(b)) {
            return false; // WB4
        }
        int li = prevSignificant(p, i - 1);
        if (li < 0) {
            return true;
        }
        WordBreak l = p[li];
        int l2i = li > 0 ? prevSignificant(p, li - 1) : -1;
        WordBreak l2 = l2i >= 0 ? p[l2i] : WordBreak.OTHER;
        int ri = nextSignificant(p, i + 1);
        WordBreak r = ri >= 0 ? p[ri] : WordBreak.OTHER;

        if (ahLetter(l) && ahLetter(b)) {
            return false; // WB5
        }
        if (ahLetter(l) && (b == WordBreak.MID_LETTER || midNumLetQ(b)) && ahLetter(r)) {
            return false; // WB6
        }
        if (ahLetter(b) && (l == WordBreak.MID_LETTER || midNumLetQ(l)) && ahLetter(l2)) {
            return false; // WB7
        }
        if (l == WordBreak.HEBREW_LETTER && b == WordBreak.SINGLE_QUOTE) {
            return false; // WB7a
        }
        if (l == WordBreak.HEBREW_LETTER && b == WordBreak.DOUBLE_QUOTE && r == WordBreak.HEBREW_LETTER) {
            return false; // WB7b
        }
        if (l == WordBreak.DOUBLE_QUOTE && b == WordBreak.HEBREW_LETTER && l2 == WordBreak.HEBREW_LETTER) {
            return false; // WB7c
        }
        if (l == WordBreak.NUMERIC && b == WordBreak.NUMERIC) {
            return false; // WB8
        }
        if (ahLetter(l) && b == WordBreak.NUMERIC) {
            return false; // WB9
        }
        if (l == WordBreak.NUMERIC && ahLetter(b)) {
            return false; // WB10
        }
        if (b == WordBreak.NUMERIC && (l == WordBreak.MID_NUM || midNumLetQ(l)) && l2 == WordBreak.NUMERIC) {
            return false; // WB11
        }
        if (l == WordBreak.NUMERIC && (b == WordBreak.MID_NUM || midNumLetQ(b)) && r == WordBreak.NUMERIC) {
            return false; // WB12
        }
        if (l == WordBreak.KATAKANA && b == WordBreak.KATAKANA) {
            return false; // WB13
        }
        if ((ahLetter(l) || l == WordBreak.NUMERIC || l == WordBreak.KATAKANA
                || l == WordBreak.EXTEND_NUM_LET) && b == WordBreak.EXTEND_NUM_LET) {
            return false; // WB13a
        }
        if (l == WordBreak.EXTEND_NUM_LET
                && (ahLetter(b) || b == WordBreak.NUMERIC || b == WordBreak.KATAKANA)) {
            return false; // WB13b
        }
        // WB15/WB16: break only between an even number of regional indicators.
        if (l == WordBreak.REGIONAL_INDICATOR && b == WordBreak.REGIONAL_INDICATOR) {
            int count = 0;
            for (int j = li; j >= 0; j--) {
                if (ignorable(p[j])) {
                    continue;
                }
                if (p[j] != WordBreak.REGIONAL_INDICATOR) {
                    break;
                }
                count++;
            }
            if (count % 2 == 1) {
                return false;
            }
        }
        return true; // WB999
    }

    /** Splits {@code text} at UAX #29 word boundaries, returning each segment's code points. */
    public static List<int[]> words(String text) {
        int[] cps = text.codePoints().toArray();
        List<int[]> out = new ArrayList<>();
        if (cps.length == 0) {
            return out;
        }
        WordBreak[] wb = new WordBreak[cps.length];
        for (int i = 0; i < cps.length; i++) {
            wb[i] = wordBreak(cps[i]);
        }
        int start = 0;
        for (int i = 1; i < cps.length; i++) {
            if (isBreak(cps, wb, i)) {
                out.add(Arrays.copyOfRange(cps, start, i));
                start = i;
            }
        }
        out.add(Arrays.copyOfRange(cps, start, cps.length));
        return out;
    }

    /**
     * {@code Simple_Lowercase_Mapping} — step 4. Not {@code toLowerCase()},
     * which is locale-sensitive (Turkish {@code I} → {@code ı}), and not full
     * folding ({@code ẞ} → {@code ss}).
     */
    public static String simpleLowercase(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> sb.appendCodePoint(lookupMap(SIMPLE_LOWERCASE, cp, cp)));
        return sb.toString();
    }

    /** Step 3's keep test: at least one Alphabetic or {@code Numeric_Type != None} character. */
    public static boolean isWordLike(int[] cps) {
        for (int cp : cps) {
            if (inRanges(ALPHABETIC, cp) || inRanges(NUMERIC_TYPE, cp)) {
                return true;
            }
        }
        return false;
    }
}
