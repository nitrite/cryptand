package org.dizitart.cryptand.text;

import java.util.ArrayList;
import java.util.List;

/**
 * UAX #29 word segmentation and the Word_Break property —
 * {@code spec/07-fulltext.md} §2.2 steps 2 to 4.
 *
 * <p>Full text is the hardest thing in this format to make portable, and the
 * reason is not the postings: two implementations that tokenize
 * {@code "Bäckerei-Straße 12"} differently produce two indexes that disagree
 * about what documents exist. So the analyzer is specified, and this is the
 * part of it that has to be reproduced rather than delegated.
 *
 * <p><strong>What is delegated and why.</strong> NFKC and
 * {@code Simple_Lowercase_Mapping} come from the JDK. Both are covered by
 * Unicode's own stability policies for characters already assigned — a
 * normalized string stays normalized in every later version, and simple case
 * mappings of assigned characters do not change — so a newer JDK cannot move
 * them for text {@code cryptand.std.v1} can contain. <strong>Word_Break is
 * not</strong> stable in that way, so it is derived here, from properties the
 * JDK exposes plus the explicit lists UAX #29 names, and the derivation is
 * checked character by character against Unicode 15.1's own
 * {@code WordBreakTest} annotations rather than trusted.
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

    // Characters whose Word_Break value is assigned by an explicit list rather
    // than derived from another property. Every one of them is in UAX #29's
    // Table 3, and every one is a character whose derivation would otherwise
    // land somewhere else.

    private static final int[] MID_LETTER = {
            0x003A, 0x00B7, 0x0387, 0x055F, 0x05F4, 0x2027, 0xFE13, 0xFE55, 0xFF1A,
            0x2018, 0x2019, 0x2024, 0xFE52, 0xFF07, 0xFF0E
    };

    private static final int[] MID_NUM = {
            0x002C, 0x003B, 0x037E, 0x0589, 0x060C, 0x060D, 0x066C, 0x07F8, 0x2044,
            0xFE10, 0xFE14, 0xFE50, 0xFE54, 0xFF0C, 0xFF1B
    };

    private static final int[] KATAKANA_EXTRA = {
            0x3031, 0x3032, 0x3033, 0x3034, 0x3035, 0x309B, 0x309C, 0x30A0, 0x30FC,
            0xFF70, 0xFF9E, 0xFF9F
    };

    private static final int[] ALETTER_EXTRA = {
            0x02C2, 0x02C3, 0x02C4, 0x02C5, 0x02D2, 0x02D3, 0x02D4, 0x02D5, 0x02D6,
            0x02D7, 0x02DE, 0x02DF, 0x02E5, 0x02E6, 0x02E7, 0x02E8, 0x02E9, 0x02EA,
            0x02EB, 0x02ED, 0x02EF, 0x02F0, 0x02F1, 0x02F2, 0x02F3, 0x02F4, 0x02F5,
            0x02F6, 0x02F7, 0x02F8, 0x02F9, 0x02FA, 0x02FB, 0x02FC, 0x02FD, 0x02FE,
            0x02FF, 0x055A, 0x055B, 0x055C, 0x055E, 0x058A, 0x05F3, 0xA708, 0xA709,
            0xA70A, 0xA70B, 0xA70C, 0xA70D, 0xA70E, 0xA70F, 0xA710, 0xA711, 0xA712,
            0xA713, 0xA714, 0xA715, 0xA716, 0xA720, 0xA721, 0xA789, 0xA78A, 0xAB5B,
            0xFF9E, 0xFF9F
    };

    /** Scripts whose Line_Break is Complex_Context (SA): excluded from ALetter. */
    private static final Character.UnicodeScript[] COMPLEX_CONTEXT = {
            Character.UnicodeScript.THAI, Character.UnicodeScript.LAO,
            Character.UnicodeScript.MYANMAR, Character.UnicodeScript.KHMER,
            Character.UnicodeScript.TAI_LE, Character.UnicodeScript.NEW_TAI_LUE,
            Character.UnicodeScript.TAI_THAM, Character.UnicodeScript.TAI_VIET,
            Character.UnicodeScript.CHAM,
            Character.UnicodeScript.HANUNOO, Character.UnicodeScript.BUHID,
            Character.UnicodeScript.TAGBANWA, Character.UnicodeScript.TAGALOG,
            Character.UnicodeScript.JAVANESE, Character.UnicodeScript.BALINESE,
            Character.UnicodeScript.SUNDANESE, Character.UnicodeScript.BATAK,
            Character.UnicodeScript.REJANG, Character.UnicodeScript.KAYAH_LI,
            Character.UnicodeScript.PAHAWH_HMONG, Character.UnicodeScript.NYIAKENG_PUACHUE_HMONG
    };

    public static WordBreak wordBreak(int cp) {
        if (cp == 0x000D) {
            return WordBreak.CR;
        }
        if (cp == 0x000A) {
            return WordBreak.LF;
        }
        if (cp == 0x000B || cp == 0x000C || cp == 0x0085 || cp == 0x2028 || cp == 0x2029) {
            return WordBreak.NEWLINE;
        }
        if (cp == 0x200D) {
            return WordBreak.ZWJ;
        }
        if (cp >= 0x1F1E6 && cp <= 0x1F1FF) {
            return WordBreak.REGIONAL_INDICATOR;
        }
        if (cp == 0x0027) {
            return WordBreak.SINGLE_QUOTE;
        }
        if (cp == 0x0022) {
            return WordBreak.DOUBLE_QUOTE;
        }
        if (isExtend(cp)) {
            return WordBreak.EXTEND;
        }
        // Three format characters that UAX #29 assigns by name rather than by
        // general category, because they behave as content: the two end-of-ayah
        // marks count as digits inside an Arabic number, and the Syriac
        // abbreviation mark sits inside a word.
        if (cp == 0x06DD || cp == 0x08E2) {
            return WordBreak.NUMERIC;
        }
        if (cp == 0x070F) {
            return WordBreak.ALETTER;
        }
        int type = Character.getType(cp);
        if (type == Character.FORMAT) {
            return WordBreak.FORMAT;
        }
        if (type == Character.CONNECTOR_PUNCTUATION) {
            return WordBreak.EXTEND_NUM_LET;
        }
        if (contains(MID_NUM_LET, cp)) {
            return WordBreak.MID_NUM_LET;
        }
        if (contains(MID_LETTER_ONLY, cp)) {
            return WordBreak.MID_LETTER;
        }
        if (contains(MID_NUM, cp)) {
            return WordBreak.MID_NUM;
        }
        if (isNumeric(cp)) {
            return WordBreak.NUMERIC;
        }
        if (isKatakana(cp)) {
            return WordBreak.KATAKANA;
        }
        if (Character.UnicodeScript.of(cp) == Character.UnicodeScript.HEBREW
                && type == Character.OTHER_LETTER) {
            return WordBreak.HEBREW_LETTER;
        }
        if (isALetter(cp)) {
            return WordBreak.ALETTER;
        }
        if (type == Character.SPACE_SEPARATOR && cp != 0x00A0 && cp != 0x2007 && cp != 0x202F) {
            return WordBreak.WSEG_SPACE;
        }
        return WordBreak.OTHER;
    }

    /** {@code MidNumLet} is the overlap of the two mid classes, so it is its own list. */
    private static final int[] MID_NUM_LET = {
            0x002E, 0x2018, 0x2019, 0x2024, 0xFE52, 0xFF07, 0xFF0E
    };

    private static final int[] MID_LETTER_ONLY = {
            0x003A, 0x00B7, 0x0387, 0x055F, 0x05F4, 0x2027, 0xFE13, 0xFE55, 0xFF1A
    };

    private static boolean isExtend(int cp) {
        if (cp == 0x200C) {
            return true;
        }
        int type = Character.getType(cp);
        if (type == Character.NON_SPACING_MARK || type == Character.ENCLOSING_MARK) {
            return true;
        }
        if (type == Character.COMBINING_SPACING_MARK) {
            return true;
        }
        // Emoji_Modifier: the five skin-tone modifiers.
        return cp >= 0x1F3FB && cp <= 0x1F3FF;
    }

    private static boolean isNumeric(int cp) {
        if (Character.getType(cp) == Character.DECIMAL_DIGIT_NUMBER) {
            // Fullwidth digits are Other, not Numeric.
            return !(cp >= 0xFF10 && cp <= 0xFF19);
        }
        return cp == 0x066B || cp == 0x066C;
    }

    private static boolean isKatakana(int cp) {
        if (contains(KATAKANA_EXTRA, cp)) {
            return true;
        }
        return Character.UnicodeScript.of(cp) == Character.UnicodeScript.KATAKANA;
    }

    private static boolean isALetter(int cp) {
        if (contains(ALETTER_EXTRA, cp)) {
            return true;
        }
        if (!Character.isAlphabetic(cp)) {
            return false;
        }
        if (Character.isIdeographic(cp)) {
            return false;
        }
        Character.UnicodeScript script = Character.UnicodeScript.of(cp);
        if (script == Character.UnicodeScript.HIRAGANA) {
            return false;
        }
        for (Character.UnicodeScript s : COMPLEX_CONTEXT) {
            if (script == s) {
                return false;
            }
        }
        return true;
    }

    private static boolean contains(int[] sorted, int cp) {
        for (int v : sorted) {
            if (v == cp) {
                return true;
            }
        }
        return false;
    }

    // ==================================================================
    // UAX #29 §4.1 — the word boundary rules
    // ==================================================================

    /**
     * Splits {@code text} at UAX #29 word boundaries, returning each segment's
     * code points.
     *
     * <p>WB4 is what makes the rest readable: {@code Extend}, {@code Format} and
     * {@code ZWJ} after any character other than a line terminator are ignored,
     * so every other rule is written against the nearest <em>significant</em>
     * neighbour rather than the literal one.
     */
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
                out.add(java.util.Arrays.copyOfRange(cps, start, i));
                start = i;
            }
        }
        out.add(java.util.Arrays.copyOfRange(cps, start, cps.length));
        return out;
    }

    private static boolean ignorable(WordBreak w) {
        return w == WordBreak.EXTEND || w == WordBreak.FORMAT || w == WordBreak.ZWJ;
    }

    /** The last index at or before {@code i} that WB4 does not ignore, or -1. */
    private static int significantBefore(WordBreak[] wb, int i) {
        int j = i;
        while (j >= 0 && ignorable(wb[j])) {
            j--;
        }
        return j;
    }

    /** The first index at or after {@code i} that WB4 does not ignore, or length. */
    private static int significantAfter(WordBreak[] wb, int i) {
        int j = i;
        while (j < wb.length && ignorable(wb[j])) {
            j++;
        }
        return j;
    }

    private static boolean isBreak(int[] cps, WordBreak[] wb, int i) {
        WordBreak before = wb[i - 1];
        WordBreak after = wb[i];

        // WB3: CR x LF.
        if (before == WordBreak.CR && after == WordBreak.LF) {
            return false;
        }
        // WB3a and WB3b: a line terminator always breaks on both sides.
        if (before == WordBreak.NEWLINE || before == WordBreak.CR || before == WordBreak.LF) {
            return true;
        }
        if (after == WordBreak.NEWLINE || after == WordBreak.CR || after == WordBreak.LF) {
            return true;
        }
        // WB3c: ZWJ x Extended_Pictographic.
        if (before == WordBreak.ZWJ && isExtendedPictographic(cps[i])) {
            return false;
        }
        // WB3d: WSegSpace x WSegSpace.
        if (before == WordBreak.WSEG_SPACE && after == WordBreak.WSEG_SPACE) {
            return false;
        }
        // WB4: X (Extend | Format | ZWJ)* -> X.
        if (ignorable(after)) {
            return false;
        }

        int p = significantBefore(wb, i - 1);
        if (p < 0) {
            return true;
        }
        WordBreak a = wb[p];
        WordBreak b = after;

        if (isAhLetter(a) && isAhLetter(b)) {
            return false;                                          // WB5
        }
        if (isAhLetter(a) && (b == WordBreak.MID_LETTER || isMidNumLetQ(b))
                && isAhLetter(peekAfter(wb, i))) {
            return false;                                          // WB6
        }
        if (isAhLetter(b)) {
            int q = significantBefore(wb, p - 1);
            if (q >= 0 && (a == WordBreak.MID_LETTER || isMidNumLetQ(a)) && isAhLetter(wb[q])) {
                return false;                                      // WB7
            }
        }
        if (a == WordBreak.HEBREW_LETTER && b == WordBreak.SINGLE_QUOTE) {
            return false;                                          // WB7a
        }
        if (a == WordBreak.HEBREW_LETTER && b == WordBreak.DOUBLE_QUOTE
                && peekAfter(wb, i) == WordBreak.HEBREW_LETTER) {
            return false;                                          // WB7b
        }
        if (b == WordBreak.HEBREW_LETTER && a == WordBreak.DOUBLE_QUOTE) {
            int q = significantBefore(wb, p - 1);
            if (q >= 0 && wb[q] == WordBreak.HEBREW_LETTER) {
                return false;                                      // WB7c
            }
        }
        if (a == WordBreak.NUMERIC && b == WordBreak.NUMERIC) {
            return false;                                          // WB8
        }
        if (isAhLetter(a) && b == WordBreak.NUMERIC) {
            return false;                                          // WB9
        }
        if (a == WordBreak.NUMERIC && isAhLetter(b)) {
            return false;                                          // WB10
        }
        if (b == WordBreak.NUMERIC) {
            int q = significantBefore(wb, p - 1);
            if (q >= 0 && (a == WordBreak.MID_NUM || isMidNumLetQ(a))
                    && wb[q] == WordBreak.NUMERIC) {
                return false;                                      // WB11
            }
        }
        if (a == WordBreak.NUMERIC && (b == WordBreak.MID_NUM || isMidNumLetQ(b))
                && peekAfter(wb, i) == WordBreak.NUMERIC) {
            return false;                                          // WB12
        }
        if (a == WordBreak.KATAKANA && b == WordBreak.KATAKANA) {
            return false;                                          // WB13
        }
        if ((isAhLetter(a) || a == WordBreak.NUMERIC || a == WordBreak.KATAKANA
                || a == WordBreak.EXTEND_NUM_LET) && b == WordBreak.EXTEND_NUM_LET) {
            return false;                                          // WB13a
        }
        if (a == WordBreak.EXTEND_NUM_LET
                && (isAhLetter(b) || b == WordBreak.NUMERIC || b == WordBreak.KATAKANA)) {
            return false;                                          // WB13b
        }
        // WB15 and WB16: regional indicators pair up, so a break falls between
        // every second one.
        if (b == WordBreak.REGIONAL_INDICATOR && a == WordBreak.REGIONAL_INDICATOR) {
            int count = 0;
            int j = p;
            while (j >= 0) {
                if (wb[j] == WordBreak.REGIONAL_INDICATOR) {
                    count++;
                    j = significantBefore(wb, j - 1);
                } else {
                    break;
                }
            }
            return count % 2 == 0;
        }
        return true;                                               // WB999
    }

    /** The Word_Break of the next significant character after position {@code i}. */
    private static WordBreak peekAfter(WordBreak[] wb, int i) {
        int j = significantAfter(wb, i + 1);
        return j < wb.length ? wb[j] : WordBreak.OTHER;
    }

    private static boolean isAhLetter(WordBreak w) {
        return w == WordBreak.ALETTER || w == WordBreak.HEBREW_LETTER;
    }

    private static boolean isMidNumLetQ(WordBreak w) {
        return w == WordBreak.MID_NUM_LET || w == WordBreak.SINGLE_QUOTE;
    }

    /**
     * Extended_Pictographic, for WB3c. The JDK exposes no such property, so the
     * ranges are listed; they are stable and they are what keeps an emoji ZWJ
     * sequence one word.
     */
    static boolean isExtendedPictographic(int cp) {
        for (int i = 0; i < EXT_PICT.length; i += 2) {
            if (cp >= EXT_PICT[i] && cp <= EXT_PICT[i + 1]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extended_Pictographic ranges, Unicode 15.1.
     *
     * <p>The regional-indicator block is deliberately <strong>not</strong> in
     * here even though it sits between two ranges that are. An RI is not
     * pictographic, and treating it as one makes WB3c join a ZWJ to the flag
     * that follows it — which is two of {@code WordBreakTest}'s 1826 cases and
     * nothing else, so an approximation that swallowed the block would look
     * almost right.
     */
    private static final int[] EXT_PICT = {
            0x00A9, 0x00A9, 0x00AE, 0x00AE, 0x203C, 0x203C, 0x2049, 0x2049,
            0x2122, 0x2122, 0x2139, 0x2139, 0x2194, 0x2199, 0x21A9, 0x21AA,
            0x231A, 0x231B, 0x2328, 0x2328, 0x2388, 0x2388, 0x23CF, 0x23CF,
            0x23E9, 0x23F3, 0x23F8, 0x23FA, 0x24C2, 0x24C2, 0x25AA, 0x25AB,
            0x25B6, 0x25B6, 0x25C0, 0x25C0, 0x25FB, 0x25FE, 0x2600, 0x2605,
            0x2607, 0x2612, 0x2614, 0x2685, 0x2690, 0x2705, 0x2708, 0x2712,
            0x2714, 0x2714, 0x2716, 0x2716, 0x271D, 0x271D, 0x2721, 0x2721,
            0x2728, 0x2728, 0x2733, 0x2734, 0x2744, 0x2744, 0x2747, 0x2747,
            0x274C, 0x274C, 0x274E, 0x274E, 0x2753, 0x2755, 0x2757, 0x2757,
            0x2763, 0x2767, 0x2795, 0x2797, 0x27A1, 0x27A1, 0x27B0, 0x27B0,
            0x27BF, 0x27BF, 0x2934, 0x2935, 0x2B05, 0x2B07, 0x2B1B, 0x2B1C,
            0x2B50, 0x2B50, 0x2B55, 0x2B55, 0x3030, 0x3030, 0x303D, 0x303D,
            0x3297, 0x3297, 0x3299, 0x3299,
            0x1F000, 0x1F0FF, 0x1F10D, 0x1F10F, 0x1F12F, 0x1F12F,
            0x1F16C, 0x1F171, 0x1F17E, 0x1F17F, 0x1F18E, 0x1F18E,
            0x1F191, 0x1F19A, 0x1F1AD, 0x1F1E5,
            0x1F201, 0x1F20F, 0x1F21A, 0x1F21A, 0x1F22F, 0x1F22F,
            0x1F232, 0x1F23A, 0x1F23C, 0x1F23F, 0x1F249, 0x1F3FA,
            0x1F400, 0x1F53D, 0x1F546, 0x1F64F, 0x1F680, 0x1F6FF,
            0x1F774, 0x1F77F, 0x1F7D5, 0x1F7FF, 0x1F80C, 0x1F80F,
            0x1F848, 0x1F84F, 0x1F85A, 0x1F85F, 0x1F888, 0x1F88F,
            0x1F8AE, 0x1F8FF, 0x1F90C, 0x1F93A, 0x1F93C, 0x1F945,
            0x1F947, 0x1FAFF, 0x1FC00, 0x1FFFD
    };

    // ==================================================================
    // the two delegated steps
    // ==================================================================

    /** NFKC — {@code spec/07-fulltext.md} §2.2 step 2. */
    public static String nfkc(String s) {
        return java.text.Normalizer.normalize(s, java.text.Normalizer.Form.NFKC);
    }

    /**
     * {@code Simple_Lowercase_Mapping} — step 4, and one of the chapter's three
     * named traps.
     *
     * <p>Not {@code String.toLowerCase()}, which is locale-sensitive: with a
     * Turkish default locale it maps {@code I} to {@code ı}. And not full case
     * folding, which maps {@code ẞ} to {@code ss} where simple lowercasing maps
     * it to {@code ß}. {@code Character.toLowerCase(int)} is the simple,
     * locale-independent, one-to-one mapping the spec names.
     */
    public static String simpleLowercase(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> sb.appendCodePoint(Character.toLowerCase(cp)));
        return sb.toString();
    }

    /**
     * Step 3's keep test: a segment survives only if it holds at least one
     * character that is Alphabetic or has {@code Numeric_Type != None}.
     */
    public static boolean isWordLike(int[] cps) {
        for (int cp : cps) {
            if (Character.isAlphabetic(cp) || Character.getNumericValue(cp) >= 0
                    || Character.isDigit(cp)) {
                return true;
            }
        }
        return false;
    }
}
