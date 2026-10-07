package org.dizitart.cryptand.util;

/** Lowercase hex, for messages and test vectors ({@code java.util.HexFormat} is Java 17). */
public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String format(byte[] b) {
        return format(b, 0, b.length);
    }

    public static String format(byte[] b, int from, int to) {
        StringBuilder sb = new StringBuilder((to - from) * 2);
        for (int i = from; i < to; i++) {
            sb.append(DIGITS[(b[i] >> 4) & 0xF]).append(DIGITS[b[i] & 0xF]);
        }
        return sb.toString();
    }

    public static byte[] parse(String s) {
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd-length hex string");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("not hex: " + s);
            }
            out[i] = (byte) (hi << 4 | lo);
        }
        return out;
    }
}
