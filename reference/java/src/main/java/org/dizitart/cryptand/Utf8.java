package org.dizitart.cryptand;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Strict UTF-8, as {@code spec/00-conventions.md} §4 requires.
 *
 * <p>Neither direction may be done with the convenient JDK call.
 * {@code new String(bytes, UTF_8)} substitutes U+FFFD for ill-formed input and
 * {@code String.getBytes(UTF_8)} substitutes '?' for an unpaired surrogate;
 * both are silent, and the spec forbids exactly that:
 *
 * <blockquote>Unpaired surrogates MUST be rejected on write. A reader
 * encountering ill-formed UTF-8 MUST report corruption; it MUST NOT substitute
 * replacement characters silently.</blockquote>
 *
 * <p>Silent substitution is worse here than a thrown error, because it changes
 * a key's bytes: two SDKs that substitute differently place the same logical
 * string at two different points in the tree.
 */
public final class Utf8 {

    private Utf8() {
    }

    /** Encodes to UTF-8, rejecting unpaired surrogates rather than substituting. */
    public static byte[] encode(String s) {
        CharsetEncoder enc = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            ByteBuffer out = enc.encode(CharBuffer.wrap(s));
            byte[] bytes = new byte[out.remaining()];
            out.get(bytes);
            return bytes;
        } catch (CharacterCodingException e) {
            throw new InvalidArgumentException("string is not encodable as UTF-8: " + e.getMessage());
        }
    }

    /** Decodes UTF-8, reporting corruption rather than substituting U+FFFD. */
    public static String decode(byte[] bytes, int offset, int length) {
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return dec.decode(ByteBuffer.wrap(bytes, offset, length)).toString();
        } catch (CharacterCodingException e) {
            throw new CorruptionException("ill-formed UTF-8: " + e.getMessage(), null, (long) offset);
        }
    }

    public static String decode(byte[] bytes) {
        return decode(bytes, 0, bytes.length);
    }
}
