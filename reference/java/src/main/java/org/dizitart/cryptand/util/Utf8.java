package org.dizitart.cryptand.util;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;

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
        // **The strict encoder is only needed when a surrogate is present.**
        //
        // `String.getBytes(UTF_8)` is intrinsified and allocates one array; the
        // `CharsetEncoder` path allocates an encoder, a `CharBuffer`, a
        // `ByteBuffer` and then the array — per string. A document carries
        // twenty of them, so this was by a wide margin the largest allocator on
        // the write path.
        //
        // The two differ on exactly one input class: `getBytes` substitutes
        // U+FFFD for an unpaired surrogate where this method must report it.
        // Ill-formed UTF-16 *requires* a surrogate code unit, so a string with
        // none cannot be malformed and the two agree byte for byte. Scanning
        // for one is a cheap pass over the chars with no allocation.
        if (!hasSurrogate(s)) {
            return s.getBytes(StandardCharsets.UTF_8);
        }
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

    /** Whether every byte is below 0x80, and so trivially valid UTF-8. */
    private static boolean isAscii(byte[] bytes, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            if (bytes[i] < 0) {
                return false;
            }
        }
        return true;
    }

    /** Whether any UTF-16 surrogate code unit appears — paired or not. */
    private static boolean hasSurrogate(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isSurrogate(s.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /** Decodes UTF-8, reporting corruption rather than substituting U+FFFD. */
    public static String decode(byte[] bytes, int offset, int length) {
        // The mirror of `encode`'s fast path. Pure ASCII is valid UTF-8 by
        // definition, so there is nothing for a strict decoder to reject, and
        // ISO-8859-1 maps those bytes one-to-one onto the same characters —
        // which the JDK stores as a Latin-1 `String` with no transcoding at
        // all. The strict `CharsetDecoder`, allocated per call along with its
        // buffers, is kept for everything else.
        if (isAscii(bytes, offset, length)) {
            return new String(bytes, offset, length, StandardCharsets.ISO_8859_1);
        }
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
