package org.dizitart.cryptand.util;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.container.Limits;

import java.util.Arrays;

/**
 * A bounds-checked little-endian byte source.
 *
 * <p>Every read is checked against the limit <em>before</em> it happens, and
 * every declared length is checked before it is used to allocate. That is
 * {@code spec/14-security.md} §9.1, which binds at every conformance level
 * whether or not the implementation supports encryption: opening a file another
 * party produced is what this format is for.
 */
public final class ByteReader {

    private final byte[] buf;
    private final int start;
    private final int limit;
    private int pos;

    public ByteReader(byte[] buf) {
        this(buf, 0, buf.length);
    }

    public ByteReader(byte[] buf, int offset, int length) {
        this.buf = buf;
        this.start = offset;
        // A window past the array (a short keyslot, F-106) ends at the array,
        // so reading past it is a typed truncation error, not an index error.
        this.limit = (int) Math.min((long) offset + length, buf.length);
        this.pos = offset;
    }

    /** Bytes consumed since the start of this reader's window. */
    public int consumed() {
        return pos - start;
    }

    public int remaining() {
        return limit - pos;
    }

    public boolean hasRemaining() {
        return pos < limit;
    }

    /** Absolute position in the backing array. */
    public int position() {
        return pos;
    }

    /** Absolute end of this reader's window in the backing array. */
    public int limit() {
        return limit;
    }

    /**
     * The backing array, for constructing a sub-reader over the same bytes
     * without copying. Callers must not mutate it — this is a view, and the
     * whole point of a lazy document read is that the bytes are not copied.
     */
    public byte[] bytesView() {
        return buf;
    }

    private void need(int n) {
        // `(long) pos + n`, not `pos + n`. An attacker-controlled length near
        // `Integer.MAX_VALUE` overflows the int addition to a negative number,
        // the check passes, and `Arrays.copyOfRange` throws
        // `OutOfMemoryError: Requested array size exceeds VM limit` — untyped,
        // which `14-security.md` §9.1 forbids: a hostile file must produce "a
        // typed corruption error rather than an allocation failure". The
        // structure-aware fuzzer reached it through `BtreePage.key`, which is
        // the path every segment cursor and the verifier take.
        if (n < 0 || (long) pos + n > limit) {
            throw new LimitException(
                    "truncated: need " + n + " byte(s) at offset " + (pos - start) + ", " + remaining() + " remain");
        }
    }

    public int u8() {
        need(1);
        return buf[pos++] & 0xFF;
    }

    /** Reads {@code n} raw bytes. The length is bounds-checked before allocating. */
    public byte[] bytes(int n) {
        need(n);
        byte[] out = Arrays.copyOfRange(buf, pos, pos + n);
        pos += n;
        return out;
    }

    /** Skips {@code n} bytes. */
    public void skip(int n) {
        need(n);
        pos += n;
    }

    // --- little-endian fixed width -------------------------------------

    public int u16() {
        need(2);
        return (buf[pos++] & 0xFF) | ((buf[pos++] & 0xFF) << 8);
    }

    public int u32() {
        need(4);
        return (buf[pos++] & 0xFF)
                | ((buf[pos++] & 0xFF) << 8)
                | ((buf[pos++] & 0xFF) << 16)
                | ((buf[pos++] & 0xFF) << 24);
    }

    public long u64() {
        need(8);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= (long) (buf[pos++] & 0xFF) << (8 * i);
        }
        return v;
    }

    public float f32() {
        return Float.intBitsToFloat(u32());
    }

    public double f64() {
        return Double.longBitsToDouble(u64());
    }

    // --- big-endian, CKE only ------------------------------------------

    public int u16be() {
        need(2);
        return ((buf[pos++] & 0xFF) << 8) | (buf[pos++] & 0xFF);
    }

    public int u32be() {
        need(4);
        int v = 0;
        for (int i = 0; i < 4; i++) {
            v = (v << 8) | (buf[pos++] & 0xFF);
        }
        return v;
    }

    public long u64be() {
        need(8);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (buf[pos++] & 0xFF);
        }
        return v;
    }

    // --- varints --------------------------------------------------------

    /**
     * LEB128 unsigned varint.
     *
     * <p>Rejects an encoding longer than ten bytes and a non-canonical one — a
     * final byte of {@code 0x80}, which encodes nothing and would let the same
     * number be written two ways. Canonicality matters because these bytes are
     * checksummed and compared: two spellings of one value are two different
     * files that mean the same thing.
     */
    public long uvar() {
        // Nearly every uvar in a page is one byte -- a cell suffix length, a
        // cell count, a name-dictionary index. The general loop below carries a
        // bounds check, an overflow test and a canonicality test per iteration,
        // and it was 22 % of the point-read profile.
        if (pos < limit() && (buf[pos] & 0x80) == 0) {
            return buf[pos++] & 0xFFL;
        }
        long v = 0;
        int shift = 0;
        for (int i = 0; i < Limits.MAX_UVAR_BYTES; i++) {
            int b = u8();
            if (i == Limits.MAX_UVAR_BYTES - 1 && (b & 0xFE) != 0) {
                // The tenth byte carries exactly one payload bit of a u64.
                throw new CorruptionException("uvar overflows 64 bits", null, (long) (pos - start - 1));
            }
            v |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                if (i > 0 && b == 0) {
                    throw new CorruptionException(
                            "non-canonical uvar: trailing zero continuation", null, (long) (pos - start - 1));
                }
                return v;
            }
            shift += 7;
        }
        throw new CorruptionException("uvar longer than " + Limits.MAX_UVAR_BYTES + " bytes", null,
                (long) (pos - start));
    }

    /**
     * A {@code uvar} that must fit a non-negative {@code int} and must not
     * exceed what remains. This is the one to use for every length read from a
     * file: it is the check that stops an attacker-chosen allocation.
     */
    public int uvarLength(String what) {
        long v = uvar();
        if (v < 0 || v > Integer.MAX_VALUE) {
            throw new LimitException(what + " length " + Long.toUnsignedString(v) + " exceeds addressable range");
        }
        if (v > remaining()) {
            throw new LimitException(
                    what + " length " + v + " exceeds the " + remaining() + " byte(s) remaining");
        }
        return (int) v;
    }

    /** Zigzag-then-LEB128 signed varint. */
    public long ivar() {
        long v = uvar();
        return (v >>> 1) ^ -(v & 1);
    }

    /** {@code uvar length} followed by that many bytes of strict UTF-8. */
    public String str() {
        int n = uvarLength("string");
        int at = pos;
        pos += n;
        return Utf8.decode(buf, at, n);
    }
}
