package org.dizitart.cryptand;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The primitives of {@code spec/00-conventions.md} §4, §6 and §8. */
class PrimitivesTest {

    @Test
    @DisplayName("uvar round-trips, low bits first, seven bits per byte")
    void uvarRoundTrips() {
        long[] cases = {0, 1, 127, 128, 300, 16383, 16384, Integer.MAX_VALUE, Long.MAX_VALUE, -1};
        for (long v : cases) {
            byte[] b = new ByteWriter().uvar(v).toBytes();
            assertEquals(v, new ByteReader(b).uvar(), Long.toUnsignedString(v));
        }
        assertArrayEquals(new byte[]{0x00}, new ByteWriter().uvar(0).toBytes());
        assertArrayEquals(new byte[]{0x7F}, new ByteWriter().uvar(127).toBytes());
        assertArrayEquals(new byte[]{(byte) 0x80, 0x01}, new ByteWriter().uvar(128).toBytes());
        // -1 as unsigned is the ten-byte maximum.
        assertEquals(10, new ByteWriter().uvar(-1).toBytes().length);
    }

    /**
     * §4: "A decoder MUST reject an encoding longer than 10 bytes and MUST
     * reject a non-canonical encoding."
     *
     * <p>Canonicality is not pedantry here. These bytes are checksummed and
     * compared, so two spellings of one number are two different files that
     * mean the same thing — and a reader that accepts both cannot tell a
     * rewritten file from an identical one.
     */
    @Test
    @DisplayName("a non-canonical uvar is refused")
    void uvarCanonicality() {
        // 0x81 0x00 encodes 1, whose canonical spelling is the single byte 0x01.
        assertThrows(CorruptionException.class,
                () -> new ByteReader(new byte[]{(byte) 0x81, 0x00}).uvar());
        byte[] eleven = new byte[11];
        java.util.Arrays.fill(eleven, (byte) 0x80);
        eleven[10] = 0x01;
        assertThrows(CorruptionException.class, () -> new ByteReader(eleven).uvar());
    }

    @Test
    @DisplayName("ivar zigzags, so small negatives stay small")
    void ivarZigzag() {
        for (long v : new long[]{0, -1, 1, -2, 2, 63, -64, Long.MIN_VALUE, Long.MAX_VALUE}) {
            byte[] b = new ByteWriter().ivar(v).toBytes();
            assertEquals(v, new ByteReader(b).ivar(), Long.toString(v));
        }
        assertArrayEquals(new byte[]{0x02}, new ByteWriter().ivar(1).toBytes());
        assertArrayEquals(new byte[]{0x01}, new ByteWriter().ivar(-1).toBytes());
    }

    /**
     * §8: "A decoder MUST treat every length read from the file as untrusted:
     * it MUST bounds-check against the containing page or extent before
     * allocating."
     */
    @Test
    @DisplayName("a length past the buffer fails before allocating")
    void lengthsAreBoundsCheckedBeforeAllocating() {
        // 0xFFFFFF7F is uvar for 0x0FFFFFFF, ~268 MB, in a four-byte buffer.
        ByteReader r = new ByteReader(Vectors.hex("ffffff7f"));
        LimitException e = assertThrows(LimitException.class, () -> r.uvarLength("BYTES"));
        assertTrue(e.getMessage().contains("remaining"), e.getMessage());
    }

    @Test
    @DisplayName("an unpaired surrogate is refused on write and ill-formed UTF-8 on read")
    void strictUtf8() {
        assertThrows(InvalidArgumentException.class, () -> Utf8.encode("\ud800"));
        assertThrows(InvalidArgumentException.class, () -> Utf8.encode("\udc00"));
        // 0xC3 0x28 is a truncated two-byte sequence; it must not become U+FFFD.
        assertThrows(CorruptionException.class, () -> Utf8.decode(Vectors.hex("c328")));
        // A CESU-8 encoded surrogate is ill-formed UTF-8 too.
        assertThrows(CorruptionException.class, () -> Utf8.decode(Vectors.hex("eda080")));
        assertEquals("héllo", Utf8.decode("héllo".getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * RFC 3720's CRC-32C check value. The JDK supplies the algorithm; this
     * asserts that the parameters are the ones the spec names, because
     * "CRC-32" without them is four different functions.
     */
    @Test
    @DisplayName("CRC-32C matches the published check value")
    void crc32c() {
        byte[] zeros = new byte[32];
        assertEquals(0x8A9136AA, Crc32c.of(zeros));
        byte[] ones = new byte[32];
        java.util.Arrays.fill(ones, (byte) 0xFF);
        assertEquals(0x62A8AB43, Crc32c.of(ones));
    }

    /**
     * {@code spec/03-key-encoding.md} §4.1 leans on 128-bit shifts and a
     * count-leading-zeros and on nothing else. {@link BigInteger} is the oracle
     * here, not the implementation.
     */
    @Test
    @DisplayName("U128 shifts and bit lengths agree with BigInteger")
    void u128AgreesWithBigInteger() {
        BigInteger mask = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
        BigInteger[] samples = {
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.valueOf(5),
                BigInteger.valueOf(Long.MAX_VALUE),
                BigInteger.ONE.shiftLeft(63),
                BigInteger.ONE.shiftLeft(64),
                BigInteger.ONE.shiftLeft(127),
                mask,
        };
        for (BigInteger b : samples) {
            U128 u = U128.fromBigInteger(b);
            assertEquals(b, u.toBigInteger());
            assertEquals(b.bitLength(), u.bitLength(), b.toString());
            for (int s : new int[]{0, 1, 7, 63, 64, 65, 127, 128}) {
                assertEquals(b.shiftLeft(s).and(mask), u.shiftLeft(s).toBigInteger(),
                        b + " << " + s);
                assertEquals(b.shiftRight(s), u.shiftRight(s).toBigInteger(), b + " >> " + s);
            }
        }
    }

    /** {@code |i128::MIN|} is 2^127, which is exactly why the magnitude is unsigned. */
    @Test
    @DisplayName("the most negative i128 has a magnitude no signed 128-bit type can hold")
    void mostNegativeI128() {
        BigInteger min = BigInteger.ONE.shiftLeft(127).negate();
        Value.Int v = Vectors.integer(NumType.I128, min);
        assertEquals(BigInteger.ONE.shiftLeft(127), v.magnitude().toBigInteger());
        assertEquals(v, Cve.decode(Cve.encode(v)));
        assertEquals(v, Cke.decode(Cke.encode(v)));
    }
}
