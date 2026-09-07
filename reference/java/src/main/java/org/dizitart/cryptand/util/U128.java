package org.dizitart.cryptand.util;

import org.dizitart.cryptand.InvalidArgumentException;

import java.math.BigInteger;

/**
 * An unsigned 128-bit integer as two {@code long} halves.
 *
 * <p>It exists because of one sentence in {@code spec/03-key-encoding.md} §4.1:
 * the CKE normalization "uses only shifts and a count-leading-zeros, and
 * requires no arbitrary-precision arithmetic in any language". {@link
 * BigInteger} would encode the same bytes, and this class is a demonstration
 * that it does not have to — the same demonstration the Dart and Rust
 * implementations make with their own two-half integers.
 *
 * <p>128 bits is not decorative. {@code |i128::MIN|} is 2<sup>127</sup>, which
 * needs the unsigned width, and {@code U128} is a CVE type in its own right.
 *
 * <p>{@link BigInteger} appears only at the edges — parsing a decimal string,
 * and handing a value to an application — never in the encoder.
 */
public final class U128 implements Comparable<U128> {

    public static final U128 ZERO = new U128(0, 0);

    private final long hi;
    private final long lo;

    public U128(long hi, long lo) {
        this.hi = hi;
        this.lo = lo;
    }

    /** The value of an unsigned 64-bit quantity. */
    public static U128 ofUnsigned(long v) {
        return new U128(0, v);
    }

    public long hi() {
        return hi;
    }

    public long lo() {
        return lo;
    }

    public boolean isZero() {
        return hi == 0 && lo == 0;
    }

    /** Whether the value fits in an unsigned 64-bit quantity. */
    public boolean fitsU64() {
        return hi == 0;
    }

    /** Number of leading zero bits, 0..128. */
    public int leadingZeros() {
        return hi == 0 ? 64 + Long.numberOfLeadingZeros(lo) : Long.numberOfLeadingZeros(hi);
    }

    /** Number of significant bits, 0..128. Zero has zero. */
    public int bitLength() {
        return 128 - leadingZeros();
    }

    /** Whether bit {@code i} (0 = least significant) is set. */
    public boolean bit(int i) {
        if (i < 0 || i >= 128) {
            return false;
        }
        return i < 64 ? ((lo >>> i) & 1) != 0 : ((hi >>> (i - 64)) & 1) != 0;
    }

    /** Whether every bit below {@code i} is zero. */
    public boolean lowBitsZero(int i) {
        if (i <= 0) {
            return true;
        }
        if (i >= 128) {
            return isZero();
        }
        if (i <= 64) {
            long mask = i == 64 ? -1L : ((1L << i) - 1);
            return (lo & mask) == 0;
        }
        long mask = (i - 64) == 64 ? -1L : ((1L << (i - 64)) - 1);
        return lo == 0 && (hi & mask) == 0;
    }

    public U128 shiftLeft(int n) {
        if (n <= 0) {
            return n == 0 ? this : shiftRight(-n);
        }
        if (n >= 128) {
            return ZERO;
        }
        if (n >= 64) {
            return new U128(lo << (n - 64), 0);
        }
        return new U128((hi << n) | (lo >>> (64 - n)), lo << n);
    }

    public U128 shiftRight(int n) {
        if (n <= 0) {
            return n == 0 ? this : shiftLeft(-n);
        }
        if (n >= 128) {
            return ZERO;
        }
        if (n >= 64) {
            return new U128(0, hi >>> (n - 64));
        }
        return new U128(hi >>> n, (lo >>> n) | (hi << (64 - n)));
    }

    /** Two's-complement negation, which is what {@code |i128::MIN|} needs. */
    public U128 negate() {
        long nlo = ~lo + 1;
        long nhi = ~hi + (nlo == 0 ? 1 : 0);
        return new U128(nhi, nlo);
    }

    /** Sixteen big-endian bytes. */
    public byte[] toBytesBE() {
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (hi >>> (56 - 8 * i));
            out[8 + i] = (byte) (lo >>> (56 - 8 * i));
        }
        return out;
    }

    /** Sixteen little-endian bytes, which is what CVE's {@code U128} payload is. */
    public byte[] toBytesLE() {
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (lo >>> (8 * i));
            out[8 + i] = (byte) (hi >>> (8 * i));
        }
        return out;
    }

    public static U128 fromBytesBE(byte[] b, int off) {
        long h = 0;
        long l = 0;
        for (int i = 0; i < 8; i++) {
            h = (h << 8) | (b[off + i] & 0xFFL);
        }
        for (int i = 0; i < 8; i++) {
            l = (l << 8) | (b[off + 8 + i] & 0xFFL);
        }
        return new U128(h, l);
    }

    public static U128 fromBytesLE(byte[] b, int off) {
        long h = 0;
        long l = 0;
        for (int i = 7; i >= 0; i--) {
            l = (l << 8) | (b[off + i] & 0xFFL);
        }
        for (int i = 7; i >= 0; i--) {
            h = (h << 8) | (b[off + 8 + i] & 0xFFL);
        }
        return new U128(h, l);
    }

    @Override
    public int compareTo(U128 other) {
        int c = Long.compareUnsigned(hi, other.hi);
        return c != 0 ? c : Long.compareUnsigned(lo, other.lo);
    }

    // --- the edges ------------------------------------------------------

    public BigInteger toBigInteger() {
        return new BigInteger(1, toBytesBE());
    }

    public static U128 fromBigInteger(BigInteger v) {
        if (v.signum() < 0 || v.bitLength() > 128) {
            throw new InvalidArgumentException("value does not fit an unsigned 128-bit integer: " + v);
        }
        byte[] be = v.toByteArray();
        byte[] padded = new byte[16];
        int n = Math.min(be.length, 16);
        System.arraycopy(be, be.length - n, padded, 16 - n, n);
        return fromBytesBE(padded, 0);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof U128 u && u.hi == hi && u.lo == lo;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(hi) * 31 + Long.hashCode(lo);
    }

    @Override
    public String toString() {
        return toBigInteger().toString();
    }
}
