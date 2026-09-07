package org.dizitart.cryptand.util;

import java.util.Arrays;

/**
 * A growable little-endian byte sink. The primitives of
 * {@code spec/00-conventions.md} §4.
 *
 * <p>Little-endian everywhere except CKE, which is big-endian throughout and
 * has its own writers here ({@link #u16be}, {@link #u32be}, {@link #u64be}) so
 * that the one exception is visible at every call site.
 */
public final class ByteWriter {

    private byte[] buf;
    private int len;

    public ByteWriter() {
        this(64);
    }

    public ByteWriter(int initialCapacity) {
        this.buf = new byte[Math.max(8, initialCapacity)];
    }

    public int length() {
        return len;
    }

    private void ensure(int extra) {
        if (len + extra > buf.length) {
            int cap = buf.length;
            while (cap < len + extra) {
                cap <<= 1;
            }
            buf = Arrays.copyOf(buf, cap);
        }
    }

    public ByteWriter u8(int v) {
        ensure(1);
        buf[len++] = (byte) v;
        return this;
    }

    public ByteWriter bytes(byte[] b) {
        return bytes(b, 0, b.length);
    }

    public ByteWriter bytes(byte[] b, int off, int n) {
        ensure(n);
        System.arraycopy(b, off, buf, len, n);
        len += n;
        return this;
    }

    // --- little-endian fixed width -------------------------------------

    public ByteWriter u16(int v) {
        ensure(2);
        buf[len++] = (byte) v;
        buf[len++] = (byte) (v >>> 8);
        return this;
    }

    public ByteWriter u32(int v) {
        ensure(4);
        buf[len++] = (byte) v;
        buf[len++] = (byte) (v >>> 8);
        buf[len++] = (byte) (v >>> 16);
        buf[len++] = (byte) (v >>> 24);
        return this;
    }

    public ByteWriter u64(long v) {
        ensure(8);
        for (int i = 0; i < 8; i++) {
            buf[len++] = (byte) (v >>> (8 * i));
        }
        return this;
    }

    public ByteWriter f32(float v) {
        return u32(Float.floatToRawIntBits(v));
    }

    public ByteWriter f64(double v) {
        return u64(Double.doubleToRawLongBits(v));
    }

    // --- big-endian, CKE only ------------------------------------------

    public ByteWriter u16be(int v) {
        ensure(2);
        buf[len++] = (byte) (v >>> 8);
        buf[len++] = (byte) v;
        return this;
    }

    public ByteWriter u32be(int v) {
        ensure(4);
        for (int i = 3; i >= 0; i--) {
            buf[len++] = (byte) (v >>> (8 * i));
        }
        return this;
    }

    public ByteWriter u64be(long v) {
        ensure(8);
        for (int i = 7; i >= 0; i--) {
            buf[len++] = (byte) (v >>> (8 * i));
        }
        return this;
    }

    // --- varints --------------------------------------------------------

    /**
     * LEB128 unsigned varint, seven payload bits per byte, low bits first.
     *
     * <p>{@code v} is treated as unsigned 64-bit, so a negative {@code long}
     * encodes as its two's-complement bit pattern in ten bytes.
     */
    public ByteWriter uvar(long v) {
        while (Long.compareUnsigned(v, 0x80L) >= 0) {
            u8((int) (v & 0x7F) | 0x80);
            v >>>= 7;
        }
        return u8((int) v);
    }

    /** Zigzag-then-LEB128 signed varint. */
    public ByteWriter ivar(long v) {
        return uvar((v << 1) ^ (v >> 63));
    }

    /** {@code uvar length} followed by that many bytes of strict UTF-8. */
    public ByteWriter str(String s) {
        byte[] b = Utf8.encode(s);
        return uvar(b.length).bytes(b);
    }

    public byte[] toBytes() {
        return Arrays.copyOf(buf, len);
    }
}
