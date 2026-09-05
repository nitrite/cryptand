package org.dizitart.cryptand;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * CKE, the Cryptand Ordered Key Encoding — {@code spec/03-key-encoding.md}.
 *
 * <p>One invariant defines this class. Writing {@code L} for the logical
 * comparison of {@code spec/02-value-encoding.md} §8 and {@code M} for
 * {@code memcmp(CKE(a), CKE(b))}:
 *
 * <ol>
 *   <li>if {@code L != 0} then {@code M} has the same sign as {@code L}; and
 *   <li>if {@code L == 0} then either the keys are equal, or {@code a} and
 *       {@code b} are numerically equal values of different declared types
 *       whose keys differ <em>only</em> in the trailing type code of §4.3.
 * </ol>
 *
 * <p>Clause 2 is the entire purpose of the type code, not a caveat: it is what
 * lets an exact-type point lookup stay a point lookup while {@code eq(5)}
 * across every numeric type stays one range scan. A plain "same sign as" would
 * be false, and demonstrably so — {@code I8(0)} and {@code I16(0)} compare
 * equal logically and encode as {@code 30 02 00} and {@code 30 02 01}.
 *
 * <p>That property is what makes a Cryptand file mean the same thing in every
 * language: no implementation ever calls a host comparator ({@code Comparable},
 * {@code Ord}, {@code compareTo}) to navigate the tree. The bytes decide.
 *
 * <p><strong>All multi-byte integers here are big-endian.</strong> This is the
 * only part of the format where that is true, which is why {@link ByteWriter}
 * and {@link ByteReader} spell the big-endian primitives differently.
 */
public final class Cke {

    private Cke() {
    }

    /**
     * Group tags, §2. Spaced by {@code 0x10} so a future group can be inserted
     * without renumbering — though a <em>new</em> group is a major-version
     * change regardless, because it moves the cross-type order.
     */
    public static final class Group {
        private Group() {
        }

        public static final int NULL = 0x00;
        public static final int BOOL = 0x10;
        public static final int NUMBER = 0x30;
        public static final int TEMPORAL = 0x40;
        public static final int CHAR = 0x50;
        public static final int STRING = 0x60;
        public static final int BYTES = 0x70;
        public static final int NITRITE_ID = 0x80;
        public static final int UUID = 0x90;
        public static final int ARRAY = 0xA0;

        /**
         * Never emitted. Reserved so that a run of {@code 0xFF} is above every
         * valid key, which {@link #successor} relies on.
         */
        public static final int FORBIDDEN = 0xFF;
    }

    /** NUMBER sign classes, §4. These are ordered, and the order is the point. */
    public static final class SignClass {
        private SignClass() {
        }

        public static final int NEG_INFINITY = 0x00;
        public static final int NEG_FINITE = 0x01;
        public static final int ZERO = 0x02;
        public static final int POS_FINITE = 0x03;
        public static final int POS_INFINITY = 0x04;
        public static final int NAN = 0x05;
    }

    /** TEMPORAL subclasses, §5. */
    public static final class TemporalClass {
        private TemporalClass() {
        }

        /**
         * Every instant-valued CVE tag canonicalizes here — {@code TIMESTAMP},
         * {@code TIMESTAMP_NS} and {@code ZONED} alike — so two values denoting
         * the same instant are one key.
         */
        public static final int INSTANT = 0x01;

        /**
         * Reserved, and MUST NOT be written. An earlier draft split millisecond
         * and nanosecond instants across {@code 0x01} and {@code 0x02}, which
         * made the subclass byte order by <em>precision</em> instead of by
         * instant: a {@code TIMESTAMP} of 2000 ms sorted below a
         * {@code TIMESTAMP_NS} of 1 s.
         */
        public static final int RESERVED_WAS_INSTANT_NS = 0x02;

        public static final int DATE = 0x03;
        public static final int TIME = 0x04;
        public static final int DURATION = 0x05;
    }

    private static final int ELEM_CONTINUE = 0x01;
    private static final int ELEM_END = 0x00;
    private static final long SIGN_BIT_64 = Long.MIN_VALUE;
    private static final int EXPONENT_BIAS = 16384;

    /** An open upper bound. Not a byte string — this is why tag {@code 0xFF} is reserved. */
    public static final byte[] UNBOUNDED_ABOVE = null;

    /** Below every key, and needs no sentinel: the empty byte string. */
    public static final byte[] UNBOUNDED_BELOW = new byte[0];

    // ==================================================================
    // escaping, §3.1
    // ==================================================================

    /**
     * {@code esc(s)} — the self-delimiting, order-preserving byte-string
     * encoding. The terminator {@code 00 00} is below every escaped
     * continuation {@code 00 01}, so a shorter string sorts before a longer one
     * that extends it: {@code "ab" < "abc"}.
     */
    static void writeEsc(ByteWriter w, byte[] s) {
        writeEscOpen(w, s);
        w.u8(0x00).u8(0x00);
    }

    /**
     * {@code esc_open(s)} — {@link #writeEsc} without the terminator: the
     * shared prefix of every byte string beginning with {@code s}. This is §8's
     * {@code starts_with}.
     */
    static void writeEscOpen(ByteWriter w, byte[] s) {
        for (byte b : s) {
            if (b == 0x00) {
                w.u8(0x00).u8(0x01);
            } else {
                w.u8(b & 0xFF);
            }
        }
    }

    /** Reads an {@code esc}-encoded byte string. */
    static byte[] readEsc(ByteReader r) {
        ByteWriter out = new ByteWriter();
        while (true) {
            int b = r.u8();
            if (b != 0x00) {
                out.u8(b);
                continue;
            }
            int n = r.u8();
            if (n == 0x00) {
                return out.toBytes();
            }
            if (n == 0x01) {
                out.u8(0x00);
                continue;
            }
            throw new CorruptionException("non-canonical CKE escape", null, (long) (r.consumed() - 1));
        }
    }

    /**
     * Reads a complemented {@code esc} stream, inverting each byte as it goes.
     *
     * <p>A negative number's ordering region is the positive body with every
     * byte inverted, so its escape character is {@code 0xFF} and its
     * continuation marker {@code 0xFE}. Inverting on the way in lets one set of
     * rules describe both.
     */
    static byte[] readEscInverted(ByteReader r) {
        ByteWriter out = new ByteWriter();
        while (true) {
            int b = (~r.u8()) & 0xFF;
            if (b != 0x00) {
                out.u8(b);
                continue;
            }
            int n = (~r.u8()) & 0xFF;
            if (n == 0x00) {
                return out.toBytes();
            }
            if (n == 0x01) {
                out.u8(0x00);
                continue;
            }
            throw new CorruptionException(
                    "non-canonical complemented CKE escape", null, (long) (r.consumed() - 1));
        }
    }

    // ==================================================================
    // NUMBER normalization, §4.1
    // ==================================================================

    /** The exact pair {@code (e, m)} with {@code |v| = m × 2^e} and {@code 1 ≤ m < 2}. */
    record Normalized(int e, U128 m) {
    }

    /**
     * §4.1, integer path:
     * {@code n = 128 - leading_zeros(u); e = n - 1; m = u << (128 - n)}.
     */
    static Normalized normalizeMagnitude(U128 u) {
        if (u.isZero()) {
            throw new InvalidArgumentException("zero has no (e, m) form");
        }
        int n = u.bitLength();
        return new Normalized(n - 1, u.shiftLeft(128 - n));
    }

    /** §4.1, binary64 path. {@code bits} is the raw IEEE 754 pattern of {@code |v|}. */
    static Normalized normalizeF64(long bits) {
        int biasedExp = (int) ((bits >>> 52) & 0x7FF);
        long frac = bits & 0xFFFFFFFFFFFFFL;
        int e;
        long sig;
        if (biasedExp != 0) {
            sig = (1L << 52) | frac;
            e = biasedExp - 1023;
        } else {
            // Subnormal: shift the fraction up until its implicit bit is at 52.
            int k = 52 - (63 - Long.numberOfLeadingZeros(frac));
            sig = frac << k;
            e = -1022 - k;
        }
        return new Normalized(e, U128.ofUnsigned(sig).shiftLeft(128 - 53));
    }

    /** §4.1, binary32 path. */
    static Normalized normalizeF32(int bits) {
        int biasedExp = (bits >>> 23) & 0xFF;
        long frac = bits & 0x7FFFFF;
        int e;
        long sig;
        if (biasedExp != 0) {
            sig = (1L << 23) | frac;
            e = biasedExp - 127;
        } else {
            int k = 23 - (63 - Long.numberOfLeadingZeros(frac));
            sig = frac << k;
            e = -126 - k;
        }
        return new Normalized(e, U128.ofUnsigned(sig).shiftLeft(128 - 24));
    }

    /**
     * §4.2: {@code u16be(e + 16384) || esc(mbytes)}, where {@code mbytes} is the
     * sixteen bytes of {@code m} with trailing zero bytes removed.
     *
     * <p>{@code mbytes} is never empty and its first byte is always at least
     * {@code 0x80}, because bit 127 of {@code m} is its integer bit.
     */
    static byte[] numberBody(Normalized n) {
        byte[] full = n.m().toBytesBE();
        int end = full.length;
        while (end > 1 && full[end - 1] == 0x00) {
            end--;
        }
        int biased = n.e() + EXPONENT_BIAS;
        if (biased < 0 || biased > 0xFFFF) {
            throw new InvalidArgumentException("binary exponent " + n.e() + " outside CKE range");
        }
        ByteWriter w = new ByteWriter(end + 6);
        w.u16be(biased);
        writeEsc(w, Arrays.copyOf(full, end));
        return w.toBytes();
    }

    /**
     * §4.2: a negative's ordering region is the positive body with every byte
     * inverted. Inverting a byte string reverses its lexicographic order, which
     * is exactly what negatives need — a larger magnitude must sort lower.
     */
    static byte[] complement(byte[] b) {
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) {
            out[i] = (byte) ~b[i];
        }
        return out;
    }

    // ==================================================================
    // encoding
    // ==================================================================

    /**
     * Whether {@code v} has a CKE encoding at all.
     *
     * <p>§2: {@code DOC}, {@code MAP}, {@code VECTOR}, {@code GEOMETRY},
     * {@code REGEX}, {@code OPAQUE}, {@code DEC128} and the three indirection
     * tags have none, and using one as a key is an error rather than a silent
     * no-op.
     */
    public static boolean isKeyEncodable(Value v) {
        if (v instanceof Value.Int i) {
            return i.type().isKeyEncodable();
        }
        if (v instanceof Value.Array a) {
            return a.items().stream().allMatch(Cke::isKeyEncodable);
        }
        return v instanceof Value.Null
                || v instanceof Value.Bool
                || v instanceof Value.Float
                || v instanceof Value.Char
                || v instanceof Value.Str
                || v instanceof Value.Bytes
                || v instanceof Value.Timestamp
                || v instanceof Value.TimestampNs
                || v instanceof Value.Zoned
                || v instanceof Value.Date
                || v instanceof Value.Time
                || v instanceof Value.Duration
                || v instanceof Value.Uuid
                || v instanceof Value.NitriteId;
    }

    public static byte[] encode(Value v) {
        ByteWriter w = new ByteWriter(32);
        write(w, v, 0);
        return w.toBytes();
    }

    static void write(ByteWriter w, Value v, int depth) {
        if (depth > Limits.MAX_DEPTH) {
            throw new LimitException("CKE nesting deeper than " + Limits.MAX_DEPTH);
        }
        if (v instanceof Value.Null) {
            w.u8(Group.NULL);
        } else if (v instanceof Value.Bool b) {
            w.u8(Group.BOOL).u8(b.value() ? 0x01 : 0x00);
        } else if (v instanceof Value.Int i) {
            writeInt(w, i);
        } else if (v instanceof Value.Float f) {
            writeFloat(w, f);
        } else if (v instanceof Value.Char c) {
            w.u8(Group.CHAR).u32be(c.scalar());
        } else if (v instanceof Value.Str s) {
            w.u8(Group.STRING);
            writeEsc(w, Utf8.encode(s.value()));
        } else if (v instanceof Value.Bytes b) {
            w.u8(Group.BYTES);
            writeEsc(w, b.value());
        } else if (v instanceof Value.NitriteId n) {
            // The XOR flips the sign bit so a signed i64 sorts correctly as
            // unsigned bytes. Snowflake ids are positive in practice, but
            // NitriteId accepts any i64 and the format must not depend on
            // application discipline.
            w.u8(Group.NITRITE_ID).u64be(n.id() ^ SIGN_BIT_64);
        } else if (v instanceof Value.Uuid u) {
            w.u8(Group.UUID).bytes(u.bytes());
        } else if (v instanceof Value.Timestamp t) {
            writeInstant(w, millisToSecs(t.millis()), millisToNanos(t.millis()));
        } else if (v instanceof Value.TimestampNs t) {
            writeInstant(w, t.secs(), t.nanos());
        } else if (v instanceof Value.Zoned z) {
            // §5: the zone id is not part of the key.
            writeInstant(w, millisToSecs(z.millis()), millisToNanos(z.millis()));
        } else if (v instanceof Value.Date d) {
            w.u8(Group.TEMPORAL).u8(TemporalClass.DATE).u32be(d.days() ^ 0x80000000);
        } else if (v instanceof Value.Time t) {
            w.u8(Group.TEMPORAL).u8(TemporalClass.TIME).u64be(t.nanos());
        } else if (v instanceof Value.Duration d) {
            w.u8(Group.TEMPORAL).u8(TemporalClass.DURATION).u64be(d.secs() ^ SIGN_BIT_64).u32be(d.nanos());
        } else if (v instanceof Value.Array a) {
            w.u8(Group.ARRAY);
            for (Value e : a.items()) {
                w.u8(ELEM_CONTINUE);
                write(w, e, depth + 1);
            }
            // ELEM_END is below ELEM_CONTINUE, so [a] < [a, b].
            w.u8(ELEM_END);
        } else if (v instanceof Value.Dec128) {
            throw new InvalidArgumentException(
                    "DEC128 has no CKE encoding and cannot be a key (spec/03-key-encoding.md §4.4): "
                            + "a decimal fraction has no exact binary m x 2^e form");
        } else {
            throw new InvalidArgumentException(v.getClass().getSimpleName()
                    + " has no CKE encoding and cannot be a key (spec/03-key-encoding.md §2)");
        }
    }

    /**
     * §5: {@code TIMESTAMP} canonicalizes with <strong>floor</strong> division,
     * not truncation, so instants before the epoch normalize correctly:
     * {@code -1 ms} is {@code (secs = -1, nanos = 999_000_000)}.
     */
    static long millisToSecs(long millis) {
        return Math.floorDiv(millis, 1000L);
    }

    static int millisToNanos(long millis) {
        return (int) (Math.floorMod(millis, 1000L) * 1_000_000L);
    }

    private static void writeInstant(ByteWriter w, long secs, int nanos) {
        w.u8(Group.TEMPORAL).u8(TemporalClass.INSTANT).u64be(secs ^ SIGN_BIT_64).u32be(nanos);
    }

    private static void writeInt(ByteWriter w, Value.Int v) {
        w.u8(Group.NUMBER);
        if (v.isZero()) {
            w.u8(SignClass.ZERO).u8(v.type().ckeCode());
            return;
        }
        byte[] body = numberBody(normalizeMagnitude(v.magnitude()));
        if (v.negative()) {
            w.u8(SignClass.NEG_FINITE).bytes(complement(body));
        } else {
            w.u8(SignClass.POS_FINITE).bytes(body);
        }
        w.u8(v.type().ckeCode());
    }

    private static void writeFloat(ByteWriter w, Value.Float v) {
        w.u8(Group.NUMBER);
        double d = v.value();
        int code = v.type().ckeCode();
        if (Double.isNaN(d)) {
            // §8 rule 3: all NaNs are equal, so a NaN key is findable. The
            // payload is not preserved; that is one of the three lossy cases.
            w.u8(SignClass.NAN).u8(code);
            return;
        }
        if (Double.isInfinite(d)) {
            w.u8(d > 0 ? SignClass.POS_INFINITY : SignClass.NEG_INFINITY).u8(code);
            return;
        }
        if (d == 0.0) {
            // §8 rule 3: -0.0 equals +0.0 and they sort equal, so they are one
            // key. A sign class separating them would put a value strictly
            // between two equal values.
            w.u8(SignClass.ZERO).u8(code);
            return;
        }
        boolean negative = d < 0;
        double mag = Math.abs(d);
        Normalized n = v.type() == NumType.F32
                ? normalizeF32(Float.floatToRawIntBits((float) mag))
                : normalizeF64(Double.doubleToRawLongBits(mag));
        byte[] body = numberBody(n);
        if (negative) {
            w.u8(SignClass.NEG_FINITE).bytes(complement(body));
        } else {
            w.u8(SignClass.POS_FINITE).bytes(body);
        }
        w.u8(code);
    }

    // ==================================================================
    // decoding, §7
    // ==================================================================

    /** Decodes a whole key and asserts nothing follows it. */
    public static Value decode(byte[] bytes) {
        ByteReader r = new ByteReader(bytes);
        Value v = read(r, 0);
        if (r.hasRemaining()) {
            throw new CorruptionException(r.remaining() + " trailing byte(s) after CKE key");
        }
        return v;
    }

    /**
     * Reads one CKE key from {@code r}.
     *
     * <p>Two groups do not round-trip to the exact source tag, by design.
     * {@code TEMPORAL/INSTANT} always decodes to {@link Value.TimestampNs}
     * whatever instant-valued tag produced it, and a {@code ZONED} key has lost
     * its zone. §7 states this; it is the price of two values denoting the same
     * instant being one key, without which an index on a timestamp field could
     * not answer an instant query.
     */
    static Value read(ByteReader r, int depth) {
        if (depth > Limits.MAX_DEPTH) {
            throw new LimitException("CKE nesting deeper than " + Limits.MAX_DEPTH);
        }
        int tag = r.u8();
        switch (tag) {
            case Group.NULL:
                return Value.NULL;
            case Group.BOOL: {
                int b = r.u8();
                if (b > 1) {
                    throw new CorruptionException("CKE bool body is not 0 or 1");
                }
                return b == 1 ? Value.TRUE : Value.FALSE;
            }
            case Group.NUMBER:
                return readNumber(r);
            case Group.TEMPORAL:
                return readTemporal(r);
            case Group.CHAR:
                return new Value.Char(r.u32be());
            case Group.STRING:
                return new Value.Str(Utf8.decode(readEsc(r)));
            case Group.BYTES:
                return new Value.Bytes(readEsc(r));
            case Group.NITRITE_ID:
                return new Value.NitriteId(r.u64be() ^ SIGN_BIT_64);
            case Group.UUID:
                return new Value.Uuid(r.bytes(16));
            case Group.ARRAY: {
                List<Value> items = new ArrayList<>();
                while (true) {
                    int marker = r.u8();
                    if (marker == ELEM_END) {
                        return new Value.Array(items);
                    }
                    if (marker != ELEM_CONTINUE) {
                        throw new CorruptionException(
                                "CKE array marker 0x" + Integer.toHexString(marker) + " is not 0x00 or 0x01");
                    }
                    items.add(read(r, depth + 1));
                }
            }
            default:
                throw new CorruptionException("unknown CKE group tag 0x" + Integer.toHexString(tag));
        }
    }

    private static NumType numTypeFromCke(int code) {
        NumType t = NumType.byCkeCode(code);
        if (t == null) {
            throw new CorruptionException("unknown CKE numeric type code 0x" + Integer.toHexString(code)
                    + (code == 0x0D ? " (0x0D is reserved: DEC128 is not a key)" : ""));
        }
        return t;
    }

    private static Value readNumber(ByteReader r) {
        int sign = r.u8();
        switch (sign) {
            case SignClass.ZERO: {
                NumType t = numTypeFromCke(r.u8());
                return t.isFloat() ? new Value.Float(t, 0.0) : new Value.Int(t, false, U128.ZERO);
            }
            case SignClass.NAN: {
                NumType t = numTypeFromCke(r.u8());
                if (!t.isFloat()) {
                    throw new CorruptionException("NaN with an integer type code");
                }
                return new Value.Float(t, Double.NaN);
            }
            case SignClass.POS_INFINITY:
            case SignClass.NEG_INFINITY: {
                NumType t = numTypeFromCke(r.u8());
                if (!t.isFloat()) {
                    throw new CorruptionException("infinity with an integer type code");
                }
                return new Value.Float(t,
                        sign == SignClass.POS_INFINITY ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY);
            }
            case SignClass.POS_FINITE:
            case SignClass.NEG_FINITE: {
                boolean negative = sign == SignClass.NEG_FINITE;
                int biased;
                byte[] mbytes;
                if (negative) {
                    biased = ((~r.u8() & 0xFF) << 8) | (~r.u8() & 0xFF);
                    mbytes = readEscInverted(r);
                } else {
                    biased = r.u16be();
                    mbytes = readEsc(r);
                }
                // §7: "A decoder MUST reject ... a mantissa whose first byte is
                // below 0x80, and an empty mantissa."
                if (mbytes.length == 0) {
                    throw new CorruptionException("empty CKE mantissa");
                }
                if ((mbytes[0] & 0xFF) < 0x80) {
                    throw new CorruptionException("CKE mantissa is not MSB-aligned (first byte below 0x80)");
                }
                if (mbytes.length > 16) {
                    throw new CorruptionException("CKE mantissa longer than 16 bytes");
                }
                U128 m = U128.fromBytesBE(Arrays.copyOf(mbytes, 16), 0);
                int e = biased - EXPONENT_BIAS;
                NumType t = numTypeFromCke(r.u8());
                return rebuild(t, negative, e, m);
            }
            default:
                throw new CorruptionException("unknown CKE sign class 0x" + Integer.toHexString(sign));
        }
    }

    /** Rebuilds a value from {@code (type, sign, e, m)} — the exact inverse of §4.1. */
    private static Value rebuild(NumType t, boolean negative, int e, U128 m) {
        if (t.isFloat()) {
            return new Value.Float(t, rebuildFloat(t, negative, e, m));
        }
        // Integer: u = m >> (127 - e), which inverts m = u << (128 - n), e = n - 1.
        if (e < 0 || e > 127) {
            throw new CorruptionException("binary exponent " + e + " cannot be an integer of " + t);
        }
        U128 u = m.shiftRight(127 - e);
        if (!u.shiftLeft(127 - e).equals(m)) {
            // §7: "m x 2^e is a ratio, so a region encoding 1.5 is well-formed;
            // only the type code says it must be a whole number." Truncating or
            // rounding would return a value no writer ever encoded, and two
            // decoders that chose differently would disagree about what the
            // same bytes mean.
            throw new CorruptionException("CKE integer mantissa has a fractional part");
        }
        try {
            return new Value.Int(t, negative, u);
        } catch (InvalidArgumentException ex) {
            // A well-formed region whose exponent exceeds the declared width.
            throw new CorruptionException(ex.getMessage());
        }
    }

    private static double rebuildFloat(NumType t, boolean negative, int e, U128 m) {
        if (t == NumType.F64) {
            long sig = m.shiftRight(128 - 53).lo();
            long bits;
            if (e >= -1022) {
                if (e > 1023) {
                    throw new CorruptionException("f64 exponent " + e + " out of range");
                }
                bits = ((long) (e + 1023) << 52) | (sig & 0xFFFFFFFFFFFFFL);
            } else {
                int k = -1022 - e;
                if (k > 52) {
                    throw new CorruptionException("f64 exponent " + e + " below subnormal");
                }
                bits = sig >>> k;
            }
            if (negative) {
                bits |= SIGN_BIT_64;
            }
            return Double.longBitsToDouble(bits);
        }
        long sig = m.shiftRight(128 - 24).lo();
        int bits;
        if (e >= -126) {
            if (e > 127) {
                throw new CorruptionException("f32 exponent " + e + " out of range");
            }
            bits = ((e + 127) << 23) | (int) (sig & 0x7FFFFF);
        } else {
            int k = -126 - e;
            if (k > 23) {
                throw new CorruptionException("f32 exponent " + e + " below subnormal");
            }
            bits = (int) (sig >>> k);
        }
        if (negative) {
            bits |= 0x80000000;
        }
        return Float.intBitsToFloat(bits);
    }

    private static Value readTemporal(ByteReader r) {
        int sub = r.u8();
        switch (sub) {
            case TemporalClass.INSTANT: {
                long secs = r.u64be() ^ SIGN_BIT_64;
                int nanos = r.u32be();
                if (nanos < 0 || nanos > 999_999_999) {
                    throw new CorruptionException("instant nanos " + Integer.toUnsignedString(nanos) + " out of range");
                }
                return new Value.TimestampNs(secs, nanos);
            }
            case TemporalClass.DATE:
                // days is an i32 and u32be yields 0..2^32-1, so the XOR result
                // is taken as a signed int directly.
                return new Value.Date(r.u32be() ^ 0x80000000);
            case TemporalClass.TIME:
                return new Value.Time(r.u64be());
            case TemporalClass.DURATION: {
                long secs = r.u64be() ^ SIGN_BIT_64;
                int nanos = r.u32be();
                if (nanos < 0 || nanos > 999_999_999) {
                    throw new CorruptionException("duration nanos " + Integer.toUnsignedString(nanos) + " out of range");
                }
                return new Value.Duration(secs, nanos);
            }
            case TemporalClass.RESERVED_WAS_INSTANT_NS:
                throw new CorruptionException("CKE temporal subclass 0x02 is reserved and MUST NOT be written "
                        + "(spec/03-key-encoding.md §5)");
            default:
                throw new CorruptionException("unknown CKE temporal subclass 0x" + Integer.toHexString(sub));
        }
    }

    // ==================================================================
    // comparison and range construction, §8
    // ==================================================================

    /**
     * Unsigned lexicographic byte comparison — {@code memcmp}. This <em>is</em>
     * the logical order, which is the whole point of the encoding.
     */
    public static int compare(byte[] a, byte[] b) {
        return Arrays.compareUnsigned(a, b);
    }

    /**
     * {@code successor(k)} — the least byte string greater than every string
     * having {@code k} as a prefix.
     *
     * <p>Returns {@link #UNBOUNDED_ABOVE} ({@code null}) when {@code k} is all
     * {@code 0xFF} bytes, which no valid key is: tag {@code 0xFF} is reserved
     * precisely so that this case cannot arise from a real key.
     */
    public static byte[] successor(byte[] k) {
        int end = k.length;
        while (end > 0 && (k[end - 1] & 0xFF) == 0xFF) {
            end--;
        }
        if (end == 0) {
            return UNBOUNDED_ABOVE;
        }
        byte[] out = Arrays.copyOf(k, end);
        out[end - 1]++;
        return out;
    }

    /**
     * {@code N(v)} — the NUMBER encoding of a numeric {@code v} with the type
     * code removed: the shared prefix of every numeric type equal to {@code v}.
     *
     * <p><strong>A numeric comparison MUST be built from this, never from
     * {@link #encode}.</strong> Every numeric tag is one ordered domain, so a
     * bound carrying a type code cuts the domain in the middle of a group of
     * numerically equal keys: {@code field > 5} built from {@code CKE(I32(5))}
     * would include {@code U8(5)} and {@code F64(5.0)}, and {@code field >= 5}
     * would miss {@code I8(5)} and {@code I16(5)}.
     */
    public static byte[] numericPrefix(Value v) {
        if (!(v instanceof Value.Int) && !(v instanceof Value.Float)) {
            throw new InvalidArgumentException("N(v) is defined for numeric values only, got " + v);
        }
        byte[] full = encode(v);
        return Arrays.copyOf(full, full.length - 1);
    }

    /**
     * {@code prefix_of_array(p1 … pk)} — the shared prefix of every
     * {@code ARRAY} key whose first {@code k} elements are {@code p1 … pk}.
     */
    public static byte[] prefixOfArray(List<Value> prefix) {
        ByteWriter w = new ByteWriter(32);
        w.u8(Group.ARRAY);
        for (Value p : prefix) {
            w.u8(ELEM_CONTINUE);
            write(w, p, 1);
        }
        return w.toBytes();
    }

    /**
     * {@code array_prefix_numeric(p1 … pk)} — {@link #prefixOfArray}, but the
     * last element is left type-agnostic.
     *
     * <p>This is what makes "one numeric domain" reachable on an actual index.
     * Without it, an index on a numeric field answers {@code eq(5)} only for
     * the exact type that was written — the divergence CKE exists to remove.
     */
    public static byte[] arrayPrefixNumeric(List<Value> prefix) {
        if (prefix.isEmpty()) {
            throw new InvalidArgumentException("array_prefix_numeric needs at least one element");
        }
        ByteWriter w = new ByteWriter(32);
        w.u8(Group.ARRAY);
        for (int i = 0; i < prefix.size() - 1; i++) {
            w.u8(ELEM_CONTINUE);
            write(w, prefix.get(i), 1);
        }
        w.u8(ELEM_CONTINUE);
        w.bytes(numericPrefix(prefix.get(prefix.size() - 1)));
        return w.toBytes();
    }

    /**
     * The lower bound of a {@code starts_with} scan on a string:
     * {@code 0x60 || esc_open(s)}.
     */
    public static byte[] stringPrefix(String s) {
        ByteWriter w = new ByteWriter(16);
        w.u8(Group.STRING);
        writeEscOpen(w, Utf8.encode(s));
        return w.toBytes();
    }
}
