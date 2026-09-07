package org.dizitart.cryptand.value;

import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.geom.Geometry;
import org.dizitart.cryptand.text.Unicode;
import org.dizitart.cryptand.util.Tag;
import org.dizitart.cryptand.util.U128;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * The Cryptand value model — one variant per CVE type tag of
 * {@code spec/02-value-encoding.md} §1.
 *
 * <p>Sealed, so that every encoder, comparator and key builder in this library
 * is a switch the compiler checks for exhaustiveness. A new type added to the
 * format breaks the build in every place that must learn about it, which is the
 * behaviour you want from a byte-level contract implemented three times.
 *
 * <p>Byte-array components are copied on the way in and on the way out. A
 * "value" whose bytes a caller can mutate after it has been used as a key is
 * not a value.
 */
public sealed interface Value {

    /** The CVE type tag this value encodes as. */
    int tag();

    // ------------------------------------------------------------------
    // scalars
    // ------------------------------------------------------------------

    Null NULL = new Null();
    Bool TRUE = new Bool(true);
    Bool FALSE = new Bool(false);

    record Null() implements Value {
        @Override
        public int tag() {
            return Tag.NULL;
        }

        @Override
        public String toString() {
            return "null";
        }
    }

    record Bool(boolean value) implements Value {
        @Override
        public int tag() {
            return value ? Tag.TRUE : Tag.FALSE;
        }

        @Override
        public String toString() {
            return Boolean.toString(value);
        }
    }

    /**
     * An integer of a declared width, held as sign plus 128-bit magnitude.
     *
     * <p>Sign-and-magnitude rather than a two's-complement pair because that is
     * what CKE's normalization consumes ({@code spec/03-key-encoding.md} §4.1
     * works on {@code |v|}), and because {@code |i128::MIN|} is
     * 2<sup>127</sup>, which needs the unsigned width.
     */
    record Int(NumType type, boolean negative, U128 magnitude) implements Value {

        public Int {
            if (type.isFloat() || type == NumType.DEC128) {
                throw new InvalidArgumentException(type + " is not an integer type");
            }
            if (negative && !type.isSigned()) {
                throw new InvalidArgumentException(type + " cannot be negative");
            }
            if (negative && magnitude.isZero()) {
                throw new InvalidArgumentException("negative zero is not an integer");
            }
            checkRange(type, negative, magnitude);
        }

        private static void checkRange(NumType type, boolean negative, U128 magnitude) {
            int bits = type.bits();
            if (!type.isSigned()) {
                if (magnitude.bitLength() > bits) {
                    throw new InvalidArgumentException("magnitude " + magnitude + " does not fit " + type);
                }
                return;
            }
            // Signed: |v| < 2^(bits-1), with the single exception of the most
            // negative value, whose magnitude is exactly 2^(bits-1).
            if (magnitude.bitLength() <= bits - 1) {
                return;
            }
            boolean isMostNegative = negative
                    && magnitude.bitLength() == bits
                    && magnitude.equals(U128.ofUnsigned(1).shiftLeft(bits - 1));
            if (!isMostNegative) {
                throw new InvalidArgumentException("magnitude " + magnitude + " does not fit " + type);
            }
        }

        public boolean isZero() {
            return magnitude.isZero();
        }

        /** The value as a {@code long}, or {@code null} when it does not fit exactly. */
        public Long asLong() {
            if (!magnitude.fitsU64()) {
                return null;
            }
            long m = magnitude.lo();
            if (!negative) {
                return m >= 0 ? m : null;
            }
            if (m == Long.MIN_VALUE) {
                return Long.MIN_VALUE;
            }
            return m >= 0 ? -m : null;
        }

        @Override
        public int tag() {
            return type.cveTag();
        }

        @Override
        public String toString() {
            return (negative ? "-" : "") + magnitude + (type == NumType.INT_VAR ? "" : "_" + type.wireName());
        }
    }

    /**
     * A binary float of a declared width.
     *
     * <p>An {@code F32} value is canonicalized through a binary32 round trip at
     * construction. Java's {@code float} widens to {@code double} silently, so
     * without this an {@code F32} could hold a binary64 that binary32 cannot
     * represent and encoding it would narrow the value — making encode-then-
     * decode change it. Dart has the same hazard from the other direction, so
     * this is a portability rule rather than a workaround for either language.
     */
    record Float(NumType type, double value) implements Value {

        public Float {
            if (type == NumType.F32) {
                value = (float) value;
            } else if (type != NumType.F64) {
                throw new InvalidArgumentException(type + " is not a float type");
            }
        }

        @Override
        public int tag() {
            return type.cveTag();
        }

        @Override
        public String toString() {
            return value + (type == NumType.F32 ? "f32" : "");
        }
    }

    /**
     * IEEE 754-2008 decimal128, sixteen opaque bytes.
     *
     * <p>Storable, and <strong>not a key</strong>:
     * {@code spec/03-key-encoding.md} §4.4.
     */
    record Dec128(byte[] bytes) implements Value {

        public Dec128 {
            if (bytes.length != 16) {
                throw new InvalidArgumentException("DEC128 is 16 bytes, got " + bytes.length);
            }
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }

        @Override
        public int tag() {
            return Tag.DEC128;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Dec128 d && Arrays.equals(bytes, d.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        @Override
        public String toString() {
            return "dec128(...)";
        }
    }

    /** A Unicode scalar value. Not equal to a one-character {@link Str} (§8 rule 6). */
    record Char(int scalar) implements Value {

        public Char {
            if (scalar < 0 || scalar > 0x10FFFF || (scalar >= 0xD800 && scalar <= 0xDFFF)) {
                throw new InvalidArgumentException("not a Unicode scalar value: " + scalar);
            }
        }

        @Override
        public int tag() {
            return Tag.CHAR;
        }
    }

    record Str(String value) implements Value {
        @Override
        public int tag() {
            return Tag.STR;
        }

        @Override
        public String toString() {
            return "'" + value + "'";
        }
    }

    record Bytes(byte[] value) implements Value {

        public Bytes {
            value = value.clone();
        }

        @Override
        public byte[] value() {
            return value.clone();
        }

        @Override
        public int tag() {
            return Tag.BYTES;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes b && Arrays.equals(value, b.value);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(value);
        }
    }

    // ------------------------------------------------------------------
    // temporal
    // ------------------------------------------------------------------

    /** Milliseconds since the Unix epoch, UTC. */
    record Timestamp(long millis) implements Value {
        @Override
        public int tag() {
            return Tag.TIMESTAMP;
        }
    }

    /** Seconds since the Unix epoch plus nanoseconds, UTC. */
    record TimestampNs(long secs, int nanos) implements Value {

        public TimestampNs {
            if (nanos < 0 || nanos > 999_999_999) {
                throw new InvalidArgumentException("nanos out of range 0..999999999: " + nanos);
            }
        }

        @Override
        public int tag() {
            return Tag.TIMESTAMP_NS;
        }
    }

    /**
     * An instant plus an IANA zone id.
     *
     * <p>The zone is stored but is <em>not</em> part of the key: two zoned
     * timestamps denoting the same instant are the same key, so an index on a
     * zoned field answers instant queries, which is what applications mean
     * ({@code spec/03-key-encoding.md} §5).
     */
    record Zoned(long millis, String zoneId) implements Value {
        @Override
        public int tag() {
            return Tag.ZONED;
        }
    }

    /** Days since the Unix epoch. No time, no zone. */
    record Date(int days) implements Value {
        @Override
        public int tag() {
            return Tag.DATE;
        }
    }

    /** Nanoseconds since midnight. */
    record Time(long nanos) implements Value {
        @Override
        public int tag() {
            return Tag.TIME;
        }
    }

    record Duration(long secs, int nanos) implements Value {

        public Duration {
            if (nanos < 0 || nanos > 999_999_999) {
                throw new InvalidArgumentException("nanos out of range 0..999999999: " + nanos);
            }
        }

        @Override
        public int tag() {
            return Tag.DURATION;
        }
    }

    record Uuid(byte[] bytes) implements Value {

        public Uuid {
            if (bytes.length != 16) {
                throw new InvalidArgumentException("UUID is 16 bytes, got " + bytes.length);
            }
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }

        @Override
        public int tag() {
            return Tag.UUID;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Uuid u && Arrays.equals(bytes, u.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }
    }

    /**
     * The SDKs' snowflake id.
     *
     * <p>Signed 64-bit and exchanged as such: values outside ±2<sup>53</sup>
     * occur in practice, and truncating them through a double has already
     * caused a unique-index bug in this project
     * ({@code spec/00-conventions.md} §7).
     */
    record NitriteId(long id) implements Value {
        @Override
        public int tag() {
            return Tag.NITRITE_ID;
        }
    }

    record Regex(String pattern, String flags) implements Value {
        @Override
        public int tag() {
            return Tag.REGEX;
        }
    }

    // ------------------------------------------------------------------
    // composites
    // ------------------------------------------------------------------

    record Array(List<Value> items) implements Value {

        public Array {
            items = List.copyOf(items);
        }

        @Override
        public int tag() {
            return Tag.ARRAY;
        }
    }

    /**
     * Entries sorted by {@code CKE(key)} byte order — sorting is what makes
     * maps comparable, hashable and diffable across languages, and makes a
     * lookup a binary search. Duplicate keys are corruption.
     */
    record Map(List<Entry> entries) implements Value {

        public Map {
            entries = List.copyOf(entries);
        }

        @Override
        public int tag() {
            return Tag.MAP;
        }

        public record Entry(Value key, Value value) {
        }
    }

    /**
     * The document.
     *
     * <p>Field order here is the caller's; the encoder sorts by resolved name
     * bytes, which is what {@code spec/02-value-encoding.md} §5.1 requires and
     * is <em>not</em> the same as sorting by {@code name_ref}.
     */
    record Doc(java.util.Map<String, Value> fields) implements Value {

        public Doc {
            fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        }

        public static Doc of(java.util.Map<String, Value> fields) {
            return new Doc(fields);
        }

        public Value field(String name) {
            return fields.get(name);
        }

        @Override
        public int tag() {
            return Tag.DOC;
        }
    }

    /**
     * An embedding. A first-class type so that a 768-dimensional f32 embedding
     * is 3074 bytes rather than 3841 as an {@code ARRAY} of tagged {@code F32},
     * and decodes as one slice.
     *
     * <p>{@code payload} is the raw body after {@code dim}, exactly as stored.
     */
    record Vector(int dtype, int dim, byte[] payload) implements Value {

        public static final int DTYPE_F32 = 0;
        public static final int DTYPE_F16 = 1;
        public static final int DTYPE_I8 = 2;

        public Vector {
            payload = payload.clone();
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }

        @Override
        public int tag() {
            return Tag.VECTOR;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Vector v && v.dtype == dtype && v.dim == dim && Arrays.equals(payload, v.payload);
        }

        @Override
        public int hashCode() {
            return (dtype * 31 + dim) * 31 + Arrays.hashCode(payload);
        }
    }

    /** ISO WKB geometry ({@code spec/08-spatial.md}). */
    record Geometry(byte[] wkb) implements Value {

        public Geometry {
            wkb = wkb.clone();
        }

        @Override
        public byte[] wkb() {
            return wkb.clone();
        }

        @Override
        public int tag() {
            return Tag.GEOMETRY;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Geometry g && Arrays.equals(wkb, g.wkb);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(wkb);
        }
    }

    /**
     * A foreign, language-specific value.
     *
     * <p>The escape hatch that makes real interchange survivable: Java's
     * {@code Document} accepts arbitrary {@code Object} values and an SDK's
     * mapper may not be able to represent every one of them in the CVE type
     * set. Rather than fail or silently drop, the writer emits this and the
     * reader round-trips the bytes unchanged.
     *
     * <p>Not comparable, and never an index key.
     */
    record Opaque(String origin, String typeName, byte[] data) implements Value {

        public Opaque {
            data = data.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }

        @Override
        public int tag() {
            return Tag.OPAQUE;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Opaque p
                    && p.origin.equals(origin)
                    && p.typeName.equals(typeName)
                    && Arrays.equals(data, p.data);
        }

        @Override
        public int hashCode() {
            return (origin.hashCode() * 31 + typeName.hashCode()) * 31 + Arrays.hashCode(data);
        }
    }

    // ------------------------------------------------------------------
    // indirections — storage, not data (§9)
    // ------------------------------------------------------------------

    record BlobRef(long startPage, long byteLen, int crc32c) implements Value {
        @Override
        public int tag() {
            return Tag.BLOB_REF;
        }
    }

    record OverflowRef(byte[] inline, long nextPage) implements Value {

        public OverflowRef {
            inline = inline.clone();
        }

        @Override
        public byte[] inline() {
            return inline.clone();
        }

        @Override
        public int tag() {
            return Tag.OVERFLOW_REF;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof OverflowRef r && r.nextPage == nextPage && Arrays.equals(inline, r.inline);
        }

        @Override
        public int hashCode() {
            return Long.hashCode(nextPage) * 31 + Arrays.hashCode(inline);
        }
    }

    record VlogRef(long segmentId, long offset, int len) implements Value {
        @Override
        public int tag() {
            return Tag.VLOG_REF;
        }
    }

    /**
     * A value whose tag this implementation does not know.
     *
     * <p>{@code spec/11-conformance.md} §4 rule 1: an unknown CVE type tag
     * round-trips byte for byte. {@code spec/02-value-encoding.md} §1.1 is what
     * makes that implementable — every unassigned tag is length-prefixed, so a
     * reader can find where the value ends without knowing what it means.
     */
    record Unknown(int unknownTag, byte[] payload) implements Value {

        public Unknown {
            payload = payload.clone();
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }

        @Override
        public int tag() {
            return unknownTag;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Unknown u && u.unknownTag == unknownTag && Arrays.equals(payload, u.payload);
        }

        @Override
        public int hashCode() {
            return unknownTag * 31 + Arrays.hashCode(payload);
        }
    }

    // ------------------------------------------------------------------
    // convenience factories
    // ------------------------------------------------------------------

    static Value of(long v) {
        return integer(NumType.INT_VAR, v);
    }

    static Int integer(NumType type, long v) {
        if (v < 0) {
            // -Long.MIN_VALUE overflows back to itself, which is the correct
            // magnitude here precisely because it is read as unsigned 2^63.
            return new Int(type, true, U128.ofUnsigned(v == Long.MIN_VALUE ? v : -v));
        }
        return new Int(type, false, U128.ofUnsigned(v));
    }

    static Int i32(int v) {
        return integer(NumType.I32, v);
    }

    static Int i64(long v) {
        return integer(NumType.I64, v);
    }

    /** An unsigned value from a raw 64-bit pattern. */
    static Int u64Bits(long bits) {
        return new Int(NumType.U64, false, U128.ofUnsigned(bits));
    }

    static Float f64(double v) {
        return new Float(NumType.F64, v);
    }

    static Float f32(double v) {
        return new Float(NumType.F32, v);
    }

    static Str str(String s) {
        return new Str(s);
    }

    static NitriteId id(long v) {
        return new NitriteId(v);
    }
}
