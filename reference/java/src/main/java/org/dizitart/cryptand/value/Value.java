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
public interface Value {

    /** The CVE type tag this value encodes as. */
    int tag();

    // ------------------------------------------------------------------
    // scalars
    // ------------------------------------------------------------------

    Null NULL = new Null();
    Bool TRUE = new Bool(true);
    Bool FALSE = new Bool(false);

    final class Null implements Value {

        public Null() {
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Null)) {
                return false;
            }
            return true;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash();
        }

        @Override
        public int tag() {
            return Tag.NULL;
        }

        @Override
        public String toString() {
            return "null";
        }
    }

    final class Bool implements Value {
        private final boolean value;

        public Bool(boolean value) {
            this.value = value;
        }

        public boolean value() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Bool)) {
                return false;
            }
            Bool that = (Bool) o;
            return value == that.value;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(value);
        }

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
    final class Int implements Value {
        private final NumType type;
        private final boolean negative;
        private final U128 magnitude;

        public Int(NumType type, boolean negative, U128 magnitude) {
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
            this.type = type;
            this.negative = negative;
            this.magnitude = magnitude;
        }

        public NumType type() {
            return type;
        }

        public boolean negative() {
            return negative;
        }

        public U128 magnitude() {
            return magnitude;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Int)) {
                return false;
            }
            Int that = (Int) o;
            return java.util.Objects.equals(type, that.type)
                    && negative == that.negative
                    && java.util.Objects.equals(magnitude, that.magnitude);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(type, negative, magnitude);
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
    final class Float implements Value {
        private final NumType type;
        private final double value;

        public Float(NumType type, double value) {
            if (type == NumType.F32) {
                value = (float) value;
            } else if (type != NumType.F64) {
                throw new InvalidArgumentException(type + " is not a float type");
            }
            this.type = type;
            this.value = value;
        }

        public NumType type() {
            return type;
        }

        public double value() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Float)) {
                return false;
            }
            Float that = (Float) o;
            return java.util.Objects.equals(type, that.type)
                    && Double.compare(value, that.value) == 0;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(type, value);
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
    final class Dec128 implements Value {
        private final byte[] bytes;

        public Dec128(byte[] bytes) {
            if (bytes.length != 16) {
                throw new InvalidArgumentException("DEC128 is 16 bytes, got " + bytes.length);
            }
            bytes = bytes.clone();
            this.bytes = bytes;
        }

        public byte[] bytes() {
            return bytes.clone();
        }

        @Override
        public int tag() {
            return Tag.DEC128;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Dec128 && Arrays.equals(bytes, ((Dec128) o).bytes);
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
    final class Char implements Value {
        private final int scalar;

        public Char(int scalar) {
            if (scalar < 0 || scalar > 0x10FFFF || (scalar >= 0xD800 && scalar <= 0xDFFF)) {
                throw new InvalidArgumentException("not a Unicode scalar value: " + scalar);
            }
            this.scalar = scalar;
        }

        public int scalar() {
            return scalar;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Char)) {
                return false;
            }
            Char that = (Char) o;
            return scalar == that.scalar;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(scalar);
        }

        @Override
        public String toString() {
            return "Char[" + "scalar=" + scalar + "]";
        }

        @Override
        public int tag() {
            return Tag.CHAR;
        }
    }

    final class Str implements Value {
        private final String value;

        public Str(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Str)) {
                return false;
            }
            Str that = (Str) o;
            return java.util.Objects.equals(value, that.value);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(value);
        }

        @Override
        public int tag() {
            return Tag.STR;
        }

        @Override
        public String toString() {
            return "'" + value + "'";
        }
    }

    final class Bytes implements Value {
        private final byte[] value;

        public Bytes(byte[] value) {
            value = value.clone();
            this.value = value;
        }

        @Override
        public String toString() {
            return "Bytes[" + "value=" + value + "]";
        }

        public byte[] value() {
            return value.clone();
        }

        @Override
        public int tag() {
            return Tag.BYTES;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes && Arrays.equals(value, ((Bytes) o).value);
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
    final class Timestamp implements Value {
        private final long millis;

        public Timestamp(long millis) {
            this.millis = millis;
        }

        public long millis() {
            return millis;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Timestamp)) {
                return false;
            }
            Timestamp that = (Timestamp) o;
            return millis == that.millis;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(millis);
        }

        @Override
        public String toString() {
            return "Timestamp[" + "millis=" + millis + "]";
        }

        @Override
        public int tag() {
            return Tag.TIMESTAMP;
        }
    }

    /** Seconds since the Unix epoch plus nanoseconds, UTC. */
    final class TimestampNs implements Value {
        private final long secs;
        private final int nanos;

        public TimestampNs(long secs, int nanos) {
            if (nanos < 0 || nanos > 999_999_999) {
                throw new InvalidArgumentException("nanos out of range 0..999999999: " + nanos);
            }
            this.secs = secs;
            this.nanos = nanos;
        }

        public long secs() {
            return secs;
        }

        public int nanos() {
            return nanos;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof TimestampNs)) {
                return false;
            }
            TimestampNs that = (TimestampNs) o;
            return secs == that.secs
                    && nanos == that.nanos;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(secs, nanos);
        }

        @Override
        public String toString() {
            return "TimestampNs[" + "secs=" + secs + ", " + "nanos=" + nanos + "]";
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
    final class Zoned implements Value {
        private final long millis;
        private final String zoneId;

        public Zoned(long millis, String zoneId) {
            this.millis = millis;
            this.zoneId = zoneId;
        }

        public long millis() {
            return millis;
        }

        public String zoneId() {
            return zoneId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Zoned)) {
                return false;
            }
            Zoned that = (Zoned) o;
            return millis == that.millis
                    && java.util.Objects.equals(zoneId, that.zoneId);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(millis, zoneId);
        }

        @Override
        public String toString() {
            return "Zoned[" + "millis=" + millis + ", " + "zoneId=" + zoneId + "]";
        }

        @Override
        public int tag() {
            return Tag.ZONED;
        }
    }

    /** Days since the Unix epoch. No time, no zone. */
    final class Date implements Value {
        private final int days;

        public Date(int days) {
            this.days = days;
        }

        public int days() {
            return days;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Date)) {
                return false;
            }
            Date that = (Date) o;
            return days == that.days;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(days);
        }

        @Override
        public String toString() {
            return "Date[" + "days=" + days + "]";
        }

        @Override
        public int tag() {
            return Tag.DATE;
        }
    }

    /** Nanoseconds since midnight. */
    final class Time implements Value {
        private final long nanos;

        public Time(long nanos) {
            this.nanos = nanos;
        }

        public long nanos() {
            return nanos;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Time)) {
                return false;
            }
            Time that = (Time) o;
            return nanos == that.nanos;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(nanos);
        }

        @Override
        public String toString() {
            return "Time[" + "nanos=" + nanos + "]";
        }

        @Override
        public int tag() {
            return Tag.TIME;
        }
    }

    final class Duration implements Value {
        private final long secs;
        private final int nanos;

        public Duration(long secs, int nanos) {
            if (nanos < 0 || nanos > 999_999_999) {
                throw new InvalidArgumentException("nanos out of range 0..999999999: " + nanos);
            }
            this.secs = secs;
            this.nanos = nanos;
        }

        public long secs() {
            return secs;
        }

        public int nanos() {
            return nanos;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Duration)) {
                return false;
            }
            Duration that = (Duration) o;
            return secs == that.secs
                    && nanos == that.nanos;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(secs, nanos);
        }

        @Override
        public String toString() {
            return "Duration[" + "secs=" + secs + ", " + "nanos=" + nanos + "]";
        }

        @Override
        public int tag() {
            return Tag.DURATION;
        }
    }

    final class Uuid implements Value {
        private final byte[] bytes;

        public Uuid(byte[] bytes) {
            if (bytes.length != 16) {
                throw new InvalidArgumentException("UUID is 16 bytes, got " + bytes.length);
            }
            bytes = bytes.clone();
            this.bytes = bytes;
        }

        @Override
        public String toString() {
            return "Uuid[" + "bytes=" + bytes + "]";
        }

        public byte[] bytes() {
            return bytes.clone();
        }

        @Override
        public int tag() {
            return Tag.UUID;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Uuid && Arrays.equals(bytes, ((Uuid) o).bytes);
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
    final class NitriteId implements Value {
        private final long id;

        public NitriteId(long id) {
            this.id = id;
        }

        public long id() {
            return id;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof NitriteId)) {
                return false;
            }
            NitriteId that = (NitriteId) o;
            return id == that.id;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(id);
        }

        @Override
        public String toString() {
            return "NitriteId[" + "id=" + id + "]";
        }

        @Override
        public int tag() {
            return Tag.NITRITE_ID;
        }
    }

    final class Regex implements Value {
        private final String pattern;
        private final String flags;

        public Regex(String pattern, String flags) {
            this.pattern = pattern;
            this.flags = flags;
        }

        public String pattern() {
            return pattern;
        }

        public String flags() {
            return flags;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Regex)) {
                return false;
            }
            Regex that = (Regex) o;
            return java.util.Objects.equals(pattern, that.pattern)
                    && java.util.Objects.equals(flags, that.flags);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(pattern, flags);
        }

        @Override
        public String toString() {
            return "Regex[" + "pattern=" + pattern + ", " + "flags=" + flags + "]";
        }

        @Override
        public int tag() {
            return Tag.REGEX;
        }
    }

    // ------------------------------------------------------------------
    // composites
    // ------------------------------------------------------------------

    final class Array implements Value {
        private final List<Value> items;

        public Array(List<Value> items) {
            items = List.copyOf(items);
            this.items = items;
        }

        public List<Value> items() {
            return items;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Array)) {
                return false;
            }
            Array that = (Array) o;
            return java.util.Objects.equals(items, that.items);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(items);
        }

        @Override
        public String toString() {
            return "Array[" + "items=" + items + "]";
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
    final class Map implements Value {
        private final List<Entry> entries;

        public Map(List<Entry> entries) {
            entries = List.copyOf(entries);
            this.entries = entries;
        }

        public List<Entry> entries() {
            return entries;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Map)) {
                return false;
            }
            Map that = (Map) o;
            return java.util.Objects.equals(entries, that.entries);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(entries);
        }

        @Override
        public String toString() {
            return "Map[" + "entries=" + entries + "]";
        }

        @Override
        public int tag() {
            return Tag.MAP;
        }

        public static final class Entry {
            private final Value key;
            private final Value value;

            public Entry(Value key, Value value) {
                this.key = key;
                this.value = value;
            }

            public Value key() {
                return key;
            }

            public Value value() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) {
                    return true;
                }
                if (!(o instanceof Entry)) {
                    return false;
                }
                Entry that = (Entry) o;
                return java.util.Objects.equals(key, that.key)
                        && java.util.Objects.equals(value, that.value);
            }

            @Override
            public int hashCode() {
                return java.util.Objects.hash(key, value);
            }

            @Override
            public String toString() {
                return "Entry[" + "key=" + key + ", " + "value=" + value + "]";
            }
        }
    }

    /**
     * The document.
     *
     * <p>Field order here is the caller's; the encoder sorts by resolved name
     * bytes, which is what {@code spec/02-value-encoding.md} §5.1 requires and
     * is <em>not</em> the same as sorting by {@code name_ref}.
     */
    final class Doc implements Value {
        private final java.util.Map<String, Value> fields;

        public Doc(java.util.Map<String, Value> fields) {
            fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
            this.fields = fields;
        }

        public java.util.Map<String, Value> fields() {
            return fields;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Doc)) {
                return false;
            }
            Doc that = (Doc) o;
            return java.util.Objects.equals(fields, that.fields);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(fields);
        }

        @Override
        public String toString() {
            return "Doc[" + "fields=" + fields + "]";
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
    final class Vector implements Value {
        private final int dtype;
        private final int dim;
        private final byte[] payload;

        public Vector(int dtype, int dim, byte[] payload) {
            payload = payload.clone();
            this.dtype = dtype;
            this.dim = dim;
            this.payload = payload;
        }

        public int dtype() {
            return dtype;
        }

        public int dim() {
            return dim;
        }

        @Override
        public String toString() {
            return "Vector[" + "dtype=" + dtype + ", " + "dim=" + dim + ", " + "payload=" + payload + "]";
        }

        public static final int DTYPE_F32 = 0;
        public static final int DTYPE_F16 = 1;
        public static final int DTYPE_I8 = 2;



        public byte[] payload() {
            return payload.clone();
        }

        @Override
        public int tag() {
            return Tag.VECTOR;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Vector && ((Vector) o).dtype == dtype && ((Vector) o).dim == dim && Arrays.equals(payload, ((Vector) o).payload);
        }

        @Override
        public int hashCode() {
            return (dtype * 31 + dim) * 31 + Arrays.hashCode(payload);
        }
    }

    /** ISO WKB geometry ({@code spec/08-spatial.md}). */
    final class Geometry implements Value {
        private final byte[] wkb;

        public Geometry(byte[] wkb) {
            wkb = wkb.clone();
            this.wkb = wkb;
        }

        @Override
        public String toString() {
            return "Geometry[" + "wkb=" + wkb + "]";
        }

        public byte[] wkb() {
            return wkb.clone();
        }

        @Override
        public int tag() {
            return Tag.GEOMETRY;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Geometry && Arrays.equals(wkb, ((Geometry) o).wkb);
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
    final class Opaque implements Value {
        private final String origin;
        private final String typeName;
        private final byte[] data;

        public Opaque(String origin, String typeName, byte[] data) {
            data = data.clone();
            this.origin = origin;
            this.typeName = typeName;
            this.data = data;
        }

        public String origin() {
            return origin;
        }

        public String typeName() {
            return typeName;
        }

        @Override
        public String toString() {
            return "Opaque[" + "origin=" + origin + ", " + "typeName=" + typeName + ", " + "data=" + data + "]";
        }

        public byte[] data() {
            return data.clone();
        }

        @Override
        public int tag() {
            return Tag.OPAQUE;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Opaque
                    && ((Opaque) o).origin.equals(origin)
                    && ((Opaque) o).typeName.equals(typeName)
                    && Arrays.equals(data, ((Opaque) o).data);
        }

        @Override
        public int hashCode() {
            return (origin.hashCode() * 31 + typeName.hashCode()) * 31 + Arrays.hashCode(data);
        }
    }

    // ------------------------------------------------------------------
    // indirections — storage, not data (§9)
    // ------------------------------------------------------------------

    final class BlobRef implements Value {
        private final long startPage;
        private final long byteLen;
        private final int crc32c;

        public BlobRef(long startPage, long byteLen, int crc32c) {
            this.startPage = startPage;
            this.byteLen = byteLen;
            this.crc32c = crc32c;
        }

        public long startPage() {
            return startPage;
        }

        public long byteLen() {
            return byteLen;
        }

        public int crc32c() {
            return crc32c;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof BlobRef)) {
                return false;
            }
            BlobRef that = (BlobRef) o;
            return startPage == that.startPage
                    && byteLen == that.byteLen
                    && crc32c == that.crc32c;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(startPage, byteLen, crc32c);
        }

        @Override
        public String toString() {
            return "BlobRef[" + "startPage=" + startPage + ", " + "byteLen=" + byteLen + ", " + "crc32c=" + crc32c + "]";
        }

        @Override
        public int tag() {
            return Tag.BLOB_REF;
        }
    }

    final class OverflowRef implements Value {
        private final byte[] inline;
        private final long nextPage;

        public OverflowRef(byte[] inline, long nextPage) {
            inline = inline.clone();
            this.inline = inline;
            this.nextPage = nextPage;
        }

        public long nextPage() {
            return nextPage;
        }

        @Override
        public String toString() {
            return "OverflowRef[" + "inline=" + inline + ", " + "nextPage=" + nextPage + "]";
        }

        public byte[] inline() {
            return inline.clone();
        }

        @Override
        public int tag() {
            return Tag.OVERFLOW_REF;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof OverflowRef && ((OverflowRef) o).nextPage == nextPage && Arrays.equals(inline, ((OverflowRef) o).inline);
        }

        @Override
        public int hashCode() {
            return Long.hashCode(nextPage) * 31 + Arrays.hashCode(inline);
        }
    }

    final class VlogRef implements Value {
        private final long segmentId;
        private final long offset;
        private final int len;

        public VlogRef(long segmentId, long offset, int len) {
            this.segmentId = segmentId;
            this.offset = offset;
            this.len = len;
        }

        public long segmentId() {
            return segmentId;
        }

        public long offset() {
            return offset;
        }

        public int len() {
            return len;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof VlogRef)) {
                return false;
            }
            VlogRef that = (VlogRef) o;
            return segmentId == that.segmentId
                    && offset == that.offset
                    && len == that.len;
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(segmentId, offset, len);
        }

        @Override
        public String toString() {
            return "VlogRef[" + "segmentId=" + segmentId + ", " + "offset=" + offset + ", " + "len=" + len + "]";
        }

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
    final class Unknown implements Value {
        private final int unknownTag;
        private final byte[] payload;

        public Unknown(int unknownTag, byte[] payload) {
            payload = payload.clone();
            this.unknownTag = unknownTag;
            this.payload = payload;
        }

        public int unknownTag() {
            return unknownTag;
        }

        @Override
        public String toString() {
            return "Unknown[" + "unknownTag=" + unknownTag + ", " + "payload=" + payload + "]";
        }

        public byte[] payload() {
            return payload.clone();
        }

        @Override
        public int tag() {
            return unknownTag;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Unknown && ((Unknown) o).unknownTag == unknownTag && Arrays.equals(payload, ((Unknown) o).payload);
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
