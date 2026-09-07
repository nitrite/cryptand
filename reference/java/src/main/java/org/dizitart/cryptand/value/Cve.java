package org.dizitart.cryptand.value;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.container.Limits;
import org.dizitart.cryptand.geom.Geometry;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.util.Tag;
import org.dizitart.cryptand.util.U128;
import org.dizitart.cryptand.util.Utf8;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CVE, the Cryptand Value Encoding — {@code spec/02-value-encoding.md}.
 *
 * <p>Little-endian, self-describing, forward compatible, and designed so that
 * reading one field of a document costs a forward scan of a sorted table and a
 * slice rather than a deserialization.
 *
 * <p>Keys use {@link Cke}, not this. The two encodings are separate because
 * they optimize opposite things: CVE optimizes decode cost and size, CKE
 * optimizes byte-comparison order.
 */
public final class Cve {

    private Cve() {
    }

    /** Document flags, §5. */
    public static final class DocFlags {
        private DocFlags() {
        }

        /** bit0. MUST be 1 in v1: the field table is sorted by resolved name bytes. */
        public static final int SORTED_BY_NAME = 0x01;
    }

    // ==================================================================
    // encoding
    // ==================================================================

    public static byte[] encode(Value v) {
        return encode(v, null);
    }

    public static byte[] encode(Value v, NameDict dict) {
        ByteWriter w = new ByteWriter(64);
        write(w, v, dict, 0);
        return w.toBytes();
    }

    static void write(ByteWriter w, Value v, NameDict dict, int depth) {
        if (depth > Limits.MAX_DEPTH) {
            throw new LimitException("CVE nesting deeper than " + Limits.MAX_DEPTH);
        }
        if (v instanceof Value.Null) {
            w.u8(Tag.NULL);
        } else if (v instanceof Value.Bool b) {
            w.u8(b.value() ? Tag.TRUE : Tag.FALSE);
        } else if (v instanceof Value.Int i) {
            writeInt(w, i);
        } else if (v instanceof Value.Float f) {
            if (f.type() == NumType.F32) {
                // floatToIntBits, not floatToRawIntBits: §3 of 00-conventions
                // canonicalizes any NaN payload to the quiet NaN.
                w.u8(Tag.F32).u32(Float.floatToIntBits((float) f.value()));
            } else {
                w.u8(Tag.F64).u64(Double.doubleToLongBits(f.value()));
            }
        } else if (v instanceof Value.Dec128 d) {
            w.u8(Tag.DEC128).bytes(d.bytes());
        } else if (v instanceof Value.Char c) {
            w.u8(Tag.CHAR).u32(c.scalar());
        } else if (v instanceof Value.Str s) {
            w.u8(Tag.STR).str(s.value());
        } else if (v instanceof Value.Bytes b) {
            byte[] raw = b.value();
            w.u8(Tag.BYTES).uvar(raw.length).bytes(raw);
        } else if (v instanceof Value.Timestamp t) {
            w.u8(Tag.TIMESTAMP).u64(t.millis());
        } else if (v instanceof Value.TimestampNs t) {
            w.u8(Tag.TIMESTAMP_NS).u64(t.secs()).u32(t.nanos());
        } else if (v instanceof Value.Zoned z) {
            w.u8(Tag.ZONED).u64(z.millis()).str(z.zoneId());
        } else if (v instanceof Value.Date d) {
            w.u8(Tag.DATE).u32(d.days());
        } else if (v instanceof Value.Time t) {
            w.u8(Tag.TIME).u64(t.nanos());
        } else if (v instanceof Value.Duration d) {
            w.u8(Tag.DURATION).u64(d.secs()).u32(d.nanos());
        } else if (v instanceof Value.Uuid u) {
            w.u8(Tag.UUID).bytes(u.bytes());
        } else if (v instanceof Value.NitriteId n) {
            w.u8(Tag.NITRITE_ID).u64(n.id());
        } else if (v instanceof Value.Regex r) {
            w.u8(Tag.REGEX).str(r.pattern()).str(r.flags());
        } else if (v instanceof Value.Array a) {
            writeLengthPrefixed(w, Tag.ARRAY, inner -> {
                inner.uvar(a.items().size());
                for (Value e : a.items()) {
                    write(inner, e, dict, depth + 1);
                }
            });
        } else if (v instanceof Value.Map m) {
            writeMap(w, m, dict, depth);
        } else if (v instanceof Value.Doc d) {
            writeDoc(w, d, dict, depth);
        } else if (v instanceof Value.Vector vec) {
            w.u8(Tag.VECTOR).u8(vec.dtype()).uvar(vec.dim()).bytes(vec.payload());
        } else if (v instanceof Value.Geometry g) {
            byte[] wkb = g.wkb();
            w.u8(Tag.GEOMETRY).uvar(wkb.length).bytes(wkb);
        } else if (v instanceof Value.BlobRef b) {
            w.u8(Tag.BLOB_REF).u64(b.startPage()).u32((int) b.byteLen()).u32(b.crc32c());
        } else if (v instanceof Value.OverflowRef o) {
            byte[] inline = o.inline();
            w.u8(Tag.OVERFLOW_REF).uvar(inline.length).bytes(inline).u64(o.nextPage());
        } else if (v instanceof Value.VlogRef vl) {
            w.u8(Tag.VLOG_REF).u64(vl.segmentId()).u32((int) vl.offset()).u32(vl.len());
        } else if (v instanceof Value.Opaque o) {
            writeLengthPrefixed(w, Tag.OPAQUE, inner -> {
                byte[] data = o.data();
                inner.str(o.origin()).str(o.typeName()).uvar(data.length).bytes(data);
            });
        } else if (v instanceof Value.Unknown u) {
            // §1.1: reserved and implementation-private tags are
            // length-prefixed, so preserving one is writing back what we read.
            byte[] payload = u.payload();
            w.u8(u.unknownTag()).uvar(payload.length).bytes(payload);
        } else {
            // Unreachable while Value stays sealed and this chain covers it.
            // On 21 the compiler proved that; here the throw is the proof.
            throw new InvalidArgumentException("no CVE encoding for " + v.getClass().getName());
        }
    }

    private interface Body {
        void write(ByteWriter w);
    }

    private static void writeLengthPrefixed(ByteWriter w, int tag, Body body) {
        ByteWriter inner = new ByteWriter(64);
        body.write(inner);
        byte[] b = inner.toBytes();
        w.u8(tag).uvar(b.length).bytes(b);
    }

    private static void writeInt(ByteWriter w, Value.Int v) {
        NumType t = v.type();
        if (t == NumType.INT_VAR) {
            Long asLong = v.asLong();
            if (asLong == null) {
                throw new InvalidArgumentException("INT_VAR value " + v + " does not fit i64");
            }
            w.u8(Tag.INT_VAR).ivar(asLong);
            return;
        }
        w.u8(t.cveTag());
        U128 mag = v.magnitude();
        long lo = v.negative() ? -mag.lo() : mag.lo();
        switch (t.bits()) {
            case 8 -> w.u8((int) (lo & 0xFF));
            case 16 -> w.u16((int) (lo & 0xFFFF));
            case 32 -> w.u32((int) lo);
            case 64 -> w.u64(lo);
            default -> w.bytes((v.negative() ? mag.negate() : mag).toBytesLE());
        }
    }

    /**
     * §4: entries MUST be sorted by {@code CKE(key)} byte order, and a map key
     * MUST be CKE-encodable. Sorting is what makes maps comparable, hashable and
     * diffable across languages; duplicate keys are corruption.
     */
    private static void writeMap(ByteWriter w, Value.Map v, NameDict dict, int depth) {
        record Keyed(byte[] cke, Value key, Value value) {
        }
        List<Keyed> keyed = new ArrayList<>(v.entries().size());
        for (Value.Map.Entry e : v.entries()) {
            if (!Cke.isKeyEncodable(e.key())) {
                throw new InvalidArgumentException(e.key().getClass().getSimpleName()
                        + " has no CKE encoding and cannot be a map key (spec/02-value-encoding.md §4)");
            }
            keyed.add(new Keyed(Cke.encode(e.key()), e.key(), e.value()));
        }
        keyed.sort(Comparator.comparing(Keyed::cke, Arrays::compareUnsigned));
        for (int i = 1; i < keyed.size(); i++) {
            if (Arrays.equals(keyed.get(i - 1).cke(), keyed.get(i).cke())) {
                throw new InvalidArgumentException("duplicate map key");
            }
        }
        writeLengthPrefixed(w, Tag.MAP, inner -> {
            inner.uvar(keyed.size());
            for (Keyed e : keyed) {
                write(inner, e.key(), dict, depth + 1);
                write(inner, e.value(), dict, depth + 1);
            }
        });
    }

    /**
     * §5. The field table is sorted by the {@code name_ref}'s <em>resolved name
     * bytes</em>, not by the numeric {@code name_ref} — otherwise dictionary
     * and inline names would interleave arbitrarily and a reader could not stop
     * its scan early.
     */
    static void writeDoc(ByteWriter w, Value.Doc doc, NameDict dict, int depth) {
        if (depth > Limits.MAX_DEPTH) {
            throw new LimitException("CVE nesting deeper than " + Limits.MAX_DEPTH);
        }
        Map<String, Value> fields = doc.fields();
        if (fields.size() > Limits.MAX_FIELD_COUNT) {
            throw new LimitException(
                    "document has " + fields.size() + " fields, limit is " + Limits.MAX_FIELD_COUNT);
        }

        List<String> names = new ArrayList<>(fields.keySet());
        names.sort(Comparator.comparing(Utf8::encode, Arrays::compareUnsigned));

        long[] nameRefs = new long[names.size()];
        List<String> inlineNames = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) {
            String n = names.get(i);
            Integer id = dict == null ? null : dict.idOf(n);
            if (id != null) {
                nameRefs[i] = ((long) id) << 1;
            } else {
                nameRefs[i] = (((long) inlineNames.size()) << 1) | 1;
                inlineNames.add(n);
            }
        }

        // Values first, so the table can carry real offsets. The offsets are
        // relative to the value area, so they do not depend on the table's own
        // encoded size and one pass is enough.
        ByteWriter values = new ByteWriter(64);
        int[] offsets = new int[names.size()];
        for (int i = 0; i < names.size(); i++) {
            offsets[i] = values.length();
            write(values, fields.get(names.get(i)), dict, depth + 1);
        }

        ByteWriter nameArea = new ByteWriter(32);
        for (String n : inlineNames) {
            nameArea.str(n);
        }

        byte[] nameAreaBytes = nameArea.toBytes();
        byte[] valueBytes = values.toBytes();
        writeLengthPrefixed(w, Tag.DOC, inner -> {
            inner.uvar(names.size()).u8(DocFlags.SORTED_BY_NAME);
            for (int i = 0; i < names.size(); i++) {
                inner.uvar(nameRefs[i]).uvar(offsets[i]);
            }
            inner.bytes(nameAreaBytes).bytes(valueBytes);
        });
    }

    // ==================================================================
    // decoding
    // ==================================================================

    /** Decodes a whole value and asserts nothing follows it. */
    public static Value decode(byte[] bytes) {
        return decode(bytes, null);
    }

    public static Value decode(byte[] bytes, NameDict dict) {
        ByteReader r = new ByteReader(bytes);
        Value v = read(r, dict, 0);
        if (r.hasRemaining()) {
            throw new CorruptionException(r.remaining() + " trailing byte(s) after CVE value");
        }
        return v;
    }

    static Value read(ByteReader r, NameDict dict, int depth) {
        if (depth > Limits.MAX_DEPTH) {
            throw new LimitException("CVE nesting deeper than " + Limits.MAX_DEPTH);
        }
        int tag = r.u8();
        switch (tag) {
            case Tag.NULL:
                return Value.NULL;
            case Tag.FALSE:
                return Value.FALSE;
            case Tag.TRUE:
                return Value.TRUE;
            case Tag.I8:
                return Value.integer(NumType.I8, (byte) r.u8());
            case Tag.I16:
                return Value.integer(NumType.I16, (short) r.u16());
            case Tag.I32:
                return Value.integer(NumType.I32, r.u32());
            case Tag.I64:
                return Value.integer(NumType.I64, r.u64());
            case Tag.I128:
                return signedU128(NumType.I128, U128.fromBytesLE(r.bytes(16), 0));
            case Tag.U8:
                return new Value.Int(NumType.U8, false, U128.ofUnsigned(r.u8()));
            case Tag.U16:
                return new Value.Int(NumType.U16, false, U128.ofUnsigned(r.u16()));
            case Tag.U32:
                return new Value.Int(NumType.U32, false, U128.ofUnsigned(r.u32() & 0xFFFFFFFFL));
            case Tag.U64:
                return new Value.Int(NumType.U64, false, U128.ofUnsigned(r.u64()));
            case Tag.U128:
                return new Value.Int(NumType.U128, false, U128.fromBytesLE(r.bytes(16), 0));
            case Tag.INT_VAR:
                return Value.integer(NumType.INT_VAR, r.ivar());
            case Tag.F32:
                return new Value.Float(NumType.F32, r.f32());
            case Tag.F64:
                return new Value.Float(NumType.F64, r.f64());
            case Tag.DEC128:
                return new Value.Dec128(r.bytes(16));
            case Tag.CHAR:
                return new Value.Char(r.u32());
            case Tag.STR:
                return new Value.Str(r.str());
            case Tag.BYTES:
                return new Value.Bytes(r.bytes(r.uvarLength("BYTES")));
            case Tag.TIMESTAMP:
                return new Value.Timestamp(r.u64());
            case Tag.TIMESTAMP_NS:
                return new Value.TimestampNs(r.u64(), checkNanos(r.u32()));
            case Tag.ZONED:
                return new Value.Zoned(r.u64(), r.str());
            case Tag.DATE:
                return new Value.Date(r.u32());
            case Tag.TIME:
                return new Value.Time(r.u64());
            case Tag.DURATION:
                return new Value.Duration(r.u64(), checkNanos(r.u32()));
            case Tag.UUID:
                return new Value.Uuid(r.bytes(16));
            case Tag.NITRITE_ID:
                return new Value.NitriteId(r.u64());
            case Tag.REGEX:
                return new Value.Regex(r.str(), r.str());
            case Tag.ARRAY: {
                int byteLen = r.uvarLength("ARRAY");
                ByteReader body = new ByteReader(r.bytesView(), r.position(), byteLen);
                r.skip(byteLen);
                long count = body.uvar();
                if (count > byteLen) {
                    throw new LimitException("ARRAY declares " + count + " items in " + byteLen + " byte(s)");
                }
                List<Value> items = new ArrayList<>((int) count);
                for (long i = 0; i < count; i++) {
                    items.add(read(body, dict, depth + 1));
                }
                return new Value.Array(items);
            }
            case Tag.MAP: {
                int byteLen = r.uvarLength("MAP");
                ByteReader body = new ByteReader(r.bytesView(), r.position(), byteLen);
                r.skip(byteLen);
                long count = body.uvar();
                if (count > byteLen) {
                    throw new LimitException("MAP declares " + count + " entries in " + byteLen + " byte(s)");
                }
                List<Value.Map.Entry> entries = new ArrayList<>((int) count);
                byte[] previous = null;
                for (long i = 0; i < count; i++) {
                    Value k = read(body, dict, depth + 1);
                    Value val = read(body, dict, depth + 1);
                    if (!Cke.isKeyEncodable(k)) {
                        throw new CorruptionException("MAP key of type " + k.getClass().getSimpleName()
                                + " has no CKE encoding (spec/02-value-encoding.md §4)");
                    }
                    byte[] cke = Cke.encode(k);
                    if (previous != null) {
                        int c = Arrays.compareUnsigned(previous, cke);
                        if (c > 0) {
                            throw new CorruptionException("MAP entries are not sorted by CKE(key)");
                        }
                        if (c == 0) {
                            throw new CorruptionException("duplicate MAP key");
                        }
                    }
                    previous = cke;
                    entries.add(new Value.Map.Entry(k, val));
                }
                return new Value.Map(entries);
            }
            case Tag.DOC:
                return readDoc(r, dict, depth);
            case Tag.VECTOR: {
                int dtype = r.u8();
                long dim = r.uvar();
                int payloadLen = vectorPayloadBytes(dtype, dim);
                return new Value.Vector(dtype, (int) dim, r.bytes(payloadLen));
            }
            case Tag.GEOMETRY:
                return new Value.Geometry(r.bytes(r.uvarLength("GEOMETRY")));
            case Tag.BLOB_REF:
                return new Value.BlobRef(r.u64(), r.u32() & 0xFFFFFFFFL, r.u32());
            case Tag.OVERFLOW_REF: {
                byte[] inline = r.bytes(r.uvarLength("OVERFLOW_REF"));
                return new Value.OverflowRef(inline, r.u64());
            }
            case Tag.VLOG_REF:
                return new Value.VlogRef(r.u64(), r.u32() & 0xFFFFFFFFL, r.u32());
            case Tag.OPAQUE: {
                int byteLen = r.uvarLength("OPAQUE");
                ByteReader body = new ByteReader(r.bytesView(), r.position(), byteLen);
                r.skip(byteLen);
                String origin = body.str();
                String typeName = body.str();
                return new Value.Opaque(origin, typeName, body.bytes(body.uvarLength("OPAQUE data")));
            }
            default:
                if (Tag.isUnassigned(tag)) {
                    // §1.1 is what makes 11-conformance §4 rule 1 — "an unknown
                    // CVE type tag round-trips byte for byte" — implementable:
                    // to preserve a value you must first know where it ends.
                    return new Value.Unknown(tag, r.bytes(r.uvarLength("unknown value")));
                }
                throw new CorruptionException("unknown CVE type tag 0x" + Integer.toHexString(tag));
        }
    }

    private static int checkNanos(int nanos) {
        if (nanos < 0 || nanos > 999_999_999) {
            throw new CorruptionException("nanos " + Integer.toUnsignedString(nanos) + " out of range 0..999999999");
        }
        return nanos;
    }

    private static Value signedU128(NumType type, U128 bits) {
        boolean negative = bits.bit(127);
        return new Value.Int(type, negative, negative ? bits.negate() : bits);
    }

    private static int vectorPayloadBytes(int dtype, long dim) {
        if (dim < 0 || dim > 0xFFFF) {
            throw new LimitException("vector dimension " + dim + " out of range");
        }
        return switch (dtype) {
            case Value.Vector.DTYPE_F32 -> (int) (dim * 4);
            case Value.Vector.DTYPE_F16 -> (int) (dim * 2);
            // i8 payload carries a trailing f32 scale and f32 zero_point.
            case Value.Vector.DTYPE_I8 -> (int) (dim + 8);
            default -> throw new CorruptionException("unknown VECTOR dtype " + dtype);
        };
    }

    /**
     * §5.2. Decodes every field. The lazy single-field path — the property the
     * design is built around — is {@link DocView}.
     */
    private static Value.Doc readDoc(ByteReader r, NameDict dict, int depth) {
        int byteLen = r.uvarLength("DOC");
        ByteReader body = new ByteReader(r.bytesView(), r.position(), byteLen);
        r.skip(byteLen);

        long fieldCount = body.uvar();
        if (fieldCount > Limits.MAX_FIELD_COUNT) {
            throw new LimitException("DOC declares " + fieldCount + " fields, limit is " + Limits.MAX_FIELD_COUNT);
        }
        if (fieldCount > byteLen) {
            throw new LimitException("DOC declares " + fieldCount + " fields in " + byteLen + " byte(s)");
        }
        int flags = body.u8();
        if ((flags & DocFlags.SORTED_BY_NAME) == 0) {
            throw new CorruptionException("DOC flag SORTED_BY_NAME must be 1 in format version 1");
        }

        int n = (int) fieldCount;
        long[] nameRefs = new long[n];
        int[] offsets = new int[n];
        for (int i = 0; i < n; i++) {
            nameRefs[i] = body.uvar();
            long off = body.uvar();
            if (off < 0 || off > byteLen) {
                throw new LimitException("DOC value offset " + off + " outside the value area");
            }
            offsets[i] = (int) off;
        }

        // The name area comes first and holds only the inline names, in table
        // order; the value area is whatever follows it.
        List<String> inline = new ArrayList<>();
        int inlineCount = 0;
        for (long ref : nameRefs) {
            if ((ref & 1) == 1) {
                inlineCount++;
            }
        }
        for (int i = 0; i < inlineCount; i++) {
            inline.add(body.str());
        }

        int valueArea = body.position();
        Map<String, Value> fields = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) {
            long ref = nameRefs[i];
            String name;
            if ((ref & 1) == 1) {
                int index = (int) (ref >>> 1);
                if (index >= inline.size()) {
                    throw new CorruptionException("DOC inline name index " + index + " out of range");
                }
                name = inline.get(index);
            } else {
                int id = (int) (ref >>> 1);
                name = dict == null ? null : dict.nameOf(id);
                if (name == null) {
                    throw new CorruptionException("DOC references name_id " + id
                            + ", which is not in the tree's name dictionary");
                }
            }
            ByteReader at = new ByteReader(body.bytesView(), valueArea + offsets[i],
                    body.limit() - (valueArea + offsets[i]));
            fields.put(name, read(at, dict, depth + 1));
        }
        return new Value.Doc(fields);
    }
}
