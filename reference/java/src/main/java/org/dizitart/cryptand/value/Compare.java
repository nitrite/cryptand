package org.dizitart.cryptand.value;

import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.util.U128;
import org.dizitart.cryptand.util.Utf8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Logical value comparison — {@code spec/02-value-encoding.md} §8.
 *
 * <p>This is the <em>definition</em> of order; {@link Cke} is a byte encoding
 * that must agree with it. {@code CompareTest} asserts
 * {@code sign(compare(a, b)) == sign(memcmp(CKE(a), CKE(b)))} over a torture
 * set, which is the most important assertion in this package: a divergence
 * there is a wrong query result in production, not a slow one. The B+tree
 * navigates by bytes and the application reasons in values, so the two orders
 * being one order is what makes a range scan return the right rows.
 *
 * <p>This class was missing for the whole life of the Java port, while both
 * other reference implementations had it. Writing it found three divergences
 * that had reached shipped code — see §8's own notes on the {@code MAP}/
 * {@code DOC} ranks and on refusing rather than approximating.
 */
public final class Compare {

    private Compare() {
    }

    /**
     * §8 rule 10 — the cross-type rank.
     *
     * <p>For key-encodable values this is the group tag of
     * {@code spec/03-key-encoding.md} §2, so the two orders agree by
     * construction. {@code MAP} and {@code DOC} are ordered by rule 8 but have
     * no group tag, so §8 rule 10 gives them the two ranks below; they are
     * ordering ranks and are never written to a file.
     */
    private static final int RANK_MAP = 0xA1;
    private static final int RANK_DOC = 0xA2;

    /** Not a rank: the sentinel for a value §8 does not order at all. */
    private static final int UNORDERED = -1;

    private static int rank(Value v) {
        if (v instanceof Value.Null) return Cke.Group.NULL;
        if (v instanceof Value.Bool) return Cke.Group.BOOL;
        if (v instanceof Value.Int || v instanceof Value.Float) return Cke.Group.NUMBER;
        // DEC128 is in the numeric domain by rule 2 but is refused below,
        // because this implementation has no exact decimal arithmetic.
        if (v instanceof Value.Dec128) return Cke.Group.NUMBER;
        if (v instanceof Value.Timestamp || v instanceof Value.TimestampNs
                || v instanceof Value.Zoned || v instanceof Value.Date
                || v instanceof Value.Time || v instanceof Value.Duration) {
            return Cke.Group.TEMPORAL;
        }
        if (v instanceof Value.Char) return Cke.Group.CHAR;
        if (v instanceof Value.Str) return Cke.Group.STRING;
        if (v instanceof Value.Bytes) return Cke.Group.BYTES;
        if (v instanceof Value.NitriteId) return Cke.Group.NITRITE_ID;
        if (v instanceof Value.Uuid) return Cke.Group.UUID;
        if (v instanceof Value.Array) return Cke.Group.ARRAY;
        if (v instanceof Value.Map) return RANK_MAP;
        if (v instanceof Value.Doc) return RANK_DOC;
        return UNORDERED;
    }

    /**
     * Whether {@code v} takes part in the ordering at all.
     *
     * <p>§8: "{@code OPAQUE}, {@code GEOMETRY}, {@code VECTOR} and
     * {@code REGEX} are not ordered." An implementation-private tag is not
     * ordered either — its bytes are preserved, not understood. {@code DEC128}
     * <em>is</em> ordered in principle (rule 2) and is still refused by
     * {@link #compare}; {@link #isOrdered} answers the spec's question, not
     * this implementation's capability.
     */
    public static boolean isOrdered(Value v) {
        return rank(v) != UNORDERED
                && !(v instanceof Value.BlobRef)
                && !(v instanceof Value.OverflowRef)
                && !(v instanceof Value.VlogRef);
    }

    /** A {@link Comparator} over the ordered values, for sorting. */
    public static Comparator<Value> comparator() {
        return Compare::compare;
    }

    /**
     * Compares {@code a} and {@code b} per §8.
     *
     * @throws InvalidArgumentException if either side is a type §8 does not
     *     order, or is a {@code DEC128}. Refusing is normative: returning
     *     "equal" for two values that are merely incomparable is the dangerous
     *     answer, because it makes them indistinguishable to a sort, a
     *     deduplication and an equality check, silently.
     */
    public static int compare(Value a, Value b) {
        requireOrdered(a);
        requireOrdered(b);
        return compareOrdered(a, b);
    }

    /** §8 rule 2's consequence: {@code I32(5)} equals {@code I64(5)}. */
    public static boolean valuesEqual(Value a, Value b) {
        if (isOrdered(a) && isOrdered(b)
                && !(a instanceof Value.Dec128) && !(b instanceof Value.Dec128)) {
            return compareOrdered(a, b) == 0;
        }
        // §8 does not order these, but it does not deny them an identity
        // either: two of them are equal exactly when they are the same value.
        return structurallyEqual(a, b);
    }

    private static void requireOrdered(Value v) {
        if (v instanceof Value.Dec128) {
            throw new InvalidArgumentException(
                    "DEC128 comparison needs exact decimal arithmetic, which this "
                            + "reference implementation does not provide; it is never a key");
        }
        if (!isOrdered(v)) {
            throw new InvalidArgumentException(v.getClass().getSimpleName()
                    + " is not ordered (spec/02-value-encoding.md §8)");
        }
    }

    private static int compareOrdered(Value a, Value b) {
        int ra = rank(a);
        int rb = rank(b);
        if (ra != rb) {
            return Integer.compare(ra, rb);
        }
        if (a instanceof Value.Null) {
            return 0; // rule 1
        }
        if (a instanceof Value.Bool x) {
            // rule 9: FALSE < TRUE
            return Boolean.compare(x.value(), ((Value.Bool) b).value());
        }
        if (a instanceof Value.Int || a instanceof Value.Float) {
            return compareNumeric(a, b);
        }
        if (a instanceof Value.Char x) {
            // rule 6: CHAR is never equal to a one-character STR; the separate
            // groups already guarantee that, so here it is just the scalar.
            return Integer.compare(x.scalar(), ((Value.Char) b).scalar());
        }
        if (a instanceof Value.Str x) {
            // rule 4: UTF-8 byte order, which is code-point order. NOT
            // String.compareTo, which is UTF-16 code-unit order and disagrees
            // for every pair that straddles U+FFFF.
            return Arrays.compareUnsigned(Utf8.encode(x.value()),
                    Utf8.encode(((Value.Str) b).value()));
        }
        if (a instanceof Value.Bytes x) {
            // rule 5: lexicographic, shorter-is-smaller on a prefix
            return Arrays.compareUnsigned(x.value(), ((Value.Bytes) b).value());
        }
        if (a instanceof Value.NitriteId x) {
            return Long.compare(x.id(), ((Value.NitriteId) b).id());
        }
        if (a instanceof Value.Uuid x) {
            return Arrays.compareUnsigned(x.bytes(), ((Value.Uuid) b).bytes());
        }
        if (isTemporal(a)) {
            return compareTemporal(a, b);
        }
        if (a instanceof Value.Array x) {
            // rule 8: element-wise, then by length
            List<Value> p = x.items();
            List<Value> q = ((Value.Array) b).items();
            int n = Math.min(p.size(), q.size());
            for (int i = 0; i < n; i++) {
                int c = compareElement(p.get(i), q.get(i));
                if (c != 0) return c;
            }
            return Integer.compare(p.size(), q.size());
        }
        if (a instanceof Value.Map x) {
            return comparePairs(x.entries(), ((Value.Map) b).entries());
        }
        if (a instanceof Value.Doc x) {
            return comparePairs(docEntries(x), docEntries((Value.Doc) b));
        }
        throw new InvalidArgumentException(
                "no §8 rule for " + a.getClass().getSimpleName());
    }

    /**
     * An element <em>inside</em> an {@code ARRAY}, {@code MAP} or {@code DOC}.
     *
     * <p>§8 gives no order for an unordered element, but the container
     * comparison has to stay total or sorting a list of documents is
     * undefined. Such an element is therefore ranked by tag and then by its own
     * bytes: deterministic, and never written down, because a container holding
     * one is not key-encodable either.
     */
    private static int compareElement(Value a, Value b) {
        boolean oa = isOrdered(a) && !(a instanceof Value.Dec128);
        boolean ob = isOrdered(b) && !(b instanceof Value.Dec128);
        if (oa && ob) {
            return compareOrdered(a, b);
        }
        int c = Integer.compare(unorderedTag(a), unorderedTag(b));
        return c != 0 ? c : Arrays.compareUnsigned(unorderedBytes(a), unorderedBytes(b));
    }

    private static int unorderedTag(Value v) {
        if (v instanceof Value.Dec128) return 0x30;
        if (v instanceof Value.Regex) return 0xF0;
        if (v instanceof Value.Vector) return 0xF1;
        if (v instanceof Value.Geometry) return 0xF2;
        if (v instanceof Value.Opaque) return 0xF3;
        if (v instanceof Value.Unknown) return 0xF4;
        return rank(v);
    }

    private static byte[] unorderedBytes(Value v) {
        if (v instanceof Value.Dec128 d) return d.bytes();
        if (v instanceof Value.Regex r) return join(r.pattern(), r.flags());
        if (v instanceof Value.Vector x) return x.payload();
        if (v instanceof Value.Geometry g) return g.wkb();
        if (v instanceof Value.Opaque o) {
            byte[] head = join(o.origin(), o.typeName());
            byte[] all = Arrays.copyOf(head, head.length + 1 + o.data().length);
            System.arraycopy(o.data(), 0, all, head.length + 1, o.data().length);
            return all;
        }
        if (v instanceof Value.Unknown u) {
            byte[] all = new byte[1 + u.payload().length];
            all[0] = (byte) u.unknownTag();
            System.arraycopy(u.payload(), 0, all, 1, u.payload().length);
            return all;
        }
        return new byte[0];
    }

    private static byte[] join(String a, String b) {
        byte[] x = Utf8.encode(a);
        byte[] y = Utf8.encode(b);
        byte[] out = new byte[x.length + 1 + y.length];
        System.arraycopy(x, 0, out, 0, x.length);
        System.arraycopy(y, 0, out, x.length + 1, y.length);
        return out;
    }

    private static boolean structurallyEqual(Value a, Value b) {
        if (a.getClass() != b.getClass()) {
            return false;
        }
        return unorderedTag(a) == unorderedTag(b)
                && Arrays.equals(unorderedBytes(a), unorderedBytes(b));
    }

    // ------------------------------------------------------------------
    // rule 8's composites
    // ------------------------------------------------------------------

    /**
     * §8 rule 8: a {@code DOC} compares as its <em>sorted</em> (key, value)
     * sequence, so the field order a caller happened to insert in is not part
     * of the value.
     */
    private static List<Value.Map.Entry> docEntries(Value.Doc d) {
        List<Value.Map.Entry> out = new ArrayList<>(d.fields().size());
        for (java.util.Map.Entry<String, Value> e : d.fields().entrySet()) {
            out.add(new Value.Map.Entry(new Value.Str(e.getKey()), e.getValue()));
        }
        out.sort((p, q) -> compareElement(p.key(), q.key()));
        return out;
    }

    private static int comparePairs(List<Value.Map.Entry> x, List<Value.Map.Entry> y) {
        int n = Math.min(x.size(), y.size());
        for (int i = 0; i < n; i++) {
            int c = compareElement(x.get(i).key(), y.get(i).key());
            if (c == 0) {
                c = compareElement(x.get(i).value(), y.get(i).value());
            }
            if (c != 0) return c;
        }
        return Integer.compare(x.size(), y.size());
    }

    // ------------------------------------------------------------------
    // rule 7's instants
    // ------------------------------------------------------------------

    private static boolean isTemporal(Value v) {
        return v instanceof Value.Timestamp || v instanceof Value.TimestampNs
                || v instanceof Value.Zoned || v instanceof Value.Date
                || v instanceof Value.Time || v instanceof Value.Duration;
    }

    /**
     * The temporal subclass ranks, matching {@code spec/03-key-encoding.md} §5
     * so that the byte order agrees. {@code TIMESTAMP}, {@code TIMESTAMP_NS}
     * and {@code ZONED} share one subclass, which is what makes rule 7's
     * "compare by that instant across the three tags" true.
     */
    private static int temporalSub(Value v) {
        if (v instanceof Value.Timestamp || v instanceof Value.TimestampNs
                || v instanceof Value.Zoned) {
            return Cke.TemporalClass.INSTANT;
        }
        if (v instanceof Value.Date) return Cke.TemporalClass.DATE;
        if (v instanceof Value.Time) return Cke.TemporalClass.TIME;
        if (v instanceof Value.Duration) return Cke.TemporalClass.DURATION;
        throw new InvalidArgumentException("not temporal: " + v.getClass().getSimpleName());
    }

    private static int compareTemporal(Value a, Value b) {
        int sa = temporalSub(a);
        int sb = temporalSub(b);
        if (sa != sb) {
            return Integer.compare(sa, sb);
        }
        if (sa == Cke.TemporalClass.INSTANT) {
            long[] x = instantOf(a);
            long[] y = instantOf(b);
            int c = Long.compare(x[0], y[0]);
            return c != 0 ? c : Long.compare(x[1], y[1]);
        }
        if (sa == Cke.TemporalClass.DATE) {
            return Integer.compare(((Value.Date) a).days(), ((Value.Date) b).days());
        }
        if (sa == Cke.TemporalClass.TIME) {
            return Long.compare(((Value.Time) a).nanos(), ((Value.Time) b).nanos());
        }
        Value.Duration da = (Value.Duration) a;
        Value.Duration db = (Value.Duration) b;
        int c = Long.compare(da.secs(), db.secs());
        return c != 0 ? c : Integer.compare(da.nanos(), db.nanos());
    }

    /**
     * {@code (secs, nanos)} for an instant-valued tag. Floor division, not
     * truncation, so instants before the epoch normalize the same way
     * {@link Cke} normalizes them: {@code -1 ms} is
     * {@code (-1, 999_000_000)}.
     */
    private static long[] instantOf(Value v) {
        if (v instanceof Value.Timestamp t) {
            return new long[] {Math.floorDiv(t.millis(), 1000L),
                    Math.floorMod(t.millis(), 1000L) * 1_000_000L};
        }
        if (v instanceof Value.Zoned z) {
            // rule 7: ZONED denotes an instant. The zone is display, not order.
            return new long[] {Math.floorDiv(z.millis(), 1000L),
                    Math.floorMod(z.millis(), 1000L) * 1_000_000L};
        }
        Value.TimestampNs n = (Value.TimestampNs) v;
        return new long[] {n.secs(), n.nanos()};
    }

    // ------------------------------------------------------------------
    // rule 2 and rule 3: the numeric domain
    // ------------------------------------------------------------------

    /** Whether {@code v} is in §8 rule 2's single numeric domain. */
    public static boolean isNumeric(Value v) {
        return v instanceof Value.Int || v instanceof Value.Float
                || v instanceof Value.Dec128;
    }

    /**
     * §8 rule 2 — every numeric tag is one domain, compared by <strong>exact
     * numeric value</strong>.
     *
     * <p>The comparison goes through {@code (sign, binary exponent, normalized
     * 128-bit mantissa)}, which is exact for every integer width and every
     * binary float the format has. Folding both sides through {@code double}
     * would be shorter and would call {@code i64(2^53 + 1)} equal to
     * {@code 2^53}; folding through {@link BigInteger} would need a rational to
     * handle floats. This is the same decomposition CKE encodes, which is why
     * the byte order and this order agree.
     *
     * @throws InvalidArgumentException for {@code DEC128}, per {@link #compare}
     */
    public static int compareNumeric(Value a, Value b) {
        requireOrdered(a);
        requireOrdered(b);
        if (!isNumeric(a) || !isNumeric(b)) {
            throw new InvalidArgumentException("compareNumeric on a non-numeric value");
        }
        // rule 3: NaN is equal to itself and above every other number.
        boolean na = isNan(a);
        boolean nb = isNan(b);
        if (na || nb) {
            return na && nb ? 0 : (na ? 1 : -1);
        }
        int[] sa = new int[1];
        int[] sb = new int[1];
        long[] ea = new long[1];
        long[] eb = new long[1];
        U128 ma = decompose(a, sa, ea);
        U128 mb = decompose(b, sb, eb);
        if (sa[0] != sb[0]) {
            return Integer.compare(sa[0], sb[0]);
        }
        if (sa[0] == 0) {
            // rule 3: -0.0 equals +0.0, and both equal integer zero.
            return 0;
        }
        int mag = Long.compare(ea[0], eb[0]);
        if (mag == 0) {
            mag = ma.compareTo(mb);
        }
        return sa[0] < 0 ? -mag : mag;
    }

    private static boolean isNan(Value v) {
        return v instanceof Value.Float f && Double.isNaN(f.value());
    }

    /**
     * {@code |v| = mantissa * 2^exponent} with the mantissa left-normalized
     * into 128 bits, so two mantissas are comparable as unsigned integers.
     * Infinity takes the maximum exponent, which is why it needs no special
     * case below.
     */
    private static U128 decompose(Value v, int[] sign, long[] exponent) {
        if (v instanceof Value.Int i) {
            if (i.magnitude().isZero()) {
                sign[0] = 0;
                exponent[0] = 0;
                return U128.ZERO;
            }
            sign[0] = i.negative() ? -1 : 1;
            int n = 128 - i.magnitude().leadingZeros();
            exponent[0] = n - 1;
            return i.magnitude().shiftLeft(128 - n);
        }
        double d = ((Value.Float) v).value();
        if (d == 0.0) {
            sign[0] = 0;
            exponent[0] = 0;
            return U128.ZERO;
        }
        sign[0] = d < 0 ? -1 : 1;
        if (Double.isInfinite(d)) {
            exponent[0] = Long.MAX_VALUE;
            return new U128(-1L, -1L); // every bit set
        }
        long bits = Double.doubleToRawLongBits(Math.abs(d));
        int biased = (int) ((bits >>> 52) & 0x7FF);
        long frac = bits & 0x000F_FFFF_FFFF_FFFFL;
        long sig;
        long exp;
        if (biased != 0) {
            sig = (1L << 52) | frac;
            exp = biased - 1023;
        } else {
            // Subnormal: no implicit leading 1, so normalize by hand. The
            // smallest positive double, 5e-324, is frac == 1.
            int k = 52 - (63 - Long.numberOfLeadingZeros(frac));
            sig = frac << k;
            exp = -1022L - k;
        }
        exponent[0] = exp;
        return new U128(0, sig).shiftLeft(128 - 53);
    }
}
