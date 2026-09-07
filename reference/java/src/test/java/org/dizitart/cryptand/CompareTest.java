package org.dizitart.cryptand;

import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.util.U128;
import org.dizitart.cryptand.value.Compare;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code spec/02-value-encoding.md} §8 — the definition of value order.
 *
 * <p>Both the class under test and this file are new. The Java port shipped
 * without any implementation of §8 at all: it had {@link Cke#compare} (byte
 * order) and nothing that ordered <em>values</em>, so the chapter that opens
 * "defined here once, for all SDKs, ending the current divergence" had no Java
 * side to diverge from.
 *
 * <p>The invariant that matters:
 * {@code sign(compare(a, b)) == sign(memcmp(CKE(a), CKE(b)))}.
 */
class CompareTest {

    // ------------------------------------------------------------------
    // corpus
    // ------------------------------------------------------------------

    private static Value.Int intOf(NumType t, BigInteger v) {
        boolean neg = v.signum() < 0;
        return new Value.Int(t, neg, U128.fromBigInteger(neg ? v.negate() : v));
    }

    /** Every boundary that has historically broken an implementation. */
    private static List<Value> torturedNumbers() {
        List<Value> out = new ArrayList<>();
        BigInteger two = BigInteger.TWO;
        for (NumType t : List.of(NumType.I8, NumType.I16, NumType.I32, NumType.I64)) {
            BigInteger hi = two.pow(t.bits() - 1);
            out.add(intOf(t, BigInteger.ZERO));
            out.add(intOf(t, BigInteger.ONE));
            out.add(intOf(t, BigInteger.ONE.negate()));
            out.add(intOf(t, hi.subtract(BigInteger.ONE)));
            out.add(intOf(t, hi.negate()));
        }
        for (NumType t : List.of(NumType.U8, NumType.U16, NumType.U32, NumType.U64)) {
            out.add(intOf(t, BigInteger.ZERO));
            out.add(intOf(t, BigInteger.ONE));
            out.add(intOf(t, two.pow(t.bits()).subtract(BigInteger.ONE)));
        }
        // i128 / u128: the whole reason U128 exists.
        out.add(intOf(NumType.I128, two.pow(127).subtract(BigInteger.ONE)));
        out.add(intOf(NumType.I128, two.pow(127).negate()));
        out.add(intOf(NumType.U128, two.pow(128).subtract(BigInteger.ONE)));
        out.add(intOf(NumType.U128, two.pow(127)));
        // The 2^53 neighbourhood, where a fold through double stops being exact.
        for (int d : new int[] {-1, 0, 1}) {
            BigInteger v = two.pow(53).add(BigInteger.valueOf(d));
            out.add(intOf(NumType.I64, v));
            out.add(intOf(NumType.U64, v));
            out.add(intOf(NumType.I64, v.negate()));
        }
        for (String v : new String[] {"1234567890123456789", "9007199254740993",
                "9223372036854775807"}) {
            out.add(intOf(NumType.I64, new BigInteger(v)));
        }
        for (double d : new double[] {0.0, -0.0, 1.0, -1.0, Double.MIN_NORMAL,
                -Double.MIN_NORMAL, Double.MIN_VALUE, Double.MAX_VALUE,
                -Double.MAX_VALUE, Double.POSITIVE_INFINITY,
                Double.NEGATIVE_INFINITY, Double.NaN, 9007199254740992.0,
                9007199254740994.0}) {
            out.add(new Value.Float(NumType.F64, d));
        }
        for (float f : new float[] {0.0f, -0.0f, 1.0f, -1.0f, Float.MAX_VALUE,
                -Float.MAX_VALUE, Float.POSITIVE_INFINITY}) {
            out.add(new Value.Float(NumType.F32, f));
        }
        return out;
    }

    /**
     * At least one value per ordered group, deliberately heterogeneous: rule
     * 10's cross-type order is only exercised if the corpus crosses group
     * boundaries, and the transitivity check is worthless on a set that does
     * not.
     */
    private static List<Value> orderedCorpus() {
        List<Value> out = new ArrayList<>();
        out.add(Value.NULL);
        out.add(Value.FALSE);
        out.add(Value.TRUE);
        out.addAll(torturedNumbers());
        out.addAll(List.of(
                new Value.Char(0x41),
                new Value.Char(0x00),
                new Value.Char(0x10FFFF),
                new Value.Str(""),
                new Value.Str("a"),
                new Value.Str("ab"),
                new Value.Str("b"),
                new Value.Str("é"),
                new Value.Str("一"),
                // U+FF61 and U+1F600 together are what make the pair sweep a
                // control for the UTF-16 mistake: U+FF61 is one UTF-16 unit
                // (0xFF61) and U+1F600 is a surrogate pair starting 0xD83D, so
                // String.compareTo orders them the opposite way to UTF-8.
                new Value.Str("｡"), // U+FF61
                new Value.Str("😀"), // U+1F600, above the BMP
                new Value.Bytes(new byte[] {}),
                new Value.Bytes(new byte[] {0}),
                new Value.Bytes(new byte[] {0, 0}),
                new Value.Bytes(new byte[] {(byte) 0xFF}),
                new Value.NitriteId(0),
                new Value.NitriteId(-1),
                new Value.NitriteId(1),
                new Value.NitriteId(Long.MAX_VALUE),
                new Value.NitriteId(Long.MIN_VALUE),
                new Value.Uuid(new byte[16]),
                new Value.Uuid(filled((byte) 0xFF)),
                new Value.Uuid(first1()),
                new Value.Timestamp(0),
                new Value.Timestamp(1000),
                new Value.Timestamp(-1),
                new Value.TimestampNs(1, 0), // equals Timestamp(1000) -- rule 7
                new Value.TimestampNs(0, 1),
                new Value.Zoned(1000, "Asia/Kolkata"),
                new Value.Date(0),
                new Value.Date(-1),
                new Value.Date(19000),
                new Value.Time(0),
                new Value.Time(86_399_999_999_999L),
                new Value.Duration(0, 0),
                new Value.Duration(-1, 999_999_999),
                new Value.Duration(1, 1),
                new Value.Array(List.of()),
                new Value.Array(List.of(Value.FALSE)),
                new Value.Array(List.of(Value.TRUE)),
                new Value.Array(List.of(Value.FALSE, Value.FALSE))));
        return out;
    }

    /** Ordered by rule 8, but with no key encoding. */
    private static List<Value> unencodableButOrdered() {
        return List.of(
                doc(),
                doc("a", Value.FALSE),
                doc("a", Value.TRUE),
                new Value.Map(List.of()),
                new Value.Map(List.of(new Value.Map.Entry(new Value.Str("a"), Value.FALSE))),
                new Value.Map(List.of(new Value.Map.Entry(new Value.Str("a"), Value.TRUE))));
    }

    private static byte[] filled(byte b) {
        byte[] x = new byte[16];
        Arrays.fill(x, b);
        return x;
    }

    private static byte[] first1() {
        byte[] x = new byte[16];
        x[0] = 1;
        return x;
    }

    private static Value.Doc doc(Object... kv) {
        LinkedHashMap<String, Value> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], (Value) kv[i + 1]);
        }
        return new Value.Doc(m);
    }

    private static int sign(int v) {
        return Integer.compare(v, 0);
    }

    // ------------------------------------------------------------------
    // the chapter's reason for existing
    // ------------------------------------------------------------------

    @Test
    @DisplayName("CKE byte order is the §8 value order, for every encodable pair")
    void ckeAgreesWithTheValueOrder() {
        List<Value> keyable = orderedCorpus().stream().filter(Cke::isKeyEncodable).toList();
        assertTrue(keyable.size() > 100,
                "the corpus must be big enough for the sweep to mean something");
        List<byte[]> keys = keyable.stream().map(Cke::encode).toList();

        int strict = 0;
        for (int i = 0; i < keyable.size(); i++) {
            for (int j = 0; j < keyable.size(); j++) {
                Value a = keyable.get(i);
                Value b = keyable.get(j);
                int want = sign(Compare.compare(a, b));
                int got = sign(Arrays.compareUnsigned(keys.get(i), keys.get(j)));
                if (want == 0) {
                    // Clause 2 of `03-key-encoding.md` §1: values the order
                    // calls equal may still differ in the trailing numeric type
                    // code. Everything before that byte must match.
                    if (got != 0) {
                        assertArrayPrefixEquals(keys.get(i), keys.get(j), a, b);
                    }
                    continue;
                }
                strict++;
                assertEquals(want, got, () -> "CKE order disagrees with §8\n  a = " + a
                        + "\n  b = " + b + "\n  compare says " + sign(Compare.compare(a, b))
                        + ", memcmp says " + sign(Arrays.compareUnsigned(
                                Cke.encode(a), Cke.encode(b))));
            }
        }
        // The bound's job is to catch a corpus that silently shrank: a sweep
        // over three values also "passes" every assertion above it.
        assertTrue(strict > 10_000, "only " + strict + " strict pairs");
    }

    private static void assertArrayPrefixEquals(byte[] ka, byte[] kb, Value a, Value b) {
        assertEquals(ka.length, kb.length, () -> "equal values, different key lengths: "
                + a + " vs " + b);
        assertArrayEqualsUnsigned(Arrays.copyOf(ka, ka.length - 1),
                Arrays.copyOf(kb, kb.length - 1),
                "equal values whose ordering regions differ: " + a + " vs " + b);
    }

    private static void assertArrayEqualsUnsigned(byte[] a, byte[] b, String why) {
        assertEquals(0, Arrays.compareUnsigned(a, b), why);
    }

    @Test
    @DisplayName("rule 10: the cross-group order is the group tag order")
    void crossGroupOrderFollowsTheGroupTag() {
        List<Value> keyable = orderedCorpus().stream().filter(Cke::isKeyEncodable).toList();
        for (Value a : keyable) {
            for (Value b : keyable) {
                int ga = Cke.encode(a)[0] & 0xFF;
                int gb = Cke.encode(b)[0] & 0xFF;
                if (ga == gb) {
                    continue;
                }
                assertEquals(sign(Integer.compare(ga, gb)), sign(Compare.compare(a, b)),
                        () -> "cross-group order must follow the group tag: " + a + " vs " + b);
            }
        }
    }

    @Test
    @DisplayName("rule 10: ARRAY < MAP < DOC, and that order is normative")
    void arrayIsBelowMapIsBelowDoc() {
        // Not a matter of taste: this is the assertion the Dart and Rust
        // implementations failed in *opposite* directions before §8 pinned it,
        // and it is unobservable from any file because these ranks are never
        // written down. Only a test that names the order holds the three
        // implementations together.
        Value arr = new Value.Array(List.of());
        Value map = new Value.Map(List.of());
        Value dc = doc();
        assertTrue(Compare.compare(arr, map) < 0);
        assertTrue(Compare.compare(map, dc) < 0);
        assertTrue(Compare.compare(arr, dc) < 0);
        for (Value v : List.of(arr, map, dc)) {
            assertTrue(Compare.compare(new Value.Str("zzz"), v) < 0, v.toString());
        }
    }

    // ------------------------------------------------------------------
    // it has to be an order at all
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the order is reflexive and antisymmetric")
    void theOrderIsReflexiveAndAntisymmetric() {
        List<Value> all = new ArrayList<>(orderedCorpus());
        all.addAll(unencodableButOrdered());
        for (Value a : all) {
            assertEquals(0, Compare.compare(a, a), () -> a + " is not equal to itself");
            assertTrue(Compare.valuesEqual(a, a));
            for (Value b : all) {
                assertEquals(sign(Compare.compare(a, b)), -sign(Compare.compare(b, a)),
                        () -> "not antisymmetric: " + a + " vs " + b);
            }
        }
    }

    @Test
    @DisplayName("sorting by it produces a pairwise ordered sequence")
    void sortingProducesAPairwiseOrderedSequence() {
        // A comparator that is not transitive cannot produce a sequence that is
        // pairwise ordered, so this catches it without the O(n^3) sweep.
        List<Value> all = new ArrayList<>(orderedCorpus());
        all.addAll(unencodableButOrdered());
        all.sort(Compare.comparator());
        for (int i = 0; i < all.size(); i++) {
            for (int j = i + 1; j < all.size(); j++) {
                int i0 = i;
                int j0 = j;
                assertTrue(Compare.compare(all.get(i), all.get(j)) <= 0,
                        () -> "sort produced an unordered sequence:\n  [" + i0 + "] "
                                + all.get(i0) + "\n  [" + j0 + "] " + all.get(j0));
            }
        }
    }

    // ------------------------------------------------------------------
    // the ten rules
    // ------------------------------------------------------------------

    @Test
    @DisplayName("rule 1: NULL equals only NULL and sorts below everything")
    void rule1() {
        assertEquals(0, Compare.compare(Value.NULL, Value.NULL));
        for (Value v : orderedCorpus()) {
            if (v instanceof Value.Null) {
                continue;
            }
            assertTrue(Compare.compare(Value.NULL, v) < 0, () -> "vs " + v);
        }
    }

    @Test
    @DisplayName("rule 2: every numeric tag is one domain, compared exactly")
    void rule2() {
        assertEquals(0, Compare.compare(intOf(NumType.I32, BigInteger.valueOf(5)),
                intOf(NumType.I64, BigInteger.valueOf(5))));
        assertEquals(0, Compare.compare(intOf(NumType.I32, BigInteger.valueOf(5)),
                new Value.Float(NumType.F64, 5.0)));
        assertEquals(0, Compare.compare(intOf(NumType.U8, BigInteger.valueOf(5)),
                new Value.Float(NumType.F32, 5.0f)));
        // 2^53+1 against the double that 2^53+1 rounds to. A fold through
        // double calls these equal; exact arithmetic does not.
        Value big = intOf(NumType.I64, BigInteger.TWO.pow(53).add(BigInteger.ONE));
        assertTrue(Compare.compare(big, new Value.Float(NumType.F64, 9007199254740992.0)) > 0);
        // 2^100 is about 1.2677e30, so it straddles 1e30 and 1e31 -- which is
        // the point: no long or double fold can place it against both.
        Value huge = intOf(NumType.I128, BigInteger.TWO.pow(100));
        assertTrue(Compare.compare(huge, new Value.Float(NumType.F64, 1e30)) > 0);
        assertTrue(Compare.compare(huge, new Value.Float(NumType.F64, 1e31)) < 0);
    }

    @Test
    @DisplayName("rule 3: NaN equals NaN and sorts above every number")
    void rule3Nan() {
        Value nan = new Value.Float(NumType.F64, Double.NaN);
        assertEquals(0, Compare.compare(nan, nan), "a NaN key must be findable");
        assertTrue(Compare.compare(nan,
                new Value.Float(NumType.F64, Double.POSITIVE_INFINITY)) > 0);
        assertTrue(Compare.compare(nan,
                intOf(NumType.I128, BigInteger.TWO.pow(127).subtract(BigInteger.ONE))) > 0);
        // Two NaN payloads are one value, which is what makes a key that
        // cannot preserve the payload legitimate.
        Value other = new Value.Float(NumType.F64,
                Double.longBitsToDouble(0x7FF8000000000001L));
        assertEquals(0, Compare.compare(nan, other));
    }

    @Test
    @DisplayName("rule 3: -0.0 equals +0.0")
    void rule3NegativeZero() {
        assertEquals(0, Compare.compare(new Value.Float(NumType.F64, -0.0),
                new Value.Float(NumType.F64, 0.0)));
        assertEquals(0, Compare.compare(new Value.Float(NumType.F64, -0.0),
                intOf(NumType.I32, BigInteger.ZERO)));
        assertEquals(0, Compare.compare(new Value.Float(NumType.F32, -0.0f),
                new Value.Float(NumType.F64, 0.0)));
    }

    @Test
    @DisplayName("rule 4: STR compares by UTF-8 byte order, not by UTF-16 code unit")
    void rule4() {
        // The case that separates them, and the one Java gets wrong by
        // default. U+FF61 is one UTF-16 unit (0xFF61); U+1F600 is a surrogate
        // pair starting 0xD83D -- lower in UTF-16, higher in code point and so
        // higher in UTF-8. String.compareTo is UTF-16 unit order and inverts.
        Value a = new Value.Str("｡");
        Value b = new Value.Str("😀");
        assertTrue(Compare.compare(a, b) < 0, "code-point order puts U+FF61 below U+1F600");
        assertTrue("｡".compareTo("😀") > 0,
                "if this fails the test's premise is gone: String.compareTo must "
                        + "disagree, or the case proves nothing");
        assertTrue(Compare.compare(new Value.Str("ab"), new Value.Str("abc")) < 0);
        assertTrue(Compare.compare(new Value.Str(""), new Value.Str("a")) < 0);
    }

    @Test
    @DisplayName("rule 4: no locale, no case folding, no normalization")
    void rule4NoCollation() {
        assertTrue(Compare.compare(new Value.Str("A"), new Value.Str("a")) < 0);
        assertNotEquals(0, Compare.compare(new Value.Str("é"),
                new Value.Str("é")),
                "§8 rule 4 forbids normalization in the comparison");
    }

    @Test
    @DisplayName("rule 5: BYTES is lexicographic, shorter-is-smaller on a prefix")
    void rule5() {
        assertTrue(Compare.compare(new Value.Bytes(new byte[] {1, 2}),
                new Value.Bytes(new byte[] {1, 2, 0})) < 0);
        assertTrue(Compare.compare(new Value.Bytes(new byte[] {}),
                new Value.Bytes(new byte[] {0})) < 0);
        // Unsigned: 0xFF is above 0x01, which a signed byte compare inverts.
        assertTrue(Compare.compare(new Value.Bytes(new byte[] {(byte) 0xFF}),
                new Value.Bytes(new byte[] {1})) > 0);
    }

    @Test
    @DisplayName("rule 6: CHAR is not a one-character STR")
    void rule6() {
        assertNotEquals(0, Compare.compare(new Value.Char(0x61), new Value.Str("a")));
        assertTrue(Compare.compare(new Value.Char(0x41), new Value.Char(0x61)) < 0);
    }

    @Test
    @DisplayName("rule 7: the three instant tags compare as one instant")
    void rule7() {
        assertEquals(0, Compare.compare(new Value.Timestamp(1000),
                new Value.TimestampNs(1, 0)));
        assertEquals(0, Compare.compare(new Value.Timestamp(1000),
                new Value.Zoned(1000, "UTC")));
        assertEquals(0, Compare.compare(new Value.Zoned(1000, "UTC"),
                new Value.Zoned(1000, "Asia/Kolkata")),
                "ZONED denotes an instant; the zone is display, not order");
        assertTrue(Compare.compare(new Value.TimestampNs(1, 0),
                new Value.TimestampNs(1, 1)) < 0);
        // Before the epoch, floor division rather than truncation: -1 ms is
        // (-1 s, 999 ms), which is below 0 and above -2 s.
        assertTrue(Compare.compare(new Value.Timestamp(-1), new Value.Timestamp(0)) < 0);
        assertEquals(0, Compare.compare(new Value.Timestamp(-1),
                new Value.TimestampNs(-1, 999_000_000)));
    }

    @Test
    @DisplayName("rule 7: DATE, TIME and DURATION are not comparable to instants")
    void rule7Subclasses() {
        Value ts = new Value.Timestamp(0);
        for (Value v : List.of(new Value.Date(0), new Value.Time(0),
                new Value.Duration(0, 0))) {
            assertNotEquals(0, Compare.compare(ts, v), () -> "vs " + v);
            assertEquals(sign(Compare.compare(ts, v)), -sign(Compare.compare(v, ts)));
        }
    }

    @Test
    @DisplayName("rule 8: ARRAY compares element-wise, then by length")
    void rule8Array() {
        assertTrue(Compare.compare(new Value.Array(List.of(Value.FALSE)),
                new Value.Array(List.of(Value.TRUE))) < 0);
        assertTrue(Compare.compare(new Value.Array(List.of(Value.FALSE)),
                new Value.Array(List.of(Value.FALSE, Value.FALSE))) < 0,
                "a prefix sorts first");
        // Element-wise beats length: [true] > [false, false].
        assertTrue(Compare.compare(new Value.Array(List.of(Value.TRUE)),
                new Value.Array(List.of(Value.FALSE, Value.FALSE))) > 0);
    }

    @Test
    @DisplayName("rule 8: DOC and MAP compare as their sorted (key, value) sequences")
    void rule8DocAndMap() {
        assertTrue(Compare.compare(doc("a", Value.FALSE), doc("a", Value.TRUE)) < 0);
        // Field insertion order must not matter: a DOC is its *sorted*
        // sequence, and a LinkedHashMap preserves the order a caller used.
        assertEquals(0, Compare.compare(
                doc("a", Value.FALSE, "b", Value.TRUE),
                doc("b", Value.TRUE, "a", Value.FALSE)),
                "a DOC is its sorted field sequence, not its literal order");
        assertTrue(Compare.compare(
                new Value.Map(List.of(new Value.Map.Entry(new Value.Str("a"), Value.FALSE))),
                new Value.Map(List.of(new Value.Map.Entry(new Value.Str("b"), Value.FALSE))))
                < 0);
    }

    @Test
    @DisplayName("rule 8: DOC and MAP are ordered but are not keys")
    void rule8NotKeys() {
        for (Value v : unencodableButOrdered()) {
            assertTrue(Compare.isOrdered(v), v.toString());
            assertFalse(Cke.isKeyEncodable(v), v + " has no key encoding");
        }
    }

    @Test
    @DisplayName("rule 9: FALSE < TRUE")
    void rule9() {
        assertTrue(Compare.compare(Value.FALSE, Value.TRUE) < 0);
        assertEquals(0, Compare.compare(Value.TRUE, Value.TRUE));
    }

    // ------------------------------------------------------------------
    // the refusals
    // ------------------------------------------------------------------

    @Test
    @DisplayName("comparing two unordered values is an error, never \"equal\"")
    void unorderedIsRefused() {
        // Returning equal is the dangerous answer, not the conservative one: it
        // makes two different geometries indistinguishable to a sort, a
        // deduplication and an equality check.
        List<Value> unordered = List.of(
                new Value.Regex("a", ""),
                new Value.Vector(0, 1, new byte[4]),
                new Value.Geometry(new byte[] {1, 1, 0, 0, 0}),
                new Value.Opaque("java", "java.lang.Object", new byte[] {1}),
                new Value.Unknown(0xEE, new byte[] {1}));
        for (Value v : unordered) {
            assertFalse(Compare.isOrdered(v), v + " must not be ordered");
            assertFalse(Cke.isKeyEncodable(v), v + " must have no key encoding");
            assertThrows(InvalidArgumentException.class,
                    () -> Compare.compare(v, Value.NULL), v + " on the left");
            assertThrows(InvalidArgumentException.class,
                    () -> Compare.compare(Value.NULL, v), v + " on the right");
        }
        Value g1 = new Value.Geometry(new byte[] {1, 1, 0, 0, 0});
        Value g2 = new Value.Geometry(new byte[] {1, 2, 0, 0, 0});
        assertThrows(InvalidArgumentException.class, () -> Compare.compare(g1, g2));
        assertFalse(Compare.valuesEqual(g1, g2), "different geometries are not equal");
        assertTrue(Compare.valuesEqual(g1, new Value.Geometry(new byte[] {1, 1, 0, 0, 0})),
                "and identical ones still are");
    }

    @Test
    @DisplayName("DEC128 is refused rather than approximated")
    void dec128IsRefused() {
        // Rule 2 puts DEC128 in the numeric domain, and this implementation has
        // no exact decimal arithmetic. Approximating it is how another
        // implementation came to compare every DEC128 as zero.
        byte[] five = new byte[16];
        five[0] = 5;
        byte[] nine = new byte[16];
        nine[0] = 9;
        Value d5 = new Value.Dec128(five);
        Value d9 = new Value.Dec128(nine);
        assertTrue(Compare.isOrdered(d5), "§8 rule 2 puts DEC128 in the numeric domain");
        assertFalse(Cke.isKeyEncodable(d5), "§4.4: no key encoding");
        assertThrows(InvalidArgumentException.class, () -> Compare.compare(d5, d9));
        assertThrows(InvalidArgumentException.class,
                () -> Compare.compare(d5, intOf(NumType.I32, BigInteger.ZERO)));
        assertFalse(Compare.valuesEqual(d5, intOf(NumType.I32, BigInteger.ZERO)));
        assertFalse(Compare.valuesEqual(d5, d9));
        assertTrue(Compare.valuesEqual(d5, new Value.Dec128(five)));
    }

    @Test
    @DisplayName("an unordered element never makes a container comparison throw")
    void anUnorderedElementKeepsContainersTotal() {
        // §8 gives no order for an unordered *element*, but sorting a list of
        // documents has to stay defined. The container ranks such an element
        // deterministically; the containers themselves stay ordered.
        Value a = new Value.Array(List.of(new Value.Geometry(new byte[] {1})));
        Value b = new Value.Array(List.of(new Value.Geometry(new byte[] {2})));
        assertEquals(sign(Compare.compare(a, b)), -sign(Compare.compare(b, a)));
        assertEquals(0, Compare.compare(a, a));
    }

    // ------------------------------------------------------------------
    // compareNumeric on its own
    // ------------------------------------------------------------------

    @Test
    @DisplayName("compareNumeric agrees with compare on every numeric pair")
    void compareNumericAgrees() {
        List<Value> nums = torturedNumbers();
        for (Value a : nums) {
            for (Value b : nums) {
                assertEquals(sign(Compare.compare(a, b)), sign(Compare.compareNumeric(a, b)),
                        () -> a + " vs " + b);
            }
        }
    }

    @Test
    @DisplayName("compareNumeric spans the whole 128-bit range without a fold")
    void compareNumericSpans128Bits() {
        Value i128max = intOf(NumType.I128, BigInteger.TWO.pow(127).subtract(BigInteger.ONE));
        Value u128max = intOf(NumType.U128, BigInteger.TWO.pow(128).subtract(BigInteger.ONE));
        assertTrue(Compare.compareNumeric(i128max, u128max) < 0);
        assertTrue(Compare.compareNumeric(u128max,
                new Value.Float(NumType.F64, Double.POSITIVE_INFINITY)) < 0);
        assertTrue(Compare.compareNumeric(intOf(NumType.I128, BigInteger.TWO.pow(127).negate()),
                new Value.Float(NumType.F64, Double.NEGATIVE_INFINITY)) > 0);
    }
}
