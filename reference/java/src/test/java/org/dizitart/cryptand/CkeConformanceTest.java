package org.dizitart.cryptand;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * CKE against the shared vectors — {@code spec/03-key-encoding.md}.
 */
class CkeConformanceTest {

    @Test
    @DisplayName("every cke/values.json case encodes and decodes byte-exactly")
    void ckeValues() {
        JsonNode doc = Vectors.load("cke/values.json");
        for (JsonNode c : doc.get("cases")) {
            Value v = Vectors.value(c.get("value"));
            byte[] expected = Vectors.hex(c.get("cke").asText());
            byte[] actual = Cke.encode(v);
            assertArrayEquals(expected, actual,
                    () -> "encode " + v + " (" + c.path("note").asText() + "): expected "
                            + c.get("cke").asText() + ", got " + Vectors.hex(actual));

            // §7: CKE is injective and decodable, with three documented lossy
            // cases that live in numbers/torture.json rather than here.
            Value back = Cke.decode(expected);
            assertArrayEquals(expected, Cke.encode(back),
                    () -> "re-encode after decode of " + c.get("cke").asText());
        }
    }

    @Test
    @DisplayName("every cke/values.json reject is refused, not guessed at")
    void ckeRejects() {
        JsonNode doc = Vectors.load("cke/values.json");
        for (JsonNode r : doc.get("rejects")) {
            byte[] bytes = Vectors.hex(r.get("cke").asText());
            String why = r.get("why").asText();
            assertThrows(CryptandException.class, () -> Cke.decode(bytes),
                    () -> "should refuse (" + why + "): " + r.get("cke").asText());
        }
    }

    @Test
    @DisplayName("the numeric torture set encodes byte-exactly, all 170 of it")
    void tortureEncodes() {
        JsonNode doc = Vectors.load("numbers/torture.json");
        assertEquals(doc.get("count").asInt(), doc.get("entries").size());
        for (JsonNode e : doc.get("entries")) {
            Value v = Vectors.value(e.get("value"));
            assertArrayEquals(Vectors.hex(e.get("cke").asText()), Cke.encode(v),
                    () -> "encode " + v + ": expected " + e.get("cke").asText()
                            + ", got " + Vectors.hex(Cke.encode(v)));
        }
    }

    @Test
    @DisplayName("sorting the torture set by CKE bytes reproduces the published order")
    void tortureSortOrder() {
        JsonNode doc = Vectors.load("numbers/torture.json");
        List<byte[]> keys = new ArrayList<>();
        for (JsonNode e : doc.get("entries")) {
            keys.add(Cke.encode(Vectors.value(e.get("value"))));
        }
        keys.sort(Cke::compare);

        List<String> expected = new ArrayList<>();
        for (JsonNode h : doc.get("sorted_by_cke")) {
            expected.add(h.asText());
        }
        List<String> actual = new ArrayList<>();
        for (byte[] k : keys) {
            actual.add(Vectors.hex(k));
        }
        assertEquals(expected, actual);
    }

    /**
     * The invariant of §1, over the full cross product of the torture set.
     *
     * <p>Checked against an <strong>independent</strong> exact comparator built
     * from {@link BigDecimal}, which shares no code with the encoder. A test
     * that compared CKE against the library's own comparator would pass
     * whenever the two were wrong in the same way, which is the only way they
     * are ever wrong.
     *
     * <p>Note the shape of clause 2. A plain "same sign as" would be false:
     * {@code I8(0)} and {@code I16(0)} are logically equal and encode
     * differently, and they must, because the type code is what keeps an
     * exact-type point lookup a point lookup.
     */
    @Test
    @DisplayName("CKE order refines logical order over all 170x170 torture pairs")
    void tortureOrderInvariant() {
        JsonNode doc = Vectors.load("numbers/torture.json");
        List<Value> values = new ArrayList<>();
        List<byte[]> keys = new ArrayList<>();
        for (JsonNode e : doc.get("entries")) {
            Value v = Vectors.value(e.get("value"));
            values.add(v);
            keys.add(Cke.encode(v));
        }

        int pairs = 0;
        for (int i = 0; i < values.size(); i++) {
            for (int j = 0; j < values.size(); j++) {
                int logical = exactCompare(values.get(i), values.get(j));
                int memcmp = Cke.compare(keys.get(i), keys.get(j));
                pairs++;
                if (logical != 0) {
                    assertEquals(Integer.signum(logical), Integer.signum(memcmp),
                            "clause 1 violated for " + values.get(i) + " vs " + values.get(j)
                                    + ": logical " + logical + ", memcmp " + memcmp);
                } else {
                    // Clause 2: equal values differ only in the trailing type
                    // code, so both lie inside [N(v), successor(N(v))).
                    byte[] a = keys.get(i);
                    byte[] b = keys.get(j);
                    assertEquals(a.length, b.length,
                            "clause 2: equal values " + values.get(i) + " and " + values.get(j)
                                    + " have different key lengths");
                    for (int k = 0; k < a.length - 1; k++) {
                        assertEquals(a[k], b[k],
                                "clause 2: equal values " + values.get(i) + " and " + values.get(j)
                                        + " differ before the type code, at byte " + k);
                    }
                }
            }
        }
        assertEquals(170 * 170, pairs);
    }

    @Test
    @DisplayName("the three lossy decodings are lossy exactly as specified")
    void lossyDecodings() {
        JsonNode doc = Vectors.load("numbers/torture.json");
        for (JsonNode l : doc.get("lossy_decodings")) {
            byte[] cke = Vectors.hex(l.get("cke").asText());
            if (l.has("input")) {
                assertArrayEquals(cke, Cke.encode(Vectors.value(l.get("input"))),
                        () -> "encode " + l.get("why").asText());
            }
            Value expected = Vectors.value(l.get("decodes_to"));
            Value actual = Cke.decode(cke);
            assertEquals(expected, actual, () -> l.get("why").asText());
        }
    }

    @Test
    @DisplayName("strings compare by UTF-8 byte order, and the escape is self-delimiting")
    void strings() {
        JsonNode doc = Vectors.load("strings/cases.json");
        for (JsonNode c : doc.get("cases")) {
            String s = new String(Vectors.hex(c.get("utf8").asText()), StandardCharsets.UTF_8);
            Value.Str v = new Value.Str(s);
            byte[] cke = Vectors.hex(c.get("cke").asText());
            assertArrayEquals(cke, Cke.encode(v), () -> "cke of " + c.path("note").asText());
            assertArrayEquals(Vectors.hex(c.get("cve").asText()), Cve.encode(v),
                    () -> "cve of " + c.path("note").asText());
            assertEquals(v, Cke.decode(cke));
        }
    }

    /**
     * The orderings the string vectors' own notes assert.
     *
     * <p>Deliberately not "the published cases ascend": they do not, and
     * assuming they did is how this test first failed. Case 4 is {@code "a\0b"},
     * whose whole point is that it sorts <em>between</em> {@code "a"} and
     * {@code "ab"} — the escape maps NUL to {@code 00 01}, which is above the
     * {@code 00 00} terminator and below {@code 'b'}. Asserting a sequence
     * instead of the relations would have hidden that.
     */
    @Test
    @DisplayName("a shorter string sorts before one that extends it, and NUL escapes in between")
    void stringOrdering() {
        assertAscending("", "a", "ab", "abc");
        assertAscending("a", "a\u0000b", "ab");
        // No normalization, no case folding, no locale: NFC and NFD are
        // different keys for the same text, and that is the specified answer.
        assertTrue(Cke.compare(Cke.encode(new Value.Str("\u00e9")),
                Cke.encode(new Value.Str("e\u0301"))) != 0);
    }

    private static void assertAscending(String... ss) {
        for (int i = 1; i < ss.length; i++) {
            byte[] lo = Cke.encode(new Value.Str(ss[i - 1]));
            byte[] hi = Cke.encode(new Value.Str(ss[i]));
            assertTrue(Cke.compare(lo, hi) < 0,
                    () -> "expected " + Vectors.hex(lo) + " < " + Vectors.hex(hi));
        }
    }

    @Test
    @DisplayName("an unpaired surrogate is refused on write, not replaced")
    void rejectsUnpairedSurrogatesOnWrite() {
        JsonNode doc = Vectors.load("strings/cases.json");
        for (JsonNode r : doc.get("rejects_on_write")) {
            int unit = Integer.parseInt(r.get("utf16").asText(), 16);
            String s = String.valueOf((char) unit);
            assertThrows(InvalidArgumentException.class, () -> Cke.encode(new Value.Str(s)),
                    () -> "should refuse on write: " + r.get("why").asText());
        }
    }

    @Test
    @DisplayName("ill-formed UTF-8 is corruption, never U+FFFD")
    void rejectsIllFormedUtf8OnRead() {
        JsonNode doc = Vectors.load("strings/cases.json");
        for (JsonNode r : doc.get("rejects_on_read")) {
            byte[] raw = Vectors.hex(r.get("utf8").asText());
            ByteWriter w = new ByteWriter();
            w.u8(Cke.Group.STRING);
            Cke.writeEsc(w, raw);
            byte[] key = w.toBytes();
            assertThrows(CorruptionException.class, () -> Cke.decode(key),
                    () -> "should report corruption: " + r.get("why").asText());
        }
    }

    @Test
    @DisplayName("N(v) has no type code, so eq(5) spans every numeric type")
    void numericPrefixSpansTypes() {
        // §8.2's worked example, which is the reason the helper exists at all.
        byte[] n = Cke.numericPrefix(Value.i32(5));
        assertEquals("30034002a00000", Vectors.hex(n));
        byte[] upper = Cke.successor(n);
        assertEquals("30034002a00001", Vectors.hex(upper));

        for (Value v : List.of(Value.i32(5), Value.i64(5), Value.integer(NumType.I8, 5),
                Value.integer(NumType.U8, 5), Value.f64(5.0), Value.f32(5.0))) {
            byte[] k = Cke.encode(v);
            assertTrue(Cke.compare(n, k) <= 0 && Cke.compare(k, upper) < 0,
                    v + " should fall inside [N(5), successor(N(5)))");
        }
        // And 5.5 must not, or the bound is not a bound.
        assertTrue(Cke.compare(Cke.encode(Value.f64(5.5)), upper) >= 0);
    }

    @Test
    @DisplayName("successor of an all-0xFF key is unbounded, which is why tag 0xFF is reserved")
    void successorDegenerates() {
        assertEquals(Cke.UNBOUNDED_ABOVE, Cke.successor(new byte[]{(byte) 0xFF, (byte) 0xFF}));
        assertEquals(Cke.UNBOUNDED_ABOVE, Cke.successor(new byte[0]));
        // §8.2: successor(30 02) is 30 03 — "all zeros" ends exactly where
        // "positive finite" begins.
        assertArrayEquals(Vectors.hex("3003"), Cke.successor(Vectors.hex("3002")));
    }

    /**
     * §4.4. {@code DEC128} is the type that looks encodable and is not: the
     * normalization produces an exact {@code m x 2^e}, and most decimal
     * fractions have no finite binary fraction, so it can be neither encoded
     * exactly nor ordered against an {@code f64} without silently rounding one
     * of them. It stores fine and round-trips fully as a value.
     */
    @Test
    @DisplayName("DEC128 stores as a value and is refused as a key")
    void dec128IsNotAKey() {
        Value.Dec128 d = new Value.Dec128(Vectors.hex("2206000000000000000000000000007b"));
        assertEquals(d, Cve.decode(Cve.encode(d)));
        assertFalse(Cke.isKeyEncodable(d));
        assertThrows(InvalidArgumentException.class, () -> Cke.encode(d));
    }

    // ------------------------------------------------------------------
    // an exact comparator that shares nothing with the encoder
    // ------------------------------------------------------------------

    /**
     * {@code spec/02-value-encoding.md} §8 rules 2 and 3, for the numeric
     * domain, computed exactly: every finite value is turned into a
     * {@link BigDecimal}, which is exact for both an integer magnitude up to
     * 2<sup>128</sup> and for any binary float.
     */
    private static int exactCompare(Value a, Value b) {
        int ca = numericClass(a);
        int cb = numericClass(b);
        if (ca != cb) {
            return Integer.compare(ca, cb);
        }
        if (ca != 0) {
            // Both are -Inf, both +Inf, or both NaN: rule 3 makes them equal.
            return 0;
        }
        return exact(a).compareTo(exact(b));
    }

    /** -1 for -Inf, 0 for finite, 1 for +Inf, 2 for NaN. Rule 3's ordering. */
    private static int numericClass(Value v) {
        if (v instanceof Value.Float f) {
            if (Double.isNaN(f.value())) {
                return 2;
            }
            if (Double.isInfinite(f.value())) {
                return f.value() > 0 ? 1 : -1;
            }
        }
        return 0;
    }

    private static BigDecimal exact(Value v) {
        if (v instanceof Value.Int i) {
            BigInteger mag = i.magnitude().toBigInteger();
            return new BigDecimal(i.negative() ? mag.negate() : mag);
        }
        if (v instanceof Value.Float f) {
            // BigDecimal(double) is the exact binary value, which is the point.
            return new BigDecimal(f.value());
        }
        return fail("not a number: " + v);
    }
}
