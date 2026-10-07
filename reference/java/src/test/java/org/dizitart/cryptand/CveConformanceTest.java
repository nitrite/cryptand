package org.dizitart.cryptand;

import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.util.Tag;
import org.dizitart.cryptand.util.U128;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NameDict;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CVE against the shared vectors — {@code spec/02-value-encoding.md}.
 */
class CveConformanceTest {

    @Test
    @DisplayName("every cve/values.json case encodes and decodes byte-exactly")
    void cveValues() {
        JsonNode doc = Vectors.load("cve/values.json");
        for (JsonNode c : doc.get("cases")) {
            Value v = Vectors.value(c.get("value"));
            byte[] expected = Vectors.hex(c.get("cve").asText());
            byte[] actual = Cve.encode(v);
            assertArrayEquals(expected, actual,
                    () -> "encode " + v + " (" + c.path("note").asText() + "): expected "
                            + c.get("cve").asText() + ", got " + Vectors.hex(actual));
            assertEquals(v, Cve.decode(expected), () -> "decode " + c.get("cve").asText());
        }
    }

    /**
     * §2: every length in CVE is untrusted input, and a decoder MUST verify that
     * a declared length fits inside the containing buffer <em>before</em>
     * allocating. That is a security requirement, not a robustness one — opening
     * a file another party produced is what this format exists for.
     */
    @Test
    @DisplayName("every cve/values.json reject fails cleanly, before allocating")
    void cveRejects() {
        JsonNode doc = Vectors.load("cve/values.json");
        for (JsonNode r : doc.get("rejects")) {
            byte[] bytes = Vectors.hex(r.get("cve").asText());
            String why = r.get("why").asText();
            assertThrows(CryptandException.class, () -> Cve.decode(bytes),
                    () -> "should refuse (" + why + "): " + r.get("cve").asText());
        }
    }

    @Test
    @DisplayName("a document encodes identically with and without the name dictionary")
    void documents() {
        JsonNode doc = Vectors.load("documents/cases.json");
        NameDict dict = Vectors.dictionary(doc.get("dictionary"));

        for (JsonNode c : doc.get("cases")) {
            Value v = Vectors.value(c.get("value"));
            if (c.has("cve")) {
                assertArrayEquals(Vectors.hex(c.get("cve").asText()), Cve.encode(v),
                        () -> c.path("note").asText());
                assertEquals(v, Cve.decode(Vectors.hex(c.get("cve").asText())),
                        () -> "decode " + c.path("note").asText());
                continue;
            }

            byte[] withDict = Vectors.hex(c.get("cve_with_dictionary").asText());
            byte[] withoutDict = Vectors.hex(c.get("cve_without_dictionary").asText());
            assertArrayEquals(withDict, Cve.encode(v, dict),
                    () -> "with dictionary: " + c.path("note").asText());
            assertArrayEquals(withoutDict, Cve.encode(v, null),
                    () -> "without dictionary: " + c.path("note").asText());

            // The dictionary is a space optimization and nothing else: both
            // encodings decode to the same document.
            assertEquals(v, Cve.decode(withDict, dict));
            assertEquals(v, Cve.decode(withoutDict, null));
            assertTrue(withDict.length < withoutDict.length,
                    "the dictionary should make the document smaller");

            // §5.1: the field table is sorted by resolved name bytes, not by
            // the numeric name_ref, or dictionary and inline names would
            // interleave arbitrarily.
            List<String> expectedOrder = new ArrayList<>();
            for (JsonNode f : c.get("field_order")) {
                expectedOrder.add(f.asText());
            }
            assertEquals(expectedOrder, new ArrayList<>(
                    ((Value.Doc) Cve.decode(withDict, dict)).fields().keySet()));
        }
    }

    /**
     * §5.4: the reserved fields SHOULD occupy {@code name_id} 1–5 in every data
     * tree's dictionary so that they encode in one byte. That is not decoration
     * — {@code _id} is on every document in every collection.
     */
    @Test
    @DisplayName("the reserved field ids are 1 to 5")
    void reservedFieldIds() {
        JsonNode expected = Vectors.load("documents/cases.json").get("reserved_field_ids");
        NameDict dict = NameDict.withReservedFields();
        for (Iterator<String> it = expected.fieldNames(); it.hasNext(); ) {
            String name = it.next();
            assertEquals(expected.get(name).asInt(), dict.idOf(name), name);
        }
    }

    /**
     * §1.1 and {@code spec/11-conformance.md} §4 rule 1. This is the case that
     * needs the length prefix: an {@code ARRAY} stores values back to back with
     * no offsets, so an unknown tag inside one is unskippable, and a reader that
     * met one without a length would have to abandon the whole array — losing
     * every <em>known</em> sibling with it.
     */
    @Test
    @DisplayName("an unknown tag inside an array round-trips byte for byte")
    void unknownTagSurvives() {
        Value.Unknown unknown = new Value.Unknown(0xC5, Vectors.hex("070707"));
        Value.Array a = new Value.Array(List.of(Value.of(1), unknown, new Value.Str("after")));
        byte[] encoded = Cve.encode(a);
        assertArrayEquals(Vectors.hex("200f030d02c50307070712056166746572"), encoded);

        Value back = Cve.decode(encoded);
        assertEquals(a, back);
        // The known siblings survive, which is the whole point.
        assertEquals(new Value.Str("after"), ((Value.Array) back).items().get(2));
        assertArrayEquals(encoded, Cve.encode(back));
    }

    @Test
    @DisplayName("an unassigned tag with no valid length is corruption, not a guess")
    void unassignedTagWithoutLengthIsCorruption() {
        // Tag 0x90 is in the reserved minor-version range, so it must carry a
        // uvar length. Here the length runs past the buffer.
        assertThrows(CryptandException.class, () -> Cve.decode(Vectors.hex("90ff")));
    }

    /**
     * §1.2: the declared width is metadata, never semantics. Equality and
     * ordering are by numeric value across every numeric tag, so an
     * implementation MUST NOT make {@code I32(5)} unequal to {@code I64(5)} as
     * <em>values</em> — while their encodings stay distinct so that each
     * round-trips its own type.
     */
    @Test
    @DisplayName("declared width round-trips and does not change the number")
    void declaredWidthIsMetadata() {
        for (NumType t : List.of(NumType.I8, NumType.I16, NumType.I32, NumType.I64,
                NumType.I128, NumType.U8, NumType.U16, NumType.U32, NumType.U64,
                NumType.U128, NumType.INT_VAR)) {
            Value.Int v = Value.integer(t, 5);
            assertEquals(v, Cve.decode(Cve.encode(v)), t.wireName());
            // One numeric domain: the CKE keys differ only in the type code.
            byte[] key = Cke.encode(v);
            assertArrayEquals(Cke.numericPrefix(Value.i32(5)),
                    java.util.Arrays.copyOf(key, key.length - 1), t.wireName());
        }
    }

    @Test
    @DisplayName("a map refuses a key that has no CKE encoding")
    void mapKeysMustBeKeyEncodable() {
        Map<String, Value> inner = new LinkedHashMap<>();
        inner.put("a", Value.of(1));
        Value.Map m = new Value.Map(List.of(
                new Value.Map.Entry(new Value.Doc(inner), Value.of(1))));
        assertThrows(InvalidArgumentException.class, () -> Cve.encode(m));
    }

    @Test
    @DisplayName("map entries are sorted by CKE(key), whatever order they arrive in")
    void mapEntriesAreSorted() {
        Value.Map m = new Value.Map(List.of(
                new Value.Map.Entry(Value.i32(3), new Value.Str("three")),
                new Value.Map.Entry(Value.i32(1), new Value.Str("one")),
                new Value.Map.Entry(Value.i32(2), new Value.Str("two"))));
        Value.Map back = (Value.Map) Cve.decode(Cve.encode(m));
        List<Value> keys = back.entries().stream().map(Value.Map.Entry::key).collect(java.util.stream.Collectors.toList());
        assertEquals(List.of(Value.i32(1), Value.i32(2), Value.i32(3)), keys);
    }

    @Test
    @DisplayName("a duplicate map key is refused on write")
    void duplicateMapKeyRefused() {
        Value.Map m = new Value.Map(List.of(
                new Value.Map.Entry(Value.i32(1), new Value.Str("a")),
                new Value.Map.Entry(Value.i32(1), new Value.Str("b"))));
        assertThrows(InvalidArgumentException.class, () -> Cve.encode(m));
    }

    /**
     * §2 and {@code spec/00-conventions.md} §8: a decoder MUST enforce the depth
     * limit of 100 and MUST NOT recurse unboundedly. A file another party wrote
     * is the input here, so an unbounded recursion is a stack overflow on
     * demand.
     */
    @Test
    @DisplayName("nesting deeper than 100 is refused rather than recursed")
    void depthLimitEnforced() {
        Value v = Value.of(1);
        for (int i = 0; i < 101; i++) {
            v = new Value.Array(List.of(v));
        }
        Value deep = v;
        assertThrows(LimitException.class, () -> Cve.encode(deep));
    }

    @org.junit.jupiter.api.Test
    void f041AHugeInlineNameRefIsCorruptionNotAnIndexError() {
        // {"a": null} with its name ref replaced by the 10-byte uvar 2^64-1.
        byte[] b = org.dizitart.cryptand.util.Hex.parse("221001" + "01" + "ffffffffffffffffff01" + "00016100");
        org.junit.jupiter.api.Assertions.assertThrows(org.dizitart.cryptand.CorruptionException.class,
                () -> org.dizitart.cryptand.value.Cve.decode(b));
    }
}
