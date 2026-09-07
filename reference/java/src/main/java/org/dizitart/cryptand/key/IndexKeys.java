package org.dizitart.cryptand.key;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Secondary index entry derivation — {@code spec/06-indexes.md}.
 *
 * <p>One layout for all three index types, in all languages:
 *
 * <pre>
 *   key   = CKE( Array[ v1, v2, ..., vk, NitriteId ] )
 *   value = EMPTY
 * </pre>
 *
 * <p>That is the whole design, and the consequences are worth stating. Insert
 * and remove are O(1) point operations — no read-modify-write of a growing id
 * list and no nested sub-map, which is what Java's
 * {@code Map<DBValue, List<NitriteId>>} and
 * {@code Map<DBValue, NavigableMap<DBValue, ?>>} were, both O(n) per write and
 * O(n²) to bulk-load a low-cardinality field. A prefix query is a range scan. A
 * scan yields the indexed values <em>and</em> the document id by decoding the
 * key, so a covering query never touches the data tree. And the
 * {@code LOWER/EXACT/UPPER} sentinel byte that Java's {@code IndexEntryKey} and
 * Dart's {@code IndexKey._Bound} store in every key is gone: {@link
 * Cke#successor} does that job outside the key.
 */
public final class IndexKeys {

    private IndexKeys() {
    }

    /**
     * §4: a writer MUST cap the cartesian product at 1024 entries per document
     * and report an error beyond it, rather than write an unbounded number of
     * index rows.
     */
    public static final int MAX_ENTRIES_PER_DOCUMENT = 1024;

    // ==================================================================
    // field paths, §5
    // ==================================================================

    /**
     * Splits a {@code .}-separated field path.
     *
     * <p>A component that is itself a literal {@code .} is escaped as
     * {@code \.}, and a literal backslash as {@code \\}. <strong>This is the
     * only escaping in the format</strong>, and it exists only here — trees are
     * addressed by numeric id and their names are plain UTF-8, which is what
     * retires Fjall's {@code | -> _P_} substitution and Hive's base64 box keys.
     */
    public static List<String> splitFieldPath(String path) {
        List<String> out = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (escaped) {
                current.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '.') {
                out.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (escaped) {
            throw new InvalidArgumentException("field path ends in a dangling backslash: " + path);
        }
        out.add(current.toString());
        return out;
    }

    /** The inverse of {@link #splitFieldPath} for one component. */
    public static String escapeComponent(String component) {
        return component.replace("\\", "\\\\").replace(".", "\\.");
    }

    /**
     * Resolves a field path against a document, flattening arrays.
     *
     * <p>Traversing an array applies the remainder of the path to every element
     * and flattens the results, so {@code orders.items.sku} indexes every sku in
     * every item of every order.
     *
     * @return the resolved values, or {@code null} when the path is
     *         <em>absent</em> — which §3 distinguishes from a path that resolves
     *         to a present {@code null}, and from one that resolves to nothing.
     */
    public static List<Value> resolve(Value root, List<String> path) {
        return resolveFrom(root, path, 0);
    }

    private static List<Value> resolveFrom(Value v, List<String> path, int i) {
        if (v instanceof Value.Array a) {
            List<Value> out = new ArrayList<>();
            for (Value item : a.items()) {
                List<Value> sub = resolveFrom(item, path, i);
                if (sub != null) {
                    out.addAll(sub);
                }
            }
            return out;
        }
        if (i == path.size()) {
            return List.of(v);
        }
        if (v instanceof Value.Doc d) {
            Value child = d.field(path.get(i));
            // An unresolvable path is treated as an absent field (§5).
            return child == null ? null : resolveFrom(child, path, i + 1);
        }
        return null;
    }

    // ==================================================================
    // entry derivation, §3 and §4
    // ==================================================================

    /**
     * The index keys one document contributes, in document order, deduplicated.
     *
     * <p>§3's null and missing table, in one place:
     *
     * <ul>
     *   <li>field present with value {@code null} — indexed as {@code NULL};
     *   <li>field absent — indexed as {@code NULL}, <strong>unless</strong>
     *       {@code sparse};
     *   <li>field absent and {@code sparse} — no entry at all.
     * </ul>
     *
     * <p>{@code NULL} sorts below every other value, so {@code field < x}
     * naturally includes nulls and {@code field > x} naturally excludes them.
     */
    public static List<byte[]> forDocument(List<String> fieldPaths, Value document,
                                           boolean sparse, long nitriteId) {
        List<List<Value>> perField = new ArrayList<>(fieldPaths.size());
        for (String p : fieldPaths) {
            List<Value> resolved = resolve(document, splitFieldPath(p));
            if (resolved == null) {
                // Absent.
                if (sparse) {
                    return List.of();
                }
                perField.add(List.of(Value.NULL));
            } else {
                perField.add(resolved);
            }
        }

        List<List<Value>> tuples = new ArrayList<>();
        tuples.add(new ArrayList<>());
        for (List<Value> values : perField) {
            List<List<Value>> next = new ArrayList<>();
            for (List<Value> prefix : tuples) {
                for (Value v : values) {
                    if (next.size() >= MAX_ENTRIES_PER_DOCUMENT) {
                        throw new LimitException("index entries for one document exceed "
                                + MAX_ENTRIES_PER_DOCUMENT + " (spec/06-indexes.md §4)");
                    }
                    List<Value> extended = new ArrayList<>(prefix);
                    extended.add(v);
                    next.add(extended);
                }
            }
            tuples = next;
        }

        // Duplicate elements produce one entry, not two: the key is identical,
        // so the second write is a no-op. Deduplicating here rather than
        // relying on that keeps the count honest for the cap above.
        Set<String> seen = new LinkedHashSet<>();
        List<byte[]> keys = new ArrayList<>();
        for (List<Value> tuple : tuples) {
            List<Value> withId = new ArrayList<>(tuple);
            withId.add(new Value.NitriteId(nitriteId));
            for (Value v : tuple) {
                if (!Cke.isKeyEncodable(v)) {
                    throw new InvalidArgumentException("a value of type " + v.getClass().getSimpleName()
                            + " has no CKE encoding and cannot be indexed (spec/06-indexes.md §6)");
                }
            }
            byte[] key = Cke.encode(new Value.Array(withId));
            String fingerprint = java.util.Arrays.toString(key);
            if (seen.add(fingerprint)) {
                keys.add(key);
            }
        }
        return keys;
    }

    /** The indexed values from an index key, without the trailing id. */
    public static List<Value> valuesOf(byte[] indexKey) {
        List<Value> items = ((Value.Array) Cke.decode(indexKey)).items();
        return List.copyOf(items.subList(0, items.size() - 1));
    }

    /** The document id an index key points at. */
    public static long idOf(byte[] indexKey) {
        List<Value> items = ((Value.Array) Cke.decode(indexKey)).items();
        Value last = items.get(items.size() - 1);
        if (!(last instanceof Value.NitriteId id)) {
            throw new CorruptionException("index key does not end in a NITRITE_ID");
        }
        return id.id();
    }

    /**
     * §1 and §3: whether the uniqueness check applies to this tuple at all.
     *
     * <p>A unique index treats every {@code NULL} as distinct — many documents
     * may lack the field — so the check is <em>skipped</em> when any element is
     * null, rather than run and passed.
     */
    public static boolean uniquenessApplies(List<Value> tuple) {
        for (Value v : tuple) {
            if (v instanceof Value.Null) {
                return false;
            }
        }
        return true;
    }

    // ==================================================================
    // the query planning contract, §7
    // ==================================================================

    /**
     * A half-open scan {@code [lower, upper)}. {@code upper == null} is
     * {@link Cke#UNBOUNDED_ABOVE}; an empty {@code lower} is unbounded below,
     * which needs no sentinel because the empty byte string is below every key.
     */
    public record Scan(byte[] lower, byte[] upper) {

        public boolean contains(byte[] key) {
            if (Cke.compare(key, lower) < 0) {
                return false;
            }
            return upper == null || Cke.compare(key, upper) < 0;
        }
    }

    /** Equality on a prefix, with the last element type-exact. */
    public static Scan equalsPrefix(List<Value> prefix) {
        byte[] lower = Cke.prefixOfArray(prefix);
        return new Scan(lower, Cke.successor(lower));
    }

    /**
     * Equality on a prefix whose last element is numeric and type-agnostic.
     *
     * <p>This is the row to get right. A bound built from the full
     * {@code CKE(v)} cuts <em>between numeric types</em> rather than between
     * numeric values, so {@code field >= 5} misses an {@code I8(5)} and
     * {@code field > 5} returns a {@code U8(5)}.
     */
    public static Scan equalsPrefixNumeric(List<Value> prefix) {
        byte[] lower = Cke.arrayPrefixNumeric(prefix);
        return new Scan(lower, Cke.successor(lower));
    }

    /** A {@code starts_with} on a string in the position after {@code prefix}. */
    public static Scan startsWith(List<Value> prefix, String s) {
        ByteWriter w = new ByteWriter(32);
        w.bytes(Cke.prefixOfArray(prefix)).u8(0x01).bytes(Cke.stringPrefix(s));
        byte[] lower = w.toBytes();
        return new Scan(lower, Cke.successor(lower));
    }
}
