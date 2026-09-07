package org.dizitart.cryptand.value;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A data tree's field-name dictionary, {@code spec/02-value-encoding.md} §5.3.
 *
 * <p>Field names live once per tree rather than once per document. For a
 * 20-field document with an average name length of 12 bytes this removes ~240
 * bytes of repeated text per document and replaces it with ~20–40 bytes of
 * varints; on document-shaped data it dominates every other space optimization
 * in the format.
 *
 * <p>{@code name_id} is allocated append-only and is <strong>never
 * reused</strong>, so a stale cached dictionary is never <em>wrong</em>, only
 * incomplete. That is what lets a reader cache the whole thing and re-read only
 * when it meets an id it does not know. Entries are never deleted, even when no
 * document uses the name — reclaiming them would require reusing ids.
 */
public final class NameDict {

    /**
     * {@code spec/02-value-encoding.md} §5.4: these SHOULD occupy
     * {@code name_id} 1–5 in every data tree, so that they encode in one byte.
     */
    public static final String[] RESERVED_FIELDS = {"_id", "_revision", "_modified", "_source", "_type"};

    private final Map<String, Integer> byName = new LinkedHashMap<>();
    private final Map<Integer, String> byId = new LinkedHashMap<>();
    private int nextId = 1;

    /** An empty dictionary. */
    public NameDict() {
    }

    /** A dictionary with the reserved fields already interned at 1–5. */
    public static NameDict withReservedFields() {
        NameDict d = new NameDict();
        for (String f : RESERVED_FIELDS) {
            d.intern(f);
        }
        return d;
    }

    /** Returns the id of {@code name}, allocating one if it is new. */
    public int intern(String name) {
        Integer existing = byName.get(name);
        if (existing != null) {
            return existing;
        }
        int id = nextId++;
        byName.put(name, id);
        byId.put(id, name);
        return id;
    }

    /** The id of {@code name}, or {@code null} when it is not in the dictionary. */
    public Integer idOf(String name) {
        return byName.get(name);
    }

    /** The name for {@code id}, or {@code null} when this dictionary has not seen it. */
    public String nameOf(int id) {
        return byId.get(id);
    }

    /** Adds a known {@code (id, name)} pair read back from the dictionary tree. */
    public void put(int id, String name) {
        byName.put(name, id);
        byId.put(id, name);
        if (id >= nextId) {
            nextId = id + 1;
        }
    }

    public int size() {
        return byId.size();
    }

    public Map<Integer, String> entries() {
        return Map.copyOf(byId);
    }
}
