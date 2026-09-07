package org.dizitart.cryptand.index;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.key.IndexKeys;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.lsm.SegmentMeta;
import org.dizitart.cryptand.text.Analyzer;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A full-text index — {@code spec/07-fulltext.md} §1 and §4.
 *
 * <p>Three trees per index: a term dictionary, its reverse map, and the
 * postings. All three carry {@code owner = <data tree name>}, so
 * {@code 05-catalog.md} §11's "what indexes does X have?" finds them together.
 *
 * <p>Scoring is deliberately <strong>not</strong> here. The format supplies
 * {@code df}, {@code ttf}, per-document term frequency and optionally positions,
 * which is everything a scorer needs; two SDKs may rank the same result set
 * differently, and they MUST NOT disagree about the set.
 */
public final class FullTextIndex {

    /** A term's dictionary entry. Both counts MUST be accurate after a merge. */
    public record Term(int id, long df, long ttf) {
    }

    private final Database db;
    private final Collection owner;
    private final String name;
    private final List<String> fields;
    private final Analyzer analyzer;
    private final boolean positions;
    private final int termDictTree;
    private final int termIndexTree;
    private final int postingsTree;
    private final Engine engine;
    private int nextTermId = 1;

    public FullTextIndex(Database db, Collection owner, String name, TreeDescriptor descriptor) {
        this.db = db;
        this.owner = owner;
        this.name = name;
        this.engine = db.engine();
        Value.Doc params = descriptor.params();
        this.fields = new ArrayList<>();
        for (Value v : ((Value.Array) params.field("fields")).items()) {
            fields.add(((Value.Str) v).value());
        }
        List<String> stopwords = new ArrayList<>();
        Value analyzerParams = params.field("analyzer_params");
        String stemmer = "none";
        if (analyzerParams instanceof Value.Doc ap) {
            Value sw = ap.field("stopwords");
            if (sw instanceof Value.Array a) {
                for (Value v : a.items()) {
                    stopwords.add(((Value.Str) v).value());
                }
            }
            Value st = ap.field("stemmer");
            if (st instanceof Value.Str s) {
                stemmer = s.value();
            }
        }
        this.analyzer = Analyzer.of(((Value.Str) params.field("analyzer")).value(), stopwords, stemmer);
        Value pos = params.field("positions");
        this.positions = pos instanceof Value.Bool b && b.value();
        this.termDictTree = (int) SegmentMeta.longOf(params.field("term_dict"));
        this.termIndexTree = (int) SegmentMeta.longOf(params.field("term_index"));
        this.postingsTree = descriptor.treeId();
        for (Term t : terms().values()) {
            nextTermId = Math.max(nextTermId, t.id() + 1);
        }
    }

    public String name() {
        return name;
    }

    public Analyzer analyzer() {
        return analyzer;
    }

    public boolean hasPositions() {
        return positions;
    }

    // ==================================================================
    // the dictionary
    // ==================================================================

    public Map<String, Term> terms() {
        Map<String, Term> out = new LinkedHashMap<>();
        try (Engine.Cursor c = engine.scan(termDictTree, null, null, false)) {
            while (c.next()) {
                String term = ((Value.Str) Cke.decode(c.row().key())).value();
                Value.Doc d = (Value.Doc) Cve.decode(c.row().value());
                out.put(term, new Term((int) SegmentMeta.longOf(d.field("id")),
                        SegmentMeta.longOf(d.field("df")), SegmentMeta.longOf(d.field("ttf"))));
            }
        }
        return out;
    }

    public Term term(String text) {
        byte[] raw = engine.get(termDictTree, Cke.encode(new Value.Str(text)));
        if (raw == null) {
            return null;
        }
        Value.Doc d = (Value.Doc) Cve.decode(raw);
        return new Term((int) SegmentMeta.longOf(d.field("id")),
                SegmentMeta.longOf(d.field("df")), SegmentMeta.longOf(d.field("ttf")));
    }

    /** {@code term_id -> term} — the reverse map of §1. */
    public String termById(int id) {
        byte[] raw = engine.get(termIndexTree, Cke.encode(Value.integer(NumType.U32, id)));
        return raw == null ? null : ((Value.Str) Cve.decode(raw)).value();
    }

    // ==================================================================
    // maintenance
    // ==================================================================

    /** Indexes a document, replacing whatever it contributed before. */
    public void put(long nitriteId, Value.Doc document) {
        remove(nitriteId);
        Map<String, List<Integer>> byTerm = new LinkedHashMap<>();
        for (String field : fields) {
            List<Value> values = IndexKeys.resolve(document, IndexKeys.splitFieldPath(field));
            if (values == null) {
                continue;
            }
            for (Value v : values) {
                if (!(v instanceof Value.Str s)) {
                    // Step 1: non-string values are skipped.
                    continue;
                }
                for (Analyzer.Token t : analyzer.analyze(s.value())) {
                    byTerm.computeIfAbsent(t.text(), k -> new ArrayList<>()).add(t.position());
                }
            }
        }
        for (Map.Entry<String, List<Integer>> e : byTerm.entrySet()) {
            int termId = internTerm(e.getKey());
            int[] pos = new int[e.getValue().size()];
            for (int i = 0; i < pos.length; i++) {
                pos[i] = e.getValue().get(i);
            }
            java.util.Arrays.sort(pos);
            addPosting(termId, new Postings.Posting(nitriteId, pos.length, pos));
            adjustTerm(e.getKey(), 1, pos.length);
        }
    }

    public void remove(long nitriteId) {
        for (Map.Entry<String, Term> e : terms().entrySet()) {
            int removed = removePosting(e.getValue().id(), nitriteId);
            if (removed > 0) {
                adjustTerm(e.getKey(), -1, -removed);
            }
        }
    }

    private int internTerm(String text) {
        Term existing = term(text);
        if (existing != null) {
            return existing.id();
        }
        int id = nextTermId++;
        Engine.Batch b = engine.batch();
        b.put(termDictTree, Cke.encode(new Value.Str(text)),
                Cve.encode(dictionaryValue(id, 0, 0)));
        b.put(termIndexTree, Cke.encode(Value.integer(NumType.U32, id)),
                Cve.encode(new Value.Str(text)));
        b.commit();
        return id;
    }

    private static Value dictionaryValue(int id, long df, long ttf) {
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("id", Value.integer(NumType.U32, id));
        f.put("df", Value.integer(NumType.U32, Math.max(0, df)));
        f.put("ttf", Value.integer(NumType.U64, Math.max(0, ttf)));
        return Value.Doc.of(f);
    }

    private void adjustTerm(String text, long dfDelta, long ttfDelta) {
        Term t = term(text);
        if (t == null) {
            return;
        }
        // §4.4: a term whose blocks are all gone has df = 0 but keeps its
        // dictionary entry, because term ids are never reused.
        engine.batch().put(termDictTree, Cke.encode(new Value.Str(text)),
                Cve.encode(dictionaryValue(t.id(), t.df() + dfDelta, t.ttf() + ttfDelta))).commit();
    }

    // ==================================================================
    // blocks
    // ==================================================================

    private TreeMap<Long, List<Postings.Posting>> blocksOf(int termId) {
        TreeMap<Long, List<Postings.Posting>> blocks = new TreeMap<>();
        byte[] low = Postings.key(termId, Long.MIN_VALUE);
        byte[] high = Postings.key(termId, Long.MAX_VALUE);
        try (Engine.Cursor c = engine.scan(postingsTree, low, high, false)) {
            while (c.next()) {
                List<Value> k = ((Value.Array) Cke.decode(c.row().key())).items();
                if (SegmentMeta.longOf(k.get(0)) != termId) {
                    continue;
                }
                long first = ((Value.NitriteId) k.get(1)).id();
                blocks.put(first, Postings.decode(((Value.Bytes) Cve.decode(c.row().value())).value()));
            }
        }
        return blocks;
    }

    public List<Postings.Posting> postings(int termId) {
        List<Postings.Posting> out = new ArrayList<>();
        for (List<Postings.Posting> block : blocksOf(termId).values()) {
            out.addAll(block);
        }
        return out;
    }

    private void addPosting(int termId, Postings.Posting posting) {
        List<Postings.Posting> all = postings(termId);
        all.removeIf(p -> p.nitriteId() == posting.nitriteId());
        all.add(posting);
        all.sort(java.util.Comparator.comparingLong(Postings.Posting::nitriteId));
        rewrite(termId, all);
    }

    private int removePosting(int termId, long nitriteId) {
        List<Postings.Posting> all = postings(termId);
        int frequency = 0;
        for (Postings.Posting p : all) {
            if (p.nitriteId() == nitriteId) {
                frequency = p.frequency();
            }
        }
        if (frequency == 0) {
            return 0;
        }
        all.removeIf(p -> p.nitriteId() == nitriteId);
        rewrite(termId, all);
        return frequency;
    }

    private void rewrite(int termId, List<Postings.Posting> all) {
        Engine.Batch b = engine.batch();
        for (long first : blocksOf(termId).keySet()) {
            b.remove(postingsTree, Postings.key(termId, first));
        }
        for (int i = 0; i < all.size(); i += Postings.MAX_PER_BLOCK) {
            List<Postings.Posting> block =
                    all.subList(i, Math.min(all.size(), i + Postings.MAX_PER_BLOCK));
            b.put(postingsTree, Postings.key(termId, block.get(0).nitriteId()),
                    Cve.encode(new Value.Bytes(Postings.encode(block, positions))));
        }
        b.commit();
    }

    // ==================================================================
    // queries
    // ==================================================================

    /** Documents holding every term of the analyzed query. */
    public List<Long> search(String query) {
        List<String> terms = analyzer.analyzeQuery(query);
        if (terms.isEmpty()) {
            return List.of();
        }
        List<Long> result = null;
        for (String text : terms) {
            Term t = term(text);
            if (t == null) {
                return List.of();
            }
            List<Long> ids = new ArrayList<>();
            for (Postings.Posting p : postings(t.id())) {
                ids.add(p.nitriteId());
            }
            if (result == null) {
                result = ids;
            } else {
                result.retainAll(ids);
            }
        }
        return result == null ? List.of() : result;
    }

    /**
     * Documents holding the query's terms adjacently, in order.
     *
     * <p>§4.3: a phrase query against an index without positions is
     * <strong>rejected</strong>, never approximated with a conjunction.
     */
    public List<Long> phrase(String query) {
        if (!positions) {
            throw new InvalidArgumentException("index " + name + " has positions = false; "
                    + "a phrase query MUST be rejected rather than approximated with a conjunction "
                    + "(spec/07-fulltext.md §4.3)");
        }
        List<String> terms = analyzer.analyzeQuery(query);
        if (terms.isEmpty()) {
            return List.of();
        }
        List<Long> out = new ArrayList<>();
        for (long id : search(query)) {
            if (matchesPhrase(id, terms)) {
                out.add(id);
            }
        }
        return out;
    }

    private boolean matchesPhrase(long nitriteId, List<String> terms) {
        List<int[]> perTerm = new ArrayList<>();
        for (String text : terms) {
            Term t = term(text);
            int[] found = null;
            for (Postings.Posting p : postings(t.id())) {
                if (p.nitriteId() == nitriteId) {
                    found = p.positions();
                }
            }
            if (found == null) {
                return false;
            }
            perTerm.add(found);
        }
        for (int start : perTerm.get(0)) {
            boolean ok = true;
            for (int i = 1; i < perTerm.size() && ok; i++) {
                ok = contains(perTerm.get(i), start + i);
            }
            if (ok) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(int[] positions, int value) {
        for (int p : positions) {
            if (p == value) {
                return true;
            }
        }
        return false;
    }

    // ==================================================================
    // §6 verification
    // ==================================================================

    /**
     * Rebuilds the index from the data tree and compares.
     *
     * <p>Rebuilding requires the analyzer, so an implementation that cannot run
     * the declared one reports "unverifiable", not "valid" — which is why
     * {@link Analyzer#of} refuses an analyzer it does not have rather than
     * approximating it.
     */
    public List<String> verify() {
        List<String> findings = new ArrayList<>();
        Map<String, Long> expectedDf = new LinkedHashMap<>();
        Map<String, Long> expectedTtf = new LinkedHashMap<>();
        try (Engine.Cursor c = owner.scan(false)) {
            while (c.next()) {
                Value.Doc doc = owner.decode(c.row().value());
                Map<String, Integer> counts = new LinkedHashMap<>();
                for (String field : fields) {
                    List<Value> values = IndexKeys.resolve(doc, IndexKeys.splitFieldPath(field));
                    if (values == null) {
                        continue;
                    }
                    for (Value v : values) {
                        if (v instanceof Value.Str s) {
                            for (Analyzer.Token t : analyzer.analyze(s.value())) {
                                counts.merge(t.text(), 1, Integer::sum);
                            }
                        }
                    }
                }
                for (Map.Entry<String, Integer> e : counts.entrySet()) {
                    expectedDf.merge(e.getKey(), 1L, Long::sum);
                    expectedTtf.merge(e.getKey(), (long) e.getValue(), Long::sum);
                }
            }
        }
        Map<String, Term> stored = terms();
        for (Map.Entry<String, Long> e : expectedDf.entrySet()) {
            Term t = stored.get(e.getKey());
            if (t == null) {
                findings.add("term '" + e.getKey() + "' is produced by a live document but absent");
                continue;
            }
            if (t.df() != e.getValue()) {
                findings.add("term '" + e.getKey() + "' declares df " + t.df()
                        + ", the documents give " + e.getValue());
            }
            if (t.ttf() != expectedTtf.get(e.getKey())) {
                findings.add("term '" + e.getKey() + "' declares ttf " + t.ttf()
                        + ", the documents give " + expectedTtf.get(e.getKey()));
            }
        }
        for (Map.Entry<String, Term> e : stored.entrySet()) {
            if (e.getValue().df() > 0 && !expectedDf.containsKey(e.getKey())) {
                findings.add("term '" + e.getKey() + "' has postings but no live document produces it");
            }
            for (Postings.Posting p : postings(e.getValue().id())) {
                if (p.positions() != null) {
                    for (int i = 1; i < p.positions().length; i++) {
                        if (p.positions()[i] <= p.positions()[i - 1]) {
                            findings.add("term '" + e.getKey() + "' has non-increasing positions in "
                                    + p.nitriteId());
                            break;
                        }
                    }
                }
            }
        }
        return findings;
    }
}
