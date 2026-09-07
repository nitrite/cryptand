/// The Nitrite model over the engine: collections, repositories and indexes.
///
/// This is the layer that makes `spec/05-catalog.md` and `spec/06-indexes.md`
/// executable rather than described. It exists to test two claims that cannot
/// be tested any other way:
///
///   * §5's "there is no second place where this list is written, so it cannot
///     drift" — enumerating collections is a **scan of the catalog**, and the
///     `"collections"` / `"repositories"` / `"keyed-repositories"` registries
///     that Java and Dart keep today are simply absent here;
///   * `06` §8's "index maintenance and the document write go into the **same
///     batch** and therefore the same commit" — [Collection.insert] writes the
///     document and every index entry through one memtable, so no durable state
///     exists in which they disagree.
library;

import 'dart:typed_data';

import 'catalog.dart';
import 'cke.dart';
import 'container.dart';
import 'cve.dart';
import 'engine.dart';
import 'errors.dart';
import 'analyzer.dart';
import 'fulltext.dart';
import 'index.dart';
import 'stats.dart';
import 'value.dart';

/// Format version reported in the store metadata of `05` §7.
const String kFormatVersion = 'CFF 1.0';

final class Database {
  Database({
    Engine? engine,
    int catalogRoot = 0,
    int treeIndexRoot = 0,
    int attributesRoot = 0,
    int nextTreeId = TreeId.firstUserTree,
    bool initStoreMetadata = true,
  }) : engine = engine ?? Engine() {
    // §2 of `spec/05-catalog.md`: the catalog is tree 0 and attributes are
    // tree 2, both in the **same** page space as everything else, both rooted
    // from the superblock. A separate store for them would have no page ids a
    // superblock could name.
    final store = this.engine.store;
    catalog = Catalog(store,
        catalogRoot: catalogRoot, treeIndexRoot: treeIndexRoot);
    catalog.nextTreeId = nextTreeId;
    attributes = Attributes(store, root: attributesRoot);
    if (initStoreMetadata) {
      attributes.initStore(
          formatVersion: kFormatVersion, nitriteVersion: 'reference-dart');
    }
  }

  final Engine engine;
  late final Catalog catalog;
  late final Attributes attributes;

  /// The roots a superblock publishes for this database's own trees.
  int get catalogRoot => catalog.tree.root;
  int get treeIndexRoot => catalog.byId.root;
  int get attributesRoot => attributes.tree.root;

  /// Creates a collection, §5.
  Collection createCollection(String name) {
    final d = catalog.create(name,
        kind: TreeKind.data,
        keyKind: 'nitrite_id',
        params: {'type': const CStr(DataTreeType.collection)});
    return Collection(this, name, d);
  }

  /// Creates a repository, keyed or not, §5.
  ///
  /// The `+` in a keyed repository's name is retained for continuity with
  /// existing Nitrite names, but it is now **just a character in a string**:
  /// `params` carries the structured truth and nothing escapes anything.
  Collection createRepository(String entity, {String? key}) {
    final name = key == null ? entity : '$entity+$key';
    final d = catalog.create(name,
        kind: TreeKind.data,
        keyKind: 'nitrite_id',
        params: {
          'type': const CStr(DataTreeType.repository),
          'entity': CStr(entity),
          if (key != null) 'key': CStr(key),
        });
    return Collection(this, name, d);
  }

  Collection? collection(String name) {
    final d = catalog.get(name);
    if (d == null || d.kind != TreeKind.data) return null;
    return Collection(this, name, d);
  }
}

/// A `data` tree and the indexes that serve it.
final class Collection {
  Collection(this.db, this.name, this.descriptor);

  final Database db;
  final String name;
  final TreeDescriptor descriptor;

  int get treeId => descriptor.treeId;

  Engine get _e => db.engine;

  /// Creates an index over [fields], §2.
  ///
  /// The tree name is a convention and nothing parses it; the binding is
  /// `params.data_tree` (§10: "nothing derives a tree name by concatenating
  /// this string, because tree names are not derived at all").
  TreeDescriptor createIndex(
    List<String> fields, {
    String indexType = IndexType.nonUnique,
    bool sparse = false,
    String? indexName,
  }) {
    final idx = IndexDescriptor(
        indexType: indexType,
        dataTree: treeId,
        fields: fields,
        sparse: sparse);
    final d = db.catalog.create(indexName ?? idx.suggestedName(name),
        kind: TreeKind.index, owner: name, params: idx.params);
    // Backfill: every document already present produces its entries now.
    for (final e in _e.scanTree(treeId)) {
      final doc = expectValue<CDoc>(decodeValue(e.value), 'document');
      _writeIndexEntries(idx, d.treeId, doc, _idOf(e.cke), remove: false);
    }
    return d;
  }

  List<(TreeDescriptor, IndexDescriptor)> get indexes => [
        for (final (_, d) in db.catalog.indexesOf(name))
          if (d.kind == TreeKind.index) (d, IndexDescriptor.fromDescriptor(d))
      ];

  /// Inserts or replaces one document, maintaining every index in the same
  /// batch (§8).
  void put(CValue id, CDoc doc) {
    final existing = get(id);
    for (final (tree, idx) in indexes) {
      if (existing != null) {
        _writeIndexEntries(idx, tree.treeId, existing, id, remove: true);
      }
      if (idx.unique) _checkUnique(tree.treeId, idx, doc, id);
      _writeIndexEntries(idx, tree.treeId, doc, id, remove: false);
    }
    _e.put(treeId, id, encodeValue(doc));
  }

  void remove(CValue id) {
    final existing = get(id);
    if (existing == null) return;
    for (final (tree, idx) in indexes) {
      _writeIndexEntries(idx, tree.treeId, existing, id, remove: true);
    }
    _e.remove(treeId, id);
  }

  CDoc? get(CValue id) {
    final v = _e.get(treeId, id);
    return v == null ? null : expectValue<CDoc>(decodeValue(v), 'document');
  }

  Iterable<(CValue, CDoc)> get all sync* {
    for (final e in _e.scanTree(treeId)) {
      yield (_idOf(e.cke), expectValue<CDoc>(decodeValue(e.value), 'document'));
    }
  }

  /// Runs one of the scans §7 permits and yields the matching document ids,
  /// in index order.
  ///
  /// "Sorted output falls out for free when the sort key is an index prefix —
  /// the scan is already in order, so a `sort` over an index prefix MUST NOT
  /// materialize."
  Iterable<CValue> lookup(TreeDescriptor indexTree, KeyRange range) sync* {
    for (final e in _e.scanTree(indexTree.treeId, range: range)) {
      yield indexEntryId(e.cke);
    }
  }

  /// The whole entry, values included — a **covering** read, which §1 says
  /// "need never touch the data tree".
  Iterable<List<CValue>> lookupCovering(
      TreeDescriptor indexTree, KeyRange range) sync* {
    final idx = IndexDescriptor.fromDescriptor(indexTree);
    for (final e in _e.scanTree(indexTree.treeId, range: range)) {
      yield [...indexEntryValues(e.cke, idx.fields.length), indexEntryId(e.cke)];
    }
  }

  /// Recomputes `params.stats` for an index tree, `spec/13-operations.md` §9.
  ///
  /// §9 maintains these "at compaction, ... free, because that compaction
  /// already touches every key". This method is the same walk, exposed so the
  /// statistics can be refreshed on demand — a scan of the index tree in key
  /// order, which is exactly what a last-level compaction of it would do.
  ///
  /// The result is **advisory** and is stored under `params.stats`; a planner
  /// must work without it.
  IndexStats analyze(TreeDescriptor indexTree) {
    final idx = IndexDescriptor.fromDescriptor(indexTree);
    final b = StatsBuilder();
    // Equi-depth: with the stream already in key order, a bucket boundary is
    // a counter reaching its quota. The quota needs the count, so the entries
    // are walked once to count and once to bound -- the second pass is over
    // keys only and touches no values.
    final keys = <Uint8List>[];
    for (final e in _e.scanTree(indexTree.treeId)) {
      keys.add(Uint8List.fromList(e.cke));
    }
    final quota = keys.length <= 64 ? 1 : (keys.length / 64).ceil();
    for (var i = 0; i < keys.length; i++) {
      final values = indexEntryValues(keys[i], idx.fields.length);
      final prefix = Keys.prefixOfArray(values);
      b.add(prefix, keys[i],
          seq: 0, isNull: values.any((v) => v is CNull));
      if ((i + 1) % quota == 0) b.boundary(keys[i]);
    }
    final stats = b.build();

    final name = db.catalog.nameOf(indexTree.treeId)!;
    db.catalog.put(
        name,
        indexTree.with_({
          'params': CDoc({...indexTree.params.fields, 'stats': stats.toDoc()})
        }));
    return stats;
  }

  /// The statistics stored for an index, or null when none have been computed.
  ///
  /// §9: "Statistics are advisory. They may be stale or absent."
  IndexStats? statsOf(TreeDescriptor indexTree) {
    final d = db.catalog.get(db.catalog.nameOf(indexTree.treeId)!);
    final s = d?.params['stats'];
    return s == null ? null : IndexStats.fromDoc(s as CDoc);
  }

  /// Picks the most selective index among [candidates], `06` §7.1.
  ///
  /// This is the decision Nitrite's `FindPlan` currently makes from static
  /// descriptor properties — "whether it is unique, and how many fields it
  /// covers" — which "routinely picks a unique index on a field the query
  /// barely constrains over a non-unique index that would eliminate 99 % of
  /// the collection". With statistics it is made on evidence.
  ///
  /// Returns null when no candidate has statistics, which a planner must treat
  /// as "choose some other way" rather than as an error.
  TreeDescriptor? mostSelective(List<TreeDescriptor> candidates) {
    TreeDescriptor? best;
    var bestSel = double.infinity;
    for (final c in candidates) {
      final s = statsOf(c);
      if (s == null) continue;
      if (s.selectivity < bestSel) {
        bestSel = s.selectivity;
        best = c;
      }
    }
    return best;
  }

  /// Creates a full-text index, `spec/07-fulltext.md` §1.
  ///
  /// Three trees — `term_dict`, `term_index` and `postings` — all carrying
  /// `owner = <data tree name>`, so `05-catalog.md` §11's "what indexes does X
  /// have?" finds them together. The **postings** tree is the index's
  /// identity: §1 says so, and it is what [fullTextSearch] is handed.
  TreeDescriptor createFullTextIndex(
    List<String> fields, {
    Analyzer? analyzer,
    bool positions = true,
    String? indexName,
  }) {
    final a = analyzer ?? Analyzer();
    a.requireUnicode(Analyzer.unicodeVersionImplemented);

    final base = indexName ?? 'fts:$name:${fields.join(",")}';
    final dict = db.catalog.create('$base:term_dict',
        kind: TreeKind.termDict, owner: name, params: {'index_type': const CStr(IndexType.fullText)});
    final rev = db.catalog.create('$base:term_index',
        kind: TreeKind.termIndex, owner: name, params: {'index_type': const CStr(IndexType.fullText)});
    final post = db.catalog.create(base,
        kind: TreeKind.postings,
        owner: name,
        params: {
          'index_type': const CStr(IndexType.fullText),
          'data_tree': CInt.of(NumType.u32, treeId),
          'fields': CArray([for (final f in fields) CStr(f)]),
          'analyzer': CStr(a.name),
          'analyzer_params': CDoc({
            if (a.stopwords.isNotEmpty)
              'stopwords': CArray([
                for (final w in Analyzer.canonicalStopwords(a.stopwords))
                  CStr(w)
              ]),
            'stemmer': CStr(a.stemmer),
          }),
          'term_dict': CInt.of(NumType.u32, dict.treeId),
          'term_index': CInt.of(NumType.u32, rev.treeId),
          'positions': CBool(positions),
        });

    for (final (id, doc) in all) {
      _indexDocumentText(post, a, fields, doc, id, positions);
    }
    return post;
  }

  Analyzer _analyzerOf(TreeDescriptor postings) {
    final p = postings.params;
    final ap = (p['analyzer_params'] as CDoc?) ?? CDoc(const {});
    final words = (ap['stopwords'] as CArray?)
            ?.items
            .map((e) => (e as CStr).value)
            .toList() ??
        const <String>[];
    return Analyzer(
      name: (p['analyzer']! as CStr).value,
      stopwords: words,
      stemmer: (ap['stemmer'] as CStr?)?.value ?? Stemmer.none,
    );
  }

  void _indexDocumentText(TreeDescriptor postings, Analyzer a,
      List<String> fields, CDoc doc, CValue id, bool positions) {
    final byTerm = <String, List<int>>{};
    for (final path in fields) {
      for (final v in resolvePath(doc, path)) {
        for (final t in a.analyzeValue(v is CStr ? v.value : null)) {
          (byTerm[t.text] ??= []).add(t.position);
        }
      }
    }
    if (byTerm.isEmpty) return;

    final p = postings.params;
    final dictId = ((p['term_dict']! as CInt).magnitude).lo;
    final revId = ((p['term_index']! as CInt).magnitude).lo;
    final docId = (id as CNitriteId).id;

    for (final entry in byTerm.entries) {
      final term = entry.key;
      final pos = entry.value..sort();
      final termId = _internTerm(dictId, revId, term);

      // Read the block this document belongs in, add the posting, write back.
      // §4.4: an update rewrites the block it touches, not the posting list.
      final existing = _blocksOf(postings, termId);
      final merged = <Posting>[
        for (final b in existing)
          for (final q in b.postings)
            if (q.docId != docId) q,
        Posting(docId, pos.length, positions ? pos : const []),
      ]..sort((x, y) => x.docId.compareTo(y.docId));

      for (final b in existing) {
        _e.remove(postings.treeId,
            decodeKey(PostingsBlock.keyFor(termId, b.firstDoc)));
      }
      for (final b in PostingsBlock.split(merged, hasPositions: positions)) {
        _e.put(postings.treeId,
            decodeKey(PostingsBlock.keyFor(termId, b.firstDoc)), b.encode());
      }
      _updateTermStats(dictId, term, termId, merged);
    }
  }

  int _internTerm(int dictId, int revId, String term) {
    final existing = _e.get(dictId, CStr(term));
    if (existing != null) return TermEntry.decode(existing).id;
    // §1: "term_id is allocated append-only and never reused (same discipline
    // as name_id)."
    final next = _e.scanTree(revId).length + 1;
    _e.put(dictId, CStr(term), const TermEntry(0, 0, 0).encode());
    _e.put(revId, CInt.of(NumType.u32, next), encodeValue(CStr(term)));
    _e.put(dictId, CStr(term), TermEntry(next, 0, 0).encode());
    return next;
  }

  void _updateTermStats(
      int dictId, String term, int termId, List<Posting> all) {
    var ttf = 0;
    for (final p in all) {
      ttf += p.freq;
    }
    _e.put(dictId, CStr(term), TermEntry(termId, all.length, ttf).encode());
  }

  List<PostingsBlock> _blocksOf(TreeDescriptor postings, int termId) {
    final lower = PostingsBlock.keyFor(termId, -0x8000000000000000);
    final upper = PostingsBlock.keyFor(termId + 1, -0x8000000000000000);
    return [
      for (final e in _e.scanTree(postings.treeId,
          range: KeyRange(lower, upper)))
        PostingsBlock.decode(e.value)
    ];
  }

  /// The `term_dict` entry for a term, or null.
  TermEntry? termEntry(TreeDescriptor postings, String term) {
    final dictId =
        ((postings.params['term_dict']! as CInt).magnitude).lo;
    final v = _e.get(dictId, CStr(term));
    return v == null ? null : TermEntry.decode(v);
  }

  /// Every posting for a term, in document order.
  List<Posting> postingsFor(TreeDescriptor postings, String term) {
    final e = termEntry(postings, term);
    if (e == null) return const [];
    return [for (final b in _blocksOf(postings, e.id)) ...b.postings];
  }

  /// A full-text search. §3: the query is analyzed with the same analyzer.
  ///
  /// Returns the matching document ids. **Scoring is not part of the format**
  /// (§3): "Two SDKs may legitimately rank the same result set differently;
  /// they MUST NOT disagree about the set." So this returns a set, in document
  /// order, and leaves ranking to the caller.
  List<CValue> fullTextSearch(TreeDescriptor postings, String query) {
    final a = _analyzerOf(postings);
    final terms = a.analyze(query).map((t) => t.text).toSet();
    if (terms.isEmpty) return const [];
    Set<int>? acc;
    for (final t in terms) {
      final ids = {for (final p in postingsFor(postings, t)) p.docId};
      acc = acc == null ? ids : acc.intersection(ids);
    }
    final out = (acc ?? <int>{}).toList()..sort();
    return [for (final id in out) CNitriteId(id)];
  }

  /// A phrase query. §4.3: an implementation MUST reject one against an index
  /// without positions "rather than approximate it with a conjunction".
  List<CValue> phraseSearch(TreeDescriptor postings, String phrase) {
    final positions = (postings.params['positions'] as CBool?)?.value ?? false;
    if (!positions) {
      throw const UnsupportedFeatureException(
          'this full-text index has positions = false, so a phrase query '
          'cannot be answered; approximating it with a conjunction would '
          'return the wrong set (spec/07-fulltext.md section 4.3)');
    }
    final a = _analyzerOf(postings);
    final tokens = a.analyze(phrase);
    if (tokens.isEmpty) return const [];

    final perTerm = <String, Map<int, List<int>>>{};
    for (final t in tokens) {
      perTerm[t.text] ??= {
        for (final p in postingsFor(postings, t.text)) p.docId: p.positions
      };
    }
    Set<int>? candidates;
    for (final m in perTerm.values) {
      final ids = m.keys.toSet();
      candidates = candidates == null ? ids : candidates.intersection(ids);
    }

    final out = <int>[];
    for (final docId in (candidates ?? <int>{}).toList()..sort()) {
      final first = perTerm[tokens.first.text]![docId]!;
      for (final start in first) {
        var ok = true;
        for (final t in tokens.skip(1)) {
          final want = start + (t.position - tokens.first.position);
          if (!perTerm[t.text]![docId]!.contains(want)) {
            ok = false;
            break;
          }
        }
        if (ok) {
          out.add(docId);
          break;
        }
      }
    }
    return [for (final id in out) CNitriteId(id)];
  }

  void _writeIndexEntries(
      IndexDescriptor idx, int indexTree, CDoc doc, CValue id,
      {required bool remove}) {
    for (final key in indexKeysFor(idx, doc, id)) {
      final k = decodeKey(key);
      if (remove) {
        _e.remove(indexTree, k);
      } else {
        _e.putEmpty(indexTree, k);
      }
    }
  }

  /// §1: "Uniqueness is enforced, not encoded." The SDK checks for an existing
  /// entry with the same `v1…vk` prefix before inserting; the tree does not
  /// need a different shape for it.
  void _checkUnique(
      int indexTree, IndexDescriptor idx, CDoc doc, CValue id) {
    for (final key in indexKeysFor(idx, doc, id)) {
      final values = indexEntryValues(key, idx.fields.length);
      // §3: the check is *skipped* when any value is NULL, not run and passed.
      if (!uniquenessApplies(values)) continue;
      final range = IndexScan.eqPrefix(values);
      for (final e in _e.scanTree(indexTree, range: range)) {
        if (indexEntryId(e.cke) != id) {
          throw InvalidArgumentException(
              'unique index on ${idx.fields.join(",")} already holds '
              '${values.join(",")}');
        }
      }
    }
  }

  CValue _idOf(List<int> cke) => decodeKey(Uint8List.fromList(cke));
}
