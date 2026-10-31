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

import 'bytes.dart';
import 'catalog.dart';
import 'cke.dart';
import 'container.dart';
import 'cve.dart';
import 'engine.dart';
import 'errors.dart';
import 'analyzer.dart';
import 'fulltext.dart';
import 'rtree.dart';
import 'vector.dart';
import 'index.dart';
import 'stats.dart';
import 'value.dart';

/// Format version reported in the store metadata of `05` §7.
const String kFormatVersion = 'CFF 1.0';

final class Database {
  Database({
    Engine? engine,
    int catalogRoot = 0,
    int catalogNonce = 0,
    int treeIndexRoot = 0,
    int attributesRoot = 0,
    int attributesNonce = 0,
    int nextTreeId = TreeId.firstUserTree,
    bool initStoreMetadata = true,
  }) : engine = engine ?? Engine() {
    // §2 of `spec/05-catalog.md`: the catalog is tree 0 and attributes are
    // tree 2, both in the **same** page space as everything else, both rooted
    // from the superblock. A separate store for them would have no page ids a
    // superblock could name.
    final store = this.engine.store;
    catalog = Catalog(store,
        catalogRoot: catalogRoot,
        catalogNonce: catalogNonce,
        treeIndexRoot: treeIndexRoot);
    catalog.nextTreeId = nextTreeId;
    attributes =
        Attributes(store, root: attributesRoot, rootNonce: attributesNonce);
    this.engine.outerTrees
      ..['the catalog'] = catalog.tree
      ..['tree 3'] = catalog.byId
      ..['the attributes'] = attributes.tree;
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
        nameDict: _createNameDict(name),
        params: {'type': const CStr(DataTreeType.collection)});
    return Collection(this, name, d);
  }

  /// §5: "a collection is a `data` tree ... and a name dictionary tree beside
  /// it" (F-200: Dart made none, so Rust and Java had nowhere to intern).
  /// Dart writes names inline; the tree is for the other two.
  int _createNameDict(String owner) =>
      catalog.create('$owner\$names', kind: TreeKind.nameDict, owner: owner, keyKind: 'u32').treeId;

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
        nameDict: _createNameDict(name),
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

  /// Open spatial and vector indexes, by name. They hold copied pages, so
  /// they live here rather than in a [Collection], which is a fresh object
  /// per lookup; the engine's commit republishes them.
  final Map<String, SpatialIndex> spatialIndexes = {};
  final Map<String, VectorIndex> vectorIndexes = {};
  final Set<String> _indexesOpened = {};
  final Map<int, NameDict> _dicts = {};

  /// Opens [owner]'s spatial and vector indexes once.
  void _openIndexes(String owner) {
    if (!_indexesOpened.add(owner)) return;
    // F-210: the owner's index trees, not a scan of the whole catalog.
    for (final (n, d) in catalog.indexesOf(owner)) {
      if (d.kind == TreeKind.rtree && !spatialIndexes.containsKey(n)) {
        _register(spatialIndexes[n] = SpatialIndex(this, n, d));
      } else if (d.kind == TreeKind.vectorGraph && !vectorIndexes.containsKey(n)) {
        _register(vectorIndexes[n] = VectorIndex(this, n, d));
      }
    }
  }

  void _register(Object ix) => engine.commitHooks.add(
      ix is SpatialIndex ? ix.commit : (ix as VectorIndex).commit);

  String _uniqueName(String base) {
    var name = base;
    for (var i = 2; catalog.get(name) != null; i++) {
      name = '$base-$i';
    }
    return name;
  }
}

/// A `data` tree and the indexes that serve it.
final class Collection {
  Collection(this.db, this.name, this.descriptor);

  final Database db;
  final String name;
  final TreeDescriptor descriptor;

  /// The next `term_id` to allocate, per `term_index` tree, held rather than
  /// re-derived.
  ///
  /// [_internTerm] used to compute it as `_e.scanTree(revId).length + 1` — a
  /// full scan of the whole reverse term index for **every new term**, so
  /// building a vocabulary of V terms cost O(V^2) row reads. The Java
  /// implementation has always held a `nextTermId` counter and Rust never had
  /// this path, so this was Dart alone.
  ///
  /// Deriving a monotone counter instead of holding it is a shape this project
  /// has met before: `14-security.md` section 4.1's nonce floor was derived
  /// rather than held, which was defect 61.
  final Map<int, int> _nextTermId = {};

  int get treeId => descriptor.treeId;

  Engine get _e => db.engine;

  /// F-200: the field-name dictionary documents written by Java and Rust
  /// encode against (02 §5.3), seeded with §5.4's reserved fields at 1-5 as
  /// they hold them. Dart writes names inline, so this only ever grows from
  /// the file. Cached per data tree on the [Database].
  NameDict get _names => db._dicts[treeId] ??= _loadNames();

  NameDict _loadNames() {
    final d = NameDict.withReservedFields();
    final tree = descriptor.nameDict;
    if (tree == null) return d;
    final rows = <int, String>{
      for (final e in _e.scanTree(tree))
        (decodeKey(e.cke) as CInt).magnitude.lo: (decodeValue(e.value) as CStr).value
    };
    for (final id in rows.keys.toList()..sort()) {
      if (id <= d.length && d.nameOf(id) == rows[id]) continue;
      if (d.intern(rows[id]!) != id) {
        throw CorruptionException('name_id $id of $name does not follow the ids before it');
      }
    }
    return d;
  }

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
      final doc = expectValue<CDoc>(decodeValue(e.value, dict: _names), 'document');
      _writeIndexEntries(idx, d.treeId, doc, _idOf(e.cke), remove: false);
    }
    return d;
  }

  List<(TreeDescriptor, IndexDescriptor)> get indexes => [
        for (final (_, d) in db.catalog.indexesOf(name))
          if (d.kind == TreeKind.index) (d, IndexDescriptor.fromDescriptor(d))
      ];

  /// This collection's open spatial and vector indexes.
  Iterable<SpatialIndex> get spatialIndexes {
    db._openIndexes(name);
    return db.spatialIndexes.values.where((i) => i.owner == name);
  }

  Iterable<VectorIndex> get vectorIndexes {
    db._openIndexes(name);
    return db.vectorIndexes.values.where((i) => i.owner == name);
  }

  /// Creates a spatial index over a geometry field and populates it,
  /// `08-spatial.md` §2. `dimensions = 3` always means Z, never M.
  SpatialIndex createSpatialIndex(String field, {int dimensions = 2, int? srid}) {
    if (dimensions < 2 || dimensions > 4) {
      throw InvalidArgumentException('dimensions $dimensions outside 2..4');
    }
    db._openIndexes(name);
    final indexName = db._uniqueName('idx:$name:$field:spatial');
    final d = db.catalog.create(indexName,
        kind: TreeKind.rtree,
        owner: name,
        keyKind: 'opaque',
        features: 1 << Feature.spatial,
        params: {
          'index_type': const CStr(IndexType.spatial),
          'data_tree': CInt.of(NumType.u32, treeId),
          'field': CStr(field),
          'dimensions': CInt.of(NumType.u8, dimensions),
          if (srid != null) 'srid': CInt.of(NumType.u32, srid),
        }).withRoot(0, 0);
    db.catalog.put(indexName, d);
    final ix = SpatialIndex(db, indexName, d);
    for (final (id, doc) in all) {
      ix.put((id as CNitriteId).id, doc, null);
    }
    db._register(db.spatialIndexes[indexName] = ix);
    _e.commit();
    return ix;
  }

  /// Creates a vector index over a `VECTOR` field, `09-vector.md` §5, with
  /// both slot maps named in the descriptor.
  VectorIndex createVectorIndex(String field,
      {required int dim, String metric = VectorMetric.l2, int initialSlots = 16}) {
    vectorDistance(const [0.0], const [0.0], metric); // refuses an unknown one
    db._openIndexes(name);
    final indexName = db._uniqueName('idx:$name:$field:vector');
    final graph = db.catalog.create(indexName,
        kind: TreeKind.vectorGraph,
        owner: name,
        keyKind: 'array',
        features: 1 << Feature.vector);
    final slots = db.catalog.create('$indexName:slots', kind: TreeKind.kv, owner: indexName);
    final docs = db.catalog.create('$indexName:docs', kind: TreeKind.kv, owner: indexName);
    final region = VectorRegion.create(_e.store,
        dim: dim, slots: initialSlots < 2 ? 2 : initialSlots);
    CInt u(NumType t, int v) => CInt.of(t, v);
    // As Java: the adjacency is a copy-on-write tree rooted at `root`
    // (F-196), so `levelled` is false whatever 05 §3's kind table says.
    final d = graph.with_({
      'levelled': const CBool(false),
      'params': CDoc({
        'index_type': const CStr(IndexType.vector),
        'data_tree': u(NumType.u32, treeId),
        'field': CStr(field),
        'dim': u(NumType.u32, dim),
        'metric': CStr(metric),
        'algorithm': const CStr('vamana'),
        'precision': const CStr('f32'),
        'vector_region': u(NumType.u64, region.startPage),
        'entry_points': CArray(const []),
        'max_level': u(NumType.u8, 0),
        'm': u(NumType.u16, 32),
        'ef_construction': u(NumType.u16, 200),
        'neighbours_sorted': const CBool(false),
        'slot_to_doc': u(NumType.u32, slots.treeId),
        'doc_to_slot': u(NumType.u32, docs.treeId),
        // §3: adjacency records are read randomly and hot.
        'inline_values': const CBool(true),
      }),
    }).withRoot(0, 0);
    db.catalog.put(indexName, d);
    final ix = VectorIndex(db, indexName, d);
    for (final (id, doc) in all) {
      ix.put((id as CNitriteId).id, doc);
    }
    db._register(db.vectorIndexes[indexName] = ix);
    _e.commit();
    return ix;
  }

  /// The spatial and vector side of a write; [doc] null is a delete.
  void _maintain(CValue id, CDoc? doc, CDoc? previous) {
    final n = (id as CNitriteId).id;
    for (final ix in spatialIndexes) {
      doc == null ? ix.remove(n, previous) : ix.put(n, doc, previous);
    }
    for (final ix in vectorIndexes) {
      doc == null ? ix.remove(n) : ix.put(n, doc);
    }
  }

  /// Inserts or replaces one document, maintaining every index in the same
  /// batch (§8).
  void put(CValue id, CDoc doc) {
    final existing = get(id);
    if (id is CNitriteId) _maintain(id, doc, existing);
    for (final (tree, idx) in indexes) {
      if (existing != null) {
        _writeIndexEntries(idx, tree.treeId, existing, id, remove: true);
      }
      if (idx.unique) _checkUnique(tree.treeId, idx, doc, id);
      _writeIndexEntries(idx, tree.treeId, doc, id, remove: false);
    }
    // Full-text indexes are maintained here too, in the same call. They used to
    // be built by `createFullTextIndex` and never touched again, so every write
    // after the build left the index silently wrong in both directions: a new
    // document was invisible, and a term an update removed still matched.
    for (final (post, fields) in _textIndexes) {
      final a = _analyzerOf(post);
      if (existing != null) {
        _unindexDocumentText(post, a, fields, existing, id);
      }
      final positions = optionalField<CBool>(post.params, 'positions', 'text index params')?.value ?? true;
      _indexDocumentText(post, a, fields, doc, id, positions);
    }
    _e.put(treeId, id, encodeValue(doc));
    _e.publishIfDue();
  }

  void remove(CValue id) {
    final existing = get(id);
    if (existing == null) return;
    if (id is CNitriteId) _maintain(id, null, existing);
    for (final (tree, idx) in indexes) {
      _writeIndexEntries(idx, tree.treeId, existing, id, remove: true);
    }
    for (final (post, fields) in _textIndexes) {
      _unindexDocumentText(post, _analyzerOf(post), fields, existing, id);
    }
    _e.remove(treeId, id);
    _e.publishIfDue();
  }

  CDoc? get(CValue id) {
    final v = _e.get(treeId, id);
    return v == null ? null : expectValue<CDoc>(decodeValue(v, dict: _names), 'document');
  }

  Iterable<(CValue, CDoc)> get all sync* {
    for (final e in _e.scanTree(treeId)) {
      yield (_idOf(e.cke), expectValue<CDoc>(decodeValue(e.value, dict: _names), 'document'));
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
    // are walked once to count and once to bound. F-183: both passes stream;
    // the first used to keep every key (O(entries) memory).
    var total = 0;
    for (final _ in _e.scanTree(indexTree.treeId)) {
      total++;
    }
    final quota = total <= 64 ? 1 : (total / 64).ceil();
    var i = 0;
    for (final e in _e.scanTree(indexTree.treeId)) {
      // F-184: walk the key in place. Decoding the whole entry, copying its
      // values and re-encoding the prefix made ~10^7 short-lived objects per
      // pass, which outran old-gen GC (+300 MB RSS at 10^7).
      final r = ByteReader(e.cke)..u8(); // Group.array
      var isNull = false;
      for (var f = 0; f < idx.fields.length; f++) {
        r.u8(); // 0x01 element marker
        if (r.data[r.position] == Group.nul) isNull = true;
        readKey(r, 1);
      }
      b.add(Uint8List.sublistView(e.cke, 0, r.position), e.cke,
          seq: 0, isNull: isNull);
      if (++i % quota == 0) b.boundary(e.cke);
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
    return s == null ? null : IndexStats.fromDoc(expectValue<CDoc>(s, 'index stats'));
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
    final ap = p['analyzer_params'] == null
        ? CDoc(const {})
        : expectField<CDoc>(p, 'analyzer_params', 'text index params');
    final words = ap['stopwords'] == null
        ? const <String>[]
        : [
            for (final e in expectField<CArray>(ap, 'stopwords', 'text index params').items)
              expectValue<CStr>(e, 'text index params stopword').value
          ];
    return Analyzer(
      name: expectField<CStr>(p, 'analyzer', 'text index params').value,
      stopwords: words,
      stemmer: ap['stemmer'] == null
          ? Stemmer.none
          : expectField<CStr>(ap, 'stemmer', 'text index params').value,
    );
  }

  void _indexDocumentText(TreeDescriptor postings, Analyzer a,
      List<String> fields, CDoc doc, CValue id, bool positions) {
    final byTerm = <String, List<int>>{};
    for (final path in fields) {
      for (final v in resolvePath(doc, path) ?? const <CValue>[]) {
        for (final t in a.analyzeValue(v is CStr ? v.value : null)) {
          (byTerm[t.text] ??= []).add(t.position);
        }
      }
    }
    if (byTerm.isEmpty) return;

    final p = postings.params;
    final dictId = expectField<CInt>(p, 'term_dict', 'text index params').magnitude.lo;
    final revId = expectField<CInt>(p, 'term_index', 'text index params').magnitude.lo;
    final docId = (id as CNitriteId).id;

    for (final entry in byTerm.entries) {
      final term = entry.key;
      final pos = entry.value..sort();
      final termId = _internTerm(dictId, revId, term);

      // Read the block this document belongs in, add the posting, write back.
      // §4.4: an update rewrites the block it touches, not the posting list
      // (F-190: it used to rewrite the whole list, O(df) per write).
      final hit = _blockFor(postings, termId, docId);
      final kept = hit?.$2.postings ?? const <Posting>[];
      final old = kept.where((q) => q.docId == docId).firstOrNull?.freq ?? 0;
      final merged = <Posting>[
        for (final q in kept)
          if (q.docId != docId) q,
        Posting(docId, pos.length, positions ? pos : const []),
      ]..sort((x, y) => x.docId.compareTo(y.docId));
      _rewriteBlock(postings, termId, hit?.$1, merged, positions);
      _adjustTermStats(dictId, term, old == 0 ? 1 : 0, pos.length - old);
    }
  }

  /// Removes every posting [id] has in [postings], for the terms of [doc].
  ///
  /// The mirror of [_indexDocumentText]. Without it a full-text index was
  /// frozen at the moment it was built: a term dropped by an update kept its
  /// posting, so a search returned a document that no longer contained the word
  /// — a silent false positive — and `07-fulltext.md` section 1's "`df` ... and
  /// `ttf` ... MUST be accurate" was false after the first write.
  void _unindexDocumentText(TreeDescriptor postings, Analyzer a,
      List<String> fields, CDoc doc, CValue id) {
    final terms = <String>{};
    for (final path in fields) {
      for (final v in resolvePath(doc, path) ?? const <CValue>[]) {
        for (final t in a.analyzeValue(v is CStr ? v.value : null)) {
          terms.add(t.text);
        }
      }
    }
    if (terms.isEmpty) return;

    final p = postings.params;
    final dictId = expectField<CInt>(p, 'term_dict', 'text index params').magnitude.lo;
    final positions = optionalField<CBool>(p, 'positions', 'text index params')?.value ?? true;
    final docId = (id as CNitriteId).id;

    for (final term in terms) {
      final entry = _e.get(dictId, CStr(term));
      if (entry == null) continue;
      final termId = TermEntry.decode(entry).id;
      final hit = _blockFor(postings, termId, docId);
      if (hit == null) continue;
      final gone = hit.$2.postings.where((q) => q.docId == docId).toList();
      if (gone.isEmpty) continue;
      _rewriteBlock(postings, termId, hit.$1,
          [for (final q in hit.$2.postings) if (q.docId != docId) q], positions);
      // `term_id` is never reused even when the last posting goes, so the
      // dictionary entry stays and only the statistics move.
      _adjustTermStats(dictId, term, -1, -gone.first.freq);
    }
  }

  /// F-190, §4.4: the one block that holds or would hold [docId], the last
  /// starting at or before it, else the term's first, as (key's first doc,
  /// block); null when the term has none.
  /// ponytail: the engine has no reverse scan, so the floor is a forward walk
  /// over the term's block keys, O(df / 128) keys and one decode per write;
  /// a reverse cursor if a very common term makes that slow.
  (int, PostingsBlock)? _blockFor(
      TreeDescriptor postings, int termId, int docId) {
    final lower = PostingsBlock.keyFor(termId, -0x8000000000000000);
    final upper = PostingsBlock.keyFor(termId + 1, -0x8000000000000000);
    (int, Uint8List)? hit;
    for (final e in _e.scanTree(postings.treeId, range: KeyRange(lower, upper))) {
      final first = expectValue<CNitriteId>(
              expectValue<CArray>(decodeKey(e.cke), 'postings key').items[1],
              'postings key first doc')
          .id;
      if (hit != null && first > docId) break;
      hit = (first, e.value);
      if (first > docId) break;
    }
    return hit == null ? null : (hit.$1, PostingsBlock.decode(hit.$2));
  }

  /// Replaces one block: an overflow past 128 splits it, an empty one goes.
  void _rewriteBlock(TreeDescriptor postings, int termId, int? oldFirst,
      List<Posting> block, bool positions) {
    if (oldFirst != null) {
      _e.remove(postings.treeId,
          decodeKey(PostingsBlock.keyFor(termId, oldFirst)));
    }
    for (final b in PostingsBlock.split(block, hasPositions: positions)) {
      _e.put(postings.treeId,
          decodeKey(PostingsBlock.keyFor(termId, b.firstDoc)), b.encode());
    }
  }

  /// Every full-text index over this collection, as (descriptor, fields).
  List<(TreeDescriptor, List<String>)> get _textIndexes => [
        for (final (_, d) in db.catalog.indexesOf(name))
          if (d.kind == TreeKind.postings)
            (
              d,
              [
                for (final f
                    in expectField<CArray>(d.params, 'fields', 'text index params').items)
                  expectValue<CStr>(f, 'text index params field').value
              ]
            )
      ];

  int _internTerm(int dictId, int revId, String term) {
    final existing = _e.get(dictId, CStr(term));
    if (existing != null) return TermEntry.decode(existing).id;
    // Section 1: "term_id is allocated append-only and never reused (same
    // discipline as name_id)." Append-only and never reused is exactly what
    // makes a held counter correct — see [_nextTermId]. The tree is scanned
    // once, on the first new term after this collection is opened, to recover
    // the high-water mark; every later term is O(1).
    final next = _nextTermId.putIfAbsent(revId, () {
      var max = 0;
      for (final e in _e.scanTree(revId)) {
        final id = expectValue<CInt>(decodeKey(e.cke), 'term_id').magnitude.lo;
        if (id > max) max = id;
      }
      return max + 1;
    });
    _nextTermId[revId] = next + 1;
    _e.put(revId, CInt.of(NumType.u32, next), encodeValue(CStr(term)));
    _e.put(dictId, CStr(term), TermEntry(next, 0, 0).encode());
    return next;
  }

  void _adjustTermStats(int dictId, String term, int dDf, int dTtf) {
    final e = TermEntry.decode(_e.get(dictId, CStr(term))!);
    _e.put(dictId, CStr(term),
        TermEntry(e.id, e.df + dDf, e.ttf + dTtf).encode());
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
        expectField<CInt>(postings.params, 'term_dict', 'text index params').magnitude.lo;
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
    final positions = optionalField<CBool>(postings.params, 'positions', 'text index params')?.value ?? false;
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
