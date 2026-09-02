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
import 'cow.dart';
import 'cve.dart';
import 'engine.dart';
import 'errors.dart';
import 'index.dart';
import 'stats.dart';
import 'value.dart';

/// Format version reported in the store metadata of `05` §7.
const String kFormatVersion = 'CFF 1.0';

final class Database {
  Database({Engine? engine})
      : engine = engine ?? Engine(),
        _catalogStore = PageStore() {
    catalog = Catalog(_catalogStore);
    attributes = Attributes(_catalogStore);
    attributes.initStore(
        formatVersion: kFormatVersion, nitriteVersion: 'reference-dart');
  }

  final Engine engine;
  final PageStore _catalogStore;
  late final Catalog catalog;
  late final Attributes attributes;

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
      final doc = decodeValue(e.value) as CDoc;
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
    return v == null ? null : decodeValue(v) as CDoc;
  }

  Iterable<(CValue, CDoc)> get all sync* {
    for (final e in _e.scanTree(treeId)) {
      yield (_idOf(e.cke), decodeValue(e.value) as CDoc);
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
