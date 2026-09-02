/// The catalog and the logical Nitrite model, `spec/05-catalog.md`.
///
/// This is where the semantic divergences of `research/nitrite-survey.md` §6
/// are settled: what a tree *means*, what a collection is called, and what
/// `"Unique"` spells on disk. A file can be byte-perfect and still be useless
/// if two SDKs disagree about any of that.
///
/// Two rules drive the shape of this file:
///
///   * **Tree names are arbitrary UTF-8** (§1). No escaping, no mangling, no
///     reserved characters. A collection may be called `"orders|2026+eu"`.
///   * **Unknown fields survive a rewrite** (§3, `11-conformance.md` §4). A
///     descriptor is therefore *held* as its decoded document and re-encoded
///     from it, so a field this implementation has never heard of comes back
///     out unchanged rather than being dropped by a round trip.
library;

import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'errors.dart';
import 'value.dart';

/// `kind` in a tree descriptor, §4.
class TreeKind {
  static const String data = 'data';
  static const String nameDict = 'name_dict';
  static const String index = 'index';
  static const String termDict = 'term_dict';
  static const String termIndex = 'term_index';
  static const String postings = 'postings';
  static const String rtree = 'rtree';
  static const String vectorGraph = 'vector_graph';
  static const String kv = 'kv';
  static const String internal = 'internal';

  /// §3: `levelled` is true for every kind whose data lives in manifest
  /// segments. `rtree` is a copy-on-write tree of its own page types, and the
  /// reserved trees 0–15 are copy-on-write too.
  static const Set<String> levelled = {
    data,
    nameDict,
    index,
    termDict,
    termIndex,
    postings,
    vectorGraph,
    kv,
  };

  static const Set<String> known = {
    data,
    nameDict,
    index,
    termDict,
    termIndex,
    postings,
    rtree,
    vectorGraph,
    kv,
    internal,
  };

  /// §11: the kinds that make a tree an index of its owner.
  static const Set<String> indexKinds = {
    index,
    termDict,
    termIndex,
    postings,
    rtree,
    vectorGraph,
  };
}

/// `params.index_type`, §10 — normative on-disk spelling.
///
/// Lower snake case, no hyphens, no camel case. Java and Dart write
/// `Unique`/`NonUnique`/`Fulltext` today and Rust writes
/// `unique`/`non-unique`/`full-text`; every SDK maps its own public constant to
/// these on write and back on read. The public API does not have to change,
/// the bytes do.
class IndexType {
  static const String unique = 'unique';
  static const String nonUnique = 'non_unique';
  static const String fullText = 'full_text';
  static const String spatial = 'spatial';
  static const String vector = 'vector';

  /// The five portable names, and only these five. Anything else MUST be
  /// treated as an opaque tree unless the reader owns the vendor feature bit
  /// that declared it (`11-conformance.md` §2).
  static const Set<String> portable = {
    unique,
    nonUnique,
    fullText,
    spatial,
    vector,
  };
}

/// `params.type` on a `data` tree, §5.
class DataTreeType {
  static const String collection = 'collection';
  static const String repository = 'repository';
}

/// One tree descriptor, §3.
///
/// Backed by the decoded document so unknown fields round-trip.
final class TreeDescriptor {
  TreeDescriptor(this.doc);

  factory TreeDescriptor.create({
    required int treeId,
    required String kind,
    int? root,
    bool? levelled,
    int entries = 0,
    int? created,
    String? keyKind,
    String? owner,
    int? nameDict,
    int features = 0,
    int? staleFrom,
    Map<String, CValue> params = const {},
  }) {
    final f = <String, CValue>{
      'tree_id': CInt.of(NumType.u32, treeId),
      'kind': CStr(kind),
      'levelled': CBool(levelled ?? TreeKind.levelled.contains(kind)),
      'entries': CInt.of(NumType.u64, entries),
      'created': CTimestamp(created ?? DateTime.now().millisecondsSinceEpoch),
      'features': CInt.of(NumType.u64, features),
      if (root != null) 'root': CInt.of(NumType.u64, root),
      if (keyKind != null) 'key_kind': CStr(keyKind),
      if (owner != null) 'owner': CStr(owner),
      if (nameDict != null) 'name_dict': CInt.of(NumType.u32, nameDict),
      if (staleFrom != null) 'stale_from': CInt.of(NumType.u64, staleFrom),
      if (params.isNotEmpty) 'params': CDoc(params),
    };
    return TreeDescriptor(CDoc(f));
  }

  /// The descriptor as stored, unknown fields included.
  final CDoc doc;

  int get treeId => ((doc['tree_id']! as CInt).magnitude).lo;
  String get kind => (doc['kind']! as CStr).value;
  bool get levelled => (doc['levelled'] as CBool?)?.value ?? false;
  int get entries => ((doc['entries'] as CInt?)?.magnitude)?.lo ?? 0;
  int get features => ((doc['features'] as CInt?)?.magnitude)?.lo ?? 0;
  int? get root => ((doc['root'] as CInt?)?.magnitude)?.lo;
  String? get owner => (doc['owner'] as CStr?)?.value;
  String? get keyKind => (doc['key_kind'] as CStr?)?.value;
  int? get nameDict => ((doc['name_dict'] as CInt?)?.magnitude)?.lo;
  int? get staleFrom => ((doc['stale_from'] as CInt?)?.magnitude)?.lo;

  /// §3.1 — every per-tree *policy* field, at the top level of one document.
  ///
  /// "That is the test for whether a field belongs in `params`: a *structural*
  /// field is one a reader must obey to read the tree at all."
  CDoc get params => (doc['params'] as CDoc?) ?? CDoc(const {});

  CValue? param(String name) => params[name];
  String? paramStr(String name) => (params[name] as CStr?)?.value;

  /// A copy with [changes] applied and every other field — including ones this
  /// implementation does not understand — left exactly as it was.
  TreeDescriptor with_(Map<String, CValue?> changes) {
    final f = {...doc.fields};
    for (final e in changes.entries) {
      if (e.value == null) {
        f.remove(e.key);
      } else {
        f[e.key] = e.value!;
      }
    }
    return TreeDescriptor(CDoc(f));
  }

  Uint8List encode() => encodeValue(doc);

  static TreeDescriptor decode(Uint8List bytes) =>
      TreeDescriptor(decodeValue(bytes) as CDoc);

  @override
  String toString() => 'tree ${doc['tree_id']} $kind';
}

/// Tree 0, and the reverse map in tree 3.
///
/// §2: "Trees 0, 1, 3, 6 and 7 always exist." Tree 3 is bootstrapped by
/// scanning the catalog if its descriptor is missing, which is what
/// [rebuildTreeIndex] does.
final class Catalog {
  Catalog(this.store, {int catalogRoot = 0, int treeIndexRoot = 0})
      : tree = CowTree(store, treeId: TreeId.catalog, root: catalogRoot),
        byId = CowTree(store, treeId: TreeId.treeIndex, root: treeIndexRoot);

  final PageStore store;
  final CowTree tree;

  /// Tree 3: `CKE(U32 tree_id) → CVE STR name`, the reverse of the catalog.
  final CowTree byId;

  /// `next_tree_id` (`spec/01-container.md` §2). §1: tree ids are **never
  /// reused**, so a stale reference is detectably dangling rather than
  /// silently pointing at a different tree.
  int nextTreeId = TreeId.firstUserTree;

  static Uint8List _nameKey(String name) => encodeKey(CStr(name));
  static Uint8List _idKey(int treeId) =>
      encodeKey(CInt.of(NumType.u32, treeId));

  /// Creates a tree and returns its descriptor.
  TreeDescriptor create(
    String name, {
    required String kind,
    String? owner,
    int? nameDict,
    String? keyKind,
    int features = 0,
    Map<String, CValue> params = const {},
  }) {
    if (name.isEmpty) {
      throw const InvalidArgumentException('a tree name cannot be empty');
    }
    if (tree.get(_nameKey(name)) != null) {
      throw InvalidArgumentException('a tree named "$name" already exists');
    }
    final d = TreeDescriptor.create(
      treeId: nextTreeId++,
      kind: kind,
      owner: owner,
      nameDict: nameDict,
      keyKind: keyKind,
      features: features,
      params: params,
    );
    put(name, d);
    return d;
  }

  void put(String name, TreeDescriptor d) {
    tree.put(_nameKey(name), d.encode());
    byId.put(_idKey(d.treeId), encodeValue(CStr(name)));
  }

  TreeDescriptor? get(String name) {
    final v = tree.get(_nameKey(name));
    return v == null ? null : TreeDescriptor.decode(v);
  }

  String? nameOf(int treeId) {
    final v = byId.get(_idKey(treeId));
    return v == null ? null : (decodeValue(v) as CStr).value;
  }

  /// §4: "A reader that does not recognize a `kind` MUST treat the tree as
  /// opaque: it may be listed and copied, it MUST NOT be deleted, and it MUST
  /// NOT be interpreted."
  bool mayDelete(String name) {
    final d = get(name);
    return d != null && TreeKind.known.contains(d.kind);
  }

  void drop(String name) {
    final d = get(name);
    if (d == null) return;
    if (!TreeKind.known.contains(d.kind)) {
      throw InvalidArgumentException(
          'tree "$name" has unrecognized kind "${d.kind}" and MUST NOT be '
          'deleted (spec/05-catalog.md section 4)');
    }
    tree.remove(_nameKey(name));
    byId.remove(_idKey(d.treeId));
  }

  Iterable<(String, TreeDescriptor)> get all sync* {
    for (final (k, v) in tree.scan()) {
      yield ((decodeKey(k) as CStr).value, TreeDescriptor.decode(v));
    }
  }

  /// Bootstraps tree 3 by scanning the catalog, §2.
  void rebuildTreeIndex() {
    for (final (name, d) in all.toList()) {
      byId.put(_idKey(d.treeId), encodeValue(CStr(name)));
    }
  }

  // ---------------------------------------------------------------------
  // §11 — the enumerations a reader must support, given only the catalog
  // ---------------------------------------------------------------------

  Iterable<(String, TreeDescriptor)> _data(String type) => all.where((e) =>
      e.$2.kind == TreeKind.data && e.$2.paramStr('type') == type);

  Iterable<String> get collections =>
      _data(DataTreeType.collection).map((e) => e.$1);

  Iterable<String> get repositories => _data(DataTreeType.repository)
      .where((e) => e.$2.param('key') == null)
      .map((e) => e.$1);

  Iterable<String> get keyedRepositories => _data(DataTreeType.repository)
      .where((e) => e.$2.param('key') != null)
      .map((e) => e.$1);

  Iterable<(String, TreeDescriptor)> indexesOf(String dataTree) => all.where(
      (e) =>
          e.$2.owner == dataTree && TreeKind.indexKinds.contains(e.$2.kind));

  Iterable<(String, TreeDescriptor)> get staleTrees =>
      all.where((e) => e.$2.staleFrom != null);

  /// §11: "what features does this file need?" — the union over every tree,
  /// which the caller ORs with the superblock's `features_required`.
  int get featuresRequired {
    var m = 0;
    for (final (_, d) in all) {
      m |= d.features;
    }
    return m;
  }
}

/// Tree 2, replacing `$nitrite_meta_map`. §6.
final class Attributes {
  Attributes(PageStore store, {int root = 0})
      : tree = CowTree(store, treeId: TreeId.attributes, root: root);

  final CowTree tree;

  /// §7: store metadata lives under this reserved name, replacing
  /// `$nitrite_store_info`.
  static const String storeKey = r'$store';

  CDoc? get(String treeName) {
    final v = tree.get(encodeKey(CStr(treeName)));
    return v == null ? null : decodeValue(v) as CDoc;
  }

  void put(String treeName, CDoc attrs) =>
      tree.put(encodeKey(CStr(treeName)), encodeValue(attrs));

  /// Sets `last_modified_at`, which §6 requires to be written **in the same
  /// commit as the mutation it describes**. Batch atomicity makes that free,
  /// so it is not a second write.
  void touch(String treeName, int nowMs) {
    final cur = get(treeName) ?? CDoc({'name': CStr(treeName)});
    put(treeName,
        CDoc({...cur.fields, 'last_modified_at': CTimestamp(nowMs)}));
  }

  /// §7.
  void initStore({
    required String formatVersion,
    required String nitriteVersion,
    int schemaVersion = 1,
    int? nowMs,
  }) {
    final existing = get(storeKey);
    final writers = existing == null
        ? const <CValue>[]
        : ((existing['writers'] as CArray?)?.items ?? const []);
    put(
        storeKey,
        CDoc({
          ...?existing?.fields,
          'created': existing?['created'] ??
              CTimestamp(nowMs ?? DateTime.now().millisecondsSinceEpoch),
          'format_version': CStr(formatVersion),
          'nitrite_version': CStr(nitriteVersion),
          'schema_version': CInt.of(NumType.u32, schemaVersion),
          'writers': CArray(writers),
        }));
  }

  /// §7: `writers` accumulates each distinct `writer_id` that has modified the
  /// file — "a genuinely useful field the moment a file is being handed
  /// between SDKs, and the first thing to look at when a file misbehaves".
  void recordWriter(String writerId) {
    final store = get(storeKey);
    if (store == null) {
      throw const InvalidArgumentException(r'$store has not been initialized');
    }
    final writers = (store['writers'] as CArray?)?.items ?? const [];
    if (writers.any((w) => w is CStr && w.value == writerId)) return;
    put(storeKey,
        CDoc({...store.fields, 'writers': CArray([...writers, CStr(writerId)])}));
  }
}
