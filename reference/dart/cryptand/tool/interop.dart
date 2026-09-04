/// The Dart half of `spec/11-conformance.md` §6's mandatory round-trip gate:
///
/// > "for each golden file, open it in implementation A, mutate it, close it,
/// > open it in B, verify, mutate, close, reopen in A. **This is the actual
/// > product claim and it must be tested as such.**"
///
/// The other half is `reference/rust/cryptand/src/bin/interop.rs`, which
/// implements the same four commands over the same fixture. Neither reads the
/// other's source; both read `spec/`.
///
/// Usage: `dart run tool/interop.dart write|read|mutate <tag>|verify <file>`
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';

const String collectionName = 'orders';
const String nameDictName = 'orders\$names';
const String indexName = 'idx:orders:country:non_unique';
const int n = 400;
const List<String> countries = ['de', 'fr', 'uk', 'in', 'us'];

/// A document is `{_id, seq, country, note}`. Every tenth `note` is 900 bytes,
/// which is above `desktop`'s `vlog_min` of 256, so the fixture exercises both
/// the inline and the separated value path.
CDoc document(int i, {Uint8List? note}) {
  note ??= Uint8List(i % 10 == 0 ? 900 : 40)..fillRange(0, i % 10 == 0 ? 900 : 40, i % 251);
  return CDoc({
    '_id': CNitriteId(i),
    'seq': CInt.of(NumType.i32, i),
    'country': CStr(countries[i % 5]),
    'note': CBytes(note),
  });
}

/// The canonical digest both implementations compute over the visible state.
/// CRC-32C because `spec/00-conventions.md` §6 already makes it mandatory
/// everywhere, so neither side needs a primitive the other lacks.
int digest(List<(int, String, Uint8List)> rows) {
  final w = ByteWriter(rows.length * 32);
  for (final (id, country, note) in rows) {
    w.u64(id);
    final c = encodeUtf8Strict(country);
    w
      ..u32(c.length)
      ..bytes(c)
      ..u32(note.length)
      ..bytes(Uint8List.sublistView(note, 0, note.length < 8 ? note.length : 8));
  }
  return crc32c(w.view);
}

class Interop {
  Interop(this.db, this.data, this.dict, this.index, this.idx, this.names);

  final Database db;
  final int data;
  final int dict;
  final int index;
  final IndexDescriptor? idx;
  final NameDict names;

  Engine get e => db.engine;

  static Interop open(String path) {
    final db = DatabaseFile.open(path, key: keyArg);
    final data = db.catalog.get(collectionName)?.treeId;
    final dictTree = db.catalog.get(nameDictName)?.treeId;
    if (data == null || dictTree == null) {
      throw StateError('the file does not hold $collectionName');
    }
    final indexDesc = db.catalog.get(indexName);
    final index = indexDesc?.treeId ?? 0;
    final idx = indexDesc == null
        ? null
        : IndexDescriptor.fromDescriptor(indexDesc);
    // §5.3 — the per-tree field-name dictionary, read back from its own tree.
    final names = NameDict();
    final rows = <int, String>{};
    for (final entry in db.engine.scanTree(dictTree)) {
      final id = ((decodeKey(entry.cke) as CInt).magnitude).lo;
      rows[id] = (decodeValue(entry.value) as CStr).value;
    }
    final ids = rows.keys.toList()..sort();
    for (final id in ids) {
      final assigned = names.intern(rows[id]!);
      if (assigned != id) {
        throw CorruptionException(
            'name_id $id does not reconstruct in order (got $assigned)');
      }
    }
    return Interop(db, data, dictTree, index, idx, names);
  }

  int intern(String name) {
    final existing = names.idOf(name);
    if (existing != null) return existing;
    final id = names.intern(name);
    // §5.3: a writer MUST write new dictionary entries in the **same commit**
    // as the document that first uses them.
    e.put(dict, CInt.of(NumType.u32, id), encodeValue(CStr(name)));
    return id;
  }

  CDoc? read(int id) {
    final v = e.get(data, CNitriteId(id));
    return v == null ? null : decodeValue(v, dict: names) as CDoc;
  }

  void put(CDoc doc) {
    final id = (doc['_id']! as CNitriteId).id;
    for (final name in doc.fields.keys) {
      intern(name);
    }
    if (index != 0) {
      final prev = read(id);
      if (prev != null) {
        for (final k in indexKeysFor(idx!, prev, CNitriteId(id))) {
          e.remove(index, decodeKey(k));
        }
      }
      for (final k in indexKeysFor(idx!, doc, CNitriteId(id))) {
        e.putEmpty(index, decodeKey(k));
      }
    }
    e.put(data, CNitriteId(id), encodeValue(doc, dict: names));
  }

  List<(int, String, Uint8List)> rows() {
    final out = <(int, String, Uint8List)>[];
    for (final entry in e.scanTree(data)) {
      final id = (decodeKey(entry.cke) as CNitriteId).id;
      final doc = decodeValue(entry.value, dict: names) as CDoc;
      // §5.4: `_id` MUST equal the tree key of the entry.
      final declared = (doc['_id']! as CNitriteId).id;
      if (declared != id) {
        throw CorruptionException('document at key $id carries _id $declared');
      }
      out.add((
        id,
        (doc['country']! as CStr).value,
        (doc['note']! as CBytes).value,
      ));
    }
    out.sort((a, b) => a.$1.compareTo(b.$1));
    return out;
  }
}

void cmdWrite(String path) {
  final f = File(path);
  if (f.existsSync()) f.deleteSync();
  final db = keyArg == null
      ? Database(engine: Engine(memtableEntries: 120, vlogMin: 256))
      : DatabaseFile.create(path,
          credential: keyArg!, kdf: Keyslot.kdfRaw, memtableEntries: 120);
  final dictDesc = db.catalog.create(nameDictName,
      kind: TreeKind.nameDict, owner: collectionName, keyKind: 'u32');
  final dataDesc = db.catalog.create(collectionName,
      kind: TreeKind.data,
      nameDict: dictDesc.treeId,
      keyKind: 'nitrite_id',
      params: {'type': const CStr(DataTreeType.collection)});
  final idxDesc = db.catalog.create(indexName,
      kind: TreeKind.index,
      owner: collectionName,
      keyKind: 'array',
      params: {
        'index_type': const CStr(IndexType.nonUnique),
        'data_tree': CInt.of(NumType.u32, dataDesc.treeId),
        'fields': CArray([const CStr('country')]),
        'sparse': const CBool(false),
      });
  final io = Interop(db, dataDesc.treeId, dictDesc.treeId, idxDesc.treeId,
      IndexDescriptor.fromDescriptor(idxDesc), NameDict());
  // §5.4: the reserved names SHOULD occupy `name_id` 1..5 in every data tree.
  for (final r in ['_id', '_revision', '_modified', '_source', '_type']) {
    io.intern(r);
  }
  for (var i = 0; i < n; i++) {
    io.put(document(i));
    if (i % 120 == 119) db.engine.flush();
  }
  db.engine.flush();
  DatabaseFile.save(db, path, writerId: 'cryptand-dart/1.0.0');
  stdout.writeln('wrote $n documents to $path');
}

void cmdRead(String path) {
  final io = Interop.open(path);
  final rows = io.rows();
  stdout
    ..writeln('docs=${rows.length}')
    ..writeln('digest=${digest(rows).toRadixString(16).padLeft(8, '0')}')
    ..writeln('dict=${io.names.length}')
    ..writeln('writer=${io.db.engine.writers.last}')
    ..writeln('page_size=${io.e.pageSize}')
    ..writeln('commit_id=${io.e.commitId}')
    ..writeln('segments=${io.e.manifest.all.length}')
    ..writeln('vlog_segments=${io.e.vlog.segments.length}');
  final trees = [for (final (name, _) in io.db.catalog.all) name]..sort();
  stdout.writeln('trees=${trees.join(',')}');
  if (io.index != 0) {
    // §7 — the index must answer a prefix scan over what the other side wrote.
    final range = KeyRange.prefix(Keys.prefixOfArray([const CStr('de')]));
    stdout.writeln('index_de=${io.e.scanTree(io.index, range: range).length}');
  }
}

void cmdMutate(String path, String tag) {
  final io = Interop.open(path);
  var updated = 0;
  var deleted = 0;
  for (var i = 0; i < n; i++) {
    if (i % 13 == 0) {
      final prev = io.read(i);
      if (prev != null) {
        if (io.index != 0) {
          for (final k in indexKeysFor(io.idx!, prev, CNitriteId(i))) {
            io.e.remove(io.index, decodeKey(k));
          }
        }
        io.e.remove(io.data, CNitriteId(i));
        deleted++;
      }
    } else if (i % 7 == 0) {
      final note = Uint8List(300)..fillRange(0, 300, 0x2E);
      final tagBytes = encodeUtf8Strict(tag);
      note.setRange(0, tagBytes.length, tagBytes);
      io.put(document(i, note: note));
      updated++;
    }
  }
  for (var i = n; i < n + 50; i++) {
    io.put(document(i));
  }
  // A field name neither the fixture nor the other side has seen, which
  // exercises §5.3's "on encountering an unknown `name_id` it MUST re-read the
  // dictionary tree before failing".
  io.intern('touched_by_$tag');
  io.e.flush();
  DatabaseFile.save(io.db, path, writerId: 'cryptand-dart/1.0.0');
  stdout.writeln('mutated by $tag: $updated updated, $deleted deleted, '
      '50 inserted');
}

int cmdVerify(String path) {
  final io = Interop.open(path);
  final findings = io.e.verify();
  final structure = io.e.verifyStructure();
  // `spec/01-container.md` §9 step 8: with a key, `sb_mac`, every page's AEAD
  // tag, and no `(key, nonce)` pair twice. Reported as its own class because
  // §9 is explicit that tampering is neither corruption nor a leak.
  final crypto = io.e.verifyEncryption();
  stdout.writeln('verify: ${io.e.manifest.all.length} segments, '
      '${findings.length + structure.findings.length + crypto.length} '
      'structural findings');
  for (final f in findings) {
    stdout.writeln('  Corruption: quarantined segment ${f.segmentId}');
  }
  for (final f in structure.findings) {
    stdout.writeln('  Corruption: $f');
  }
  for (final f in crypto) {
    stdout.writeln('  Tampering: $f');
  }
  return findings.isEmpty && structure.isClean && crypto.isEmpty ? 0 : 1;
}

/// `spec/14-security.md` section 3.3's `kdf = 0` credential, when the gate is
/// run over an encrypted file. A fixed key rather than a password because the
/// subject is the *format*, not Argon2id, which the vectors already pin.
List<int>? keyArg;

void main(List<String> args) {
  final at = args.indexOf('--key');
  if (at >= 0 && at + 1 < args.length) {
    final hex = args[at + 1];
    keyArg = [
      for (var i = 0; i + 1 < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16)
    ];
    args = [...args]..removeRange(at, at + 2);
  }
  if (args.length < 2) {
    stderr.writeln('interop write|read|mutate <tag>|verify <file> [--key <hex>]');
    exit(2);
  }
  try {
    switch (args[0]) {
      case 'write':
        cmdWrite(args[1]);
      case 'read':
        cmdRead(args[1]);
      case 'mutate':
        if (args.length < 3) {
          stderr.writeln('mutate needs a tag');
          exit(2);
        }
        cmdMutate(args[1], args[2]);
      case 'verify':
        exit(cmdVerify(args[1]));
      default:
        stderr.writeln('unknown command ${args[0]}');
        exit(2);
    }
  } on Object catch (err) {
    stderr.writeln(err);
    exit(1);
  }
}
