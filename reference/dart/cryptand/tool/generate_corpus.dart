/// Generates `reference/conformance/files/` — the golden and deliberately
/// broken databases of `spec/11-conformance.md` section 6 and
/// `spec/14-security.md` section 13, plus the `manifest.json` that says what
/// each one must do.
///
/// Usage: `dart run tool/generate_corpus.dart [outdir]`
///
/// **Why this exists as a shared corpus rather than a fixture in each suite.**
/// All three implementations already have thorough negative tests, and every
/// one of them builds its own broken file, in its own writer, and then checks
/// that its own reader refuses it. That arrangement cannot find a disagreement:
/// phase 15 recorded the general form of it — "a self-generated vector set
/// cannot contain this fix: the generator and its test both knew they were
/// writing a prefix". A corpus is the fix. These bytes exist once; three
/// readers that did not write them have to agree about what they mean.
///
/// The files are deliberately small. A conformance corpus lives in the
/// repository forever and is read on every CI run, so each fixture uses the
/// `mobile` profile's 4 KiB pages and a few hundred documents — enough
/// structure to hold several segments, a value log, an index and a name
/// dictionary, and nothing more.
///
/// The document shape is the one `tool/interop.dart` already writes, and that
/// is not laziness: all three implementations already have a reader for it, so
/// a corpus runner in each is a thin layer over code that exists rather than a
/// fourth parser to keep in step.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';

const String collectionName = 'orders';
const String nameDictName = 'orders\$names';
const String indexName = 'idx:orders:country:non_unique';
const List<String> countries = ['de', 'fr', 'uk', 'in', 'us'];

/// `14-security.md` section 3.3's `kdf = 0` credential — "32 bytes the host
/// already holds". The corpus publishes it, which is the point: these files are
/// test data, not secrets, and Argon2id at a real cost would add half a second
/// to every implementation's CI for no coverage the raw path does not give.
final Uint8List corpusKey = Uint8List.fromList(List.generate(32, (i) => i + 1));

/// A foreign database's key, for `security-foreign-slot`.
final Uint8List foreignKey = Uint8List.fromList(List.generate(32, (i) => 200 - i));

const int pageSize = 4096;

/// A value-log segment extent is **preallocated**, so `mobile`'s 4 MiB makes a
/// 180-document fixture a 4.4 MB file — and this corpus has eighteen of them,
/// every one of which is read on every CI run of three implementations forever.
/// 64 KiB holds the fixture's separated values several times over.
const int corpusVlogSegmentBytes = 64 << 10;

CDoc document(int i) {
  // 1500 bytes is above `mobile`'s `vlog_min` of 1024, so every tenth document
  // is separated into the value log and the corpus exercises both the inline
  // and the separated path. At 900 it did not, and the value-log fixtures below
  // had nothing to damage — `12-profiles.md` is explicit that mobile inlines
  // most documents, and a corpus built on that profile has to be told.
  final big = i % 10 == 0;
  final len = big ? 1500 : 40;
  return CDoc({
    '_id': CNitriteId(i),
    'seq': CInt.of(NumType.i32, i),
    'country': CStr(countries[i % 5]),
    'note': CBytes(Uint8List(len)..fillRange(0, len, i % 251)),
  });
}

/// The canonical digest over the visible state, byte-identical to
/// `tool/interop.dart`'s so all three implementations already compute it.
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

// ---------------------------------------------------------------------------
// Building a fixture
// ---------------------------------------------------------------------------

final class Fixture {
  Fixture(this.db, this.data, this.dict, this.index, this.idx, this.names);

  final Database db;
  final int data;
  final int dict;
  final int index;
  final IndexDescriptor idx;
  final NameDict names;

  Engine get e => db.engine;

  static Fixture build(String path,
      {Uint8List? key, int documents = 180, int flushEvery = 45}) {
    final f = File(path);
    if (f.existsSync()) f.deleteSync();
    final db = key == null
        ? Database(
            engine: Engine(
                memtableEntries: flushEvery,
                vlogMin: 1024,
                vlogSegmentBytes: corpusVlogSegmentBytes))
        : DatabaseFile.create(path,
            credential: key,
            kdf: Keyslot.kdfRaw,
            memtableEntries: flushEvery,
            profile: Profile.mobile,
            vlogSegmentBytes: corpusVlogSegmentBytes);
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
    final fx = Fixture(db, dataDesc.treeId, dictDesc.treeId, idxDesc.treeId,
        IndexDescriptor.fromDescriptor(idxDesc), NameDict());
    // Section 5.4: the reserved names SHOULD occupy `name_id` 1..5.
    for (final r in ['_id', '_revision', '_modified', '_source', '_type']) {
      fx.intern(r);
    }
    for (var i = 0; i < documents; i++) {
      fx.put(document(i));
      if (i % flushEvery == flushEvery - 1) db.engine.flush();
    }
    db.engine.flush();
    return fx;
  }

  int intern(String name) {
    final existing = names.idOf(name);
    if (existing != null) return existing;
    final id = names.intern(name);
    e.put(dict, CInt.of(NumType.u32, id), encodeValue(CStr(name)));
    return id;
  }

  void put(CDoc doc) {
    final id = (doc['_id']! as CNitriteId).id;
    for (final name in doc.fields.keys) {
      intern(name);
    }
    for (final k in indexKeysFor(idx, doc, CNitriteId(id))) {
      e.putEmpty(index, decodeKey(k));
    }
    e.put(data, CNitriteId(id), encodeValue(doc, dict: names));
  }

  List<(int, String, Uint8List)> rows() {
    final out = <(int, String, Uint8List)>[];
    for (final entry in e.scanTree(data)) {
      final id = (decodeKey(entry.cke) as CNitriteId).id;
      final doc = decodeValue(entry.value, dict: names) as CDoc;
      out.add((
        id,
        (doc['country']! as CStr).value,
        (doc['note']! as CBytes).value,
      ));
    }
    out.sort((a, b) => a.$1.compareTo(b.$1));
    return out;
  }

  void save(String path) =>
      DatabaseFile.save(db, path, writerId: 'cryptand-corpus/1.0.0');
}

// ---------------------------------------------------------------------------
// Byte surgery
// ---------------------------------------------------------------------------

/// The pages the **live manifest** names, which is the only set a reader is
/// guaranteed to touch.
///
/// This exists because the first version of this generator picked its target by
/// walking the image for a page whose header parsed, and got page 2 — a page a
/// previous commit had written and the current manifest no longer names. Five
/// corrupt files were emitted, none of them reproduced a failure in any reader,
/// and every one of them would have shipped as a green test that asserts
/// nothing. **A corrupt fixture that damages a page nobody reads is a control
/// that cannot fail**, which is the sixth time this project has met that shape.
///
/// [selfCheck] below is the other half: a file that claims `expect = error`
/// must actually produce one here before it is written.
final class LivePages {
  LivePages(this.segmentHead, this.segmentBody, this.vlogHead, this.dictPage);

  /// The head page of a live segment extent — the `CRY_SEG` header.
  final int segmentHead;

  /// A data page inside a live segment extent.
  final int segmentBody;

  /// The head page of a live value-log segment, or -1.
  final int vlogHead;

  /// A page inside the live segment that holds the name dictionary's strings.
  final int dictPage;

  static LivePages of(String path, Uint8List? key, Uint8List image) {
    final db = DatabaseFile.open(path, key: key);
    final refs = db.engine.manifest.all.toList()
      ..sort((a, b) => b.pages.compareTo(a.pages));
    if (refs.isEmpty) throw StateError('the fixture has no live segments');
    final ref = refs.first;
    if (ref.pages < 2) throw StateError('the live segment is one page');
    final vlog = db.engine.vlog.segments.values
        .where((s) => s.startPage != 0)
        .toList();
    // The dictionary's strings are in whichever live segment holds tree 2's
    // entries; on a fixture this size that is the same extent, so scan the live
    // extent for the needle rather than the whole file.
    var dictPage = -1;
    final needle = utf8.encode('country');
    for (var p = ref.startPage; p < ref.startPage + ref.pages; p++) {
      if (_find(Uint8List.sublistView(image, p * pageSize, (p + 1) * pageSize),
              needle) >=
          0) {
        dictPage = p;
        break;
      }
    }
    return LivePages(ref.startPage, ref.startPage + 1,
        vlog.isEmpty ? -1 : vlog.first.startPage, dictPage);
  }
}

/// Every page in [image] whose header parses, with its index and header.
List<(int, PageHeader)> headedPages(Uint8List image) {
  final out = <(int, PageHeader)>[];
  for (var p = 2; (p + 1) * pageSize <= image.length; p++) {
    try {
      out.add((
        p,
        PageHeader.read(
            Uint8List.sublistView(image, p * pageSize, (p + 1) * pageSize),
            pageId: p)
      ));
    } on CryptandException {
      continue;
    }
  }
  return out;
}

int firstPageOfType(Uint8List image, int pageType) {
  for (final (p, h) in headedPages(image)) {
    if (h.pageType == pageType) return p;
  }
  throw StateError('the fixture holds no page of type $pageType');
}

void putU32(Uint8List b, int off, int v) {
  b[off] = v & 0xFF;
  b[off + 1] = (v >>> 8) & 0xFF;
  b[off + 2] = (v >>> 16) & 0xFF;
  b[off + 3] = (v >>> 24) & 0xFF;
}

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

/// One entry of `manifest.json`.
///
/// `expect` is `read` or `error`. For `read`, a conforming implementation opens
/// the file, verifies it clean, and reproduces `documents` and `digest`. For
/// `error`, it must fail with an error of `class` — and section 6's rule that
/// matters more than the class: it "MUST NOT crash, hang, or allocate
/// unboundedly".
///
/// `at_open_or_read` records that some breakages are detected when the file is
/// opened and others only when the damaged part is read, and that **both are
/// conforming**. A corpus that demanded failure at open would be specifying an
/// eagerness the format does not require; one that accepted a clean read would
/// be specifying nothing.
final class Entry {
  Entry(this.name, this.expect,
      {this.errorClass,
      this.documents,
      this.digest,
      this.key,
      required this.note,
      this.atOpenOrRead = true,
      this.tolerated = false});

  final String name;
  final String expect;
  final String? errorClass;
  final int? documents;
  final int? digest;
  final Uint8List? key;
  final String note;
  final bool atOpenOrRead;

  /// True when a *clean* read is also conforming — see [Entry] and the two
  /// files that carry it.
  final bool tolerated;

  Map<String, Object?> toJson() => {
        'name': name,
        'page_size': pageSize,
        'expect': expect,
        if (errorClass != null) 'error_class': errorClass,
        if (documents != null) 'documents': documents,
        if (digest != null)
          'digest': digest!.toRadixString(16).padLeft(8, '0'),
        'key': key?.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        'at_open_or_read': atOpenOrRead,
        'tolerated_clean': tolerated,
        'note': note,
      };
}

void main(List<String> args) {
  final outDir = args.isEmpty
      ? Directory('${Directory.current.path}/../../conformance/files')
      : Directory(args[0]);
  outDir.createSync(recursive: true);
  final tmp = Directory.systemTemp.createTempSync('cryptand-corpus-');
  final entries = <Entry>[];

  /// Writes a corpus file, and — for one that claims to be broken — **checks
  /// that it is**.
  ///
  /// The check is not optional decoration. The first version of this generator
  /// emitted five corrupt files that damaged pages the live manifest no longer
  /// names; every one opened, read and verified perfectly, and would have
  /// shipped in three test suites as a case that asserts nothing. A corpus of
  /// negative tests has to be able to fail, and the cheapest place to find out
  /// is here rather than in three CI runs that all go green.
  ///
  /// It costs one honest limitation, stated rather than hidden: a file only
  /// enters the corpus if *this* reader detects it, so the corpus cannot
  /// contain a case only some other implementation would catch. What it can and
  /// does contain is a case some other implementation **misses**, which is the
  /// direction that matters.
  void emit(String name, Uint8List bytes,
      {required bool broken, Uint8List? key, bool tolerated = false}) {
    final path = '${outDir.path}/$name';
    File(path).writeAsBytesSync(bytes, flush: true);
    var detected = 'n/a';
    if (broken) {
      try {
        final probe = readAll(path, key);
        detected = probe == 0
            ? 'NOTHING'
            : '$probe finding(s)';
        if (probe == 0 && !tolerated) {
          throw StateError(
              '$name claims to be broken and this reader read it cleanly. '
              'Either the damage landed on a page nothing reads, or the '
              'mechanism that should catch it does not exist.');
        }
      } on CryptandException catch (e) {
        detected = '${e.runtimeType}';
      }
    }
    stdout.writeln(
        '  ${name.padRight(36)} ${bytes.length.toString().padLeft(8)} B  $detected');
  }

  // -------------------------------------------------------------------------
  // The plaintext golden file, and everything derived from its bytes.
  // -------------------------------------------------------------------------
  stdout.writeln('golden files:');
  final corePath = '${tmp.path}/core.cryptand';
  final core = Fixture.build(corePath);
  final coreRows = core.rows();
  final coreDigest = digest(coreRows);
  core.save(corePath);
  final coreImage = File(corePath).readAsBytesSync();
  emit('v1.0-core.cryptand', coreImage, broken: false);
  entries.add(Entry('v1.0-core.cryptand', 'read',
      documents: coreRows.length,
      digest: coreDigest,
      note: 'the golden file: 180 documents, an index, a name dictionary, '
          'several segments and a value log. Every other plaintext file in '
          'this corpus is these bytes with one thing done to them.'));

  stdout.writeln('corrupt files:');
  final live = LivePages.of(corePath, null, coreImage);
  final leaf = live.segmentBody;

  // 1. Bad CRC — the container gate, and the only failure a reader may repair
  //    from a redundant copy.
  {
    final b = Uint8List.fromList(coreImage);
    b[leaf * pageSize + PageHeader.size + 3] ^= 0x40; // and no repair
    emit('v1.0-corrupt-crc.cryptand', b, broken: true);
    entries.add(Entry('v1.0-corrupt-crc.cryptand', 'error',
        errorClass: 'corruption',
        key: null,
        note: 'one payload byte flipped on live page $leaf with the checksum left '
            'stale. Section 3: the checksum "verifies before decompression and '
            'before decryption", so this must be refused before any decoder '
            'runs.'));
  }

  // 2. Truncated segment — the file ends mid-extent.
  {
    final cut = (live.segmentHead + 1) * pageSize;
    emit('v1.0-corrupt-truncated.cryptand',
        Uint8List.sublistView(coreImage, 0, cut),
        broken: true);
    entries.add(Entry('v1.0-corrupt-truncated.cryptand', 'error',
        errorClass: 'corruption',
        note: 'the file ends one page into the first segment extent, so the '
            'superblock names a page_count the file does not have. A reader '
            'that sizes a buffer from page_count before checking the file '
            'length allocates from a number an attacker chose.'));
  }

  // 3. Torn value-log tail — the last record is half there.
  {
    final b = Uint8List.fromList(coreImage);
    final vlog = live.vlogHead;
    // The record space begins at `data_offset` inside the head page. Damaging
    // a record's own crc32c is what section 6.2 makes the mechanism here: the
    // page checksum deliberately does not cover these bytes.
    final at = vlog * pageSize + 104 + 8;
    for (var i = 0; i < 24 && at + i < b.length; i++) {
      b[at + i] ^= 0x5A;
    }
    emit('v1.0-corrupt-torn-vlog.cryptand', b, broken: true, tolerated: true);
    entries.add(Entry('v1.0-corrupt-torn-vlog.cryptand', 'error',
        errorClass: 'corruption',
        atOpenOrRead: false,
        tolerated: true,
        note: 'a value-log record damaged in place. Section 3 excludes these '
            'bytes from the page checksum on purpose — records are appended '
            'into the head page for the life of the segment — so the only '
            'mechanism that catches this is the per-record crc32c, and it runs '
            'when the value is read, not when the file is opened. A reader that '
            'reports nothing here has not read the record; one that reports '
            'nothing after reading every document has no per-record check.'));
  }

  // 4. Dangling value-log pointer — past the durable watermark.
  {
    final b = Uint8List.fromList(coreImage);
    final vlog = live.vlogHead;
    // `bytes` is the watermark; section 6.2 puts the durable copy in tree 7 and
    // a pointer past it is corruption. Move the head's own `data_offset` past
    // the page instead, which is the same class of lie and reachable from the
    // bytes alone.
    putU32(b, vlog * pageSize + PageHeader.size + 32, 0x7FFF0000);
    repairChecksum(b, vlog, pageSize);
    emit('v1.0-corrupt-dangling-vlog.cryptand', b, broken: true, tolerated: true);
    entries.add(Entry('v1.0-corrupt-dangling-vlog.cryptand', 'error',
        errorClass: 'corruption',
        atOpenOrRead: false,
        tolerated: true,
        note: "the value-log head's data_offset moved past the end of its "
            'extent, so every pointer into the segment resolves outside it. '
            'The checksum is repaired, which is section 9.4 in one line: a CRC '
            '"is trivially recomputed by anyone who edits the file".'));
  }

  // 5. A declared length far past the page — the allocation bomb.
  {
    final b = Uint8List.fromList(coreImage);
    putU32(b, leaf * pageSize + 24, 0xFFFFFFFC); // payload_len
    repairChecksum(b, leaf, pageSize);
    emit('v1.0-corrupt-huge-len.cryptand', b, broken: true);
    entries.add(Entry('v1.0-corrupt-huge-len.cryptand', 'error',
        errorClass: 'corruption',
        note: 'payload_len set to 0xFFFFFFFC with the checksum repaired, so it '
            'reaches the decoder. Section 9.1: a decoder "MUST bounds-check '
            'against the containing page or extent before allocating, and MUST '
            'fail with a typed corruption error rather than an allocation '
            'failure". Read as a signed 32-bit int this is -4, which is the '
            'second way to fail it.'));
  }

  // 6. A tree pointer that leaves the file — the cyclic/wild-pointer case.
  {
    final b = Uint8List.fromList(coreImage);
    final segHead = live.segmentHead;
    // `root_page` lives in the CRY_SEG header, after the 8-byte magic and
    // segment_id/level/flags/filter_bits/tree_count.
    final rootAt = segHead * pageSize + PageHeader.size + 8 + 8 + 1 + 1 + 2 + 4;
    for (var i = 0; i < 8; i++) {
      b[rootAt + i] = 0xFF;
    }
    repairChecksum(b, segHead, pageSize);
    emit('v1.0-corrupt-wild-root.cryptand', b, broken: true);
    entries.add(Entry('v1.0-corrupt-wild-root.cryptand', 'error',
        errorClass: 'corruption',
        note: "a segment header's root_page set to 0xFFFFFFFFFFFFFFFF. It is a "
            'u64, so a reader that holds it in a signed 64-bit int sees a '
            'negative page index and a bound written as "< page_count" alone '
            'lets it through — which is exactly how it reached a slice in one '
            'implementation.'));
  }

  // 7. Ill-formed UTF-8 inside a decoded string.
  {
    final b = Uint8List.fromList(coreImage);
    // The name dictionary's strings are the shortest reliable target: every
    // reader decodes them at open to rebuild the dictionary.
    if (live.dictPage < 0) {
      throw StateError('no live page holds the name `country`');
    }
    final base = live.dictPage * pageSize;
    final at = base +
        _find(Uint8List.sublistView(b, base, base + pageSize),
            utf8.encode('country'));
    b[at + 3] = 0xC3; // a lead byte with no continuation after it
    b[at + 4] = 0x28;
    repairChecksum(b, live.dictPage, pageSize);
    emit('v1.0-corrupt-bad-utf8.cryptand', b, broken: true);
    entries.add(Entry('v1.0-corrupt-bad-utf8.cryptand', 'error',
        errorClass: 'corruption',
        atOpenOrRead: false,
        note: 'ill-formed UTF-8 in a field name. Section 4: "A reader '
            'encountering ill-formed UTF-8 MUST report corruption; it MUST NOT '
            'substitute replacement characters silently." The silent '
            'substitution is the failure worth testing for: it turns a broken '
            'file into a readable one with the wrong field names in it.'));
  }

  // 8. A superblock that lies about the size of the file.
  {
    final b = Uint8List.fromList(coreImage);
    // page_count, in both slots, so neither is preferred.
    for (final slot in [0, pageSize]) {
      for (var i = 0; i < 8; i++) {
        b[slot + Sb.pageCount + i] = i < 4 ? 0xFF : 0x00;
      }
    }
    emit('v1.0-corrupt-page-count.cryptand', b, broken: true);
    entries.add(Entry('v1.0-corrupt-page-count.cryptand', 'error',
        errorClass: 'corruption',
        note: 'page_count set to 4 294 967 295 in both superblock slots. A '
            'reader that trusts it sizes a page table from a number in the '
            'file; at 4 KiB pages that is 16 TiB of addressable space claimed '
            'by a 1 MiB file.'));
  }

  // -------------------------------------------------------------------------
  // Forward compatibility — sections 3 and 4.
  // -------------------------------------------------------------------------
  {
    final b = Uint8List.fromList(coreImage);
    // An unknown *optional* feature bit. Section 3: a reader MUST open the
    // file and MUST NOT refuse it; an unknown bit in `features_required` is
    // the opposite case and has its own file below.
    b[Sb.featuresOptional + 7] |= 0x40;
    b[pageSize + Sb.featuresOptional + 7] |= 0x40;
    for (final slot in [0, pageSize]) {
      final sb = Uint8List.sublistView(b, slot, slot + Sb.size);
      putU32(b, slot + Sb.checksum, crc32c(sb, 0, Sb.checksum));
    }
    emit('v1.0-future.cryptand', b, broken: false);
    entries.add(Entry('v1.0-future.cryptand', 'read',
        documents: coreRows.length,
        digest: coreDigest,
        note: 'an unknown OPTIONAL feature bit set in features_optional. '
            'Section 3: a reader MUST open this file and read it exactly as it '
            'reads v1.0-core. This is the one file in the corpus whose failure '
            'mode is being too strict rather than too lax, and it is the '
            'expensive kind: a reader that refuses it makes every future minor '
            'version unreadable by every shipped copy of itself.'));
  }
  {
    final b = Uint8List.fromList(coreImage);
    b[Sb.featuresRequired + 7] |= 0x40;
    b[pageSize + Sb.featuresRequired + 7] |= 0x40;
    for (final slot in [0, pageSize]) {
      final sb = Uint8List.sublistView(b, slot, slot + Sb.size);
      putU32(b, slot + Sb.checksum, crc32c(sb, 0, Sb.checksum));
    }
    emit('v1.0-future-required.cryptand', b, broken: true);
    entries.add(Entry('v1.0-future-required.cryptand', 'error',
        errorClass: 'unsupported',
        note: 'an unknown REQUIRED feature bit. Section 3: a reader MUST refuse '
            'this, and the error must say the feature is unsupported rather '
            'than that the file is corrupt — the file is not corrupt, it is '
            'newer. The pair with v1.0-future.cryptand is the whole of section '
            "3: the same bit in the other word means the opposite thing."));
  }

  // -------------------------------------------------------------------------
  // The encrypted golden file, and the tamper set of 14 section 13.
  // -------------------------------------------------------------------------
  stdout.writeln('encrypted files:');
  final encPath = '${tmp.path}/enc.cryptand';
  final enc = Fixture.build(encPath, key: corpusKey);
  final encRows = enc.rows();
  final encDigest = digest(encRows);
  enc.save(encPath);
  final encImage = File(encPath).readAsBytesSync();
  emit('v1.0-encrypted.cryptand', encImage, broken: false, key: corpusKey);
  entries.add(Entry('v1.0-encrypted.cryptand', 'read',
      documents: encRows.length,
      digest: encDigest,
      key: corpusKey,
      note: 'the encrypted golden file, under a published kdf = 0 credential. '
          'An SDK that does not implement the CIPHER feature refuses it by '
          'name, which section 13 says is equally conforming.'));

  final encLive = LivePages.of(encPath, corpusKey, encImage);
  final encData = encLive.segmentBody;

  {
    final b = Uint8List.fromList(encImage);
    b[encData * pageSize + PageHeader.size + 5] ^= 0x01;
    repairChecksum(b, encData, pageSize);
    emit('v1.0-security-tamper-page.cryptand', b, broken: true, key: corpusKey);
    entries.add(Entry('v1.0-security-tamper-page.cryptand', 'error',
        errorClass: 'tampering',
        key: corpusKey,
        atOpenOrRead: false,
        note: 'one ciphertext byte flipped, checksum repaired. This MUST be '
            'reported as tampering and NOT as corruption: section 9.4 — "CRC-32C '
            'detects accidental corruption ... Integrity comes from the AEAD '
            'tag". A reader that calls this corruption invites a repair pass '
            'over bytes an attacker chose.'));
  }
  {
    final b = Uint8List.fromList(encImage);
    putU32(b, encData * pageSize + 8, 0x0000BEEF); // tree_id, inside the AAD
    repairChecksum(b, encData, pageSize);
    emit('v1.0-security-tamper-header.cryptand', b, broken: true, key: corpusKey);
    entries.add(Entry('v1.0-security-tamper-header.cryptand', 'error',
        errorClass: 'tampering',
        key: corpusKey,
        atOpenOrRead: false,
        note: "the page header's tree_id edited. The ciphertext is untouched: "
            'section 5.2 makes the 40-byte header the AEAD\'s AAD, so this '
            'fails the tag. A reader that does not bind the header cannot tell '
            "this page from the one it is impersonating, and that is what "
            'relabelling a page between trees would buy an attacker.'));
  }
  {
    final b = Uint8List.fromList(encImage);
    for (final slot in [0, pageSize]) {
      b[slot + Sb.cipher] = 0;
      final sb = Uint8List.sublistView(b, slot, slot + Sb.size);
      putU32(b, slot + Sb.checksum, crc32c(sb, 0, Sb.checksum));
    }
    emit('v1.0-security-tamper-sb.cryptand', b, broken: true, key: corpusKey);
    entries.add(Entry('v1.0-security-tamper-sb.cryptand', 'error',
        errorClass: 'tampering',
        key: corpusKey,
        note: 'cipher forced to 0 on a file that still carries keyslots — the '
            'downgrade of section 6.1. sb_mac is what catches it, and it is '
            'the reason sb_mac exists: without it anyone can turn the cipher '
            'off in one byte and the reader has no way to know the file was '
            'ever encrypted.'));
  }
  {
    final b = Uint8List.fromList(encImage);
    // t_cost is the first u32 of a keyslot's KDF parameter block.
    for (final slot in [0, pageSize]) {
      putU32(b, slot + Sb.keyslots + 16, 1);
      final sb = Uint8List.sublistView(b, slot, slot + Sb.size);
      putU32(b, slot + Sb.checksum, crc32c(sb, 0, Sb.checksum));
    }
    emit('v1.0-security-downgrade-kdf.cryptand', b, broken: true, key: corpusKey);
    entries.add(Entry('v1.0-security-downgrade-kdf.cryptand', 'error',
        errorClass: 'tampering',
        key: corpusKey,
        note: "a keyslot's Argon2id t_cost lowered to 1. On its own this is "
            'free to do and cannot be caught by trying the key — the slot '
            'still opens, at a cost an attacker can brute-force. sb_mac covers '
            'the keyslot area for exactly this reason.'));
  }
  {
    final b = Uint8List.fromList(encImage);
    // A page copied to another page's offset: the ciphertext is authentic, the
    // nonce and the page id are not the ones it was sealed under.
    final other = encLive.segmentBody + 1;
    b.setRange(other * pageSize, (other + 1) * pageSize, encImage,
        encData * pageSize);
    emit('v1.0-security-splice.cryptand', b, broken: true, key: corpusKey);
    entries.add(Entry('v1.0-security-splice.cryptand', 'error',
        errorClass: 'tampering',
        key: corpusKey,
        atOpenOrRead: false,
        note: 'page $encData copied over page $other. Every byte is authentic '
            'and every checksum is valid — the file was never edited, only '
            'rearranged. Section 4.2 binds the nonce to the page, which is the '
            'only thing that separates this from a legitimate page.'));
  }
  {
    // A keyslot lifted from a different database. Section 3.4 makes the wrap
    // AAD the database uuid plus the slot index, so it cannot unwrap here — and
    // threat T3 is precisely someone who has a slot from another file.
    final otherPath = '${tmp.path}/other.cryptand';
    final other = Fixture.build(otherPath, key: foreignKey, documents: 30);
    other.save(otherPath);
    final otherImage = File(otherPath).readAsBytesSync();
    final b = Uint8List.fromList(encImage);
    for (final slot in [0, pageSize]) {
      b.setRange(slot + Sb.keyslots, slot + Sb.keyslots + Sb.keyslotSize,
          otherImage, Sb.keyslots);
      final sb = Uint8List.sublistView(b, slot, slot + Sb.size);
      putU32(b, slot + Sb.checksum, crc32c(sb, 0, Sb.checksum));
    }
    emit('v1.0-security-foreign-slot.cryptand', b, broken: true, key: foreignKey);
    entries.add(Entry('v1.0-security-foreign-slot.cryptand', 'error',
        errorClass: 'tampering',
        key: foreignKey,
        note: "another database's keyslot pasted into this one, and the key "
            'that opens *that* database supplied. Both the wrap AAD (section '
            '3.4) and sb_mac refuse it. Supplying the foreign key rather than '
            'this file\'s is deliberate: with the right key the slot is simply '
            'unused and nothing is proven.'));
  }

  // -------------------------------------------------------------------------
  // manifest.json
  // -------------------------------------------------------------------------
  final manifest = {
    'format': 'cryptand-conformance/1',
    'spec': ['spec/11-conformance.md#6', 'spec/14-security.md#13'],
    'generated_by': 'reference/dart/cryptand/tool/generate_corpus.dart',
    'rules': [
      'A file with expect=read MUST open, verify with no CORRUPTION and no '
          'TAMPERING finding, and reproduce both documents and digest. A LEAK '
          'is not damage: 01-container.md section 9 says "a leak is '
          'repairable", and a copy-on-write container leaks tree 1 own pages '
          'by one commit as a property of the format, so a runner that counts '
          'leaks fails every file this format can produce.',
      'A file with expect=error MUST fail with an error of error_class, and '
          'MUST NOT crash, hang, or allocate unboundedly (11 section 6, '
          '14 section 9.1).',
      'at_open_or_read=false means the failure is permitted to surface only '
          'when the damaged part is read, not at open. Both are conforming; a '
          'runner MUST read every document before concluding a file was '
          'accepted.',
      'tolerated_clean=true means a reader that reports nothing has not '
          'necessarily failed the corpus, but has demonstrably not exercised '
          "the mechanism the file is about; a runner SHOULD say so.",
      'An implementation that does not support a feature a file needs (CIPHER, '
          'a codec) MUST refuse it by name rather than misread it, and that is '
          'conforming.',
    ],
    'files': [for (final e in entries) e.toJson()],
  };
  File('${outDir.path}/manifest.json').writeAsStringSync(
      '${const JsonEncoder.withIndent('  ').convert(manifest)}\n');
  stdout.writeln('\nmanifest.json: ${entries.length} files');
  tmp.deleteSync(recursive: true);
}

/// Opens, verifies and reads everything, returning the number of findings.
///
/// This is the same three steps every implementation's corpus runner takes, and
/// it is deliberately the same code the self-check above uses: a generator that
/// validated its files with a weaker read than the runners use would emit files
/// the runners then fail on.
int readAll(String path, Uint8List? key) {
  final db = DatabaseFile.open(path, key: key);
  final v = db.engine.verifyStructure();
  var findings = v.of(FindingClass.corruption).length +
      v.of(FindingClass.tampering).length;
  final data = db.catalog.get(collectionName)?.treeId;
  final dictTree = db.catalog.get(nameDictName)?.treeId;
  if (data == null || dictTree == null) {
    throw const CorruptionException('the file does not hold `orders`');
  }
  final names = NameDict();
  final byId = <int, String>{};
  for (final e in db.engine.scanTree(dictTree)) {
    byId[expectValue<CInt>(decodeKey(e.cke), 'name_id').magnitude.lo] =
        expectValue<CStr>(decodeValue(e.value), 'name').value;
  }
  for (final id in byId.keys.toList()..sort()) {
    names.intern(byId[id]!);
  }
  for (final e in db.engine.scanTree(data)) {
    final doc =
        expectValue<CDoc>(decodeValue(e.value, dict: names), 'document');
    expectField<CStr>(doc, 'country', 'document');
    expectField<CBytes>(doc, 'note', 'document');
  }
  return findings;
}

int _find(Uint8List haystack, List<int> needle) {
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
