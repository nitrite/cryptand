/// The file layer: `spec/01-container.md` §1's layout, written and read back.
///
/// Until a database is a file, `spec/11-conformance.md` §6's round-trip gate —
/// "open it in implementation A, mutate it, close it, open it in B" — is not a
/// test that can be run at all.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

const int t = 16;

String tmp(String tag) {
  final d = Directory.systemTemp.createTempSync('cryptand-file-$tag-');
  return '${d.path}/db.cryptand';
}

Database fresh({int memtableEntries = 200}) => Database(
    engine: Engine(memtableEntries: memtableEntries, vlogMin: 256));

void main() {
  test('a database round-trips through a file', () {
    final path = tmp('roundtrip');
    final db = fresh();
    for (var i = 0; i < 500; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList('v$i'.codeUnits));
      if (i % 200 == 199) db.engine.flush();
    }
    db.engine.flush();
    DatabaseFile.save(db, path);

    final back = DatabaseFile.open(path);
    for (var i = 0; i < 500; i++) {
      expect(back.engine.get(t, CNitriteId(i)), isNotNull, reason: 'id $i');
      expect(String.fromCharCodes(back.engine.get(t, CNitriteId(i))!), 'v$i');
    }
    expect(back.engine.scanTree(t).length, 500);
  });

  test('a separated value survives the file, and its watermark with it', () {
    final path = tmp('vlog');
    final db = fresh();
    final big = Uint8List(4000)..fillRange(0, 4000, 7);
    for (var i = 0; i < 20; i++) {
      db.engine.put(t, CNitriteId(i), big);
    }
    db.engine.flush();
    DatabaseFile.save(db, path);

    final back = DatabaseFile.open(path);
    // §6.2: a pointer past the durable `bytes` watermark is corruption, so a
    // watermark that did not survive the file would fail every read.
    expect(back.engine.vlog.segments, isNotEmpty);
    for (final s in back.engine.vlog.segments.values) {
      expect(s.bytes, greaterThan(0));
      expect(s.sealed, isTrue,
          reason: 'spec/14-security.md section 4.3: a segment this session did '
              'not open is sealed');
    }
    for (var i = 0; i < 20; i++) {
      expect(back.engine.get(t, CNitriteId(i)), big);
    }
  });

  test('the value-log head page is a page: header, type and checksum', () {
    final path = tmp('vloghead');
    final db = fresh();
    db.engine
        .put(t, CNitriteId(1), Uint8List(4000)..fillRange(0, 4000, 3));
    db.engine.flush();
    DatabaseFile.save(db, path);

    final bytes = File(path).readAsBytesSync();
    final sb = Superblock.open(Uint8List.sublistView(bytes, 0, Sb.size),
        Uint8List.sublistView(bytes, 4096, 4096 + Sb.size));
    var found = 0;
    for (var p = 2; p < sb.pageCount; p++) {
      final page = Uint8List.sublistView(
          bytes, p * sb.pageSize, (p + 1) * sb.pageSize);
      if (page[4] != PageType.vlogSegment) continue;
      // Reading it verifies the checksum, which is the point: without a page
      // header a repair pass scanning for VLOG_SEGMENT pages
      // (spec/13-operations.md section 3) cannot find the segment at all.
      final h = PageHeader.read(page);
      expect(h.flags & PageFlags.extentHead, PageFlags.extentHead);
      expect(h.extentPages, greaterThan(0));
      expect(h.treeId, TreeId.noTree);
      found++;
    }
    expect(found, greaterThan(0), reason: 'no value-log head page was written');
  });

  test('the catalog and its collections survive the file', () {
    final path = tmp('catalog');
    final db = fresh();
    final c = db.createCollection('orders|2026+eu');
    c.put(
        CNitriteId(1),
        CDoc({
          '_id': CNitriteId(1),
          'country': const CStr('de'),
          'total': CInt.of(NumType.i32, 42),
        }));
    db.engine.flush();
    DatabaseFile.save(db, path);

    final back = DatabaseFile.open(path);
    expect(back.catalog.get('orders|2026+eu'), isNotNull);
    final names = [
      for (final (name, d) in back.catalog.all)
        if (d.kind == TreeKind.data && d.paramStr('type') == 'collection') name
    ];
    expect(names, contains('orders|2026+eu'));
    final doc = back.collection('orders|2026+eu')!.get(CNitriteId(1));
    expect(doc, isNotNull);
    expect((doc!['country']! as CStr).value, 'de');
  });

  test('page 0 and page 1 are the two superblock slots', () {
    final path = tmp('slots');
    final db = fresh();
    db.engine.put(t, CNitriteId(1), Uint8List.fromList([1]));
    db.engine.flush();
    DatabaseFile.save(db, path);
    final bytes = File(path).readAsBytesSync();
    for (final at in [0, 4096]) {
      final sb =
          Superblock.tryDecode(Uint8List.sublistView(bytes, at, at + Sb.size));
      expect(sb, isNotNull, reason: 'slot at $at');
      expect(sb!.pageCount * sb.pageSize, bytes.length);
    }
  });

  test('reading a file twice is byte-identical', () {
    final path = tmp('stable');
    final db = fresh();
    for (var i = 0; i < 100; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList([i]));
    }
    db.engine.flush();
    DatabaseFile.save(db, path);
    final a = File(path).readAsBytesSync();

    final reopened = DatabaseFile.open(path);
    final second = '$path.2';
    DatabaseFile.save(reopened, second);
    final b = File(second).readAsBytesSync();
    // The page space is rebuilt from the file, so a save of an unmutated reopen
    // reproduces it. Only the modified timestamp differs, which lives in the
    // superblock.
    expect(b.length, a.length);
    expect(
        Uint8List.sublistView(b, 2 * 4096),
        Uint8List.sublistView(a, 2 * 4096),
        reason: 'the page space past the superblocks must be identical');
  });
}
