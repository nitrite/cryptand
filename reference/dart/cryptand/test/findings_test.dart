/// Dart halves of FINDINGS rows first found in Rust or Java: each test is the
/// Rust/Java repro, ported. A pass here is the row's `D = ok`.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:cryptand/src/cow.dart' show FileHook, fileHook;
import 'package:test/test.dart';

const int t = 17;
Uint8List b(List<int> v) => Uint8List.fromList(v);
Uint8List big(int fill, [int n = 6000]) => Uint8List(n)..fillRange(0, n, fill);

void main() {
  test('F-007: the point index is charged to the page cache', () {
    final e = Engine();
    for (var i = 0; i < 1000; i++) {
      e.put(t, CNitriteId(i), b([1]));
    }
    e.flush();
    final s = e.extents.values.single;
    final before = s.residentBytes;
    for (var pass = 0; pass < 2; pass++) {
      for (var i = 0; i < 1000; i++) {
        e.get(t, CNitriteId(i));
      }
    }
    expect(s.pointIndexed, isTrue);
    expect(s.residentBytes - before, greaterThanOrEqualTo(1000 * 16));
  });

  test('F-171: an unbounded scan opens only its own tree\'s segments', () {
    final e = Engine(segmentTargetBytes: 4096);
    for (var i = 0; i < 5; i++) {
      e.put(16, CNitriteId(i), b([1]));
    }
    e.flush();
    for (var s = 0; s < 10; s++) {
      for (var i = 0; i < 200; i++) {
        e.put(17, CNitriteId(s * 1000 + i), big(s, 100));
      }
      e.flush();
    }
    final before = e.cacheHits + e.cacheMisses;
    expect(e.scanTree(16).length, 5);
    expect(e.cacheHits + e.cacheMisses - before, lessThan(3));
  });

  test('F-169: a bounded scan opens only segments that overlap its range', () {
    final e = Engine(segmentTargetBytes: 4096);
    for (var s = 0; s < 20; s++) {
      for (var i = 0; i < 200; i++) {
        e.put(t, CNitriteId(s * 1000 + i), big(s, 100));
      }
      e.flush();
    }
    final live = e.liveSegments.length;
    final before = e.cacheHits + e.cacheMisses;
    final rows = e
        .scanTree(t,
            range: KeyRange(encodeKey(const CNitriteId(5000)),
                encodeKey(const CNitriteId(5010))))
        .length;
    expect(rows, 10);
    expect(live, greaterThan(3));
    expect(e.cacheHits + e.cacheMisses - before, lessThan(3));
  });

  test('F-018: compaction does not resurrect rows hidden by a range delete', () {
    final e = Engine();
    for (var i = 0; i < 100; i++) {
      e.put(t, CNitriteId(i), b([1]));
    }
    e.flush();
    e.removeRange(t, const CNitriteId(20), const CNitriteId(40));
    e.flush();
    e.compact();
    expect(e.get(t, const CNitriteId(25)), isNull);
    expect(e.scanTree(t).length, 80);
    e.put(t, const CNitriteId(1000), b([2]));
    e.flush();
    e.compact();
    expect(e.scanTree(t).length, 81);
  });

  test('F-018: a range delete reaching past its inputs still hides its rows', () {
    final e = Engine();
    for (var i = 500; i < 600; i++) {
      e.put(t, CNitriteId(i), b([1]));
    }
    e.flush();
    e.compact();
    e.put(t, const CNitriteId(1), b([2]));
    e.removeRange(t, const CNitriteId(2), const CNitriteId(10000));
    e.flush();
    final l0 = e.refsAt(0);
    expect(l0.length, 1);
    final job = e.beginCompaction(l0, e.lastLevel)!;
    while (!e.stepCompaction(job)) {}
    e.finishCompaction(job);
    expect(e.get(t, const CNitriteId(550)), isNull);
    expect(e.scanTree(t).length, 1);
  });

  test('F-019: value-log collection does not resurrect a range-deleted row', () {
    final e = Engine();
    e.put(t + 1, const CNitriteId(1), big(7));
    e.compact();
    e.put(t, const CNitriteId(5), big(7));
    final s = e.snapshot();
    e.removeRange(t, const CNitriteId(0), const CNitriteId(10));
    e.compact();
    e.collectWhileOverDebt();
    expect(e.get(t, const CNitriteId(5)), isNull);
    expect(e.get(t, const CNitriteId(5), at: s), isNull);
    expect(e.scanTree(t), isEmpty);
  });

  test('F-020: value-log collection keeps a value\'s expiry', () {
    final e = Engine();
    e.put(t + 1, const CNitriteId(1), big(7));
    e.compact();
    e.put(t, const CNitriteId(5), big(7), expiryMs: 1000);
    e.snapshot();
    e.put(t + 1, const CNitriteId(2), big(7));
    e.compact();
    e.collectWhileOverDebt();
    e.nowMs = 2000;
    expect(e.get(t, const CNitriteId(5)), isNull);
  });

  test('F-021: compaction does not resurrect a deleted version under a snapshot',
      () {
    final e = Engine();
    e.put(t, const CNitriteId(1), b([1]));
    e.remove(t, const CNitriteId(1));
    e.flush();
    final s = e.snapshot();
    e.put(t, const CNitriteId(1), b([2]));
    e.flush();
    e.compact();
    expect(e.get(t, const CNitriteId(1), at: s), isNull);
    expect(e.scanTree(t, at: s), isEmpty);
    expect(e.get(t, const CNitriteId(1)), [2]);
  });

  test('F-176: an encrypted page read verifies its checksum once', () {
    final dir = Directory.systemTemp.createTempSync('f176');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/e.cryptand';
    final key = List.filled(32, 7);
    DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw)
      ..createCollection('c')
      ..engine.close();
    var db = DatabaseFile.open(path, key: key);
    for (var i = 0; i < 2000; i++) {
      db.collection('c')!.put(CInt.of(NumType.i64, i), CDoc({'a': CStr('v' * 40)}));
    }
    db.engine.commit();
    db.engine.flush();
    db.engine.close();
    db = DatabaseFile.open(path, key: key);
    final c = db.collection('c')!;
    final pages0 = db.engine.store.encryptedPages;
    final v0 = PageHeader.verifications;
    for (var i = 0; i < 2000; i += 7) {
      expect(c.get(CInt.of(NumType.i64, i)), isNotNull);
    }
    final pages = db.engine.store.encryptedPages - pages0;
    final perPage = (PageHeader.verifications - v0) / pages;
    print('F-176: $pages pages, ${perPage.toStringAsFixed(2)} verifications each');
    expect(pages, greaterThan(0));
    expect(perPage, lessThan(1.5));
    db.engine.close();
  });

  test('F-175: an encrypted put does not re-read the catalog, and a new index is seen', () {
    final dir = Directory.systemTemp.createTempSync('f175');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/e.cryptand';
    final key = List.filled(32, 7);
    DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw)
      ..createCollection('c')
      ..engine.close();
    final db = DatabaseFile.open(path, key: key);
    final c = db.collection('c')!;
    c.put(CInt.of(NumType.i64, 0), CDoc({'a': CInt.of(NumType.i64, 0)}));
    final before = db.engine.store.encryptedPages;
    for (var i = 1; i <= 200; i++) {
      c.put(CInt.of(NumType.i64, i), CDoc({'a': CInt.of(NumType.i64, i)}));
    }
    // Was two catalog walks per put: >= 400 page opens.
    expect(db.engine.store.encryptedPages - before, lessThan(20));
    expect(c.indexes, isEmpty);
    c.createIndex(['a']);
    expect(c.indexes, hasLength(1));
    db.engine.close();
  });

  test('F-084: collected values survive commits without flush and a reopen', () {
    final path =
        '${Directory.systemTemp.createTempSync('cryptand-f084-').path}/db.cryptand';
    DatabaseFile.save(Database(engine: Engine()), path);
    var e = DatabaseFile.open(path).engine;
    Uint8List v(int k) => big((k ~/ 40 + k) & 0xff, 5000);
    for (var g = 0; g < 3; g++) {
      for (var i = 0; i < 40; i++) {
        e.put(t, CNitriteId(g * 40 + i), v(g * 40 + i));
      }
      e.flush();
      e.compact();
    }
    // Overwrite half so collection has dead records to drop.
    final before = e.coldCollections;
    for (var k = 0; k < 120; k += 2) {
      e.put(t, CNitriteId(k), v(k));
    }
    e.flush();
    e.compact();
    expect(e.coldCollections, greaterThan(before), reason: 'nothing collected');
    for (var i = 0; i < 4; i++) {
      e.commit();
    }
    e.close(flushMemtable: false);
    e = DatabaseFile.open(path).engine;
    for (var k = 0; k < 120; k++) {
      expect(e.get(t, CNitriteId(k)), v(k), reason: 'key $k');
    }
    expect(e.verifyStructure().findings, isEmpty);
    e.close();
  });

  group('conversion', () {
    final key = List<int>.filled(32, 9);
    Uint8List val(int i) => big(i & 0xff, 3000);
    Database fresh(String name) {
      final path =
          '${Directory.systemTemp.createTempSync('cryptand-$name-').path}/db.cryptand';
      DatabaseFile.save(Database(engine: Engine()), path);
      return DatabaseFile.open(path);
    }

    void convert(Database db) {
      for (var i = 0; db.convertStep(); i++) {
        if (i == 10) fail('convertStep never finishes');
      }
    }

    void check(Database db, int n, String phase) {
      for (var i = 0; i < n; i++) {
        expect(db.engine.get(t, CNitriteId(i)), val(i), reason: '$phase: key $i');
      }
      expect(db.engine.verifyStructure().findings, isEmpty, reason: phase);
    }

    test('F-081: memtable-held values survive encrypt, rotate, decrypt', () {
      var db = fresh('f081');
      for (var i = 0; i < 100; i++) {
        db.engine.put(t, CNitriteId(i), val(i));
      }
      db.engine.commit();
      db.encrypt(key, kdf: Keyslot.kdfRaw);
      convert(db);
      for (var i = 100; i < 200; i++) {
        db.engine.put(t, CNitriteId(i), val(i));
      }
      db.engine.flush();
      check(db, 200, 'encrypted');
      db = DatabaseFile.rotateMasterKey(db, List<int>.filled(32, 5),
          kdf: Keyslot.kdfRaw);
      check(db, 200, 'rotated');
      db.decrypt(confirmRemoveEncryption: true);
      convert(db);
      check(db, 200, 'decrypted');
      db.engine.close();
    });

    test('F-087: converts under a live snapshot', () {
      final db = fresh('f087');
      final e = db.engine;
      for (var i = 0; i < 300; i++) {
        e.put(t, CNitriteId(i), val(i));
      }
      e.flush();
      final snap = e.snapshot();
      for (var i = 0; i < 300; i += 2) {
        e.put(t, CNitriteId(i), val(i + 300));
      }
      e.commit();
      void snapOk(String phase) {
        for (var i = 0; i < 300; i++) {
          expect(e.get(t, CNitriteId(i), at: snap), val(i), reason: '$phase: $i');
        }
      }

      snapOk('plain');
      for (var round = 0; round < 3; round++) {
        db.encrypt(key, kdf: Keyslot.kdfRaw);
        convert(db);
        expect(db.fullyEncrypted, isTrue);
        snapOk('encrypted $round');
        db.decrypt(confirmRemoveEncryption: true);
        convert(db);
        snapOk('decrypted $round');
      }
      for (var i = 0; i < 300; i++) {
        expect(e.get(t, CNitriteId(i)), val(i.isEven ? i + 300 : i));
      }
      e.release(snap);
      e.close();
    });
  });

  test('F-025: a scan range is half-open', () {
    final e = Engine();
    for (var i = 0; i < 10; i++) {
      e.put(t, CNitriteId(i), b([i]));
    }
    final r = KeyRange(encodeKey(const CNitriteId(2)), encodeKey(const CNitriteId(5)));
    expect(e.scanTree(t, range: r).length, 3);
    e.flush();
    expect(e.scanTree(t, range: r).length, 3);
  });

  test('F-026: a scan reads the newest value-log values of the open segment', () {
    final e = Engine();
    for (var i = 0; i < 50; i++) {
      e.put(t, CNitriteId(i), big(i, 5000 + i));
    }
    expect([for (final r in e.scanTree(t)) r.value.length],
        [for (var i = 0; i < 50; i++) 5000 + i]);
    e.flush();
    expect(e.scanTree(t).length, 50);
  });

  test('F-027/F-037: a snapshot reads its versions after collection retires their segment',
      () {
    final e = Engine();
    for (var i = 0; i < 60; i++) {
      e.put(t, CNitriteId(i), big(1));
    }
    e.compact();
    final s = e.snapshot();
    final before = e.coldCollections;
    for (var round = 2; round < 6; round++) {
      for (var i = 0; i < 60; i++) {
        e.put(t, CNitriteId(i), big(round));
      }
      e.compact();
    }
    expect(e.coldCollections, greaterThan(before), reason: 'nothing collected');
    for (var i = 0; i < 60; i++) {
      expect(e.get(t, CNitriteId(i), at: s), big(1), reason: 'snapshot $i');
      expect(e.get(t, CNitriteId(i)), big(5), reason: 'current $i');
    }
    e.release(s);
    e.compact();
    for (var i = 0; i < 60; i++) {
      expect(e.get(t, CNitriteId(i)), big(5));
    }
  });

  test('F-089/F-091/F-092: a write failing anywhere in compact+commit+close '
      'loses no acked data and leaves the file reopenable', () {
    final dir = Directory.systemTemp.createTempSync('cryptand-f091-');
    var faults = 0;
    for (var k = 1; k < 80; k++) {
      final path = '${dir.path}/db$k.cryptand';
      DatabaseFile.save(Database(engine: Engine()), path);
      var e = DatabaseFile.open(path).engine;
      for (var g = 0; g < 3; g++) {
        for (var i = 0; i < 50; i++) {
          e.put(t, CNitriteId(g * 50 + i), big(g, 300 + 200 * (i % 3)));
        }
        e.commit();
      }
      final hook = _FailNth(k);
      fileHook = hook;
      try {
        for (var i = 0; i < 150; i += 3) {
          e.remove(t, CNitriteId(i));
        }
        e.compact();
        e.commit();
        e.close();
      } on Object {
        faults++;
        fileHook = null;
        try {
          e.close(flushMemtable: false);
        } on Object {/* the handle goes in `finally` regardless */}
      } finally {
        fileHook = null;
      }
      e = DatabaseFile.open(path).engine; // F-089: the lock was released
      for (var g = 0; g < 3; g++) {
        for (var i = 0; i < 50; i++) {
          final id = g * 50 + i;
          final got = e.get(t, CNitriteId(id));
          // Every put was acked; the removes only if close finished.
          if (got != null) expect(got, big(g, 300 + 200 * (i % 3)), reason: 'k=$k id=$id');
          if (!hook.fired && id % 3 == 0) expect(got, isNull, reason: 'k=$k id=$id back');
          if (id % 3 != 0) expect(got, isNotNull, reason: 'k=$k id=$id lost');
        }
      }
      expect(e.verifyStructure().findings, isEmpty, reason: 'k=$k');
      e.close();
    }
    expect(faults, greaterThan(30), reason: 'the hook never fired');
  });
}

class _FailNth implements FileHook {
  _FailNth(this.n);
  final int n;
  int seen = 0;
  bool fired = false;
  @override
  void beforeWrite(RandomAccessFile f, int pos, List<int> bytes) {
    if (++seen == n) {
      fired = true;
      throw const FileSystemException('injected ENOSPC', '', OSError('No space left on device', 28));
    }
  }

  @override
  void beforeSync(RandomAccessFile f) {}
}
