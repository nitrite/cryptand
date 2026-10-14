/// F-150: dead value-log space must come back (04 §6.8).
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

void main() {
  test('F-150: overwriting the same values does not grow the file', () {
    // 150 x (open, overwrite 256 x 4 KiB, commit, close), as Rust's
    // space_test. Before the fix: 460 MB at 100 and superlinear (1 GB at
    // 300). Then flat near 80 MB with tiered levels keeping every version;
    // since §5 drops a superseded version at any level (F-150), ~26 MB.
    final path =
        '${Directory.systemTemp.createTempSync('cryptand-f150-').path}/db.cryptand';
    DatabaseFile.save(Database(engine: Engine()), path);
    var at75 = 0;
    for (var cycle = 0; cycle < 150; cycle++) {
      final e = DatabaseFile.open(path).engine;
      for (var i = 0; i < 256; i++) {
        e.put(16, CNitriteId(i), Uint8List(4096)..fillRange(0, 4096, cycle));
      }
      e.commit();
      e.close();
      if (cycle == 75) at75 = File(path).lengthSync();
    }
    final len = File(path).lengthSync();
    final e = DatabaseFile.open(path).engine;
    for (var i = 0; i < 256; i++) {
      expect(
          e.get(16, CNitriteId(i)), Uint8List(4096)..fillRange(0, 4096, 149));
    }
    e.close();
    expect(len, lessThanOrEqualTo(at75 + at75 ~/ 20),
        reason: 'still growing: $at75 at cycle 75');
    expect(len, lessThan(32 << 20));
  });

  test('F-151: a cold point read reads pages, not the segment', () {
    // Before the fix a cache miss read, decrypted and decoded the whole
    // segment extent: hundreds of pages for one get.
    final path =
        '${Directory.systemTemp.createTempSync('cryptand-f151-').path}/db.cryptand';
    DatabaseFile.save(Database(engine: Engine()), path);
    var e = DatabaseFile.open(path).engine;
    Uint8List v(int i) => Uint8List(100)..fillRange(0, 100, i % 251);
    for (var i = 0; i < 20000; i++) {
      e.put(16, CNitriteId(i), v(i));
    }
    e.commit();
    e.close();
    e = DatabaseFile.open(path).engine;
    for (final i in [7, 12345, 19999]) {
      final p0 = e.store.pageReads;
      expect(e.get(16, CNitriteId(i)), v(i));
      final n = e.store.pageReads - p0;
      expect(n, lessThanOrEqualTo(32),
          reason: 'a cold get of $i read $n pages');
    }
    e.close();
  });

  test('F-158: compaction keeps the page cache within its budget', () {
    // Before the fix each compaction output was admitted whole: a 10^7 build
    // held a 100 MB output extent in a 64 MB cache.
    final e = Engine(memtableEntries: 500)..pageCacheBytes = 64 << 10;
    Uint8List v(int i) => Uint8List(100)..fillRange(0, 100, i % 251);
    for (var i = 0; i < 20000; i++) {
      e.put(16, CNitriteId(i), v(i));
    }
    e.compact();
    final resident = e.extents.values.fold(0, (n, s) => n + s.residentBytes);
    expect(resident, lessThanOrEqualTo(64 << 10));
  });

  test('F-152: a bulk load keeps L0 under its hard bound', () {
    // 10 §6: flushes that outgrow one compaction step must not run L0 past
    // l0_trigger x 4; the step is raised while a bound is in overshoot.
    // Before the fix the 10^6 rung left 46 L0 segments.
    final path =
        '${Directory.systemTemp.createTempSync('cryptand-f152-').path}/db.cryptand';
    DatabaseFile.save(Database(engine: Engine()), path);
    final e = DatabaseFile.open(path).engine;
    final hard = e.levels.l0Trigger * 4;
    var worst = 0;
    for (var c = 0; c < 30; c++) {
      for (var i = 0; i < 20000; i++) {
        e.put(16, CNitriteId(c * 20000 + i), Uint8List(100));
      }
      e.commit();
      worst = worst > e.refsAt(0).length ? worst : e.refsAt(0).length;
      expect(e.backpressure.delayMs, lessThan(100),
          reason: '${e.backpressure.cause} at its hard bound, commit $c');
    }
    e.close();
    expect(worst, lessThanOrEqualTo(hard));
  });

  for (final encrypted in [false, true]) {
    test(
        'F-154: shrink relocates live extents down and truncates the file'
        '${encrypted ? ' (encrypted)' : ''}', () {
      // Before the fix Dart's shrink() truncated nothing: a settled 10^6 file
      // stayed 1487 MB with 800 MB of it free, its tail included.
      final path =
          '${Directory.systemTemp.createTempSync('cryptand-f154-').path}/db.cryptand';
      // Encrypted: a moved segment's manifest entry records its new head nonce.
      final key = List.filled(32, 7);
      Engine reopen() => DatabaseFile.open(path,
              key: encrypted ? Uint8List.fromList(key) : null)
          .engine;
      if (encrypted) {
        DatabaseFile.create(path,
                credential: Uint8List.fromList(key), kdf: Keyslot.kdfRaw)
            .engine
            .close();
      } else {
        DatabaseFile.save(Database(engine: Engine()), path);
      }
      var e = reopen();
      // Small values in segments, 4 KiB ones in the value log.
      Uint8List v(int i, int round) =>
          Uint8List(i.isEven ? 100 : 4096)..fillRange(0, 8, (i + round) % 251);
      for (var round = 0; round < 4; round++) {
        for (var i = 0; i < 4000; i++) {
          e.put(16, CNitriteId(i), v(i, round));
        }
        e.commit();
      }
      e
        ..compact()
        ..commit();
      final before = File(path).lengthSync();
      final cut = e.shrink().bytesProcessed;
      final after = File(path).lengthSync();
      e.close();
      expect(cut, greaterThan(0));
      e = reopen();
      for (var i = 0; i < 4000; i++) {
        expect(e.get(16, CNitriteId(i)), v(i, 3));
      }
      expect(e.verifyStructure().isSound, isTrue);
      e.close();
      // Encrypted (8 KiB pages here) keeps holes freed too late to reuse in
      // this shrink: 69 -> 51 MB, plaintext 48 -> 21 MB.
      expect(after, lessThan(encrypted ? before * 3 ~/ 4 : before ~/ 2),
          reason: '$before -> $after');
    });
  }
}
