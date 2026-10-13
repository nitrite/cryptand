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
    // 300). Now flat near 80 MB: this policy's tiered levels keep up to ~36
    // versions until the last level drops them (§5 condition 3).
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
      expect(e.get(16, CNitriteId(i)), Uint8List(4096)..fillRange(0, 4096, 149));
    }
    e.close();
    expect(len, lessThanOrEqualTo(at75 + at75 ~/ 20),
        reason: 'still growing: $at75 at cycle 75');
    expect(len, lessThan(100 << 20));
  });
}
