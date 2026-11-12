/// A process for `spec/13-operations.md` §8 tests, in Dart
/// (`test/multiproc_test.dart`) and across languages
/// (`reference/conformance/interop/multiproc.py`).
///
///     reader PATH : print the mode; on a line, scan tree 16 and print rows/bad; on a line, exit
///     leak PATH   : open a reader, idle 3 s, print whether its beat moved, return unclosed
///     writer PATH : create, 5000 rows of 200 x 1, print ready; on a line, churn and print
///                   the floor; on a line, close
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';

const tree = 16;
const rows = 5000;

Uint8List doc(int fill) => Uint8List(200)..fillRange(0, 200, fill);

Engine populated(String path) {
  DatabaseFile.save(Database(engine: Engine()), path);
  final e = DatabaseFile.open(path).engine;
  for (var i = 0; i < rows; i++) {
    e.put(tree, CNitriteId(i), doc(1));
  }
  e.commit();
  return e;
}

/// Overwrite every row, compact and shrink: every extent of an old snapshot is freed.
void churn(Engine e) {
  for (var round = 2; round < 6; round++) {
    for (var i = 0; i < rows; i++) {
      e.put(tree, CNitriteId(i), doc(round));
    }
    e
      ..commit()
      ..compact()
      ..commit();
  }
  e
    ..shrink()
    ..commit();
}

Future<void> main(List<String> args) async {
  // Sync reads of stdin: the child is a script, not a server.
  String? next() => stdin.readLineSync();
  final path = args[1];
  if (args[0] == 'leak') {
    final mp = DatabaseFile.openReadOnly(path).engine.multiproc!;
    await Future<void>.delayed(const Duration(seconds: 3));
    final beat = mp.sidecar!.slot(mp.slot!.index).heartbeatMs;
    print('beats=${beat > mp.slot!.heartbeatMs}');
    return;
  }
  if (args[0] == 'writer') {
    final e = populated(path);
    print('ready commit=${e.commitId}');
    next();
    churn(e);
    print('churned floor=${e.minRetainedCommit}');
    next();
    e.close();
    return;
  }
  final e = DatabaseFile.openReadOnly(path).engine;
  final mp = e.multiproc!;
  print(mp.slot != null
      ? 'mode=slotted index=${mp.slot!.index} commit=${mp.slot!.commitId}'
      : 'mode=volatile reason=${mp.volatileReason}');
  next();
  try {
    var n = 0, bad = 0;
    final want = doc(1);
    for (final r in e.scanTree(tree)) {
      n++;
      if (r.value.length != 200 || r.value.any((b) => b != want[0])) bad++;
    }
    print('rows=$n bad=$bad');
  } on Object catch (x) {
    print('error=$x');
  }
  next();
  e.close(flushMemtable: false);
}
