/// Point reads served from the **memtable** — the read-your-writes path.
///
/// `reference/bench`'s `ops.dart` deliberately measures point reads *after a
/// compaction*, "so it measures the engine and not the memtable". That makes it
/// structurally unable to see anything about memtable lookup: by the time it
/// reads, there is nothing pending. This measures the other side.
///
/// The memtable was a `Map<Uint8List, _Pending>`, and Dart gives `Uint8List`
/// identity equality — a key rebuilt from the same bytes is a different key —
/// so the map could not be looked up at all and every read walked every pending
/// entry. Rust range-seeks an ordered map; Java uses a `ConcurrentSkipListMap`.
///
///   dart run bench/memtable_read.dart
library;

import 'package:cryptand/cryptand.dart';

void main() {
  print('# reads served from the memtable, by number of pending writes.');
  print('# `us per read` is an observation; the SHAPE of the column is the '
      'result.');
  print('${'pending'.padLeft(9)} | ${'us per read'.padLeft(12)} | '
      '${'vs previous'.padLeft(11)}');
  print('-' * 40);

  double? previous;
  for (final n in [250, 500, 1000, 2000]) {
    final db = Database();
    // The default memtable holds 20 000 entries, well above anything written
    // here, so nothing flushes and every read below is served from pending
    // writes — which is the whole point.
    final c = db.createCollection('docs');
    for (var i = 0; i < n; i++) {
      c.put(CNitriteId(i), CDoc({'body': CStr('row $i')}));
    }
    const reads = 20000;
    final sw = Stopwatch()..start();
    for (var r = 0; r < reads; r++) {
      c.get(CNitriteId(r % n));
    }
    sw.stop();
    final us = sw.elapsedMicroseconds / reads;
    final ratio =
        previous == null ? '' : '${(us / previous).toStringAsFixed(2)}x';
    print('${n.toString().padLeft(9)} | ${us.toStringAsFixed(2).padLeft(12)} | '
        '${ratio.padLeft(11)}');
    previous = us;
  }
  print('\nAn ordered memtable keeps `us per read` flat and `vs previous` near '
      '1.00x.\nA linear scan doubles when the pending set doubles.');
}
