/// M5.5 Verify: open an N-document file with RSS <= the desktop page cache
/// budget + 64 MB.
///
/// ```
/// dart run tool/rss_scale.dart build PATH N   # writes, commits per 100k
/// dart run tool/rss_scale.dart open PATH N    # fresh process, 10k gets
/// ```
///
/// `open` prints `max_rss_mb`, `budget_mb` and PASS/FAIL. Run it AOT
/// (`dart compile exe`): under `dart run` the JIT alone peaks near 265 MB.
library;

import 'dart:io';

import 'package:cryptand/cryptand.dart';

import '../bench/harness.dart';

void main(List<String> args) {
  final path = args[1];
  final n = int.parse(args[2]);
  CValue id(int i) => CNitriteId(snowflakeId(i));
  if (args[0] == 'build') {
    DatabaseFile.save(Database(engine: Engine())..createCollection('c'), path);
    final db = DatabaseFile.open(path);
    final c = db.collection('c')!;
    for (var i = 0; i < n; i++) {
      c.put(id(i), benchDoc(i));
      if ((i + 1) % 100000 == 0) {
        db.engine.commit();
        stdout.writeln('${i + 1} rss_mb=${ProcessInfo.currentRss >> 20}');
      }
    }
    db.engine.close();
    stdout.writeln('built $n bytes=${File(path).lengthSync()}');
    return;
  }
  final db = DatabaseFile.open(path);
  final c = db.collection('c')!;
  var s = 0x51EDC0DE, missing = 0;
  for (var k = 0; k < 10000; k++) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    if (c.get(id(s % n)) == null) missing++;
  }
  db.engine.close();
  final rss = ProcessInfo.maxRss >> 20;
  final budget = (Profile.desktop.pageCacheBytes >> 20) + 64;
  stdout.writeln('max_rss_mb=$rss budget_mb=$budget missing=$missing '
      '${rss <= budget && missing == 0 ? 'PASS' : 'FAIL'}');
}
