/// M6 Dart rung (PLAN 6.2) and the M5.5 RSS check. Each phase prints one
/// JSON metrics line.
///
/// ```
/// dart compile exe tool/scale.dart -o scale
/// ./scale build PATH N   # load, commit per 100k
/// ./scale settle PATH N  # compact + commit + shrink, file size (F-154)
/// ./scale read PATH N    # fresh process: cold open, gets, scan, verify
/// ```
///
/// `read` ends with PASS/FAIL against PLAN 6.3's RSS bar (cache + 256 MB). Run
/// AOT: under `dart run` the JIT alone peaks near 265 MB.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:cryptand/cryptand.dart';

import '../bench/harness.dart';

CValue id(int i) => CNitriteId(snowflakeId(i));

/// `CRYPTAND_ENC=1`: encrypted file, fixed raw key (kdf 0), as Rust `rss_scale`.
/// ponytail: fixed bench key, never a real secret.
final List<int>? key =
    Platform.environment.containsKey('CRYPTAND_ENC') ? List.filled(32, 7) : null;

void main(List<String> args) {
  final path = args[1];
  final n = int.parse(args[2]);
  final out = <String, Object>{'impl': 'dart', 'phase': args[0], 'n': n};
  final sw = Stopwatch()..start();
  if (args[0] == 'build') {
    if (key == null) {
      DatabaseFile.save(
          Database(engine: Engine(pageSize: Profile.desktop.pageSize))
            ..createCollection('c'),
          path);
    } else {
      DatabaseFile.create(path, credential: key!, kdf: Keyslot.kdfRaw)
        ..createCollection('c')
        ..engine.close();
    }
    final db = DatabaseFile.open(path, key: key);
    final c = db.collection('c')!;
    var peak = 0;
    for (var i = 0; i < n; i++) {
      c.put(id(i), benchDoc(i));
      if ((i + 1) % 100000 == 0 || i + 1 == n) {
        db.engine.commit();
        peak = math.max(peak, ProcessInfo.currentRss >> 20);
      }
    }
    db.engine.close();
    final bytes = File(path).lengthSync();
    out
      ..['load_docs_per_s'] = (n * 1e6 / sw.elapsedMicroseconds).round()
      ..['file_bytes'] = bytes
      // 516 B logical record per benchDoc (harness.dart).
      ..['space_amp'] = double.parse((bytes / (n * 516)).toStringAsFixed(2))
      ..['writer_rss_mb'] = peak;
    stdout.writeln(jsonEncode(out));
    return;
  }

  if (args[0] == 'settle') {
    final db = DatabaseFile.open(path, key: key);
    db.engine
      ..compact()
      ..commit()
      ..shrink()
      ..close();
    final bytes = File(path).lengthSync();
    out
      ..['settle_ms'] = sw.elapsedMilliseconds
      ..['file_bytes'] = bytes
      ..['space_amp'] = double.parse((bytes / (n * 516)).toStringAsFixed(2));
    stdout.writeln(jsonEncode(out));
    return;
  }

  final db = DatabaseFile.open(path, key: key);
  out['open_ms'] = sw.elapsedMilliseconds;
  // Max RSS after each step: shows which step sets the rung's peak.
  void mark(String step) => out['rss_${step}_mb'] = ProcessInfo.maxRss >> 20;
  mark('open');
  final c = db.collection('c')!;
  final rnd = math.Random(0x51EDC0DE);
  var missing = 0;
  // ponytail: zipf by inverse power (s~1.2 skew), not an exact Zipf(0.99).
  int zipf() => (n * math.pow(rnd.nextDouble(), 6)).floor() % n;
  for (final (name, pick) in [
    ('uniform', () => rnd.nextInt(n)),
    ('zipf', zipf),
  ]) {
    final us = <int>[];
    for (var k = 0; k < 10000; k++) {
      final t = Stopwatch()..start();
      if (c.get(id(pick())) == null) missing++;
      us.add(t.elapsedMicroseconds);
    }
    us.sort();
    out['${name}_misses'] = db.engine.cacheMisses;
    out['${name}_evictions'] = db.engine.cacheEvictions;
    out['${name}_cached'] = db.engine.extents.length;
    for (final (q, p) in [('p50', 0.5), ('p99', 0.99), ('p999', 0.999)]) {
      out['get_${name}_${q}_us'] = us[(us.length * p).floor()];
    }
    mark(name);
  }
  sw.reset();
  var rows = 0;
  final lo = rnd.nextInt(math.max(1, n - 100000));
  for (final _ in db.engine.scanTree(c.treeId,
      range: KeyRange(encodeKey(id(lo)), encodeKey(id(lo + 100000))))) {
    rows++;
  }
  out['scan_rows_per_s'] = (rows * 1e6 / sw.elapsedMicroseconds).round();
  mark('scan');
  sw.reset();
  final sound = db.engine.verifyStructure(claims: db.indexClaims()).isSound;
  out
    ..['verify_ms'] = sw.elapsedMilliseconds
    ..['verify_sound'] = sound
    ..['missing'] = missing;
  db.engine.close();
  final rss = ProcessInfo.maxRss >> 20;
  // PLAN 6.3: profile budget + memtables + 256 MB; a read rung's memtable is
  // empty. (+64 MB is M5.5's bar for a bare open, not for a rung.)
  final budget = (Profile.desktop.pageCacheBytes >> 20) + 256;
  out
    ..['max_rss_mb'] = rss
    ..['budget_mb'] = budget
    ..['pass'] = rss <= budget && missing == 0 && sound;
  stdout.writeln(jsonEncode(out));
}
