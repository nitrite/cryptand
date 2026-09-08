/// The CRUD-under-load matrix — see `reference/bench/README.md`.
///
/// `bench/ops.dart` beside this one measures **C** and **R**: a bulk insert, a
/// point read, a scan, an index lookup. It has no **U** and no **D**, and every
/// phase of it runs against a database that has just been compacted and is
/// otherwise idle. That is the best case, and it is not the case a person
/// choosing a database is asking about when they say "under load".
///
/// This one measures all four operations, and it measures them twice: once each
/// in isolation, and once in a sustained mixed workload with background
/// maintenance running underneath. The difference between the two is the point.
///
/// **"Under load" here means a sustained mixed workload, not concurrency.**
/// `reference/bench/README.md` explains why the cross-language suite has no
/// concurrency row: Dart has no shared-memory threads, so a multi-writer number
/// would not mean the same thing in each of the three, and `10-transactions.md`
/// §2's scaling has its own single-language harness. Load here is the shape of
/// the work, and that is a definition all three can honour.
///
/// `design/performance-model.md` §8's rule governs the output: **a counter is
/// the primary result and wall time is an observation.**
library;

import 'dart:io';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/database.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/file.dart';
import 'package:cryptand/src/value.dart';

import 'harness.dart';

void row(String name, Object value, String unit, {required bool primary}) {
  stdout.writeln(
      '$name=$value unit=$unit kind=${primary ? "counter" : "observation"}');
}

int percentile(List<int> xs, double p) {
  if (xs.isEmpty) return 0;
  final s = [...xs]..sort();
  return s[((s.length - 1) * p).round()];
}

String f(num v, [int d = 3]) => v.toStringAsFixed(d);

/// `benchDoc` with the value bytes varied by [rev], so an update is a real
/// rewrite rather than a no-op the engine could elide. The *shape* is
/// unchanged, which is what keeps it comparable with `bench/ops.dart`.
CDoc revDoc(int i, int rev) {
  final fields = {...benchDoc(i).fields};
  final pad = i.toString().padLeft(6, '0');
  fields['ordStatusTxt'] =
      CStr('stat-$pad-${rev % 10}'.padRight(19, 'y'));
  return CDoc(fields);
}

/// A deterministic xorshift, the same shape the other two benches use.
int _seed = 0x51EDC0DE;
int nextRandom() {
  _seed ^= (_seed << 13) & 0x7FFFFFFF;
  _seed ^= _seed >> 7;
  _seed ^= (_seed << 17) & 0x7FFFFFFF;
  return _seed & 0x7FFFFFFF;
}

/// p50/p99 plus the counters, printed with the same names the Rust and Java
/// versions print so a comparison script can filter rather than translate.
void report(String name, List<int> lat, int pageReads, int ops, double secs) {
  row('${name}_ops_per_s', f(ops / (secs <= 0 ? 1e-9 : secs), 0), 'ops/s',
      primary: false);
  row('${name}_us_p50', percentile(lat, 0.50), 'us', primary: false);
  row('${name}_us_p99', percentile(lat, 0.99), 'us', primary: false);
  row('${name}_us_p999', percentile(lat, 0.999), 'us', primary: false);
  row('${name}_page_reads_per_op', f(pageReads / (ops == 0 ? 1 : ops)),
      'pages/op',
      primary: true);
}

void main(List<String> args) {
  final n = args.isNotEmpty ? int.parse(args.first) : 20000;
  final mixedOps = args.length > 1 ? int.parse(args[1]) : 20000;

  stdout.writeln('# cryptand crud-under-load matrix -- dart');
  stdout.writeln('# implementation=dart documents=$n mixed_ops=$mixedOps '
      'profile=desktop durability=os');

  final dir = Directory.systemTemp.createTempSync('cryptand-crud-');
  final path = '${dir.path}/db.cryptand';
  final db = Database(
      engine: Engine(
          pageSize: Profile.desktop.pageSize,
          vlogMin: Profile.desktop.vlogMin,
          memtableEntries: 4096,
          levels: LevelPolicy.desktop));
  final c = db.createCollection('orders');

  // ------------------------------------------------------------------
  // C — create
  // ------------------------------------------------------------------
  var logical = 0;
  final createLat = <int>[];
  final sw = Stopwatch()..start();
  for (var i = 0; i < n; i++) {
    final d = benchDoc(i);
    logical += encodeValue(d).length;
    final t = Stopwatch()..start();
    c.put(CNitriteId(snowflakeId(i)), d);
    t.stop();
    createLat.add(t.elapsedMicroseconds);
  }
  db.engine.flush();
  sw.stop();
  report('create', createLat, 0, n, sw.elapsedMicroseconds / 1e6);
  row('create_logical_bytes', logical, 'bytes', primary: true);

  // Drain compaction before every measured phase: a phase that reads what it
  // just wrote measures the memtable, not the engine.
  db.engine.drainCompaction();
  DatabaseFile.save(db, path);
  row('create_bytes_device_per_op', f(File(path).lengthSync() / n, 1),
      'bytes/op',
      primary: true);

  // ------------------------------------------------------------------
  // R — read
  // ------------------------------------------------------------------
  for (var i = 0; i < 200; i++) {
    c.get(CNitriteId(snowflakeId(nextRandom() % n)));
  }
  db.engine.store.pageReads = 0;
  final reads = n < 5000 ? n : 5000;
  final readLat = <int>[];
  final rsw = Stopwatch()..start();
  for (var i = 0; i < reads; i++) {
    final t = Stopwatch()..start();
    final got = c.get(CNitriteId(snowflakeId(nextRandom() % n)));
    t.stop();
    readLat.add(t.elapsedMicroseconds);
    if (got == null) throw StateError('the fixture must hold every id it reads');
  }
  rsw.stop();
  report('read', readLat, db.engine.store.pageReads, reads,
      rsw.elapsedMicroseconds / 1e6);

  // ------------------------------------------------------------------
  // U — update. An overwrite at the same key: a new version, not an edit in
  // place.
  // ------------------------------------------------------------------
  db.engine.store.pageReads = 0;
  final updates = n < 5000 ? n : 5000;
  final updLat = <int>[];
  final usw = Stopwatch()..start();
  for (var k = 0; k < updates; k++) {
    final i = nextRandom() % n;
    final d = revDoc(i, k + 1);
    final t = Stopwatch()..start();
    c.put(CNitriteId(snowflakeId(i)), d);
    t.stop();
    updLat.add(t.elapsedMicroseconds);
  }
  db.engine.flush();
  usw.stop();
  report('update', updLat, db.engine.store.pageReads, updates,
      usw.elapsedMicroseconds / 1e6);

  db.engine.drainCompaction();

  // ------------------------------------------------------------------
  // D — delete. A tombstone, so it is a write and not a reclaim.
  // ------------------------------------------------------------------
  db.engine.store.pageReads = 0;
  final deletes = n < 5000 ? n : 5000;
  final delLat = <int>[];
  final dsw = Stopwatch()..start();
  for (var k = 0; k < deletes; k++) {
    final t = Stopwatch()..start();
    c.remove(CNitriteId(snowflakeId(k % n)));
    t.stop();
    delLat.add(t.elapsedMicroseconds);
  }
  db.engine.flush();
  dsw.stop();
  report('delete', delLat, db.engine.store.pageReads, deletes,
      dsw.elapsedMicroseconds / 1e6);

  // A delete must actually have deleted. Benchmarking an operation that did
  // nothing is the easiest way to publish a fast number.
  if (c.get(CNitriteId(snowflakeId(0))) != null) {
    throw StateError('the delete phase deleted nothing');
  }

  db.engine.drainCompaction();

  // ------------------------------------------------------------------
  // The mixed phase — 70 % read, 20 % update, 5 % insert, 5 % delete,
  // interleaved, with compaction running underneath rather than drained
  // first. The isolated phases above are each one operation's best case; the
  // difference between the two columns is the cost of everything the best
  // case leaves out.
  // ------------------------------------------------------------------
  db.engine.store.pageReads = 0;
  var nextNew = n;
  final mixRead = <int>[];
  final mixUpdate = <int>[];
  final mixInsert = <int>[];
  final mixDelete = <int>[];
  final msw = Stopwatch()..start();
  for (var k = 0; k < mixedOps; k++) {
    final roll = nextRandom() % 100;
    final t = Stopwatch()..start();
    if (roll < 70) {
      c.get(CNitriteId(snowflakeId(nextRandom() % n)));
      t.stop();
      mixRead.add(t.elapsedMicroseconds);
    } else if (roll < 90) {
      final i = nextRandom() % n;
      c.put(CNitriteId(snowflakeId(i)), revDoc(i, k + 2));
      t.stop();
      mixUpdate.add(t.elapsedMicroseconds);
    } else if (roll < 95) {
      c.put(CNitriteId(snowflakeId(nextNew)), benchDoc(nextNew));
      nextNew++;
      t.stop();
      mixInsert.add(t.elapsedMicroseconds);
    } else {
      c.remove(CNitriteId(snowflakeId(nextRandom() % n)));
      t.stop();
      mixDelete.add(t.elapsedMicroseconds);
    }
    // Background maintenance, paced as `12-profiles.md` §4 requires rather
    // than drained: this is the load the phase is named for.
    if (k % 64 == 0) db.engine.maybeCompact();
  }
  msw.stop();
  final mixedSecs = msw.elapsedMicroseconds / 1e6;
  row('mixed_ops_per_s', f(mixedOps / (mixedSecs <= 0 ? 1e-9 : mixedSecs), 0),
      'ops/s',
      primary: false);
  row('mixed_page_reads_per_op', f(db.engine.store.pageReads / mixedOps),
      'pages/op',
      primary: true);
  for (final e in [
    ('mixed_read', mixRead),
    ('mixed_update', mixUpdate),
    ('mixed_insert', mixInsert),
    ('mixed_delete', mixDelete),
  ]) {
    row('${e.$1}_us_p50', percentile(e.$2, 0.50), 'us', primary: false);
    row('${e.$1}_us_p99', percentile(e.$2, 0.99), 'us', primary: false);
    row('${e.$1}_count', e.$2.length, 'ops', primary: true);
  }

  stdout.writeln('# done');
  dir.deleteSync(recursive: true);
}
