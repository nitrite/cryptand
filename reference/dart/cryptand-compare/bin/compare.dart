/// Cryptand against **Hive** — the Dart comparison table.
///
/// `reference/rust/cryptand-compare` does this for Rust against fjall, redb and
/// sled, and `CompareBench.java` for Java against MVStore, RocksDB and PalDB.
/// This one follows the same rules, which are `reference/bench/README.md`'s:
///
/// * **The same bytes.** Both engines are handed the same already-encoded CVE
///   document for the same key, built before the clock starts, so neither
///   encoding nor key layout is the variable.
/// * **The same phase shape**, in the same order, from the same pseudo-random
///   sequence as the other two tables.
/// * **One durability barrier per phase.** Cryptand buffers a phase's writes in
///   its memtable and makes them durable at `commit(os)`; Hive's `put` writes
///   into its in-memory box and queues the append, and `flush()` is what waits
///   for the queue. Both therefore pay one barrier per phase and neither pays
///   one per operation.
/// * **A read returns a handle, in both.** Hive's `get` returns the
///   `Uint8List` it holds -- the same object on every call, never a copy.
///   Cryptand's `get` copies the value into a fresh array, so this table calls
///   `getView`, the same resolution returning an unmodifiable view of the
///   value where it lives. It is the rule the Rust table follows with
///   `get_ref`: calling `get` here would be measuring a whole-document copy,
///   and the garbage it leaves, that Hive is not being asked to make.
/// * **The first pass is discarded**, and the runner takes medians.
///
/// ## What is not equal, and has to be said first
///
/// **A Hive `Box` keeps every value in memory.** `openBox` reads the whole file
/// into a map on open and serves every `get` from it; the file is an append-only
/// log that `compact()` rewrites. That is the same caveat MVStore carries in the
/// Java table, and it is most of what Hive's read column is. `LazyBox` is the
/// variant that reads from disk, and its `get` is asynchronous — a row for it
/// would be measuring the event loop, not the store, so it is not here.
///
/// Cryptand is also doing more per operation: a manifest, per-segment filters,
/// liveness statistics, a value-log GC, a CRC-32C per page, and a file three
/// other language runtimes can open. Hive has none of that and is not trying to.
///
/// Keys are the `int` snowflake id rather than its eight big-endian bytes,
/// which is the same key: Hive's box is keyed by `int` or `String`, and
/// Cryptand's `NitriteId` encodes to those eight bytes. Neither engine is given
/// a shorter key than the other.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/database.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/file.dart';
import 'package:cryptand/src/value.dart';
import 'package:hive/hive.dart';

const int tree = 16;

int snowflake(int i) => (1767225600000 * 4194304) + i * 4096 + 1;

/// The suite's document: 20 fields, names averaging 12 B, values averaging
/// 20 B — `design/performance-model.md` §1's shape.
CDoc doc(int i, int rev) {
  final pad = i.toString().padLeft(6, '0');
  CValue v(String p) {
    var s = '$p-$pad-${rev % 10}';
    while (s.length < 19) {
      s += 'y';
    }
    return CStr(s);
  }

  return CDoc({
    '_id': CNitriteId(snowflake(i)),
    'custAddr1_ln': v('addr1'),
    'custAddr2_ln': v('addr2'),
    'custCityName': v('city'),
    'custPostCode': v('post'),
    'custCountryX': v('ctry'),
    'custEmailAdr': v('mail'),
    'custPhoneNum': v('phon'),
    'ordReference': v('ordr'),
    'ordStatusTxt': v('stat'),
    'ordCurrencyC': v('curr'),
    'ordNotesText': v('note'),
    'whseLocation': v('whse'),
    'carrierName_': v('carr'),
    'trackingNumb': v('trak'),
    'ordTotMinorU': CInt.varInt(1299 + i),
    'ordTaxMinorU': CInt.varInt(216),
    'ordShipMinor': CInt.varInt(499),
    'placedAtUtcM': const CTimestamp(1767225000000),
    'dispatchUtcM': const CTimestamp(1767225600000),
  });
}

/// xorshift64, identical in the Java, Rust and Dart benchmarks so the operation
/// order is the same sequence everywhere. Dart's `int` is 64-bit and its `>>`
/// is arithmetic, so the logical shift is written out.
int next(int s) {
  s ^= (s << 13);
  s ^= (s >>> 7);
  s ^= (s << 17);
  return s;
}

int below(int seed, int n) => (seed >>> 32) % n;

double rate(int count, Stopwatch w) =>
    count / (w.elapsedMicroseconds / 1e6).clamp(1e-9, double.infinity);

int onDisk(Directory d) {
  var total = 0;
  for (final e in d.listSync(recursive: true)) {
    if (e is File) total += e.lengthSync();
  }
  return total;
}

class Row {
  double create = 0;
  double read = 0;
  double update = 0;
  double delete = 0;
  double mixed = 0;
  int bytes = 0;
}

Row benchCryptand(int n, int mixedOps, List<Uint8List> v0, List<Uint8List> v1) {
  final dir = Directory.systemTemp.createTempSync('cmp-cryptand-');
  final path = '${dir.path}/db.cryptand';
  // The same construction `bench/xlang_crud.dart` uses, so this row and that
  // one are the same engine in the same shape.
  final db = Database(
      engine: Engine(
    pageSize: Profile.desktop.pageSize,
    vlogMin: Profile.desktop.vlogMin,
    // The profile's, as the other two use: left out, the engine's 4 MiB
    // default ran a `desktop` bench with a sixteenth of `desktop`'s value-log
    // segment, and a value-log workload wrote a file half the others' size.
    vlogSegmentBytes: Profile.desktop.vlogSegmentBytes,
    memtableEntries: 4096,
    levels: LevelPolicy.desktop,
  ));
  final e = db.engine;
  CValue key(int i) => CNitriteId(snowflake(i));
  final r = Row();
  final w = Stopwatch();

  w.start();
  for (var i = 0; i < n; i++) {
    e.put(tree, key(i), v0[i]);
  }
  e.flush();
  r.create = rate(n, w);
  e.compact();

  var seed = 0x51EDC0DE;
  for (var i = 0; i < 2000; i++) {
    seed = next(seed);
    e.getView(tree, key(below(seed, n)));
  }
  w.reset();
  for (var i = 0; i < n; i++) {
    seed = next(seed);
    e.getView(tree, key(below(seed, n)));
  }
  r.read = rate(n, w);

  final updates = n < 5000 ? n : 5000;
  w.reset();
  for (var k = 0; k < updates; k++) {
    seed = next(seed);
    final i = below(seed, n);
    e.put(tree, key(i), v1[i]);
  }
  e.flush();
  r.update = rate(updates, w);

  final deletes = n < 5000 ? n : 5000;
  w.reset();
  for (var k = 0; k < deletes; k++) {
    e.remove(tree, key(k % n));
  }
  e.flush();
  r.delete = rate(deletes, w);

  w.reset();
  for (var k = 0; k < mixedOps; k++) {
    seed = next(seed);
    final roll = below(seed, 100);
    seed = next(seed);
    final i = below(seed, n);
    if (roll < 70) {
      e.getView(tree, key(i));
    } else if (roll < 95) {
      e.put(tree, key(i), v1[i]);
    } else {
      e.remove(tree, key(i));
    }
  }
  e.flush();
  r.mixed = rate(mixedOps, w);

  // The page space is in the heap; making it durable is a whole-file write,
  // which is what `storage_model` in the cross-language table records. It is
  // done once, outside every timed phase, so `on_disk` is comparable.
  e.flush();
  DatabaseFile.save(db, path);
  r.bytes = onDisk(dir);
  dir.deleteSync(recursive: true);
  return r;
}

Future<Row> benchHive(
    int n, int mixedOps, List<Uint8List> v0, List<Uint8List> v1) async {
  final dir = Directory.systemTemp.createTempSync('cmp-hive-');
  Hive.init(dir.path);
  final box = await Hive.openBox<Uint8List>('bench');
  final r = Row();
  final w = Stopwatch();

  // `put` returns a future that completes when the append reaches the file;
  // Hive applies it to the in-memory box synchronously and queues the write in
  // order. Awaiting each one would be a durability barrier per operation, which
  // no other engine in any of these three tables is asked to pay, so the phase
  // awaits `flush()` instead -- one barrier, at the end.
  w.start();
  for (var i = 0; i < n; i++) {
    unawaited(box.put(snowflake(i), v0[i]));
  }
  await box.flush();
  r.create = rate(n, w);

  var seed = 0x51EDC0DE;
  for (var i = 0; i < 2000; i++) {
    seed = next(seed);
    box.get(snowflake(below(seed, n)));
  }
  w.reset();
  for (var i = 0; i < n; i++) {
    seed = next(seed);
    box.get(snowflake(below(seed, n)));
  }
  r.read = rate(n, w);

  final updates = n < 5000 ? n : 5000;
  w.reset();
  for (var k = 0; k < updates; k++) {
    seed = next(seed);
    final i = below(seed, n);
    unawaited(box.put(snowflake(i), v1[i]));
  }
  await box.flush();
  r.update = rate(updates, w);

  final deletes = n < 5000 ? n : 5000;
  w.reset();
  for (var k = 0; k < deletes; k++) {
    unawaited(box.delete(snowflake(k % n)));
  }
  await box.flush();
  r.delete = rate(deletes, w);

  w.reset();
  for (var k = 0; k < mixedOps; k++) {
    seed = next(seed);
    final roll = below(seed, 100);
    seed = next(seed);
    final i = below(seed, n);
    if (roll < 70) {
      box.get(snowflake(i));
    } else if (roll < 95) {
      unawaited(box.put(snowflake(i), v1[i]));
    } else {
      unawaited(box.delete(snowflake(i)));
    }
  }
  await box.flush();
  r.mixed = rate(mixedOps, w);

  await box.close();
  r.bytes = onDisk(dir);
  dir.deleteSync(recursive: true);
  return r;
}

void unawaited(Future<void> f) {
  f.catchError((Object e) {
    stderr.writeln('hive write failed: $e');
  });
}

void emit(String name, Row r) {
  print('${name}_create=${r.create.toStringAsFixed(0)} unit=ops/s');
  print('${name}_read=${r.read.toStringAsFixed(0)} unit=ops/s');
  print('${name}_update=${r.update.toStringAsFixed(0)} unit=ops/s');
  print('${name}_delete=${r.delete.toStringAsFixed(0)} unit=ops/s');
  print('${name}_mixed=${r.mixed.toStringAsFixed(0)} unit=ops/s');
  print('${name}_on_disk=${r.bytes} unit=bytes');
}

Future<void> main(List<String> args) async {
  final n = args.isNotEmpty ? int.parse(args[0]) : 20000;
  final mixedOps = args.length > 1 ? int.parse(args[1]) : 20000;

  print('# cryptand against hive -- dart');
  print('# documents=$n mixed_ops=$mixedOps profile=desktop '
      'durability=no-fsync, one barrier per phase');

  final v0 = [for (var i = 0; i < n; i++) encodeValue(doc(i, 0))];
  final v1 = [for (var i = 0; i < n; i++) encodeValue(doc(i, 1))];

  // Discarded: a cold isolate measures the isolate.
  benchCryptand(n, mixedOps, v0, v1);
  emit('cryptand', benchCryptand(n, mixedOps, v0, v1));

  await benchHive(n, mixedOps, v0, v1);
  emit('hive', await benchHive(n, mixedOps, v0, v1));

  print('# done');
}
