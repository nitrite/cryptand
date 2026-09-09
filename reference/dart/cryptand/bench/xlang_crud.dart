/// The CRUD matrix at the **engine** level, in the one shape all three
/// implementations can run — the like-for-like cross-language number that
/// `bench/crud.dart` does not give, because that one drives a `Collection`
/// and builds and encodes a document inside the timed loop.
///
/// Java's `org.dizitart.cryptand.bench.XlangCrudBench` carries the full
/// statement of what is and is not held identical. The short version: the
/// document, the key, the profile, the durability, the phase sizes and the
/// pseudo-random sequence are the same bit for bit, and the **storage model is
/// not**.
///
/// This implementation's is `in-memory page space`: [PageStore] is a list of
/// pages in the heap, a file is read whole on open and written whole on save,
/// and **nothing reaches a disk during a run**. That is the largest term in any
/// gap between these numbers and another language's, so it is printed as
/// `storage_model` rather than left to be discovered.
///
/// The consequence for the rows: `*_ops_per_s` measures engine work up to the
/// segment build, which is the part all three actually do, and making the
/// result durable is measured once and separately as `persist_ms` — which here
/// is a whole-file write and in the other two is not. Averaging that into a
/// per-operation figure would hide exactly the thing worth seeing.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/database.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/file.dart';
import 'package:cryptand/src/value.dart';

import 'harness.dart';

const int tree = 16;

/// The same document as [benchDoc], with a revision digit so an update writes
/// different bytes — matching the other two implementations.
CDoc doc(int i, int rev) {
  final pad = i.toString().padLeft(6, '0');
  String v(String prefix) => '$prefix-$pad-${rev % 10}'.padRight(19, 'y');
  return CDoc({
    '_id': CNitriteId(snowflakeId(i)),
    'custAddr1_ln': CStr(v('addr1')),
    'custAddr2_ln': CStr(v('addr2')),
    'custCityName': CStr(v('city')),
    'custPostCode': CStr(v('post')),
    'custCountryX': CStr(v('ctry')),
    'custEmailAdr': CStr(v('mail')),
    'custPhoneNum': CStr(v('phon')),
    'ordReference': CStr(v('ordr')),
    'ordStatusTxt': CStr(v('stat')),
    'ordCurrencyC': CStr(v('curr')),
    'ordNotesText': CStr(v('note')),
    'whseLocation': CStr(v('whse')),
    'carrierName_': CStr(v('carr')),
    'trackingNumb': CStr(v('trak')),
    'ordTotMinorU': CInt.varInt(1299 + i),
    'ordTaxMinorU': CInt.varInt(216),
    'ordShipMinor': CInt.varInt(499),
    'placedAtUtcM': const CTimestamp(1767225000000),
    'dispatchUtcM': const CTimestamp(1767225600000),
  });
}

/// xorshift64, and a reduction chosen so that a signed `%` and an unsigned one
/// cannot disagree. `>>>` is the unsigned shift, and it is what makes this
/// identical to Java's `long` and Rust's `u64`.
int next(int s) {
  s ^= (s << 13);
  s ^= (s >>> 7);
  s ^= (s << 17);
  return s;
}

int below(int seed, int n) => (seed >>> 32) % n;

bool measuring = true;

void row(String name, Object value, String unit) {
  if (measuring) stdout.writeln('$name=$value unit=$unit');
}

void ops(String phase, int count, double secs) {
  row('${phase}_ops_per_s',
      (count / (secs < 1e-9 ? 1e-9 : secs)).toStringAsFixed(0), 'ops/s');
}

void pass(int n, int mixedOps, List<Uint8List> v0, List<Uint8List> v1) {
  final dir = Directory.systemTemp.createTempSync('xlang-dart-');
  final path = '${dir.path}/db.cryptand';
  final db = Database(
      engine: Engine(
    pageSize: Profile.desktop.pageSize,
    vlogMin: Profile.desktop.vlogMin,
    memtableEntries: 4096,
    levels: LevelPolicy.desktop,
  ));
  final e = db.engine;
  CValue key(int i) => CNitriteId(snowflakeId(i));

  var sw = Stopwatch()..start();
  for (var i = 0; i < n; i++) {
    e.put(tree, key(i), v0[i]);
  }
  e.flush();
  sw.stop();
  ops('create', n, sw.elapsedMicroseconds / 1e6);

  e.compact();

  var seed = 0x51EDC0DE;
  for (var i = 0; i < 2000; i++) {
    seed = next(seed);
    e.get(tree, key(below(seed, n)));
  }
  final reads = n < 5000 ? n : 5000;
  sw = Stopwatch()..start();
  for (var i = 0; i < reads; i++) {
    seed = next(seed);
    e.get(tree, key(below(seed, n)));
  }
  sw.stop();
  ops('read', reads, sw.elapsedMicroseconds / 1e6);

  final updates = n < 5000 ? n : 5000;
  sw = Stopwatch()..start();
  for (var k = 0; k < updates; k++) {
    seed = next(seed);
    final i = below(seed, n);
    e.put(tree, key(i), v1[i]);
  }
  e.flush();
  sw.stop();
  ops('update', updates, sw.elapsedMicroseconds / 1e6);

  final deletes = n < 5000 ? n : 5000;
  sw = Stopwatch()..start();
  for (var k = 0; k < deletes; k++) {
    e.remove(tree, key(k % n));
  }
  e.flush();
  sw.stop();
  ops('delete', deletes, sw.elapsedMicroseconds / 1e6);

  sw = Stopwatch()..start();
  for (var k = 0; k < mixedOps; k++) {
    seed = next(seed);
    final roll = below(seed, 100);
    seed = next(seed);
    final i = below(seed, n);
    if (roll < 70) {
      e.get(tree, key(i));
    } else if (roll < 95) {
      e.put(tree, key(i), v1[i]);
    } else {
      e.remove(tree, key(i));
    }
  }
  e.flush();
  sw.stop();
  ops('mixed', mixedOps, sw.elapsedMicroseconds / 1e6);

  // Making it durable, once. In this implementation that is the whole page
  // space, because the page space is in the heap.
  final psw = Stopwatch()..start();
  e.flush();
  DatabaseFile.save(db, path);
  psw.stop();

  row('persist_ms', (psw.elapsedMicroseconds / 1e3).toStringAsFixed(1), 'ms');
  row('file_bytes', File(path).lengthSync(), 'bytes');
  row('storage_model', 'in-memory page space', 'text');
  dir.deleteSync(recursive: true);
}

void main(List<String> args) {
  final n = args.isNotEmpty ? int.parse(args.first) : 20000;
  final mixedOps = args.length > 1 ? int.parse(args[1]) : 20000;

  stdout.writeln('# cryptand cross-language CRUD matrix -- dart');
  stdout.writeln('# implementation=dart documents=$n mixed_ops=$mixedOps '
      'profile=desktop durability=os');
  stdout.writeln('# the first pass is discarded; see the library docs for what '
      'is and is not held identical');

  final v0 = <Uint8List>[];
  final v1 = <Uint8List>[];
  for (var i = 0; i < n; i++) {
    v0.add(encodeValue(doc(i, 0)));
    v1.add(encodeValue(doc(i, 1)));
  }

  for (var p = 0; p < 2; p++) {
    measuring = p == 1;
    pass(n, mixedOps, v0, v1);
  }
  stdout.writeln('# done');
}
