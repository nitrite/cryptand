/// The cross-language operational benchmark — see `reference/bench/README.md`.
///
/// The `p*` benchmarks beside this one measure the *design*: whether a bound
/// holds, whether a mechanism is the one doing the work. This one measures what
/// "performance claim" usually means to a person choosing a database — what the
/// implementation does per second, and what it costs on the device — and it
/// prints the same rows as the Rust and Java versions so the three can be put
/// next to each other.
///
/// `design/performance-model.md` section 8's rule governs the output: **a
/// counter is the primary result and wall time is an observation.** Page reads
/// per lookup is comparable across machines and across languages;
/// microseconds are not, and are labelled.
library;

import 'dart:io';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/catalog.dart';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/database.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/file.dart';
import 'package:cryptand/src/security.dart';
import 'package:cryptand/src/value.dart';

import 'harness.dart';

/// `counter` and `observation` are the two words the other two implementations
/// print too, so a comparison script filters on them rather than on a
/// hand-maintained list of row names.
void row(String name, Object value, String unit, {required bool primary}) {
  stdout.writeln(
      '$name=$value unit=$unit kind=${primary ? "counter" : "observation"}');
}

int percentile(List<int> xs, double p) {
  if (xs.isEmpty) return 0;
  final s = [...xs]..sort();
  return s[((s.length - 1) * p).round()];
}

String f(num v, [int d = 2]) => v.toStringAsFixed(d);

String tmpPath(String tag) {
  final d = Directory.systemTemp.createTempSync('cryptand-ops-$tag-');
  return '${d.path}/db.cryptand';
}

/// Fills a database and returns `(logical bytes, elapsed seconds, index)`.
({int logical, double secs, TreeDescriptor? index}) fill(
    Database db, int n, bool withIndex) {
  final c = db.createCollection('orders');
  final idx = withIndex ? c.createIndex(['ordStatusTxt']) : null;
  var logical = 0;
  final sw = Stopwatch()..start();
  for (var i = 0; i < n; i++) {
    final d = benchDoc(i);
    logical += encodeValue(d).length;
    c.put(CNitriteId(snowflakeId(i)), d);
  }
  db.engine.flush();
  sw.stop();
  return (
    logical: logical,
    secs: sw.elapsedMicroseconds / 1e6,
    index: idx,
  );
}

void main(List<String> args) {
  final n = args.isNotEmpty ? int.parse(args.first) : 20000;
  stdout.writeln('# cryptand ops bench -- dart');
  stdout.writeln(
      '# implementation=dart documents=$n profile=desktop durability=os');

  // ------------------------------------------------------------------
  // insert
  // ------------------------------------------------------------------
  final path = tmpPath('main');
  // `DatabaseFile.create` is the *encrypted* path (it takes a credential), so
  // the plaintext case is an in-memory database saved to a file -- which is
  // also what the Rust and Java `create` do underneath.
  final db = Database(engine: Engine(
      pageSize: Profile.desktop.pageSize,
      vlogMin: Profile.desktop.vlogMin,
      memtableEntries: 4096,
      levels: LevelPolicy.desktop));
  final r = fill(db, n, true);
  db.engine.drainCompaction();
  DatabaseFile.save(db, path);

  // **This implementation's write path differs, and the row says so rather
  // than pretending otherwise.** Dart's `Database` writes into a page store and
  // `DatabaseFile.save` puts the whole store on the device in one pass, so
  // "bytes to device during the insert" is not the same quantity the Rust and
  // Java engines report incrementally. The file size after the save is the
  // comparable number, and it is what is printed.
  final device = File(path).lengthSync();
  row('insert_docs_per_s', f(n / r.secs, 0), 'docs/s', primary: false);
  row('insert_bytes_device', device, 'bytes', primary: true);
  row('insert_logical_bytes', r.logical, 'bytes', primary: true);
  row('write_amplification', f(device / r.logical, 3), 'ratio', primary: true);

  // ------------------------------------------------------------------
  // point read -- **through the file**, and after a compaction, so it measures
  // the engine rather than the memtable or a buffer. Reading back the same
  // in-memory `Database` would report 0 page reads, which is a true statement
  // about a page list and a false one about a database.
  // ------------------------------------------------------------------
  final reopened = DatabaseFile.open(path);
  final c = reopened.collection('orders')!;
  var seed = 0x51EDC0DE;
  int next() {
    seed ^= (seed << 13) & 0x7FFFFFFF;
    seed ^= seed >> 7;
    seed ^= (seed << 17) & 0x7FFFFFFF;
    return seed & 0x7FFFFFFF;
  }

  // Warm the path: the first reads pay for a cold page cache and, on a JIT,
  // for compilation. Dart ships AOT in Flutter, so a cold-JIT number here would
  // describe a runtime nobody deploys.
  for (var i = 0; i < 200; i++) {
    c.get(CNitriteId(snowflakeId(next() % n)));
  }
  reopened.engine.store.pageReads = 0;
  final reads = n < 5000 ? n : 5000;
  final samples = <int>[];
  for (var i = 0; i < reads; i++) {
    final id = CNitriteId(snowflakeId(next() % n));
    final sw = Stopwatch()..start();
    final got = c.get(id);
    sw.stop();
    samples.add(sw.elapsedMicroseconds);
    if (got == null) throw StateError('the fixture must hold every id it reads');
  }
  final pageReads = reopened.engine.store.pageReads;
  row('point_read_us_p50', percentile(samples, 0.50), 'us', primary: false);
  row('point_read_us_p99', percentile(samples, 0.99), 'us', primary: false);
  row('point_read_page_reads', f(pageReads / reads, 3), 'pages/lookup',
      primary: true);

  // ------------------------------------------------------------------
  // scan
  // ------------------------------------------------------------------
  reopened.engine.store.pageReads = 0;
  final sw = Stopwatch()..start();
  final rows = c.all.length;
  sw.stop();
  final scanPages = reopened.engine.store.pageReads;
  if (rows != n) throw StateError('the scan must return every document');
  row('scan_rows_per_s', f(rows / (sw.elapsedMicroseconds / 1e6), 0), 'rows/s',
      primary: false);
  row('scan_page_reads_per_row', f(scanPages / rows, 4), 'pages/row',
      primary: true);

  // ------------------------------------------------------------------
  // index lookup
  // ------------------------------------------------------------------
  final idxOnFile = reopened.catalog
      .indexesOf('orders')
      .map((e) => e.$2)
      .firstWhere((d) => d.kind == TreeKind.index);
  if (r.index != null) {
    final s = <int>[];
    final probes = n < 2000 ? n : 2000;
    for (var i = 0; i < probes; i++) {
      final key = benchDoc(i).fields['ordStatusTxt']!;
      final range = KeyRange.prefix(Keys.prefixOfArray([key]));
      final t = Stopwatch()..start();
      c.lookup(idxOnFile, range).toList();
      t.stop();
      s.add(t.elapsedMicroseconds);
    }
    row('index_lookup_us_p50', percentile(s, 0.50), 'us', primary: false);
  }
  final bytesOff = File(path).lengthSync();

  // ------------------------------------------------------------------
  // the codec -- and the row is here because it measures ZERO, which is why
  // `page_codec` is 0 in every profile now. `01-container.md` section 7
  // carries the reasoning: a page is a fixed-size slot, so a compressed page
  // occupies the same slot and is written with the same page_size-byte write.
  // The row stays so that a container shape which *does* make it pay shows up
  // here rather than in an argument.
  // ------------------------------------------------------------------
  final path2 = tmpPath('codec');
  final db2 = Database(engine: Engine(
      pageSize: Profile.desktop.pageSize,
      vlogMin: Profile.desktop.vlogMin,
      memtableEntries: 4096,
      levels: LevelPolicy.desktop));
  db2.engine.store.pageCodec = Codec.lz4;
  fill(db2, n, true);
  db2.engine.drainCompaction();
  DatabaseFile.save(db2, path2);
  final bytesOn = File(path2).lengthSync();
  row('codec_bytes_on', bytesOn, 'bytes', primary: true);
  row('codec_bytes_off', bytesOff, 'bytes', primary: true);
  row('codec_saving', f(1 - bytesOn / bytesOff, 4), 'ratio', primary: true);

  // ------------------------------------------------------------------
  // the cipher, on the write path -- P11
  // ------------------------------------------------------------------
  final path3 = tmpPath('enc');
  final key = List<int>.filled(32, 7);
  final db3 = DatabaseFile.create(path3,
      credential: key, kdf: Keyslot.kdfRaw, profile: Profile.desktop);
  final enc = fill(db3, n, true);
  DatabaseFile.save(db3, path3);
  row('cipher_write_ratio', f(enc.secs / r.secs, 3), 'ratio', primary: false);

  stdout.writeln('# done');
}
