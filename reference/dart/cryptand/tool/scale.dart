/// M6 Dart rung (PLAN 6.2) and the M5.5 RSS check. Each phase prints one
/// JSON metrics line.
///
/// ```
/// dart compile exe tool/scale.dart -o scale
/// ./scale build PATH N   # load, commit per 100k
/// ./scale settle PATH N  # compact + commit + shrink, file size (F-154)
/// ./scale read PATH N    # fresh process: cold open, gets, scan, verify
/// ./scale index PATH N   # PLAN 6.5: unique + compound index build, probes, analyze, verify
/// ./scale text PATH N    # PLAN 6.5: full-text index build, searches, verify
/// ./scale spatial PATH N # PLAN 6.5: R-tree build, near/nearestK vs brute force, verify
/// ./scale vector PATH N  # PLAN 6.5: 128-d Vamana build, recall@10 vs brute force, verify
/// ```
///
/// `read` ends with PASS/FAIL against PLAN 6.3's RSS bar (cache + 256 MB). Run
/// AOT: under `dart run` the JIT alone peaks near 265 MB.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';

import '../bench/harness.dart';

CValue id(int i) => CNitriteId(snowflakeId(i));

/// `CRYPTAND_ENC=1`: encrypted file, fixed raw key (kdf 0), as Rust `rss_scale`.
/// ponytail: fixed bench key, never a real secret.
final List<int>? key =
    Platform.environment.containsKey('CRYPTAND_ENC') ? List.filled(32, 7) : null;

/// `CRYPTAND_PROFILE=mobile` (any `Profile` name): the profile `build` creates
/// the file with; `read` takes it from the file, and the bar from this.
final Profile profile =
    Profile.values.byName(Platform.environment['CRYPTAND_PROFILE'] ?? 'desktop');

void main(List<String> args) {
  final path = args[1];
  final n = int.parse(args[2]);
  final out = <String, Object>{
    'impl': 'dart',
    'phase': args[0],
    'n': n,
    'profile': profile.name
  };
  final sw = Stopwatch()..start();
  if (args[0] == 'build') {
    if (key == null) {
      DatabaseFile.save(
          Database(
              engine: Engine(
                  pageSize: profile.pageSize,
                  vlogSegmentBytes: profile.vlogSegmentBytes)
                ..setProfile(profile))
            ..createCollection('c'),
          path);
    } else {
      DatabaseFile.create(path,
          credential: key!, kdf: Keyslot.kdfRaw, profile: profile)
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

  if (args[0] == 'index') {
    indexRung(path, n, out, sw);
    return;
  }
  if (args[0] == 'text') {
    textRung(path, n, out, sw);
    return;
  }
  if (args[0] == 'spatial') {
    spatialRung(path, n, out, sw);
    return;
  }
  if (args[0] == 'vector') {
    vectorRung(path, n, out, sw);
    return;
  }
  if (args[0] == 'patho') {
    pathoRung(path, n, args.length > 3 ? args[3] : null);
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
  final budget = (profile.pageCacheBytes >> 20) + 256;
  out
    ..['max_rss_mb'] = rss
    ..['budget_mb'] = budget
    ..['pass'] = rss <= budget && missing == 0 && sound;
  stdout.writeln(jsonEncode(out));
}

/// PLAN 6.5, Rust `rss_scale PATH N index`: a unique index on `ordReference`
/// and a compound one on (`custCityName` over 1000 cities, `ordTotMinorU`).
/// ponytail: plaintext only; CRYPTAND_ENC is ignored here.
void indexRung(String path, int n, Map<String, Object> out, Stopwatch sw) {
  CStr city(int i) => CStr('city-${(i % 1000).toString().padLeft(3, '0')}');
  int rss() => ProcessInfo.currentRss >> 20;
  if (File(path).existsSync()) File(path).deleteSync();
  DatabaseFile.save(
      Database(
          engine: Engine(
              pageSize: profile.pageSize,
              vlogSegmentBytes: profile.vlogSegmentBytes)
            ..setProfile(profile))
        ..createCollection('c'),
      path);
  final db = DatabaseFile.open(path);
  final c = db.collection('c')!;
  final uq = c.createIndex(['ordReference'], indexType: IndexType.unique);
  final cx = c.createIndex(['custCityName', 'ordTotMinorU']);
  var peak = 0;
  for (var i = 0; i < n; i++) {
    c.put(id(i), CDoc({...benchDoc(i).fields, 'custCityName': city(i)}));
    if ((i + 1) % 100000 == 0 || i + 1 == n) {
      db.engine.commit();
      peak = math.max(peak, rss());
    }
  }
  out
    ..['build_s'] = sw.elapsed.inSeconds
    ..['file_bytes'] = File(path).lengthSync()
    ..['rss_build_mb'] = peak;
  var s = 0x51EDC0DE;
  final us = <int>[];
  for (var k = 0; k < 10000; k++) {
    s = s * 6364136223846793005 + 1442695040888963407;
    final i = (s >>> 11) % n;
    final v = benchDoc(i)['ordReference']!;
    final t = Stopwatch()..start();
    if (c.lookup(uq, IndexScan.eqPrefix([v])).length != 1) {
      throw StateError('unique probe $i');
    }
    us.add(t.elapsedMicroseconds);
  }
  us.sort();
  var t = Stopwatch()..start();
  out
    ..['unique_us_p50'] = us[5000]
    ..['unique_us_p99'] = us[9900]
    ..['compound_rows'] = c.lookup(cx, IndexScan.eqPrefix([city(7)])).length
    ..['compound_ms'] = t.elapsedMilliseconds
    ..['rss_probe_mb'] = rss();
  t = Stopwatch()..start();
  final st = c.analyze(cx);
  out
    ..['analyze_ms'] = t.elapsedMilliseconds
    ..['rss_analyze_mb'] = rss()
    ..['entries'] = st.entries
    ..['distinct'] = st.distinctEstimate
    ..['nulls'] = st.nullCount
    ..['buckets'] = st.histogram.length;
  t = Stopwatch()..start();
  out
    ..['verify_sound'] =
        db.engine.verifyStructure(claims: db.indexClaims()).isSound
    ..['verify_ms'] = t.elapsedMilliseconds
    ..['rss_verify_mb'] = rss();
  db.engine.close();
  stdout.writeln(jsonEncode(out));
}

/// PLAN 6.5 full text: word [k] of document [i], from 26^3 three-letter
/// words; same as Java `RssScale.word`.
String word(int i, int k) {
  var z = i * 8 + k + 0x9E3779B97F4A7C15;
  z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
  z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
  z ^= z >>> 31;
  // Unsigned remainder of a 64-bit value.
  final w = ((z >>> 1) % 17576 * 2 + (z & 1)) % 17576;
  return String.fromCharCodes(
      [97 + w ~/ 676, 97 + w ~/ 26 % 26, 97 + w % 26]);
}

/// PLAN 6.5, Java `RssScale PATH N text`: a full-text index on
/// `ordNotesText`, 8 words per document. ponytail: plaintext only.
void textRung(String path, int n, Map<String, Object> out, Stopwatch sw) {
  int rss() => ProcessInfo.currentRss >> 20;
  if (File(path).existsSync()) File(path).deleteSync();
  DatabaseFile.save(
      Database(
          engine: Engine(
              pageSize: profile.pageSize,
              vlogSegmentBytes: profile.vlogSegmentBytes)
            ..setProfile(profile))
        ..createCollection('c'),
      path);
  final db = DatabaseFile.open(path);
  final c = db.collection('c')!;
  final ft = c.createFullTextIndex(['ordNotesText'],
      analyzer: Analyzer(stopwords: const []));
  var peak = 0;
  for (var i = 0; i < n; i++) {
    final notes = [for (var k = 0; k < 8; k++) word(i, k)].join(' ');
    c.put(id(i), CDoc({...benchDoc(i).fields, 'ordNotesText': CStr(notes)}));
    if ((i + 1) % 100000 == 0 || i + 1 == n) {
      db.engine.commit();
      peak = math.max(peak, rss());
      stderr.writeln('${i + 1} t=${sw.elapsed.inSeconds} rss_mb=${rss()}');
    }
  }
  out
    ..['build_s'] = sw.elapsed.inSeconds
    ..['file_bytes'] = File(path).lengthSync()
    ..['rss_build_mb'] = peak;
  var s = 0x51EDC0DE;
  final us = <int>[];
  var rows = 0;
  for (var k = 0; k < 1000; k++) {
    s = s * 6364136223846793005 + 1442695040888963407;
    final i = (s >>> 11) % n;
    final t = Stopwatch()..start();
    final hits = c.fullTextSearch(ft, '${word(i, 0)} ${word(i, 1)}').length;
    us.add(t.elapsedMicroseconds);
    if (hits < 1) throw StateError('text probe $i');
    rows += hits;
  }
  us.sort();
  // One term against brute force: df, and the search's set size.
  final q = word(n ~/ 2, 3);
  var df = 0;
  for (var i = 0; i < n; i++) {
    for (var k = 0; k < 8; k++) {
      if (word(i, k) == q) {
        df++;
        break;
      }
    }
  }
  final t = Stopwatch()..start();
  final got = c.fullTextSearch(ft, q).length;
  out
    ..['and2_us_p50'] = us[500]
    ..['and2_us_p99'] = us[990]
    ..['and2_rows'] = rows
    ..['term_ms'] = t.elapsedMilliseconds
    ..['term_rows'] = got
    ..['brute_df'] = df
    ..['dict_df'] = c.termEntry(ft, q)!.df
    ..['rss_probe_mb'] = rss();
  if (got != df || c.termEntry(ft, q)!.df != df) throw StateError('df $q');
  final v = Stopwatch()..start();
  out
    ..['verify_sound'] =
        db.engine.verifyStructure(claims: db.indexClaims()).isSound
    ..['verify_ms'] = v.elapsedMilliseconds
    ..['rss_verify_mb'] = rss();
  db.engine.close();
  stdout.writeln(jsonEncode(out));
}

Database _freshFile(String path) {
  if (File(path).existsSync()) File(path).deleteSync();
  DatabaseFile.save(
      Database(
          engine: Engine(
              pageSize: profile.pageSize,
              vlogSegmentBytes: profile.vlogSegmentBytes)
            ..setProfile(profile)),
      path);
  return DatabaseFile.open(path);
}

/// PLAN 6.5 spatial, as Java `RssScale.xy`: point of document i in [0, 1000)^2.
(double, double) xy(int i) {
  var z = i * 0x9E3779B97F4A7C15 + 0x51EDC0DE;
  z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
  z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
  z ^= z >>> 31;
  return ((z >>> 40) * 1000.0 / (1 << 24), (z & 0xFFFFFF) * 1000.0 / (1 << 24));
}

/// PLAN 6.5, as Java `spatialRung`: a spatial index on point field `loc`;
/// near and nearestK checked against brute force. ponytail: plaintext only.
void spatialRung(String path, int n, Map<String, Object> out, Stopwatch sw) {
  int rss() => ProcessInfo.currentRss >> 20;
  final db = _freshFile(path);
  final c = db.createCollection('c');
  final sp = c.createSpatialIndex('loc');
  var peak = 0;
  for (var i = 0; i < n; i++) {
    final (x, y) = xy(i);
    c.put(id(i), CDoc({...benchDoc(i).fields, 'loc': CGeometry(encodeWkb(Geometry(
        type: GeometryType.point, hasZ: false, hasM: false, coords: [Coord(x, y)])))}));
    if ((i + 1) % 100000 == 0 || i + 1 == n) {
      db.engine.commit();
      peak = math.max(peak, rss());
      stderr.writeln('${i + 1} t=${sw.elapsed.inSeconds} rss_mb=${rss()}');
    }
  }
  out
    ..['build_s'] = sw.elapsed.inSeconds
    ..['file_bytes'] = File(path).lengthSync()
    ..['rss_build_mb'] = peak;
  var s = 0x51EDC0DE;
  final us = <int>[], kus = <int>[];
  var rows = 0;
  for (var k = 0; k < 1000; k++) {
    s = s * 6364136223846793005 + 1442695040888963407;
    final (x, y) = xy((s >>> 11) % n);
    var t = Stopwatch()..start();
    final hits = sp.near(Coord(x, y), 1).length;
    us.add(t.elapsedMicroseconds);
    if (hits < 1) throw StateError('near probe $k');
    rows += hits;
    t = Stopwatch()..start();
    if (sp.nearestK(Coord(x, y), 10).length != math.min(10, n)) throw StateError('knn probe $k');
    kus.add(t.elapsedMicroseconds);
  }
  us.sort();
  kus.sort();
  const qx = 500.5, qy = 499.5;
  var brute = 0;
  final best = <double>[];
  for (var i = 0; i < n; i++) {
    final (x, y) = xy(i);
    final d = math.sqrt((x - qx) * (x - qx) + (y - qy) * (y - qy));
    if (d <= 1) brute++;
    if (best.length < 10 || d < best.last) {
      best
        ..add(d)
        ..sort();
      if (best.length > 10) best.removeLast();
    }
  }
  final got = sp.near(const Coord(qx, qy), 1).length;
  final knn = sp.nearestK(const Coord(qx, qy), 10);
  final ring = sp.near(const Coord(qx, qy), best[math.min(10, n) - 1]).toSet();
  final knnOk = knn.length == math.min(10, n) && knn.every((h) => ring.contains(h.$1));
  out
    ..['near_us_p50'] = us[500]
    ..['near_us_p99'] = us[990]
    ..['near_rows'] = rows
    ..['knn10_us_p50'] = kus[500]
    ..['knn10_us_p99'] = kus[990]
    ..['near_rows_q'] = got
    ..['brute_near'] = brute
    ..['knn_ok'] = knnOk
    ..['rss_probe_mb'] = rss();
  if (got != brute || !knnOk) throw StateError('brute force: $out');
  final t = Stopwatch()..start();
  out
    ..['verify_sound'] = db.engine.verifyStructure(claims: db.indexClaims()).isSound
    ..['verify_ms'] = t.elapsedMilliseconds
    ..['rss_verify_mb'] = rss();
  db.engine.close();
  stdout.writeln(jsonEncode(out));
}

double _unit(int x) {
  var z = x + 0x9E3779B97F4A7C15;
  z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
  z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
  return ((z ^ (z >>> 31)) >>> 11) / (1 << 53).toDouble();
}

/// PLAN 6.5 vectors, as Java `RssScale.vec`: 128-d around one of 1000 centres.
List<double> vec128(int i) {
  final c = i % 1000;
  return [
    for (var k = 0; k < 128; k++)
      _unit(c * 128 + k) + 0.15 * (_unit((i + 1) * 0x2545F4914F6CDD1D + k) - 0.5)
  ];
}

/// PLAN 6.5, as Java `vectorRung`: a 128-d l2 vector index; 100 searches,
/// recall@10 against brute force. ponytail: plaintext only.
void vectorRung(String path, int n, Map<String, Object> out, Stopwatch sw) {
  int rss() => ProcessInfo.currentRss >> 20;
  final db = _freshFile(path);
  final c = db.createCollection('c');
  final vx = c.createVectorIndex('emb', dim: 128, initialSlots: 1024);
  var peak = 0;
  for (var i = 0; i < n; i++) {
    c.put(id(i), CDoc({...benchDoc(i).fields, 'emb': CVector.f32(vec128(i))}));
    if ((i + 1) % 100000 == 0 || i + 1 == n) {
      db.engine.commit();
      peak = math.max(peak, rss());
      stderr.writeln('${i + 1} t=${sw.elapsed.inSeconds} rss_mb=${rss()}');
    } else if ((i + 1) % 10000 == 0) {
      stderr.writeln('${i + 1} t=${sw.elapsed.inSeconds}');
    }
  }
  out
    ..['build_s'] = sw.elapsed.inSeconds
    ..['file_bytes'] = File(path).lengthSync()
    ..['rss_build_mb'] = peak;
  const queries = 100;
  final q = [for (var k = 0; k < queries; k++) vec128(n + 7919 * k)];
  final us = <int>[];
  final got = <Set<int>>[];
  for (final qk in q) {
    final t = Stopwatch()..start();
    got.add({for (final h in vx.search(qk, 10)) h.$1});
    us.add(t.elapsedMicroseconds);
  }
  us.sort();
  // The region holds f32: brute force ranks the vectors as stored.
  final best = List.generate(queries, (_) => <(double, int)>[]);
  for (var i = 0; i < n; i++) {
    final v = CVector.f32(vec128(i)).f32Values!;
    final docId = (id(i) as CNitriteId).id;
    for (var k = 0; k < queries; k++) {
      final d = vectorDistance(q[k], v, VectorMetric.l2);
      final b = best[k];
      if (b.length < 10 || d < b.last.$1) {
        b
          ..add((d, docId))
          ..sort((x, y) => x.$1.compareTo(y.$1));
        if (b.length > 10) b.removeLast();
      }
    }
  }
  var hit = 0;
  for (var k = 0; k < queries; k++) {
    for (final (_, d) in best[k]) {
      if (got[k].contains(d)) hit++;
    }
  }
  out
    ..['search_us_p50'] = us[queries ~/ 2]
    ..['search_us_p99'] = us[queries * 99 ~/ 100]
    ..['recall10'] = double.parse((hit / (queries * 10)).toStringAsFixed(3))
    ..['fallbacks'] = vx.fallbacks
    ..['rss_probe_mb'] = rss();
  final t = Stopwatch()..start();
  out
    ..['verify_sound'] = db.engine.verifyStructure(claims: db.indexClaims()).isSound
    ..['verify_ms'] = t.elapsedMilliseconds
    ..['rss_verify_mb'] = rss();
  db.engine.close();
  stdout.writeln(jsonEncode(out));
}

/// PLAN 6.6, Rust `rss_scale PATH N patho [WORKLOAD]`: same workloads,
/// checks and output line.
void pathoRung(String path, int n, String? only) {
  const t = 16;
  CValue nid(int i) => CNitriteId(i);
  CValue pre(int i) =>
      CStr('${'shared/prefix/' * 16}${i.toString().padLeft(12, '0')}');
  Uint8List val(int i) => Uint8List(100)..fillRange(0, 100, i % 251);
  bool same(Uint8List? a, Uint8List b) =>
      a != null && a.length == b.length && a[0] == b[0] && a.last == b.last;
  for (final w in const [
    'mono',
    'prefix',
    'bigdoc',
    'fields',
    'colls',
    'tombstone',
    'rangedel',
    'ttl'
  ]) {
    if (only != null && only != w) continue;
    final p = '$path.$w';
    var db = _freshFile(p);
    var e = db.engine;
    final sw = Stopwatch()..start();
    final extra = <String, Object>{};
    void every(int i) {
      if ((i + 1) % 100000 == 0) e.commit();
    }

    switch (w) {
      case 'mono' || 'tombstone':
        for (var i = 0; i < n; i++) {
          e.put(t, nid(i), val(i));
          every(i);
        }
        if (w == 'tombstone') {
          for (var i = 0; i < n; i++) {
            e.remove(t, nid(i));
            every(i);
          }
          e.commit();
          extra['bytes_deleted'] = File(p).lengthSync();
          for (var i = 0; i < n; i++) {
            e.put(t, nid(i), val(i + 1));
            every(i);
          }
        }
      case 'prefix':
        for (var i = 0; i < n; i++) {
          e.put(t, pre(i), val(i));
          every(i);
        }
      case 'bigdoc':
        for (var i = 0; i < 64; i++) {
          e.put(
              t, nid(i), Uint8List(16 << 20)..fillRange(0, 16 << 20, i % 251));
          e.commit();
        }
      case 'fields':
        final c = db.createCollection('c');
        for (var i = 0; i < 100000; i++) {
          c.put(
              nid(i + 1),
              CDoc({
                for (var k = 0; k < 10; k++)
                  'f${i * 10 + k}': CInt.of(NumType.i64, i)
              }));
          if ((i + 1) % 10000 == 0) e.commit();
        }
      case 'colls':
        for (var i = 0; i < 100000; i++) {
          db.createCollection('c$i').put(nid(i + 1), CDoc({}));
          if ((i + 1) % 10000 == 0) e.commit();
        }
      case 'rangedel':
        for (var i = 0; i < n; i++) {
          e.put(t, nid(i), val(i));
          every(i);
        }
        e.commit();
        final spans = n ~/ 100;
        for (var j = 0; j < spans; j++) {
          final s = (j * 7919) % spans;
          e.removeRange(t, nid(s * 100), nid(s * 100 + 100));
          if ((j + 1) % 1000 == 0) e.commit();
        }
      default:
        final at = DateTime.now().millisecondsSinceEpoch + 2000;
        for (var i = 0; i < n; i++) {
          e.put(t, nid(i), val(i), expiryMs: at);
          every(i);
        }
        e.commit();
        final wait = at + 100 - DateTime.now().millisecondsSinceEpoch;
        if (wait > 0) sleep(Duration(milliseconds: wait));
    }
    e.commit();
    final buildS = sw.elapsedMilliseconds / 1000;
    e
      ..drainCompaction()
      ..commit()
      ..close();
    db = DatabaseFile.open(p);
    e = db.engine;
    var bad = 0;
    final k = w == 'fields'
        ? 100000
        : w == 'bigdoc'
            ? 64
            : n;
    final step = w == 'bigdoc' ? 1 : math.max(1, k ~/ 1000);
    for (var i = 0; i < k && w != 'colls'; i += step) {
      final ok = switch (w) {
        'mono' => same(e.get(t, nid(i)), val(i)),
        'tombstone' => same(e.get(t, nid(i)), val(i + 1)),
        'prefix' => same(e.get(t, pre(i)), val(i)),
        'bigdoc' => (e.get(t, nid(i))?.length ?? 0) == 16 << 20 &&
            e.get(t, nid(i))![0] == i % 251,
        'fields' =>
          db.collection('c')!.get(nid(i + 1))?.fields['f${i * 10 + 9}'] ==
              CInt.of(NumType.i64, i),
        _ => e.get(t, nid(i)) == null,
      };
      if (!ok) bad++;
    }
    if (w == 'colls') {
      final names = db.catalog.collections.length;
      extra['collections'] = names;
      if (names != 100000) bad++;
    }
    if (w == 'rangedel' || w == 'ttl') {
      extra['scan_rows'] = e.scanTree(t).length;
    }
    final rss = ProcessInfo.currentRss >> 20;
    final sound = e.verifyStructure(claims: db.indexClaims()).isSound;
    stdout.writeln(jsonEncode({
      'impl': 'dart',
      'workload': w,
      'n': n,
      'build_s': buildS,
      'bytes': File(p).lengthSync(),
      'bad': bad,
      'verify_sound': sound,
      'rss_mb': rss,
      ...extra,
    }));
    e.close();
    File(p).deleteSync();
  }
}
