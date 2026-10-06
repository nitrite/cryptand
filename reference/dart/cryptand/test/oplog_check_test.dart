/// Model checker (PLAN M1.2), the Dart port of Rust's `oplog_check`:
/// replays an op-log (`reference/conformance/oplog/`) against [Engine] and a
/// sorted map, comparing every read and the full-scan digest at the end and
/// after every `reopen`.
///
/// Replays `regress/*.jsonl`, and every `*.jsonl` in `$OPLOG_DIR` when set
/// (ponytail: no Dart generator, Rust's `oplog_gen` is the one source of logs).
library;

import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

final _key = List<int>.filled(32, 7);

int _memcmp(List<int> a, List<int> b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/// SplitMix64 bytes, little-endian, as `oplog/README.md` defines `{n, s}`.
Uint8List valueBytes(int n, int seed) {
  final out = Uint8List(n + 8);
  final bd = ByteData.sublistView(out);
  var state = BigInt.from(seed);
  final mask = (BigInt.one << 64) - BigInt.one;
  for (var o = 0; o < n; o += 8) {
    state = (state + BigInt.parse('9E3779B97F4A7C15', radix: 16)) & mask;
    var z = state;
    z = ((z ^ (z >> 30)) * BigInt.parse('BF58476D1CE4E5B9', radix: 16)) & mask;
    z = ((z ^ (z >> 27)) * BigInt.parse('94D049BB133111EB', radix: 16)) & mask;
    z = z ^ (z >> 31);
    bd.setUint64(o, z.toSigned(64).toInt(), Endian.little);
  }
  return Uint8List.sublistView(out, 0, n);
}

Uint8List _unhex(String s) => Uint8List.fromList(
    [for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);
String _hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
String _short(List<int>? v) => v == null
    ? 'absent'
    : '${v.length} bytes ${_hex(v.take(8).toList())}…';

class Diverged implements Exception {
  Diverged(this.message);
  final String message;
  @override
  String toString() => message;
}

typedef Cell = ({Uint8List v, int x});
typedef Tree = SplayTreeMap<Uint8List, Cell>;
typedef Model = Map<int, Tree>;

Model _copy(Model m) => {for (final e in m.entries) e.key: Tree.of(e.value, _memcmp)};

class _Run {
  _Run(this.path, this.encrypted, this.profile, this.trees);
  final String path;
  final bool encrypted;
  final Profile profile;
  final int trees;
  late Database db;
  Engine get e => db.engine;
  Model model = {};
  /// Model after each write, keyed by the engine's last seq: what a snapshot
  /// at that seq sees (a snapshot reads at `visibleSeq`).
  final history = SplayTreeMap<int, Model>();
  final snaps = <int, Snapshot>{};
  final snapModels = <int, Model>{};
  int clock = 0;

  Tree tree(int t) => model.putIfAbsent(t, () => Tree(_memcmp));

  void create() {
    if (encrypted) {
      db = DatabaseFile.create(path, credential: _key, kdf: Keyslot.kdfRaw, profile: profile);
    } else {
      db = Database(
          engine: Engine(
              pageSize: profile.pageSize,
              vlogMin: profile.vlogMin,
              vlogSegmentBytes: profile.vlogSegmentBytes)
            ..setProfile(profile));
    }
    e.nowMs = clock;
  }

  void record() => history[e.nextSeq - 1] = _copy(model);

  List<(Uint8List, Uint8List)> modelScan(Model m, int t, Uint8List? lo, Uint8List? hi) => [
        for (final en in (m[t] ?? Tree(_memcmp)).entries)
          if ((lo == null || _memcmp(en.key, lo) >= 0) &&
              (hi == null || _memcmp(en.key, hi) < 0) &&
              (en.value.x == 0 || en.value.x > clock))
            (en.key, en.value.v)
      ];

  List<(Uint8List, Uint8List)> engineScan(int t, Uint8List? lo, Uint8List? hi, Snapshot? s) {
    final range = lo == null && hi == null
        ? null
        : KeyRange(lo == null ? Uint8List(0) : encodeKey(CBytes(lo)),
            hi == null ? null : encodeKey(CBytes(hi)));
    return [
      for (final r in e.scanTree(t, range: range, at: s))
        ((decodeKey(Uint8List.fromList(r.cke)) as CBytes).value, r.value)
    ];
  }

  void compareScan(int t, List<(Uint8List, Uint8List)> want, List<(Uint8List, Uint8List)> got) {
    final n = want.length < got.length ? want.length : got.length;
    var i = 0;
    while (i < n && _memcmp(want[i].$1, got[i].$1) == 0 && _memcmp(want[i].$2, got[i].$2) == 0) {
      i++;
    }
    if (i == n && want.length == got.length) return;
    String row(List<(Uint8List, Uint8List)> rows) =>
        i < rows.length ? 'k=${_hex(rows[i].$1)} ${_short(rows[i].$2)}' : 'end';
    throw Diverged('scan t=$t: model ${want.length} rows, engine ${got.length} rows; '
        'first difference at row $i: model ${row(want)} engine ${row(got)}');
  }

  String digestCheck() {
    final b = BytesBuilder();
    for (var t = 1; t <= trees; t++) {
      final got = engineScan(t, null, null, null);
      compareScan(t, modelScan(model, t, null, null), got);
      for (final (k, v) in got) {
        b
          ..add((ByteData(8)..setUint32(0, t)..setUint32(4, k.length)).buffer.asUint8List())
          ..add(k)
          ..add((ByteData(4)..setUint32(0, v.length)).buffer.asUint8List())
          ..add(v);
      }
    }
    return _hex(sha256(b.takeBytes()));
  }

  void write(Map<String, dynamic> w) {
    final t = w['t'] as int;
    final k = _unhex(w['k'] as String);
    switch (w['op']) {
      case 'put':
        final v = valueBytes(w['v']['n'] as int, w['v']['s'] as int);
        final x = (w['x'] as int?) ?? 0;
        tree(t)[k] = (v: v, x: x);
        e.put(t, CBytes(k), v, expiryMs: x == 0 ? null : x);
      case 'del':
        tree(t).remove(k);
        e.remove(t, CBytes(k));
      default:
        throw Diverged('${w['op']} not allowed here');
    }
  }

  Snapshot? at(Map<String, dynamic> j) {
    if (!j.containsKey('at')) return null;
    return snaps[j['at']] ?? (throw ArgumentError('invalid log'));
  }

  void step(Map<String, dynamic> j) {
    switch (j['op']) {
      case 'put' || 'del':
        write(j);
        record();
      case 'range_del':
        final t = j['t'] as int;
        final lo = _unhex(j['lo'] as String), hi = _unhex(j['hi'] as String);
        tree(t).removeWhere((k, _) => _memcmp(k, lo) >= 0 && _memcmp(k, hi) < 0);
        e.removeRange(t, CBytes(lo), CBytes(hi));
        record();
      case 'batch':
        // ponytail: sequential writes; `visibleSeq` moves only at commit, so
        // no snapshot can split them.
        for (final w in j['ops'] as List) {
          write(w as Map<String, dynamic>);
        }
        record();
      case 'get':
        final t = j['t'] as int;
        final k = _unhex(j['k'] as String);
        final s = at(j);
        final m = s == null ? model : snapModels[j['at']]!;
        final c = m[t]?[k];
        final want = c == null || (c.x != 0 && c.x <= clock) ? null : c.v;
        final got = e.get(t, CBytes(k), at: s);
        if ((want == null) != (got == null) || (want != null && _memcmp(want, got!) != 0)) {
          throw Diverged('get t=$t k=${_hex(k)}: model ${_short(want)} engine ${_short(got)}');
        }
      case 'scan':
        final t = j['t'] as int;
        final lo = j['lo'] == null ? null : _unhex(j['lo'] as String);
        final hi = j['hi'] == null ? null : _unhex(j['hi'] as String);
        final s = at(j);
        final m = s == null ? model : snapModels[j['at']]!;
        compareScan(t, modelScan(m, t, lo, hi), engineScan(t, lo, hi, s));
      case 'snapshot':
        final id = j['id'] as int;
        if (snaps.containsKey(id)) throw ArgumentError('invalid log');
        final s = e.snapshot(nowMs: clock);
        final floor = history.lastKeyBefore(s.seq + 1);
        snaps[id] = s;
        snapModels[id] = floor == null ? {} : history[floor]!;
      case 'release':
        final s = snaps.remove(j['id']) ?? (throw ArgumentError('invalid log'));
        snapModels.remove(j['id']);
        e.release(s);
      case 'commit' || 'checkpoint':
        e.commit(); // ponytail: durability is recorded as `none` either way (no file under it)
      case 'compact':
        e.compact();
        e.collectWhileOverDebt(); // Rust's compact runs GC while over debt
      case 'shrink':
        e.shrink();
      case 'ttl_advance':
        clock += j['ms'] as int;
        e.nowMs = clock;
      case 'reopen':
        if (snaps.isNotEmpty) throw ArgumentError('invalid log');
        e.commit();
        DatabaseFile.save(db, path);
        e.close();
        db = DatabaseFile.open(path, key: encrypted ? _key : null);
        e.nowMs = clock;
        history
          ..clear()
          ..[e.visibleSeq] = _copy(model);
        digestCheck();
      default:
        throw Diverged('unknown op ${j['op']}');
    }
    // Nothing below the visible seq can be snapshotted again.
    final floor = history.lastKeyBefore(e.visibleSeq + 1);
    if (floor != null) history.removeWhere((k, _) => k < floor);
  }
}

/// The model effect of one op without an engine: lines another language
/// played (M1.3). Returns the clock.
int _modelApply(_Run r, Map<String, dynamic> j) {
  switch (j['op']) {
    case 'put':
      final x = (j['x'] as int?) ?? 0;
      r.tree(j['t'] as int)[_unhex(j['k'] as String)] =
          (v: valueBytes(j['v']['n'] as int, j['v']['s'] as int), x: x);
    case 'del':
      r.tree(j['t'] as int).remove(_unhex(j['k'] as String));
    case 'range_del':
      final lo = _unhex(j['lo'] as String), hi = _unhex(j['hi'] as String);
      r.tree(j['t'] as int).removeWhere((k, _) => _memcmp(k, lo) >= 0 && _memcmp(k, hi) < 0);
    case 'batch':
      for (final w in j['ops'] as List) {
        _modelApply(r, w as Map<String, dynamic>);
      }
    case 'ttl_advance':
      r.clock += j['ms'] as int;
  }
  return r.clock;
}

/// M1.3, one leg of a cross-language hop, as Rust's `oplog_check --hop`:
/// lines before [from] (1-based, header = 1) update only the model; [db] is
/// created ([from] = 2) or opened as another language left it and its digest
/// checked; lines `[from, to)` are replayed; then commit, save, close.
String hop(List<String> lines, String db, int from, int to) {
  final h = jsonDecode(lines[0]) as Map<String, dynamic>;
  final profile = switch (h['profile']) {
    'mobile' => Profile.mobile,
    'tablet' => Profile.tablet,
    'server' => Profile.server,
    _ => Profile.desktop,
  };
  final r = _Run(db, h['encrypted'] == true, profile, (h['trees'] as int?) ?? 1);
  for (final l in lines.sublist(1, from - 1)) {
    _modelApply(r, jsonDecode(l) as Map<String, dynamic>);
  }
  if (from == 2) {
    r.create();
  } else {
    r.db = DatabaseFile.open(db, key: r.encrypted ? _key : null);
    r.e.nowMs = r.clock;
  }
  r.history[r.e.visibleSeq] = _copy(r.model);
  try {
    r.digestCheck();
  } on Diverged catch (x) {
    throw Diverged('at open: $x');
  }
  for (var n = from - 1; n < to - 1; n++) {
    final j = jsonDecode(lines[n]) as Map<String, dynamic>;
    try {
      r.step(j);
    } on Diverged catch (x) {
      throw Diverged('line ${n + 1}: ${j['op']} — $x');
    }
  }
  r.e.commit();
  final d = r.digestCheck();
  DatabaseFile.save(r.db, db);
  r.e.close();
  return d;
}

/// Replays one log; returns the digest or throws Diverged('line N: …').
String replay(List<String> lines, Directory dir) {
  final h = jsonDecode(lines[0]) as Map<String, dynamic>;
  if (h['oplog'] != 1) throw Diverged('line 1: not an oplog v1');
  final profile = switch (h['profile']) {
    'mobile' => Profile.mobile,
    'tablet' => Profile.tablet,
    'server' => Profile.server,
    _ => Profile.desktop,
  };
  final path = '${dir.path}/oplog-${h['seed']}.cff';
  final f = File(path);
  if (f.existsSync()) f.deleteSync();
  final r = _Run(path, h['encrypted'] == true, profile, (h['trees'] as int?) ?? 1)..create();
  r.history[0] = {};
  for (var n = 1; n < lines.length; n++) {
    if (lines[n].trim().isEmpty) continue;
    final j = jsonDecode(lines[n]) as Map<String, dynamic>;
    try {
      r.step(j);
    } on Diverged catch (x) {
      throw Diverged('line ${n + 1}: ${j['op']} — $x');
    } catch (x) {
      if (x is ArgumentError && x.message == 'invalid log') rethrow;
      throw Diverged('line ${n + 1}: ${j['op']} — $x');
    }
  }
  try {
    return r.digestCheck();
  } on Diverged catch (x) {
    throw Diverged('end: $x');
  } finally {
    if (f.existsSync()) f.deleteSync();
  }
}

List<File> _logs(String dir) => Directory(dir)
    .listSync()
    .whereType<File>()
    .where((f) => f.path.endsWith('.jsonl'))
    .toList()
  ..sort((a, b) => a.path.compareTo(b.path));

void _replayAll(List<File> files) {
  final tmp = Directory.systemTemp.createTempSync('oplog_check');
  final fails = <String>[];
  for (final f in files) {
    try {
      replay(f.readAsLinesSync(), tmp);
    } on Diverged catch (x) {
      fails.add('${f.uri.pathSegments.last}: $x');
    }
  }
  tmp.deleteSync(recursive: true);
  expect(fails, isEmpty, reason: '${fails.length}/${files.length} logs diverge:\n${fails.join('\n')}');
}

void main() {
  test('value bytes match the Rust vector', () {
    final b = ByteData(8)..setUint64(0, 0xE220A8397B1DCDAF, Endian.little);
    expect(valueBytes(8, 0), b.buffer.asUint8List());
    expect(valueBytes(3, 0), [0xAF, 0xCD, 0x1D]);
    expect(valueBytes(0, 5), isEmpty);
  });

  test('regress logs replay', () {
    final files = _logs('../../conformance/oplog/regress');
    expect(files, isNotEmpty);
    _replayAll(files);
  });

  // `OPLOG_SHRINK=FILE` writes a minimal still-failing log to FILE.min
  // (greedy chunk removal, as Rust's and Java's).
  final shrink = Platform.environment['OPLOG_SHRINK'];
  test('shrink', () {
    final tmp = Directory.systemTemp.createTempSync('oplog_shrink');
    bool fails(List<String> l) {
      try {
        replay(l, tmp);
        return false;
      } on Diverged {
        return true;
      } on ArgumentError {
        return false; // the cut made the log invalid
      }
    }

    var lines = File(shrink!).readAsLinesSync().where((l) => l.trim().isNotEmpty).toList();
    expect(fails(lines), isTrue, reason: 'the log does not fail');
    for (var chunk = (lines.length - 1) ~/ 2; chunk >= 1;) {
      var dropped = false;
      for (var i = 1; i < lines.length;) {
        final end = i + chunk < lines.length ? i + chunk : lines.length;
        final trial = [...lines.sublist(0, i), ...lines.sublist(end)];
        if (fails(trial)) {
          lines = trial;
          dropped = true;
        } else {
          i = end;
        }
      }
      if (!dropped) chunk ~/= 2;
    }
    File('$shrink.min').writeAsStringSync('${lines.join('\n')}\n');
    tmp.deleteSync(recursive: true);
  }, skip: shrink == null ? 'set OPLOG_SHRINK to minimize a failing log' : false,
      timeout: Timeout.none);

  // `OPLOG_HOP="LOG DB FROM TO"` runs one hop leg and prints its digest.
  final hopArgs = Platform.environment['OPLOG_HOP']?.split(' ');
  test('hop', () {
    try {
      print('ok digest ${hop(File(hopArgs![0]).readAsLinesSync(), hopArgs[1], int.parse(hopArgs[2]), int.parse(hopArgs[3]))}');
    } on Diverged catch (x) {
      print('FAIL $x');
      rethrow;
    }
  }, skip: hopArgs == null ? 'set OPLOG_HOP to run one hop leg' : false);

  final dir = Platform.environment['OPLOG_DIR'];
  test('generated logs replay', () => _replayAll(_logs(dir!)),
      skip: dir == null ? 'set OPLOG_DIR to replay generated logs' : false);
}
