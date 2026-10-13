/// PLAN M2.1 — crash consistency under injected faults; the port of Rust's
/// `tests/fault_test.rs` and Java's `FaultTest`. Each seed runs random batches
/// (puts, removes, sometimes a compaction), each committed at `sync`; loses
/// power at a random write; keeps a random subset of the un-fsynced writes,
/// some torn at a 512-byte boundary; and reopens. On reopen the file opens,
/// `verifyStructure` finds nothing worse than a warning, the state is the last
/// acknowledged batch or that plus the one in flight, and an encrypted file's
/// nonce cursor starts above every nonce that could have been used.
///
/// `CRYPTAND_FAULT_SEEDS=a..b` widens the run (default 0..40).
// ponytail: no per-seed hang guard (sync code cannot be timed out in-isolate);
// the test runner's timeout is the guard.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:cryptand/src/cow.dart';
import 'package:test/test.dart';

const _tree = TreeId.firstUserTree;
final _key = Uint8List(32)..fillRange(0, 32, 7);

int _mix(List<int> s) {
  s[0] += 0x9e3779b97f4a7c15;
  var z = s[0];
  z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9;
  z = (z ^ (z >>> 27)) * 0x94d049bb133111eb;
  return z ^ (z >>> 31);
}

/// Unsigned `r % n` for a 64-bit [r].
int _mod(int r, int n) => (r >>> 1) % n;

final class Plan {
  /// Power is lost at this write (0-based): it and all later I/O fail.
  int crashAtWrite = -1;

  /// This fsync fails with EIO; what it covered stays un-fsynced.
  int eioAtSync = -1;

  /// This write fails with ENOSPC, writing nothing.
  int enospcAtWrite = -1;

  /// Every fsync reports success and persists nothing: the control.
  bool syncLies = false;

  @override
  String toString() => 'Plan{crash=$crashAtWrite eio=$eioAtSync '
      'enospc=$enospcAtWrite${syncLies ? ' syncLies' : ''}}';
}

final class _State {
  _State(this.plan);
  final Plan plan;
  int writes = 0, syncs = 0;
  bool dead = false;
  final pending = <(int, Uint8List, Uint8List)>[]; // offset, old, fresh
}

/// The fault layer under [fileHook]. A write is remembered with the bytes it
/// replaced until the next successful fsync, so [crash] can model a power cut.
final class Faults implements FileHook {
  static final _armed = <String, _State>{};
  static final _instance = Faults();

  static String _k(String path) => File(path).absolute.path;

  static void arm(String path, Plan plan) {
    _armed[_k(path)] = _State(plan);
    fileHook = _instance;
  }

  static void disarm(String path) => _armed.remove(_k(path));

  static (int, int) counts(String path) {
    final s = _armed[_k(path)];
    return s == null ? (0, 0) : (s.writes, s.syncs);
  }

  static Never _dead() => throw const FileSystemException('fault: power lost');

  @override
  void beforeWrite(RandomAccessFile f, int pos, List<int> bytes) {
    final s = _armed[_k(f.path)];
    if (s == null) return;
    if (s.dead) _dead();
    final n = s.writes++;
    if (s.plan.crashAtWrite == n) {
      s.dead = true;
      _dead();
    }
    if (s.plan.enospcAtWrite == n) {
      throw const FileSystemException('fault: ENOSPC (No space left on device)');
    }
    final old = Uint8List(bytes.length);
    final size = f.lengthSync();
    if (pos < size) {
      final r = File(f.path).openSync();
      try {
        r
          ..setPositionSync(pos)
          ..readIntoSync(old, 0, size - pos < old.length ? size - pos : old.length);
      } finally {
        r.closeSync();
      }
    }
    s.pending.add((pos, old, Uint8List.fromList(bytes)));
  }

  @override
  void beforeSync(RandomAccessFile f) {
    final s = _armed[_k(f.path)];
    if (s == null) return;
    if (s.dead) _dead();
    if (s.plan.eioAtSync == s.syncs++) {
      throw const FileSystemException('fault: EIO (Input/output error)');
    }
    if (!s.plan.syncLies) s.pending.clear();
  }

  /// Disarms [path] and rewrites the file as a power cut now could have left
  /// it: undo every un-fsynced write, then replay a random subset in order,
  /// some torn. Call after every handle is closed. Returns the number dropped.
  static int crash(String path, int seed) {
    final s = _armed.remove(_k(path));
    if (s == null) return 0;
    final rng = [seed ^ 0x9e3779b97f4a7c15];
    var dropped = 0;
    final f = File(path).openSync(mode: FileMode.append);
    try {
      for (final (off, old, _) in s.pending.reversed) {
        f
          ..setPositionSync(off)
          ..writeFromSync(old);
      }
      for (final (off, _, fresh) in s.pending) {
        final r = _mix(rng);
        if (r & 1 == 0) {
          dropped++;
          continue;
        }
        final blocks = fresh.length ~/ 512;
        final keep = (r & 6) == 0 && blocks > 1
            ? (1 + _mod(r >>> 8, blocks - 1)) * 512
            : fresh.length;
        f
          ..setPositionSync(off)
          ..writeFromSync(fresh, 0, keep);
      }
      f.flushSync();
    } finally {
      f.closeSync();
    }
    return dropped;
  }
}

Database _create(String path, bool encrypted) {
  if (encrypted) {
    return DatabaseFile.create(path,
        credential: Uint8List.fromList(_key), kdf: Keyslot.kdfRaw, memtableEntries: 64);
  }
  DatabaseFile.save(
      Database(
          engine: Engine(
              pageSize: Profile.desktop.pageSize,
              memtableEntries: 64,
              vlogMin: Profile.desktop.vlogMin,
              vlogSegmentBytes: Profile.desktop.vlogSegmentBytes)
            ..setProfile(Profile.desktop)),
      path);
  return DatabaseFile.open(path);
}

/// The process dies: no close, no flush. Only the handle (and lock) goes.
void _abandon(Database db) => db.engine.onClose!();

/// The smallest value any page or record of this session may have used.
int _nonceBound(Engine e) {
  final n = e.nonces;
  if (n == null) return 0;
  return n.next < n.publishedWatermark ? n.next : n.publishedWatermark;
}

CValue _k(int n) => CBytes(Uint8List(8)..buffer.asByteData().setUint64(0, n));

final class _Run {
  var acked = <int, Uint8List>{};
  var inflight = <int, Uint8List>{};
  int nonceBound = 0;
}

_Run _workload(Engine e, int seed) {
  final rng = [seed];
  final model = <int, Uint8List>{};
  final run = _Run();
  for (var batch = 0; batch < 12; batch++) {
    try {
      final n = 1 + _mod(_mix(rng), 40);
      for (var i = 0; i < n; i++) {
        final r = _mix(rng);
        final key = _mod(r, 200);
        if (_mod(r, 5) == 0) {
          model.remove(key);
          e.remove(_tree, _k(key));
        } else {
          final len = _mod(r, 7) == 0 ? 3000 : 1 + _mod(r >>> 20, 60);
          final v = Uint8List(len)..fillRange(0, len, (r >>> 8) & 0xff);
          model[key] = v;
          e.put(_tree, _k(key), v);
        }
      }
      run.inflight = Map.of(model);
      final r = _mix(rng);
      e.commit(durability: Durability.sync);
      if (_mod(r, 4) == 0) e.compact();
    } on Object {
      return run;
    } finally {
      final b = _nonceBound(e);
      if (b > run.nonceBound) run.nonceBound = b;
    }
    run.acked = Map.of(model);
  }
  return run;
}

bool _same(Map<int, Uint8List> a, Map<int, Uint8List> b) =>
    a.length == b.length &&
    a.entries.every((x) {
      final y = b[x.key];
      if (y == null || y.length != x.value.length) return false;
      for (var i = 0; i < y.length; i++) {
        if (y[i] != x.value[i]) return false;
      }
      return true;
    });

String? _one(Directory dir, String name, int seed,
    Plan Function((int, int) counts, List<int> rng) planOf) {
  final encrypted = seed.isOdd;
  final rng = [seed * 31 + 1];

  final dry = '${dir.path}/dry-$name-$seed.cryptand';
  final d = _create(dry, encrypted);
  Faults.arm(dry, Plan());
  _workload(d.engine, seed);
  final counts = Faults.counts(dry);
  Faults.disarm(dry);
  _abandon(d);

  final p = '${dir.path}/$name-$seed.cryptand';
  final live = _create(p, encrypted);
  final plan = planOf(counts, rng);
  Faults.arm(p, plan);
  final run = _workload(live.engine, seed);
  _abandon(live);
  final dropped = Faults.crash(p, _mix(rng));
  final ctx = 'seed $seed enc=$encrypted $plan writes=${counts.$1} dropped=$dropped';

  final Database back;
  try {
    back = DatabaseFile.open(p, key: encrypted ? Uint8List.fromList(_key) : null);
  } on Object catch (x) {
    return '$ctx: open refused: $x';
  }
  try {
    final e = back.engine;
    final bad = e
        .verifyStructure()
        .findings
        .where((f) => f.kind != FindingClass.warning)
        .toList();
    if (bad.isNotEmpty) return '$ctx: verify: $bad';
    final got = <int, Uint8List>{};
    for (var i = 0; i < 200; i++) {
      final v = e.get(_tree, _k(i));
      if (v != null) got[i] = v;
    }
    if (!_same(got, run.acked) && !_same(got, run.inflight)) {
      return '$ctx: state is neither the acked batch (${run.acked.length} keys) '
          'nor the in-flight one (${run.inflight.length}): ${got.length}';
    }
    if (encrypted && _nonceBound(e) < run.nonceBound) {
      return '$ctx: nonce cursor ${_nonceBound(e)} below ${run.nonceBound}';
    }
  } on Object catch (x) {
    return '$ctx: threw $x';
  } finally {
    back.engine.close(flushMemtable: false);
  }
  return null;
}

List<String> _sweep(String name, int from, int to,
    Plan Function((int, int), List<int>) planOf) {
  final dir = Directory.systemTemp.createTempSync('fault-');
  try {
    return [
      for (var s = from; s < to; s++)
        if (_one(dir, name, s, planOf) case final f?) f,
    ];
  } finally {
    dir.deleteSync(recursive: true);
  }
}

void _check(String name, Plan Function((int, int), List<int>) planOf) {
  final r = (Platform.environment['CRYPTAND_FAULT_SEEDS'] ?? '0..40').split('..');
  final failures = _sweep(name, int.parse(r[0]), int.parse(r[1]), planOf);
  expect(failures, isEmpty, reason: '$name: ${failures.length} failures:\n${failures.join('\n')}');
}

int _below(List<int> rng, int n) => _mod(_mix(rng), n < 1 ? 1 : n);

void main() {
  _f095();

  test('power cut at a random write', () {
    _check('crash', (c, rng) => Plan()..crashAtWrite = _below(rng, c.$1));
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('fsync EIO, then a power cut', () {
    _check('eio', (c, rng) => Plan()..eioAtSync = _below(rng, c.$2));
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('ENOSPC at a random write, then a power cut', () {
    _check('enospc', (c, rng) => Plan()..enospcAtWrite = _below(rng, c.$1));
  }, timeout: const Timeout(Duration(minutes: 10)));

  /// The control (PLAN rule 5): when fsync lies, acknowledged batches are
  /// lost, and the checks must say so.
  test('control: a lying fsync is caught', () {
    final failures = _sweep('control', 0, 20, (c, rng) {
      final w = c.$1 < 4 ? 4 : c.$1;
      return Plan()
        ..crashAtWrite = w - 1 - _below(rng, w ~/ 4)
        ..syncLies = true;
    });
    expect(failures, isNotEmpty, reason: 'a lying fsync went unnoticed in 20 seeds');
  }, timeout: const Timeout(Duration(minutes: 10)));
}

/// F-095: a publish that fails after numbering its commit must not skip a
/// number. Slots alternate by commit id, so the skipped retry overwrote the
/// last durable superblock.
void _f095() {
  test('a failed publish does not skip a commit id', () {
    final dir = Directory.systemTemp.createTempSync('f095-');
    final path = '${dir.path}/db.cryptand';
    final db = _create(path, false);
    final e = db.engine;
    try {
      e.put(_tree, _k(1), Uint8List(8));
      e.commit();
      // #0, #1: the barriers before the flush and after it; #2: the one
      // before the superblock write, after the commit is numbered.
      Faults.arm(path, Plan()..eioAtSync = 2);
      e.put(_tree, _k(1), Uint8List(9));
      expect(() => e.commit(), throwsA(anything));
      Faults.disarm(path);
      e.commit();
      final all = File(path).readAsBytesSync();
      final ps = e.store.pageSize;
      final a = Superblock.tryDecode(Uint8List.sublistView(all, 0, ps))!.commitId;
      final b = Superblock.tryDecode(Uint8List.sublistView(all, ps, 2 * ps))!.commitId;
      expect((a - b).abs(), 1, reason: 'slots hold commits $a and $b');
    } finally {
      e.close();
      dir.deleteSync(recursive: true);
    }
  });
}
