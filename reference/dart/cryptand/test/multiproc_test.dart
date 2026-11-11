/// `spec/13-operations.md` §8, PLAN A1.5: readers in other processes, run as
/// `tool/multiproc_child.dart`.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

import '../tool/multiproc_child.dart' as child;

final class Reader {
  final Process p;
  final StreamIterator<String> _out;
  Reader._(this.p)
      : _out = StreamIterator(
            p.stdout.transform(utf8.decoder).transform(const LineSplitter()));

  static Future<Reader> spawn(String db) async {
    final p = await Process.start(Platform.resolvedExecutable,
        ['run', 'tool/multiproc_child.dart', 'reader', db]);
    p.stderr.drain<void>();
    return Reader._(p);
  }

  Future<String> line(String prefix) async {
    while (await _out.moveNext().timeout(const Duration(seconds: 120))) {
      final l = _out.current;
      if (l.startsWith(prefix)) return l;
    }
    throw StateError('reader exited before $prefix');
  }

  void go() => p.stdin.writeln('go');

  void kill() => p.kill(ProcessSignal.sigkill);
}

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('cryptand-mp-'));
  tearDown(() => dir.deleteSync(recursive: true));
  String db(String name) => '${dir.path}/$name.cryptand';
  int live(String path) {
    final s = Sidecar.openReader(path, defaultReaderHeartbeatMs, (_) {})!;
    try {
      return s.slots.where((x) => !x.isFree).length;
    } finally {
      s.close();
    }
  }

  test('a pinned reader process scans its snapshot while the writer reclaims', () async {
    final path = db('pin');
    final e = child.populated(path);
    final pinned = e.commitId;
    final r = await Reader.spawn(path);
    try {
      final mode = await r.line('mode=');
      expect(mode, startsWith('mode=slotted'));
      expect(mode, endsWith('commit=$pinned'));
      child.churn(e);
      expect(e.minRetainedCommit, lessThan(pinned), reason: 'the live slot must hold the floor');
      r.go();
      expect(await r.line('rows='), 'rows=${child.rows} bad=0');
    } finally {
      r.kill();
      e.close();
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test("a killed reader's slot is reclaimed after three heartbeats", () async {
    final path = db('kill');
    final e = child.populated(path);
    final pinned = e.commitId;
    final r = await Reader.spawn(path);
    expect(await r.line('mode='), startsWith('mode=slotted'));
    r.kill();
    await r.p.exitCode;
    e
      ..put(child.tree, CNitriteId(0), child.doc(9))
      ..commit();
    expect(e.minRetainedCommit, lessThan(pinned), reason: 'a fresh dead slot still pins');
    await Future<void>.delayed(
        const Duration(milliseconds: staleMultiplier * defaultReaderHeartbeatMs + 500));
    e
      ..put(child.tree, CNitriteId(0), child.doc(8))
      ..commit();
    expect(e.minRetainedCommit, greaterThanOrEqualTo(pinned));
    expect(live(path), 0);
    e.close();
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('racing reader processes claim distinct slots', () async {
    final path = db('race');
    final e = child.populated(path);
    final readers = await Future.wait([for (var i = 0; i < 8; i++) Reader.spawn(path)]);
    try {
      final idx = <String>{
        for (final r in readers) (await r.line('mode=slotted')).split(' ')[1]
      };
      expect(idx, hasLength(8));
    } finally {
      for (final r in readers) {
        r.kill();
      }
      e.close();
    }
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('two readers in one process keep their own slots', () {
    final path = db('same');
    final e = child.populated(path);
    final a = DatabaseFile.openReadOnly(path).engine;
    e
      ..put(child.tree, CNitriteId(0), child.doc(9))
      ..commit();
    final b = DatabaseFile.openReadOnly(path).engine;
    expect(live(path), 2);
    a.close(flushMemtable: false);
    expect(live(path), 1);
    expect(b.multiproc!.slot!.commitId, e.commitId);
    b.close(flushMemtable: false);
    expect(live(path), 0);
    e.close();
    final s = Sidecar.openReader(path, defaultReaderHeartbeatMs, (_) {})!;
    expect(s.writerPid, 0, reason: 'closed: no live writer');
    s.close();
  });

  // F-220: pages reused under a reader fail its read, not hang it or end it
  // short. The slot is released behind the reader's back while the writer
  // churns, then restored, so neither rule 3 nor rule 4 sees anything.
  test('F-220: a read of reused pages fails loudly', () {
    final path = db('f220');
    final e = child.populated(path);
    final pinned = e.commitId;
    final v = DatabaseFile.openReadOnly(path).engine;
    final slot = v.multiproc!.slot!;
    final sc = Sidecar.openReader(path, defaultReaderHeartbeatMs, (_) {})!;
    sc.release(slot);
    child.churn(e);
    expect(e.minRetainedCommit, greaterThan(pinned));
    expect(sc.claim(pinned, DateTime.now().millisecondsSinceEpoch)!.index, slot.index);
    expect(
        () => v.scanTree(child.tree).length,
        throwsA(isA<CorruptionException>().having(
            (x) => x.toString(), 'message', contains('reclaimed under'))));
    sc.close();
    v.close(flushMemtable: false);
    e.close();
  });

  test('a full sidecar opens volatile, says why, and revalidates', () {
    final path = db('full');
    final e = child.populated(path);
    final held = [for (var i = 0; i < 64; i++) DatabaseFile.openReadOnly(path).engine];
    final v = DatabaseFile.openReadOnly(path).engine;
    expect(v.multiproc!.volatileReason, VolatileReason.sidecarFull);
    expect(v.get(child.tree, CNitriteId(1)), isNotNull);
    for (final h in held) {
      h.close(flushMemtable: false);
    }
    child.churn(e);
    expect(() => v.get(child.tree, CNitriteId(1)), throwsA(isA<LockedException>()));
    v.close(flushMemtable: false);
    e.close();
  });

  test('a read-only sidecar opens volatile and says why', () {
    final path = db('ro');
    child.populated(path).close();
    Process.runSync('chmod', ['0400', sidecarPath(path)]);
    final r = DatabaseFile.openReadOnly(path).engine;
    expect(r.multiproc!.volatileReason, VolatileReason.sidecarReadOnly);
    expect(r.multiproc!.writerAlive, isFalse);
    r.close(flushMemtable: false);
  }, testOn: '!windows');

  test('a reader with no sidecar creates one with no writer', () {
    final path = db('none');
    child.populated(path).close();
    File(sidecarPath(path)).deleteSync();
    final r = DatabaseFile.openReadOnly(path).engine;
    expect(r.multiproc!.slot, isNotNull);
    expect(r.multiproc!.writerAlive, isFalse);
    r.close(flushMemtable: false);
  });

  test('the sidecar file is owner-only and refuses a symlink', () {
    final path = db('perm');
    child.populated(path).close();
    if (!Platform.isWindows) {
      expect(File(sidecarPath(path)).statSync().modeString(), 'rw-------');
      final victim = File('${dir.path}/victim')..writeAsBytesSync([7]);
      final link = db('link');
      Link(sidecarPath(link)).createSync(victim.path);
      expect(() => Sidecar.openWriter(link, 2000, (_) {}), throwsA(isA<FileSystemException>()));
      expect(Sidecar.openReader(link, 2000, (_) {}), isNull);
      expect(victim.readAsBytesSync(), Uint8List.fromList([7]));
    }
  });
}
