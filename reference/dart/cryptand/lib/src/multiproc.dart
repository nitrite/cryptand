/// `spec/13-operations.md` §8 — multi-process readers, feature bit
/// `MULTIPROC_READ`. One writing process, any number of reading processes;
/// the only coordination is retention, through `<name>.cryptand-lock`:
///
/// ```
/// header:  u32 magic, u32 slot_count, u64 writer_pid, u64 writer_heartbeat_ms
/// slots:   slot_count × { u64 pid, u64 commit_id, u64 heartbeat_ms }
/// ```
///
/// Every slot read-modify-write holds an exclusive lock on the byte at
/// [claimLockByte], the same byte Rust and Java lock. A slot belongs to a
/// reader only while both its pid and its commit id are the ones it wrote.
library;

import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'errors.dart';

/// `"CLK1"` little-endian.
const int sidecarMagic = 0x314B4C43;
const int _header = 24;
const int _slotBytes = 24;
const int defaultSlotCount = 64;
const int defaultReaderHeartbeatMs = 2000;
const int staleMultiplier = 3;
const int claimLockByte = 1 << 40;

int wallMs() => DateTime.now().millisecondsSinceEpoch;

String sidecarPath(String database) => '$database-lock';

final class SidecarSlot {
  final int index;
  final int pid;
  final int commitId;
  final int heartbeatMs;
  const SidecarSlot(this.index, this.pid, this.commitId, this.heartbeatMs);

  bool get isFree => pid == 0;

  bool isStale(int now, int intervalMs) =>
      !isFree && now - heartbeatMs > staleMultiplier * intervalMs;

  @override
  String toString() => 'SidecarSlot(index: $index, pid: $pid, commitId: $commitId)';
}

/// Rule 4: which of the two ways a reader is volatile.
enum VolatileReason { sidecarReadOnly, sidecarFull }

final class Sidecar {
  final RandomAccessFile _f;
  final int intervalMs;
  final bool readOnly;
  int slotCount = 0;

  Sidecar._(this._f, this.intervalMs, this.readOnly);

  /// The writer: keep live readers' slots, (re)create when absent or invalid,
  /// publish the pid. [ownerOnly] makes a new file `0600` (PLAN 4.7).
  static Sidecar openWriter(String database, int intervalMs,
      void Function(String) ownerOnly) {
    final s = _openRw(database, intervalMs, pid, ownerOnly);
    s._locked(() {
      s._writeU64(8, pid);
      s._writeU64(16, wallMs());
    });
    return s;
  }

  /// A reader: read-write, creating it with `writer_pid` 0 when absent;
  /// read-only when it cannot be written; `null` when it cannot be read.
  static Sidecar? openReader(String database, int intervalMs,
      void Function(String) ownerOnly) {
    try {
      return _openRw(database, intervalMs, 0, ownerOnly);
    } on FileSystemException {
      final p = sidecarPath(database);
      if (FileSystemEntity.isLinkSync(p)) return null;
      try {
        final s = Sidecar._(File(p).openSync(mode: FileMode.read), intervalMs, true);
        final n = s._readHeader();
        if (n == 0) {
          s.close();
          return null;
        }
        return s..slotCount = n;
      } on FileSystemException {
        return null;
      }
    }
  }

  static Sidecar _openRw(String database, int intervalMs, int writerPid,
      void Function(String) ownerOnly) {
    final p = sidecarPath(database);
    // PLAN 4.7: the path is predictable; never write through a planted link.
    if (FileSystemEntity.isLinkSync(p)) {
      throw FileSystemException('the lock sidecar is a symbolic link', p);
    }
    try {
      File(p).createSync(exclusive: true);
      ownerOnly(p);
    } on PathExistsException {
      // Another process made it; it is initialized under the lock below.
    }
    final s = Sidecar._(File(p).openSync(mode: FileMode.append), intervalMs, false);
    try {
      s.slotCount = s._locked(() {
        final n = s._readHeader();
        if (n > 0) return n;
        final image = ByteData(_header + defaultSlotCount * _slotBytes)
          ..setUint32(0, sidecarMagic, Endian.little)
          ..setUint32(4, defaultSlotCount, Endian.little)
          ..setUint64(8, writerPid, Endian.little)
          ..setUint64(16, wallMs(), Endian.little);
        s._f
          ..truncateSync(0)
          ..setPositionSync(0)
          ..writeFromSync(image.buffer.asUint8List())
          ..flushSync();
        return defaultSlotCount;
      });
    } catch (_) {
      s.close();
      rethrow;
    }
    return s;
  }

  /// The slot count of a valid header whose slots are all present, else 0.
  int _readHeader() {
    final len = _f.lengthSync();
    if (len < _header) return 0;
    final h = ByteData.sublistView(_read(0, _header));
    final n = h.getUint32(4, Endian.little);
    final ok = h.getUint32(0, Endian.little) == sidecarMagic &&
        n > 0 &&
        len >= _header + n * _slotBytes;
    return ok ? n : 0;
  }

  T _locked<T>(T Function() body) {
    _f.lockSync(FileLock.blockingExclusive, claimLockByte, claimLockByte + 1);
    try {
      return body();
    } finally {
      _f.unlockSync(claimLockByte, claimLockByte + 1);
    }
  }

  Uint8List _read(int at, int len) {
    _f.setPositionSync(at);
    final b = _f.readSync(len);
    if (b.length != len) {
      throw CorruptionException('lock sidecar truncated at $at');
    }
    return b;
  }

  int _readU64(int at) =>
      ByteData.sublistView(_read(at, 8)).getUint64(0, Endian.little);

  void _writeU64(int at, int v) {
    _f
      ..setPositionSync(at)
      ..writeFromSync((ByteData(8)..setUint64(0, v, Endian.little)).buffer.asUint8List());
  }

  int get writerPid => _readU64(8);

  /// Rule 5: the writer refreshes on the schedule it asks of readers.
  void refreshWriter(int now) => _writeU64(16, now);

  /// Writer close: `writer_pid` 0 is "no live writer".
  void clearWriter() => _writeU64(8, 0);

  /// Rule 5: pid 0 or an aged writer heartbeat is no live writer.
  bool writerAlive(int now) =>
      writerPid != 0 && now - _readU64(16) <= staleMultiplier * intervalMs;

  SidecarSlot slot(int i) {
    final b = ByteData.sublistView(_read(_header + i * _slotBytes, _slotBytes));
    return SidecarSlot(i, b.getUint64(0, Endian.little),
        b.getUint64(8, Endian.little), b.getUint64(16, Endian.little));
  }

  List<SidecarSlot> get slots => [for (var i = 0; i < slotCount; i++) slot(i)];

  void _writeSlot(int i, int p, int commitId, int beat) {
    final b = ByteData(_slotBytes)
      ..setUint64(0, p, Endian.little)
      ..setUint64(8, commitId, Endian.little)
      ..setUint64(16, beat, Endian.little);
    _f
      ..setPositionSync(_header + i * _slotBytes)
      ..writeFromSync(b.buffer.asUint8List());
  }

  bool _owns(SidecarSlot s) {
    final cur = slot(s.index);
    return cur.pid == s.pid && cur.commitId == s.commitId;
  }

  /// Rule 1: claim a free or stale slot; `null` when none is (or read-only).
  SidecarSlot? claim(int commitId, int now) {
    if (readOnly) return null;
    return _locked(() {
      for (var i = 0; i < slotCount; i++) {
        final s = slot(i);
        if (s.isFree || s.isStale(now, intervalMs)) {
          _writeSlot(i, pid, commitId, now);
          return SidecarSlot(i, pid, commitId, now);
        }
      }
      return null;
    });
  }

  /// Moves a held slot to a newer superblock; `null` if it was reclaimed.
  SidecarSlot? repin(SidecarSlot s, int commitId, int now) => _locked(() {
        if (!_owns(s)) return null;
        _writeSlot(s.index, s.pid, commitId, now);
        return SidecarSlot(s.index, s.pid, commitId, now);
      });

  /// Rule 1's refresh, rule 3's detection: `false` means reclaimed, reopen.
  bool heartbeat(SidecarSlot s, int now) => _locked(() {
        if (!_owns(s)) return false;
        _writeSlot(s.index, s.pid, s.commitId, now);
        return true;
      });

  void release(SidecarSlot s) => _locked(() {
        if (_owns(s)) _writeSlot(s.index, 0, 0, 0);
      });

  /// Rules 2 and 3 for the writer: reclaim stale slots, return the lowest
  /// commit a live slot pins, or `null`.
  int? reclaimAndMinPinned(int now) {
    try {
      return reclaimAndHold(now);
    } finally {
      releaseClaims();
    }
  }

  /// F-222: [reclaimAndMinPinned] with the claim lock kept until
  /// [releaseClaims], which the writer calls once the superblock carrying
  /// this floor is written. A claim then lands before this read (counted) or
  /// after that superblock (the reader's re-read sees it and re-pins);
  /// released in between, a claim could land unseen by both and the next
  /// window reused its pages.
  int? reclaimAndHold(int now) {
    _f.lockSync(FileLock.blockingExclusive, claimLockByte, claimLockByte + 1);
    _held = true;
    int? min;
    for (var i = 0; i < slotCount; i++) {
      final s = slot(i);
      if (s.isStale(now, intervalMs)) {
        _writeSlot(i, 0, 0, 0);
      } else if (!s.isFree && (min == null || s.commitId < min)) {
        min = s.commitId;
      }
    }
    return min;
  }

  bool _held = false;

  void releaseClaims() {
    if (!_held) return;
    _held = false;
    _f.unlockSync(claimLockByte, claimLockByte + 1);
  }

  void close() => _f.closeSync();
}

/// 13 §8 rules 1 and 5: the periodic beat for every live handle of this
/// isolate. A timer here would keep the isolate alive, and a handle never
/// closed would hang its process, so the clock is a second isolate and its
/// ticks arrive on a port that does not. The beats themselves stay on this
/// isolate: POSIX record locks are per process, so a beat from another
/// isolate would release a claim lock this one is holding (F-222).
/// ponytail: an isolate blocked in synchronous code for 3 intervals without
/// touching its handle still goes stale; only a second locking primitive
/// (OFD locks over FFI) would let another isolate beat for it.
final Set<Multiproc> _live = {};
RawReceivePort? _ticks;

void _startTicks() {
  if (_ticks != null) return;
  final port = _ticks = RawReceivePort((Object? _) {
    for (final m in _live.toList()) {
      m.beatIfDue(force: true);
    }
  })
    ..keepIsolateAlive = false;
  // If the clock cannot start, handles still beat on their own operations.
  Isolate.spawn(_clock, (port.sendPort, Isolate.current.controlPort)).ignore();
}

/// Ticks until the isolate it serves exits.
void _clock((SendPort, SendPort) a) {
  final (ticks, owner) = a;
  Isolate(owner).addOnExitListener(RawReceivePort((Object? _) => Isolate.exit()).sendPort);
  Timer.periodic(const Duration(milliseconds: defaultReaderHeartbeatMs ~/ 2),
      (_) => ticks.send(null));
}

/// An engine's side of the sidecar. A writer has [writer] set; a reader has
/// [slot] (slotted) or [volatileReason]. Both beat from [beatIfDue]: on their
/// own operations, and on the clock above while their isolate is idle.
final class Multiproc {
  final Sidecar? sidecar;
  final bool writer;
  final SidecarSlot? slot;
  final VolatileReason? volatileReason;
  bool slotLost = false;
  final Stopwatch _sinceBeat = Stopwatch()..start();

  Multiproc.writer(Sidecar this.sidecar)
      : writer = true,
        slot = null,
        volatileReason = null {
    _live.add(this);
    _startTicks();
  }

  Multiproc.reader(this.sidecar, this.slot, this.volatileReason) : writer = false {
    if (slot == null) return; // volatile: nothing to beat
    _live.add(this);
    _startTicks();
  }

  void beatIfDue({bool force = false}) {
    final sc = sidecar;
    if (sc == null || slotLost) return;
    if (!force && _sinceBeat.elapsedMilliseconds < defaultReaderHeartbeatMs ~/ 2) return;
    _sinceBeat.reset();
    try {
      if (writer) {
        sc.refreshWriter(wallMs());
      } else if (slot != null && !sc.heartbeat(slot!, wallMs())) {
        slotLost = true;
      }
    } on Object {
      if (!writer) slotLost = true;
    }
  }

  /// Rule 3: a reader whose slot was reclaimed MUST reopen.
  void checkSlot() {
    if (slotLost) {
      throw const LockedException(
          "this reader's sidecar slot was reclaimed (13 §8 rule 3): reopen");
    }
  }

  /// Rule 5, for a reader to report: is a writing process live?
  bool get writerAlive => writer || (sidecar?.writerAlive(wallMs()) ?? false);

  void detach() {
    _live.remove(this);
    final sc = sidecar;
    if (sc == null) return;
    try {
      if (writer) {
        sc.clearWriter();
      } else if (slot != null && !slotLost) {
        sc.release(slot!);
      }
    } on Object {
      // A stale slot ages out on its own (rule 3).
    } finally {
      sc.close();
    }
  }
}
