/// Sequencing, snapshots, transactions and durability —
/// `spec/10-transactions.md`.
///
/// **What is here and what is not, stated first because the gap is the point.**
/// §2 is the concurrent write protocol: *N* application threads contending on
/// one atomic counter. Dart has no shared-memory threads, so §2 cannot be
/// implemented here and prediction P3 cannot be measured here — which is
/// exactly the case `spec/11-conformance.md` §1.1 covers, and this
/// implementation declares `Level 0 (single-writer)` accordingly.
///
/// Everything else in the chapter is independent of thread count and is
/// implemented: the snapshot of §1, the commit and its **ordering invariants**
/// (§2.3), transactions and conflict detection (§3), recovery (§4), the
/// manifest publish (§5), the **normative backpressure curve** (§6),
/// durability modes (§7), retention watermarks (§8), store events (§9) and
/// close (§10).
///
/// That split is worth being precise about: a single writer still has to get
/// atomicity, visibility, conflict detection and recovery right, and those are
/// where a database returns *wrong answers* rather than slow ones.
library;

import 'dart:typed_data';

import 'errors.dart';

/// A read snapshot, `spec/10-transactions.md` §1.
///
/// **All nine roots, not a subset.** §1: "A snapshot that omits one is not a
/// consistent view of the database: a reader restored to it would see the
/// current change feed against an older manifest." `13-operations.md` §1
/// stores exactly this tuple for a checkpoint, for the same reason.
final class Snapshot {
  const Snapshot({
    required this.seq,
    required this.commitId,
    required this.catalogRoot,
    required this.freelistRoot,
    required this.attributesRoot,
    required this.manifestRoot,
    required this.vlogStatsRoot,
    required this.checkpointRoot,
    required this.changefeedRoot,
    this.takenAtMs = 0,
  });

  final int seq;
  final int commitId;
  final int catalogRoot;
  final int freelistRoot;
  final int attributesRoot;
  final int manifestRoot;
  final int vlogStatsRoot;
  final int checkpointRoot;
  final int changefeedRoot;

  /// Wall clock at which this snapshot was taken, for
  /// `oldest_snapshot_age_ms` (`13-operations.md` §6).
  final int takenAtMs;

  /// True when a record at [recordSeq] is visible here.
  ///
  /// §1: "A read at snapshot S sees exactly the records with `seq ≤ S.seq`
  /// that were not superseded or deleted by a record with a seq also ≤ S.seq."
  bool sees(int recordSeq) => recordSeq <= seq;

  @override
  String toString() => 'Snapshot(seq $seq, commit $commitId)';
}

/// `spec/10-transactions.md` §3.
enum Isolation {
  /// Reads at the start snapshot; writes buffered and sequenced at commit;
  /// write–write conflicts detected by key.
  snapshot,

  /// Each statement takes a fresh snapshot.
  readCommitted,

  /// Additionally records the read set and validates it at commit.
  serializable,

  /// Pins a snapshot; cannot conflict; never blocks and is never blocked.
  readOnly,
}

/// `spec/10-transactions.md` §7.
///
/// The chapter's rule is an obligation rather than a syscall: use the
/// strongest primitive the platform provides, and **record what was actually
/// performed**. [Durability.achieved] is that record, and an implementation
/// that cannot reach a mode reports the one it reached and is conforming.
enum Durability {
  none(0),
  os(1),
  sync(2),
  full(3);

  const Durability(this.code);
  final int code;

  static Durability fromCode(int c) =>
      Durability.values.firstWhere((d) => d.code == c,
          orElse: () => Durability.none);
}

/// `spec/10-transactions.md` §9.
enum StoreEventKind {
  opened,
  commit,
  flushed,
  compacted,
  backpressure,
  closing,
  closed,
}

/// One store event. §9: "Events are delivered after durability, never before."
final class StoreEvent {
  const StoreEvent(this.kind, {this.commitId, this.visibleSeq, this.detail});
  final StoreEventKind kind;
  final int? commitId;
  final int? visibleSeq;
  final String? detail;

  @override
  String toString() => 'StoreEvent(${kind.name}'
      '${commitId != null ? ", commit $commitId" : ""}'
      '${visibleSeq != null ? ", visible_seq $visibleSeq" : ""}'
      '${detail != null ? ", $detail" : ""})';
}

/// One backpressure bound and where it currently sits, §6.
final class Bound {
  const Bound(this.name, this.current, this.soft, this.hard);
  final String name;
  final num current;
  final num soft;
  final num hard;

  /// `(current − soft) / (hard − soft)`, clamped to `[0, 1]`.
  double get overshoot {
    if (hard <= soft) return current > soft ? 1 : 0;
    final x = (current - soft) / (hard - soft);
    return x < 0 ? 0 : (x > 1 ? 1 : x.toDouble());
  }
}

/// The backpressure curve, `spec/10-transactions.md` §6 — **normative**.
///
/// ```
/// x = max over bounds of (current − soft) / (hard − soft), clamped to [0, 1]
/// delay_ms = max_delay_ms × x²
/// ```
///
/// Quadratic, "so it is imperceptible while the engine is merely busy and firm
/// before it is in trouble". §6 also forbids the shape that makes this matter:
/// "An implementation MUST NOT stall at the hard threshold without having
/// applied increasing delay before it — a cliff turns a throughput problem into
/// a hang, and that is the failure users report."
final class Backpressure {
  const Backpressure(this.delayMs, this.cause);

  final double delayMs;

  /// Which bound produced the delay. §6: an implementation "MUST expose the
  /// current delay and the bound that caused it".
  final String? cause;

  static Backpressure compute(List<Bound> bounds, {double maxDelayMs = 100}) {
    Bound? worst;
    var x = 0.0;
    for (final b in bounds) {
      final o = b.overshoot;
      if (o > x) {
        x = o;
        worst = b;
      }
    }
    return Backpressure(maxDelayMs * x * x, worst?.name);
  }

  bool get isApplied => delayMs > 0;

  @override
  String toString() => delayMs == 0
      ? 'no backpressure'
      : '${delayMs.toStringAsFixed(1)} ms (${cause ?? "unknown"})';
}

/// A buffered write inside a transaction, before it is sequenced.
final class TxnWrite {
  const TxnWrite(this.treeId, this.cke, this.value, this.isDelete);
  final int treeId;
  final Uint8List cke;
  final Uint8List value;
  final bool isDelete;
}

/// A transaction, `spec/10-transactions.md` §3.
///
/// Writes are buffered until [commit], which is what makes rollback free:
/// "Nothing durable is written before sequencing, so rollback is free and
/// leaves no trace — unlike the undo-log approach all three SDKs use today,
/// which writes and then reverses."
final class Transaction {
  Transaction({
    required this.snapshot,
    required this.isolation,
    required int Function(String key) writtenSeqOf,
    required void Function(Transaction txn) onCommit,
    void Function() onFinish = _noop,
  })  : _writtenSeqOf = writtenSeqOf,
        _onCommit = onCommit,
        _onFinish = onFinish;

  static void _noop() {}

  final Snapshot snapshot;
  final Isolation isolation;
  final int Function(String key) _writtenSeqOf;
  final void Function(Transaction txn) _onCommit;

  /// Run once, when the transaction commits or aborts. The engine uses it to
  /// stop recording per-key write sequences once no transaction can read them.
  final void Function() _onFinish;

  final List<TxnWrite> writes = [];
  final Set<String> _readSet = {};
  final List<int> _savepoints = [];

  bool _done = false;
  bool get isDone => _done;

  static String keyOf(int treeId, List<int> cke) {
    final sb = StringBuffer()..write(treeId)..write(':');
    for (final b in cke) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  void _checkWritable() {
    if (_done) throw const InvalidArgumentException('transaction is finished');
    if (isolation == Isolation.readOnly) {
      throw const InvalidArgumentException(
          'a read-only transaction cannot write');
    }
  }

  void put(int treeId, Uint8List cke, Uint8List value) {
    _checkWritable();
    writes.add(TxnWrite(treeId, cke, value, false));
  }

  void remove(int treeId, Uint8List cke) {
    _checkWritable();
    writes.add(TxnWrite(treeId, cke, Uint8List(0), true));
  }

  /// Records a key this transaction read, for [Isolation.serializable].
  void observed(int treeId, List<int> cke) {
    if (isolation == Isolation.serializable) {
      _readSet.add(keyOf(treeId, cke));
    }
  }

  /// Marks a point that [rollbackTo] can discard back to, §3.
  int savepoint() {
    _checkWritable();
    _savepoints.add(writes.length);
    return _savepoints.length - 1;
  }

  /// Discards buffered entries after a mark, §3.
  ///
  /// Free, and it leaves no trace: nothing durable exists yet.
  void rollbackTo(int savepoint) {
    _checkWritable();
    if (savepoint < 0 || savepoint >= _savepoints.length) {
      throw InvalidArgumentException('no savepoint $savepoint');
    }
    writes.removeRange(_savepoints[savepoint], writes.length);
    _savepoints.removeRange(savepoint + 1, _savepoints.length);
  }

  /// The keys this transaction would write.
  Set<String> get writeSet =>
      {for (final w in writes) keyOf(w.treeId, w.cke)};

  /// §3: compares the transaction's written key set against keys written by
  /// batches with `seq` in `(start_seq, commit_seq)`.
  ///
  /// A [Isolation.serializable] transaction additionally validates its read
  /// set, which is the only difference between the two levels here.
  void validate() {
    if (isolation == Isolation.readOnly) return;
    for (final key in writeSet) {
      final seq = _writtenSeqOf(key);
      if (seq > snapshot.seq) {
        throw ConflictException(
            'write-write conflict: $key was written at seq $seq, after this '
            'transaction began at seq ${snapshot.seq}',
            key: key);
      }
    }
    if (isolation == Isolation.serializable) {
      for (final key in _readSet) {
        final seq = _writtenSeqOf(key);
        if (seq > snapshot.seq) {
          throw ConflictException(
              'read-write conflict: $key was read at seq ${snapshot.seq} and '
              'written at seq $seq',
              key: key);
        }
      }
    }
  }

  void commit() {
    if (_done) throw const InvalidArgumentException('transaction is finished');
    validate();
    _onCommit(this);
    _finish();
  }

  /// §3: "Value-log records written by a transaction that then aborts are
  /// garbage, not corruption: nothing points at them, and GC reclaims them."
  /// Nothing is written before [commit] here, so an abort is a discard.
  void abort() {
    writes.clear();
    _finish();
  }

  void _finish() {
    if (!_done) {
      _done = true;
      _onFinish();
    }
  }
}
