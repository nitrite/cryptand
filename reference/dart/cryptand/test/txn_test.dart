/// `spec/10-transactions.md` — snapshots, transactions, retention, backpressure.
///
/// **What this file cannot test, stated first.** §2 is the concurrent write
/// protocol, and Dart has no shared-memory threads: `N` writers contending on
/// one counter cannot be exercised here at all, and prediction P3 cannot be
/// measured here. This implementation therefore declares
/// `Level 0 (single-writer)`, which `spec/11-conformance.md` §1.1 defines.
///
/// Everything below is independent of thread count — and it is the half where
/// a database returns *wrong answers* rather than slow ones.
library;

import 'dart:typed_data';

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/txn.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

import '../bench/harness.dart';

const int tree = 17;

Uint8List doc(NameDict d, int i) => encodeValue(benchDoc(i), dict: d);

void main() {
  late NameDict dict;
  setUp(() => dict = benchDict());

  group('snapshots, section 1', () {
    test('a snapshot carries all nine roots, not a subset', () {
      // Section 1: "A snapshot that omits one is not a consistent view of the
      // database: a reader restored to it would see the current change feed
      // against an older manifest."
      final e = Engine(memtableEntries: 100);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.flush();
      final s = e.snapshot();
      expect(s.seq, e.visibleSeq);
      expect(s.commitId, e.commitId);
      expect(s.manifestRoot, e.manifest.root);
      // Every field of the tuple exists, including the ones this
      // implementation does not yet populate.
      expect(
          [
            s.catalogRoot, s.freelistRoot, s.attributesRoot, s.manifestRoot,
            s.vlogStatsRoot, s.checkpointRoot, s.changefeedRoot,
          ].length,
          7);
    });

    test('a read at a snapshot does not see later writes', () {
      final e = Engine(memtableEntries: 10);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.flush();
      final s = e.snapshot();

      e.put(tree, const CNitriteId(1), doc(dict, 2));
      e.flush();

      expect(e.get(tree, const CNitriteId(1)), doc(dict, 2),
          reason: 'a reader with no snapshot sees the latest');
      expect(e.get(tree, const CNitriteId(1), at: s), doc(dict, 1),
          reason: 'the snapshot reader still sees its own version');
      e.release(s);
    });

    test('a key created after the snapshot is invisible to it', () {
      final e = Engine(memtableEntries: 10);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.flush();
      final s = e.snapshot();
      e.put(tree, const CNitriteId(2), doc(dict, 2));
      e.flush();
      expect(e.get(tree, const CNitriteId(2), at: s), isNull);
      expect(e.get(tree, const CNitriteId(2)), isNotNull);
      e.release(s);
    });

    test('a delete after the snapshot does not hide the row from it', () {
      final e = Engine(memtableEntries: 10);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.flush();
      final s = e.snapshot();
      e.remove(tree, const CNitriteId(1));
      e.flush();
      expect(e.get(tree, const CNitriteId(1)), isNull);
      expect(e.get(tree, const CNitriteId(1), at: s), doc(dict, 1));
      e.release(s);
    });

    test('a scan honours the snapshot too', () {
      final e = Engine(memtableEntries: 50, vlogMin: 1024);
      for (var i = 0; i < 20; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush();
      final s = e.snapshot();
      for (var i = 20; i < 40; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush();
      expect(e.scanTree(tree).length, 40);
      expect(e.scanTree(tree, at: s).length, 20);
      e.release(s);
    });
  });

  group('retention, sections 5 and 8', () {
    test('a live snapshot stops compaction collapsing its versions', () {
      // Section 5 condition 2: a version may be dropped only when the version
      // superseding it is at or below the oldest live snapshot's seq. Without
      // that, a long-running reader's next lookup returns a NEWER row than its
      // own snapshot -- the same class of wrong answer as resolving a point
      // read by segment order.
      final e = Engine(memtableEntries: 10, vlogMin: 1024);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.flush();
      final s = e.snapshot();

      for (var v = 2; v < 12; v++) {
        e.put(tree, const CNitriteId(1), doc(dict, v));
        e.flush();
      }
      e.compact();

      expect(e.get(tree, const CNitriteId(1), at: s), doc(dict, 1),
          reason: 'compaction must not have dropped the pinned version');
      expect(e.get(tree, const CNitriteId(1)), doc(dict, 11));

      // Once released, the same compaction may collapse them.
      e.release(s);
      e.compact();
      expect(e.get(tree, const CNitriteId(1)), doc(dict, 11));
    });

    test('a tombstone survives a snapshot older than itself', () {
      // Section 5: "if a snapshot older than the tombstone is live, the
      // versions the tombstone hides cannot be dropped, so dropping the
      // tombstone alone would resurrect them for every reader at or after the
      // delete."
      final e = Engine(memtableEntries: 10, vlogMin: 1024);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.flush();
      final s = e.snapshot();
      e.remove(tree, const CNitriteId(1));
      e.flush();
      e.compact();
      expect(e.get(tree, const CNitriteId(1)), isNull,
          reason: 'the delete must not be resurrected');
      expect(e.get(tree, const CNitriteId(1), at: s), doc(dict, 1));
      e.release(s);
    });

    test('the watermarks track the oldest live snapshot', () {
      final e = Engine(memtableEntries: 10);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.flush();
      final early = e.snapshot();
      final earlySeq = early.seq;

      e.put(tree, const CNitriteId(2), doc(dict, 2));
      e.flush();
      final late_ = e.snapshot();

      expect(e.minRetainedSeq, earlySeq);
      expect(e.liveSnapshotCount, 2);
      e.release(early);
      expect(e.minRetainedSeq, late_.seq);
      e.release(late_);
      expect(e.minRetainedSeq, e.visibleSeq);
    });

    test('pinned space is reported, and the warning has a threshold', () {
      final e = Engine(memtableEntries: 100, vlogMin: 128)
        ..snapshotPinWarningBytes = 1024;
      for (var i = 0; i < 300; i++) {
        e.put(tree, CNitriteId(i % 20), doc(dict, i));
      }
      final s = e.snapshot();
      for (var i = 300; i < 600; i++) {
        e.put(tree, CNitriteId(i % 20), doc(dict, i));
      }
      e.compact();
      expect(e.pinnedBySnapshots, greaterThan(0),
          reason: 'versions the snapshot entitles it to see are still held');
      expect(e.snapshotPinExceeded, isTrue);
      e.release(s);
      e.compact();
      expect(e.pinnedBySnapshots, 0,
          reason: 'released, the next compaction collapses them');
    });

    test('oldest_snapshot_age_ms is exposed', () {
      final e = Engine();
      expect(e.oldestSnapshotAgeMs(1000), 0);
      final s = e.snapshot(nowMs: 400);
      expect(e.oldestSnapshotAgeMs(1000), 600);
      e.release(s);
    });
  });

  group('transactions, section 3', () {
    Uint8List k(int id) => Uint8List.fromList([id]);

    test('writes are invisible until commit and land atomically', () {
      final e = Engine(memtableEntries: 100);
      final t = e.begin();
      t.put(tree, k(1), Uint8List.fromList([10]));
      t.put(tree, k(2), Uint8List.fromList([20]));
      expect(e.scanTree(tree).length, 0, reason: 'nothing durable before commit');
      t.commit();
      expect(e.scanTree(tree).length, 2);
    });

    test('an abort leaves no trace', () {
      // Section 3: "Nothing durable is written before sequencing, so rollback
      // is free and leaves no trace -- unlike the undo-log approach all three
      // SDKs use today, which writes and then reverses."
      final e = Engine(memtableEntries: 100);
      final t = e.begin();
      t.put(tree, k(1), Uint8List.fromList([10]));
      t.abort();
      expect(e.scanTree(tree), isEmpty);
      expect(t.isDone, isTrue);
    });

    test('savepoints discard buffered entries after a mark', () {
      final e = Engine(memtableEntries: 100);
      final t = e.begin();
      t.put(tree, k(1), Uint8List.fromList([1]));
      final mark = t.savepoint();
      t.put(tree, k(2), Uint8List.fromList([2]));
      t.put(tree, k(3), Uint8List.fromList([3]));
      expect(t.writes.length, 3);
      t.rollbackTo(mark);
      expect(t.writes.length, 1);
      t.commit();
      expect(e.scanTree(tree).length, 1);
    });

    test('a write-write conflict aborts the later transaction', () {
      final e = Engine(memtableEntries: 100);
      e.put(tree, const CNitriteId(1), Uint8List.fromList([0]));
      e.flush();

      final a = e.begin();
      a.put(tree, encodeKeyOf(1), Uint8List.fromList([1]));

      // Another writer commits the same key in between.
      e.put(tree, const CNitriteId(1), Uint8List.fromList([2]));
      e.flush();

      expect(a.commit, throwsA(isA<ConflictException>()));
    });

    test('disjoint transactions do not conflict', () {
      final e = Engine(memtableEntries: 100);
      final a = e.begin();
      a.put(tree, encodeKeyOf(1), Uint8List.fromList([1]));
      e.put(tree, const CNitriteId(99), Uint8List.fromList([2]));
      e.flush();
      expect(a.commit, returnsNormally);
    });

    test('serializable also validates the read set', () {
      final e = Engine(memtableEntries: 100);
      e.put(tree, const CNitriteId(1), Uint8List.fromList([0]));
      e.flush();

      final t = e.begin(isolation: Isolation.serializable);
      t.observed(tree, encodeKeyOf(1)); // read it
      t.put(tree, encodeKeyOf(2), Uint8List.fromList([9])); // wrote something else

      e.put(tree, const CNitriteId(1), Uint8List.fromList([5]));
      e.flush();

      expect(t.commit, throwsA(isA<ConflictException>()));
    });

    test('snapshot isolation ignores a read-set collision', () {
      final e = Engine(memtableEntries: 100);
      e.put(tree, const CNitriteId(1), Uint8List.fromList([0]));
      e.flush();
      final t = e.begin();
      t.observed(tree, encodeKeyOf(1));
      t.put(tree, encodeKeyOf(2), Uint8List.fromList([9]));
      e.put(tree, const CNitriteId(1), Uint8List.fromList([5]));
      e.flush();
      expect(t.commit, returnsNormally);
    });

    test('a read-only transaction cannot write and never conflicts', () {
      final e = Engine(memtableEntries: 100);
      final t = e.begin(isolation: Isolation.readOnly);
      expect(() => t.put(tree, k(1), Uint8List(1)),
          throwsA(isA<InvalidArgumentException>()));
      e.put(tree, const CNitriteId(1), Uint8List.fromList([1]));
      e.flush();
      expect(t.commit, returnsNormally);
    });
  });

  group('the commit protocol, section 2.3', () {
    test('visible_seq advancing is the commit', () {
      final e = Engine(memtableEntries: 1000);
      final before = e.visibleSeq;
      e.put(tree, const CNitriteId(1), Uint8List.fromList([1]));
      expect(e.visibleSeq, before,
          reason: 'an unflushed record is above the watermark');
      final id = e.commit();
      expect(e.visibleSeq, greaterThan(before));
      expect(id, e.commitId);
    });

    test('the value log is sealed before anything names its records', () {
      // Section 2.3 invariant 1: a superblock MUST NOT name a segment whose
      // value-log records are not already durable. The observable form of
      // that here is ordering: sealOpen precedes the segment build.
      final e = Engine(memtableEntries: 1000, vlogMin: 64);
      for (var i = 0; i < 50; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.commit();
      for (final seg in e.vlog.segments.values) {
        expect(seg.sealed, isTrue,
            reason: 'every value-log segment named by a commit is sealed');
      }
      for (var i = 0; i < 50; i++) {
        expect(e.get(tree, CNitriteId(i)), doc(dict, i));
      }
    });

    test('durability records what was performed, not what was asked', () {
      // Section 7, and spec/00-conventions.md section 1.1: the obligation is
      // language-neutral and the record must be honest. There is no file under
      // this implementation, so `none` is the truthful answer whatever the
      // caller requests.
      final e = Engine(memtableEntries: 10);
      e.put(tree, const CNitriteId(1), Uint8List.fromList([1]));
      e.commit(durability: Durability.full);
      expect(e.durabilityAchieved, Durability.none);
    });
  });

  group('backpressure, section 6 — the normative curve', () {
    test('delay is max_delay * x^2 over the worst overshoot', () {
      const b = Bound('t', 6, 4, 8); // halfway between soft and hard
      expect(b.overshoot, closeTo(0.5, 1e-9));
      final p = Backpressure.compute([b]);
      expect(p.delayMs, closeTo(100 * 0.25, 1e-9));
      expect(p.cause, 't');
    });

    test('inside the soft bound there is no delay', () {
      expect(Backpressure.compute([const Bound('t', 3, 4, 8)]).delayMs, 0);
      expect(Backpressure.compute([const Bound('t', 4, 4, 8)]).delayMs, 0);
    });

    test('at and past the hard bound the delay saturates', () {
      expect(Backpressure.compute([const Bound('t', 8, 4, 8)]).delayMs, 100);
      expect(Backpressure.compute([const Bound('t', 800, 4, 8)]).delayMs, 100);
    });

    test('the worst bound wins and is named', () {
      final p = Backpressure.compute(const [
        Bound('mild', 5, 4, 8),
        Bound('bad', 7, 4, 8),
      ]);
      expect(p.cause, 'bad');
      expect(p.delayMs, closeTo(100 * 0.75 * 0.75, 1e-9));
    });

    test('the curve is quadratic, not linear — imperceptible while merely busy',
        () {
      // Section 6's whole point: gentle early, firm late. At a quarter of the
      // way into the band the delay is a sixteenth of the maximum.
      final quarter = Backpressure.compute([const Bound('t', 5, 4, 8)]).delayMs;
      final threeQ = Backpressure.compute([const Bound('t', 7, 4, 8)]).delayMs;
      expect(quarter, closeTo(100 / 16, 1e-9));
      expect(threeQ / quarter, closeTo(9, 1e-9));
    });

    test('the engine exposes every bound section 6 lists', () {
      final e = Engine(memtableEntries: 100);
      final names = e.bounds.map((b) => b.name).toList();
      expect(names, contains('l0_segment_count'));
      expect(names, contains('memtable_entries'));
      expect(names, contains('vlog_space_amplification'));
      expect(names, contains('locality_debt'));
      expect(e.backpressure.delayMs, 0);
    });
  });

  group('store events, section 9', () {
    test('a commit emits after durability, carrying the new watermarks', () {
      final e = Engine(memtableEntries: 1000);
      e.put(tree, const CNitriteId(1), Uint8List.fromList([1]));
      e.commit();
      final commits =
          e.events.where((x) => x.kind == StoreEventKind.commit).toList();
      expect(commits, hasLength(1));
      expect(commits.single.commitId, e.commitId);
      expect(commits.single.visibleSeq, e.visibleSeq);
      // The flush that produced the segment precedes the commit event.
      expect(e.events.map((x) => x.kind).toList(),
          containsAllInOrder([StoreEventKind.flushed, StoreEventKind.commit]));
    });

    test('close emits closing then closed', () {
      final e = Engine(memtableEntries: 100);
      e.put(tree, const CNitriteId(1), Uint8List.fromList([1]));
      e.close();
      expect(e.isClosed, isTrue);
      expect(e.events.map((x) => x.kind).toList(),
          containsAllInOrder([StoreEventKind.closing, StoreEventKind.closed]));
      expect(() => e.commit(), throwsA(isA<InvalidArgumentException>()));
    });

    test('close is idempotent', () {
      final e = Engine()..close();
      final n = e.events.length;
      e.close();
      expect(e.events.length, n);
    });
  });
}

/// The CKE of a NitriteId, for building a transaction key by hand.
Uint8List encodeKeyOf(int id) => encodeKey(CNitriteId(id));
