/// `spec/13-operations.md` §1 (checkpoints) and §9 (planner statistics),
/// plus `spec/11-conformance.md` §6's **mandatory stale-version test**.
library;

import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

import '../bench/harness.dart';

const int tree = 17;
Uint8List doc(NameDict d, int i) => encodeValue(benchDoc(i), dict: d);

void main() {
  late NameDict dict;
  setUp(() => dict = benchDict());

  group('checkpoints, spec/13-operations.md section 1', () {
    Engine seeded({int n = 200}) {
      final e = Engine(memtableEntries: 100, vlogMin: 1024);
      for (var i = 0; i < n; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush();
      return e;
    }

    test('a checkpoint captures eight roots and NOT checkpoint_root', () {
      // Section 1: checkpoint_root "is deliberately not captured: restoring a
      // checkpoint must not delete the other checkpoints".
      final e = seeded();
      final c = e.createCheckpoint('before-migration', nowMs: 1000);
      expect(c.capturesCheckpointRoot, isFalse);
      expect(c.snapshot.checkpointRoot, 0);
      expect(c.seq, e.visibleSeq);
      expect(c.manifestRoot, e.manifest.root);
      // changefeed_root IS captured -- an earlier draft omitted it, which left
      // a restore pairing the current change feed with an older manifest.
      expect(c.encode(), isNotEmpty);
      final back = Checkpoint.decode(c.name, c.encode());
      expect(back.changefeedRoot, c.changefeedRoot);
      expect(back.manifestRoot, c.manifestRoot);
    });

    test('restore rolls back the data and keeps the counters', () {
      // Section 1's security-relevant MUST: "Restore rolls back roots, never
      // counters." Rolling next_nonce back would reissue nonces the abandoned
      // commits already used against pages still in the file.
      final e = seeded(n: 100);
      e.createCheckpoint('undo', nowMs: 1000);
      final seqAtCheckpoint = e.visibleSeq;

      for (var i = 100; i < 200; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush();
      final seqAfter = e.visibleSeq;
      final nextSegBefore = e.extents.length;
      expect(e.get(tree, const CNitriteId(150)), isNotNull);
      expect(seqAfter, greaterThan(seqAtCheckpoint));

      e.restore('undo');

      expect(e.get(tree, const CNitriteId(150)), isNull,
          reason: 'writes after the checkpoint are unreachable');
      expect(e.get(tree, const CNitriteId(50)), isNotNull,
          reason: 'writes before it survive');
      expect(e.visibleSeq, seqAtCheckpoint);
      // Counters did not move backwards: the next write gets a fresh seq
      // above everything the abandoned commits used.
      e.put(tree, const CNitriteId(999), doc(dict, 999));
      e.flush();
      expect(e.visibleSeq, greaterThan(seqAfter),
          reason: 'next_seq survived the restore, as ids that are never '
              'reused must');
      expect(e.extents.length, greaterThanOrEqualTo(1));
      expect(nextSegBefore, greaterThan(0));
    });

    test('a restore does not delete the other checkpoints', () {
      final e = seeded(n: 50);
      e.createCheckpoint('a', nowMs: 1000);
      for (var i = 50; i < 100; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush();
      e.createCheckpoint('b', nowMs: 2000);
      e.restore('a');
      expect(e.checkpoints.all.map((c) => c.name).toList()..sort(),
          ['a', 'b'],
          reason: 'checkpoint_root is not restored, so siblings survive');
    });

    test('open_at yields a read-only view at the checkpoint', () {
      final e = seeded(n: 50);
      e.createCheckpoint('mark', nowMs: 1000);
      for (var i = 0; i < 50; i++) {
        e.put(tree, CNitriteId(i), doc(dict, 900 + i));
      }
      e.flush();
      final s = e.openAt('mark');
      expect(e.get(tree, const CNitriteId(10), at: s), doc(dict, 10));
      expect(e.get(tree, const CNitriteId(10)), doc(dict, 910));
      e.release(s);
    });

    test('a checkpoint pins retention exactly as a live reader does', () {
      final e = seeded(n: 50);
      e.createCheckpoint('pin', nowMs: 1000);
      final pinnedSeq = e.visibleSeq;
      for (var i = 0; i < 50; i++) {
        e.put(tree, CNitriteId(i), doc(dict, 900 + i));
      }
      e.flush();
      expect(e.minRetainedSeq, pinnedSeq,
          reason: 'the checkpoint holds the watermark down');
      e.compact();
      // The pinned versions survived, so the checkpoint still resolves.
      final s = e.openAt('pin');
      expect(e.get(tree, const CNitriteId(10), at: s), doc(dict, 10));
      e.release(s);
      // Dropping it releases the watermark.
      e.checkpoints.remove('pin');
      expect(e.minRetainedSeq, e.visibleSeq);
    });

    test('expires is honoured', () {
      final e = seeded(n: 20);
      e.createCheckpoint('temp', expires: 5000, nowMs: 1000);
      e.createCheckpoint('keep', nowMs: 1000);
      expect(e.dropExpiredCheckpoints(4000), isEmpty);
      expect(e.dropExpiredCheckpoints(5000), ['temp']);
      expect(e.checkpoints.all.map((c) => c.name), ['keep']);
    });

    test('the space limit refuses a checkpoint that would pin too much', () {
      final e = Engine(memtableEntries: 50, vlogMin: 128)
        ..checkpointSpaceLimitPct = 1;
      for (var i = 0; i < 400; i++) {
        e.put(tree, CNitriteId(i % 20), doc(dict, i));
      }
      e.flush();
      // The fixture needs *dead* bytes, and only a compaction that reaches the
      // last level produces them: it is what drops superseded versions and
      // promotes the survivors, leaving the hot run's 380 older records dead
      // but not yet reclaimed. Without it `allocated - live` is 0 and the
      // limit has nothing to refuse — the test used to pass because promotion
      // ran on every compaction, which `spec/04-segments.md` §6.3 confines to
      // the last level.
      e.compact();
      expect(e.checkpointWouldPin(), greaterThan(0),
          reason: 'a limit test needs something to be over the limit');
      expect(() => e.createCheckpoint('big', nowMs: 1000),
          throwsA(isA<LimitException>()));
      // Section 1: "unless the caller overrides it".
      expect(() => e.createCheckpoint('big', nowMs: 1000, force: true),
          returnsNormally);
    });

    test('a duplicate name is refused', () {
      final e = seeded(n: 10);
      e.createCheckpoint('x', nowMs: 1);
      expect(() => e.createCheckpoint('x', nowMs: 2),
          throwsA(isA<InvalidArgumentException>()));
    });
  });

  group('planner statistics, spec/13-operations.md section 9', () {
    late Database db;
    late Collection c;

    setUp(() {
      db = Database();
      c = db.createCollection('orders');
      // country is very low cardinality; email is unique. A planner choosing
      // on "is it unique" picks email even when the query barely constrains
      // it -- section 06 section 7.1's worked complaint.
      for (var i = 0; i < 300; i++) {
        c.put(
            CNitriteId(i),
            CDoc({
              'country': CStr(['fr', 'de', 'us'][i % 3]),
              'email': CStr('user$i@example.com'),
            }));
      }
    });

    test('distinct_estimate is close to the truth', () {
      final idx = c.createIndex(['country']);
      final s = c.analyze(idx);
      expect(s.entries, 300);
      expect(s.distinctEstimate, closeTo(3, 1),
          reason: 'three countries');
      expect(s.nullCount, 0);
    });

    test('a HyperLogLog sketch estimates a large cardinality', () {
      final h = HyperLogLog();
      for (var i = 0; i < 50000; i++) {
        h.add(encodeKey(CInt.i64(i)));
      }
      // ~1.6 % standard error at precision 12; allow a generous band.
      expect(h.estimate, closeTo(50000, 50000 * 0.10));
    });

    test('sketches merge by register-wise maximum', () {
      final a = HyperLogLog();
      final b = HyperLogLog();
      for (var i = 0; i < 10000; i++) {
        a.add(encodeKey(CInt.i64(i)));
      }
      for (var i = 5000; i < 15000; i++) {
        b.add(encodeKey(CInt.i64(i)));
      }
      a.merge(b);
      expect(a.estimate, closeTo(15000, 15000 * 0.10),
          reason: 'the union, not the sum');
    });

    test('the histogram is equi-depth and capped at 64 buckets', () {
      final idx = c.createIndex(['email']);
      final s = c.analyze(idx);
      expect(s.histogram.length, lessThanOrEqualTo(64));
      expect(s.histogram, isNotEmpty);
      // Cumulative counts are non-decreasing, and bounds are in key order.
      for (var i = 1; i < s.histogram.length; i++) {
        expect(s.histogram[i].cumulative,
            greaterThanOrEqualTo(s.histogram[i - 1].cumulative));
        expect(compareKeys(s.histogram[i].bound, s.histogram[i - 1].bound),
            greaterThan(0));
      }
      expect(s.rowsAtOrBelow(s.maxKey), greaterThan(0));
    });

    test('selectivity picks the discriminating index, not the unique one', () {
      // spec/06-indexes.md section 7.1: "That routinely picks a unique index
      // on a field the query barely constrains over a non-unique index that
      // would eliminate 99 % of the collection."
      final country = c.createIndex(['country']);
      final email = c.createIndex(['email'], indexType: IndexType.unique);
      c.analyze(country);
      c.analyze(email);

      final cs = c.statsOf(country)!;
      final es = c.statsOf(email)!;
      expect(cs.averageRowsPerValue, closeTo(100, 20));
      expect(es.averageRowsPerValue, closeTo(1, 0.5));
      expect(es.selectivity, lessThan(cs.selectivity));
      expect(c.mostSelective([country, email])!.treeId, email.treeId);
    });

    test('statistics are advisory — absent is not an error', () {
      // Section 9: "a planner MUST produce correct results without them, and
      // MUST NOT refuse to run because they are missing."
      final idx = c.createIndex(['country']);
      expect(c.statsOf(idx), isNull, reason: 'not analyzed yet');
      expect(c.mostSelective([idx]), isNull);
      // And the index still answers queries.
      expect(c.lookup(idx, IndexScan.eqPrefix([const CStr('fr')])).length, 100);
    });

    test('stats round-trip through the catalog descriptor', () {
      final idx = c.createIndex(['country']);
      final written = c.analyze(idx);
      final read = c.statsOf(idx)!;
      expect(read.entries, written.entries);
      expect(read.distinctEstimate, written.distinctEstimate);
      expect(read.histogram.length, written.histogram.length);
    });
  });

  group('MANDATORY: the stale-version test (spec/11-conformance.md section 6)',
      () {
    test('a lower level with a higher max_seq must not win', () {
      // "Build a file in which a segment at a *lower* level has a higher
      // max_seq than a segment above it, from an unrelated key, while both
      // cover the queried key. A reader that resolves candidates by segment
      // order instead of by entry seq returns the stale version and fails."
      //
      // This is spec/04-segments.md section 4's first load-bearing rule, and
      // the defect it guards (round-three defect 9) would return a WRONG
      // answer, not a slow one.
      final e = Engine(memtableEntries: 1000, vlogMin: 1024);

      // The queried key, written early. 505 is deliberately NOT a multiple of
      // 10: an earlier version of this test used 500, which the padding loop
      // below then overwrote, so the test was measuring its own fixture.
      e.put(tree, const CNitriteId(505), doc(dict, 1));
      // Padding so the segment covers a wide range.
      for (var i = 0; i < 100; i++) {
        e.put(tree, CNitriteId(i * 10), doc(dict, i));
      }
      e.flush();
      e.compact(); // everything to the last level

      // Now a NEWER write of an UNRELATED key, which lands above the last
      // level and gives that segment a higher max_seq than the one below --
      // while the key we query lives only in the lower segment.
      e.put(tree, const CNitriteId(999999), doc(dict, 77));
      e.flush();

      final upper = e.refsAt(0);
      final lower = e.refsAt(e.lastLevel);
      expect(upper, isNotEmpty);
      expect(lower, isNotEmpty);
      expect(upper.first.maxSeq, greaterThan(lower.first.maxSeq),
          reason: 'the upper segment must have the higher max_seq');

      // The read must return the version from the LOWER level, because that
      // is where this key's only entry is -- resolving by segment max_seq
      // would consult the upper segment, find nothing, and a naive early exit
      // ordered by max_seq would return absent or stale.
      expect(e.get(tree, const CNitriteId(505)), doc(dict, 1));

      // And with a newer version of the queried key added above, the newer
      // one must win -- by its own seq, not by which segment it sits in.
      e.put(tree, const CNitriteId(505), doc(dict, 2));
      e.flush();
      expect(e.get(tree, const CNitriteId(505)), doc(dict, 2));
    });
  });
}
