/// `spec/04-segments.md` §2.5 (range deletes) and §9 (time to live).
///
/// Two of these are **mandatory conformance tests**
/// (`spec/11-conformance.md` §6):
///
///   * the range-delete-under-filter test — "a reader that filter-prunes that
///     segment resurrects a deleted key and fails";
///   * and the clock rule of §9, which is the one place this format
///     deliberately does *not* treat a surprise as corruption.
library;

import 'dart:typed_data';

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

import '../bench/harness.dart';

const int tree = 17;
Uint8List doc(NameDict d, int i) => encodeValue(benchDoc(i), dict: d);

void main() {
  late NameDict dict;
  setUp(() => dict = benchDict());

  group('range deletes, section 2.5', () {
    Engine seeded({int n = 40}) {
      final e = Engine(memtableEntries: 1000, vlogMin: 1024);
      for (var i = 0; i < n; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush();
      return e;
    }

    test('one write deletes a whole interval', () {
      // Section 2.5: this is what makes clear(), drop() and the rollback of a
      // bulk insert O(1) writes rather than O(n) tombstones.
      final e = seeded();
      e.removeRange(tree, const CNitriteId(10), const CNitriteId(20));
      e.flush();
      for (var i = 0; i < 40; i++) {
        final got = e.get(tree, CNitriteId(i));
        if (i >= 10 && i < 20) {
          expect(got, isNull, reason: 'id $i is inside the interval');
        } else {
          expect(got, isNotNull, reason: 'id $i is outside it');
        }
      }
      expect(e.scanTree(tree).length, 30);
    });

    test('the interval is half-open', () {
      final e = seeded();
      e.removeRange(tree, const CNitriteId(10), const CNitriteId(20));
      e.flush();
      expect(e.get(tree, const CNitriteId(10)), isNull, reason: 'start included');
      expect(e.get(tree, const CNitriteId(19)), isNull);
      expect(e.get(tree, const CNitriteId(20)), isNotNull,
          reason: 'end excluded');
    });

    test('a write after the range delete survives it', () {
      // Section 2.5: "an entry at seq' < seq whose key falls in the interval is
      // invisible" -- seq' < seq, not <=, and not every entry in the interval.
      final e = seeded();
      e.removeRange(tree, const CNitriteId(10), const CNitriteId(20));
      e.flush();
      e.put(tree, const CNitriteId(15), doc(dict, 999));
      e.flush();
      expect(e.get(tree, const CNitriteId(15)), doc(dict, 999));
      expect(e.get(tree, const CNitriteId(14)), isNull);
      expect(e.scanTree(tree).length, 31);
    });

    test('it survives compaction', () {
      final e = seeded();
      e.removeRange(tree, const CNitriteId(10), const CNitriteId(20));
      e.flush();
      e.compact();
      expect(e.scanTree(tree).length, 30);
      expect(e.get(tree, const CNitriteId(15)), isNull);
    });

    test('a snapshot older than the range delete still sees the rows', () {
      final e = seeded();
      final s = e.snapshot();
      e.removeRange(tree, const CNitriteId(10), const CNitriteId(20));
      e.flush();
      e.compact();
      expect(e.get(tree, const CNitriteId(15)), isNull);
      expect(e.get(tree, const CNitriteId(15), at: s), isNotNull,
          reason: 'the delete is newer than this snapshot');
      e.release(s);
    });

    test('start must be below end', () {
      final e = seeded();
      expect(() => e.removeRange(tree, const CNitriteId(20), const CNitriteId(10)),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => e.removeRange(tree, const CNitriteId(10), const CNitriteId(10)),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('MANDATORY: a range delete is not pruned by the segment filter', () {
      // spec/11-conformance.md section 6, and spec/04-segments.md section 4:
      // "The filter contains the segment's *point* keys; a RANGE_DELETE covers
      // keys that are not in it, so filtering a segment out loses the delete
      // and resurrects a deleted key."
      //
      // The construction that matters: the segment holding the range delete
      // must NOT hold the deleted key as a point key, so its filter would
      // answer "absent" for that key.
      final e = Engine(memtableEntries: 1000, vlogMin: 1024);
      for (var i = 0; i < 40; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush(); // segment A: the point keys

      e.removeRange(tree, const CNitriteId(10), const CNitriteId(20));
      e.flush(); // segment B: the range delete, and NO point key of 10..19

      final withRd = e.extents.values
          .where((s) => s.header.hasRangeDeletes)
          .toList();
      expect(withRd, hasLength(1), reason: 'exactly one segment carries one');
      final b = withRd.single;

      // The filter genuinely does not contain the deleted keys -- which is
      // what makes this test a test.
      final probe = userKeyPrefix(tree, encodeKeyOf(15));
      expect(b.filter, isNotNull);
      expect(b.filter!.mayContain(probe), isFalse,
          reason: 'the filter would prune this segment on a point probe');

      // And the key is still deleted.
      expect(e.get(tree, const CNitriteId(15)), isNull,
          reason: 'filter-pruning segment B would resurrect id 15');
      expect(e.rangeDeletesFor(probe), hasLength(1));
    });

    test('the range-delete summary is only built when the flag is set', () {
      // Section 4 SHOULDs an in-memory summary "so rd_sources is normally
      // empty after an in-memory test rather than after a page read".
      final e = seeded();
      for (final s in e.extents.values) {
        expect(s.header.hasRangeDeletes, isFalse);
        expect(s.rangeDeletes, isEmpty);
      }
    });
  });

  group('time to live, section 9', () {
    test('an expired entry is invisible, exactly as a DELETE', () {
      final e = Engine(memtableEntries: 1000, vlogMin: 1024)..nowMs = 1000;
      e.put(tree, const CNitriteId(1), doc(dict, 1), expiryMs: 2000);
      e.put(tree, const CNitriteId(2), doc(dict, 2)); // no expiry
      e.flush();

      expect(e.get(tree, const CNitriteId(1)), isNotNull);
      e.nowMs = 2000; // "at or before" -- the deadline itself expires it
      expect(e.get(tree, const CNitriteId(1)), isNull);
      expect(e.get(tree, const CNitriteId(2)), isNotNull);
      expect(e.scanTree(tree).length, 1);
    });

    test('expiry is evaluated at read time, so it is exact', () {
      // Section 9: "Expiry is evaluated at read time, so it is exact
      // regardless of when compaction runs."
      final e = Engine(memtableEntries: 1000, vlogMin: 1024)..nowMs = 1000;
      e.put(tree, const CNitriteId(1), doc(dict, 1), expiryMs: 5000);
      e.flush();
      e.compact(); // compaction runs long before the deadline
      expect(e.get(tree, const CNitriteId(1)), isNotNull);
      e.nowMs = 5001;
      expect(e.get(tree, const CNitriteId(1)), isNull,
          reason: 'no sweeper ran, and it is still exactly expired');
    });

    test('a backwards clock jump resurrects entries, it is not corruption', () {
      // Section 9, and this is deliberate: "An implementation MUST NOT use
      // expiry to enforce anything security relevant, and MUST treat a
      // backwards clock jump as resurrecting entries rather than as
      // corruption."
      final e = Engine(memtableEntries: 1000, vlogMin: 1024)..nowMs = 1000;
      e.put(tree, const CNitriteId(1), doc(dict, 1), expiryMs: 2000);
      e.flush();
      e.nowMs = 3000;
      expect(e.get(tree, const CNitriteId(1)), isNull);
      e.nowMs = 1500; // the clock went backwards
      expect(e.get(tree, const CNitriteId(1)), doc(dict, 1),
          reason: 'resurrected, and no error raised');
    });

    test('compaction reclaims an expired entry once it is safe to', () {
      final e = Engine(memtableEntries: 1000, vlogMin: 1024)..nowMs = 1000;
      for (var i = 0; i < 20; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i), expiryMs: 2000);
      }
      e.put(tree, const CNitriteId(99), doc(dict, 99));
      e.flush();
      e.nowMs = 3000;
      e.compact();
      expect(e.scanTree(tree).length, 1);
      // The entries are gone from the segments, not merely hidden.
      var live = 0;
      for (final s in e.extents.values) {
        live += s.header.entryCount;
      }
      expect(live, 1, reason: 'expired entries were dropped, not just hidden');
    });

    test('a snapshot taken before the deadline still sees the entry', () {
      // Section 5: an expired entry may be dropped only when "its deadline is
      // older than the oldest live snapshot's wall-clock floor".
      final e = Engine(memtableEntries: 1000, vlogMin: 1024)..nowMs = 1000;
      e.put(tree, const CNitriteId(1), doc(dict, 1), expiryMs: 2000);
      e.flush();
      final s = e.snapshot(nowMs: 1000);
      e.nowMs = 3000;
      e.compact();
      var live = 0;
      for (final x in e.extents.values) {
        live += x.header.entryCount;
      }
      expect(live, 1, reason: 'the pinned entry must survive compaction');
      e.release(s);
    });

    test('min_expiry is recorded so a picker can prefer expiring segments', () {
      final e = Engine(memtableEntries: 1000, vlogMin: 1024)..nowMs = 1000;
      e.put(tree, const CNitriteId(1), doc(dict, 1), expiryMs: 9000);
      e.put(tree, const CNitriteId(2), doc(dict, 2), expiryMs: 4000);
      e.flush();
      final seg = e.extents.values.single;
      expect(seg.header.minExpiry, 4000);
      expect(seg.header.flags & SegFlags.hasTtl, isNot(0));
    });
  });
}

Uint8List encodeKeyOf(int id) => encodeKey(CNitriteId(id));
