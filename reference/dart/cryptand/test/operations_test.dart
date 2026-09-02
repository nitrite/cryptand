/// `spec/13-operations.md` §4 (corruption containment) and §6 (required
/// metrics).
///
/// §4 is a **mandatory conformance test** (`spec/11-conformance.md` §6):
/// "Corrupt one page of a mid-level segment; the database MUST still open,
/// MUST still serve every key outside that segment's range, and MUST name the
/// affected range."
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

  group('corruption containment, section 4', () {
    /// A database with several last-level segments, so quarantining one leaves
    /// most of the key space intact -- which is the property under test.
    Engine seeded() {
      // Small segments so the last level holds several of them: containment
      // is only observable when there is something left to serve.
      final e = Engine(
          memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      for (var i = 0; i < 2000; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.compact();
      return e;
    }

    test('MANDATORY: one damaged page does not make the database unreadable',
        () {
      final e = seeded();
      final refs = e.refsAt(e.lastLevel);
      expect(refs.length, greaterThan(2),
          reason: 'the test needs more than one segment to contain anything');

      // Corrupt a page in the middle of one segment, the way a bad block would.
      final victim = refs[refs.length ~/ 2];
      e.extents[victim.segmentId]!.extent[victim.pages ~/ 2 * 4096 + 100] ^= 0xFF;

      // Step 1 and 2: verification finds it and names the affected range.
      final bad = e.verify();
      expect(bad, hasLength(1));
      expect(bad.single.segmentId, victim.segmentId);
      expect(bad.single.minKey, isNotEmpty);
      expect(bad.single.maxKey, isNotEmpty);

      // Step 3: every key outside the range is still served.
      var served = 0;
      var refused = 0;
      for (var i = 0; i < 2000; i++) {
        try {
          if (e.get(tree, CNitriteId(i)) != null) served++;
        } on UnavailableRangeException {
          refused++;
        }
      }
      expect(served, greaterThan(0));
      expect(refused, greaterThan(0));
      expect(served + refused, 2000);
      expect(served, greaterThan(refused),
          reason: 'containment, not collapse: most of the database survives');
    });

    test('a read inside the range fails specifically, never emptily', () {
      // Step 4: "fail reads that land inside it with a specific corruption
      // error naming the range, never with a wrong or empty answer." Returning
      // null would be the dangerous behaviour -- indistinguishable from "the
      // key was deleted".
      final e = seeded();
      final victim = e.refsAt(e.lastLevel)[1];
      e.extents[victim.segmentId]!.extent[4096 + 100] ^= 0xFF;
      e.verify();

      var sawSpecificError = false;
      for (var i = 0; i < 2000; i++) {
        try {
          e.get(tree, CNitriteId(i));
        } on UnavailableRangeException catch (ex) {
          sawSpecificError = true;
          expect(ex.segmentId, victim.segmentId);
          expect(ex.message, contains('unavailable'));
          expect(ex.treeIds, contains(tree));
          break;
        }
      }
      expect(sawSpecificError, isTrue);
    });

    test('the affected trees are named, for step 5', () {
      // Step 5: "mark the affected trees so that a query planner does not
      // silently substitute an index scan that would return incomplete
      // results."
      final e = seeded();
      expect(e.affectedTrees, isEmpty);
      final victim = e.refsAt(e.lastLevel).first;
      e.extents[victim.segmentId]!.extent[4096 + 100] ^= 0xFF;
      e.verify();
      expect(e.affectedTrees, contains(tree));
    });

    test('a clean database quarantines nothing', () {
      final e = seeded();
      expect(e.verify(), isEmpty);
      expect(e.quarantined, isEmpty);
      expect(e.affectedTrees, isEmpty);
    });

    test('the affected range is knowable without touching the extent', () {
      // What makes containment cheap: min_key/max_key come from the manifest,
      // so the range can be reported even though the segment cannot be read.
      final e = seeded();
      final victim = e.refsAt(e.lastLevel).first;
      final ref = e.quarantine(victim.segmentId);
      expect(ref.minKey, victim.minKey);
      expect(ref.maxKey, victim.maxKey);
    });
  });

  group('required metrics, section 6', () {
    test('every metric the chapter names is present', () {
      // Section 6 is normative: "An implementation MUST expose the following."
      final e = Engine(memtableEntries: 100, vlogMin: 128);
      for (var i = 0; i < 500; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.compact();
      e.get(tree, const CNitriteId(1));
      final m = e.metrics().toMap();
      for (final key in Metrics.requiredKeys) {
        expect(m.containsKey(key), isTrue, reason: 'missing metric: $key');
        expect(m[key], isNotNull, reason: 'null metric: $key');
      }
    });

    test('locality_debt is the run-based definition', () {
      // Section 6: "it has to be the run-based definition: the earlier
      // flag-based one read 0 % on a database whose scans had already degraded
      // 2.1x."
      final e = Engine(memtableEntries: 100, vlogMin: 128);
      for (var i = 0; i < 400; i++) {
        e.put(tree, CNitriteId(i % 50), doc(dict, i));
      }
      e.compact();
      final m = e.metrics();
      expect(m.localityDebt, e.vlog.localityDebt);
      expect(m.vlogLiveRuns, greaterThan(0));
      expect(m.vlogIdealRuns, greaterThan(0));
    });

    test('space amplification is derivable and sane', () {
      final e = Engine(memtableEntries: 100, vlogMin: 128);
      for (var i = 0; i < 300; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.compact();
      expect(e.metrics().spaceAmplification, greaterThanOrEqualTo(1.0));
    });

    test('unencrypted_pages gates the encryption claim', () {
      // Section 6: "An implementation MUST NOT report a database as encrypted
      // while this is above 0."
      final e = Engine();
      expect(e.metrics().unencryptedPages, 0);
      expect(e.metrics().claimsEncryptionFalsely, isFalse);
    });

    test('segments_probed_per_lookup is reported at p50 and p99', () {
      final e = Engine(memtableEntries: 100, vlogMin: 1024);
      for (var i = 0; i < 500; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.flush();
      e.resetCounters();
      for (var i = 0; i < 200; i++) {
        e.get(tree, CNitriteId(i));
      }
      final m = e.metrics();
      expect(m.segmentsProbedP50, greaterThanOrEqualTo(0));
      expect(m.segmentsProbedP99, greaterThanOrEqualTo(m.segmentsProbedP50));
    });

    test('backpressure reports its cause alongside its delay', () {
      final e = Engine(memtableEntries: 100);
      final m = e.metrics();
      expect(m.backpressureDelayMs, 0);
      // With no overshoot there is no cause to name.
      expect(m.backpressureCause, isNull);
    });

    test('unavailable_ranges surfaces containment in the metrics', () {
      final e = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      for (var i = 0; i < 1000; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      e.compact();
      expect(e.metrics().unavailableRanges, 0);
      final victim = e.refsAt(e.lastLevel).first;
      e.extents[victim.segmentId]!.extent[4096 + 100] ^= 0xFF;
      e.verify();
      expect(e.metrics().unavailableRanges, 1);
    });
  });
}
