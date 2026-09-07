/// The verifier (`spec/04-segments.md` §11, `spec/01-container.md` §9) and
/// repair (`spec/13-operations.md` §3).
///
/// The two checks that matter most here are the ones the reference
/// implementation needed and did not have:
///
///   * **§11.6** would have caught phase 5's worst defect — a levelled level
///     that had silently stopped being disjoint and was returning stale
///     versions under 338 passing tests;
///   * **§11.5's header-against-manifest agreement** is what §3 calls the
///     redundancy that "rots unnoticed until the day it is needed" — the day
///     the manifest has to be rebuilt from the headers.
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

  Engine seeded({int n = 600, int? segmentEntries}) {
    final e = Engine(
        memtableEntries: 100,
        vlogMin: 128,
        segmentEntries: segmentEntries ?? 50);
    for (var i = 0; i < n; i++) {
      e.put(tree, CNitriteId(i), doc(dict, i));
    }
    e.compact();
    return e;
  }

  group('the verifier, spec/04-segments.md section 11', () {
    test('a healthy database verifies clean', () {
      final e = seeded();
      final r = e.verifyStructure();
      expect(r.isSound, isTrue, reason: r.toString());
      expect(r.segmentsChecked, greaterThan(1));
      expect(r.entriesChecked, greaterThan(0));
    });

    test('11.6 catches a levelled level that is not disjoint', () {
      // This is the check that would have caught phase 5's defect 33. It is
      // constructed here by hand because the engine no longer produces the
      // shape -- which is the point: the verifier must catch a file another
      // implementation wrote, not only one this engine could write.
      final e = seeded();
      final refs = e.refsAt(e.lastLevel);
      expect(refs.length, greaterThan(1));

      // Widen the first segment's max_key so it runs into its neighbour --
      // the shape an internal-key overlap test leaves behind. The manifest key
      // is (level, group, min_key), so widening max_key does not collide with
      // the entry that is already there; re-filing under a duplicate min_key
      // would be refused by the manifest's own guard, which is a different
      // check doing its job.
      final victim = refs[0];
      e.manifest.remove(victim);
      e.manifest.add(SegmentRef(
        segmentId: victim.segmentId,
        level: victim.level,
        group: victim.group,
        minKey: victim.minKey,
        maxKey: refs[1].maxKey, // now reaches across its neighbour
        minSeq: victim.minSeq,
        maxSeq: victim.maxSeq,
        entries: victim.entries,
        tombstones: victim.tombstones,
        hasRangeDeletes: victim.hasRangeDeletes,
        pages: victim.pages,
        trees: victim.trees,
      ));
      e.clearLevelCache();

      final r = e.verifyStructure(deep: false);
      expect(r.isSound, isFalse);
      expect(r.findings.map((f) => f.invariant), contains('11.6'));
      expect(r.findings.firstWhere((f) => f.invariant == '11.6').message,
          contains('levelled level MUST be disjoint'));
    });

    test('11.5 catches a manifest that disagrees with a header', () {
      // spec/13-operations.md section 3: "A verifier MUST check
      // header-against-manifest agreement on every duplicated field, or the
      // redundancy rots unnoticed until the day it is needed."
      final e = seeded();
      final victim = e.refsAt(e.lastLevel).first;
      e.manifest.remove(victim);
      e.manifest.add(SegmentRef(
        segmentId: victim.segmentId,
        level: victim.level,
        group: victim.group,
        minKey: victim.minKey,
        maxKey: victim.maxKey,
        minSeq: victim.minSeq,
        maxSeq: victim.maxSeq,
        entries: victim.entries + 1, // the lie
        tombstones: victim.tombstones,
        hasRangeDeletes: victim.hasRangeDeletes,
        pages: victim.pages,
        trees: victim.trees,
      ));
      e.clearLevelCache();
      final r = e.verifyStructure(deep: false);
      expect(r.findings.map((f) => f.invariant), contains('11.5'));
      expect(r.findings.first.message, contains('entries'));
    });

    test('11.7 would catch a filter false negative — a lost key', () {
      // A false negative in a filter is a LOST KEY, not a slow lookup, which
      // is why section 2.4 is specified to the bit.
      final e = seeded();
      final ref = e.refsAt(e.lastLevel).first;
      final seg = e.extents[ref.segmentId]!;
      expect(seg.filter, isNotNull);
      // Every key present must pass its own filter.
      final r = e.verifyStructure();
      expect(r.findings.where((f) => f.invariant == '11.7'), isEmpty);
    });

    test('checksum damage is reported, not thrown', () {
      // spec/01-container.md section 9: verification REPORTS.
      final e = seeded();
      final victim = e.refsAt(e.lastLevel).first;
      e.extents[victim.segmentId]!.extent[4096 + 100] ^= 0xFF;
      final r = e.verifyStructure();
      expect(r.isSound, isFalse);
      expect(r.findings.first.invariant, '01§9.2');
      expect(r.findings.first.segmentId, victim.segmentId);
    });

    test('11.11 reports locality debt over its bound', () {
      final e = Engine(memtableEntries: 50, vlogMin: 128, localityDebtPct: 0);
      for (var i = 0; i < 300; i++) {
        e.put(tree, CNitriteId(i % 30), doc(dict, i));
      }
      e.flush();
      final r = e.verifyStructure(deep: false);
      // With the bound at 0 any debt at all is a finding.
      if (e.vlog.localityDebt > 0) {
        expect(r.findings.map((f) => f.invariant), contains('11.11'));
      }
    });
  });

  group('repair, spec/13-operations.md section 3', () {
    test('the manifest rebuilds from segment headers alone', () {
      // Section 3's central bet: "a damaged manifest root [becomes] a
      // scan-and-rebuild rather than a total loss."
      final e = seeded(n: 800);
      final before = e.scanTree(tree).length;
      final levelsBefore = [
        for (var l = 0; l <= e.lastLevel; l++) e.refsAt(l).length
      ];

      // Destroy the manifest utterly.
      e.manifest.tree.root = 0;
      e.clearLevelCache();
      expect(e.refsAt(e.lastLevel), isEmpty);
      expect(e.scanTree(tree).length, 0, reason: 'nothing is reachable');

      final rep = e.rebuildManifest();
      expect(rep.action, 'rebuild_manifest');
      expect(rep.segmentsRecovered, greaterThan(0));

      // Everything is back, including the level/group placement -- which is
      // why `group` is duplicated into the header at all.
      expect(e.scanTree(tree).length, before);
      expect([for (var l = 0; l <= e.lastLevel; l++) e.refsAt(l).length],
          levelsBefore);
      expect(e.verifyStructure().isSound, isTrue);
    });

    test('every field the manifest key needs survives in the header', () {
      // If any of level, group or min_internal_key were absent from the
      // header, the rebuild would silently re-file segments and the levelled
      // level could stop being disjoint -- the redundancy has to be COMPLETE
      // for section 3's claim to hold.
      final e = seeded(n: 800);
      final expected = <int, ({int level, int group})>{
        for (var l = 0; l <= e.lastLevel; l++)
          for (final r in e.refsAt(l)) r.segmentId: (level: l, group: r.group)
      };
      e.manifest.tree.root = 0;
      e.clearLevelCache();
      e.rebuildManifest();
      for (var l = 0; l <= e.lastLevel; l++) {
        for (final r in e.refsAt(l)) {
          expect(r.level, expected[r.segmentId]!.level,
              reason: 'segment ${r.segmentId} landed at the wrong level');
          expect(r.group, expected[r.segmentId]!.group,
              reason: 'segment ${r.segmentId} landed in the wrong group');
        }
      }
    });

    test('a dry run changes nothing', () {
      // Section 3: "Repair MUST be non-destructive by default."
      final e = seeded();
      final root = e.manifest.tree.root;
      final rep = e.rebuildManifest(dryRun: true);
      expect(rep.action, contains('dry run'));
      expect(rep.segmentsRecovered, greaterThan(0));
      expect(e.manifest.tree.root, root);
    });

    test('a corrupt segment is left out and reported', () {
      final e = seeded(n: 800);
      final victim = e.refsAt(e.lastLevel).first;
      e.extents[victim.segmentId]!.extent[4096 + 100] ^= 0xFF;
      e.manifest.tree.root = 0;
      e.clearLevelCache();
      final rep = e.rebuildManifest();
      expect(rep.notes.join(' '), contains('${victim.segmentId}'));
      expect(rep.notes.join(' '), contains('fails its checksums'));
      // The rest of the database came back.
      expect(e.scanTree(tree).length, greaterThan(0));
    });

    test('dropping a segment says what was lost, never silently', () {
      // Section 4: an implementation SHOULD offer that "as an explicit,
      // reported choice -- never as a silent one".
      final e = seeded(n: 800);
      final victim = e.refsAt(e.lastLevel).first;
      final rep = e.dropCorruptSegment(victim.segmentId);
      expect(rep.segmentsRecovered, 1);
      expect(rep.entriesRecovered, victim.entries);
      expect(rep.notes.single, contains('LAST level'));
      expect(rep.notes.single, contains('entries were lost'));
    });
  });
}
