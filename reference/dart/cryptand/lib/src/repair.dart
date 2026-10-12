/// Repair — `spec/13-operations.md` §3.
///
/// "Verification reports; repair fixes." §3 makes this one of the few things
/// the *reference* implementation MUST provide rather than SHOULD.
///
/// The marquee item is the manifest rebuild, and §3 states the design bet it
/// settles:
///
/// > "**The manifest is deliberately redundant with the segment headers.** That
/// > duplication costs a few dozen bytes per segment and is what makes the
/// > single most likely catastrophic failure — a damaged manifest root — into a
/// > scan-and-rebuild rather than a total loss."
///
/// This file is the test of that bet. If a segment header is missing any field
/// the manifest key or entry needs, the rebuild is lossy and the redundancy was
/// never complete. `group` is in the header for no other reason
/// (`04-segments.md` §2.1) — it is part of the manifest key and nothing else
/// would recover it.
library;

import 'container.dart';
import 'engine.dart';
import 'errors.dart';
import 'manifest.dart';
import 'segment.dart';
import 'verify.dart';

/// What a repair did.
final class RepairReport {
  const RepairReport({
    required this.action,
    required this.segmentsRecovered,
    required this.entriesRecovered,
    required this.notes,
  });

  final String action;
  final int segmentsRecovered;
  final int entriesRecovered;
  final List<String> notes;

  @override
  String toString() => '$action: $segmentsRecovered segments, '
      '$entriesRecovered entries'
      '${notes.isEmpty ? "" : "\n  ${notes.join("\n  ")}"}';
}

extension EngineRepair on Engine {
  /// Rebuilds the manifest by scanning for `SEGMENT_HEADER` pages, §3.
  ///
  /// Every field the manifest holds is read back out of the header: `level`,
  /// `group`, the key bounds, the seq range, the counts. Nothing is inferred
  /// and nothing is guessed — which is the whole claim, and the reason `group`
  /// is duplicated into the header at all.
  ///
  /// **Non-destructive by default** (§3's closing rule): the rebuild is
  /// assembled in full and verified before it replaces the live manifest, and
  /// [dryRun] stops before the replacement.
  RepairReport rebuildManifest({bool dryRun = false}) {
    final notes = <String>[];
    final recovered = <SegmentRef>[];
    var entries = 0;

    // The scan, as Rust `rebuild_manifest`: every page of the store, not the
    // resident cache, which after M5 holds only what was recently read. A
    // retired segment's head survives in its freed extent until reused; the
    // free tree is a separate root, so it says which heads are debris.
    final freed = {for (final x in store.freeExtents) x.startPage};
    var page = 2;
    while (page < store.pageCount) {
      final PageHeader h;
      try {
        h = PageHeader.read(store.readClear(page), pageId: page);
      } on CryptandException {
        page++;
        continue;
      }
      final pages = h.extentPages < 1 ? 1 : h.extentPages;
      if (h.pageType != PageType.segmentHeader || freed.contains(page)) {
        page += pages;
        continue;
      }
      final Segment seg;
      try {
        seg = Segment(store.readExtent(page, pages), pageSize)
          ..verifyChecksums();
      } on Exception catch (x) {
        notes.add('segment at page $page fails its checksums and was left '
            'out of the rebuilt manifest: $x');
        page += pages;
        continue;
      }
      final sh = seg.header;
      // Repair trusts what it finds: the head's own nonce.
      recovered.add(SegmentRef.of(seg, level: sh.level, group: sh.group)
          .placedAt(page, h.nonce));
      entries += sh.entryCount;
      page += pages;
    }

    recovered.sort((a, b) {
      final c = a.level.compareTo(b.level);
      if (c != 0) return c;
      final g = a.group.compareTo(b.group);
      return g != 0 ? g : a.segmentId.compareTo(b.segmentId);
    });

    if (dryRun) {
      return RepairReport(
        action: 'rebuild_manifest (dry run)',
        segmentsRecovered: recovered.length,
        entriesRecovered: entries,
        notes: notes,
      );
    }

    // Replace, then verify. §3: "write the repaired database beside the
    // original and swap only after verification" — the in-memory analogue is
    // that the old root is kept until the new manifest verifies.
    // §5.2 and §5: a compaction in flight refers to manifest entries that are
    // about to be replaced, so it is abandoned rather than allowed to publish
    // into a manifest it was not planned against.
    abandonCompaction();
    final oldRoot = manifest.tree.root;
    manifest.tree.root = 0;
    clearLevelCache();
    for (final r in recovered) {
      manifest.add(r);
    }
    clearLevelCache();

    final report = verifyStructure(deep: false);
    // `isSound`, not `isClean`: `spec/01-container.md` section 9 says in as many
    // words that "a leak is repairable", so refusing to repair a file *because*
    // it leaks refuses every file this format produces — a copy-on-write tree
    // leaks its own pages by one commit, by construction.
    if (!report.isSound) {
      manifest.tree.root = oldRoot;
      clearLevelCache();
      notes.add('rebuild rejected: '
          '${report.of(FindingClass.corruption).length} corruption and '
          '${report.of(FindingClass.tampering).length} tampering findings; '
          'the original manifest was kept');
      return RepairReport(
        action: 'rebuild_manifest (rejected)',
        segmentsRecovered: 0,
        entriesRecovered: 0,
        notes: notes,
      );
    }

    return RepairReport(
      action: 'rebuild_manifest',
      segmentsRecovered: recovered.length,
      entriesRecovered: entries,
      notes: notes,
    );
  }

  /// Drops a corrupt segment above the last level, §3 and §4.
  ///
  /// §4: "A corrupt segment at a level above the last is often fully
  /// recoverable: the older versions of its keys survive lower down, so
  /// dropping it loses only the updates it held. An implementation SHOULD
  /// offer that as an **explicit, reported** choice — never as a silent one."
  RepairReport dropCorruptSegment(int segmentId) {
    SegmentRef? found;
    for (var l = 0; l <= lastLevel; l++) {
      for (final r in refsAt(l)) {
        if (r.segmentId == segmentId) found = r;
      }
    }
    if (found == null) {
      return const RepairReport(
        action: 'drop_segment',
        segmentsRecovered: 0,
        entriesRecovered: 0,
        notes: ['no such segment'],
      );
    }
    final atLast = found.level == lastLevel;
    manifest.remove(found);
    extents.remove(segmentId);
    quarantined.remove(segmentId);
    clearLevelCache();
    return RepairReport(
      action: 'drop_segment',
      segmentsRecovered: 1,
      entriesRecovered: found.entries,
      notes: [
        if (atLast)
          'segment was at the LAST level: the only copy of its keys is gone, '
              'and ${found.entries} entries were lost'
        else
          'segment was above the last level: older versions of its keys '
              'survive below, so only the updates it held were lost',
      ],
    );
  }
}
