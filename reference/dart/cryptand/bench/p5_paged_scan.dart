/// Prediction P5: "A paged walk over a whole collection costs ~1.0-1.2x one
/// full scan, and `nitrite-rust`'s measured 40.4x collapses to that."
///
/// Harness taken from `research/nitrite-survey.md` section 7, which is the
/// measured baseline this has to beat: "20k rows of ~1 KB, 400 per page",
/// paged walk vs full scan.
///
/// Three strategies are measured over the same segment:
///
///   A. full scan             seek once, then next() to the end
///   B. paged walk, cursor    per page: skipTo(offset) then 400 x next()
///   C. paged walk, re-seek   the `nitrite-rust` defect, reproduced: navigate
///                            by repeated seek from the root, once per row,
///                            because the map contract has no cursor
///
/// C is what `research/nitrite-survey.md` section 7 records as "its store
/// navigates by repeated higher_key from the root -- there is no cursor in the
/// NitriteMap API". It is included so the fix is measured against the defect
/// rather than against nothing.
library;

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/segment.dart';

import 'harness.dart';

const int kRows = 20000;
const int kPageSize = 400;

int fullScan(Segment s) {
  s.resetCounters();
  final c = s.cursor()..seekFirst();
  var n = 0;
  while (c.isValid) {
    c.key();
    n++;
    c.next();
  }
  if (n != kRows) throw StateError('scanned $n, expected $kRows');
  return n;
}

int pagedWithCursor(Segment s) {
  s.resetCounters();
  var n = 0;
  for (var offset = 0; offset < kRows; offset += kPageSize) {
    final c = s.cursor()..skipTo(offset);
    for (var i = 0; i < kPageSize && c.isValid; i++) {
      c.key();
      n++;
      c.next();
    }
  }
  if (n != kRows) throw StateError('paged $n, expected $kRows');
  return n;
}

int pagedWithReseek(Segment s) {
  s.resetCounters();
  var n = 0;
  for (var offset = 0; offset < kRows; offset += kPageSize) {
    // The defect: no cursor, so each row is found by descending from the root
    // again, using the previous key as the lower bound.
    final probe = s.cursor()..skipTo(offset);
    if (!probe.isValid) break;
    var key = probe.key();
    for (var i = 0; i < kPageSize; i++) {
      final c = s.cursor()..seekCeiling(key);
      if (!c.isValid) break;
      key = c.key();
      n++;
      // Advance past this key the way higher_key does: seek strictly above it.
      final next = Keys.successor(key);
      if (next == null) break;
      key = next;
    }
  }
  return n;
}

void main() {
  final built = buildDataSegment(kRows, inlineValues: true);
  final s = built.segment;

  print('# P5 -- paged scan versus full scan');
  print('');
  print('Segment: $kRows documents, ${s.pageCount} pages of ${s.pageSize} B, '
      'height ${s.height}, ${leavesOf(s)} leaves');
  print('Page of $kPageSize rows, ${kRows ~/ kPageSize} pages walked');
  print('');

  warmUp(() => fullScan(s));
  final tFull = medianMicros(7, () => fullScan(s));
  final aFull = s.nodeAccesses;

  warmUp(() => pagedWithCursor(s));
  final tPaged = medianMicros(7, () => pagedWithCursor(s));
  final aPaged = s.nodeAccesses;

  warmUp(() => pagedWithReseek(s), reps: 1);
  final tReseek = medianMicros(3, () => pagedWithReseek(s));
  final aReseek = s.nodeAccesses;

  const w = [34, 14, 16, 12];
  print(row(['strategy', 'node accesses', 'vs full scan', 'median ms'], w));
  print(row(['---', '---', '---', '---'], w));
  print(row([
    'A  full scan',
    '$aFull',
    '1.00x',
    fmt(tFull / 1000, 3),
  ], w));
  print(row([
    'B  paged walk, cursor + skipTo',
    '$aPaged',
    '${fmt(ratio(aPaged, aFull))}x',
    fmt(tPaged / 1000, 3),
  ], w));
  print(row([
    'C  paged walk, re-seek per row',
    '$aReseek',
    '${fmt(ratio(aReseek, aFull))}x',
    fmt(tReseek / 1000, 3),
  ], w));
  print('');
  print('Wall-clock ratios (recorded, never gated):');
  print('  B / A = ${fmt(tPaged / tFull)}x');
  print('  C / A = ${fmt(tReseek / tFull)}x   <- the defect this fixes');
  print('');
  print('Cold page reads (cache cleared, every fetch a miss):');
  s
    ..clearCache()
    ..cacheEnabled = false;
  fullScan(s);
  final coldFull = s.pageReads;
  pagedWithCursor(s);
  final coldPaged = s.pageReads;
  s
    ..cacheEnabled = true
    ..clearCache();
  print('  full scan  $coldFull');
  print('  paged walk $coldPaged  (${fmt(ratio(coldPaged, coldFull))}x)');
  print('');
  print('P5 verdict: paged/full = ${fmt(ratio(aPaged, aFull))}x on node '
      'accesses, ${fmt(tPaged / tFull)}x on wall time.');
}
