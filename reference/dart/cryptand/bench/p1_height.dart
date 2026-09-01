/// Prediction P1: "Segment height <= 4 for every collection below 613 M
/// documents at 4 KiB pages, and the interior of the last level's key index
/// fits in under 2 MiB per 10^7 documents."
///
/// Also measures the fanout arithmetic of `design/performance-model.md`
/// section 2, which P1 rests on: "Leaf cell in a data segment ~= 32 B ->
/// ~127 entries per leaf. Internal cell ... ~= 24 B -> ~169 children per
/// internal page."
///
/// Both shapes are measured, because they are different engines:
///
///   separated   the leaf holds a 16-byte value-log pointer (`desktop`,
///               `vlog_min` = 256 B) -- this is the shape section 2 costs
///   inline      the leaf holds the whole document (`mobile`, `vlog_min` at
///               its `page_size / 4` ceiling)
library;

import 'package:cryptand/src/segment.dart';

import 'harness.dart';

({int leaves, int internals, double perLeaf, double perInternal}) shape(
    Segment s) {
  var leaves = 0, internals = 0, childCells = 0, leafCells = 0;
  for (var i = 1; i < s.pageCount; i++) {
    final n = s.node(i);
    if (n.isLeaf) {
      leaves++;
      leafCells += n.cellCount;
    } else {
      internals++;
      childCells += n.cellCount;
    }
  }
  return (
    leaves: leaves,
    internals: internals,
    perLeaf: leaves == 0 ? 0 : leafCells / leaves,
    perInternal: internals == 0 ? 0 : childCells / internals,
  );
}

void report(String label, int n, bool inlineValues) {
  final built = buildDataSegment(n, inlineValues: inlineValues);
  final s = built.segment;
  final sh = shape(s);
  final total = s.extent.length;
  final interior = s.interiorBytes;
  const w = [12, 10, 8, 12, 13, 12, 12, 14];
  print(row([
    label,
    '$n',
    '${s.height}',
    sh.perLeaf.toStringAsFixed(1),
    sh.perInternal.toStringAsFixed(1),
    '${(total / 1024).round()} KiB',
    '${(interior / 1024).round()} KiB',
    pct(interior, total),
  ], w));
}

void main() {
  print('# P1 -- segment height and key-index size');
  print('');
  print('page_size 4096, snowflake-shaped keys, the 20-field document of');
  print('design/performance-model.md section 1.');
  print('');
  const w = [12, 10, 8, 12, 13, 12, 12, 14];
  print(row([
    'shape',
    'documents',
    'height',
    'per leaf',
    'per internal',
    'extent',
    'interior',
    'interior/extent'
  ], w));
  print(row(['---', '---', '---', '---', '---', '---', '---', '---'], w));
  for (final n in [10000, 100000, 1000000]) {
    report('separated', n, false);
  }
  for (final n in [10000, 100000, 1000000]) {
    report('inline', n, true);
  }
  print('');

  // Extrapolate the height ceiling from the measured fanouts.
  final probe = buildDataSegment(1000000, inlineValues: false);
  final sh = shape(probe.segment);
  final perLeaf = sh.perLeaf;
  final perInternal = sh.perInternal;
  var capacity = perLeaf;
  final rows = <String>[];
  for (var h = 1; h <= 5; h++) {
    rows.add('  height $h  <= ${capacity.round()} entries');
    capacity *= perInternal;
  }
  print('Measured fanout: ${perLeaf.toStringAsFixed(1)} entries per leaf, '
      '${perInternal.toStringAsFixed(1)} children per internal page');
  print('Implied capacity by height (separated shape):');
  rows.forEach(print);
  print('');
  final at1e7 = probe.segment.interiorBytes * 10;
  print('Interior at 10^6 documents: '
      '${(probe.segment.interiorBytes / 1024).round()} KiB');
  print('Extrapolated to 10^7:       ${(at1e7 / 1024 / 1024).toStringAsFixed(2)} MiB '
      '(P1 predicts under 2 MiB)');
}
