/// Measures the segment filter's false-positive rate against the rates
/// `spec/04-segments.md` section 2.4 predicts, for the CRC-32C-derived hash
/// this reference uses in place of XXH3-64 (see REPORT.md).
///
/// The read-tail arithmetic of section 4.1 rests on these numbers, so if they
/// hold, so does the bounded-read-tail claim for this hash.
library;

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

import 'harness.dart';

void main() {
  print('# Segment filter false-positive rate');
  print('');
  print('100 000 keys inserted, 1 000 000 absent keys probed.');
  print('Hash: two CRC-32C evaluations (not XXH3-64; see REPORT.md).');
  print('');
  const n = 100000, trials = 1000000;
  final present = [
    for (var i = 0; i < n; i++)
      userKeyPrefix(benchTree, encodeKey(CNitriteId(snowflakeId(i))))
  ];
  const w = [16, 10, 14, 16, 14];
  print(row(['bits per key', 'probes', 'measured FPR', 'section 2.4', 'filter bytes'], w));
  print(row(['---', '---', '---', '---', '---'], w));
  for (final bits in [10, 12, 14, 16]) {
    final f = BlockedBloom.build(present, bitsPerKey: bits, distinctKeys: n);
    var hits = 0;
    for (var i = 0; i < trials; i++) {
      final k = userKeyPrefix(benchTree, encodeKey(CNitriteId(-1 - i * 7919)));
      if (f.mayContain(k)) hits++;
    }
    final predicted = switch (bits) { 16 => '0.04 %', 10 => '1 %', _ => '--' };
    print(row([
      '$bits',
      '${f.probes}',
      '${(100 * hits / trials).toStringAsFixed(4)} %',
      predicted,
      '${(f.blocks.length / 1024).round()} KiB',
    ], w));
  }
}
