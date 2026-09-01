import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';
import 'dart:typed_data';
const int n = 100000, trials = 1000000;
void main() {
  final keys = <Uint8List>[
    for (var i = 0; i < n; i++)
      userKeyPrefix(17, encodeKey(CNitriteId(1767225600000 * 4194304 + i * 4096 + 1)))
  ];
  print('bits  k   blocked FPR   filter KiB   bytes/key');
  for (final bpk in [10, 12, 14, 16, 18, 20, 24, 28, 32]) {
    final f = BlockedBloom.build(keys, bitsPerKey: bpk, distinctKeys: n);
    var hits = 0;
    for (var i = 0; i < trials; i++) {
      if (f.mayContain(userKeyPrefix(17, encodeKey(CNitriteId(-1 - i * 7919))))) hits++;
    }
    print('${bpk.toString().padLeft(4)}  ${f.probes.toString().padLeft(2)}  '
        '${(100*hits/trials).toStringAsFixed(4).padLeft(9)}%  '
        '${(f.blocks.length/1024).round().toString().padLeft(9)}  '
        '${(f.blocks.length/n).toStringAsFixed(2).padLeft(8)}');
  }
}
