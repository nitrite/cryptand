/// Does the blocked-Bloom false-positive penalty come from the *block size*?
///
/// 512-bit blocks at 16 bits/key put ~32 keys in a block; Poisson spread means
/// the overfull blocks dominate the false-positive rate. Larger blocks average
/// that away. The question is how much, and what it costs in read size.
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

const int n = 100000, trials = 1000000;

class Blocked {
  Blocked(this.blockBits, this.bpk, this.k)
      : blockCount = math.max(1, (n * bpk + blockBits - 1) ~/ blockBits) {
    a = Uint8List(blockCount * (blockBits ~/ 8));
  }
  final int blockBits, bpk, k, blockCount;
  late final Uint8List a;
  int get blockBytes => blockBits ~/ 8;

  void _each(List<int> key, void Function(int) f) {
    final h = crcHash64(key);
    final h1 = h & 0xFFFFFFFF, h2 = ((h >>> 32) | 1) & 0xFFFFFFFF;
    final base = ((h1 * blockCount) >> 32) * blockBytes;
    var p = h1;
    for (var i = 0; i < k; i++) {
      f(base * 8 + (p & (blockBits - 1)));
      p = (p + h2) & 0xFFFFFFFF;
    }
  }

  void add(List<int> key) => _each(key, (b) => a[b >> 3] |= 1 << (b & 7));
  bool has(List<int> key) {
    var ok = true;
    _each(key, (b) { if (a[b >> 3] & (1 << (b & 7)) == 0) ok = false; });
    return ok;
  }
}

void main() {
  final keys = <Uint8List>[
    for (var i = 0; i < n; i++)
      userKeyPrefix(17, encodeKey(CNitriteId(1767225600000 * 4194304 + i * 4096 + 1)))
  ];
  print('bits/key  block bits  block bytes  keys/block   FPR');
  for (final bpk in [10, 16]) {
    final k = probesFor(bpk);
    for (final bb in [512, 1024, 2048, 4096, 8192, 32768]) {
      final f = Blocked(bb, bpk, k);
      for (final key in keys) { f.add(key); }
      var hits = 0;
      for (var i = 0; i < trials; i++) {
        if (f.has(userKeyPrefix(17, encodeKey(CNitriteId(-1 - i * 7919))))) hits++;
      }
      print('${bpk.toString().padLeft(8)}  ${bb.toString().padLeft(10)}  '
          '${(bb ~/ 8).toString().padLeft(11)}  '
          '${(n / f.blockCount).toStringAsFixed(1).padLeft(10)}  '
          '${(100*hits/trials).toStringAsFixed(4).padLeft(8)}%');
    }
    print('');
  }
}
