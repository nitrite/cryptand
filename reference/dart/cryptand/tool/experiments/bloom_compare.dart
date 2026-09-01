/// Decisive experiment: is the measured false-positive rate a property of the
/// hash, or of *blocking*?
///
/// Builds three filters over the same keys with the same hash:
///   classic  one bit array of m bits, k probes anywhere in it
///   blocked  the spec's structure: 512-bit blocks, k probes inside one block
///   blocked-mix  as blocked, but block selection uses a mixed h1
///
/// If classic lands near the textbook (1-e^(-kn/m))^k and blocked does not,
/// the hash is fine and the spec is quoting classic-Bloom numbers for a
/// blocked-Bloom structure.
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

const int n = 100000, trials = 1000000;

List<Uint8List> present() => [
      for (var i = 0; i < n; i++)
        userKeyPrefix(17, encodeKey(CNitriteId(1767225600000 * 4194304 + i * 4096 + 1)))
    ];
Uint8List absent(int i) => userKeyPrefix(17, encodeKey(CNitriteId(-1 - i * 7919)));

class Classic {
  Classic(this.bits, this.k) : a = Uint8List((bits + 7) ~/ 8);
  final int bits, k;
  final Uint8List a;
  void add(List<int> key) => _each(key, (b) => a[b >> 3] |= 1 << (b & 7));
  bool has(List<int> key) {
    var ok = true;
    _each(key, (b) { if (a[b >> 3] & (1 << (b & 7)) == 0) ok = false; });
    return ok;
  }
  void _each(List<int> key, void Function(int) f) {
    final h = crcHash64(key);
    final h1 = h & 0xFFFFFFFF, h2 = ((h >>> 32) | 1) & 0xFFFFFFFF;
    var p = h1;
    for (var i = 0; i < k; i++) { f(p % bits); p = (p + h2) & 0xFFFFFFFF; }
  }
}

void main() {
  final keys = present();
  print('bits  k   classic     blocked     textbook (1-e^-kn/m)^k');
  for (final bpk in [10, 12, 14, 16]) {
    final k = probesFor(bpk);
    final m = n * bpk;
    final c = Classic(m, k);
    for (final key in keys) { c.add(key); }
    var ch = 0;
    for (var i = 0; i < trials; i++) { if (c.has(absent(i))) ch++; }

    final b = BlockedBloom.build(keys, bitsPerKey: bpk, distinctKeys: n);
    var bh = 0;
    for (var i = 0; i < trials; i++) { if (b.mayContain(absent(i))) bh++; }

    final theory = math.pow(1 - math.exp(-k * n / m), k) as double;
    print('${bpk.toString().padLeft(4)}  ${k.toString().padLeft(2)}  '
        '${(100*ch/trials).toStringAsFixed(4).padLeft(8)}%  '
        '${(100*bh/trials).toStringAsFixed(4).padLeft(8)}%  '
        '${(100*theory).toStringAsFixed(4).padLeft(8)}%');
  }
}
