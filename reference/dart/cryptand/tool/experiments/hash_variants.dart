/// Which 64-bit hash should the segment filter use?
///
/// The spec names XXH3-64 (~500 lines, 7 branches, a 192-byte secret). The
/// question is whether something far smaller is good enough for a Bloom
/// filter, measured across key shapes that stress a hash differently.
///
/// CRC-32C is linear over GF(2), which is the standard objection to using it
/// as a hash. So a finalized variant is measured too: CRC gives 64 raw bits,
/// a splitmix64 finalizer (three constants, four lines) removes the
/// linearity.
import 'dart:typed_data';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/crc32c.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

const int n = 200000, trials = 2000000;

// --- variant A: two domain-separated CRC-32C evaluations (current) --------
int crcPlain(List<int> key) => crcHash64(key);

// --- variant B: the same, then a splitmix64 finalizer ---------------------
int splitmix64Finalize(int x) {
  var z = x;
  z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
  z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
  return z ^ (z >>> 31);
}
int crcMixed(List<int> key) => splitmix64Finalize(crcHash64(key));

// --- variant C: one CRC-32C, expanded by the finalizer only --------------
int crcSingleMixed(List<int> key) => splitmix64Finalize(crc32c(key) * 0x9E3779B97F4A7C15);

// --- key shapes ----------------------------------------------------------
typedef Shape = Uint8List Function(int i);

Uint8List snowflake(int i) =>
    userKeyPrefix(17, encodeKey(CNitriteId(1767225600000 * 4194304 + i * 4096 + 1)));
Uint8List sequential(int i) => userKeyPrefix(17, encodeKey(CNitriteId(i)));
Uint8List sparse(int i) => userKeyPrefix(17, encodeKey(CNitriteId(i * 1048576)));
Uint8List commonPrefixString(int i) =>
    userKeyPrefix(17, encodeKey(CStr('customer/eu/london/order-${i.toString().padLeft(9, "0")}')));
Uint8List indexKey(int i) => userKeyPrefix(
    17, encodeKey(CArray([CStr('dispatched'), CNitriteId(i)])));

void main() {
  final shapes = <String, (Shape, Shape)>{
    // (present, absent) generators; absent must be disjoint from present.
    'snowflake ids': (snowflake, (i) => snowflake(-1 - i)),
    'sequential ids': (sequential, (i) => sequential(-1 - i)),
    'sparse ids': (sparse, (i) => sparse(-1 - i)),
    'long common prefix': (
      commonPrefixString,
      (i) => userKeyPrefix(17, encodeKey(CStr('customer/eu/london/order-X${i.toString().padLeft(8, "0")}')))
    ),
    'compound index keys': (indexKey, (i) => indexKey(-1 - i)),
  };
  final hashes = <String, Hash64>{
    'A crc x2': crcPlain,
    'B crc x2 + mix': crcMixed,
    'C crc x1 + mix': crcSingleMixed,
  };

  print('Blocked Bloom, 16 bits/key, $n keys, $trials absent probes.');
  print('Textbook classic-Bloom rate at 16 bits, k=11: 0.0459%.');
  print('Blocked Bloom is structurally ~7x that, so ~0.33% is the target.');
  print('');
  final head = 'key shape'.padRight(22) + hashes.keys.map((h) => h.padLeft(16)).join();
  print(head);
  print('-' * head.length);
  shapes.forEach((shapeName, gen) {
    final present = [for (var i = 0; i < n; i++) gen.$1(i)];
    final row = StringBuffer(shapeName.padRight(22));
    for (final h in hashes.values) {
      final f = BlockedBloom.build(present, bitsPerKey: 16, distinctKeys: n, hash: h);
      var hits = 0;
      for (var i = 0; i < trials; i++) {
        if (f.mayContain(gen.$2(i))) hits++;
      }
      row.write('${(100 * hits / trials).toStringAsFixed(4)}%'.padLeft(16));
    }
    print(row);
  });
}
