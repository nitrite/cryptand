/// Confirms the signed-int constants in cfh64() are the unsigned values the
/// spec prints, and re-measures entropy and FPR with the shipped function.
import 'dart:typed_data';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

String u64(int v) => BigInt.from(v).toUnsigned(64).toRadixString(16).toUpperCase();

class Lcg { Lcg(this.s); int s; int next() => s = s*6364136223846793005+1442695040888963407; }

void main() {
  print('constants as unsigned 64-bit:');
  for (final e in {
    'P1': 0x9E3779B185EBCA87,
    'P2': -0x3D4D51C2D82B14B1,
    'P3': 0x165667B19E3779F9,
    'M1': -0x40A7B892E31B1A47,
    'M2': -0x6B2FB644ECCEEE15,
  }.entries) {
    print('  ${e.key} = 0x${u64(e.value)}');
  }
  print('');
  const m = 4000000;
  final rng = Lcg(12345);
  final seen = <int>{};
  for (var i = 0; i < m; i++) {
    final k = Uint8List(22);
    for (var j = 0; j < 22; j += 8) {
      final w = rng.next();
      for (var b = 0; b < 8 && j + b < 22; b++) { k[j + b] = (w >>> (8 * b)) & 0xFF; }
    }
    seen.add(cfh64(k));
  }
  print('$m random keys -> ${m - seen.length} collisions (32-bit bound predicts 1863)');
  print('');
  const n = 200000, trials = 2000000;
  final shapes = <String, (Uint8List Function(int), Uint8List Function(int))>{
    'snowflake ids': ((i) => userKeyPrefix(17, encodeKey(CNitriteId(1767225600000*4194304+i*4096+1))),
                      (i) => userKeyPrefix(17, encodeKey(CNitriteId(-1-i*4096)))),
    'sequential ids': ((i) => userKeyPrefix(17, encodeKey(CNitriteId(i))),
                       (i) => userKeyPrefix(17, encodeKey(CNitriteId(-1-i)))),
    'sparse ids': ((i) => userKeyPrefix(17, encodeKey(CNitriteId(i*1048576))),
                   (i) => userKeyPrefix(17, encodeKey(CNitriteId(-1-i*1048576)))),
    'long common prefix': ((i) => userKeyPrefix(17, encodeKey(CStr('customer/eu/london/order-${i.toString().padLeft(9,"0")}'))),
                           (i) => userKeyPrefix(17, encodeKey(CStr('customer/eu/london/order-X${i.toString().padLeft(8,"0")}')))),
    'compound index keys': ((i) => userKeyPrefix(17, encodeKey(CArray([CStr('dispatched'), CNitriteId(i)]))),
                            (i) => userKeyPrefix(17, encodeKey(CArray([CStr('dispatched'), CNitriteId(-1-i)])))),
  };
  print('CFH-64 blocked-Bloom FPR at 16 bits/key:');
  shapes.forEach((name, gen) {
    final present = [for (var i = 0; i < n; i++) gen.$1(i)];
    final f = BlockedBloom.build(present, bitsPerKey: 16, distinctKeys: n);
    var hits = 0;
    for (var i = 0; i < trials; i++) { if (f.mayContain(gen.$2(i))) hits++; }
    print('  ${name.padRight(22)} ${(100*hits/trials).toStringAsFixed(4)}%');
  });
}
