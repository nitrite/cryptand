/// Two questions, both decisive for the filter-hash recommendation.
///
/// 1. ENTROPY. CRC is affine in its initial state: CRC(i1,m) XOR CRC(i2,m)
///    depends only on len(m). Appending or prepending a salt is likewise a
///    linear map of the original value. So *any* pair of CRC-32C evaluations
///    over the same key carries only 32 bits of entropy, and a finalizer can
///    spread those bits but cannot create more. Counting distinct hash values
///    over many keys shows it directly: 32-bit entropy collides at the 2^32
///    birthday bound, 64-bit entropy does not.
///
/// 2. QUALITY. False-positive rate across key shapes, against the blocked
///    baseline.
import 'dart:typed_data';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/crc32c.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

int rotl(int x, int n) => (x << n) | (x >>> (64 - n));

int splitmix(int x) {
  var z = x;
  z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
  z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
  return z ^ (z >>> 31);
}

// A: two CRC-32C evaluations (32 bits of entropy, as argued above).
int hashA(List<int> k) => crcHash64(k);
int hashB(List<int> k) => splitmix(crcHash64(k));

// D: CRC-32C and CRC-32 (different polynomials) -> genuine 64 bits.
final Uint32List _t32 = () {
  final t = Uint32List(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
    }
    t[i] = c;
  }
  return t;
}();
int crc32(List<int> b) {
  var c = 0xFFFFFFFF;
  for (final x in b) {
    c = _t32[(c ^ x) & 0xFF] ^ (c >> 8);
  }
  return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF;
}
int hashD(List<int> k) => splitmix((crc32(k) << 32) | crc32c(k));

// E: a self-contained 64-bit mixer, small enough to print in the spec.
const int _p1 = 0x9E3779B185EBCA87;
const int _p2 = 0xC2B2AE3D27D4EB4F;
const int _p3 = 0x165667B19E3779F9;
int hashE(List<int> key) {
  var h = _p1 ^ (key.length * _p2);
  var i = 0;
  final n = key.length;
  while (i + 8 <= n) {
    var w = 0;
    for (var j = 7; j >= 0; j--) {
      w = (w << 8) | key[i + j];
    }
    h ^= w * _p2;
    h = rotl(h, 31) * _p1;
    i += 8;
  }
  var tail = 0;
  while (i < n) {
    tail = (tail << 8) | key[i];
    i++;
  }
  h ^= tail * _p3;
  h = rotl(h, 27) * _p1;
  return splitmix(h);
}

Uint8List snowflake(int i) =>
    userKeyPrefix(17, encodeKey(CNitriteId(1767225600000 * 4194304 + i * 4096 + 1)));
Uint8List sequential(int i) => userKeyPrefix(17, encodeKey(CNitriteId(i)));
Uint8List sparse(int i) => userKeyPrefix(17, encodeKey(CNitriteId(i * 1048576)));
Uint8List prefixed(int i) => userKeyPrefix(
    17, encodeKey(CStr('customer/eu/london/order-${i.toString().padLeft(9, "0")}')));
Uint8List compound(int i) =>
    userKeyPrefix(17, encodeKey(CArray([CStr('dispatched'), CNitriteId(i)])));

void main() {
  final hashes = <String, Hash64>{
    'A crc32c x2': hashA,
    'B crc32c x2 + mix': hashB,
    'D crc32c + crc32 + mix': hashD,
    'E inline 64-bit mixer': hashE,
  };

  print('=== 1. Entropy: distinct 64-bit hash values over 4 000 000 keys ===');
  print('64 bits of entropy => ~0 collisions. 32 bits => ~1 860 000 expected.');
  print('');
  const m = 4000000;
  hashes.forEach((name, h) {
    final seen = <int>{};
    for (var i = 0; i < m; i++) {
      seen.add(h(snowflake(i)));
    }
    final collisions = m - seen.length;
    print('${name.padRight(24)} distinct ${seen.length.toString().padLeft(9)}   '
        'collisions ${collisions.toString().padLeft(8)}');
  });

  print('');
  print('=== 2. Blocked-Bloom FPR by key shape, 16 bits/key ===');
  print('200 000 keys, 2 000 000 absent probes. Structural target ~0.22%.');
  print('');
  const n = 200000, trials = 2000000;
  final shapes = <String, (Uint8List Function(int), Uint8List Function(int))>{
    'snowflake ids': (snowflake, (i) => snowflake(-1 - i)),
    'sequential ids': (sequential, (i) => sequential(-1 - i)),
    'sparse ids': (sparse, (i) => sparse(-1 - i)),
    'long common prefix': (prefixed, (i) => userKeyPrefix(17,
        encodeKey(CStr('customer/eu/london/order-X${i.toString().padLeft(8, "0")}')))),
    'compound index keys': (compound, (i) => compound(-1 - i)),
  };
  final head = 'key shape'.padRight(22) + hashes.keys.map((h) => h.padLeft(24)).join();
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
      row.write('${(100 * hits / trials).toStringAsFixed(4)}%'.padLeft(24));
    }
    print(row);
  });
}
