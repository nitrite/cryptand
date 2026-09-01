/// Entropy with RANDOM keys, where CRC's error-detection guarantee gives it no
/// help. Two CRC-32C evaluations over the same bytes are affinely related, so
/// the pair carries only 32 bits; random keys make that visible as birthday
/// collisions at the 2^32 bound.
import 'dart:typed_data';
import 'package:cryptand/src/crc32c.dart';
import 'package:cryptand/src/filter.dart';

int rotl(int x, int n) => (x << n) | (x >>> (64 - n));
int splitmix(int x) {
  var z = x;
  z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
  z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
  return z ^ (z >>> 31);
}
int hashB(List<int> k) => splitmix(crcHash64(k));

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

class Lcg {
  Lcg(this.s);
  int s;
  int next() => s = s * 6364136223846793005 + 1442695040888963407;
}

void main() {
  const m = 4000000;
  final rng = Lcg(12345);
  final keys = <Uint8List>[];
  for (var i = 0; i < m; i++) {
    final k = Uint8List(22);
    for (var j = 0; j < 22; j += 8) {
      var w = rng.next();
      for (var b = 0; b < 8 && j + b < 22; b++) {
        k[j + b] = (w >>> (8 * b)) & 0xFF;
      }
    }
    keys.add(k);
  }
  final expected32 = (m * m) / (2 * 4294967296);
  print('$m random 22-byte keys.');
  print('Expected collisions if the hash carries 32 bits: '
      '${expected32.toStringAsFixed(0)}');
  print('Expected collisions if it carries 64 bits: ~0');
  print('');
  for (final e in <String, Hash64>{
    'B  crc32c x2 + splitmix': hashB,
    'E  inline 64-bit mixer': hashE,
  }.entries) {
    final seen = <int>{};
    for (final k in keys) {
      seen.add(e.value(k));
    }
    print('${e.key.padRight(26)} collisions ${(m - seen.length).toString().padLeft(8)}');
  }
}
