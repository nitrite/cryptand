import 'package:cryptand/src/u128.dart';
import 'package:test/test.dart';

/// The reference for every case here is `BigInt`, which this library
/// deliberately does not use on any encoding path.
void main() {
  final rng = _Lcg(0xC0FFEE);
  final samples = <BigInt>[
    BigInt.zero,
    BigInt.one,
    BigInt.from(5),
    BigInt.two.pow(53) - BigInt.one,
    BigInt.two.pow(53),
    BigInt.two.pow(53) + BigInt.one,
    BigInt.two.pow(63) - BigInt.one,
    BigInt.two.pow(63),
    BigInt.two.pow(64) - BigInt.one,
    BigInt.two.pow(64),
    BigInt.two.pow(127),
    BigInt.two.pow(128) - BigInt.one,
    for (var i = 0; i < 400; i++) rng.nextU128(),
  ];

  test('round-trips through BigInt', () {
    for (final v in samples) {
      expect(U128.fromBigInt(v).toBigInt(), v, reason: '$v');
    }
  });

  test('round-trips through big-endian bytes', () {
    for (final v in samples) {
      final u = U128.fromBigInt(v);
      expect(U128.fromBytesBE(u.toBytesBE()), u, reason: '$v');
    }
  });

  test('bitLength matches BigInt', () {
    for (final v in samples) {
      expect(U128.fromBigInt(v).bitLength, v.bitLength, reason: '$v');
    }
  });

  test('shl matches BigInt', () {
    final mask = (BigInt.one << 128) - BigInt.one;
    for (final v in samples) {
      for (final n in [0, 1, 7, 31, 63, 64, 65, 96, 127, 128, 200]) {
        expect(U128.fromBigInt(v).shl(n).toBigInt(), ((v << n) & mask),
            reason: '$v << $n');
      }
    }
  });

  test('shr matches BigInt', () {
    for (final v in samples) {
      for (final n in [0, 1, 63, 64, 65, 127, 128, 200]) {
        expect(U128.fromBigInt(v).shr(n).toBigInt(), v >> n, reason: '$v >> $n');
      }
    }
  });

  test('addition wraps like BigInt mod 2^128', () {
    final mask = (BigInt.one << 128) - BigInt.one;
    for (final a in samples) {
      for (final b in samples.take(40)) {
        expect((U128.fromBigInt(a) + U128.fromBigInt(b)).toBigInt(),
            (a + b) & mask,
            reason: '$a + $b');
      }
    }
  });

  test('negate is two\'s complement', () {
    final mask = (BigInt.one << 128) - BigInt.one;
    for (final v in samples) {
      expect(U128.fromBigInt(v).negate().toBigInt(), (-v) & mask, reason: '$v');
    }
  });

  test('compareTo is unsigned across the 2^63 and 2^127 boundaries', () {
    // The exact failure mode that broke unique indexes on snowflake ids:
    // signed comparison of a value above 2^63.
    final below = U128.fromBigInt(BigInt.two.pow(63) - BigInt.one);
    final above = U128.fromBigInt(BigInt.two.pow(63));
    expect(below.compareTo(above), lessThan(0));
    expect(above.compareTo(below), greaterThan(0));

    final sorted = [...samples]..sort();
    for (var i = 1; i < sorted.length; i++) {
      expect(sorted[i - 1] <= sorted[i], isTrue);
    }
    final us = samples.map(U128.fromBigInt).toList()..sort();
    expect(us.map((u) => u.toBigInt()).toList(), sorted);
  });

  test('clz64 matches a bit-by-bit count', () {
    for (final v in [0, 1, 0xFF, 0x7FFFFFFFFFFFFFFF, -1, -0x8000000000000000]) {
      var n = 0;
      for (var i = 63; i >= 0; i--) {
        if ((v >>> i) & 1 == 1) break;
        n++;
      }
      expect(clz64(v), n, reason: '0x${v.toRadixString(16)}');
    }
  });
}

/// Deterministic generator, so a failure is reproducible.
class _Lcg {
  _Lcg(this.s);
  int s;
  int next() => s = (s * 6364136223846793005 + 1442695040888963407);
  BigInt nextU128() {
    final bits = next().toUnsigned(8) % 129; // exercise every width
    if (bits == 0) return BigInt.zero;
    final v = (BigInt.from(next()).toUnsigned(64) << 64) |
        BigInt.from(next()).toUnsigned(64);
    return v >> (128 - bits);
  }
}
