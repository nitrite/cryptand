/// A 128-bit unsigned integer as two 64-bit halves.
///
/// This type exists to make one specific claim in the spec true. Section 4.1 of
/// `spec/03-key-encoding.md` says the CKE number normalization
///
///   > "is exact, uses only shifts and a count-leading-zeros, and requires no
///   >  arbitrary-precision arithmetic in any language."
///
/// Dart has no 128-bit integer, and neither does Java. If that claim held only
/// where a native `u128` exists (Rust), it would not be a portable format. So
/// the reference implementation deliberately does *not* reach for [BigInt]: it
/// carries the mantissa in two `int`s, exactly as a Java implementation would
/// carry it in two `long`s, and every operation below is a shift, a mask or an
/// add.
///
/// Dart's `int` is a 64-bit two's-complement value on the native VM with
/// wrapping arithmetic, so it doubles as a `u64` bit pattern provided every
/// comparison and shift is written unsigned. That is what [_ucmp] and the
/// `>>>` operator below are for.
library;

import 'dart:typed_data';

/// Bit pattern of `1 << 63`, used to map unsigned order onto signed order.
const int _signBit = -0x8000000000000000;

/// Compares two `int`s as unsigned 64-bit values.
///
/// Flipping the sign bit of both operands turns the unsigned ordering into the
/// signed ordering, which is what `compareTo` implements. This is the only
/// correct way to compare `u64` bit patterns in Dart and getting it wrong is
/// invisible until a key above 2^63 appears — precisely the bug class
/// `research/nitrite-survey.md` section 6.3 records for snowflake ids.
int _ucmp(int a, int b) => (a ^ _signBit).compareTo(b ^ _signBit);

/// Count of leading zero bits in the unsigned 64-bit value [x].
int clz64(int x) {
  if (x == 0) return 64;
  if (x < 0) return 0; // top bit set
  return 64 - x.bitLength;
}

/// An unsigned 128-bit integer, `hi * 2^64 + lo`.
///
/// [hi] and [lo] hold raw 64-bit patterns; interpret them as unsigned.
final class U128 implements Comparable<U128> {
  const U128(this.hi, this.lo);

  final int hi;
  final int lo;

  static const U128 zero = U128(0, 0);
  static const U128 one = U128(0, 1);

  /// The 128-bit value `1 << 127`, i.e. the magnitude of `i128::MIN`.
  static const U128 minI128Magnitude = U128(_signBit, 0);

  /// Builds from a raw unsigned 64-bit pattern.
  factory U128.fromU64(int bits) => U128(0, bits);

  /// Builds from a non-negative Dart `int`.
  factory U128.fromInt(int v) {
    if (v < 0) {
      throw ArgumentError.value(v, 'v', 'negative; use U128.fromU64 for a raw pattern');
    }
    return U128(0, v);
  }

  bool get isZero => hi == 0 && lo == 0;

  /// Number of significant bits, 0 for zero. `128 - clz`.
  int get bitLength => hi != 0 ? 128 - clz64(hi) : (lo != 0 ? 64 - clz64(lo) : 0);

  /// Count of leading zero bits across the full 128 bits.
  int get clz => 128 - bitLength;

  /// Logical left shift. Shifting by 128 or more yields zero.
  U128 shl(int n) {
    if (n <= 0) return n == 0 ? this : throw ArgumentError.value(n, 'n');
    if (n >= 128) return zero;
    if (n >= 64) return U128(lo << (n - 64), 0);
    return U128((hi << n) | (lo >>> (64 - n)), lo << n);
  }

  /// Logical right shift. Shifting by 128 or more yields zero.
  U128 shr(int n) {
    if (n <= 0) return n == 0 ? this : throw ArgumentError.value(n, 'n');
    if (n >= 128) return zero;
    if (n >= 64) return U128(0, hi >>> (n - 64));
    return U128(hi >>> n, (lo >>> n) | (hi << (64 - n)));
  }

  /// Wrapping 128-bit addition.
  U128 operator +(U128 other) {
    final lo2 = lo + other.lo;
    // Unsigned carry detection without a wider type: the sum wrapped iff it
    // compares below either addend as an unsigned value.
    final carry = _ucmp(lo2, lo) < 0 ? 1 : 0;
    return U128(hi + other.hi + carry, lo2);
  }

  /// Bitwise complement.
  U128 operator ~() => U128(~hi, ~lo);

  /// Two's-complement negation, wrapping.
  U128 negate() => (~this) + one;

  @override
  int compareTo(U128 other) {
    final h = _ucmp(hi, other.hi);
    return h != 0 ? h : _ucmp(lo, other.lo);
  }

  bool operator <(U128 o) => compareTo(o) < 0;
  bool operator <=(U128 o) => compareTo(o) <= 0;
  bool operator >(U128 o) => compareTo(o) > 0;
  bool operator >=(U128 o) => compareTo(o) >= 0;

  @override
  bool operator ==(Object other) =>
      other is U128 && other.hi == hi && other.lo == lo;

  @override
  int get hashCode => Object.hash(hi, lo);

  /// Sixteen bytes, most significant first.
  Uint8List toBytesBE() {
    final out = Uint8List(16);
    final bd = ByteData.view(out.buffer);
    bd.setUint64(0, hi);
    bd.setUint64(8, lo);
    return out;
  }

  /// Reads sixteen big-endian bytes starting at [offset].
  static U128 fromBytesBE(List<int> bytes, [int offset = 0]) {
    if (offset + 16 > bytes.length) {
      throw ArgumentError('need 16 bytes at $offset, have ${bytes.length}');
    }
    var hi = 0, lo = 0;
    for (var i = 0; i < 8; i++) {
      hi = (hi << 8) | (bytes[offset + i] & 0xFF);
    }
    for (var i = 8; i < 16; i++) {
      lo = (lo << 8) | (bytes[offset + i] & 0xFF);
    }
    return U128(hi, lo);
  }

  /// Decimal representation. Used only by diagnostics and test failure output,
  /// so [BigInt] is acceptable here and nowhere else in this file.
  @override
  String toString() => toBigInt().toString();

  /// Escape hatch for tests and error messages only. No encoding path calls it.
  BigInt toBigInt() =>
      (BigInt.from(hi).toUnsigned(64) << 64) | BigInt.from(lo).toUnsigned(64);

  /// Test helper: builds from a [BigInt] in `[0, 2^128)`.
  static U128 fromBigInt(BigInt v) {
    if (v.isNegative || v.bitLength > 128) {
      throw ArgumentError.value(v, 'v', 'out of u128 range');
    }
    final mask = (BigInt.one << 64) - BigInt.one;
    return U128(((v >> 64) & mask).toSigned(64).toInt(),
        (v & mask).toSigned(64).toInt());
  }
}
