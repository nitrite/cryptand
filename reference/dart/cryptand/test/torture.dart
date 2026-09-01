/// The numeric torture set of `spec/11-conformance.md` section 6, plus the
/// generators the ordering tests draw from.
///
/// "numbers/ — the numeric torture set: +/-0, subnormals, 2^53 +/- 1,
///  i64/i128/u128 extremes, NaN payloads, int/float cross-type ordering"
library;

import 'dart:typed_data';

import 'package:cryptand/src/u128.dart';
import 'package:cryptand/src/value.dart';

double bitsToF64(int bits) => (ByteData(8)..setUint64(0, bits)).getFloat64(0);
double bitsToF32(int bits) => (ByteData(4)..setUint32(0, bits)).getFloat32(0);

CInt intOf(NumType t, BigInt v) {
  final neg = v.isNegative;
  return CInt(t, neg, U128.fromBigInt(neg ? -v : v));
}

/// Every integer the format can hold, at every boundary that has ever broken
/// an implementation.
List<CInt> torturedIntegers() {
  final out = <CInt>[];
  void add(NumType t, BigInt v) => out.add(intOf(t, v));

  final two = BigInt.two;
  for (final t in [NumType.i8, NumType.i16, NumType.i32, NumType.i64]) {
    final hi = two.pow(t.bits - 1);
    add(t, BigInt.zero);
    add(t, BigInt.one);
    add(t, -BigInt.one);
    add(t, hi - BigInt.one); // max
    add(t, -hi); // min: the magnitude that needs the unsigned width
  }
  for (final t in [NumType.u8, NumType.u16, NumType.u32, NumType.u64]) {
    add(t, BigInt.zero);
    add(t, BigInt.one);
    add(t, two.pow(t.bits) - BigInt.one); // max
  }
  // i128 / u128: the whole reason U128 exists.
  add(NumType.i128, two.pow(127) - BigInt.one);
  add(NumType.i128, -two.pow(127));
  add(NumType.u128, two.pow(128) - BigInt.one);
  add(NumType.u128, two.pow(127));

  // The 2^53 neighbourhood, where a fold through double stops being exact.
  for (final d in [-1, 0, 1]) {
    add(NumType.i64, two.pow(53) + BigInt.from(d));
    add(NumType.u64, two.pow(53) + BigInt.from(d));
    add(NumType.i64, -(two.pow(53) + BigInt.from(d)));
  }
  // Snowflake-shaped ids, the concrete bug from survey section 6.3.
  for (final v in [
    '1234567890123456789',
    '9007199254740993',
    '9223372036854775807',
  ]) {
    add(NumType.i64, BigInt.parse(v));
  }
  // Small values in every width, so cross-type equality has work to do.
  for (final t in [
    NumType.i8, NumType.i16, NumType.i32, NumType.i64, NumType.i128,
    NumType.u8, NumType.u16, NumType.u32, NumType.u64, NumType.u128,
    NumType.intVar,
  ]) {
    for (final v in [0, 1, 5, 9, 127]) {
      add(t, BigInt.from(v));
    }
    if (t.signed) {
      for (final v in [-1, -5, -9, -128]) {
        add(t, BigInt.from(v));
      }
    }
  }
  return out;
}

/// Every float that has ever broken an encoder.
List<CFloat> torturedFloats() {
  final f64 = <double>[
    0.0, -0.0, 1.0, -1.0, 5.0, -5.0, 9.0, -9.0,
    0.5, -0.5, 0.1, -0.1, 1e308, -1e308, 1e-308,
    double.minPositive, // 2^-1074, the smallest subnormal
    bitsToF64(0x000FFFFFFFFFFFFF), // largest subnormal
    bitsToF64(0x0010000000000000), // smallest normal
    bitsToF64(0x0008000000000000), // a mid subnormal
    double.maxFinite,
    double.infinity, double.negativeInfinity, double.nan,
    9007199254740992.0, // 2^53
    9007199254740994.0, // 2^53 + 2
    -9007199254740992.0,
    // A NaN with a non-canonical payload: spec/00-conventions.md section 3
    // requires canonicalization on encode, so this must behave as quiet NaN.
    bitsToF64(0x7FF8000000000001),
    bitsToF64(0xFFF8000000000000), // negative NaN
  ];
  final f32 = <double>[
    0.0, -0.0, 1.0, -1.0, 5.0, -5.0, 0.5, 0.1,
    bitsToF32(0x00000001), // smallest f32 subnormal
    bitsToF32(0x007FFFFF), // largest f32 subnormal
    bitsToF32(0x00800000), // smallest f32 normal
    bitsToF32(0x7F7FFFFF), // f32 max
    double.infinity, double.negativeInfinity, double.nan,
  ];
  return [
    for (final d in f64) CFloat(NumType.f64, d),
    for (final d in f32) CFloat(NumType.f32, d),
  ];
}

/// The exact value of a numeric [CValue] as a rational `num / den`, computed
/// with [BigInt] and therefore **independent of anything in `lib/`**.
///
/// This is what makes the ordering test a real test rather than a restatement
/// of the encoder: it compares CKE byte order against arithmetic that shares
/// no code with it.
(BigInt, BigInt)? exactRational(CValue v) {
  if (v is CInt) {
    final mag = v.magnitude.toBigInt();
    return (v.negative ? -mag : mag, BigInt.one);
  }
  final f = v as CFloat;
  final d = f.value;
  if (d.isNaN || d.isInfinite) return null;
  if (d == 0.0) return (BigInt.zero, BigInt.one);

  final int sig, exp;
  if (f.type == NumType.f64) {
    final bits = (ByteData(8)..setFloat64(0, d.abs())).getUint64(0);
    final biased = (bits >>> 52) & 0x7FF;
    final frac = bits & 0xFFFFFFFFFFFFF;
    if (biased == 0) {
      sig = frac;
      exp = -1074;
    } else {
      sig = (1 << 52) | frac;
      exp = biased - 1075;
    }
  } else {
    final bits = (ByteData(4)..setFloat32(0, d.abs())).getUint32(0);
    final biased = (bits >>> 23) & 0xFF;
    final frac = bits & 0x7FFFFF;
    if (biased == 0) {
      sig = frac;
      exp = -149;
    } else {
      sig = (1 << 23) | frac;
      exp = biased - 150;
    }
  }
  var n = BigInt.from(sig);
  var den = BigInt.one;
  if (exp >= 0) {
    n = n << exp;
  } else {
    den = BigInt.one << (-exp);
  }
  return (d.isNegative ? -n : n, den);
}

/// Independent exact ordering of the numeric domain, using [BigInt] only.
///
/// Order, per `spec/02-value-encoding.md` section 8 rules 2 and 3:
/// -inf < finite < +inf < NaN, with -0.0 == +0.0 and NaN == NaN.
int referenceCompareNumeric(CValue a, CValue b) {
  int cls(CValue v) {
    if (v is CFloat) {
      if (v.value.isNaN) return 5;
      if (v.value == double.infinity) return 4;
      if (v.value == double.negativeInfinity) return 0;
    }
    return 2; // finite (including every integer)
  }

  final ca = cls(a), cb = cls(b);
  if (ca != cb) return ca.compareTo(cb);
  if (ca != 2) return 0;
  final ra = exactRational(a)!, rb = exactRational(b)!;
  // a1/a2 vs b1/b2  ->  a1*b2 vs b1*a2, denominators are positive.
  return (ra.$1 * rb.$2).compareTo(rb.$1 * ra.$2);
}
