/// CKE, the Cryptand Ordered Key Encoding. `spec/03-key-encoding.md`.
///
/// One invariant defines this file:
///
///   > For any two keys a and b, `memcmp(CKE(a), CKE(b))` has the same sign as
///   > the logical comparison of a and b defined in
///   > `spec/02-value-encoding.md` section 8.
///
/// `test/cke_order_test.dart` asserts exactly that over a cross product of the
/// numeric torture set, so a regression here fails loudly rather than as a
/// wrong query result three SDKs later.
///
/// **All multi-byte integers in this file are big-endian.** It is the only
/// part of the format where that is true.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'bytes.dart';
import 'errors.dart';
import 'u128.dart';
import 'value.dart';

/// CKE group tags, `spec/03-key-encoding.md` section 2. Spaced by 0x10 so a
/// future group can be inserted without renumbering — though section 8 of
/// `spec/11-conformance.md` notes that a *new* group is a major-version change
/// because it moves the cross-type order.
class Group {
  static const int nul = 0x00;
  static const int boolean = 0x10;
  static const int number = 0x30;
  static const int temporal = 0x40;
  static const int char = 0x50;
  static const int string = 0x60;
  static const int bytes = 0x70;
  static const int nitriteId = 0x80;
  static const int uuid = 0x90;
  static const int array = 0xA0;
  /// Never emitted. Reserved so that a run of 0xFF is above every valid key,
  /// which `successor` relies on.
  static const int forbidden = 0xFF;
}

/// NUMBER sign classes, `spec/03-key-encoding.md` section 4. Ordered.
class SignClass {
  static const int negInfinity = 0x00;
  static const int negFinite = 0x01;
  static const int zero = 0x02;
  static const int posFinite = 0x03;
  static const int posInfinity = 0x04;
  static const int nan = 0x05;
}

/// TEMPORAL subclasses, `spec/03-key-encoding.md` section 5.
class TemporalClass {
  /// Every instant-valued CVE tag canonicalizes here: TIMESTAMP,
  /// TIMESTAMP_NS and ZONED alike, so two values denoting the same instant
  /// are one key.
  static const int instant = 0x01;

  /// Reserved and MUST NOT be written. An earlier draft split millisecond and
  /// nanosecond instants across 0x01 and 0x02, which made the subclass byte
  /// order by *precision* instead of by instant.
  static const int reservedWasInstantNs = 0x02;

  static const int date = 0x03;
  static const int time = 0x04;
  static const int duration = 0x05;
}

const int _signBit64 = -0x8000000000000000;

// ---------------------------------------------------------------------------
// Escaping, section 3.1
// ---------------------------------------------------------------------------

/// `esc(s)`: self-delimiting, order-preserving byte-string encoding.
///
/// The terminator `00 00` is below every escaped continuation `00 01`, so a
/// shorter string sorts before a longer one that extends it.
void writeEsc(ByteWriter w, List<int> s) {
  for (final b in s) {
    if (b == 0x00) {
      w
        ..u8(0x00)
        ..u8(0x01);
    } else {
      w.u8(b);
    }
  }
  w
    ..u8(0x00)
    ..u8(0x00);
}

/// `esc_open(s)`: [writeEsc] without the terminator — the shared prefix of
/// every byte string beginning with [s]. Section 8's `starts_with`.
void writeEscOpen(ByteWriter w, List<int> s) {
  for (final b in s) {
    if (b == 0x00) {
      w
        ..u8(0x00)
        ..u8(0x01);
    } else {
      w.u8(b);
    }
  }
}

/// Reads an `esc`-encoded byte string, returning the decoded bytes.
Uint8List readEsc(ByteReader r) {
  final out = <int>[];
  while (true) {
    final b = r.u8();
    if (b != 0x00) {
      out.add(b);
      continue;
    }
    final n = r.u8();
    if (n == 0x00) return Uint8List.fromList(out);
    if (n == 0x01) {
      out.add(0x00);
      continue;
    }
    // Section 7: "A decoder MUST reject ... a non-canonical escape (0x00
    // followed by anything but 0x00 or 0x01)."
    throw CorruptionException(
        'non-canonical CKE escape 00 ${n.toRadixString(16)}',
        offset: r.position - 1);
  }
}

// ---------------------------------------------------------------------------
// NUMBER, section 4
// ---------------------------------------------------------------------------

/// The exact pair `(e, m)` with `|v| = m * 2^e` and `1 <= m < 2`, with `m` held
/// as a 128-bit MSB-aligned fraction.
typedef Normalized = ({int e, U128 m});

/// Section 4.1, integer path.
///
/// ```
/// n = 128 - leading_zeros(u)
/// e = n - 1
/// m = u << (128 - n)
/// ```
Normalized normalizeMagnitude(U128 u) {
  if (u.isZero) throw InvalidArgumentException('zero has no (e, m) form');
  final n = u.bitLength;
  return (e: n - 1, m: u.shl(128 - n));
}

/// Section 4.1, binary64 path. [bits] is the raw IEEE 754 pattern.
Normalized normalizeF64(int bits) {
  final biasedExp = (bits >>> 52) & 0x7FF;
  final frac = bits & 0xFFFFFFFFFFFFF;
  int e;
  int sig;
  if (biasedExp != 0) {
    sig = (1 << 52) | frac;
    e = biasedExp - 1023;
  } else {
    // Subnormal: shift the fraction up until its implicit bit is at 52.
    final k = 52 - (63 - clz64(frac));
    sig = frac << k;
    e = -1022 - k;
  }
  return (e: e, m: U128(0, sig).shl(128 - 53));
}

/// Section 4.1, binary32 path. [bits] is the raw 32-bit IEEE 754 pattern.
Normalized normalizeF32(int bits) {
  final biasedExp = (bits >>> 23) & 0xFF;
  final frac = bits & 0x7FFFFF;
  int e;
  int sig;
  if (biasedExp != 0) {
    sig = (1 << 23) | frac;
    e = biasedExp - 127;
  } else {
    final k = 23 - (63 - clz64(frac));
    sig = frac << k;
    e = -126 - k;
  }
  return (e: e, m: U128(0, sig).shl(128 - 24));
}

/// Section 4.2: `u16be(e + 16384) || esc(mbytes)`, where `mbytes` is the 16
/// bytes of `m` with trailing zeros removed.
Uint8List numberBody(Normalized n) {
  final full = n.m.toBytesBE();
  var end = full.length;
  while (end > 1 && full[end - 1] == 0x00) {
    end--;
  }
  final biased = n.e + 16384;
  if (biased < 0 || biased > 0xFFFF) {
    throw InvalidArgumentException('binary exponent ${n.e} outside CKE range');
  }
  final w = ByteWriter(end + 6)
    ..u8((biased >> 8) & 0xFF)
    ..u8(biased & 0xFF);
  writeEsc(w, Uint8List.sublistView(full, 0, end));
  return w.takeBytes();
}

/// Section 4.2: negatives are the positive body with every byte inverted.
/// Inverting a byte string reverses its lexicographic order, which is what
/// negatives need — larger magnitude must sort lower.
Uint8List complementBytes(Uint8List b) {
  final out = Uint8List(b.length);
  for (var i = 0; i < b.length; i++) {
    out[i] = (~b[i]) & 0xFF;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Whether [v] has a CKE encoding at all.
///
/// Section 2: DOC, MAP, VECTOR, GEOMETRY, REGEX, OPAQUE, DEC128 and the three
/// indirection tags have none, and attempting to use one as a key is an error.
bool isKeyEncodable(CValue v) => switch (v) {
      CNull() ||
      CBool() ||
      CFloat() ||
      CChar() ||
      CStr() ||
      CBytes() ||
      CTimestamp() ||
      CTimestampNs() ||
      CZoned() ||
      CDate() ||
      CTime() ||
      CDuration() ||
      CUuid() ||
      CNitriteId() =>
        true,
      CInt() => v.type.isKeyEncodable,
      CArray() => v.items.every(isKeyEncodable),
      _ => false,
    };

/// Encodes [v] as a CKE key.
Uint8List encodeKey(CValue v) {
  final w = ByteWriter(32);
  writeKey(w, v);
  return w.takeBytes();
}

void writeKey(ByteWriter w, CValue v, [int depth = 0]) {
  if (depth > 100) {
    throw const LimitException('CKE nesting deeper than 100');
  }
  switch (v) {
    case CNull():
      w.u8(Group.nul);
    case CBool():
      w
        ..u8(Group.boolean)
        ..u8(v.value ? 0x01 : 0x00);
    case CInt():
      _writeInt(w, v);
    case CFloat():
      _writeFloat(w, v);
    case CChar():
      w.u8(Group.char);
      _wU32be(w, v.scalar);
    case CStr():
      w.u8(Group.string);
      writeEsc(w, encodeUtf8Strict(v.value));
    case CBytes():
      w.u8(Group.bytes);
      writeEsc(w, v.value);
    case CNitriteId():
      w.u8(Group.nitriteId);
      // Flip the sign bit so a signed i64 sorts correctly as unsigned bytes.
      _wU64be(w, v.id ^ _signBit64);
    case CUuid():
      w
        ..u8(Group.uuid)
        ..bytes(v.bytes);
    case CTimestamp():
      _writeInstant(w, _millisToInstant(v.millis));
    case CTimestampNs():
      _writeInstant(w, (secs: v.secs, nanos: v.nanos));
    case CZoned():
      // The zone id is not part of the key: two zoned timestamps denoting the
      // same instant are the same key (section 5).
      _writeInstant(w, _millisToInstant(v.millis));
    case CDate():
      w
        ..u8(Group.temporal)
        ..u8(TemporalClass.date);
      _wU32be(w, v.days ^ 0x80000000);
    case CTime():
      w
        ..u8(Group.temporal)
        ..u8(TemporalClass.time);
      _wU64be(w, v.nanos);
    case CDuration():
      w
        ..u8(Group.temporal)
        ..u8(TemporalClass.duration);
      _wU64be(w, v.secs ^ _signBit64);
      _wU32be(w, v.nanos);
    case CArray():
      w.u8(Group.array);
      for (final e in v.items) {
        w.u8(0x01); // ELEM_CONTINUE
        writeKey(w, e, depth + 1);
      }
      w.u8(0x00); // ELEM_END, below ELEM_CONTINUE so [a] < [a, b]
    case CDec128():
      throw const InvalidArgumentException(
          'DEC128 has no CKE encoding and cannot be a key '
          '(spec/03-key-encoding.md section 4.4)');
    default:
      throw InvalidArgumentException(
          '${v.runtimeType} has no CKE encoding and cannot be a key '
          '(spec/03-key-encoding.md section 2)');
  }
}

typedef Instant = ({int secs, int nanos});

/// Section 5: `TIMESTAMP(millis)` canonicalizes with **floor** division, so
/// instants before the epoch normalize correctly.
Instant _millisToInstant(int millis) {
  var secs = millis ~/ 1000;
  var rem = millis - secs * 1000;
  if (rem < 0) {
    secs -= 1;
    rem += 1000;
  }
  return (secs: secs, nanos: rem * 1000000);
}

void _writeInstant(ByteWriter w, Instant t) {
  w
    ..u8(Group.temporal)
    ..u8(TemporalClass.instant);
  _wU64be(w, t.secs ^ _signBit64);
  _wU32be(w, t.nanos);
}

void _writeInt(ByteWriter w, CInt v) {
  w.u8(Group.number);
  if (v.isZero) {
    w
      ..u8(SignClass.zero)
      ..u8(v.type.cke);
    return;
  }
  final body = numberBody(normalizeMagnitude(v.magnitude));
  if (v.negative) {
    w
      ..u8(SignClass.negFinite)
      ..bytes(complementBytes(body));
  } else {
    w
      ..u8(SignClass.posFinite)
      ..bytes(body);
  }
  w.u8(v.type.cke);
}

void _writeFloat(ByteWriter w, CFloat v) {
  w.u8(Group.number);
  final d = v.value;
  if (d.isNaN) {
    w
      ..u8(SignClass.nan)
      ..u8(v.type.cke);
    return;
  }
  if (d.isInfinite) {
    w
      ..u8(d.isNegative ? SignClass.negInfinity : SignClass.posInfinity)
      ..u8(v.type.cke);
    return;
  }
  if (d == 0.0) {
    // Section 8 rule 3: -0.0 equals +0.0 and they sort equal.
    w
      ..u8(SignClass.zero)
      ..u8(v.type.cke);
    return;
  }
  final Normalized n;
  if (v.type == NumType.f32) {
    final bd = ByteData(4)..setFloat32(0, d.abs());
    n = normalizeF32(bd.getUint32(0));
  } else {
    final bd = ByteData(8)..setFloat64(0, d.abs());
    n = normalizeF64(bd.getUint64(0));
  }
  final body = numberBody(n);
  if (d.isNegative) {
    w
      ..u8(SignClass.negFinite)
      ..bytes(complementBytes(body));
  } else {
    w
      ..u8(SignClass.posFinite)
      ..bytes(body);
  }
  w.u8(v.type.cke);
}

void _wU32be(ByteWriter w, int v) {
  w
    ..u8((v >>> 24) & 0xFF)
    ..u8((v >>> 16) & 0xFF)
    ..u8((v >>> 8) & 0xFF)
    ..u8(v & 0xFF);
}

void _wU64be(ByteWriter w, int v) => w.u64be(v);


// ---------------------------------------------------------------------------
// Decoding, section 7
// ---------------------------------------------------------------------------

/// Decodes one CKE key from [r].
///
/// Section 7: "CKE is decodable. Each group's body is either fixed-width or
/// self-delimiting, so a decoder reads the tag, consumes exactly the body, and
/// returns a value plus the number of bytes consumed."
///
/// Two groups do not round-trip to the exact source tag, by design:
/// TEMPORAL/INSTANT always decodes to [CTimestampNs] whatever instant-valued
/// tag produced it, and a ZONED key has lost its zone. Section 7 states this;
/// it is the price of two values denoting the same instant being one key.
CValue readKey(ByteReader r, [int depth = 0]) {
  if (depth > 100) throw const LimitException('CKE nesting deeper than 100');
  final tag = r.u8();
  switch (tag) {
    case Group.nul:
      return const CNull();
    case Group.boolean:
      final b = r.u8();
      if (b > 1) throw const CorruptionException('CKE bool body not 0 or 1');
      return CBool(b == 1);
    case Group.number:
      return _readNumber(r);
    case Group.temporal:
      return _readTemporal(r);
    case Group.char:
      return CChar(_u32be(r));
    case Group.string:
      final raw = readEsc(r);
      try {
        return CStr(const Utf8Decoder(allowMalformed: false).convert(raw));
      } on FormatException catch (e) {
        throw CorruptionException('ill-formed UTF-8 in CKE string: ${e.message}');
      }
    case Group.bytes:
      return CBytes(readEsc(r));
    case Group.nitriteId:
      return CNitriteId(_u64be(r) ^ _signBit64);
    case Group.uuid:
      return CUuid(r.bytesCopy(16));
    case Group.array:
      final items = <CValue>[];
      while (true) {
        final marker = r.u8();
        if (marker == 0x00) return CArray(items);
        if (marker != 0x01) {
          throw CorruptionException(
              'CKE array marker 0x${marker.toRadixString(16)} is not 0x00 or 0x01');
        }
        items.add(readKey(r, depth + 1));
      }
    default:
      throw CorruptionException(
          'unknown CKE group tag 0x${tag.toRadixString(16)}');
  }
}

/// Decodes a whole key and asserts nothing follows it.
CValue decodeKey(Uint8List bytes) {
  final r = ByteReader(bytes);
  final v = readKey(r);
  if (!r.isAtEnd) {
    throw CorruptionException('${r.remaining} trailing byte(s) after CKE key');
  }
  return v;
}

NumType _numTypeFromCke(int code) {
  for (final t in NumType.values) {
    if (t.cke == code) return t;
  }
  throw CorruptionException(
      'unknown CKE numeric type code 0x${code.toRadixString(16)}'
      '${code == 0x0D ? " (0x0D is reserved: DEC128 is not a key)" : ""}');
}

CValue _readNumber(ByteReader r) {
  final sign = r.u8();
  switch (sign) {
    case SignClass.zero:
      final t = _numTypeFromCke(r.u8());
      return t.isFloat ? CFloat(t, 0.0) : CInt(t, false, U128.zero);
    case SignClass.nan:
      final t = _numTypeFromCke(r.u8());
      if (!t.isFloat) throw const CorruptionException('NaN with integer type code');
      return CFloat(t, double.nan);
    case SignClass.posInfinity:
    case SignClass.negInfinity:
      final t = _numTypeFromCke(r.u8());
      if (!t.isFloat) {
        throw const CorruptionException('infinity with integer type code');
      }
      return CFloat(t,
          sign == SignClass.posInfinity ? double.infinity : double.negativeInfinity);
    case SignClass.posFinite:
    case SignClass.negFinite:
      final negative = sign == SignClass.negFinite;
      final int biased;
      final Uint8List mbytes;
      if (negative) {
        biased = ((~r.u8() & 0xFF) << 8) | (~r.u8() & 0xFF);
        mbytes = _readEscInverted(r);
      } else {
        biased = (r.u8() << 8) | r.u8();
        mbytes = readEsc(r);
      }
      // Section 7: "A decoder MUST reject ... a mantissa whose first byte is
      // below 0x80, and an empty mantissa."
      if (mbytes.isEmpty) throw const CorruptionException('empty CKE mantissa');
      if (mbytes[0] < 0x80) {
        throw const CorruptionException(
            'CKE mantissa is not MSB-aligned (first byte below 0x80)');
      }
      if (mbytes.length > 16) {
        throw const CorruptionException('CKE mantissa longer than 16 bytes');
      }
      final padded = Uint8List(16)..setRange(0, mbytes.length, mbytes);
      final m = U128.fromBytesBE(padded);
      final e = biased - 16384;
      final t = _numTypeFromCke(r.u8());
      return _rebuild(t, negative, e, m);
    default:
      throw CorruptionException(
          'unknown CKE sign class 0x${sign.toRadixString(16)}');
  }
}

/// Reads a complemented `esc` stream, inverting each byte as it goes.
Uint8List _readEscInverted(ByteReader r) {
  final out = <int>[];
  while (true) {
    final b = (~r.u8()) & 0xFF;
    if (b != 0x00) {
      out.add(b);
      continue;
    }
    final n = (~r.u8()) & 0xFF;
    if (n == 0x00) return Uint8List.fromList(out);
    if (n == 0x01) {
      out.add(0x00);
      continue;
    }
    throw CorruptionException(
        'non-canonical complemented CKE escape', offset: r.position - 1);
  }
}

/// Rebuilds a value from `(type, sign, e, m)`. The exact inverse of
/// section 4.1's normalization.
CValue _rebuild(NumType t, bool negative, int e, U128 m) {
  if (t.isFloat) {
    return CFloat(t, _rebuildFloat(t, negative, e, m));
  }
  // Integer: u = m >> (127 - e), which inverts `m = u << (128 - n)`, e = n - 1.
  if (e < 0 || e > 127) {
    throw CorruptionException('binary exponent $e cannot be an integer of $t');
  }
  final u = m.shr(127 - e);
  if (u.shl(127 - e) != m) {
    throw CorruptionException('CKE integer mantissa has a fractional part');
  }
  return CInt(t, negative, u);
}

double _rebuildFloat(NumType t, bool negative, int e, U128 m) {
  final bd = ByteData(8);
  if (t == NumType.f64) {
    final sig = m.shr(128 - 53).lo;
    int bits;
    if (e >= -1022) {
      if (e > 1023) throw CorruptionException('f64 exponent $e out of range');
      bits = ((e + 1023) << 52) | (sig & 0xFFFFFFFFFFFFF);
    } else {
      final k = -1022 - e;
      if (k > 52) throw CorruptionException('f64 exponent $e below subnormal');
      bits = sig >>> k;
    }
    if (negative) bits |= _signBit64;
    bd.setUint64(0, bits);
    return bd.getFloat64(0);
  }
  final sig = m.shr(128 - 24).lo;
  int bits;
  if (e >= -126) {
    if (e > 127) throw CorruptionException('f32 exponent $e out of range');
    bits = ((e + 127) << 23) | (sig & 0x7FFFFF);
  } else {
    final k = -126 - e;
    if (k > 23) throw CorruptionException('f32 exponent $e below subnormal');
    bits = sig >>> k;
  }
  if (negative) bits |= 0x80000000;
  bd.setUint32(0, bits);
  return bd.getFloat32(0);
}

CValue _readTemporal(ByteReader r) {
  final sub = r.u8();
  switch (sub) {
    case TemporalClass.instant:
      final secs = _u64be(r) ^ _signBit64;
      final nanos = _u32be(r);
      if (nanos > 999999999) {
        throw CorruptionException('instant nanos $nanos out of range');
      }
      return CTimestampNs(secs, nanos);
    case TemporalClass.date:
      // Sign-extend: days is an i32, and _u32be yields 0..2^32-1.
      return CDate((_u32be(r) ^ 0x80000000).toSigned(32));
    case TemporalClass.time:
      return CTime(_u64be(r));
    case TemporalClass.duration:
      final secs = _u64be(r) ^ _signBit64;
      final nanos = _u32be(r);
      if (nanos > 999999999) {
        throw CorruptionException('duration nanos $nanos out of range');
      }
      return CDuration(secs, nanos);
    case TemporalClass.reservedWasInstantNs:
      throw const CorruptionException(
          'CKE temporal subclass 0x02 is reserved and MUST NOT be written '
          '(spec/03-key-encoding.md section 5)');
    default:
      throw CorruptionException(
          'unknown CKE temporal subclass 0x${sub.toRadixString(16)}');
  }
}

int _u32be(ByteReader r) =>
    (r.u8() << 24) | (r.u8() << 16) | (r.u8() << 8) | r.u8();

int _u64be(ByteReader r) {
  var v = 0;
  for (var i = 0; i < 8; i++) {
    v = (v << 8) | r.u8();
  }
  return v;
}

// ---------------------------------------------------------------------------
// Range construction, section 8
// ---------------------------------------------------------------------------

/// The five normative helpers of section 8, and no others. Every SDK's query
/// planner is required to build every bound from exactly these.
class Keys {
  Keys._();

  /// `UNBOUNDED_BELOW` is the empty byte string, which is below every key.
  static final Uint8List unboundedBelow = Uint8List(0);

  /// `successor(k)`: the least byte string greater than every string having
  /// [k] as a prefix. Returns null for `UNBOUNDED_ABOVE`, which is why group
  /// tag 0xFF is reserved and never emitted.
  static Uint8List? successor(Uint8List k) {
    var end = k.length;
    while (end > 0 && k[end - 1] == 0xFF) {
      end--;
    }
    if (end == 0) return null;
    final out = Uint8List(end)..setRange(0, end, k);
    out[end - 1] = out[end - 1] + 1;
    return out;
  }

  /// `prefix_of_array(p1..pk)`: the shared prefix of every ARRAY key whose
  /// first k elements are p1..pk.
  static Uint8List prefixOfArray(List<CValue> prefix) {
    final w = ByteWriter(16 * prefix.length + 4)..u8(Group.array);
    for (final p in prefix) {
      w.u8(0x01);
      writeKey(w, p);
    }
    return w.takeBytes();
  }

  /// `N(v)`: the NUMBER encoding **without** the trailing type code — the
  /// shared prefix of every numeric type equal to [v].
  ///
  /// Every numeric comparison MUST be built from this and never from
  /// [encodeKey]. A bound carrying a type code cuts between numeric *types*
  /// rather than numeric values, which makes `field >= 5` miss an `I8(5)` and
  /// `field > 5` return a `U8(5)`. Section 8.2 has the worked failure.
  static Uint8List numberPrefix(CValue v) {
    if (v is! CInt && v is! CFloat) {
      throw InvalidArgumentException('N(v) needs a numeric value, got $v');
    }
    final full = encodeKey(v);
    return Uint8List.sublistView(full, 0, full.length - 1);
  }

  /// `esc_open`-based string prefix: the shared prefix of every string key
  /// beginning with [s].
  static Uint8List stringPrefix(String s) {
    final w = ByteWriter(s.length + 4)..u8(Group.string);
    writeEscOpen(w, encodeUtf8Strict(s));
    return w.takeBytes();
  }

  /// `array_prefix_numeric(p1..pk)`: [prefixOfArray] with the **last** element
  /// left type-agnostic. This is what makes "one numeric domain" reachable on
  /// an actual index, where every key is an ARRAY.
  static Uint8List arrayPrefixNumeric(List<CValue> prefix) {
    if (prefix.isEmpty) {
      throw const InvalidArgumentException('array_prefix_numeric needs an element');
    }
    final w = ByteWriter(16 * prefix.length + 4)..u8(Group.array);
    for (var i = 0; i < prefix.length - 1; i++) {
      w.u8(0x01);
      writeKey(w, prefix[i]);
    }
    w
      ..u8(0x01)
      ..bytes(numberPrefix(prefix.last));
    return w.takeBytes();
  }
}

/// A half-open key range `[lower, upper)`. [upper] of null is unbounded above.
///
/// Section 8: "Every range below is half-open ... there is no exclusive lower
/// bound anywhere in the format, because `successor` already produces one."
final class KeyRange {
  const KeyRange(this.lower, this.upper);

  final Uint8List lower;
  final Uint8List? upper;

  /// Every key having [prefix] as a prefix.
  factory KeyRange.prefix(Uint8List prefix) =>
      KeyRange(prefix, Keys.successor(prefix));

  /// `field == v`, exactly one declared numeric type or a non-numeric value.
  factory KeyRange.eq(CValue v) => KeyRange.prefix(encodeKey(v));

  /// `field == v` across every numeric type. Section 8.2.
  factory KeyRange.eqNumeric(CValue v) =>
      KeyRange.prefix(Keys.numberPrefix(v));

  /// `field > v`. Numeric values MUST use [gtNumeric].
  factory KeyRange.gt(CValue v) {
    final s = Keys.successor(encodeKey(v));
    return KeyRange(s ?? Uint8List(0), s == null ? Uint8List(0) : null);
  }

  factory KeyRange.gtNumeric(CValue v) =>
      KeyRange(Keys.successor(Keys.numberPrefix(v)) ?? Uint8List(0), null);

  factory KeyRange.gteNumeric(CValue v) => KeyRange(Keys.numberPrefix(v), null);

  factory KeyRange.ltNumeric(CValue v) =>
      KeyRange(Keys.unboundedBelow, Keys.numberPrefix(v));

  factory KeyRange.lteNumeric(CValue v) =>
      KeyRange(Keys.unboundedBelow, Keys.successor(Keys.numberPrefix(v)));

  /// `field between a, b` inclusive, across every numeric type.
  factory KeyRange.betweenNumeric(CValue a, CValue b) =>
      KeyRange(Keys.numberPrefix(a), Keys.successor(Keys.numberPrefix(b)));

  factory KeyRange.startsWith(String s) => KeyRange.prefix(Keys.stringPrefix(s));

  bool contains(Uint8List key) =>
      compareKeys(key, lower) >= 0 &&
      (upper == null || compareKeys(key, upper!) < 0);

  @override
  String toString() =>
      '[${_hex(lower)}, ${upper == null ? "inf" : _hex(upper!)})';
}

/// Unsigned lexicographic byte comparison. This is the *only* comparison the
/// engine performs on keys; no host comparator is ever consulted.
int compareKeys(List<int> a, List<int> b) {
  // The typed loop, for the callers that pass byte arrays -- the point read's
  // `SegmentRef.covers` among them. Through `List<int>` every element read is
  // a polymorphic call, and covering one segment cost 11 % of a read.
  if (a is Uint8List && b is Uint8List) return _compareBytes(a, b);
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    final d = a[i] - b[i];
    if (d != 0) return d < 0 ? -1 : 1;
  }
  return a.length == b.length ? 0 : (a.length < b.length ? -1 : 1);
}

int _compareBytes(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    final d = a[i] - b[i];
    if (d != 0) return d < 0 ? -1 : 1;
  }
  return a.length == b.length ? 0 : (a.length < b.length ? -1 : 1);
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join(' ').toUpperCase();
