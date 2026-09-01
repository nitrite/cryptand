/// The Cryptand value model, `spec/02-value-encoding.md` section 1.
///
/// One class per CVE type tag. The integer family collapses into a single
/// [CInt] carrying `(tag, sign, magnitude)` because that is the shape both
/// encodings want: CVE reconstitutes a width from it, and CKE section 4
/// normalizes it to `(e, m)` without a second representation.
library;

import 'dart:typed_data';

import 'errors.dart';
import 'u128.dart';

/// CVE type tags, `spec/02-value-encoding.md` section 1.
class Tag {
  static const int nul = 0x00;
  static const int fals = 0x01;
  static const int tru = 0x02;
  static const int i8 = 0x03;
  static const int i16 = 0x04;
  static const int i32 = 0x05;
  static const int i64 = 0x06;
  static const int i128 = 0x07;
  static const int u8 = 0x08;
  static const int u16 = 0x09;
  static const int u32 = 0x0A;
  static const int u64 = 0x0B;
  static const int u128 = 0x0C;
  static const int intVar = 0x0D;
  static const int f32 = 0x0E;
  static const int f64 = 0x0F;
  static const int dec128 = 0x10;
  static const int char = 0x11;
  static const int str = 0x12;
  static const int bytes = 0x13;
  static const int timestamp = 0x14;
  static const int timestampNs = 0x15;
  static const int zoned = 0x16;
  static const int date = 0x17;
  static const int time = 0x18;
  static const int duration = 0x19;
  static const int uuid = 0x1A;
  static const int nitriteId = 0x1B;
  static const int regex = 0x1C;
  static const int array = 0x20;
  static const int map = 0x21;
  static const int doc = 0x22;
  static const int vector = 0x23;
  static const int geometry = 0x24;
  static const int blobRef = 0x30;
  static const int overflowRef = 0x31;
  static const int vlogRef = 0x32;
  static const int opaque = 0x7F;
}

/// The numeric family. [cve] is the CVE type tag; [cke] is the CKE type code
/// of `spec/03-key-encoding.md` section 4.3, which is a *different* numbering
/// and is a place two implementations can silently disagree.
enum NumType {
  i8(Tag.i8, 0x00, 8, true),
  i16(Tag.i16, 0x01, 16, true),
  i32(Tag.i32, 0x02, 32, true),
  i64(Tag.i64, 0x03, 64, true),
  i128(Tag.i128, 0x04, 128, true),
  u8(Tag.u8, 0x05, 8, false),
  u16(Tag.u16, 0x06, 16, false),
  u32(Tag.u32, 0x07, 32, false),
  u64(Tag.u64, 0x08, 64, false),
  u128(Tag.u128, 0x09, 128, false),
  f32(Tag.f32, 0x0A, 32, true),
  f64(Tag.f64, 0x0B, 64, true),
  intVar(Tag.intVar, 0x0C, 64, true),
  // 0x0D is reserved in CKE: spec/03-key-encoding.md section 4.4 removed
  // DEC128 from the key domain because a decimal fraction has no exact
  // binary m x 2^e form. It keeps its CVE tag and no CKE code.
  dec128(Tag.dec128, -1, 128, true);

  const NumType(this.cve, this.cke, this.bits, this.signed);
  final int cve;
  final int cke;
  final int bits;
  final bool signed;

  bool get isFloat => this == NumType.f32 || this == NumType.f64;
  bool get isKeyEncodable => cke >= 0;
}

/// Base of every Cryptand value.
sealed class CValue {
  const CValue();

  /// The CVE type tag this value encodes as.
  int get tag;
}

final class CNull extends CValue {
  const CNull();
  @override
  int get tag => Tag.nul;
  @override
  bool operator ==(Object other) => other is CNull;
  @override
  int get hashCode => 0;
  @override
  String toString() => 'null';
}

final class CBool extends CValue {
  const CBool(this.value);
  final bool value;
  @override
  int get tag => value ? Tag.tru : Tag.fals;
  @override
  bool operator ==(Object other) => other is CBool && other.value == value;
  @override
  int get hashCode => value.hashCode;
  @override
  String toString() => '$value';
}

/// Every integer tag, carried as sign plus 128-bit magnitude.
///
/// `spec/02-value-encoding.md` section 1.1: "The declared width is metadata,
/// never semantics." [type] round-trips the source width; [negative] and
/// [magnitude] carry the value, and equality (section 8 rule 2) ignores the
/// width entirely.
final class CInt extends CValue {
  CInt(this.type, this.negative, this.magnitude) {
    if (type.isFloat || type == NumType.dec128) {
      throw InvalidArgumentException('$type is not an integer type');
    }
    if (negative && !type.signed) {
      throw InvalidArgumentException('$type cannot be negative');
    }
    if (magnitude.isZero && negative) {
      throw InvalidArgumentException('negative zero is not an integer');
    }
    _checkRange();
  }

  final NumType type;
  final bool negative;
  final U128 magnitude;

  void _checkRange() {
    final bits = type.bits;
    if (type.signed) {
      // Magnitude fits in bits-1, except the single value -2^(bits-1).
      final maxMag = negative ? bits - 1 : bits - 1;
      if (magnitude.bitLength > maxMag) {
        final isMin = negative &&
            magnitude.bitLength == bits &&
            magnitude == U128.one.shl(bits - 1);
        if (!(negative && magnitude == U128.one.shl(bits - 1)) && !isMin) {
          throw InvalidArgumentException(
              'magnitude $magnitude does not fit $type');
        }
      }
    } else if (magnitude.bitLength > bits) {
      throw InvalidArgumentException('magnitude $magnitude does not fit $type');
    }
  }

  /// Builds from a Dart `int`, which is exactly `i64`.
  factory CInt.of(NumType type, int v) => v < 0
      ? CInt(type, true, U128(0, v == -0x8000000000000000 ? v : -v))
      : CInt(type, false, U128(0, v));

  factory CInt.i32(int v) => CInt.of(NumType.i32, v);
  factory CInt.i64(int v) => CInt.of(NumType.i64, v);
  factory CInt.varInt(int v) => CInt.of(NumType.intVar, v);

  /// Builds an unsigned value from a raw 64-bit pattern.
  factory CInt.u64Bits(int bits) => CInt(NumType.u64, false, U128(0, bits));

  bool get isZero => magnitude.isZero;

  /// The value as a Dart `int`, or null if it does not fit `i64` exactly.
  int? get asInt {
    if (magnitude.hi != 0) return null;
    if (!negative) return magnitude.lo >= 0 ? magnitude.lo : null;
    if (magnitude.lo == -0x8000000000000000) return -0x8000000000000000;
    return magnitude.lo >= 0 ? -magnitude.lo : null;
  }

  @override
  int get tag => type.cve;

  @override
  bool operator ==(Object other) =>
      other is CInt &&
      other.type == type &&
      other.negative == negative &&
      other.magnitude == magnitude;

  @override
  int get hashCode => Object.hash(type, negative, magnitude);

  @override
  String toString() => '${negative ? "-" : ""}$magnitude${_suffix()}';
  String _suffix() => type == NumType.intVar ? '' : '_${type.name}';
}

final class CFloat extends CValue {
  /// Builds a float value.
  ///
  /// An `f32` value is **canonicalized through a binary32 round trip** at
  /// construction. Dart has only `double`, so `CFloat(f32, 0.1)` would
  /// otherwise hold a binary64 that binary32 cannot represent, and encoding it
  /// would narrow it — making encode-then-decode change the value. Java has the
  /// same hazard in reverse (`float` widens silently to `double`), so this is a
  /// portability rule, not a Dart workaround: an `f32` value is exactly what
  /// binary32 can hold, always.
  factory CFloat(NumType type, double value) {
    if (type == NumType.f32) {
      final bd = ByteData(4)..setFloat32(0, value);
      return CFloat._(type, bd.getFloat32(0));
    }
    if (type != NumType.f64) {
      throw InvalidArgumentException('$type is not a float type');
    }
    return CFloat._(type, value);
  }

  const CFloat._(this.type, this.value);

  factory CFloat.f64(double v) => CFloat(NumType.f64, v);
  factory CFloat.f32(double v) => CFloat(NumType.f32, v);

  final NumType type;
  final double value;

  @override
  int get tag => type.cve;

  @override
  bool operator ==(Object other) =>
      other is CFloat &&
      other.type == type &&
      // Identical bit patterns, so NaN == NaN and -0.0 != +0.0 at this level.
      // Semantic equality is compareValues, spec section 8 rules 3 and 2.
      value.compareTo(other.value) == 0;

  @override
  int get hashCode => Object.hash(type, value);
  @override
  String toString() => '$value${type == NumType.f32 ? "f32" : ""}';
}

/// IEEE 754-2008 decimal128, sixteen opaque bytes.
///
/// Storable but **not a key**: `spec/03-key-encoding.md` section 4.4.
final class CDec128 extends CValue {
  CDec128(Uint8List bytes) : bytes = Uint8List.fromList(bytes) {
    if (bytes.length != 16) {
      throw InvalidArgumentException('DEC128 is 16 bytes, got ${bytes.length}');
    }
  }
  final Uint8List bytes;
  @override
  int get tag => Tag.dec128;
  @override
  bool operator ==(Object other) =>
      other is CDec128 && _eqBytes(bytes, other.bytes);
  @override
  int get hashCode => Object.hashAll(bytes);
  @override
  String toString() => 'dec128(...)';
}

final class CChar extends CValue {
  CChar(this.scalar) {
    if (scalar < 0 ||
        scalar > 0x10FFFF ||
        (scalar >= 0xD800 && scalar <= 0xDFFF)) {
      throw InvalidArgumentException(
          'not a Unicode scalar value: U+${scalar.toRadixString(16)}');
    }
  }
  final int scalar;
  @override
  int get tag => Tag.char;
  @override
  bool operator ==(Object other) => other is CChar && other.scalar == scalar;
  @override
  int get hashCode => scalar;
  @override
  String toString() => "char(U+${scalar.toRadixString(16).toUpperCase()})";
}

final class CStr extends CValue {
  const CStr(this.value);
  final String value;
  @override
  int get tag => Tag.str;
  @override
  bool operator ==(Object other) => other is CStr && other.value == value;
  @override
  int get hashCode => value.hashCode;
  @override
  String toString() => "'$value'";
}

final class CBytes extends CValue {
  CBytes(List<int> b) : value = Uint8List.fromList(b);
  final Uint8List value;
  @override
  int get tag => Tag.bytes;
  @override
  bool operator ==(Object other) =>
      other is CBytes && _eqBytes(value, other.value);
  @override
  int get hashCode => Object.hashAll(value);
  @override
  String toString() => 'bytes(${value.length})';
}

/// `i64` milliseconds since the Unix epoch, UTC.
final class CTimestamp extends CValue {
  const CTimestamp(this.millis);
  final int millis;
  @override
  int get tag => Tag.timestamp;
  @override
  bool operator ==(Object other) =>
      other is CTimestamp && other.millis == millis;
  @override
  int get hashCode => millis.hashCode;
  @override
  String toString() => 'ts($millis)';
}

/// `i64` seconds plus `u32` nanos, UTC.
final class CTimestampNs extends CValue {
  CTimestampNs(this.secs, this.nanos) {
    if (nanos < 0 || nanos > 999999999) {
      throw InvalidArgumentException('nanos $nanos outside 0..999999999');
    }
  }
  final int secs;
  final int nanos;
  @override
  int get tag => Tag.timestampNs;
  @override
  bool operator ==(Object other) =>
      other is CTimestampNs && other.secs == secs && other.nanos == nanos;
  @override
  int get hashCode => Object.hash(secs, nanos);
  @override
  String toString() => 'tsns($secs.$nanos)';
}

final class CZoned extends CValue {
  const CZoned(this.millis, this.zoneId);
  final int millis;
  final String zoneId;
  @override
  int get tag => Tag.zoned;
  @override
  bool operator ==(Object other) =>
      other is CZoned && other.millis == millis && other.zoneId == zoneId;
  @override
  int get hashCode => Object.hash(millis, zoneId);
  @override
  String toString() => 'zoned($millis @ $zoneId)';
}

/// `i32` days since the Unix epoch; no time, no zone.
final class CDate extends CValue {
  const CDate(this.days);
  final int days;
  @override
  int get tag => Tag.date;
  @override
  bool operator ==(Object other) => other is CDate && other.days == days;
  @override
  int get hashCode => days.hashCode;
  @override
  String toString() => 'date($days)';
}

/// `u64` nanoseconds since midnight.
final class CTime extends CValue {
  CTime(this.nanos) {
    if (nanos < 0) throw InvalidArgumentException('time nanos negative');
  }
  final int nanos;
  @override
  int get tag => Tag.time;
  @override
  bool operator ==(Object other) => other is CTime && other.nanos == nanos;
  @override
  int get hashCode => nanos.hashCode;
  @override
  String toString() => 'time($nanos)';
}

final class CDuration extends CValue {
  CDuration(this.secs, this.nanos) {
    if (nanos < 0 || nanos > 999999999) {
      throw InvalidArgumentException('nanos $nanos outside 0..999999999');
    }
  }
  final int secs;
  final int nanos;
  @override
  int get tag => Tag.duration;
  @override
  bool operator ==(Object other) =>
      other is CDuration && other.secs == secs && other.nanos == nanos;
  @override
  int get hashCode => Object.hash(secs, nanos);
  @override
  String toString() => 'dur($secs.$nanos)';
}

final class CUuid extends CValue {
  CUuid(List<int> b) : bytes = Uint8List.fromList(b) {
    if (b.length != 16) {
      throw InvalidArgumentException('UUID is 16 bytes, got ${b.length}');
    }
  }
  final Uint8List bytes;
  @override
  int get tag => Tag.uuid;
  @override
  bool operator ==(Object other) =>
      other is CUuid && _eqBytes(bytes, other.bytes);
  @override
  int get hashCode => Object.hashAll(bytes);
  @override
  String toString() => 'uuid(...)';
}

/// `spec/00-conventions.md` section 7: signed 64-bit, exchanged as such.
final class CNitriteId extends CValue {
  const CNitriteId(this.id);
  final int id;
  @override
  int get tag => Tag.nitriteId;
  @override
  bool operator ==(Object other) => other is CNitriteId && other.id == id;
  @override
  int get hashCode => id.hashCode;
  @override
  String toString() => 'id($id)';
}

final class CRegex extends CValue {
  const CRegex(this.pattern, this.flags);
  final String pattern;
  final String flags;
  @override
  int get tag => Tag.regex;
  @override
  bool operator ==(Object other) =>
      other is CRegex && other.pattern == pattern && other.flags == flags;
  @override
  int get hashCode => Object.hash(pattern, flags);
  @override
  String toString() => 'regex(/$pattern/$flags)';
}

final class CArray extends CValue {
  CArray(List<CValue> items) : items = List.unmodifiable(items);
  final List<CValue> items;
  @override
  int get tag => Tag.array;
  @override
  bool operator ==(Object other) =>
      other is CArray &&
      other.items.length == items.length &&
      Iterable<int>.generate(items.length)
          .every((i) => other.items[i] == items[i]);
  @override
  int get hashCode => Object.hashAll(items);
  @override
  String toString() => '[${items.join(", ")}]';
}

/// A map with CKE-encodable keys.
///
/// `spec/02-value-encoding.md` section 4 requires entries to be stored in
/// `CKE(key)` byte order and forbids keys that have no CKE encoding. The sort
/// is applied by the **encoder** in `cve.dart` rather than by this constructor,
/// because CKE depends on this file and the dependency cannot run the other
/// way. A [CMap] built out of order therefore encodes correctly and decodes
/// back sorted; equality here is positional, so compare decoded maps, not
/// hand-built ones.
final class CMap extends CValue {
  CMap(this.entries);
  final List<(CValue, CValue)> entries;
  @override
  int get tag => Tag.map;
  @override
  bool operator ==(Object other) =>
      other is CMap &&
      other.entries.length == entries.length &&
      Iterable<int>.generate(entries.length).every((i) =>
          other.entries[i].$1 == entries[i].$1 &&
          other.entries[i].$2 == entries[i].$2);
  @override
  int get hashCode => Object.hashAll(entries.map((e) => Object.hash(e.$1, e.$2)));
  @override
  String toString() =>
      '{${entries.map((e) => "${e.$1}: ${e.$2}").join(", ")}}';
}

/// A document: field name to value.
final class CDoc extends CValue {
  CDoc(Map<String, CValue> fields) : fields = Map.unmodifiable(fields);
  final Map<String, CValue> fields;
  @override
  int get tag => Tag.doc;
  CValue? operator [](String name) => fields[name];
  @override
  bool operator ==(Object other) =>
      other is CDoc &&
      other.fields.length == fields.length &&
      fields.entries.every((e) => other.fields[e.key] == e.value);
  @override
  int get hashCode =>
      Object.hashAllUnordered(fields.entries.map((e) => Object.hash(e.key, e.value)));
  @override
  String toString() =>
      '{${fields.entries.map((e) => "${e.key}: ${e.value}").join(", ")}}';
}

/// `spec/02-value-encoding.md` section 6.
enum VectorDType {
  f32(0),
  f16(1),
  i8(2);

  const VectorDType(this.code);
  final int code;
}

final class CVector extends CValue {
  CVector.f32(List<double> values)
      : dtype = VectorDType.f32,
        f32Values = Float32List.fromList(values),
        i8Values = null,
        scale = 0,
        zeroPoint = 0;

  CVector.i8(List<int> codes, this.scale, this.zeroPoint)
      : dtype = VectorDType.i8,
        f32Values = null,
        i8Values = Int8List.fromList(codes);

  CVector.raw(this.dtype, this.f32Values, this.i8Values, this.scale,
      this.zeroPoint);

  final VectorDType dtype;
  final Float32List? f32Values;
  final Int8List? i8Values;
  final double scale;
  final double zeroPoint;

  int get dim => f32Values?.length ?? i8Values!.length;

  @override
  int get tag => Tag.vector;
  @override
  bool operator ==(Object other) =>
      other is CVector &&
      other.dtype == dtype &&
      other.dim == dim &&
      Iterable<int>.generate(dim).every((i) => f32Values != null
          ? f32Values![i] == other.f32Values![i]
          : i8Values![i] == other.i8Values![i]);
  @override
  int get hashCode => Object.hash(dtype, dim);
  @override
  String toString() => 'vector(${dtype.name}, $dim)';
}

final class CGeometry extends CValue {
  CGeometry(List<int> wkb) : wkb = Uint8List.fromList(wkb);
  final Uint8List wkb;
  @override
  int get tag => Tag.geometry;
  @override
  bool operator ==(Object other) =>
      other is CGeometry && _eqBytes(wkb, other.wkb);
  @override
  int get hashCode => Object.hashAll(wkb);
  @override
  String toString() => 'geometry(${wkb.length}B)';
}

/// `spec/02-value-encoding.md` section 7: the escape hatch that makes real
/// interchange survivable. Round-tripped byte for byte, never comparable,
/// never an index key.
final class COpaque extends CValue {
  COpaque(this.origin, this.typeName, List<int> data)
      : data = Uint8List.fromList(data);
  final String origin;
  final String typeName;
  final Uint8List data;
  @override
  int get tag => Tag.opaque;
  @override
  bool operator ==(Object other) =>
      other is COpaque &&
      other.origin == origin &&
      other.typeName == typeName &&
      _eqBytes(data, other.data);
  @override
  int get hashCode => Object.hash(origin, typeName, Object.hashAll(data));
  @override
  String toString() => 'opaque($origin/$typeName, ${data.length}B)';
}

/// `spec/02-value-encoding.md` section 9: storage, not data. These never
/// appear inside a document; a tree cell holds one in place of a value.
final class CBlobRef extends CValue {
  const CBlobRef(this.startPage, this.byteLen, this.crc32c);
  final int startPage;
  final int byteLen;
  final int crc32c;
  @override
  int get tag => Tag.blobRef;
  @override
  bool operator ==(Object other) =>
      other is CBlobRef &&
      other.startPage == startPage &&
      other.byteLen == byteLen &&
      other.crc32c == crc32c;
  @override
  int get hashCode => Object.hash(startPage, byteLen, crc32c);
  @override
  String toString() => 'blob(page $startPage, $byteLen B)';
}

final class COverflowRef extends CValue {
  COverflowRef(List<int> inline, this.nextPage)
      : inline = Uint8List.fromList(inline);
  final Uint8List inline;
  final int nextPage;
  @override
  int get tag => Tag.overflowRef;
  @override
  bool operator ==(Object other) =>
      other is COverflowRef &&
      other.nextPage == nextPage &&
      _eqBytes(inline, other.inline);
  @override
  int get hashCode => Object.hash(Object.hashAll(inline), nextPage);
  @override
  String toString() => 'overflow(${inline.length}B -> $nextPage)';
}

final class CVlogRef extends CValue {
  const CVlogRef(this.segmentId, this.offset, this.len);
  final int segmentId;
  final int offset;
  final int len;
  @override
  int get tag => Tag.vlogRef;
  @override
  bool operator ==(Object other) =>
      other is CVlogRef &&
      other.segmentId == segmentId &&
      other.offset == offset &&
      other.len == len;
  @override
  int get hashCode => Object.hash(segmentId, offset, len);
  @override
  String toString() => 'vlog($segmentId+$offset, $len B)';
}

/// A value whose tag this implementation does not know.
///
/// `spec/11-conformance.md` section 4 requires these to round-trip byte for
/// byte when a document is rewritten for an unrelated reason. That is only
/// possible because `spec/02-value-encoding.md` section 1.2 requires every
/// reserved and implementation-private tag to be length-prefixed; without that
/// rule a reader could not find where an unknown value ends inside an ARRAY.
final class CUnknown extends CValue {
  CUnknown(this.unknownTag, List<int> payload)
      : payload = Uint8List.fromList(payload);
  final int unknownTag;
  final Uint8List payload;
  @override
  int get tag => unknownTag;
  @override
  bool operator ==(Object other) =>
      other is CUnknown &&
      other.unknownTag == unknownTag &&
      other.payload.length == payload.length &&
      _eqBytes(payload, other.payload);
  @override
  int get hashCode => Object.hash(unknownTag, Object.hashAll(payload));
  @override
  String toString() =>
      'unknown(0x${unknownTag.toRadixString(16)}, ${payload.length}B)';
}

bool _eqBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
