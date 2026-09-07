/// Logical value comparison, `spec/02-value-encoding.md` section 8.
///
/// This is the *definition* of order; CKE (`cke.dart`) is a byte encoding that
/// must agree with it. `test/cke_order_test.dart` asserts
/// `sign(compareValues(a, b)) == sign(memcmp(CKE(a), CKE(b)))` over a torture
/// set, which is the single most important test in this package: a divergence
/// there is a wrong query result in production, not a slow one.
library;

import 'dart:typed_data';

import 'cke.dart';
import 'errors.dart';
import 'u128.dart';
import 'value.dart';

/// Cross-type rank, section 8 rule 10. For CKE-encodable values this is the
/// group tag of `spec/03-key-encoding.md` section 2, so the two orders agree
/// by construction. DOC and MAP are ordered by section 8 rule 8 but have no
/// CKE encoding, so they rank above every key group and are comparable as
/// values only.
int _rank(CValue v) => switch (v) {
      CNull() => Group.nul,
      CBool() => Group.boolean,
      CInt() || CFloat() => Group.number,
      CTimestamp() || CTimestampNs() || CZoned() => Group.temporal,
      CDate() || CTime() || CDuration() => Group.temporal,
      CChar() => Group.char,
      CStr() => Group.string,
      CBytes() => Group.bytes,
      CNitriteId() => Group.nitriteId,
      CUuid() => Group.uuid,
      CArray() => Group.array,
      // `spec/02-value-encoding.md` section 8 rule 10's extension: ordering
      // ranks, never written to a file. ARRAY < MAP < DOC. An earlier version
      // of this file used 0xB0/0xB1 -- which are inside the range section 2
      // *reserves* -- and put DOC below MAP, the opposite of what the Rust
      // implementation chose. Nothing could see it because nothing tested
      // this file.
      CMap() => 0xA1,
      CDoc() => 0xA2,
      _ => -1, // unordered
    };

/// Whether [v] participates in the ordering at all.
///
/// Section 8: "OPAQUE, GEOMETRY, VECTOR and REGEX are not ordered. Using them
/// as index keys is an error." DEC128 is storable and comparable *as a value*
/// but has no key encoding (section 4.4 of `spec/03-key-encoding.md`).
bool isOrdered(CValue v) => _rank(v) >= 0 || v is CDec128;

/// Compares [a] and [b] per section 8. Throws for unordered types.
int compareValues(CValue a, CValue b) {
  if (a is CDec128 || b is CDec128) {
    throw const InvalidArgumentException(
        'DEC128 comparison needs exact decimal arithmetic, which this '
        'reference implementation does not provide; it is never a key');
  }
  final ra = _rank(a), rb = _rank(b);
  if (ra < 0 || rb < 0) {
    throw InvalidArgumentException(
        '${ra < 0 ? a.runtimeType : b.runtimeType} is not ordered '
        '(spec/02-value-encoding.md section 8)');
  }
  if (ra != rb) return ra < rb ? -1 : 1;

  switch (a) {
    case CNull():
      return 0;
    case CBool():
      // Rule 9: FALSE < TRUE.
      final x = a.value ? 1 : 0, y = (b as CBool).value ? 1 : 0;
      return x.compareTo(y);
    case CInt():
    case CFloat():
      return compareNumeric(a, b);
    case CChar():
      // Rule 6: CHAR is not equal to a one-character STR; separate groups
      // already guarantee that, so within the group it is just the scalar.
      return a.scalar.compareTo((b as CChar).scalar);
    case CStr():
      // Rule 4: UTF-8 byte order, i.e. Unicode code-point order. No locale,
      // no case folding, no normalization.
      return compareKeys(
          Uint8List.fromList(a.value.codeUnits.isEmpty ? const [] : _utf8(a.value)),
          Uint8List.fromList(_utf8((b as CStr).value)));
    case CBytes():
      // Rule 5: lexicographic, shorter-is-smaller on a prefix.
      return compareKeys(a.value, (b as CBytes).value);
    case CNitriteId():
      return a.id.compareTo((b as CNitriteId).id);
    case CUuid():
      return compareKeys(a.bytes, (b as CUuid).bytes);
    case CTimestamp():
    case CTimestampNs():
    case CZoned():
    case CDate():
    case CTime():
    case CDuration():
      return _compareTemporal(a, b);
    case CArray():
      // Rule 8: element-wise, then by length.
      final other = b as CArray;
      final n = a.items.length < other.items.length
          ? a.items.length
          : other.items.length;
      for (var i = 0; i < n; i++) {
        final c = compareValues(a.items[i], other.items[i]);
        if (c != 0) return c;
      }
      return a.items.length.compareTo(other.items.length);
    case CDoc():
      return _compareEntries(_docEntries(a), _docEntries(b as CDoc));
    case CMap():
      return _compareEntries(_mapEntries(a), _mapEntries(b as CMap));
    default:
      throw InvalidArgumentException('unordered ${a.runtimeType}');
  }
}

List<int> _utf8(String s) {
  final out = <int>[];
  for (final rune in s.runes) {
    if (rune < 0x80) {
      out.add(rune);
    } else if (rune < 0x800) {
      out..add(0xC0 | (rune >> 6))..add(0x80 | (rune & 0x3F));
    } else if (rune < 0x10000) {
      out
        ..add(0xE0 | (rune >> 12))
        ..add(0x80 | ((rune >> 6) & 0x3F))
        ..add(0x80 | (rune & 0x3F));
    } else {
      out
        ..add(0xF0 | (rune >> 18))
        ..add(0x80 | ((rune >> 12) & 0x3F))
        ..add(0x80 | ((rune >> 6) & 0x3F))
        ..add(0x80 | (rune & 0x3F));
    }
  }
  return out;
}

/// Section 8 rule 8: "MAP and DOC compare as their **sorted** (key, value)
/// sequences." [_docEntries] has always sorted; the MAP arm compared in
/// *stored* order, so two maps holding the same entries written in a different
/// order compared unequal. All three implementations had it, identically —
/// which is why no cross-language check could see it: the order is consumed in
/// memory and the bytes never differ.
///
/// A MAP may hold a duplicate key where a DOC cannot, so the sort is by (key,
/// then value): sorting on the key alone leaves the sequence undetermined
/// exactly where the duplicates are.
List<(CValue, CValue)> _mapEntries(CMap m) {
  final e = [...m.entries]..sort((p, q) {
      final c = compareValues(p.$1, q.$1);
      return c != 0 ? c : compareValues(p.$2, q.$2);
    });
  return e;
}

List<(CValue, CValue)> _docEntries(CDoc d) {
  final e = d.fields.entries.map((x) => (CStr(x.key) as CValue, x.value)).toList()
    ..sort((p, q) => compareValues(p.$1, q.$1));
  return e;
}

int _compareEntries(List<(CValue, CValue)> a, List<(CValue, CValue)> b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    var c = compareValues(a[i].$1, b[i].$1);
    if (c != 0) return c;
    c = compareValues(a[i].$2, b[i].$2);
    if (c != 0) return c;
  }
  return a.length.compareTo(b.length);
}

/// Temporal subclass ranks, matching `spec/03-key-encoding.md` section 5.
/// TIMESTAMP, TIMESTAMP_NS and ZONED share subclass 0x01 so they compare by
/// instant across the three tags — section 8 rule 7.
int _temporalSub(CValue v) => switch (v) {
      CTimestamp() || CTimestampNs() || CZoned() => TemporalClass.instant,
      CDate() => TemporalClass.date,
      CTime() => TemporalClass.time,
      CDuration() => TemporalClass.duration,
      _ => throw InvalidArgumentException('not temporal: ${v.runtimeType}'),
    };

int _compareTemporal(CValue a, CValue b) {
  final sa = _temporalSub(a), sb = _temporalSub(b);
  if (sa != sb) return sa.compareTo(sb);
  switch (sa) {
    case TemporalClass.instant:
      final ia = instantOf(a), ib = instantOf(b);
      final c = ia.secs.compareTo(ib.secs);
      return c != 0 ? c : ia.nanos.compareTo(ib.nanos);
    case TemporalClass.date:
      return (a as CDate).days.compareTo((b as CDate).days);
    case TemporalClass.time:
      return (a as CTime).nanos.compareTo((b as CTime).nanos);
    default:
      final da = a as CDuration, db = b as CDuration;
      final c = da.secs.compareTo(db.secs);
      return c != 0 ? c : da.nanos.compareTo(db.nanos);
  }
}

/// Canonical `(secs, nanos)` for any instant-valued tag, using **floor**
/// division so pre-epoch milliseconds normalize correctly.
Instant instantOf(CValue v) {
  final int millis;
  switch (v) {
    case CTimestampNs():
      return (secs: v.secs, nanos: v.nanos);
    case CTimestamp():
      millis = v.millis;
    case CZoned():
      millis = v.millis;
    default:
      throw InvalidArgumentException('not an instant: ${v.runtimeType}');
  }
  var secs = millis ~/ 1000;
  var rem = millis - secs * 1000;
  if (rem < 0) {
    secs -= 1;
    rem += 1000;
  }
  return (secs: secs, nanos: rem * 1000000);
}

// ---------------------------------------------------------------------------
// Numeric comparison, section 8 rule 2 and rule 3
// ---------------------------------------------------------------------------

/// The `(sign_class, e, m)` triple of `spec/03-key-encoding.md` section 4,
/// which is a *total, exact* ordering key for the whole numeric domain.
typedef _Tri = ({int sign, int e, U128 m});

_Tri _triple(CValue v) {
  if (v is CInt) {
    if (v.isZero) return (sign: SignClass.zero, e: 0, m: U128.zero);
    final n = normalizeMagnitude(v.magnitude);
    return (
      sign: v.negative ? SignClass.negFinite : SignClass.posFinite,
      e: n.e,
      m: n.m
    );
  }
  final f = v as CFloat;
  final d = f.value;
  if (d.isNaN) return (sign: SignClass.nan, e: 0, m: U128.zero);
  if (d.isInfinite) {
    return (
      sign: d.isNegative ? SignClass.negInfinity : SignClass.posInfinity,
      e: 0,
      m: U128.zero
    );
  }
  // Rule 3: -0.0 equals +0.0 and they sort equal.
  if (d == 0.0) return (sign: SignClass.zero, e: 0, m: U128.zero);
  final Normalized n;
  if (f.type == NumType.f32) {
    final bd = ByteData(4)..setFloat32(0, d.abs());
    n = normalizeF32(bd.getUint32(0));
  } else {
    final bd = ByteData(8)..setFloat64(0, d.abs());
    n = normalizeF64(bd.getUint64(0));
  }
  return (
    sign: d.isNegative ? SignClass.negFinite : SignClass.posFinite,
    e: n.e,
    m: n.m
  );
}

/// Exact comparison across every numeric tag, section 8 rule 2.
///
/// Integers above 2^53 compare exactly against floats — there is no fold to
/// `double` anywhere. That fold is what
/// `research/nitrite-survey.md` section 6.3 records as having collided
/// snowflake ids onto one key and made a unique index reject ids it had never
/// seen.
int compareNumeric(CValue a, CValue b) {
  final x = _triple(a), y = _triple(b);
  if (x.sign != y.sign) return x.sign < y.sign ? -1 : 1;
  // Empty ordering region: -inf, zero, +inf and NaN each compare equal within
  // their class. Rule 3: NaN equals NaN, so a NaN key is findable.
  if (x.sign != SignClass.negFinite && x.sign != SignClass.posFinite) return 0;
  var c = x.e.compareTo(y.e);
  if (c == 0) c = x.m.compareTo(y.m);
  // Larger magnitude sorts lower among negatives.
  return x.sign == SignClass.negFinite ? -c : c;
}
