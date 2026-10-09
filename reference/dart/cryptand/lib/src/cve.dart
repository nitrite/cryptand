/// CVE, the Cryptand Value Encoding. `spec/02-value-encoding.md`.
///
/// Little-endian, self-describing, forward compatible, and designed so that
/// reading one field of a document costs a binary search and a slice rather
/// than a deserialization. [DocView] is where that last property lives, and
/// `bench/decode_bench.dart` measures it.
library;

import 'dart:typed_data';


import 'bytes.dart';
import 'cke.dart';
import 'errors.dart';
import 'limits.dart';
import 'u128.dart';
import 'value.dart';

/// A per-tree, append-only field-name dictionary, `spec/02-value-encoding.md`
/// section 5.3.
///
/// Ids are never reused, so a stale cached dictionary is never *wrong*, only
/// incomplete — which is what lets a reader cache the whole thing and re-read
/// only on an unknown id.
final class NameDict {
  NameDict();

  final List<String> _byId = [''];
  final List<Uint8List> _bytesById = [Uint8List(0)];
  final Map<String, int> _byName = {};

  /// Section 5.4: the reserved fields SHOULD occupy ids 1..5 in every data
  /// tree so they encode in one byte.
  factory NameDict.withReservedFields() {
    final d = NameDict();
    for (final n in ['_id', '_revision', '_modified', '_source', '_type']) {
      d.intern(n);
    }
    return d;
  }

  int get length => _byId.length - 1;

  /// Allocates an id for [name], or returns the existing one.
  int intern(String name) {
    final existing = _byName[name];
    if (existing != null) return existing;
    final id = _byId.length;
    _byId.add(name);
    // The lookup path compares name *bytes*, so encode once here rather than
    // on every binary-search probe. A Java or Rust implementation stores the
    // same byte array for the same reason; this is not a Dart workaround.
    _bytesById.add(encodeUtf8Strict(name));
    _byName[name] = id;
    return id;
  }

  int? idOf(String name) => _byName[name];

  String nameOf(int id) {
    if (id <= 0 || id >= _byId.length) {
      // Section 5.3: "on encountering an unknown name_id it MUST re-read the
      // dictionary tree before failing". A caller that has done so and still
      // cannot resolve it is looking at corruption.
      throw CorruptionException('unknown name_id $id');
    }
    return _byId[id];
  }

  /// UTF-8 bytes of [id], without building a Dart [String].
  Uint8List bytesOf(int id) {
    if (id <= 0 || id >= _bytesById.length) {
      throw CorruptionException('unknown name_id $id');
    }
    return _bytesById[id];
  }

  bool has(int id) => id > 0 && id < _byId.length;

  Iterable<(int, String)> get entries sync* {
    for (var i = 1; i < _byId.length; i++) {
      yield (i, _byId[i]);
    }
  }
}

/// Encodes a single value.
Uint8List encodeValue(CValue v, {NameDict? dict}) {
  final w = ByteWriter(64);
  writeValue(w, v, dict: dict);
  return w.takeBytes();
}

void writeValue(ByteWriter w, CValue v, {NameDict? dict, int depth = 0}) {
  if (depth > kMaxDepth) {
    throw const LimitException('CVE nesting deeper than 100');
  }
  switch (v) {
    case CNull():
      w.u8(Tag.nul);
    case CBool():
      w.u8(v.value ? Tag.tru : Tag.fals);
    case CInt():
      _writeInt(w, v);
    case CFloat():
      if (v.type == NumType.f32) {
        // spec/00-conventions.md section 3: NaN is written as the quiet NaN's
        // bits. `double.nan` is not that on x64, where it has the sign set
        // (F-061).
        w.u8(Tag.f32);
        v.value.isNaN ? w.u32(0x7FC00000) : w.f32(v.value);
      } else {
        w.u8(Tag.f64);
        v.value.isNaN ? w.u64(0x7FF8000000000000) : w.f64(v.value);
      }
    case CDec128():
      w
        ..u8(Tag.dec128)
        ..bytes(v.bytes);
    case CChar():
      w
        ..u8(Tag.char)
        ..u32(v.scalar);
    case CStr():
      w
        ..u8(Tag.str)
        ..str(v.value);
    case CBytes():
      w..u8(Tag.bytes)..uvar(v.value.length)..bytes(v.value);
    case CTimestamp():
      w
        ..u8(Tag.timestamp)
        ..i64(v.millis);
    case CTimestampNs():
      w
        ..u8(Tag.timestampNs)
        ..i64(v.secs)
        ..u32(v.nanos);
    case CZoned():
      w
        ..u8(Tag.zoned)
        ..i64(v.millis)
        ..str(v.zoneId);
    case CDate():
      w
        ..u8(Tag.date)
        ..i32(v.days);
    case CTime():
      w
        ..u8(Tag.time)
        ..u64(v.nanos);
    case CDuration():
      w
        ..u8(Tag.duration)
        ..i64(v.secs)
        ..u32(v.nanos);
    case CUuid():
      w
        ..u8(Tag.uuid)
        ..bytes(v.bytes);
    case CNitriteId():
      w
        ..u8(Tag.nitriteId)
        ..i64(v.id);
    case CRegex():
      w
        ..u8(Tag.regex)
        ..str(v.pattern)
        ..str(v.flags);
    case CArray():
      _writeLengthPrefixed(w, Tag.array, (b) {
        b.uvar(v.items.length);
        for (final e in v.items) {
          writeValue(b, e, dict: dict, depth: depth + 1);
        }
      });
    case CMap():
      _writeMap(w, v, dict, depth);
    case CDoc():
      writeDoc(w, v, dict: dict, depth: depth);
    case CVector():
      _writeVector(w, v);
    case CGeometry():
      w..u8(Tag.geometry)..uvar(v.wkb.length)..bytes(v.wkb);
    case CBlobRef():
      w..u8(Tag.blobRef)..u64(v.startPage)..u32(v.byteLen)..u32(v.crc32c);
    case COverflowRef():
      w
        ..u8(Tag.overflowRef)
        ..uvar(v.inline.length)
        ..bytes(v.inline)
        ..u64(v.nextPage);
    case CVlogRef():
      w..u8(Tag.vlogRef)..u64(v.segmentId)..u32(v.offset)..u32(v.len);
    case COpaque():
      _writeLengthPrefixed(w, Tag.opaque, (b) {
        b
          ..str(v.origin)
          ..str(v.typeName)
          ..uvar(v.data.length)
          ..bytes(v.data);
      });
    case CUnknown():
      // Section 1.2: reserved and implementation-private tags are
      // length-prefixed, so preserving one is writing back what we read.
      w..u8(v.unknownTag)..uvar(v.payload.length)..bytes(v.payload);
  }
}

void _writeLengthPrefixed(ByteWriter w, int tag, void Function(ByteWriter) body) {
  final inner = ByteWriter(64);
  body(inner);
  final b = inner.view;
  w
    ..u8(tag)
    ..uvar(b.length)
    ..bytes(b);
}

void _writeInt(ByteWriter w, CInt v) {
  final t = v.type;
  if (t == NumType.intVar) {
    final asInt = v.asInt;
    if (asInt == null) {
      throw InvalidArgumentException('INT_VAR value $v does not fit i64');
    }
    w
      ..u8(Tag.intVar)
      ..ivar(asInt);
    return;
  }
  w.u8(t.cve);
  final mag = v.magnitude;
  switch (t.bits) {
    case 8:
      w.u8(v.negative ? (-mag.lo) & 0xFF : mag.lo & 0xFF);
    case 16:
      w.u16(v.negative ? (-mag.lo) & 0xFFFF : mag.lo & 0xFFFF);
    case 32:
      w.u32(v.negative ? (-mag.lo) & 0xFFFFFFFF : mag.lo & 0xFFFFFFFF);
    case 64:
      w.u64(v.negative ? -mag.lo : mag.lo);
    default: // 128
      final bits = v.negative ? mag.negate() : mag;
      // Two's complement, 16 bytes little-endian.
      final be = bits.toBytesBE();
      for (var i = 15; i >= 0; i--) {
        w.u8(be[i]);
      }
  }
}

void _writeVector(ByteWriter w, CVector v) {
  w
    ..u8(Tag.vector)
    ..u8(v.dtype.code)
    ..uvar(v.dim);
  switch (v.dtype) {
    case VectorDType.f32:
      for (final x in v.f32Values!) {
        w.f32(x);
      }
    case VectorDType.f16:
      throw const UnsupportedFeatureException(
          'f16 vectors are not implemented by this reference (phase 1)');
    case VectorDType.i8:
      for (final x in v.i8Values!) {
        w.i8(x);
      }
      w
        ..f32(v.scale)
        ..f32(v.zeroPoint);
  }
}

void _writeMap(ByteWriter w, CMap v, NameDict? dict, int depth) {
  // Section 4: "Entries MUST be sorted by CKE(key) byte order" and "A map key
  // MUST be CKE-encodable."
  final keyed = <(Uint8List, CValue, CValue)>[];
  for (final e in v.entries) {
    if (!isKeyEncodable(e.$1)) {
      throw InvalidArgumentException(
          '${e.$1.runtimeType} has no CKE encoding and cannot be a map key '
          '(spec/02-value-encoding.md section 4)');
    }
    keyed.add((encodeKey(e.$1), e.$1, e.$2));
  }
  keyed.sort((a, b) => compareKeys(a.$1, b.$1));
  for (var i = 1; i < keyed.length; i++) {
    if (compareKeys(keyed[i - 1].$1, keyed[i].$1) == 0) {
      throw const InvalidArgumentException('duplicate map key');
    }
  }
  _writeLengthPrefixed(w, Tag.map, (b) {
    b.uvar(keyed.length);
    for (final e in keyed) {
      writeValue(b, e.$2, dict: dict, depth: depth + 1);
      writeValue(b, e.$3, dict: dict, depth: depth + 1);
    }
  });
}

// ---------------------------------------------------------------------------
// DOC, section 5
// ---------------------------------------------------------------------------

/// Document flags, section 5.
class DocFlags {
  /// bit0. MUST be 1 in v1: the field table is sorted by resolved name bytes.
  static const int sortedByName = 0x01;
}

void writeDoc(ByteWriter w, CDoc doc, {NameDict? dict, int depth = 0}) {
  if (depth > kMaxDepth) {
    throw const LimitException('CVE nesting deeper than 100');
  }
  if (doc.fields.length > kMaxFieldCount) {
    throw LimitException(
        'document has ${doc.fields.length} fields, limit is $kMaxFieldCount');
  }

  // Section 5.1: "The field table is sorted by name_ref's resolved name bytes,
  // not by the numeric name_ref -- otherwise dictionary and inline names would
  // interleave arbitrarily."
  final names = doc.fields.keys.toList()
    ..sort((a, b) => compareKeys(encodeUtf8Strict(a), encodeUtf8Strict(b)));

  final nameRefs = <int>[];
  final inlineNames = <String>[];
  for (final n in names) {
    final id = dict?.idOf(n);
    if (id != null) {
      nameRefs.add(id << 1);
    } else {
      nameRefs.add((inlineNames.length << 1) | 1);
      inlineNames.add(n);
    }
  }

  // Values first, so the table can carry real offsets. The offsets do not
  // depend on the table's own encoded size, so one pass is enough.
  final values = ByteWriter(64);
  final offsets = <int>[];
  for (final n in names) {
    offsets.add(values.length);
    writeValue(values, doc.fields[n]!, dict: dict, depth: depth + 1);
  }

  final nameArea = ByteWriter(32);
  for (final n in inlineNames) {
    nameArea.str(n);
  }

  _writeLengthPrefixed(w, Tag.doc, (b) {
    b
      ..uvar(names.length)
      ..u8(DocFlags.sortedByName);
    for (var i = 0; i < names.length; i++) {
      b
        ..uvar(nameRefs[i])
        ..uvar(offsets[i]);
    }
    b
      ..bytes(nameArea.view)
      ..bytes(values.view);
  });
}

/// A lazy view over an encoded document.
///
/// This is the property `spec/02-value-encoding.md` section 5.2 is built
/// around: "No allocation for unread fields." Resolving one field is a binary
/// search over the field table and one value decode; the other fields are
/// never touched.
final class DocView {
  DocView._(this._data, this._tableStart, this.fieldCount, this._nameArea,
      this._valueArea, this._end, this._dict);

  final Uint8List _data;
  final int _tableStart;
  final int fieldCount;
  final int _nameArea;
  final int _valueArea;
  final int _end;
  final NameDict? _dict;

  /// Offsets of the field table entries, filled lazily on first use.
  List<int>? _entryOffsets;

  /// Offsets of the inline names inside the name area, filled lazily and only
  /// if the document actually has inline names.
  List<int>? _inlineOffsets;

  /// Parses the header of an encoded DOC. Does not decode any value.
  factory DocView.parse(Uint8List data, {NameDict? dict, int offset = 0}) {
    final r = ByteReader(data, offset);
    final tag = r.u8();
    if (tag != Tag.doc) {
      throw CorruptionException(
          'expected DOC tag 0x22, found 0x${tag.toRadixString(16)}');
    }
    final byteLen = r.uvar();
    if (byteLen > r.remaining) {
      throw CorruptionException(
          'DOC byte_len $byteLen exceeds ${r.remaining} available');
    }
    final end = r.position + byteLen;
    final count = r.uvar();
    if (count > kMaxFieldCount) {
      throw LimitException('document field count $count exceeds $kMaxFieldCount');
    }
    final flags = r.u8();
    if (flags & DocFlags.sortedByName == 0) {
      throw const CorruptionException(
          'DOC flags bit0 SORTED_BY_NAME_ID MUST be 1 in v1');
    }
    final tableStart = r.position;

    // Walk the table once to find where it ends, without decoding names.
    //
    // Direct byte access rather than ByteReader.uvar(): this loop runs once
    // per document on every projection, and the canonical-encoding checks
    // ByteReader performs are redundant here because the loop only needs each
    // entry's *length* and its low bit. Correctness of the values themselves
    // is checked where they are used. Bounds are still enforced against `end`.
    var inlineCount = 0;
    var p = tableStart;
    for (var i = 0; i < count; i++) {
      if (p >= end) {
        throw const CorruptionException('DOC field table overruns byte_len');
      }
      final ref0 = data[p];
      var q = p;
      while (data[q] & 0x80 != 0) {
        q++;
        if (q >= end) {
          throw const CorruptionException('DOC name_ref overruns byte_len');
        }
      }
      q++;
      while (q < end && data[q] & 0x80 != 0) {
        q++;
      }
      q++;
      if (q > end) {
        throw const CorruptionException('DOC value_offset overruns byte_len');
      }
      if (ref0 & 1 == 1) inlineCount++;
      p = q;
    }
    r.position = p;
    final nameArea = r.position;
    for (var i = 0; i < inlineCount; i++) {
      final n = r.uvar();
      if (n > r.remaining) {
        throw CorruptionException('inline name length $n past end of document');
      }
      r.position = r.position + n;
    }
    final valueArea = r.position;
    if (valueArea > end) {
      throw const CorruptionException('DOC name area overruns byte_len');
    }
    return DocView._(data, tableStart, count, nameArea, valueArea, end, dict);
  }

  List<int> get _table {
    var t = _entryOffsets;
    if (t != null) return t;
    t = List<int>.filled(fieldCount, 0);
    final r = ByteReader(_data, _tableStart, _nameArea);
    for (var i = 0; i < fieldCount; i++) {
      t[i] = r.position;
      r
        ..uvar()
        ..uvar();
    }
    return _entryOffsets = t;
  }

  (int nameRef, int valueOffset) entryAt(int i) {
    var p = _table[i];
    var ref = 0, shift = 0;
    while (true) {
      final b = _data[p++];
      ref |= (b & 0x7F) << shift;
      if (b & 0x80 == 0) break;
      shift += 7;
      if (shift > 63) throw const CorruptionException('name_ref uvar overflow');
    }
    var off = 0;
    shift = 0;
    while (true) {
      final b = _data[p++];
      off |= (b & 0x7F) << shift;
      if (b & 0x80 == 0) break;
      shift += 7;
      if (shift > 63) {
        throw const CorruptionException('value_offset uvar overflow');
      }
    }
    return (ref, off);
  }

  List<int> get _inlineIndex {
    var idx = _inlineOffsets;
    if (idx != null) return idx;
    idx = <int>[];
    final r = ByteReader(_data, _nameArea, _valueArea);
    while (!r.isAtEnd) {
      idx.add(r.position);
      final n = r.uvar();
      r.position = r.position + n;
    }
    return _inlineOffsets = idx;
  }

  /// The resolved field name at table index [i].
  String nameAt(int i) {
    final (ref, _) = entryAt(i);
    if (ref & 1 == 0) {
      final d = _dict;
      if (d == null) {
        throw const CorruptionException(
            'document uses a name dictionary but none was supplied');
      }
      return d.nameOf(ref >>> 1);
    }
    final idx = _inlineIndex;
    final slot = ref >>> 1;
    if (slot >= idx.length) {
      throw CorruptionException('inline name index $slot out of range');
    }
    return ByteReader(_data, idx[slot], _valueArea).str();
  }

  /// Name bytes at table index [i], without building a Dart [String].
  ///
  /// The search path uses this so a lookup never allocates a string for a
  /// field it is not going to return.
  Uint8List _nameBytesAt(int i) {
    final (ref, _) = entryAt(i);
    if (ref & 1 == 0) {
      final d = _dict;
      if (d == null) {
        throw const CorruptionException(
            'document uses a name dictionary but none was supplied');
      }
      return d.bytesOf(ref >>> 1);
    }
    final idx = _inlineIndex;
    final slot = ref >>> 1;
    if (slot >= idx.length) {
      throw CorruptionException('inline name index $slot out of range');
    }
    final r = ByteReader(_data, idx[slot], _valueArea);
    return r.bytesView(r.uvar());
  }

  /// The value at table index [i].
  CValue valueAt(int i) {
    final (_, off) = entryAt(i);
    final start = _valueArea + off;
    if (start > _end) {
      throw CorruptionException('field value offset $off past end of document');
    }
    return readValue(ByteReader(_data, start, _end), dict: _dict);
  }

  /// Field count at or above which a binary search beats a linear pass.
  ///
  /// `spec/02-value-encoding.md` section 5.2 describes the lookup as "a binary
  /// search and a slice", and for a large document it is. For a *typical*
  /// document it is not the cheaper algorithm, and the reason is the format:
  /// the field table holds two varints per entry, so it cannot be indexed
  /// without first walking it. A binary search therefore pays an O(n) index
  /// build before its O(log n) probes, while a single forward pass over the
  /// same table costs one walk and stops early because the table is sorted.
  ///
  /// Measured on the 20-field document of `design/performance-model.md`
  /// section 1, the linear pass is the faster of the two by a wide margin, so
  /// it is the default and the binary search is kept for wide documents.
  static const int binarySearchThreshold = 64;

  /// Locates [name], returning its table index or -1.
  int indexOf(String name) {
    final target = encodeUtf8Strict(name);
    if (fieldCount >= binarySearchThreshold) return _binarySearch(target);
    // One forward pass. The table is sorted by resolved name bytes, so a name
    // above the target means the target is absent.
    var p = _tableStart;
    for (var i = 0; i < fieldCount; i++) {
      final start = p;
      p = _skipEntry(p);
      final c = compareKeys(_nameBytesAtEntry(start), target);
      if (c == 0) return i;
      if (c > 0) return -1;
    }
    return -1;
  }

  int _binarySearch(Uint8List target) {
    var lo = 0, hi = fieldCount - 1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      final c = compareKeys(_nameBytesAt(mid), target);
      if (c == 0) return mid;
      if (c < 0) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return -1;
  }

  /// Advances past one table entry (two varints) and returns the new offset.
  int _skipEntry(int p) {
    while (_data[p] & 0x80 != 0) {
      p++;
    }
    p++;
    while (_data[p] & 0x80 != 0) {
      p++;
    }
    return p + 1;
  }

  /// Name bytes of the entry starting at byte offset [p].
  Uint8List _nameBytesAtEntry(int p) {
    var ref = 0, shift = 0;
    while (true) {
      final b = _data[p++];
      ref |= (b & 0x7F) << shift;
      if (b & 0x80 == 0) break;
      shift += 7;
    }
    if (ref & 1 == 0) {
      final d = _dict;
      if (d == null) {
        throw const CorruptionException(
            'document uses a name dictionary but none was supplied');
      }
      return d.bytesOf(ref >>> 1);
    }
    final idx = _inlineIndex;
    final slot = ref >>> 1;
    if (slot >= idx.length) {
      throw CorruptionException('inline name index $slot out of range');
    }
    final r = ByteReader(_data, idx[slot], _valueArea);
    return r.bytesView(r.uvar());
  }

  /// One field, decoded. Null if absent. Nothing else in the document is
  /// touched.
  CValue? operator [](String name) {
    final i = indexOf(name);
    return i < 0 ? null : valueAt(i);
  }

  /// Locates [name] and decodes its value in a single forward pass, without
  /// building the table offset index at all. This is the projection path.
  CValue? get(String name) {
    if (fieldCount >= binarySearchThreshold) return this[name];
    final target = encodeUtf8Strict(name);
    var p = _tableStart;
    for (var i = 0; i < fieldCount; i++) {
      final start = p;
      p = _skipEntry(p);
      final c = compareKeys(_nameBytesAtEntry(start), target);
      if (c > 0) return null;
      if (c == 0) {
        final off = _valueOffsetAtEntry(start);
        final vs = _valueArea + off;
        if (vs > _end) {
          throw CorruptionException('field value offset $off past end');
        }
        return readValue(ByteReader(_data, vs, _end), dict: _dict);
      }
    }
    return null;
  }

  int _valueOffsetAtEntry(int p) {
    while (_data[p] & 0x80 != 0) {
      p++;
    }
    p++;
    var off = 0, shift = 0;
    while (true) {
      final b = _data[p++];
      off |= (b & 0x7F) << shift;
      if (b & 0x80 == 0) break;
      shift += 7;
    }
    return off;
  }

  /// The whole document, materialized.
  CDoc toDoc() {
    final m = <String, CValue>{};
    for (var i = 0; i < fieldCount; i++) {
      m[nameAt(i)] = valueAt(i);
    }
    return CDoc(m);
  }

  /// Offset of the first byte past this document.
  int get endOffset => _end;
}


// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decodes one value from [r].
///
/// Every length is bounds-checked before it is used, and every recursion is
/// depth-limited: `spec/00-conventions.md` section 8 and
/// `spec/14-security.md` section 9.1.
CValue readValue(ByteReader r, {NameDict? dict, int depth = 0}) {
  if (depth > kMaxDepth) {
    throw const LimitException('CVE nesting deeper than 100');
  }
  final tag = r.u8();
  switch (tag) {
    case Tag.nul:
      return const CNull();
    case Tag.fals:
      return const CBool(false);
    case Tag.tru:
      return const CBool(true);
    case Tag.i8:
      return CInt.of(NumType.i8, r.i8());
    case Tag.i16:
      return CInt.of(NumType.i16, r.i16());
    case Tag.i32:
      return CInt.of(NumType.i32, r.i32());
    case Tag.i64:
      return CInt.of(NumType.i64, r.i64());
    case Tag.i128:
      return _readI128(r, NumType.i128);
    case Tag.u8:
      return CInt(NumType.u8, false, U128(0, r.u8()));
    case Tag.u16:
      return CInt(NumType.u16, false, U128(0, r.u16()));
    case Tag.u32:
      return CInt(NumType.u32, false, U128(0, r.u32()));
    case Tag.u64:
      return CInt(NumType.u64, false, U128(0, r.u64()));
    case Tag.u128:
      return _readI128(r, NumType.u128);
    case Tag.intVar:
      return CInt.varInt(r.ivar());
    case Tag.f32:
      return CFloat(NumType.f32, r.f32());
    case Tag.f64:
      return CFloat(NumType.f64, r.f64());
    case Tag.dec128:
      return CDec128(r.bytesCopy(16));
    case Tag.char:
      final scalar = r.u32();
      if (scalar > 0x10FFFF || (scalar >= 0xD800 && scalar <= 0xDFFF)) {
        throw CorruptionException(
            'CHAR U+${scalar.toRadixString(16)} is not a Unicode scalar value');
      }
      return CChar(scalar);
    case Tag.str:
      return CStr(r.str());
    case Tag.bytes:
      return CBytes(r.bytesCopy(r.uvar()));
    case Tag.timestamp:
      return CTimestamp(r.i64());
    case Tag.timestampNs:
      final secs = r.i64();
      final nanos = r.u32();
      if (nanos > 999999999) {
        throw CorruptionException('TIMESTAMP_NS nanos $nanos out of range');
      }
      return CTimestampNs(secs, nanos);
    case Tag.zoned:
      return CZoned(r.i64(), r.str());
    case Tag.date:
      return CDate(r.i32());
    case Tag.time:
      final n = r.u64();
      if (n < 0) throw const CorruptionException('TIME nanos overflow i64');
      return CTime(n);
    case Tag.duration:
      final secs = r.i64();
      final nanos = r.u32();
      if (nanos > 999999999) {
        throw CorruptionException('DURATION nanos $nanos out of range');
      }
      return CDuration(secs, nanos);
    case Tag.uuid:
      return CUuid(r.bytesCopy(16));
    case Tag.nitriteId:
      return CNitriteId(r.i64());
    case Tag.regex:
      return CRegex(r.str(), r.str());
    case Tag.array:
      final len = _boundedLen(r);
      final end = r.position + len;
      final inner = ByteReader(r.data, r.position, end);
      final count = inner.uvar();
      if (count < 0 || count > len) {
        throw CorruptionException('ARRAY count $count exceeds its $len bytes');
      }
      final items = <CValue>[];
      for (var i = 0; i < count; i++) {
        items.add(readValue(inner, dict: dict, depth: depth + 1));
      }
      r.position = end;
      return CArray(items);
    case Tag.map:
      final len = _boundedLen(r);
      final end = r.position + len;
      final inner = ByteReader(r.data, r.position, end);
      final count = inner.uvar();
      if (count < 0 || count > len) {
        throw CorruptionException('MAP count $count exceeds its $len bytes');
      }
      final entries = <(CValue, CValue)>[];
      Uint8List? prevKey;
      for (var i = 0; i < count; i++) {
        final k = readValue(inner, dict: dict, depth: depth + 1);
        final v = readValue(inner, dict: dict, depth: depth + 1);
        if (!isKeyEncodable(k)) {
          throw CorruptionException(
              'MAP key ${k.runtimeType} has no CKE encoding');
        }
        final kb = encodeKey(k);
        if (prevKey != null) {
          final c = compareKeys(prevKey, kb);
          if (c > 0) {
            throw const CorruptionException('MAP entries are not sorted by CKE(key)');
          }
          if (c == 0) throw const CorruptionException('duplicate MAP key');
        }
        prevKey = kb;
        entries.add((k, v));
      }
      r.position = end;
      return CMap(entries);
    case Tag.doc:
      final view = DocView.parse(r.data, dict: dict, offset: r.position - 1);
      r.position = view._end;
      return view.toDoc();
    case Tag.vector:
      return _readVector(r);
    case Tag.geometry:
      return CGeometry(r.bytesCopy(r.uvar()));
    case Tag.blobRef:
      return CBlobRef(r.u64(), r.u32(), r.u32());
    case Tag.overflowRef:
      final inline = r.bytesCopy(r.uvar());
      return COverflowRef(inline, r.u64());
    case Tag.vlogRef:
      return CVlogRef(r.u64(), r.u32(), r.u32());
    case Tag.opaque:
      final len = _boundedLen(r);
      final end = r.position + len;
      final inner = ByteReader(r.data, r.position, end);
      final origin = inner.str();
      final typeName = inner.str();
      final data = inner.bytesCopy(inner.uvar());
      r.position = end;
      return COpaque(origin, typeName, data);
    default:
      // Section 1.2: reserved (0x80-0xBF) and implementation-private
      // (0xC0-0xFF) tags are length-prefixed precisely so this branch can
      // skip and preserve them (spec/11-conformance.md section 4 rule 1).
      if (tag >= 0x80 || _isReservedScalar(tag)) {
        final len = _boundedLen(r);
        return CUnknown(tag, r.bytesCopy(len));
      }
      throw CorruptionException(
          'unknown CVE type tag 0x${tag.toRadixString(16)} in a range that '
          'carries no length prefix, so it cannot be skipped or preserved');
  }
}

/// The unassigned scalar ranges of section 1 that a future minor version may
/// use: 0x1D-0x1F, 0x25-0x2F and 0x33-0x7E.
bool _isReservedScalar(int tag) =>
    (tag >= 0x1D && tag <= 0x1F) ||
    (tag >= 0x25 && tag <= 0x2F) ||
    (tag >= 0x33 && tag <= 0x7E);

int _boundedLen(ByteReader r) {
  final len = r.uvar();
  if (len < 0 || len > r.remaining) {
    throw CorruptionException(
        'declared length $len exceeds ${r.remaining} remaining', offset: r.position);
  }
  return len;
}

CValue _readI128(ByteReader r, NumType t) {
  final le = r.bytesView(16);
  final be = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    be[i] = le[15 - i];
  }
  final raw = U128.fromBytesBE(be);
  if (t == NumType.u128) return CInt(t, false, raw);
  // i128: top bit is the sign.
  final negative = raw.hi < 0;
  return CInt(t, negative, negative ? raw.negate() : raw);
}

CValue _readVector(ByteReader r) {
  final dtype = r.u8();
  final dim = r.uvar();
  if (dim < 0 || dim > 1 << 24) {
    throw CorruptionException('VECTOR dim $dim out of range');
  }
  switch (dtype) {
    case 0:
      if (dim * 4 > r.remaining) {
        throw CorruptionException('VECTOR dim $dim exceeds remaining bytes');
      }
      return CVector.f32(List<double>.generate(dim, (_) => r.f32()));
    case 2:
      if (dim + 8 > r.remaining) {
        throw CorruptionException('VECTOR dim $dim exceeds remaining bytes');
      }
      final codes = List<int>.generate(dim, (_) => r.i8());
      return CVector.i8(codes, r.f32(), r.f32());
    case 1:
      throw const UnsupportedFeatureException(
          'f16 vectors are not implemented by this reference (phase 1)');
    default:
      throw CorruptionException('unknown VECTOR dtype $dtype');
  }
}

/// Decodes a whole value and asserts nothing follows it.
/// Narrows a value that came out of the file to the type the caller needs, or
/// reports corruption.
///
/// `spec/14-security.md` section 9.1 requires a decoder to "fail with a typed
/// corruption error rather than an allocation failure, a panic, an abort, or an
/// unbounded recursion", and a failed cast is a panic wearing a different name.
/// Every `as CDoc` over a decoded record is a place a hostile file chooses the
/// exception class: a data tree holding a `CArray` where the reader expects a
/// document produced a bare `_TypeError` out of an ordinary `get`, found by
/// `lib/src/fuzz.dart` on its first long run.
///
/// This is deliberately one function rather than a check at each of the thirty
/// or so sites, because the shortest way to write the narrowing has to be the
/// safe one.
T expectValue<T extends CValue>(CValue? v, String what) {
  if (v is T) return v;
  throw CorruptionException(
      '$what: expected $T, found ${v == null ? 'nothing' : v.runtimeType}');
}

/// [expectValue] for a required field of a decoded document.
T expectField<T extends CValue>(CDoc d, String field, String what) =>
    expectValue<T>(d[field], '$what field `$field`');

CValue decodeValue(Uint8List bytes, {NameDict? dict}) {
  final r = ByteReader(bytes);
  final v = readValue(r, dict: dict);
  if (!r.isAtEnd) {
    throw CorruptionException('${r.remaining} trailing byte(s) after value');
  }
  return v;
}
