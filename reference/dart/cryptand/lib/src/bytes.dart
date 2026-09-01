/// Primitive reading and writing, `spec/00-conventions.md` sections 3 and 4.
///
/// Two rules from the spec shape this file:
///
///  * **Little-endian everywhere except inside a CKE key.** CKE builds its own
///    big-endian bytes in `cke.dart`; nothing here does.
///  * **"Inside a page, no alignment is required or assumed — a conforming
///    reader MUST use unaligned reads (or byte assembly). This keeps Dart and
///    WASM implementations honest."** [ByteData] does unaligned access, so
///    every accessor below is offset-agnostic by construction.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';
import 'limits.dart';

/// A growable little-endian byte sink.
final class ByteWriter {
  ByteWriter([int initialCapacity = 256])
      : _buf = Uint8List(initialCapacity < 16 ? 16 : initialCapacity) {
    _view = ByteData.view(_buf.buffer);
  }

  Uint8List _buf;
  late ByteData _view;
  int _len = 0;

  int get length => _len;

  void _ensure(int extra) {
    final need = _len + extra;
    if (need <= _buf.length) return;
    var cap = _buf.length;
    while (cap < need) {
      cap *= 2;
    }
    final grown = Uint8List(cap)..setRange(0, _len, _buf);
    _buf = grown;
    _view = ByteData.view(_buf.buffer);
  }

  void u8(int v) {
    _ensure(1);
    _buf[_len++] = v & 0xFF;
  }

  void u16(int v) {
    _ensure(2);
    _view.setUint16(_len, v, Endian.little);
    _len += 2;
  }

  void u32(int v) {
    _ensure(4);
    _view.setUint32(_len, v, Endian.little);
    _len += 4;
  }

  /// Writes a raw 64-bit pattern; signedness is the caller's interpretation.
  void u64(int v) {
    _ensure(8);
    _view.setUint64(_len, v, Endian.little);
    _len += 8;
  }

  void i8(int v) {
    _ensure(1);
    _view.setInt8(_len, v);
    _len += 1;
  }

  void i16(int v) {
    _ensure(2);
    _view.setInt16(_len, v, Endian.little);
    _len += 2;
  }

  void i32(int v) {
    _ensure(4);
    _view.setInt32(_len, v, Endian.little);
    _len += 4;
  }

  void i64(int v) => u64(v);

  void f32(double v) {
    _ensure(4);
    _view.setFloat32(_len, v, Endian.little);
    _len += 4;
  }

  void f64(double v) {
    _ensure(8);
    _view.setFloat64(_len, v, Endian.little);
    _len += 8;
  }

  void bytes(List<int> b) {
    _ensure(b.length);
    _buf.setRange(_len, _len + b.length, b);
    _len += b.length;
  }

  /// LEB128 unsigned varint over a raw 64-bit pattern, seven payload bits per
  /// byte, low bits first, high bit set on every byte but the last.
  void uvar(int v) {
    var x = v;
    while (true) {
      final b = x & 0x7F;
      x = x >>> 7;
      if (x == 0) {
        u8(b);
        return;
      }
      u8(b | 0x80);
    }
  }

  /// Zigzag then LEB128.
  void ivar(int v) => uvar(zigzagEncode(v));

  /// `uvar length` then that many bytes of UTF-8.
  ///
  /// `spec/00-conventions.md` section 4: "Unpaired surrogates MUST be rejected
  /// on write." Dart strings are UTF-16, so an unpaired surrogate is
  /// representable and [utf8.encode] would silently substitute U+FFFD — the
  /// exact silent corruption the spec forbids. Hence the explicit scan.
  void str(String s) {
    final encoded = encodeUtf8Strict(s);
    uvar(encoded.length);
    bytes(encoded);
  }

  /// Overwrites four bytes already written, for back-patched lengths and
  /// checksums.
  void patchU32(int offset, int v) => _view.setUint32(offset, v, Endian.little);

  /// A view over what has been written. Not a copy; do not retain it across
  /// further writes.
  Uint8List get view => Uint8List.sublistView(_buf, 0, _len);

  Uint8List takeBytes() => Uint8List.fromList(view);
}

/// Encodes [s] as UTF-8, rejecting unpaired surrogates rather than replacing
/// them.
Uint8List encodeUtf8Strict(String s) {
  for (var i = 0; i < s.length; i++) {
    final c = s.codeUnitAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      final next = i + 1 < s.length ? s.codeUnitAt(i + 1) : 0;
      if (next < 0xDC00 || next > 0xDFFF) {
        throw InvalidArgumentException(
            'unpaired high surrogate U+${c.toRadixString(16)} at index $i');
      }
      i++;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      throw InvalidArgumentException(
          'unpaired low surrogate U+${c.toRadixString(16)} at index $i');
    }
  }
  return Uint8List.fromList(utf8.encode(s));
}

int zigzagEncode(int v) => (v << 1) ^ (v >> 63);
int zigzagDecode(int v) => (v >>> 1) ^ -(v & 1);

/// A bounds-checked little-endian byte source.
///
/// Every accessor calls [_need] before it touches or allocates anything, which
/// is `spec/00-conventions.md` section 8's untrusted-length rule and
/// `spec/14-security.md` section 9.1's restatement of it as a security
/// requirement.
final class ByteReader {
  ByteReader(this.data, [this.start = 0, int? end])
      : end = end ?? data.length,
        _pos = start {
    if (this.end > data.length || start > this.end) {
      throw ArgumentError('slice $start..${this.end} outside ${data.length}');
    }
    _view = ByteData.view(data.buffer, data.offsetInBytes, data.length);
  }

  final Uint8List data;
  final int start;
  final int end;
  late final ByteData _view;
  int _pos;

  int get position => _pos;
  set position(int p) {
    if (p < start || p > end) {
      throw CorruptionException('seek to $p outside $start..$end');
    }
    _pos = p;
  }

  int get remaining => end - _pos;
  bool get isAtEnd => _pos >= end;

  void _need(int n) {
    if (n < 0 || n > end - _pos) {
      throw CorruptionException(
          'truncated: need $n byte(s), ${end - _pos} remain', offset: _pos);
    }
  }

  int u8() {
    _need(1);
    return data[_pos++];
  }

  int u16() {
    _need(2);
    final v = _view.getUint16(_pos, Endian.little);
    _pos += 2;
    return v;
  }

  int u32() {
    _need(4);
    final v = _view.getUint32(_pos, Endian.little);
    _pos += 4;
    return v;
  }

  int u64() {
    _need(8);
    final v = _view.getUint64(_pos, Endian.little);
    _pos += 8;
    return v;
  }

  int i8() {
    _need(1);
    return _view.getInt8(_pos++);
  }

  int i16() {
    _need(2);
    final v = _view.getInt16(_pos, Endian.little);
    _pos += 2;
    return v;
  }

  int i32() {
    _need(4);
    final v = _view.getInt32(_pos, Endian.little);
    _pos += 4;
    return v;
  }

  int i64() => u64();

  double f32() {
    _need(4);
    final v = _view.getFloat32(_pos, Endian.little);
    _pos += 4;
    return v;
  }

  double f64() {
    _need(8);
    final v = _view.getFloat64(_pos, Endian.little);
    _pos += 8;
    return v;
  }

  /// A **view**, not a copy. Callers that retain it must copy.
  Uint8List bytesView(int n) {
    _need(n);
    final v = Uint8List.sublistView(data, _pos, _pos + n);
    _pos += n;
    return v;
  }

  Uint8List bytesCopy(int n) => Uint8List.fromList(bytesView(n));

  /// LEB128 unsigned varint.
  ///
  /// Rejects, per `spec/00-conventions.md` section 4:
  ///  * an encoding longer than 10 bytes;
  ///  * a 10th byte contributing more than the one bit a `u64` has room for;
  ///  * a non-canonical encoding — a continuation byte followed by a final
  ///    byte that contributes nothing.
  int uvar() {
    var result = 0;
    var shift = 0;
    var count = 0;
    while (true) {
      final b = u8();
      count++;
      if (count > kMaxUvarBytes) {
        throw const CorruptionException('uvar longer than 10 bytes');
      }
      if (count == kMaxUvarBytes && (b & 0x7F) > 0x01) {
        throw const CorruptionException('uvar overflows 64 bits');
      }
      result |= (b & 0x7F) << shift;
      if (b & 0x80 == 0) {
        if (count > 1 && b == 0x00) {
          throw const CorruptionException(
              'non-canonical uvar: final byte contributes no bits');
        }
        return result;
      }
      shift += 7;
    }
  }

  int ivar() => zigzagDecode(uvar());

  /// `uvar length` then that many bytes of UTF-8.
  ///
  /// `spec/00-conventions.md` section 4: "A reader encountering ill-formed
  /// UTF-8 MUST report corruption; it MUST NOT substitute replacement
  /// characters silently."
  String str() {
    final n = uvar();
    _need(n); // before allocating
    final raw = bytesView(n);
    try {
      return const Utf8Decoder(allowMalformed: false).convert(raw);
    } on FormatException catch (e) {
      throw CorruptionException('ill-formed UTF-8: ${e.message}', offset: _pos);
    }
  }
}
