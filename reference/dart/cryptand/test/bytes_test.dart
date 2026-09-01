import 'dart:typed_data';
import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/errors.dart';
import 'package:test/test.dart';

ByteReader readerOf(List<int> b) => ByteReader(Uint8List.fromList(b));

void main() {
  group('uvar', () {
    test('round-trips every interesting width', () {
      final values = [
        0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000,
        0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF, -1, // -1 is the all-ones u64 pattern
      ];
      for (final v in values) {
        final w = ByteWriter()..uvar(v);
        expect(readerOf(w.takeBytes()).uvar(), v,
            reason: '0x${v.toRadixString(16)}');
      }
    });

    test('encodes the canonical minimum number of bytes', () {
      expect((ByteWriter()..uvar(0)).length, 1);
      expect((ByteWriter()..uvar(127)).length, 1);
      expect((ByteWriter()..uvar(128)).length, 2);
      expect((ByteWriter()..uvar(-1)).length, 10); // full 64 bits
    });

    // spec/00-conventions.md section 4: "MUST reject a non-canonical encoding".
    test('rejects a non-canonical encoding', () {
      expect(() => readerOf([0x80, 0x00]).uvar(),
          throwsA(isA<CorruptionException>()));
      expect(() => readerOf([0x81, 0x80, 0x00]).uvar(),
          throwsA(isA<CorruptionException>()));
    });

    test('rejects an encoding longer than 10 bytes', () {
      expect(() => readerOf(List.filled(11, 0x80) + [0x01]).uvar(),
          throwsA(isA<CorruptionException>()));
    });

    test('rejects a 10th byte that overflows 64 bits', () {
      expect(() => readerOf(List.filled(9, 0x80) + [0x02]).uvar(),
          throwsA(isA<CorruptionException>()));
    });

    test('rejects a truncated encoding', () {
      expect(() => readerOf([0x80]).uvar(), throwsA(isA<CorruptionException>()));
    });
  });

  group('ivar', () {
    test('round-trips across zero and the extremes', () {
      for (final v in [
        0, 1, -1, 2, -2, 63, -64, 0x7FFFFFFF, -0x80000000,
        0x7FFFFFFFFFFFFFFF, -0x8000000000000000,
      ]) {
        final w = ByteWriter()..ivar(v);
        expect(readerOf(w.takeBytes()).ivar(), v, reason: '$v');
      }
    });

    test('small magnitudes are one byte in both directions', () {
      expect((ByteWriter()..ivar(-1)).length, 1);
      expect((ByteWriter()..ivar(63)).length, 1);
      expect((ByteWriter()..ivar(-64)).length, 1);
    });
  });

  group('fixed width', () {
    test('is little-endian', () {
      expect((ByteWriter()..u32(0x01020304)).takeBytes(), [4, 3, 2, 1]);
      expect((ByteWriter()..u16(0x0102)).takeBytes(), [2, 1]);
      expect((ByteWriter()..u64(0x0102030405060708)).takeBytes(),
          [8, 7, 6, 5, 4, 3, 2, 1]);
    });

    test('round-trips at unaligned offsets', () {
      // spec/00-conventions.md section 5: a reader MUST use unaligned reads.
      for (var pad = 0; pad < 8; pad++) {
        final w = ByteWriter()..bytes(List.filled(pad, 0xAA));
        w
          ..u64(0x0102030405060708)
          ..u32(0xDEADBEEF)
          ..f64(3.141592653589793);
        final r = ByteReader(w.takeBytes())..position = pad;
        expect(r.u64(), 0x0102030405060708, reason: 'pad $pad');
        expect(r.u32(), 0xDEADBEEF, reason: 'pad $pad');
        expect(r.f64(), 3.141592653589793, reason: 'pad $pad');
      }
    });
  });

  group('str', () {
    test('round-trips ASCII, multibyte and 4-byte code points', () {
      for (final s in [
        '',
        'ab',
        'Bäckerei-Straße 12',
        '日本語',
        'cat \u{1F408} tail',
        'zwj \u{1F408}‍⬛ end',
      ]) {
        final w = ByteWriter()..str(s);
        expect(readerOf(w.takeBytes()).str(), s, reason: s);
      }
    });

    // spec/00-conventions.md section 4: unpaired surrogates MUST be rejected
    // on write. Dart strings are UTF-16, so this is reachable, and utf8.encode
    // would silently substitute U+FFFD.
    test('rejects an unpaired high surrogate on write', () {
      expect(() => ByteWriter().str('a\uD800b'),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('rejects an unpaired low surrogate on write', () {
      expect(() => ByteWriter().str('a\uDC00'),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('accepts a correctly paired surrogate', () {
      final w = ByteWriter()..str('a\u{1F408}b');
      expect(readerOf(w.takeBytes()).str(), 'a\u{1F408}b');
    });

    // "A reader encountering ill-formed UTF-8 MUST report corruption; it MUST
    // NOT substitute replacement characters silently."
    test('reports corruption on ill-formed UTF-8, never U+FFFD', () {
      expect(() => readerOf([2, 0xC3, 0x28]).str(),
          throwsA(isA<CorruptionException>()));
      expect(() => readerOf([1, 0xFF]).str(),
          throwsA(isA<CorruptionException>()));
      // A lone surrogate encoded as CESU-8 must not decode.
      expect(() => readerOf([3, 0xED, 0xA0, 0x80]).str(),
          throwsA(isA<CorruptionException>()));
    });

    test('a declared length past the end is corruption, not an allocation', () {
      expect(() => readerOf([0xFF, 0xFF, 0xFF, 0x7F, 1, 2]).str(),
          throwsA(isA<CorruptionException>()));
    });
  });

  test('reads never run past a slice boundary', () {
    final r = ByteReader(Uint8List.fromList([1, 2, 3, 4, 5, 6]), 1, 4);
    expect(r.remaining, 3);
    expect(r.u16(), 0x0302);
    expect(() => r.u32(), throwsA(isA<CorruptionException>()));
  });
}
