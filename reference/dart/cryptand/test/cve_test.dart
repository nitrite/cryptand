import 'dart:typed_data';

import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

import 'torture.dart';

/// Every value the reference model can express, used as the round-trip corpus.
List<CValue> corpus() => <CValue>[
      const CNull(),
      const CBool(false),
      const CBool(true),
      ...torturedIntegers(),
      ...torturedFloats(),
      CDec128(Uint8List.fromList(List.generate(16, (i) => i))),
      CChar(0x1F408),
      CChar(0),
      const CStr(''),
      const CStr('customerAddressLine1'),
      CBytes([]),
      CBytes([0, 255, 1]),
      const CTimestamp(0),
      const CTimestamp(-1),
      const CTimestamp(1767225600000),
      CTimestampNs(-1, 999000000),
      const CZoned(1767225600000, 'Asia/Kolkata'),
      const CDate(-719162),
      CTime(86399999999999),
      CDuration(-5, 1),
      CUuid(List.generate(16, (i) => i)),
      const CNitriteId(-0x8000000000000000),
      const CNitriteId(0x7FFFFFFFFFFFFFFF),
      const CRegex(r'^a.*z$', 'im'),
      CArray([]),
      CArray([const CNull(), CInt.i32(1), const CStr('x')]),
      // Already in CKE order: the round-trip corpus asserts identity, and
      // the encoder normalizes order (see the MAP group below).
      CMap([
        (CInt.i32(1), const CStr('one')),
        (CInt.i32(2), const CStr('two')),
      ]),
      CDoc({'b': CInt.i32(2), 'a': const CStr('x')}),
      CVector.f32([1.5, -2.25, 0.0]),
      CVector.i8([1, -2, 3], 0.5, 0.25),
      CGeometry([1, 1, 0, 0, 0]),
      const CBlobRef(42, 1024, 0xDEADBEEF),
      COverflowRef([1, 2, 3], 99),
      const CVlogRef(7, 8, 9),
      COpaque('java', 'org.dizitart.Thing', [0xCA, 0xFE]),
    ];

void main() {
  group('round trip', () {
    test('every value in the corpus', () {
      for (final v in corpus()) {
        final bytes = encodeValue(v);
        final back = decodeValue(bytes);
        if (v is CFloat && v.value.isNaN) {
          expect((back as CFloat).value.isNaN, isTrue, reason: '$v');
        } else {
          expect(back, v, reason: '$v');
        }
      }
    });

    test('nested to the depth limit', () {
      CValue v = const CNull();
      for (var i = 0; i < 90; i++) {
        v = CArray([v]);
      }
      expect(decodeValue(encodeValue(v)), v);
    });

    test('rejects nesting past the depth limit on write and on read', () {
      CValue v = const CNull();
      for (var i = 0; i < 120; i++) {
        v = CArray([v]);
      }
      expect(() => encodeValue(v), throwsA(isA<LimitException>()));
    });
  });

  group('canonical forms', () {
    test('NaN is canonicalized on encode', () {
      // spec/00-conventions.md section 3.
      final weird = CFloat(NumType.f64, bitsToF64(0x7FF8000000000001));
      final canonical = CFloat.f64(double.nan);
      expect(encodeValue(weird), encodeValue(canonical));
    });

    test('an f32 value is exactly what binary32 can hold', () {
      final v = CFloat(NumType.f32, 0.1);
      expect(v.value, isNot(0.1));
      expect(decodeValue(encodeValue(v)), v);
    });

    test('INT_VAR is compact and I64 is fixed width', () {
      expect(encodeValue(CInt.varInt(1)).length, 2); // tag + one ivar byte
      expect(encodeValue(CInt.i64(1)).length, 9); // tag + 8
    });

    test('a 128-bit integer survives both signs and both extremes', () {
      for (final v in [
        intOf(NumType.i128, BigInt.two.pow(127) - BigInt.one),
        intOf(NumType.i128, -BigInt.two.pow(127)),
        intOf(NumType.i128, BigInt.from(-1)),
        intOf(NumType.u128, BigInt.two.pow(128) - BigInt.one),
      ]) {
        expect(encodeValue(v).length, 17);
        expect(decodeValue(encodeValue(v)), v, reason: '$v');
      }
    });
  });

  group('MAP', () {
    test('is stored sorted by CKE(key) whatever order it was built in', () {
      final m = CMap([
        (const CStr('b'), CInt.i32(2)),
        (const CStr('a'), CInt.i32(1)),
        (CInt.i32(9), const CStr('nine')),
      ]);
      final back = decodeValue(encodeValue(m)) as CMap;
      // NUMBER (0x30) sorts before STRING (0x60).
      expect((back.entries[0].$1 as CInt).asInt, 9);
      expect((back.entries[1].$1 as CStr).value, 'a');
      expect((back.entries[2].$1 as CStr).value, 'b');
    });

    test('rejects a key with no CKE encoding', () {
      // spec/02-value-encoding.md section 4.
      final m = CMap([
        (CDoc({'a': const CNull()}), CInt.i32(1)),
      ]);
      expect(() => encodeValue(m), throwsA(isA<InvalidArgumentException>()));
    });

    test('rejects duplicate keys', () {
      final m = CMap([
        (CInt.i32(1), const CStr('a')),
        (CInt.i32(1), const CStr('b')),
      ]);
      expect(() => encodeValue(m), throwsA(isA<InvalidArgumentException>()));
    });

    test('rejects an out-of-order map on read', () {
      // Hand-build a MAP whose entries are not sorted.
      final inner = <int>[];
      inner.addAll(encodeValue(const CStr('b')));
      inner.addAll(encodeValue(CInt.i32(2)));
      inner.addAll(encodeValue(const CStr('a')));
      inner.addAll(encodeValue(CInt.i32(1)));
      final body = <int>[2, ...inner];
      final bytes = Uint8List.fromList([Tag.map, body.length, ...body]);
      expect(() => decodeValue(bytes), throwsA(isA<CorruptionException>()));
    });
  });

  group('unknown tags', () {
    // spec/11-conformance.md section 4 rule 1, made possible by
    // spec/02-value-encoding.md section 1.2's length-prefix rule.
    test('a reserved tag round-trips byte for byte', () {
      final payload = [1, 2, 3, 4, 5];
      final bytes =
          Uint8List.fromList([0x90, payload.length, ...payload]);
      final v = decodeValue(bytes);
      expect(v, isA<CUnknown>());
      expect((v as CUnknown).unknownTag, 0x90);
      expect(v.payload, payload);
      expect(encodeValue(v), bytes);
    });

    test('an unknown tag survives inside an array, which needs the length',
        () {
      final unknown = CUnknown(0xC5, [7, 7, 7]);
      final a = CArray([CInt.i32(1), unknown, const CStr('after')]);
      final back = decodeValue(encodeValue(a)) as CArray;
      expect(back.items[1], unknown);
      expect((back.items[2] as CStr).value, 'after');
    });

    test('an unassigned scalar tag with no length prefix is corruption', () {
      // 0x1D is reserved but a hostile file could use it without a length.
      // The decoder must refuse rather than guess a width.
      expect(() => decodeValue(Uint8List.fromList([0x1D])),
          throwsA(isA<CryptandException>()));
    });
  });

  group('hostile input', () {
    test('a declared length past the buffer is corruption, not an allocation',
        () {
      for (final bytes in [
        [Tag.bytes, 0xFF, 0xFF, 0xFF, 0x7F],
        [Tag.array, 0xFF, 0xFF, 0xFF, 0x7F],
        [Tag.opaque, 0xFF, 0xFF, 0xFF, 0x7F],
        [Tag.geometry, 0xFF, 0xFF, 0xFF, 0x7F],
      ]) {
        expect(() => decodeValue(Uint8List.fromList(bytes)),
            throwsA(isA<CryptandException>()),
            reason: '${bytes.first}');
      }
    });

    test('an array count larger than its own byte span is rejected', () {
      // count = 1000 inside a 2-byte array body.
      final bytes = Uint8List.fromList([Tag.array, 2, 0xE8, 0x07]);
      expect(() => decodeValue(bytes), throwsA(isA<CryptandException>()));
    });

    test('trailing bytes after a complete value are rejected', () {
      expect(() => decodeValue(Uint8List.fromList([Tag.nul, Tag.nul])),
          throwsA(isA<CorruptionException>()));
    });

    test('a CHAR that is not a scalar value is rejected', () {
      final bd = ByteData(4)..setUint32(0, 0xD800, Endian.little);
      final bytes = Uint8List.fromList(
          [Tag.char, ...Uint8List.view(bd.buffer)]);
      expect(() => decodeValue(bytes), throwsA(isA<CorruptionException>()));
    });
  });
}
