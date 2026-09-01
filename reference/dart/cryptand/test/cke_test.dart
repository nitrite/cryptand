import 'dart:typed_data';

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

import 'torture.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0').toUpperCase()).join(' ');

Uint8List bytesOf(String h) => Uint8List.fromList(h
    .split(' ')
    .where((s) => s.isNotEmpty)
    .map((s) => int.parse(s, radix: 16))
    .toList());

void main() {
  // ------------------------------------------------------------------
  // spec/03-key-encoding.md section 9, byte for byte.
  // ------------------------------------------------------------------
  group('worked examples from the spec', () {
    final cases = <String, (CValue, String)>{
      'null': (const CNull(), '00'),
      'true': (const CBool(true), '10 01'),
      '0 (i32)': (CInt.i32(0), '30 02 02'),
      '5 (i32)': (CInt.i32(5), '30 03 40 02 A0 00 00 02'),
      '5.0 (f64)': (CFloat.f64(5.0), '30 03 40 02 A0 00 00 0B'),
      '-5 (i32)': (CInt.i32(-5), '30 01 BF FD 5F FF FF 02'),
      '-9 (i32)': (CInt.i32(-9), '30 01 BF FC 6F FF FF 02'),
      'ab': (const CStr('ab'), '60 61 62 00 00'),
      'abc': (const CStr('abc'), '60 61 62 63 00 00'),
      'NitriteId(1)': (const CNitriteId(1), '80 80 00 00 00 00 00 00 01'),
      'array of ab and id 1': (
        CArray([const CStr('ab'), const CNitriteId(1)]),
        'A0 01 60 61 62 00 00 01 80 80 00 00 00 00 00 00 01 00'
      ),
      'TIMESTAMP(1000)': (
        const CTimestamp(1000),
        '40 01 80 00 00 00 00 00 00 01 00 00 00 00'
      ),
      'TIMESTAMP_NS(1, 0)': (
        CTimestampNs(1, 0),
        '40 01 80 00 00 00 00 00 00 01 00 00 00 00'
      ),
      'TIMESTAMP(2000)': (
        const CTimestamp(2000),
        '40 01 80 00 00 00 00 00 00 02 00 00 00 00'
      ),
    };

    cases.forEach((name, c) {
      test(name, () => expect(hex(encodeKey(c.$1)), c.$2));
    });

    test('a millisecond and a nanosecond instant are byte-identical', () {
      // The defect the earlier draft had: two temporal subclasses made the
      // subclass byte order by precision instead of by instant.
      expect(encodeKey(const CTimestamp(1000)), encodeKey(CTimestampNs(1, 0)));
      expect(
          compareKeys(encodeKey(const CTimestamp(2000)),
              encodeKey(CTimestampNs(1, 0))),
          greaterThan(0));
    });

    test('a ZONED key drops its zone and equals the bare instant', () {
      expect(encodeKey(const CZoned(1000, 'Asia/Kolkata')),
          encodeKey(const CTimestamp(1000)));
      expect(encodeKey(const CZoned(1000, 'UTC')),
          encodeKey(const CZoned(1000, 'America/New_York')));
    });

    test('the two orderings the spec calls out', () {
      expect(compareKeys(encodeKey(CInt.i32(-9)), encodeKey(CInt.i32(-5))),
          lessThan(0));
      expect(compareKeys(encodeKey(CInt.i32(5)), encodeKey(CFloat.f64(5.0))),
          lessThan(0));
      final r = KeyRange.eqNumeric(CInt.i32(5));
      expect(hex(r.lower), '30 03 40 02 A0 00 00');
      expect(hex(r.upper!), '30 03 40 02 A0 00 01');
      expect(r.contains(encodeKey(CInt.i32(5))), isTrue);
      expect(r.contains(encodeKey(CFloat.f64(5.0))), isTrue);
    });
  });

  // ------------------------------------------------------------------
  // The chapter's defining invariant.
  // ------------------------------------------------------------------
  group('memcmp of CKE matches the exact numeric order', () {
    final numbers = <CValue>[...torturedIntegers(), ...torturedFloats()];

    // spec/03-key-encoding.md section 1, both clauses.
    //
    //   1. L != 0  =>  memcmp has the same sign as L
    //   2. L == 0  =>  the keys are equal, or differ only in the trailing
    //                  numeric type code and are adjacent inside
    //                  [N(v), successor(N(v)))
    //
    // Clause 2 is why the invariant is stated as a *refinement*: I8(0) and
    // I16(0) are numerically equal and encode as 30 02 00 and 30 02 01.
    test('clause 1: a non-zero comparison never inverts', () {
      var strict = 0;
      for (final a in numbers) {
        for (final b in numbers) {
          final want = referenceCompareNumeric(a, b).sign;
          if (want == 0) continue;
          final got = compareKeys(encodeKey(a), encodeKey(b)).sign;
          if (want != got) {
            fail('CKE order disagrees with exact arithmetic'
                '\n  a = $a  CKE ${hex(encodeKey(a))}'
                '\n  b = $b  CKE ${hex(encodeKey(b))}'
                '\n  exact says $want, memcmp says $got');
          }
          strict++;
        }
      }
      expect(strict, greaterThan(20000));
    });

    test('clause 2: equal values differ only in the type code, and adjacently',
        () {
      var classes = 0;
      for (final a in numbers) {
        for (final b in numbers) {
          if (referenceCompareNumeric(a, b) != 0) continue;
          final ka = encodeKey(a), kb = encodeKey(b);
          // Same ordering region, so the keys differ at most in their last
          // byte -- the type code.
          expect(ka.length, kb.length, reason: 'lengths differ: $a vs $b');
          expect(Uint8List.sublistView(ka, 0, ka.length - 1),
              Uint8List.sublistView(kb, 0, kb.length - 1),
              reason: 'ordering regions differ: $a vs $b');
          // And both fall inside the type-agnostic equality range of either.
          for (final probe in [a, b]) {
            final r = KeyRange.eqNumeric(probe);
            expect(r.contains(ka), isTrue, reason: '$a not in eq($probe)');
            expect(r.contains(kb), isTrue, reason: '$b not in eq($probe)');
          }
          classes++;
        }
      }
      expect(classes, greaterThan(500));
    });

    test('CKE order is total and its collapse is the logical order', () {
      // Sorting by CKE bytes and then dropping type codes must produce a
      // sequence that is non-decreasing under exact arithmetic.
      final sorted = [...numbers]
        ..sort((a, b) => compareKeys(encodeKey(a), encodeKey(b)));
      for (var i = 1; i < sorted.length; i++) {
        expect(referenceCompareNumeric(sorted[i - 1], sorted[i]),
            lessThanOrEqualTo(0),
            reason: 'CKE sort inverted ${sorted[i - 1]} before ${sorted[i]}');
      }
    });

    test('numerically equal values across types are byte-adjacent', () {
      final five = <CValue>[
        CInt.of(NumType.i8, 5),
        CInt.of(NumType.i16, 5),
        CInt.i32(5),
        CInt.i64(5),
        intOf(NumType.i128, BigInt.from(5)),
        CInt.of(NumType.u8, 5),
        CInt.of(NumType.u16, 5),
        CInt.of(NumType.u32, 5),
        CInt.of(NumType.u64, 5),
        intOf(NumType.u128, BigInt.from(5)),
        CInt.varInt(5),
        CFloat.f32(5.0),
        CFloat.f64(5.0),
      ];
      final range = KeyRange.eqNumeric(CInt.i32(5));
      for (final v in five) {
        expect(range.contains(encodeKey(v)), isTrue, reason: '$v');
      }
      for (final v in [
        CInt.i32(4),
        CInt.i32(6),
        CFloat.f64(5.0000000000000009),
        CFloat.f64(4.999999999999999),
        CInt.i32(-5),
      ]) {
        expect(range.contains(encodeKey(v)), isFalse, reason: '$v');
      }
    });
  });

  // ------------------------------------------------------------------
  // Round trips.
  // ------------------------------------------------------------------
  group('decoding', () {
    test('round-trips every numeric in the torture set', () {
      // spec/03-key-encoding.md section 7 lists exactly three lossy cases.
      // Everything else must be byte-for-byte injective.
      for (final v in [...torturedIntegers(), ...torturedFloats()]) {
        final back = decodeKey(encodeKey(v));
        if (v is CFloat && v.value.isNaN) {
          // Lossy case 3: a NaN payload is not preserved.
          expect((back as CFloat).value.isNaN, isTrue, reason: '$v');
          expect(back.type, v.type);
        } else if (v is CFloat && v.value == 0.0 && v.value.isNegative) {
          // Lossy case 2: -0.0 decodes as +0.0, because section 8 rule 2 of
          // spec/02-value-encoding.md declares them equal and a key that
          // separated them would sit strictly between two equal values.
          expect(back, CFloat(v.type, 0.0), reason: '$v');
          expect((back as CFloat).value.isNegative, isFalse);
        } else {
          expect(back, v, reason: '$v -> ${hex(encodeKey(v))}');
        }
      }
    });

    test('the three lossy decodings are exactly the three the spec lists', () {
      // Negative zero.
      expect(decodeKey(encodeKey(CFloat.f64(-0.0))), CFloat.f64(0.0));
      expect(encodeKey(CFloat.f64(-0.0)), encodeKey(CFloat.f64(0.0)));
      // NaN payload.
      final payloadNan = CFloat(NumType.f64, bitsToF64(0x7FF8000000000001));
      expect(encodeKey(payloadNan), encodeKey(CFloat.f64(double.nan)));
      // Instant precision and zone: covered by the instant test below.
      // And nothing else: a positive zero, an infinity and every integer
      // width all come back exactly.
      expect(decodeKey(encodeKey(CFloat.f64(0.0))), CFloat.f64(0.0));
      expect(decodeKey(encodeKey(CFloat.f64(double.infinity))),
          CFloat.f64(double.infinity));
      expect(decodeKey(encodeKey(CInt.of(NumType.u8, 0))),
          CInt.of(NumType.u8, 0));
      expect(decodeKey(encodeKey(CInt.of(NumType.i16, 0))),
          CInt.of(NumType.i16, 0));
    });

    test('round-trips the non-numeric groups', () {
      final values = <CValue>[
        const CNull(),
        const CBool(false),
        const CBool(true),
        CChar(0x1F408),
        CChar(65),
        const CStr(''),
        const CStr('ab'),
        const CStr('Backerei-Strasse 12'),
        CBytes([]),
        CBytes([0, 0, 1, 0xFF]),
        const CNitriteId(0),
        const CNitriteId(-1),
        const CNitriteId(0x7FFFFFFFFFFFFFFF),
        const CNitriteId(-0x8000000000000000),
        CUuid(List.generate(16, (i) => i * 7 & 0xFF)),
        const CDate(0),
        const CDate(-719162),
        CTime(86399999999999),
        CDuration(-5, 500000000),
        CArray([]),
        CArray([const CStr('a')]),
        CArray([const CStr('a'), const CNitriteId(1)]),
        CArray([
          CArray([const CBool(true)]),
          const CNull()
        ]),
      ];
      for (final v in values) {
        expect(decodeKey(encodeKey(v)), v, reason: '$v');
      }
    });

    test('a string containing NUL survives the escape', () {
      final s = CStr('a\u0000b');
      expect(decodeKey(encodeKey(s)), s);
      // The escape must keep "a NUL b" above "a" and below "a b".
      expect(compareKeys(encodeKey(s), encodeKey(const CStr('a'))),
          greaterThan(0));
      expect(compareKeys(encodeKey(s), encodeKey(const CStr('ab'))), lessThan(0));
    });

    test('instants decode to TIMESTAMP_NS whatever tag produced them', () {
      expect(decodeKey(encodeKey(const CTimestamp(1500))),
          CTimestampNs(1, 500000000));
      expect(
          decodeKey(encodeKey(const CTimestamp(-1))), CTimestampNs(-1, 999000000));
      expect(decodeKey(encodeKey(const CZoned(1500, 'UTC'))),
          CTimestampNs(1, 500000000));
    });

    test('rejects what section 7 says it must', () {
      expect(() => decodeKey(bytesOf('B0')), throwsA(isA<CorruptionException>()),
          reason: 'unknown group tag');
      expect(() => decodeKey(bytesOf('60 61')),
          throwsA(isA<CorruptionException>()),
          reason: 'truncated body');
      expect(() => decodeKey(bytesOf('60 61 00 02 00 00')),
          throwsA(isA<CorruptionException>()),
          reason: 'non-canonical escape');
      expect(() => decodeKey(bytesOf('30 03 40 02 7F 00 00 02')),
          throwsA(isA<CorruptionException>()),
          reason: 'mantissa first byte below 0x80');
      expect(() => decodeKey(bytesOf('30 03 40 02 00 00 02')),
          throwsA(isA<CorruptionException>()),
          reason: 'empty mantissa');
      expect(() => decodeKey(bytesOf('30 03 40 02 A0 00 00 0D')),
          throwsA(isA<CorruptionException>()),
          reason: 'type code 0x0D is reserved: DEC128 is not a key');
      expect(
          () => decodeKey(bytesOf('40 02 80 00 00 00 00 00 00 01 00 00 00 00')),
          throwsA(isA<CorruptionException>()),
          reason: 'temporal subclass 0x02 is reserved');
      expect(() => decodeKey(bytesOf('00 00')),
          throwsA(isA<CorruptionException>()),
          reason: 'trailing bytes');
    });
  });

  // ------------------------------------------------------------------
  // Types that must not be keys.
  // ------------------------------------------------------------------
  test('rejects every value section 2 says has no CKE encoding', () {
    final unkeyable = <CValue>[
      CDoc({'a': const CNull()}),
      CMap([]),
      CVector.f32([1, 2, 3]),
      CGeometry([1, 2, 3]),
      const CRegex('a.*', 'i'),
      COpaque('java', 'com.example.Thing', [1, 2]),
      CDec128(Uint8List(16)),
      const CBlobRef(1, 2, 3),
      COverflowRef([1], 2),
      const CVlogRef(1, 2, 3),
    ];
    for (final v in unkeyable) {
      expect(isKeyEncodable(v), isFalse, reason: '$v');
      expect(() => encodeKey(v), throwsA(isA<InvalidArgumentException>()),
          reason: '$v');
    }
  });

  test('an array containing an unkeyable value is itself unkeyable', () {
    final a = CArray([
      const CStr('x'),
      CVector.f32([1])
    ]);
    expect(isKeyEncodable(a), isFalse);
    expect(() => encodeKey(a), throwsA(isA<InvalidArgumentException>()));
  });
}
