/// `spec/02-value-encoding.md` section 8 — the definition of value order.
///
/// This file exists because it was missing. `lib/src/compare.dart` is exported
/// from `package:cryptand` and its own header names
/// `test/cke_order_test.dart` as "the single most important test in this
/// package"; that file has never existed, and the coverage run that found this
/// reported **0 of 144 lines** for the whole library. `cke_test.dart` does
/// test the numeric ordering invariant, but against a `referenceCompareNumeric`
/// local to the test — so the shipped definition of order and the shipped key
/// encoding could disagree with each other and every test would still pass.
///
/// The invariant that matters, and the reason section 8 and
/// `03-key-encoding.md` are two chapters describing one thing:
///
///     sign(compareValues(a, b)) == sign(memcmp(CKE(a), CKE(b)))
///
/// A divergence there is a wrong query result in production, not a slow one:
/// the B+tree navigates by bytes, the application reasons in values, and a
/// range scan silently returns the wrong rows.
library;

import 'dart:typed_data';

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/compare.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/u128.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

import 'torture.dart';

/// Every ordered value the format can hold, at least one per group, with the
/// boundaries that have historically broken implementations.
///
/// Deliberately mixes groups: rule 10's cross-type order is only exercised if
/// the set is heterogeneous, and the transitivity check below is worthless on a
/// set that never crosses a group boundary.
List<CValue> orderedCorpus() => <CValue>[
      const CNull(),
      const CBool(false),
      const CBool(true),
      ...torturedIntegers(),
      ...torturedFloats(),
      CChar(0x41),
      CChar(0x10FFFF),
      CChar(0x00),
      const CStr(''),
      const CStr('a'),
      const CStr('ab'),
      const CStr('b'),
      const CStr('é'), // 2-byte UTF-8
      const CStr('一'), // 3-byte
      // U+FF61 and U+1F600 together are what make the pair sweep a control
      // for the UTF-16 mistake: U+FF61 is one UTF-16 code unit (0xFF61) and
      // U+1F600 is a surrogate pair starting 0xD83D, so a comparator written
      // over code units orders them the opposite way to UTF-8.
      const CStr('\u{FF61}'),
      const CStr('\u{1F600}'), // 4-byte, above the BMP
      CBytes(const []),
      CBytes(const [0]),
      CBytes(const [0, 0]),
      CBytes(const [0xFF]),
      const CNitriteId(0),
      const CNitriteId(-1),
      const CNitriteId(1),
      const CNitriteId(9223372036854775807),
      const CNitriteId(-9223372036854775808),
      CUuid(List<int>.filled(16, 0)),
      CUuid(List<int>.filled(16, 0xFF)),
      CUuid([1, ...List<int>.filled(15, 0)]),
      const CTimestamp(0),
      const CTimestamp(1000),
      const CTimestamp(-1),
      CTimestampNs(1, 0), // equals CTimestamp(1000) -- rule 7
      CTimestampNs(0, 1),
      const CZoned(1000, 'Asia/Kolkata'), // also equals CTimestamp(1000)
      const CDate(0),
      const CDate(-1),
      const CDate(19000),
      CTime(0),
      CTime(86399999999999),
      CDuration(0, 0),
      CDuration(-1, 999999999),
      CDuration(1, 1),
      CArray(const []),
      CArray(const [CBool(false)]),
      CArray(const [CBool(true)]),
      CArray(const [CBool(false), CBool(false)]),
    ];

/// Values that are ordered but have no key encoding — rule 8's DOC and MAP.
List<CValue> unencodableButOrdered() => <CValue>[
      CDoc(const {}),
      CDoc(const {'a': CBool(false)}),
      CDoc(const {'a': CBool(true)}),
      CDoc(const {'a': CBool(false), 'b': CBool(false)}),
      CMap(const []),
      CMap(const [(CStr('a'), CBool(false))]),
      CMap(const [(CStr('a'), CBool(true))]),
    ];

int _sign(int v) => v < 0 ? -1 : (v > 0 ? 1 : 0);

void main() {
  final corpus = orderedCorpus();

  // ------------------------------------------------------------------
  // The chapter's reason for existing.
  // ------------------------------------------------------------------
  group('CKE byte order is the section 8 value order', () {
    test('every encodable pair agrees, in sign', () {
      final keyable = corpus.where(isKeyEncodable).toList();
      expect(keyable.length, greaterThan(150),
          reason: 'the corpus must be large enough for the pair sweep to mean '
              'something');
      var pairs = 0;
      var strict = 0;
      for (final a in keyable) {
        for (final b in keyable) {
          final want = _sign(compareValues(a, b));
          final got = _sign(compareKeys(encodeKey(a), encodeKey(b)));
          pairs++;
          if (want != 0) strict++;
          // Clause 2 of `03-key-encoding.md` section 1: values the order calls
          // equal may still differ in their trailing numeric type code, so the
          // byte comparison is allowed to be non-zero there. Every other
          // disagreement is a defect.
          if (want == 0) {
            if (got != 0) {
              expect(a.runtimeType == b.runtimeType || _bothNumeric(a, b), isTrue,
                  reason: 'values compare equal but their keys differ, and they '
                      'are not two numerics differing only in type code:\n'
                      '  a = $a  CKE ${_hex(encodeKey(a))}\n'
                      '  b = $b  CKE ${_hex(encodeKey(b))}');
              _expectDiffersOnlyInTypeCode(a, b);
            }
            continue;
          }
          if (want != got) {
            fail('CKE order disagrees with section 8\n'
                '  a = $a  CKE ${_hex(encodeKey(a))}\n'
                '  b = $b  CKE ${_hex(encodeKey(b))}\n'
                '  compareValues says $want, memcmp says $got');
          }
        }
      }
      expect(pairs, greaterThan(20000));
      expect(strict, greaterThan(20000));
    });

    test('the cross-group order is the group tag order, rule 10', () {
      // Rule 10 says cross-type order "is the group order given in
      // 03-key-encoding.md section 2". That is checkable directly: the first
      // byte of a CKE key is its group tag.
      final keyable = corpus.where(isKeyEncodable).toList();
      for (final a in keyable) {
        for (final b in keyable) {
          final ga = encodeKey(a)[0], gb = encodeKey(b)[0];
          if (ga == gb) continue;
          expect(_sign(compareValues(a, b)), _sign(ga.compareTo(gb)),
              reason: 'cross-group order must follow the group tag: '
                  '$a (0x${ga.toRadixString(16)}) vs '
                  '$b (0x${gb.toRadixString(16)})');
        }
      }
    });
  });

  // ------------------------------------------------------------------
  // It has to be an order at all. A comparator that is not transitive makes
  // every sort in the engine undefined behaviour, and no round-trip test can
  // see it.
  // ------------------------------------------------------------------
  group('it is a total order', () {
    final all = [...corpus, ...unencodableButOrdered()];

    test('reflexive: compareValues(a, a) == 0', () {
      for (final a in all) {
        expect(compareValues(a, a), 0, reason: '$a is not equal to itself');
      }
    });

    test('antisymmetric: sign flips when the arguments do', () {
      for (final a in all) {
        for (final b in all) {
          expect(_sign(compareValues(a, b)), -_sign(compareValues(b, a)),
              reason: 'not antisymmetric: $a vs $b');
        }
      }
    });

    test('transitive over a sorted sweep', () {
      // A full O(n^3) sweep over ~200 values is 8M triples, which is slow for
      // no extra signal. Sorting and then asserting the sorted order is
      // consistent catches non-transitivity just as surely: a comparator that
      // is not transitive cannot produce a sequence that is pairwise ordered.
      final sorted = [...all]..sort(compareValues);
      for (var i = 0; i < sorted.length; i++) {
        for (var j = i + 1; j < sorted.length; j++) {
          expect(compareValues(sorted[i], sorted[j]), lessThanOrEqualTo(0),
              reason: 'sort produced a sequence that is not ordered:\n'
                  '  [$i] = ${sorted[i]}\n  [$j] = ${sorted[j]}');
        }
      }
    });
  });

  // ------------------------------------------------------------------
  // The ten rules, one test each. These are what an SDK author reads section 8
  // for, and each one is a divergence that has actually shipped somewhere.
  // ------------------------------------------------------------------
  group('section 8, rule by rule', () {
    test('1: NULL equals only NULL and sorts below everything', () {
      expect(compareValues(const CNull(), const CNull()), 0);
      for (final v in corpus) {
        if (v is CNull) continue;
        expect(compareValues(const CNull(), v), lessThan(0), reason: 'vs $v');
      }
    });

    test('2: every numeric tag is one domain, compared by exact value', () {
      expect(compareValues(CInt.i32(5), CInt.i64(5)), 0);
      expect(compareValues(CInt.i32(5), CFloat.f64(5.0)), 0);
      expect(compareValues(CInt.of(NumType.u8, 5), CFloat.f32(5.0)), 0);
      // The 2^53 neighbourhood: a fold through double would call these equal.
      final big = intOf(NumType.i64, BigInt.two.pow(53) + BigInt.one);
      expect(compareValues(big, CFloat.f64(9007199254740992.0)), greaterThan(0),
          reason: '2^53+1 is strictly above the double that 2^53+1 rounds to');
      // i128 against f64, which no 64-bit fold can do.
      // 2^100 is about 1.2677e30, so it straddles 1e30 and 1e31 -- which is
      // the point: no i64 or f64 fold can place it against both.
      final huge = intOf(NumType.i128, BigInt.two.pow(100));
      expect(compareValues(huge, CFloat.f64(1e30)), greaterThan(0));
      expect(compareValues(huge, CFloat.f64(1e31)), lessThan(0));
    });

    test('2: DEC128 is comparable in principle and refused in practice', () {
      final d = CDec128(Uint8List(16));
      expect(isOrdered(d), isTrue,
          reason: 'section 8 rule 2 puts DEC128 in the numeric domain');
      expect(isKeyEncodable(d), isFalse,
          reason: '03-key-encoding.md section 4.4: no key encoding');
      // The reference implementation declines rather than comparing wrongly.
      expect(() => compareValues(d, CInt.i32(1)),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('3: NaN equals NaN and sorts above every number', () {
      final nan = CFloat.f64(double.nan);
      expect(compareValues(nan, nan), 0, reason: 'a NaN key must be findable');
      expect(compareValues(nan, CFloat.f64(double.infinity)), greaterThan(0));
      expect(compareValues(nan, intOf(NumType.i128, BigInt.two.pow(127) - BigInt.one)),
          greaterThan(0));
      // Two different NaN payloads are one value.
      final other = CFloat.f64(bitsToF64(0x7FF8000000000001));
      expect(compareValues(nan, other), 0,
          reason: 'all NaNs are equal, so the key can be lossy about payload');
    });

    test('3: -0.0 equals +0.0', () {
      expect(compareValues(CFloat.f64(-0.0), CFloat.f64(0.0)), 0);
      expect(compareValues(CFloat.f64(-0.0), CInt.i32(0)), 0);
      expect(compareValues(CFloat.f32(-0.0), CFloat.f64(0.0)), 0);
    });

    test('4: STR compares by UTF-8 byte order, not by UTF-16 code unit', () {
      // The case that separates them. U+FF61 (HALFWIDTH IDEOGRAPHIC FULL STOP)
      // is one UTF-16 code unit, 0xFF61. U+10000 is a surrogate pair whose
      // first unit is 0xD800 -- lower in UTF-16, higher in code point and
      // therefore higher in UTF-8. A comparator using Dart's String.compareTo
      // gets this backwards.
      const a = CStr('｡');
      const b = CStr('\u{10000}');
      expect(compareValues(a, b), lessThan(0),
          reason: 'code-point order puts U+FF61 below U+10000');
      expect(a.value.compareTo(b.value), greaterThan(0),
          reason: "if this fails the test's premise is gone: Dart's own "
              'String.compareTo must disagree, or the case proves nothing');
      // And the plain prefix rule.
      expect(compareValues(const CStr('ab'), const CStr('abc')), lessThan(0));
      expect(compareValues(const CStr(''), const CStr('a')), lessThan(0));
    });

    test('4: no locale, no case folding, no normalization', () {
      // 'A' < 'a' by byte; a case-folding comparator calls them equal.
      expect(compareValues(const CStr('A'), const CStr('a')), lessThan(0));
      // NFC and NFD forms of the same grapheme are different values here.
      expect(compareValues(const CStr('é'), const CStr('é')),
          isNot(0),
          reason: 'section 8 rule 4 forbids normalization in the comparison');
    });

    test('5: BYTES is lexicographic, shorter-is-smaller on a prefix', () {
      expect(compareValues(CBytes(const [1, 2]), CBytes(const [1, 2, 0])),
          lessThan(0));
      expect(compareValues(CBytes(const []), CBytes(const [0])), lessThan(0));
      // Unsigned: 0xFF is above 0x01, not below it.
      expect(compareValues(CBytes(const [0xFF]), CBytes(const [0x01])),
          greaterThan(0));
    });

    test('6: CHAR is not a one-character STR', () {
      expect(compareValues(CChar(0x61), const CStr('a')), isNot(0),
          reason: 'rule 6: separate groups, never equal');
      expect(compareValues(CChar(0x41), CChar(0x61)), lessThan(0));
    });

    test('7: the three instant tags compare as one instant', () {
      expect(compareValues(const CTimestamp(1000), CTimestampNs(1, 0)), 0);
      expect(compareValues(const CTimestamp(1000), const CZoned(1000, 'UTC')), 0);
      expect(compareValues(const CZoned(1000, 'UTC'),
          const CZoned(1000, 'Asia/Kolkata')), 0,
          reason: 'ZONED denotes an instant; the zone is display, not order');
      expect(compareValues(CTimestampNs(1, 0), CTimestampNs(1, 1)), lessThan(0),
          reason: 'nanosecond resolution across the subclass');
    });

    test('7: DATE, TIME and DURATION are not comparable to instants', () {
      // They sort in their own groups: the order is total, but crossing a
      // subclass boundary is never a semantic comparison.
      final ts = const CTimestamp(0);
      for (final v in [const CDate(0), CTime(0), CDuration(0, 0)]) {
        expect(compareValues(ts, v), isNot(0), reason: 'vs $v');
        // and it is consistent in both directions
        expect(_sign(compareValues(ts, v)), -_sign(compareValues(v, ts)));
      }
    });

    test('8: ARRAY compares element-wise, then by length', () {
      expect(
          compareValues(CArray(const [CBool(false)]),
              CArray(const [CBool(true)])),
          lessThan(0));
      expect(
          compareValues(CArray(const [CBool(false)]),
              CArray(const [CBool(false), CBool(false)])),
          lessThan(0),
          reason: 'a prefix sorts first');
      expect(compareValues(CArray(const []), CArray(const [])), 0);
      // Element-wise beats length: [true] > [false, false].
      expect(
          compareValues(CArray(const [CBool(true)]),
              CArray(const [CBool(false), CBool(false)])),
          greaterThan(0));
    });

    test('8: DOC and MAP compare as their sorted (key, value) sequences', () {
      expect(compareValues(CDoc(const {'a': CBool(false)}),
              CDoc(const {'a': CBool(true)})),
          lessThan(0));
      // Field insertion order must not matter -- the sequence is sorted.
      expect(
          compareValues(CDoc(const {'a': CBool(false), 'b': CBool(true)}),
              CDoc(const {'b': CBool(true), 'a': CBool(false)})),
          0,
          reason: 'a DOC is its sorted field sequence, not its literal order');
      expect(compareValues(CMap(const []), CMap(const [])), 0);
      expect(
          compareValues(CMap(const [(CStr('a'), CBool(false))]),
              CMap(const [(CStr('b'), CBool(false))])),
          lessThan(0));
    });

    test('10: ARRAY < MAP < DOC, and that order is normative', () {
      // Rule 10's extension. Not a matter of taste: this is the assertion two
      // implementations failed in opposite directions, and it is unobservable
      // from any file because these ranks are never written down. Only a test
      // that names the order can hold the two implementations together.
      final arr = CArray(const []);
      final map = CMap(const []);
      final doc = CDoc(const {});
      expect(compareValues(arr, map), lessThan(0));
      expect(compareValues(map, doc), lessThan(0));
      expect(compareValues(arr, doc), lessThan(0));
      // and every one of them sits above every key group
      for (final v in [arr, map, doc]) {
        expect(compareValues(const CStr('zzz'), v), lessThan(0), reason: '$v');
      }
    });

    test('8: DOC and MAP are ordered but are not keys', () {
      for (final v in unencodableButOrdered()) {
        expect(isOrdered(v), isTrue, reason: '$v');
        expect(isKeyEncodable(v), isFalse,
            reason: '$v has no key encoding, so it cannot be an index key');
      }
    });

    test('9: FALSE < TRUE', () {
      expect(compareValues(const CBool(false), const CBool(true)), lessThan(0));
      expect(compareValues(const CBool(true), const CBool(true)), 0);
    });
  });

  // ------------------------------------------------------------------
  // The refusals. Section 8's last paragraph is a MUST-NOT and an
  // implementation that quietly returns 0 for two OPAQUE values makes them
  // indexable by accident.
  // ------------------------------------------------------------------
  group('unordered types are refused, not guessed at', () {
    final unordered = <CValue>[
      const CRegex('a', ''),
      CVector.f32(const [1.0]),
      CGeometry(Uint8List.fromList(const [1, 1, 0, 0, 0])),
      COpaque('java', 'java.lang.Object', const [1]),
    ];

    test('isOrdered says no', () {
      for (final v in unordered) {
        expect(isOrdered(v), isFalse, reason: '$v');
      }
    });

    test('compareValues throws, in either position', () {
      for (final v in unordered) {
        expect(() => compareValues(v, const CNull()),
            throwsA(isA<InvalidArgumentException>()),
            reason: '$v on the left');
        expect(() => compareValues(const CNull(), v),
            throwsA(isA<InvalidArgumentException>()),
            reason: '$v on the right');
      }
    });

    test('and they have no key encoding either', () {
      for (final v in unordered) {
        expect(isKeyEncodable(v), isFalse, reason: '$v');
      }
    });
  });

  // ------------------------------------------------------------------
  // compareNumeric on its own. It is exported, so it is API.
  // ------------------------------------------------------------------
  group('compareNumeric', () {
    test('agrees with compareValues on every numeric pair', () {
      final nums = <CValue>[...torturedIntegers(), ...torturedFloats()];
      for (final a in nums) {
        for (final b in nums) {
          expect(_sign(compareNumeric(a, b)), _sign(compareValues(a, b)),
              reason: '$a vs $b');
        }
      }
    });

    test('spans the whole i128/u128 range without a bignum fold', () {
      final i128max = intOf(NumType.i128, BigInt.two.pow(127) - BigInt.one);
      final u128max = intOf(NumType.u128, BigInt.two.pow(128) - BigInt.one);
      expect(compareNumeric(i128max, u128max), lessThan(0));
      expect(compareNumeric(u128max, CFloat.f64(double.infinity)), lessThan(0));
      expect(compareNumeric(intOf(NumType.i128, -BigInt.two.pow(127)),
              CFloat.f64(double.negativeInfinity)),
          greaterThan(0));
    });
  });
}

bool _bothNumeric(CValue a, CValue b) =>
    (a is CInt || a is CFloat) && (b is CInt || b is CFloat);

/// Clause 2 of `03-key-encoding.md` section 1: two values the order calls equal
/// encode to keys that differ only in the trailing numeric type code.
void _expectDiffersOnlyInTypeCode(CValue a, CValue b) {
  final ka = encodeKey(a), kb = encodeKey(b);
  expect(ka.length, kb.length, reason: 'equal values, different key lengths');
  expect(Uint8List.sublistView(ka, 0, ka.length - 1),
      Uint8List.sublistView(kb, 0, kb.length - 1),
      reason: 'equal values whose ordering regions differ: $a vs $b');
}

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0').toUpperCase()).join(' ');
