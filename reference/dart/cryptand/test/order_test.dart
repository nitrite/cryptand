/// `spec/02-value-encoding.md` section 8 — equality and comparison, against the
/// shared vector corpus.
///
/// Section 8 opens "defined here once, for all SDKs, ending the current
/// divergence", and then records that a divergence survived inside it — two
/// implementations filled a hole in **opposite** directions — "and no test
/// could see it because nothing tested this section at all".
///
/// The cross-language round-trip gate cannot see this section either, and not
/// by oversight: section 8's order is consumed **in memory**. Three
/// implementations can disagree completely about how values sort and every
/// direction of the file gate still passes, because the bytes never differ.
///
/// What is checked is a **matrix**, not a sorted permutation. Section 8 makes
/// many of these values equal — every numeric tag holding 5 is one value, a
/// TIMESTAMP of 1000 ms equals a TIMESTAMP_NS of (1 s, 0), -0.0 equals +0.0 —
/// and equal elements have no defined relative position in an unstable sort. A
/// permutation would encode the sort algorithm; the matrix encodes the order.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

Uint8List unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

CValue build(Map<String, Object?> d) {
  switch (d['t'] as String) {
    case 'null':
      return const CNull();
    case 'bool':
      return CBool(d['v']! as bool);
    case 'int':
      final w = NumType.values.firstWhere((t) => t.name == d['w']);
      final s = d['v']! as String;
      final neg = s.startsWith('-');
      return CInt(
          w, neg, U128.fromBigInt(BigInt.parse(neg ? s.substring(1) : s)));
    case 'float':
      final bits = unhex(d['bits']! as String);
      final bd = ByteData.view(bits.buffer);
      return d['w'] == 'f64'
          ? CFloat(NumType.f64, bd.getFloat64(0))
          : CFloat(NumType.f32, bd.getFloat32(0));
    case 'str':
      return CStr(const Utf8Decoder().convert(unhex(d['utf8']! as String)));
    case 'bytes':
      return CBytes(unhex(d['v']! as String));
    case 'char':
      return CChar(d['v']! as int);
    case 'timestamp':
      return CTimestamp(d['millis']! as int);
    case 'timestamp_ns':
      return CTimestampNs(d['secs']! as int, d['nanos']! as int);
    case 'zoned':
      return CZoned(d['millis']! as int, d['zone']! as String);
    case 'date':
      return CDate(d['days']! as int);
    case 'time':
      return CTime(d['nanos']! as int);
    case 'duration':
      return CDuration(d['secs']! as int, d['nanos']! as int);
    case 'uuid':
      return CUuid(unhex(d['v']! as String));
    case 'nitrite_id':
      return CNitriteId(int.parse(d['v']! as String));
    case 'array':
      return CArray([
        for (final x in d['items']! as List) build(x as Map<String, Object?>)
      ]);
    case 'map':
      return CMap([
        for (final e in d['entries']! as List)
          (
            build((e as Map<String, Object?>)['k']! as Map<String, Object?>),
            build(e['v']! as Map<String, Object?>)
          )
      ]);
    case 'doc':
      return CDoc({
        for (final e in (d['fields']! as Map<String, Object?>).entries)
          e.key: build(e.value! as Map<String, Object?>)
      });
    default:
      throw ArgumentError('unhandled vector value type: ${d['t']}');
  }
}

String sign(int c) => c < 0 ? '-' : (c == 0 ? '0' : '+');

void main() {
  final path =
      '${Directory.current.path}/../../conformance/vectors/order/values.json';
  final file = File(path);
  if (!file.existsSync()) {
    test('the order corpus is present', () => fail('$path does not exist'));
    return;
  }
  final doc = jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
  final entries = (doc['entries']! as List).cast<Map<String, Object?>>();
  final values = [
    for (final e in entries) build(e['value']! as Map<String, Object?>)
  ];
  final notes = [for (final e in entries) (e['note'] ?? '') as String];

  group('02 section 8 -- equality and comparison', () {
    test('the shared order corpus matches the published matrix', () {
      final want = (doc['matrix'] as List?)?.cast<String>();
      expect(want, isNotNull,
          reason: 'order/values.json carries no `matrix` -- regenerate it');
      expect(want!.length, values.length);
      for (var i = 0; i < values.length; i++) {
        final row = [
          for (final b in values) sign(compareValues(values[i], b))
        ].join();
        expect(row, want[i],
            reason: 'row $i of the order matrix differs (${notes[i]})');
      }
    });

    test('the order is a total order over the corpus', () {
      final n = values.length;
      final s = [
        for (final a in values)
          [for (final b in values) compareValues(a, b).sign]
      ];
      for (var i = 0; i < n; i++) {
        expect(s[i][i], 0, reason: 'value $i (${notes[i]}) != itself');
        for (var j = 0; j < n; j++) {
          expect(s[i][j], -s[j][i],
              reason: 'antisymmetry fails for $i (${notes[i]}) '
                  'and $j (${notes[j]})');
        }
      }
      // Transitivity over every triple -- the property a comparator built out
      // of per-type special cases is most likely to violate.
      for (var i = 0; i < n; i++) {
        for (var j = 0; j < n; j++) {
          if (s[i][j] > 0) continue;
          for (var k = 0; k < n; k++) {
            if (s[j][k] <= 0) {
              expect(s[i][k] <= 0, isTrue,
                  reason: 'transitivity fails: $i <= $j <= $k but $i > $k\n'
                      '  ${notes[i]}\n  ${notes[j]}\n  ${notes[k]}');
            }
          }
        }
      }
    });

    /// The matrix proves the three implementations agree. It cannot prove they
    /// are right: all three produced an identical matrix while all three
    /// compared MAP entries in *stored* rather than sorted order, which rule 8
    /// forbids in the same sentence that covers DOC. Agreement is not
    /// conformance, and these rules are the half that reads the spec rather
    /// than the neighbours.
    test('the named rules of section 8 hold', () {
      final rules = (doc['rules'] as List?)?.cast<Map<String, Object?>>();
      expect(rules, isNotNull,
          reason: 'order/values.json carries no `rules`');
      expect(rules!.length, greaterThan(100),
          reason: 'the rule set is suspiciously small');
      for (final r in rules) {
        final a = r['a']! as int;
        final b = r['b']! as int;
        expect(sign(compareValues(values[a], values[b])), r['expect'],
            reason: 'section 8 rule ${r['rule']} -- ${r['note']}\n'
                '  a[$a] = ${notes[a]}\n  b[$b] = ${notes[b]}');
      }
    });
  });
}
