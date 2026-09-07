/// `spec/08-spatial.md` sections 1, 3 and 4, against the shared vector corpus.
///
/// Section 2.3 says what a spatial conformance test may compare: "two
/// implementations inserting the same documents will produce different (equally
/// valid) trees. A conformance test therefore compares **query results**, never
/// tree shape." So the corpus carries no tree — geometries, envelopes, the
/// pairwise predicate matrices and section 1's reject list, all properties of
/// the geometry rather than of anybody's R-tree.
///
/// Chapter 08 had **no shared vectors at all** before this, the same structural
/// gap `02-value-encoding.md` section 8 was in: the predicates are consumed in
/// memory, so three implementations can disagree about what `within` means and
/// every direction of the cross-language file gate still passes. They did
/// disagree — on 32 pairs — until section 4.1 defined the predicates as point
/// sets.
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

void main() {
  final path =
      '${Directory.current.path}/../../conformance/vectors/spatial/geometries.json';
  final file = File(path);
  if (!file.existsSync()) {
    test('the spatial corpus is present', () => fail('$path does not exist'));
    return;
  }
  final doc = jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
  final entries = (doc['geometries']! as List).cast<Map<String, Object?>>();
  final names = [for (final e in entries) e['name']! as String];
  final gs = [for (final e in entries) decodeWkb(unhex(e['wkb']! as String))];

  group('08 sections 1, 3 and 4 -- the spatial corpus', () {
    test('every published envelope is reproduced', () {
      for (var i = 0; i < gs.length; i++) {
        final want = (entries[i]['envelope']! as List)
            .map((e) => (e as num).toDouble())
            .toList();
        final e = gs[i].envelope();
        expect([e.min[0], e.min[1], e.max[0], e.max[1]], want,
            reason: 'envelope of ${names[i]}');
      }
    });

    /// Section 1: "EWKB MUST NOT be written and MUST be rejected on read",
    /// plus the rest of the reject list.
    test('every published reject is refused', () {
      for (final r in (doc['rejects']! as List).cast<Map<String, Object?>>()) {
        expect(() => decodeWkb(unhex(r['wkb']! as String)),
            throwsA(isA<CryptandException>()),
            reason: '${r['name']}: ${r['why']}');
      }
    });

    /// The negative control for the test above: a reader that refused
    /// everything would pass it and fail this.
    test('a big-endian geometry is accepted', () {
      final be = doc['accept_big_endian']! as Map<String, Object?>;
      final g = decodeWkb(unhex(be['wkb']! as String));
      final e = g.envelope();
      expect([e.min[0], e.min[1], e.max[0], e.max[1]],
          (be['envelope']! as List).map((x) => (x as num).toDouble()).toList());
    });

    bool predicate(String kind, Geometry a, Geometry b) => switch (kind) {
          'intersects' => Spatial.intersects(a, b),
          'contains' => Spatial.contains(a, b),
          _ => Spatial.within(a, b),
        };

    test('the predicate matrices match the published vectors', () {
      final m = doc['matrix'] as Map<String, Object?>?;
      expect(m, isNotNull, reason: 'no `matrix` in the vector');
      for (final kind in ['intersects', 'contains', 'within']) {
        final want = (m![kind]! as List).cast<String>();
        for (var i = 0; i < gs.length; i++) {
          final row = [
            for (final b in gs) predicate(kind, gs[i], b) ? '1' : '0'
          ].join();
          expect(row, want[i], reason: '$kind row $i (${names[i]})');
        }
      }
    });

    /// The matrix proves the three implementations agree; it cannot prove they
    /// are right, and here it could not have. Before section 4.1 was written
    /// the three disagreed on 32 of these pairs while each was internally
    /// consistent -- this one made containment non-reflexive for anything that
    /// was not a polygon.
    test('the named rules of section 4.1 hold', () {
      final rules = (doc['rules'] as List?)?.cast<Map<String, Object?>>();
      expect(rules, isNotNull, reason: 'no `rules` in the vector');
      expect(rules!.length, greaterThan(10));
      for (final r in rules) {
        final a = r['a']! as int;
        final b = r['b']! as int;
        final kind = r['predicate']! as String;
        expect(predicate(kind, gs[a], gs[b]), r['expect'],
            reason: 'section ${r['rule']} -- ${r['note']}\n'
                '  $kind(${names[a]}, ${names[b]})');
      }
    });
  });
}
