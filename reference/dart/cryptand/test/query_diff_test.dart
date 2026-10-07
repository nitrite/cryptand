// M1.5 query differential: an index scan built from 06-indexes.md section 7's
// helpers against a brute-force model using 02-value-encoding.md section 8's
// logical order. QUERY_SEEDS=N for a sweep.

import 'dart:io';
import 'dart:math';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

const _widths = [
  NumType.i8,
  NumType.i32,
  NumType.i64,
  NumType.u64,
  NumType.f64,
  NumType.f32
];
const _words = ['', 'a', 'ab', 'abc', 'b', 'ba'];

CValue _scalar(Random r) {
  final k = r.nextInt(10);
  if (k == 0) return const CNull();
  if (k == 1) return CBool(r.nextBool());
  if (k < 4) return CStr(_words[r.nextInt(6)]);
  final n = r.nextInt(11) - 3; // small, so values collide across types
  final w = _widths[r.nextInt(6)];
  if (w == NumType.u64) return CInt.of(w, n.abs());
  if (w == NumType.f64 || w == NumType.f32) {
    return CFloat(w, n + (r.nextInt(3) == 0 ? 0.5 : 0.0));
  }
  return CInt.of(w, n);
}

bool _numeric(CValue v) => v is CInt || v is CFloat;

void _runSeed(int seed) {
  final r = Random(seed);
  final c = Database().createCollection('q');
  final idx = c.createIndex(['v']);
  final live = <int, CDoc>{};
  var next = 1;
  for (var i = 20 + r.nextInt(60); i > 0; i--) {
    final k = r.nextInt(8);
    final d = CDoc({
      if (k == 1)
        'v': CArray([for (var j = r.nextInt(4); j > 0; j--) _scalar(r)]),
      if (k > 1) 'v': _scalar(r),
    });
    c.put(CNitriteId(next), d);
    live[next++] = d;
    if (r.nextInt(6) == 0) {
      final gone = live.keys.elementAt(r.nextInt(live.length));
      c.remove(CNitriteId(gone));
      live.remove(gone);
    }
  }
  for (var q = 0; q < 40; q++) {
    final b = _scalar(r);
    final k = r.nextInt(7);
    final String label;
    final KeyRange scan;
    final bool Function(CValue) pred;
    if (k == 0 && b is CStr) {
      label = 'starts_with "${b.value}"';
      scan = IndexScan.startsWith([], b.value);
      pred = (x) => x is CStr && x.value.startsWith(b.value);
    } else if (k <= 1) {
      label = 'eq $b';
      scan = _numeric(b)
          ? IndexScan.eqPrefixNumeric([b])
          : IndexScan.eqPrefix([b]);
      pred = (x) => compareValues(x, b) == 0;
    } else {
      final op = (k - 2) % 4; // gt, ge, lt, le
      label = '${['gt', 'ge', 'lt', 'le'][op]} $b';
      scan = op < 2
          ? IndexScan.range([], lower: b, lowerInclusive: op == 1)
          : IndexScan.range([], upper: b, upperInclusive: op == 3);
      pred = (x) {
        final o = compareValues(x, b);
        return [o > 0, o >= 0, o < 0, o <= 0][op];
      };
    }
    final got = (c
        .lookup(idx, scan)
        .map((v) => (v as CNitriteId).id)
        .toSet()
        .toList())
      ..sort();
    final want = [
      for (final e in live.entries)
        if ((resolvePath(e.value, 'v') ?? [const CNull()]).any(pred)) e.key
    ];
    expect(got, want, reason: 'seed $seed query $q: $label');
  }
}

void main() {
  test('an index scan answers what a full scan answers', () {
    final n = int.tryParse(Platform.environment['QUERY_SEEDS'] ?? '') ?? 50;
    for (var seed = 0; seed < n; seed++) {
      _runSeed(seed);
    }
  });
}
