/// What it costs to build a full-text vocabulary, as a function of its size.
///
/// `_internTerm` allocated the next `term_id` as
/// `_e.scanTree(revId).length + 1` — a full scan of the reverse term index for
/// **every new term** — so the cost of adding the V-th term was O(V) and
/// building a vocabulary of V terms was O(V^2). The Java implementation has
/// always held a `nextTermId` counter.
///
/// The row that matters is `ratio`: a held counter is O(1) per term, so the
/// per-term cost must not grow with the vocabulary. A derived one doubles when
/// the vocabulary doubles.
///
///   dart run bench/term_intern.dart
library;

import 'package:cryptand/cryptand.dart';

void main(List<String> args) {
  print('# vocabulary build, section 07 full text.');
  print('# `us_per_term` is an observation; the SHAPE of the column is the '
      'result.');
  print('${'terms'.padLeft(8)} | ${'total ms'.padLeft(10)} | '
      '${'us per term'.padLeft(12)} | ${'vs previous'.padLeft(11)}');
  print('-' * 52);

  double? previous;
  for (final n in [500, 1000, 2000, 4000]) {
    {
      final db = Database();
      final c = db.createCollection('docs');
      c.createFullTextIndex(['body']);
      final sw = Stopwatch()..start();
      // One document per term, each introducing exactly one new term, so the
      // vocabulary grows by one per insert and nothing else varies.
      for (var i = 0; i < n; i++) {
        c.put(CNitriteId(i), CDoc({'body': CStr('zzterm$i')}));
      }
      sw.stop();
      final us = sw.elapsedMicroseconds / n;
      final ratio = previous == null ? '' : '${(us / previous).toStringAsFixed(2)}x';
      print('${n.toString().padLeft(8)} | '
          '${(sw.elapsedMicroseconds / 1000).toStringAsFixed(1).padLeft(10)} | '
          '${us.toStringAsFixed(1).padLeft(12)} | ${ratio.padLeft(11)}');
      previous = us;
    }
  }
  print('\nA held counter keeps `us per term` flat and `vs previous` near '
      '1.00x.\nA derived one grows with the vocabulary.');
}
