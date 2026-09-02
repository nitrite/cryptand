/// **P10 — the bounded read tail.**
///
/// `design/performance-model.md` §5.4: "`segments_probed_per_lookup` p99 ≤ 2
/// and p99.9 ≤ 3, at every database size. *Measure:* the required metric of
/// `spec/13-operations.md` §6 under a uniform-random point-read load. This
/// validates range-partitioned tiers and the per-level filter allocation; if it
/// fails, one of the two is not being implemented."
///
/// So both are measured, and both are measured *against their absence*: the
/// same database is built with range partitioning off (plain tiering, §3.1's
/// "plain tiering lets all `tier_width` segments at a level overlap a key") and
/// with the filter off (`filter_page = 0`, which §2.4 says a reader must treat
/// as "every probe is a hit"). A bound that is not falsifiable by turning off
/// the mechanism that produces it has not been measured.
///
/// **The write load is the part that has to be right.** A first version of
/// this benchmark inserted keys in ascending order and reported p99 = 1 for
/// every shape, controls included — because sequential inserts make every
/// memtable flush cover a *disjoint* key range, so manifest pruning alone
/// leaves one candidate and there is no read tail to bound. A measurement
/// whose control cannot fail has measured nothing. Keys are therefore written
/// in random order and then updated, which is what makes segments at different
/// levels overlap. Calling `compact()` would likewise flatten everything into
/// the disjoint last level and make the claim vacuously true.
library;

import 'dart:math';

import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/value.dart';

import 'harness.dart';

typedef Shape = ({
  int docs,
  int probes,
  int p50,
  int p99,
  int p999,
  int max,
  double mean,
  String levels,
  double fpr,
});

Shape run(int docs,
    {required LevelPolicy levels,
    required bool filters,
    bool earlyExit = true}) {
  final dict = benchDict();
  final e = Engine(
    memtableEntries: 2000,
    levels: levels,
    filters: filters,
    earlyExit: earlyExit,
    // Documents inline: this benchmark is about the key index, and a value-log
    // read would add a page fetch that has nothing to do with the read tail.
    vlogMin: 1024,
  );
  // Random insertion order: every memtable spans the whole key space, so the
  // L0 segments it flushes overlap each other and every level below.
  final order = [for (var i = 0; i < docs; i++) i]..shuffle(Random(7));
  for (final i in order) {
    e.put(benchTree, CNitriteId(snowflakeId(i)),
        encodeValue(benchDoc(i), dict: dict));
  }
  // Updates put newer versions of already-settled keys into the upper levels,
  // which is what a candidate list longer than one is made of.
  final rw = Random(11);
  for (var i = 0; i < docs ~/ 2; i++) {
    final k = rw.nextInt(docs);
    e.put(benchTree, CNitriteId(snowflakeId(k)),
        encodeValue(benchDoc(k), dict: dict));
  }
  e.flush();
  // Let the level policy settle. This is NOT `compact()` -- that would flatten
  // everything into the disjoint last level and make the claim vacuous. It is
  // the background cascade a real engine runs on its own; since phase 9 a
  // `flush` only does `compaction_step_bytes` of it on the caller's thread
  // (spec/04-segments.md section 5.2), so a benchmark that wants the settled
  // shape has to ask for it.
  e.drainCompaction();

  final shape = StringBuffer();
  for (var l = 0; l <= e.lastLevel; l++) {
    final refs = e.refsAt(l);
    if (refs.isEmpty) continue;
    shape.write('L$l:${refs.length}s/${e.groupsAt(l).length}g ');
  }

  e.resetCounters();
  final rnd = Random(20260902);
  const probes = 20000;
  for (var i = 0; i < probes; i++) {
    e.get(benchTree, CNitriteId(snowflakeId(rnd.nextInt(docs))));
  }

  final s = e.segmentsProbed;
  return (
    docs: docs,
    probes: probes,
    p50: percentile(s, 0.50),
    p99: percentile(s, 0.99),
    p999: percentile(s, 0.999),
    max: s.reduce(max),
    mean: s.reduce((a, b) => a + b) / s.length,
    levels: shape.toString().trim(),
    fpr: e.filterAdmitted == 0
        ? 0
        : e.filterFalsePositives / e.filterAdmitted,
  );
}

String row(String label, Shape r) =>
    '| ${label.padRight(26)} | ${r.docs.toString().padRight(8)} '
    '| ${r.p50.toString().padRight(4)} | ${r.p99.toString().padRight(4)} '
    '| ${r.p999.toString().padRight(5)} | ${r.max.toString().padRight(4)} '
    '| ${r.mean.toStringAsFixed(2).padRight(5)} | ${r.levels} |';

void main() {
  const header = '| shape                      | docs     | p50  | p99  '
      '| p99.9 | max  | mean  | levels |\n'
      '| ---                        | ---      | ---  | ---  '
      '| ---   | ---  | ---   | --- |';

  print('# P10 -- the bounded read tail\n');
  print('20 000 uniform-random point reads over existing keys, after an');
  print('ordinary write load (no forced full compaction). The metric is');
  print('`segments_probed_per_lookup`: segments that survived manifest');
  print('key-range pruning AND the filter, i.e. that were descended into.\n');
  print(header);

  const desktop = LevelPolicy.desktop;
  final sizes = [10000, 25000, 50000, 100000, 200000];
  final results = <int, Shape>{};
  for (final n in sizes) {
    final r = run(n, levels: desktop, filters: true);
    results[n] = r;
    print(row('range-partitioned', r));
  }
  print('');

  // The controls have to run at a size whose *shape* exercises the mechanism.
  // A tiered level that happens to hold one run cannot show what range
  // partitioning buys, and reporting the control there would be the same
  // mistake as the ascending-insert order this benchmark started with.
  for (final n in [sizes.first, sizes.last]) {
    final groups = results[n]!.levels;
    print('Controls, at $n documents (shape $groups):\n');
    print(header);
    print(row('range-partitioned', results[n]!));
    print(row('no filter', run(n, levels: desktop, filters: false)));
    print(row('plain tiering',
        run(n, levels: desktop.plainTiered, filters: true)));
    print(row('neither',
        run(n, levels: desktop.plainTiered, filters: false)));
    print(row('plain tiering, no early exit',
        run(n,
            levels: desktop.plainTiered,
            filters: true,
            earlyExit: false)));
    print('');
  }

  print('Without the §4 early exit -- every candidate examined, the winner');
  print('chosen by its own seq. This is what §4 requires absent a level-');
  print('discipline proof, and it is NOT what P10 arithmetic counts:\n');
  print(header);
  for (final n in sizes) {
    print(row('no early exit',
        run(n, levels: desktop, filters: true, earlyExit: false)));
  }
  print('');

  print('The §4.1 candidate bound for this shape '
      '(l0_trigger + overlap_bound x (level_count - 2) + 1) is '
      '${desktop.candidateBound}.');
  print('Filter false-positive rate over admitted probes: '
      '${(results[sizes.last]!.fpr * 100).toStringAsFixed(3)}% '
      '(§2.4 predicts ~0.33% above the last level, ~1.7% at it).');
  print('');
  print('P10 predicts p99 <= 2 and p99.9 <= 3 at every size.');
  for (final n in sizes) {
    final r = results[n]!;
    final ok = r.p99 <= 2 && r.p999 <= 3;
    print('  $n docs: p99 ${r.p99}, p99.9 ${r.p999} -- '
        '${ok ? "CONFIRMED" : "FAILED"}');
  }
}
