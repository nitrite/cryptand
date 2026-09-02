/// Prediction P8 — the aged scan.
///
/// `design/performance-model.md` §5.2 calls this "the load-bearing one", and
/// `adoption/rollout.md` calls clustered promotion "the highest-risk item".
/// The claim:
///
///   > "On a database aged by 10x its size in random updates, a full scan
///   >  returning whole documents costs <= 1.5x the same scan on a
///   >  freshly-loaded database, and `value_reads_per_scanned_row` stays below
///   >  0.3 — with clustered promotion, the locality-debt bound and readahead
///   >  in force; and >= 6x with all three disabled."
///
/// It is also `spec/11-conformance.md` §6's mandatory aged-scan test:
/// "load a dataset, scan it, apply 10x its size in random updates, then scan
/// again."
///
/// The measurement is **page reads**, not wall time, per
/// `design/performance-model.md` §8. Values are laid out over real pages and
/// read through a bounded LRU, so a clustered log hits the same page for
/// consecutive rows and a scattered one does not. A value log held in a flat
/// map would make the whole claim vacuously true.
library;

import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/value.dart';

import 'harness.dart';

/// Overridable, so `REPORT.md`'s outstanding item — "re-run the aged-scan test
/// at 10⁶ documents" — is one argument rather than an edit:
///
///     dart run bench/p8_aged_scan.dart 1000000
int kDocs = 20000;
const int kAgeMultiple = 10;

/// Deterministic, so a failure is reproducible.
class Lcg {
  Lcg(this.s);
  int s;
  int next() => s = (s * 6364136223846793005 + 1442695040888963407);
  int below(int n) => (next() >>> 1) % n;
}

({ScanResult fresh, ScanResult aged, int vlogSegments, double debt}) run(
    LocalityPolicy policy) {
  final dict = benchDict();
  final e = Engine(
    pageSize: 4096,
    vlogMin: 256,
    memtableEntries: 5000,
    policy: policy,
    cachePages: 256,
  );

  Uint8ListWriter doc(int i) {
    final w = ByteWriter();
    writeDoc(w, benchDoc(i), dict: dict);
    return w;
  }

  for (var i = 0; i < kDocs; i++) {
    e.put(17, CNitriteId(snowflakeId(i)), doc(i).takeBytes());
  }
  e.compact();
  final fresh = e.scanDocuments();

  // Age it: 10x the dataset in random updates, compacting as a real engine
  // would when the memtable fills.
  final rng = Lcg(0xA6ED);
  for (var round = 0; round < kAgeMultiple; round++) {
    for (var i = 0; i < kDocs; i++) {
      final target = rng.below(kDocs);
      e.put(17, CNitriteId(snowflakeId(target)), doc(target).takeBytes());
    }
    e.compact();
  }
  final aged = e.scanDocuments();

  return (
    fresh: fresh,
    aged: aged,
    vlogSegments: e.vlog.segments.length,
    debt: e.vlog.localityDebt
  );
}

typedef Uint8ListWriter = ByteWriter;

void report(String label, LocalityPolicy policy) {
  final r = run(policy);
  const w = [26, 10, 12, 14, 12, 10];
  print(row([
    label,
    '${r.fresh.rows}',
    '${r.fresh.totalPageReads}',
    '${r.aged.totalPageReads}',
    '${fmt(ratio(r.aged.totalPageReads, r.fresh.totalPageReads))}x',
    fmt(r.aged.valueReadsPerScannedRow, 3),
  ], w));
}

void main(List<String> args) {
  final positional = args.where((a) => !a.startsWith('--')).toList();
  if (positional.isNotEmpty) kDocs = int.parse(positional.first);
  // At 10^6 documents the three control configurations cost an hour each and
  // establish nothing the smaller runs have not; --only-on measures the row
  // the size claim is about.
  final onlyOn = args.contains('--only-on');
  print('# P8 -- aged scan over separated values');
  print('');
  print('$kDocs documents, then ${kAgeMultiple}x that many random updates.');
  print('Values are in the value log (vlog_min 256 B, desktop shape), laid out');
  print('over 4 KiB pages and read through a 256-page LRU.');
  print('');
  const w = [26, 10, 12, 14, 12, 10];
  print(row(
      ['mechanisms', 'rows', 'fresh pages', 'aged pages', 'aged/fresh', 'v/row'],
      w));
  print(row(['---', '---', '---', '---', '---', '---'], w));

  report('all three on', const LocalityPolicy());
  if (onlyOn) return;
  report('no readahead', const LocalityPolicy(readahead: false));
  report('no promotion',
      const LocalityPolicy(clusteredPromotion: false));
  report('none (P8 floor case)', LocalityPolicy.none);

  print('');
  final on = run(const LocalityPolicy());
  final off = run(LocalityPolicy.none);
  final onRatio = ratio(on.aged.totalPageReads, on.fresh.totalPageReads);
  final offRatio = ratio(off.aged.totalPageReads, off.fresh.totalPageReads);
  print('P8 predicts: aged/fresh <= 1.5x and v/row < 0.3 with the mechanisms');
  print('             on, and >= 6x with them off.');
  print('');
  print('  with:    ${fmt(onRatio)}x, v/row ${fmt(on.aged.valueReadsPerScannedRow, 3)}, '
      'locality debt ${fmt(on.debt * 100, 1)}%');
  print('  without: ${fmt(offRatio)}x, v/row ${fmt(off.aged.valueReadsPerScannedRow, 3)}, '
      'locality debt ${fmt(off.debt * 100, 1)}%');
  print('  ratio between them: ${fmt(offRatio / onRatio)}x');
}
