/// Planner statistics — `spec/13-operations.md` §9.
///
/// `spec/06-indexes.md` §7.1 is what these are *for*: Nitrite's `FindPlan`
/// today picks an index from static descriptor properties — whether it is
/// unique, and how many fields it covers — which "routinely picks a unique
/// index on a field the query barely constrains over a non-unique index that
/// would eliminate 99 % of the collection."
///
/// **They are advisory.** §9: "They may be stale or absent; a planner MUST
/// produce correct results without them, and MUST NOT refuse to run because
/// they are missing." Nothing in this file may ever be on a correctness path.
///
/// Both estimators are computed during the last-level compaction that produced
/// the segment, which "already touches every key" — so they are free in the
/// sense that matters: no extra pass over the data.
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'cke.dart';
import 'cve.dart';
import 'filter.dart';
import 'value.dart';

/// A HyperLogLog sketch for `distinct_estimate`, §9.
///
/// Chosen for the property that makes it usable here: it is **mergeable and
/// fixed-size**, so a compaction accumulates it in a few hundred bytes while
/// streaming, and two segments' sketches combine without revisiting either.
/// An exact distinct count would need memory proportional to cardinality,
/// which is the thing a compaction cannot afford.
final class HyperLogLog {
  HyperLogLog({this.precision = 12})
      : _m = 1 << precision,
        _registers = Uint8List(1 << precision);

  /// 2^precision registers. 12 gives 4096 registers and ~1.6 % standard error,
  /// which is far finer than any planner decision needs.
  final int precision;
  final int _m;
  final Uint8List _registers;

  void add(List<int> key) {
    final h = cfh64(key);
    // The low `precision` bits select the register; the rest supply the run.
    final idx = h & (_m - 1);
    final w = h >>> precision;
    final rank = w == 0 ? (64 - precision + 1) : (_leadingZeros(w) + 1);
    if (rank > _registers[idx]) _registers[idx] = rank;
  }

  int _leadingZeros(int w) {
    // Counting within the (64 - precision)-bit remainder.
    var n = 0;
    final bits = 64 - precision;
    for (var i = bits - 1; i >= 0; i--) {
      if ((w >>> i) & 1 == 1) break;
      n++;
    }
    return n;
  }

  /// Merges [other] in place. Two segments' sketches combine by taking the
  /// register-wise maximum, which is why this works at all.
  void merge(HyperLogLog other) {
    if (other.precision != precision) {
      throw ArgumentError('cannot merge sketches of different precision');
    }
    for (var i = 0; i < _m; i++) {
      if (other._registers[i] > _registers[i]) {
        _registers[i] = other._registers[i];
      }
    }
  }

  int get estimate {
    var sum = 0.0;
    var zeros = 0;
    for (var i = 0; i < _m; i++) {
      sum += 1.0 / (1 << _registers[i]);
      if (_registers[i] == 0) zeros++;
    }
    final alpha = switch (_m) {
      16 => 0.673,
      32 => 0.697,
      64 => 0.709,
      _ => 0.7213 / (1 + 1.079 / _m),
    };
    var e = alpha * _m * _m / sum;
    // Small-range correction: with empty registers, linear counting is much
    // more accurate than the raw estimator.
    if (e <= 2.5 * _m && zeros > 0) {
      e = _m * math.log(_m / zeros);
    }
    return e.round();
  }

  Uint8List get registers => Uint8List.fromList(_registers);
}

/// One equi-depth histogram bucket, §9.
final class HistogramBucket {
  const HistogramBucket(this.bound, this.cumulative);

  /// A CKE key, "so a planner can compare them without decoding".
  final Uint8List bound;
  final int cumulative;
}

/// `params.stats`, §9.
final class IndexStats {
  const IndexStats({
    required this.updatedSeq,
    required this.entries,
    required this.distinctEstimate,
    required this.nullCount,
    required this.minKey,
    required this.maxKey,
    required this.histogram,
  });

  final int updatedSeq;
  final int entries;
  final int distinctEstimate;
  final int nullCount;
  final Uint8List minKey;
  final Uint8List maxKey;

  /// Equi-depth, at most 64 buckets, §9.
  final List<HistogramBucket> histogram;

  /// Rows a planner should expect from an equality probe.
  ///
  /// Advisory: with no statistics a planner assumes nothing and scans, which
  /// is correct but slow — never wrong.
  double get averageRowsPerValue =>
      distinctEstimate == 0 ? entries.toDouble() : entries / distinctEstimate;

  /// Fraction of the index an equality probe is expected to touch. Lower is
  /// more selective, and this is the number `06` §7.1 says the planner should
  /// choose an index on — rather than on whether it happens to be unique.
  double get selectivity =>
      entries == 0 ? 1 : averageRowsPerValue / entries;

  /// Estimated rows at or below [key], from the histogram. Advisory.
  int rowsAtOrBelow(Uint8List key) {
    var cum = 0;
    for (final b in histogram) {
      if (compareKeys(key, b.bound) < 0) break;
      cum = b.cumulative;
    }
    return cum;
  }

  CDoc toDoc() => CDoc({
        'updated_seq': CInt.of(NumType.u64, updatedSeq),
        'entries': CInt.of(NumType.u64, entries),
        'distinct_estimate': CInt.of(NumType.u64, distinctEstimate),
        'null_count': CInt.of(NumType.u64, nullCount),
        'min_key': CBytes(minKey),
        'max_key': CBytes(maxKey),
        'histogram': CArray([
          for (final b in histogram)
            CDoc({
              'bound': CBytes(b.bound),
              'cumulative': CInt.of(NumType.u64, b.cumulative),
            })
        ]),
      });

  static IndexStats fromDoc(CDoc d) {
    int u(String f) => ((d[f]! as CInt).magnitude).lo;
    return IndexStats(
      updatedSeq: u('updated_seq'),
      entries: u('entries'),
      distinctEstimate: u('distinct_estimate'),
      nullCount: u('null_count'),
      minKey: (d['min_key']! as CBytes).value,
      maxKey: (d['max_key']! as CBytes).value,
      histogram: [
        for (final b in (d['histogram']! as CArray).items)
          HistogramBucket(
            ((b as CDoc)['bound']! as CBytes).value,
            ((b['cumulative']!) as CInt).magnitude.lo,
          )
      ],
    );
  }

  Uint8List encode() => encodeValue(toDoc());
}

/// Accumulates [IndexStats] over a key-ordered stream.
///
/// Fed by the last-level compaction, which already walks every key in order —
/// which is what makes the histogram equi-depth for free: the stream is
/// already sorted, so a bucket boundary is just a counter reaching a quota.
final class StatsBuilder {
  StatsBuilder({this.maxBuckets = 64, this.byteBudget = 3072, int precision = 12})
      : _hll = HyperLogLog(precision: precision);

  /// §9: "at most 64 buckets".
  final int maxBuckets;

  /// The encoded size the whole `params.stats` document must fit in.
  ///
  /// **§9 bounds the histogram in the wrong dimension.** It caps the bucket
  /// *count* at 64 and says the bounds are CKE keys — but a CKE key runs to
  /// kilobytes (`00-conventions.md` §8), and `params.stats` lives inside a
  /// catalog descriptor, which is **one cell of a copy-on-write B+tree**
  /// (`04-segments.md` §3.3) and must therefore fit one page. 64 bounds over
  /// 300 string keys measured 4734 B against a 4096 B page: the descriptor
  /// simply could not be written.
  ///
  /// A count bound cannot fix that, because the bound length is the free
  /// variable. So the builder honours a byte budget as well and halves the
  /// bucket count until the encoding fits, which is safe precisely because
  /// statistics are advisory: fewer buckets is a coarser estimate, never a
  /// wrong answer.
  final int byteBudget;
  final HyperLogLog _hll;

  final List<HistogramBucket> _buckets = [];
  Uint8List? _minKey;
  Uint8List? _maxKey;
  int _entries = 0;
  int _nulls = 0;
  int _maxSeq = 0;

  /// [indexedPrefix] is the key without the trailing document id, so
  /// `distinct_estimate` counts distinct *values* rather than distinct entries.
  void add(Uint8List indexedPrefix, Uint8List fullKey,
      {required int seq, required bool isNull}) {
    _entries++;
    if (isNull) _nulls++;
    if (seq > _maxSeq) _maxSeq = seq;
    _minKey ??= Uint8List.fromList(fullKey);
    _maxKey = Uint8List.fromList(fullKey);
    _hll.add(indexedPrefix);
  }

  IndexStats build() {
    var buckets = _buckets;
    var stats = _with(buckets);
    // Halve until it fits. Dropping every other bucket keeps the histogram
    // equi-depth — the surviving bounds still partition the stream evenly,
    // just at twice the width.
    while (buckets.length > 1 && stats.encode().length > byteBudget) {
      buckets = [
        for (var i = 1; i < buckets.length; i += 2) buckets[i]
      ];
      stats = _with(buckets);
    }
    if (stats.encode().length > byteBudget) stats = _with(const []);
    return stats;
  }

  IndexStats _with(List<HistogramBucket> buckets) => IndexStats(
        updatedSeq: _maxSeq,
        entries: _entries,
        distinctEstimate: _hll.estimate,
        nullCount: _nulls,
        minKey: _minKey ?? Uint8List(0),
        maxKey: _maxKey ?? Uint8List(0),
        histogram: buckets,
      );

  /// Records a histogram boundary. The caller feeds keys in order and calls
  /// this at each quota; keeping it explicit means the builder never has to
  /// buffer the stream it is summarizing.
  void boundary(Uint8List key) {
    if (_buckets.length >= maxBuckets) return;
    _buckets.add(HistogramBucket(Uint8List.fromList(key), _entries));
  }

  int get entries => _entries;
}
