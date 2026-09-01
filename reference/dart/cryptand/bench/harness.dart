/// Benchmark harness shared by every file in `bench/`.
///
/// Rules taken from `design/performance-model.md` section 8, which are taken
/// in turn from this project's own history of flaky timing guards:
///
///   * "Never assert on a wall-clock ratio in CI. Performance assertions go on
///     plan shape or a store counter (page reads, bytes written); wall time is
///     recorded and charted, not gated."
///   * A short run measures the memtable, not the engine.
///
/// So every benchmark below reports a **counter** as its primary result and
/// wall time as an observation, clearly labelled.
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

const int benchTree = 17;

/// Snowflake-shaped ids: a long shared prefix, as
/// `design/performance-model.md` section 1 assumes ("id | snowflake i64 --
/// ids share a long common prefix").
int snowflakeId(int i) => 1767225600000 * 4194304 + i * 4096 + 1;

/// The document shape `design/performance-model.md` section 1 assumes:
///
///   > "document shape | 20 fields, names averaging 12 B, values averaging
///   >  20 B"
///
/// giving a 516 B logical record (16 B key + 500 B value). It is built to that
/// shape deliberately rather than picked for looks: every density and decode
/// number in section 6 is costed against it, so a smaller document would
/// flatter the name dictionary and understate decode work, and a larger one
/// would do the reverse. `tool/shape.dart` prints the realized averages.
CDoc benchDoc(int i) {
  final pad = i.toString().padLeft(6, '0');
  // 12-character field names, as assumed.
  String v(String prefix) => '$prefix-$pad-x'.padRight(19, 'y'); // 19 chars -> 21 B encoded
  return CDoc({
    '_id': CNitriteId(snowflakeId(i)),
    'custAddr1_ln': CStr(v('addr1')),
    'custAddr2_ln': CStr(v('addr2')),
    'custCityName': CStr(v('city')),
    'custPostCode': CStr(v('post')),
    'custCountryX': CStr(v('ctry')),
    'custEmailAdr': CStr(v('mail')),
    'custPhoneNum': CStr(v('phon')),
    'ordReference': CStr(v('ordr')),
    'ordStatusTxt': CStr(v('stat')),
    'ordCurrencyC': CStr(v('curr')),
    'ordNotesText': CStr(v('note')),
    'whseLocation': CStr(v('whse')),
    'carrierName_': CStr(v('carr')),
    'trackingNumb': CStr(v('trak')),
    'ordTotMinorU': CInt.varInt(1299 + i),
    'ordTaxMinorU': CInt.varInt(216),
    'ordShipMinor': CInt.varInt(499),
    'placedAtUtcM': const CTimestamp(1767225000000),
    'dispatchUtcM': const CTimestamp(1767225600000),
  });
}

NameDict benchDict() {
  final d = NameDict.withReservedFields();
  for (final k in benchDoc(0).fields.keys) {
    d.intern(k);
  }
  return d;
}

/// Builds a data segment of [n] documents.
///
/// [inlineValues] models the `mobile` profile, where `vlog_min` is at its
/// ceiling and documents stay in the leaf. When false the leaf holds a
/// 16-byte value-log pointer instead, which is the `desktop` shape.
({Segment segment, int logicalBytes, int valueBytes}) buildDataSegment(
  int n, {
  int pageSize = 4096,
  bool inlineValues = true,
}) {
  final dict = benchDict();
  final b = SegmentBuilder(pageSize: pageSize, segmentId: 1, treeId: benchTree);
  var logical = 0;
  var valueTotal = 0;
  for (var i = 0; i < n; i++) {
    final doc = benchDoc(i);
    final encoded = encodeValue(doc, dict: dict);
    logical += encoded.length;
    final key = internalKey(
        benchTree, encodeKey(CNitriteId(snowflakeId(i))), i + 1, Op.put);
    if (inlineValues) {
      valueTotal += encoded.length;
      b.add(SegEntry(key, ValueKind.inline, encoded));
    } else {
      final ptr = encodeValue(CVlogRef(1, i * 512, encoded.length));
      // spec/04-segments.md section 6.4: the pointer is exactly 16 bytes, and
      // the leaf cell carries no length for it.
      final pointer = Uint8List.fromList(
          Uint8List.sublistView(ptr, ptr.length - 16));
      valueTotal += 16;
      b.add(SegEntry(key, ValueKind.vlog, pointer));
    }
  }
  return (
    segment: Segment(b.build(), pageSize),
    logicalBytes: logical,
    valueBytes: valueTotal
  );
}

/// Runs [body] [reps] times and returns the **median** microseconds.
///
/// Median rather than mean: a single GC pause should not decide a headline
/// number, and the median is what survives one.
double medianMicros(int reps, void Function() body) {
  final samples = <double>[];
  for (var i = 0; i < reps; i++) {
    final sw = Stopwatch()..start();
    body();
    sw.stop();
    samples.add(sw.elapsedMicroseconds.toDouble());
  }
  samples.sort();
  return samples[samples.length ~/ 2];
}

void warmUp(void Function() body, {int reps = 3}) {
  for (var i = 0; i < reps; i++) {
    body();
  }
}

String row(List<String> cells, List<int> widths) {
  final b = StringBuffer('| ');
  for (var i = 0; i < cells.length; i++) {
    b.write(cells[i].padRight(widths[i]));
    b.write(i == cells.length - 1 ? ' |' : ' | ');
  }
  return b.toString();
}

String fmt(double v, [int digits = 2]) => v.toStringAsFixed(digits);

String pct(num a, num b) => '${fmt(100 * a / b, 1)}%';

double ratio(num a, num b) => b == 0 ? double.nan : a / b;

int leavesOf(Segment s) {
  var n = 0;
  for (var i = 1; i < s.pageCount; i++) {
    if (s.node(i).isLeaf) n++;
  }
  return n;
}

int maxOf(Iterable<int> xs) => xs.reduce(math.max);
