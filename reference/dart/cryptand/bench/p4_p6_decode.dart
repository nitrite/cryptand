/// Prediction P4's mechanism, and the encoding-density table of
/// `design/performance-model.md` section 6.
///
/// P4 claims "on projections touching <= 25 % of a document's fields: >= 3x
/// MVStore, >= 2x Fjall, because decode dominates". A Dart implementation
/// cannot run MVStore or Fjall, so what is measurable here is the
/// **mechanism** that claim rests on, stated in `design/architecture.md`
/// section 3:
///
///   > "Projections decode one field, not the document. ... On a 20-field
///   >  document where a query needs two fields, that is ~10x less decode
///   >  work"
///
/// If that ratio is real, the engine-to-engine comparison is a matter of what
/// the other engine's full decode costs. If it is not, P4 has no mechanism.
library;

import 'dart:convert';

import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/value.dart';

import 'harness.dart';

/// A JSON rendering of the same document, for the section 6 density table.
String asJson(CDoc d) {
  final m = <String, Object?>{};
  d.fields.forEach((k, v) {
    m[k] = switch (v) {
      CStr() => v.value,
      CInt() => v.asInt,
      CNitriteId() => v.id,
      CTimestamp() => v.millis,
      _ => v.toString(),
    };
  });
  return jsonEncode(m);
}

void main() {
  final dict = benchDict();
  final doc = benchDoc(42);

  // -------------------------------------------------------------------
  // Encoding density, section 6.
  // -------------------------------------------------------------------
  final withDict = (ByteWriter()..let((w) => writeDoc(w, doc, dict: dict)));
  final noDict = (ByteWriter()..let((w) => writeDoc(w, doc)));
  final json = asJson(doc);

  print('# P4 mechanism and P6 encoding density');
  print('');
  print('The 20-field document of design/performance-model.md section 1.');
  print('');
  const w1 = [40, 10, 14];
  print(row(['encoding', 'bytes', 'vs CVE+dict'], w1));
  print(row(['---', '---', '---'], w1));
  print(row([
    'CVE with a per-tree name dictionary',
    '${withDict.length}',
    '1.00x'
  ], w1));
  print(row([
    'CVE, every name inline',
    '${noDict.length}',
    '${fmt(ratio(noDict.length, withDict.length))}x'
  ], w1));
  print(row([
    'JSON (dart:convert)',
    '${json.length}',
    '${fmt(ratio(json.length, withDict.length))}x'
  ], w1));
  print('');
  print('section 6 predicts ~485 B for CVE+dictionary and ~740 B for JSON.');
  print('');

  // -------------------------------------------------------------------
  // P4 mechanism: decoding one field versus the whole document.
  // -------------------------------------------------------------------
  final encoded = withDict.takeBytes();
  const reps = 20000;

  void decodeAll() {
    for (var i = 0; i < reps; i++) {
      DocView.parse(encoded, dict: dict).toDoc();
    }
  }

  void decodeOne() {
    for (var i = 0; i < reps; i++) {
      DocView.parse(encoded, dict: dict).get('trackingNumb');
    }
  }

  void decodeTwo() {
    for (var i = 0; i < reps; i++) {
      final v = DocView.parse(encoded, dict: dict);
      v.get('trackingNumb');
      v.get('ordTotMinorU');
    }
  }

  void decodeFive() {
    for (var i = 0; i < reps; i++) {
      final v = DocView.parse(encoded, dict: dict);
      for (final f in [
        'trackingNumb',
        'ordTotMinorU',
        'custCityName',
        'ordStatusTxt',
        '_id'
      ]) {
        v.get(f);
      }
    }
  }

  warmUp(decodeAll);
  warmUp(decodeOne);
  final tAll = medianMicros(7, decodeAll);
  final tOne = medianMicros(7, decodeOne);
  final tTwo = medianMicros(7, decodeTwo);
  final tFive = medianMicros(7, decodeFive);

  const w2 = [30, 16, 16];
  print(row(['work per document', 'ns/document', 'vs full decode'], w2));
  print(row(['---', '---', '---'], w2));
  print(row([
    'decode all 20 fields',
    fmt(tAll * 1000 / reps, 0),
    '1.00x'
  ], w2));
  print(row([
    'decode 1 field',
    fmt(tOne * 1000 / reps, 0),
    '${fmt(ratio(tAll, tOne))}x cheaper'
  ], w2));
  print(row([
    'decode 2 fields (10 %)',
    fmt(tTwo * 1000 / reps, 0),
    '${fmt(ratio(tAll, tTwo))}x cheaper'
  ], w2));
  print(row([
    'decode 5 fields (25 %)',
    fmt(tFive * 1000 / reps, 0),
    '${fmt(ratio(tAll, tFive))}x cheaper'
  ], w2));
  print('');
  print('design/architecture.md section 3 predicts ~10x for a 2-field '
      'projection.');
  print('Measured: ${fmt(ratio(tAll, tTwo))}x');
}

extension<T> on T {
  T let(void Function(T) f) {
    f(this);
    return this;
  }
}
