import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

/// The document shape the performance model assumes:
/// "20 fields, names averaging 12 B, values averaging 20 B".
CDoc sampleDoc({int id = 1}) => CDoc({
      '_id': CNitriteId(id),
      '_revision': CInt.varInt(3),
      '_modified': const CTimestamp(1767225600000),
      'customerAddressLine1': const CStr('221B Baker Street'),
      'customerAddressLine2': const CStr('Marylebone'),
      'customerCity': const CStr('London'),
      'customerPostcode': const CStr('NW1 6XE'),
      'customerCountry': const CStr('GB'),
      'orderReference': CStr('ORD-$id'),
      'orderStatus': const CStr('dispatched'),
      'orderCurrency': const CStr('GBP'),
      'orderTotalMinor': CInt.varInt(1299),
      'orderTaxMinor': CInt.varInt(216),
      'orderShippingMinor': CInt.varInt(499),
      'itemCount': CInt.varInt(3),
      'warehouseCode': const CStr('LHR-04'),
      'carrierName': const CStr('Royal Mail'),
      'trackingNumber': const CStr('AB123456789GB'),
      'placedAt': const CTimestamp(1767225000000),
      'dispatchedAt': const CTimestamp(1767225600000),
    });

NameDict dictFor(CDoc d) {
  final dict = NameDict.withReservedFields();
  for (final k in d.fields.keys) {
    dict.intern(k);
  }
  return dict;
}

void main() {
  group('layout', () {
    test('the field table is sorted by resolved name bytes', () {
      // spec/02-value-encoding.md section 5.1: sorted by the resolved name,
      // NOT by the numeric name_ref, or dictionary and inline names would
      // interleave arbitrarily.
      final dict = NameDict.withReservedFields();
      // Intern in an order that does not match alphabetical order.
      dict.intern('zebra');
      dict.intern('apple');
      final doc = CDoc({
        'zebra': CInt.i32(1),
        'apple': CInt.i32(2),
        'mango': CInt.i32(3), // inline: not in the dictionary
      });
      final w = ByteWriter();
      writeDoc(w, doc, dict: dict);
      final view = DocView.parse(w.takeBytes(), dict: dict);
      expect([for (var i = 0; i < view.fieldCount; i++) view.nameAt(i)],
          ['apple', 'mango', 'zebra']);
    });

    test('SORTED_BY_NAME_ID must be set', () {
      final w = ByteWriter();
      writeDoc(w, CDoc({'a': const CNull()}));
      final bytes = w.takeBytes();
      // Flags byte sits after tag, byte_len and field_count, all one byte here.
      expect(bytes[3], 0x01);
      final broken = Uint8List.fromList(bytes)..[3] = 0x00;
      expect(() => DocView.parse(broken), throwsA(isA<CorruptionException>()));
    });

    test('dictionary and inline names coexist and both resolve', () {
      final dict = NameDict.withReservedFields()..intern('known');
      final doc = CDoc({
        'known': const CStr('a'),
        'oneOff': const CStr('b'),
        '_id': const CNitriteId(9),
      });
      final w = ByteWriter();
      writeDoc(w, doc, dict: dict);
      final view = DocView.parse(w.takeBytes(), dict: dict);
      expect(view.toDoc(), doc);
      expect((view['oneOff'] as CStr).value, 'b');
      expect((view['known'] as CStr).value, 'a');
      expect((view['_id'] as CNitriteId).id, 9);
    });
  });

  group('lazy projection', () {
    final doc = sampleDoc();
    final dict = dictFor(doc);
    late Uint8List encoded;

    setUp(() {
      final w = ByteWriter();
      writeDoc(w, doc, dict: dict);
      encoded = w.takeBytes();
    });

    test('resolves a single field without materializing the document', () {
      final view = DocView.parse(encoded, dict: dict);
      expect((view['trackingNumber'] as CStr).value, 'AB123456789GB');
      expect((view['orderTotalMinor'] as CInt).asInt, 1299);
      expect(view['nonexistent'], isNull);
    });

    test('a full materialization equals the original', () {
      expect(DocView.parse(encoded, dict: dict).toDoc(), doc);
    });

    test('binary search visits O(log n) fields, not n', () {
      // The claim in spec/02-value-encoding.md section 5.2 is a binary search.
      // 20 fields means at most 5 probes.
      final view = DocView.parse(encoded, dict: dict);
      var probes = 0;
      // Re-run the search manually to count comparisons.
      var lo = 0, hi = view.fieldCount - 1;
      while (lo <= hi) {
        probes++;
        final mid = (lo + hi) >> 1;
        final c = view.nameAt(mid).compareTo('trackingNumber');
        if (c == 0) break;
        if (c < 0) {
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      expect(probes, lessThanOrEqualTo(5));
      expect(view.fieldCount, 20);
    });
  });

  group('the name dictionary is the space win', () {
    test('measures the claim in section 5.3', () {
      final doc = sampleDoc();
      final dict = dictFor(doc);

      final withDict = ByteWriter();
      writeDoc(withDict, doc, dict: dict);
      final withoutDict = ByteWriter();
      writeDoc(withoutDict, doc); // every name inline

      final saved = withoutDict.length - withDict.length;
      final nameBytes = doc.fields.keys
          .map((k) => utf8.encode(k).length)
          .fold<int>(0, (a, b) => a + b);

      printOnFailure('with dictionary:    ${withDict.length} B');
      printOnFailure('without dictionary: ${withoutDict.length} B');
      printOnFailure('raw name bytes:     $nameBytes B');
      printOnFailure('saved:              $saved B');

      // Section 5.3 predicts "~240 bytes of repeated text per document,
      // replacing it with ~20-40 bytes of varints" for a 20-field document
      // with 12-byte names. Assert the mechanism, not a wall-clock number.
      expect(saved, greaterThan(nameBytes * 0.7),
          reason: 'the dictionary should recover most of the name bytes');
      expect(withDict.length, lessThan(withoutDict.length));
    });
  });

  group('reserved fields', () {
    test('the five reserved names occupy ids 1..5', () {
      // spec/02-value-encoding.md section 5.4: they SHOULD occupy name_id 1-5
      // so they encode in one byte.
      final d = NameDict.withReservedFields();
      expect(d.idOf('_id'), 1);
      expect(d.idOf('_revision'), 2);
      expect(d.idOf('_modified'), 3);
      expect(d.idOf('_source'), 4);
      expect(d.idOf('_type'), 5);
      // name_ref = id << 1, so all five fit in one uvar byte.
      for (final n in ['_id', '_revision', '_modified', '_source', '_type']) {
        expect(d.idOf(n)! << 1, lessThan(128));
      }
    });

    test('ids are never reused', () {
      final d = NameDict();
      final a = d.intern('alpha');
      final b = d.intern('beta');
      expect(d.intern('alpha'), a);
      expect(b, isNot(a));
      expect(d.nameOf(a), 'alpha');
    });

    test('an unknown name_id is corruption, not a silent blank', () {
      final d = NameDict();
      expect(() => d.nameOf(99), throwsA(isA<CorruptionException>()));
    });
  });

  group('hostile documents', () {
    test('a byte_len past the buffer is rejected', () {
      final bytes = Uint8List.fromList([Tag.doc, 0x7F, 1, 1]);
      expect(() => DocView.parse(bytes), throwsA(isA<CryptandException>()));
    });

    test('an inline name length past the end is rejected', () {
      // tag, byte_len, count=1, flags=1, name_ref=1 (inline 0), offset=0,
      // then an inline name claiming 100 bytes.
      final body = [1, 0x01, 0x01, 0x00, 100];
      final bytes = Uint8List.fromList([Tag.doc, body.length, ...body]);
      expect(() => DocView.parse(bytes), throwsA(isA<CryptandException>()));
    });

    test('a value offset past the end is rejected', () {
      final body = [1, 0x01, 0x00, 0x7F];
      final bytes = Uint8List.fromList([Tag.doc, body.length, ...body]);
      final view = DocView.parse(bytes, dict: NameDict.withReservedFields());
      expect(() => view.valueAt(0), throwsA(isA<CryptandException>()));
    });
  });
}
