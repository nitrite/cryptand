/// `spec/06-indexes.md` — one index layout, for all three index types.
///
/// The scans of §7 are the load-bearing part: "an SDK's planner MUST express
/// every indexed predicate as one of them", and the numeric rows are the ones
/// the third review round found wrong. Those get a torture test rather than an
/// example.
library;

import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

CDoc doc(Map<String, CValue> f) => CDoc(f);

void main() {
  group('field paths, section 5', () {
    test('splits on unescaped dots only', () {
      expect(splitFieldPath('a.b.c'), ['a', 'b', 'c']);
      expect(splitFieldPath(r'a\.b.c'), ['a.b', 'c']);
      expect(splitFieldPath(r'a\\b'), [r'a\b']);
      expect(splitFieldPath('plain'), ['plain']);
    });

    test('rejects an unknown escape and a dangling backslash', () {
      expect(() => splitFieldPath(r'a\nb'),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => splitFieldPath('a\\'),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('array traversal flattens the remainder of the path', () {
      // "orders.items.sku indexes every sku in every item of every order"
      final d = doc({
        'orders': CArray([
          doc({
            'items': CArray([
              doc({'sku': const CStr('a')}),
              doc({'sku': const CStr('b')}),
            ])
          }),
          doc({
            'items': CArray([doc({'sku': const CStr('c')})])
          }),
        ])
      });
      expect(resolvePath(d, 'orders.items.sku')!.map((v) => (v as CStr).value),
          ['a', 'b', 'c']);
    });

    test('an unresolvable path is an absent field', () {
      expect(resolvePath(doc({'a': const CStr('x')}), 'a.b.c'), isNull);
      expect(resolvePath(doc({'a': const CStr('x')}), 'zzz'), isNull);
    });
  });

  group('entries, sections 3 and 4', () {
    final idx = const IndexDescriptor(
        indexType: IndexType.nonUnique, dataTree: 20, fields: ['tags']);

    test('an array field produces one entry per element', () {
      final keys = indexKeysFor(
          idx,
          doc({
            'tags': CArray([const CStr('red'), const CStr('blue')])
          }),
          const CNitriteId(7));
      expect(keys.length, 2);
      expect(keys.map((k) => (indexEntryValues(k, 1).single as CStr).value),
          ['red', 'blue']);
      expect(keys.every((k) => indexEntryId(k) == const CNitriteId(7)), isTrue);
    });

    test('duplicate elements produce one entry, not two', () {
      final keys = indexKeysFor(
          idx,
          doc({
            'tags': CArray([const CStr('red'), const CStr('red')])
          }),
          const CNitriteId(7));
      expect(keys.length, 1);
    });

    test('a null value and an absent field both index as NULL', () {
      final present =
          indexKeysFor(idx, doc({'tags': const CNull()}), const CNitriteId(1));
      final absent = indexKeysFor(idx, doc({}), const CNitriteId(1));
      expect(present.single, absent.single);
      expect(indexEntryValues(absent.single, 1).single, isA<CNull>());
    });

    test('an empty array has no entries; an unresolved traversal is NULL',
        () {
      // F-058/F-059: section 4 gives an empty array zero entries, section 5
      // makes a path no array element resolves an absent field.
      expect(indexKeysFor(idx, doc({'tags': CArray([])}), const CNitriteId(1)),
          isEmpty);
      const nested = IndexDescriptor(
          indexType: IndexType.nonUnique, dataTree: 20, fields: ['a.b']);
      final keys = indexKeysFor(
          nested,
          doc({
            'a': CArray([const CStr('x')])
          }),
          const CNitriteId(1));
      expect(indexEntryValues(keys.single, 1).single, isA<CNull>());
    });

    test('sparse skips an absent field entirely', () {
      const sparse = IndexDescriptor(
          indexType: IndexType.nonUnique,
          dataTree: 20,
          fields: ['tags'],
          sparse: true);
      expect(indexKeysFor(sparse, doc({}), const CNitriteId(1)), isEmpty);
      // A field that is present and null is still indexed.
      expect(
          indexKeysFor(sparse, doc({'tags': const CNull()}), const CNitriteId(1))
              .length,
          1);
    });

    test('the cartesian product is capped at 1024 entries', () {
      const compound = IndexDescriptor(
          indexType: IndexType.nonUnique, dataTree: 20, fields: ['a', 'b']);
      CArray n(int count, String p) =>
          CArray([for (var i = 0; i < count; i++) CStr('$p$i')]);
      expect(indexKeysFor(compound, doc({'a': n(32, 'a'), 'b': n(32, 'b')}),
              const CNitriteId(1)).length,
          1024);
      expect(
          () => indexKeysFor(compound,
              doc({'a': n(33, 'a'), 'b': n(32, 'b')}), const CNitriteId(1)),
          throwsA(isA<LimitException>()));
    });

    test('a value with no CKE encoding is refused, naming the field', () {
      // section 6: DEC128 is the surprising member of that list.
      expect(
          () => indexKeysFor(idx, doc({'tags': CDec128(Uint8List(16))}),
              const CNitriteId(1)),
          throwsA(predicate((e) =>
              e is InvalidArgumentException && e.toString().contains('tags'))));
    });

    test('BYTES is indexable, unlike nitrite-rust today', () {
      final keys = indexKeysFor(idx,
          doc({'tags': CBytes(Uint8List.fromList([1, 2, 3]))}),
          const CNitriteId(1));
      expect(keys.length, 1);
    });

    test('a unique index skips its check when any value is NULL', () {
      expect(uniquenessApplies([const CStr('a')]), isTrue);
      expect(uniquenessApplies([const CStr('a'), const CNull()]), isFalse);
    });
  });

  group('the section 7 scans, over a real index', () {
    late Database db;
    late Collection c;

    setUp(() {
      db = Database();
      c = db.createCollection('orders');
      for (var i = 0; i < 200; i++) {
        c.put(
            CNitriteId(i),
            doc({
              'city': CStr('city${(i % 10).toString().padLeft(2, '0')}'),
              // Deliberately mixed numeric types over the *same* values: qty
              // 20 is stored twice as I32 and twice as F64. Making the type
              // depend on i's parity would not do it, because i % 50 == 20
              // implies i is even -- and then the section 8.2 failure this
              // guards could not show up at all.
              'qty': (i ~/ 50).isEven
                  ? CInt.i32(i % 50)
                  : CFloat.f64((i % 50).toDouble()),
              'name': CStr('name-$i'),
            }));
      }
    });

    test('equality on a prefix is one seek', () {
      final idx = c.createIndex(['city', 'qty']);
      final ids =
          c.lookup(idx, IndexScan.eqPrefix([const CStr('city03')])).toList();
      expect(ids.length, 20);
      for (final id in ids) {
        expect((c.get(id)!['city']! as CStr).value, 'city03');
      }
    });

    test('a numeric equality matches every numeric type', () {
      final idx = c.createIndex(['qty']);
      // 20 appears as I32(20) on even i and F64(20.0) on odd i.
      // A type-carrying bound: CKE(I32(20)) matches the I32 rows only.
      final typed = c.lookup(idx, IndexScan.eqPrefix([CInt.i32(20)])).toList();
      final agnostic =
          c.lookup(idx, IndexScan.eqPrefixNumeric([CInt.i32(20)])).toList();
      expect(typed.length, 2, reason: 'the two I32(20) rows');
      expect(agnostic.length, 4, reason: 'both I32(20) and F64(20.0)');
      for (final id in agnostic) {
        final q = c.get(id)!['qty']!;
        expect(q is CInt ? q.magnitude.lo : (q as CFloat).value, 20);
      }
    });

    test('a numeric range bound cuts between values, not types', () {
      // The failure this guards: a bound built from the full CKE(v) carries
      // the type code, so `field >= 5` misses an I8(5) and `field > 5`
      // returns a U8(5). spec/03-key-encoding.md section 8.2.
      final idx = c.createIndex(['qty']);
      final ge = c
          .lookup(idx, IndexScan.range([], lower: CInt.i32(20)))
          .map((id) => _qty(c.get(id)!))
          .toList();
      expect(ge, isNotEmpty);
      expect(ge.every((q) => q >= 20), isTrue);
      // Both encodings of every qualifying value are present.
      expect(ge.where((q) => q == 20).length, 4,
          reason: 'the I32(20) and the F64(20.0) rows must both appear');

      final between = c
          .lookup(
              idx,
              IndexScan.range([],
                  lower: CInt.i32(10),
                  upper: CInt.i32(20),
                  upperInclusive: true))
          .map((id) => _qty(c.get(id)!))
          .toList();
      expect(between.every((q) => q >= 10 && q <= 20), isTrue);
      expect(between.contains(10), isTrue);
      expect(between.contains(20), isTrue);
    });

    test('a range after an equality prefix', () {
      final idx = c.createIndex(['city', 'qty']);
      final got = c
          .lookup(
              idx,
              IndexScan.range([const CStr('city03')],
                  lower: CInt.i32(20), upperInclusive: false))
          .map((id) => c.get(id)!)
          .toList();
      expect(got, isNotEmpty);
      for (final d in got) {
        expect((d['city']! as CStr).value, 'city03');
        expect(_qty(d), greaterThanOrEqualTo(20));
      }
    });

    test('starts_with is a prefix scan', () {
      final idx = c.createIndex(['name']);
      final got =
          c.lookup(idx, IndexScan.startsWith([], 'name-1')).toList();
      // name-1, name-1x for x in 0..9, name-1xy for the rest under 200
      expect(got.length, 111);
      for (final id in got) {
        expect((c.get(id)!['name']! as CStr).value, startsWith('name-1'));
      }
    });

    test('a covering query never touches the data tree', () {
      // section 1: "A scan yields the indexed values *and* the document id by
      // decoding the key; there is no second lookup."
      final idx = c.createIndex(['city', 'qty']);
      final rows =
          c.lookupCovering(idx, IndexScan.eqPrefix([const CStr('city03')]))
              .toList();
      expect(rows.length, 20);
      for (final r in rows) {
        expect((r[0] as CStr).value, 'city03');
        expect(r.length, 3); // city, qty, id
      }
    });

    test('the scan is already in index order, so a sort must not materialize',
        () {
      final idx = c.createIndex(['name']);
      final names = c
          .lookupCovering(idx, IndexScan.all())
          .map((r) => (r[0] as CStr).value)
          .toList();
      expect(names, equals([...names]..sort()));
    });
  });

  group('index maintenance, section 8', () {
    late Database db;
    late Collection c;
    setUp(() {
      db = Database();
      c = db.createCollection('orders');
    });

    test('an update removes the old entries and writes the new ones', () {
      final idx = c.createIndex(['city']);
      c.put(const CNitriteId(1), doc({'city': const CStr('paris')}));
      expect(c.lookup(idx, IndexScan.eqPrefix([const CStr('paris')])).toList(),
          [const CNitriteId(1)]);
      c.put(const CNitriteId(1), doc({'city': const CStr('berlin')}));
      expect(c.lookup(idx, IndexScan.eqPrefix([const CStr('paris')])), isEmpty);
      expect(c.lookup(idx, IndexScan.eqPrefix([const CStr('berlin')])).toList(),
          [const CNitriteId(1)]);
    });

    test('a delete removes every entry the document produced', () {
      final idx = c.createIndex(['tags']);
      c.put(
          const CNitriteId(1),
          doc({
            'tags': CArray([const CStr('red'), const CStr('blue')])
          }));
      expect(c.lookupCovering(idx, IndexScan.all()).length, 2);
      c.remove(const CNitriteId(1));
      expect(c.lookupCovering(idx, IndexScan.all()), isEmpty);
    });

    test('a unique index refuses a duplicate', () {
      final idx = c.createIndex(['email'], indexType: IndexType.unique);
      c.put(const CNitriteId(1), doc({'email': const CStr('a@b.c')}));
      expect(
          () => c.put(const CNitriteId(2), doc({'email': const CStr('a@b.c')})),
          throwsA(isA<InvalidArgumentException>()));
      // Updating the same document is not a duplicate.
      c.put(const CNitriteId(1),
          doc({'email': const CStr('a@b.c'), 'x': CInt.i32(1)}));
      expect(c.lookup(idx, IndexScan.eqPrefix([const CStr('a@b.c')])).toList(),
          [const CNitriteId(1)]);
    });

    test('a unique index treats every NULL as distinct', () {
      // The SQL convention, which all three SDKs already follow.
      c.createIndex(['email'], indexType: IndexType.unique);
      c.put(const CNitriteId(1), doc({'x': CInt.i32(1)}));
      c.put(const CNitriteId(2), doc({'x': CInt.i32(2)}));
      expect(c.all.length, 2);
    });

    test('creating an index backfills every document already present', () {
      for (var i = 0; i < 50; i++) {
        c.put(CNitriteId(i), doc({'city': CStr('city${i % 5}')}));
      }
      final idx = c.createIndex(['city']);
      expect(c.lookup(idx, IndexScan.eqPrefix([const CStr('city2')])).length, 10);
    });

    test('an index entry carries no value bytes', () {
      // section 1: value = EMPTY, value_kind 3, zero bytes. So adding indexes
      // adds index *keys* and nothing at all to the segment's value bytes.
      final d = doc({'city': const CStr('paris'), 'tag': const CStr('x')});
      final bare = Database()..createCollection('o');
      bare.collection('o')!.put(const CNitriteId(1), d);
      bare.engine.flush();

      c.createIndex(['city']);
      c.createIndex(['tag']);
      c.put(const CNitriteId(1), d);
      db.engine.flush();

      expect(db.engine.extents.values.last.header.valueBytes,
          bare.engine.extents.values.last.header.valueBytes);
      expect(db.engine.extents.values.last.header.entryCount,
          greaterThan(bare.engine.extents.values.last.header.entryCount));
    });
  });
}

num _qty(CDoc d) {
  final q = d['qty']!;
  return q is CInt ? q.magnitude.lo : (q as CFloat).value;
}
