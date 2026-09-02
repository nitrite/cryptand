/// `spec/05-catalog.md` — the catalog, tree descriptors and the logical
/// Nitrite model.
///
/// The tests that matter here are the ones about *divergence*: every
/// assertion below is a place where `research/nitrite-survey.md` §6 records
/// the three SDKs disagreeing today.
library;

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

void main() {
  group('tree names, section 1', () {
    test('a name may hold any UTF-8, including | and +', () {
      final c = Catalog(PageStore());
      // Fjall substitutes | -> _P_ and + -> _K_ in partition names today, and
      // Hive base64s its box keys. Both are retired.
      for (final name in [
        'orders|2026+eu',
        'коллекция',
        '主集合',
        'a/b\\c',
        'name with spaces',
        r'$weird%^&*',
      ]) {
        c.create(name, kind: TreeKind.data);
        expect(c.get(name), isNotNull, reason: name);
      }
    });

    test('tree ids are never reused', () {
      final c = Catalog(PageStore());
      final a = c.create('a', kind: TreeKind.data);
      c.drop('a');
      final b = c.create('b', kind: TreeKind.data);
      expect(b.treeId, greaterThan(a.treeId));
      // The dangling reference is detectable rather than silently rebound.
      expect(c.nameOf(a.treeId), isNull);
    });

    test('tree 3 is the reverse of the catalog and can be rebuilt', () {
      final c = Catalog(PageStore());
      final d = c.create('orders', kind: TreeKind.data);
      expect(c.nameOf(d.treeId), 'orders');
      c.byId.root = 0; // as if tree 3's descriptor were missing
      expect(c.nameOf(d.treeId), isNull);
      c.rebuildTreeIndex();
      expect(c.nameOf(d.treeId), 'orders');
    });
  });

  group('descriptors, section 3', () {
    test('unknown fields survive a rewrite', () {
      // spec/11-conformance.md section 4. A round trip that drops a field a
      // future minor version added is how two SDKs quietly stop agreeing.
      final original = TreeDescriptor.create(
        treeId: 20,
        kind: TreeKind.data,
        params: {'type': const CStr('collection')},
      ).with_({
        'a_field_from_2027': const CStr('keep me'),
        'another': CInt.of(NumType.u32, 42),
      });

      final back = TreeDescriptor.decode(original.encode());
      expect((back.doc['a_field_from_2027']! as CStr).value, 'keep me');

      // Now change something known and re-encode: the unknowns must still be
      // there.
      final edited = back.with_({'entries': CInt.of(NumType.u64, 99)});
      final again = TreeDescriptor.decode(edited.encode());
      expect(again.entries, 99);
      expect((again.doc['a_field_from_2027']! as CStr).value, 'keep me');
      expect(((again.doc['another']! as CInt).magnitude).lo, 42);
    });

    test('levelled is true exactly for the kinds section 3 lists', () {
      for (final kind in TreeKind.known) {
        final d = TreeDescriptor.create(treeId: 20, kind: kind);
        expect(d.levelled, TreeKind.levelled.contains(kind), reason: kind);
      }
      // rtree is the interesting one: it is a copy-on-write tree of its own
      // page types, not a levelled segment set.
      expect(
          TreeDescriptor.create(treeId: 20, kind: TreeKind.rtree).levelled,
          isFalse);
    });

    test('policy fields live in params, structural fields do not', () {
      // section 3.1: "params is the single place". An earlier draft listed
      // five of these at the top level while every other chapter wrote them
      // as params.x.
      final d = TreeDescriptor.create(
        treeId: 20,
        kind: TreeKind.data,
        params: {
          'ttl_ms': CInt.of(NumType.u64, 86400000),
          'change_feed': const CBool(true),
          'inline_values': const CBool(true),
        },
      );
      for (final f in ['ttl_ms', 'change_feed', 'inline_values']) {
        expect(d.param(f), isNotNull, reason: f);
        expect(d.doc[f], isNull, reason: '$f must not be top-level');
      }
      // A reader that ignores every one of them still reads the tree.
      expect(d.treeId, 20);
      expect(d.levelled, isTrue);
    });
  });

  group('kinds, section 4', () {
    test('an unrecognized kind is opaque and MUST NOT be deleted', () {
      final c = Catalog(PageStore());
      final d = TreeDescriptor.create(treeId: 20, kind: 'some_future_kind');
      c.put('mystery', d);
      expect(c.mayDelete('mystery'), isFalse);
      expect(() => c.drop('mystery'), throwsA(isA<InvalidArgumentException>()));
      // It may still be listed and copied.
      expect(c.all.map((e) => e.$1), contains('mystery'));
    });
  });

  group('index type names, section 10', () {
    test('the on-disk spelling is lower snake case', () {
      expect(IndexType.unique, 'unique');
      expect(IndexType.nonUnique, 'non_unique');
      expect(IndexType.fullText, 'full_text');
      expect(IndexType.portable.length, 5);
      // Not Unique/NonUnique/Fulltext (Java, Dart) and not non-hyphenated
      // spellings (Rust).
      for (final n in IndexType.portable) {
        expect(n, equals(n.toLowerCase()));
        expect(n, isNot(contains('-')));
      }
    });
  });

  group('enumerations, section 11', () {
    late Database db;
    setUp(() {
      db = Database();
      db.createCollection('orders');
      db.createCollection('orders|2026+eu');
      db.createRepository('org.dizitart.no2.Employee');
      db.createRepository('org.dizitart.no2.Employee', key: 'archive');
    });

    test('collections, repositories and keyed repositories are one scan', () {
      expect(db.catalog.collections.toList(),
          containsAll(['orders', 'orders|2026+eu']));
      expect(db.catalog.repositories.toList(),
          ['org.dizitart.no2.Employee']);
      expect(db.catalog.keyedRepositories.toList(),
          ['org.dizitart.no2.Employee+archive']);
    });

    test('a keyed repository is distinguished by params, not by its name', () {
      final d = db.catalog.get('org.dizitart.no2.Employee+archive')!;
      expect((d.param('key')! as CStr).value, 'archive');
      expect((d.param('entity')! as CStr).value, 'org.dizitart.no2.Employee');
      // The + is just a character; nothing parses it.
      expect(db.catalog.repositories, isNot(contains(
          'org.dizitart.no2.Employee+archive')));
    });

    test('indexes of a collection are found by owner', () {
      final c = db.collection('orders')!;
      c.createIndex(['custCityName']);
      expect(db.catalog.indexesOf('orders').length, 1);
      expect(db.catalog.indexesOf('orders|2026+eu'), isEmpty);
    });

    test('a stale index is found by its stale_from field', () {
      final c = db.collection('orders')!;
      final idx = c.createIndex(['custCityName']);
      expect(db.catalog.staleTrees, isEmpty);
      final name = db.catalog.nameOf(idx.treeId)!;
      db.catalog.put(name, idx.with_({'stale_from': CInt.of(NumType.u64, 7)}));
      expect(db.catalog.staleTrees.map((e) => e.$1), [name]);
    });
  });

  group('attributes and store metadata, sections 6 and 7', () {
    test('store metadata replaces \$nitrite_store_info', () {
      final db = Database();
      final store = db.attributes.get(Attributes.storeKey)!;
      expect((store['format_version']! as CStr).value, kFormatVersion);
      expect(((store['schema_version']! as CInt).magnitude).lo, 1);
    });

    test('writers accumulates distinct writer ids', () {
      final db = Database();
      db.attributes
        ..recordWriter('dart-reference')
        ..recordWriter('rust-1.0')
        ..recordWriter('dart-reference');
      final w = db.attributes.get(Attributes.storeKey)!['writers']! as CArray;
      expect(w.items.map((e) => (e as CStr).value),
          ['dart-reference', 'rust-1.0']);
    });

    test('attribute names are unrestricted UTF-8', () {
      final db = Database();
      db.attributes.put('orders', CDoc({
        'name': const CStr('orders'),
        'приложение.ключ': const CStr('value'),
      }));
      expect(db.attributes.get('orders')!['приложение.ключ'],
          const CStr('value'));
    });
  });
}
