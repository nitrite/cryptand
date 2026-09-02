/// `spec/04-segments.md` §3.3 and `spec/05-catalog.md` §2 — the reserved trees.
///
/// The tree is checked against a `SplayTreeMap` under the *same* byte order it
/// uses, over enough random operations to force splits, path copies and root
/// collapses. A B+tree that agrees with a sorted map on every read after every
/// write is the whole contract.
library;

import 'dart:math';
import 'dart:typed_data';

import 'dart:collection';
import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

Uint8List _k(String s) => Uint8List.fromList(s.codeUnits);
String _s(Uint8List b) => String.fromCharCodes(b);

void main() {
  group('CowTree', () {
    test('an empty tree has root 0 and reads nothing', () {
      final t = CowTree(PageStore(), treeId: TreeId.catalog);
      expect(t.isEmpty, isTrue);
      expect(t.root, 0);
      expect(t.get(_k('a')), isNull);
      expect(t.scan().toList(), isEmpty);
      expect(t.height, 0);
    });

    test('put publishes a new root every time — copy-on-write', () {
      final t = CowTree(PageStore(), treeId: TreeId.catalog);
      final roots = <int>{};
      for (var i = 0; i < 20; i++) {
        t.put(_k('key$i'), _k('value$i'));
        roots.add(t.root);
      }
      // A root that repeats would mean a page was updated in place.
      expect(roots.length, 20);
      for (var i = 0; i < 20; i++) {
        expect(_s(t.get(_k('key$i'))!), 'value$i');
      }
    });

    test('agrees with a sorted map over 4000 random operations', () {
      final rnd = Random(20260902);
      final store = PageStore();
      final t = CowTree(store, treeId: TreeId.manifest);
      final model = SplayTreeMap<String, String>(
          (a, b) => compareKeys(_k(a), _k(b)));

      for (var op = 0; op < 4000; op++) {
        final key = 'k${rnd.nextInt(600).toString().padLeft(4, '0')}';
        if (rnd.nextInt(4) == 0) {
          expect(t.remove(_k(key)), model.remove(key) != null,
              reason: 'remove($key) at op $op');
        } else {
          // Values long enough that a page holds only a few dozen.
          final v = '${'v' * (8 + rnd.nextInt(60))}:$op';
          t.put(_k(key), _k(v));
          model[key] = v;
        }
        if (op % 250 == 0) {
          expect(t.entryCount, model.length, reason: 'count at op $op');
        }
      }

      expect(t.entryCount, model.length);
      for (final e in model.entries) {
        expect(_s(t.get(_k(e.key))!), e.value, reason: e.key);
      }
      expect([for (final (k, v) in t.scan()) '${_s(k)}=${_s(v)}'],
          [for (final e in model.entries) '${e.key}=${e.value}']);
      expect(t.height, greaterThan(1), reason: 'the tree must have split');
    });

    test('scan honours a half-open range', () {
      final t = CowTree(PageStore(), treeId: TreeId.catalog);
      for (var i = 0; i < 200; i++) {
        t.put(_k('k${i.toString().padLeft(3, '0')}'), _k('v$i'));
      }
      final got = [
        for (final (k, _) in t.scan(lower: _k('k050'), upper: _k('k060')))
          _s(k)
      ];
      expect(got.first, 'k050');
      expect(got.last, 'k059');
      expect(got.length, 10);
    });

    test('emptying the tree returns the root to 0', () {
      final t = CowTree(PageStore(), treeId: TreeId.catalog);
      for (var i = 0; i < 300; i++) {
        t.put(_k('k${i.toString().padLeft(3, '0')}'), _k('v' * 40));
      }
      expect(t.height, greaterThan(1));
      for (var i = 0; i < 300; i++) {
        expect(t.remove(_k('k${i.toString().padLeft(3, '0')}')), isTrue);
      }
      expect(t.root, 0);
      expect(t.entryCount, 0);
    });

    test('a path copy writes height pages, not one', () {
      final store = PageStore();
      final t = CowTree(store, treeId: TreeId.manifest);
      for (var i = 0; i < 500; i++) {
        t.put(_k('k${i.toString().padLeft(4, '0')}'), _k('v' * 40));
      }
      final h = t.height;
      expect(h, greaterThanOrEqualTo(2));
      t.resetCounters();
      t.put(_k('k0250'), _k('w' * 40));
      expect(t.pagesCopied, h,
          reason: 'a copy-on-write edit copies exactly the root-to-leaf path');
    });

    test('a cell too large for a page is refused, not silently split', () {
      final t = CowTree(PageStore(), treeId: TreeId.catalog);
      expect(() => t.put(_k('k'), Uint8List(5000)),
          throwsA(isA<LimitException>()));
    });

    test('pages carry the owning tree id and the §2.2 page type', () {
      final store = PageStore();
      final t = CowTree(store, treeId: TreeId.manifest)
        ..put(_k('a'), _k('1'));
      final h = PageHeader.read(store.read(t.root));
      expect(h.treeId, TreeId.manifest);
      expect(h.pageType, PageType.btreeLeaf);
    });
  });
}
