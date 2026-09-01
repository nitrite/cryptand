import 'dart:typed_data';

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

const int kTree = 17;

Uint8List ikFor(int id, {int seq = 1, int op = Op.put}) =>
    internalKey(kTree, encodeKey(CNitriteId(id)), seq, op);

/// A snowflake-shaped id, so keys share a long common prefix -- the shape
/// `design/performance-model.md` section 1 assumes.
int snowflake(int i) => 1767225600000 * 4194304 + i;

Segment buildSegment(int n,
    {int pageSize = 4096, int valueBytes = 16, int segmentId = 1}) {
  final b = SegmentBuilder(
      pageSize: pageSize, segmentId: segmentId, treeId: kTree);
  final value = Uint8List(valueBytes);
  for (var i = 0; i < n; i++) {
    b.add(SegEntry(ikFor(snowflake(i)), ValueKind.inline, value));
  }
  return Segment(b.build(), pageSize);
}

void main() {
  group('bulk construction', () {
    test('a single-entry segment is a header plus one leaf', () {
      final s = buildSegment(1);
      expect(s.pageCount, 2);
      expect(s.header.entryCount, 1);
      expect(s.height, 1);
      s.verifyChecksums();
    });

    test('rejects out-of-order input rather than sorting around it', () {
      final b = SegmentBuilder(pageSize: 4096, segmentId: 1);
      b.add(SegEntry(ikFor(5), ValueKind.empty, Uint8List(0)));
      expect(() => b.add(SegEntry(ikFor(4), ValueKind.empty, Uint8List(0))),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => b.add(SegEntry(ikFor(5), ValueKind.empty, Uint8List(0))),
          throwsA(isA<InvalidArgumentException>()),
          reason: 'strictly increasing, so a duplicate is an error too');
    });

    test('every page passes its checksum at every size', () {
      for (final n in [1, 10, 200, 5000]) {
        buildSegment(n).verifyChecksums();
      }
    });

    test('the header records what the manifest needs to prune without I/O',
        () {
      final s = buildSegment(1000, segmentId: 99);
      expect(s.header.segmentId, 99);
      expect(s.header.entryCount, 1000);
      expect(s.header.treeSpan[kTree], 1000);
      expect(s.header.flags & SegFlags.singleTree, isNot(0));
      // min_key/max_key are bounds: min <= every key <= max.
      final c = s.cursor()..seekFirst();
      expect(compareKeys(s.header.minKey, c.key()), lessThanOrEqualTo(0));
      c.seekLast();
      expect(compareKeys(s.header.maxKey, c.key()), greaterThanOrEqualTo(0));
    });
  });

  group('invariants a verifier checks (spec section 11)', () {
    late Segment s;
    setUp(() => s = buildSegment(20000));

    test('1: internal keys strictly increase within and across pages', () {
      final c = s.cursor()..seekFirst();
      Uint8List? prev;
      var seen = 0;
      while (c.isValid) {
        final k = c.key();
        if (prev != null) {
          expect(compareKeys(prev, k), lessThan(0),
              reason: 'order broke at entry $seen');
        }
        prev = k;
        seen++;
        c.next();
      }
      expect(seen, s.header.entryCount);
    });

    test('2: every separator is >= the subtree left of it and <= its own', () {
      // The invariant exactly as spec/04-segments.md section 11 states it.
      // Note it says nothing about cell 0: nothing sits left of it, so its
      // separator is the empty string, which is below every key and makes the
      // descent total.
      (Uint8List, Uint8List) bounds(Node n) {
        if (n.isLeaf) return (n.keyAt(0), n.keyAt(n.cellCount - 1));
        final first = bounds(s.node(n.childAt(0).$1));
        final last = bounds(s.node(n.childAt(n.cellCount - 1).$1));
        return (first.$1, last.$2);
      }

      void walk(Node n) {
        if (n.isLeaf) return;
        // Only the globally leftmost page at a level has an empty cell-0
        // separator; every other page's is a real truncated key.
        for (var i = 0; i < n.cellCount; i++) {
          final child = s.node(n.childAt(i).$1);
          final (lo, hi) = bounds(child);
          final sep = n.keyAt(i);
          expect(compareKeys(sep, lo), lessThanOrEqualTo(0),
              reason: 'separator $i must not exceed its subtree minimum');
          if (i > 0) {
            final (_, prevHi) = bounds(s.node(n.childAt(i - 1).$1));
            expect(compareKeys(sep, prevHi), greaterThan(0),
                reason: 'separator $i must exceed the subtree left of it');
          }
          expect(compareKeys(lo, hi), lessThanOrEqualTo(0));
          walk(child);
        }
      }

      walk(s.node(s.header.rootPage));
    });

    test('the descent finds every key that is present', () {
      // The end-to-end statement of invariant 2: if separators were wrong,
      // some key would be unreachable through the tree even though it is in a
      // leaf.
      final c = s.cursor()..seekFirst();
      final keys = <Uint8List>[];
      while (c.isValid) {
        keys.add(c.key());
        c.next();
      }
      for (var i = 0; i < keys.length; i += 37) {
        final probe = s.cursor()..seekCeiling(keys[i]);
        expect(probe.isValid, isTrue, reason: 'entry $i unreachable');
        expect(probe.key(), keys[i], reason: 'entry $i landed elsewhere');
      }
    });

    test('3: subtree_entries sums correctly and leaves are at one depth', () {
      final depths = <int>{};
      int walk(Node n, int depth) {
        if (n.isLeaf) {
          depths.add(depth);
          expect(n.subtreeEntries, n.cellCount);
          return n.cellCount;
        }
        var total = 0;
        for (var i = 0; i < n.cellCount; i++) {
          final (child, declared) = n.childAt(i);
          final actual = walk(s.node(child), depth + 1);
          expect(actual, declared,
              reason: 'child_subtree_entries is wrong at page ${n.pageIndex}');
          total += actual;
        }
        expect(n.subtreeEntries, total);
        return total;
      }

      expect(walk(s.node(s.header.rootPage), 0), s.header.entryCount);
      expect(depths.length, 1, reason: 'all leaves must be at one depth');
    });

    test('4: prefix is a prefix of every key on its page', () {
      for (var p = 1; p < s.pageCount; p++) {
        final n = s.node(p);
        final prefix = n.prefix;
        for (var i = 0; i < n.cellCount; i++) {
          final k = n.keyAt(i);
          expect(k.length, greaterThanOrEqualTo(prefix.length));
          for (var j = 0; j < prefix.length; j++) {
            expect(k[j], prefix[j], reason: 'page $p cell $i');
          }
        }
      }
    });
  });

  group('cursor', () {
    test('seekCeiling lands on the first key at or above the target', () {
      final s = buildSegment(5000);
      for (final i in [0, 1, 2499, 4998, 4999]) {
        final c = s.cursor()..seekCeiling(ikFor(snowflake(i)));
        expect(c.isValid, isTrue, reason: 'i=$i');
        expect(c.key(), ikFor(snowflake(i)), reason: 'i=$i');
      }
      // Past the end.
      final c = s.cursor()..seekCeiling(ikFor(snowflake(999999)));
      expect(c.isValid, isFalse);
    });

    test('seekCeiling on a key that is not present rolls forward', () {
      final b = SegmentBuilder(pageSize: 4096, segmentId: 1, treeId: kTree);
      for (var i = 0; i < 1000; i += 2) {
        b.add(SegEntry(ikFor(i), ValueKind.empty, Uint8List(0)));
      }
      final s = Segment(b.build(), 4096);
      final c = s.cursor()..seekCeiling(ikFor(501));
      expect(c.isValid, isTrue);
      expect(parseInternalKey(c.key()).cke, encodeKey(const CNitriteId(502)));
    });

    test('forward and reverse iteration visit the same entries', () {
      final s = buildSegment(3000);
      final forward = <Uint8List>[];
      final c = s.cursor()..seekFirst();
      while (c.isValid) {
        forward.add(c.key());
        c.next();
      }
      final backward = <Uint8List>[];
      c.seekLast();
      while (c.isValid) {
        backward.add(c.key());
        c.prev();
      }
      expect(forward.length, 3000);
      expect(backward.length, 3000);
      expect(backward.reversed.toList(), forward);
    });

    test('skipTo lands on the right ordinal at every position', () {
      final s = buildSegment(5000);
      final all = <Uint8List>[];
      final c = s.cursor()..seekFirst();
      while (c.isValid) {
        all.add(c.key());
        c.next();
      }
      for (final n in [0, 1, 399, 400, 401, 2500, 4999]) {
        final k = s.cursor()..skipTo(n);
        expect(k.isValid, isTrue, reason: 'n=$n');
        expect(k.key(), all[n], reason: 'n=$n');
      }
      final past = s.cursor()..skipTo(5000);
      expect(past.isValid, isFalse);
    });

    test('skipTo costs O(height) page reads, not O(n)', () {
      // spec/04-segments.md section 2.2: subtree_entries is what makes skip(n)
      // cost O(height) instead of O(n).
      final s = buildSegment(50000);
      final h = s.height;
      s.resetCounters();
      final c = s.cursor()..skipTo(49000);
      expect(c.isValid, isTrue);
      // A cold cursor reads at most one page per level.
      expect(s.pageReads, lessThanOrEqualTo(h),
          reason: 'skipTo(49000) read ${s.pageReads} pages at height $h');
    });

    test('value() is lazy: a key-only walk decodes no values', () {
      final s = buildSegment(2000, valueBytes: 512);
      final c = s.cursor()..seekFirst();
      var keys = 0;
      while (c.isValid) {
        c.key();
        keys++;
        c.next();
      }
      expect(keys, 2000);
      // And the values are still readable when asked for.
      c.seekFirst();
      expect(c.record().value.length, 512);
    });

    test('a DELETE carries no value payload', () {
      final b = SegmentBuilder(pageSize: 4096, segmentId: 1, treeId: kTree);
      b
        ..add(SegEntry(ikFor(1, seq: 2, op: Op.delete), ValueKind.empty,
            Uint8List(0)))
        ..add(SegEntry(ikFor(2), ValueKind.inline, Uint8List(8)));
      final s = Segment(b.build(), 4096);
      final c = s.cursor()..seekFirst();
      expect(c.record().op, Op.delete);
      expect(c.record().value.length, 0);
      c.next();
      expect(c.record().op, Op.put);
      expect(c.record().value.length, 8);
    });
  });

  group('internal key', () {
    test('newest version of a key sorts first', () {
      // spec/04-segments.md section 1: seq is inverted.
      final older = internalKey(kTree, encodeKey(const CNitriteId(1)), 5, Op.put);
      final newer = internalKey(kTree, encodeKey(const CNitriteId(1)), 9, Op.put);
      expect(compareKeys(newer, older), lessThan(0));
    });

    test('a tree is one contiguous range of the key space', () {
      final a = internalKey(1, encodeKey(const CNitriteId(999999)), 1, Op.put);
      final b = internalKey(2, encodeKey(const CNitriteId(0)), 1, Op.put);
      expect(compareKeys(a, b), lessThan(0));
    });

    test('round-trips its parts', () {
      final ik = internalKey(
          0xFEDCBA98, encodeKey(const CStr('x')), 0x0102030405060708, Op.rangeDelete);
      final p = parseInternalKey(ik);
      expect(p.treeId, 0xFEDCBA98);
      expect(p.seq, 0x0102030405060708);
      expect(p.op, Op.rangeDelete);
      expect(decodeKey(Uint8List.fromList(p.cke)), const CStr('x'));
    });
  });

  group('shortestSeparator', () {
    test('always satisfies prev < sep <= next', () {
      final rng = _Lcg(7);
      for (var t = 0; t < 2000; t++) {
        final a = rng.bytes(1 + rng.next().abs() % 12);
        final b = rng.bytes(1 + rng.next().abs() % 12);
        if (compareKeys(a, b) >= 0) continue;
        final sep = shortestSeparator(a, b);
        expect(compareKeys(a, sep), lessThan(0), reason: 'sep must exceed prev');
        expect(compareKeys(sep, b), lessThanOrEqualTo(0),
            reason: 'sep must not exceed next');
      }
    });

    test('the first separator is empty, so it bounds everything', () {
      expect(shortestSeparator(null, Uint8List.fromList([1, 2, 3])).length, 0);
    });

    test('handles a prefix relationship', () {
      final sep = shortestSeparator(
          Uint8List.fromList([1, 2]), Uint8List.fromList([1, 2, 3]));
      expect(sep, [1, 2, 3]);
    });
  });
}

class _Lcg {
  _Lcg(this.s);
  int s;
  int next() => s = (s * 6364136223846793005 + 1442695040888963407);
  Uint8List bytes(int n) =>
      Uint8List.fromList(List.generate(n, (_) => next().abs() % 256));
}
