import 'dart:typed_data';

import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

List<Uint8List> keySet(int from, int to) => [
      for (var i = from; i < to; i++)
        userKeyPrefix(17, encodeKey(CNitriteId(1767225600000 * 4194304 + i)))
    ];

void main() {
  group('structure, exactly as section 2.4 states it', () {
    test('k is derived as round(bits * ln 2), clamped to 1..16', () {
      // The spec spells out the four values the profile table produces.
      expect(probesFor(10), 7);
      expect(probesFor(12), 8);
      expect(probesFor(14), 10);
      expect(probesFor(16), 11);
      expect(probesFor(1), 1);
      expect(probesFor(64), 16, reason: 'clamped');
    });

    test('block_count is ceil(entries * bits / 512), at least 1', () {
      expect(blockCountFor(0, 16), 1);
      expect(blockCountFor(32, 16), 1); // 32*16 = 512 bits exactly
      expect(blockCountFor(33, 16), 2);
      expect(blockCountFor(1000000, 10), (1000000 * 10 + 511) ~/ 512);
    });

    test('a block is 512 bits, so a probe reads one 64-byte line', () {
      expect(kBlockBits, 512);
      expect(kBlockBytes, 64);
    });

    test('every inserted key is found: no false negatives, ever', () {
      // This is the property whose violation loses data.
      for (final bits in [10, 12, 14, 16]) {
        final keys = keySet(0, 20000);
        final f = BlockedBloom.build(keys,
            bitsPerKey: bits, distinctKeys: keys.length);
        for (final k in keys) {
          expect(f.mayContain(k), isTrue,
              reason: 'false negative at $bits bits/key');
        }
      }
    });

    test('all probes land inside one block', () {
      // Block selection depends only on h1, and the probe sequence is taken
      // mod 512, so a probe never leaves its block. A filter that spilled
      // across blocks would still "work" but would read two cache lines.
      final keys = keySet(0, 5000);
      final f =
          BlockedBloom.build(keys, bitsPerKey: 16, distinctKeys: keys.length);
      var touched = 0;
      for (var b = 0; b < f.blockCount; b++) {
        var any = false;
        for (var i = 0; i < kBlockBytes; i++) {
          if (f.blocks[b * kBlockBytes + i] != 0) any = true;
        }
        if (any) touched++;
      }
      expect(touched, greaterThan(0));
      expect(f.blocks.length, f.blockCount * kBlockBytes);
    });
  });

  group('page encoding', () {
    test('round-trips through its page payload', () {
      final keys = keySet(0, 3000);
      final f =
          BlockedBloom.build(keys, bitsPerKey: 16, distinctKeys: keys.length);
      final back = BlockedBloom.decodePayload(f.encodePayload());
      expect(back.blockCount, f.blockCount);
      expect(back.probes, f.probes);
      expect(back.bitsPerKey, f.bitsPerKey);
      expect(back.distinctKeys, f.distinctKeys);
      for (final k in keys) {
        expect(back.mayContain(k), isTrue);
      }
    });

    test('probes is read from the page, not recomputed', () {
      // Section 2.4: "a reader MUST use this value, not recompute it", so a
      // future minor version can change the derivation without invalidating
      // files already written.
      final keys = keySet(0, 100);
      final f =
          BlockedBloom.build(keys, bitsPerKey: 16, distinctKeys: keys.length);
      final payload = f.encodePayload();
      // probes sits at offset 10 as a u16.
      final bd = ByteData.view(payload.buffer, payload.offsetInBytes);
      expect(bd.getUint16(10, Endian.little), 11);
      bd.setUint16(10, 3, Endian.little);
      expect(BlockedBloom.decodePayload(payload).probes, 3);
    });

    test('a truncated or mislabelled filter page is corruption', () {
      final keys = keySet(0, 100);
      final f =
          BlockedBloom.build(keys, bitsPerKey: 16, distinctKeys: keys.length);
      final payload = f.encodePayload();
      expect(
          () => BlockedBloom.decodePayload(
              Uint8List.sublistView(payload, 0, payload.length - 10)),
          throwsA(isA<CorruptionException>()));
      final badMagic = Uint8List.fromList(payload)..[0] = 0;
      expect(() => BlockedBloom.decodePayload(badMagic),
          throwsA(isA<CorruptionException>()));
    });

    test('pages tile the payload and each carries a valid header', () {
      final keys = keySet(0, 200000);
      final f =
          BlockedBloom.build(keys, bitsPerKey: 16, distinctKeys: keys.length);
      final pages = f.encodePages(4096);
      expect(pages.length, greaterThan(1));
      final rejoined = <int>[];
      for (var i = 0; i < pages.length; i++) {
        final h = PageHeaderProbe.read(pages[i], i);
        expect(h.type, 6, reason: 'SEGMENT_FILTER');
        rejoined.addAll(
            pages[i].sublist(40, 40 + h.payloadLen));
      }
      expect(rejoined.length, f.encodePayload().length);
      expect(Uint8List.fromList(rejoined), f.encodePayload());
    });
  });

  group('false-positive rate against the rates section 2.4 predicts', () {
    // "L0 and tiered levels | 16 | ~0.04 %" and "last level | 10 | ~1 %".
    //
    // These are measurements of the *hash* this reference uses, which is not
    // XXH3-64. If the measured rates match the predicted ones, the spec's
    // read-tail arithmetic (section 4.1) holds for this hash too, which is
    // what REPORT.md's recommendation rests on.
    double falsePositiveRate(int bits, int n, int trials) {
      final present = keySet(0, n);
      final f =
          BlockedBloom.build(present, bitsPerKey: bits, distinctKeys: n);
      var hits = 0;
      // Probe with keys that are definitely absent: a disjoint id range.
      for (var i = 0; i < trials; i++) {
        final k = userKeyPrefix(
            17, encodeKey(CNitriteId(-1 - i * 7919)));
        if (f.mayContain(k)) hits++;
      }
      return hits / trials;
    }

    test('16 bits per key is at or below the predicted 0.04 %', () {
      final r = falsePositiveRate(16, 100000, 200000);
      printOnFailure('measured ${(r * 100).toStringAsFixed(4)} %');
      expect(r, lessThan(0.002),
          reason: 'measured ${(r * 100).toStringAsFixed(4)} %, '
              'section 2.4 predicts ~0.04 %');
    });

    test('10 bits per key is at or below the predicted 1 %', () {
      final r = falsePositiveRate(10, 100000, 200000);
      printOnFailure('measured ${(r * 100).toStringAsFixed(4)} %');
      expect(r, lessThan(0.02),
          reason: 'measured ${(r * 100).toStringAsFixed(4)} %, '
              'section 2.4 predicts ~1 %');
    });
  });
}

/// Minimal page-header probe, so this test does not depend on container.dart's
/// full parse path.
class PageHeaderProbe {
  PageHeaderProbe(this.type, this.payloadLen);
  final int type;
  final int payloadLen;
  static PageHeaderProbe read(Uint8List page, int index) {
    final bd = ByteData.view(page.buffer, page.offsetInBytes, page.length);
    return PageHeaderProbe(bd.getUint8(4), bd.getUint32(24, Endian.little));
  }
}
