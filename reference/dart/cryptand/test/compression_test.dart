/// `spec/01-container.md` section 7 — per-page compression.
///
/// This file exists because section 7 was implemented in **no write path in
/// any of the three reference implementations**, while `12-profiles.md`
/// section 1 names `page_codec = LZ4` for every profile and section 7 calls LZ4
/// "the default and the only codec a Level-0 implementation MUST support".
/// Rust had a correct LZ4 and an `encode_data_page` nothing called; Java could
/// decompress and never compressed; Dart had no LZ4 at all and **ignored the
/// `COMPRESSED` flag entirely**, so a conforming file from either of the others
/// was silently mis-decoded.
///
/// It is the same shape as defect 58 (page encryption absent from both
/// implementations while every test passed), and it carries the same lesson:
/// **test what is in the bytes, not what the API returns.** A page round-trips
/// perfectly when it is not compressed, so the round-trip test proves nothing
/// on its own and the tests below check the stored page.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/cow.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/lz4.dart';
import 'package:test/test.dart';

/// A page-sized payload that compresses well, shaped like the documents this
/// format actually holds: repeated field names and short values.
Uint8List _documentish(int n) {
  final b = BytesBuilder();
  var i = 0;
  while (b.length < n) {
    b.add(Uint8List.fromList(
        '{"_id":${i++},"name":"widget","kind":"tool","qty":7}'.codeUnits));
  }
  return Uint8List.sublistView(b.toBytes(), 0, n);
}

/// Bytes no codec can shrink. A page of these must be stored as it is, not
/// stored larger.
Uint8List _incompressible(int n, [int seed = 1]) {
  final r = Random(seed);
  return Uint8List.fromList(List.generate(n, (_) => r.nextInt(256)));
}

/// The shared vectors of `reference/conformance/vectors/codec/lz4.json`.
///
/// This is what makes section 7 portable rather than merely implemented: a
/// fourth SDK checks itself against these bytes without either of the other
/// three being present.
Map<String, dynamic> _vectors() => jsonDecode(
        File('../../conformance/vectors/codec/lz4.json').readAsStringSync())
    as Map<String, dynamic>;

Uint8List _unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

void main() {
  // ------------------------------------------------------------------
  // The shared vectors. Only the DECODER is normative: any conforming LZ4
  // block decompresses to the same output whatever produced it, so a reader is
  // checked against these and a writer is not.
  // ------------------------------------------------------------------
  group('conformance/vectors/codec/lz4', () {
    final v = _vectors();

    test('every recorded block decodes to its recorded plaintext', () {
      final cases = v['cases'] as List;
      expect(cases.length, greaterThan(8),
          reason: 'a vector file that shrank silently measures nothing');
      for (final c in cases.cast<Map<String, dynamic>>()) {
        final plain = _unhex(c['plain'] as String);
        expect(plain.length, c['plain_len'],
            reason: 'the vector disagrees with itself: ${c['note']}');
        expect(lz4Decompress(_unhex(c['lz4'] as String), plain.length), plain,
            reason: c['note'] as String);
      }
    });

    test('this implementation also produces a block the vector can check', () {
      // The writer is free, so the assertion is not byte equality: it is that
      // what this compressor emits decodes to the same plaintext.
      for (final c in (v['cases'] as List).cast<Map<String, dynamic>>()) {
        final plain = _unhex(c['plain'] as String);
        expect(lz4Decompress(lz4Compress(plain), plain.length), plain,
            reason: c['note'] as String);
      }
    });

    test('every block the vector says to refuse is refused', () {
      final cases = (v['refuse'] as Map)['cases'] as List;
      expect(cases, isNotEmpty);
      for (final c in cases.cast<Map<String, dynamic>>()) {
        expect(
            () => lz4Decompress(
                _unhex(c['lz4'] as String), c['plain_len'] as int),
            throwsA(isA<CorruptionException>()),
            reason: c['why'] as String);
      }
    });

    test('the 12.5 % threshold matches the recorded cases', () {
      for (final c in ((v['threshold'] as Map)['cases'] as List)
          .cast<Map<String, dynamic>>()) {
        expect(worthCompressing(c['raw'] as int, c['compressed'] as int),
            c['worth'], reason: "${c['raw']} -> ${c['compressed']}");
      }
    });
  });

  // ------------------------------------------------------------------
  // The block codec on its own.
  // ------------------------------------------------------------------
  group('LZ4 block', () {
    test('round-trips every shape, including the degenerate lengths', () {
      final shapes = <Uint8List>[
        Uint8List(0),
        Uint8List.fromList([0x41]),
        Uint8List.fromList(List.filled(4, 0x41)),
        // 11, 12 and 13 straddle the end-of-block guard, which is where an
        // off-by-one in the compressor's limit lands.
        for (final n in [11, 12, 13, 16, 17])
          Uint8List.fromList(List.filled(n, 0x41)),
        Uint8List.fromList(List.filled(4056, 0x41)),
        _documentish(4056),
        _incompressible(4056),
        // A long run, which is the case that exercises an overlapping match.
        Uint8List.fromList(List.generate(4056, (i) => (i ~/ 64) % 3)),
        // A short period, so the matcher finds a match at every position.
        Uint8List.fromList(List.generate(4056, (i) => i % 7)),
      ];
      for (final src in shapes) {
        final block = lz4Compress(src);
        final back = lz4Decompress(block, src.length);
        expect(back, src, reason: 'length ${src.length}');
      }
    });

    test('an overlapping match is a run, and must not be a block copy', () {
      // LZ4 encodes a run as a match whose offset is smaller than its length,
      // so the copy has to be byte at a time. A `setRange` here decodes to the
      // wrong bytes without failing anything.
      final src = Uint8List.fromList(List.filled(1000, 0x5A));
      final block = lz4Compress(src);
      expect(block.length, lessThan(64), reason: 'a run must compress hard');
      expect(lz4Decompress(block, src.length), src);
    });

    test('it actually compresses what it claims to', () {
      final src = _documentish(4056);
      expect(lz4Compress(src).length, lessThan(src.length ~/ 2));
      expect(worthCompressing(src.length, lz4Compress(src).length), isTrue);
    });

    test('an incompressible page is not worth compressing', () {
      final src = _incompressible(4056);
      // The compressor may still emit something; the 12.5 % rule is what stops
      // it being *stored*.
      expect(worthCompressing(src.length, lz4Compress(src).length), isFalse);
    });

    test('the 12.5 % rule is exactly section 7 arithmetic', () {
      expect(worthCompressing(4096, 3584), isTrue, reason: 'saves exactly 1/8');
      expect(worthCompressing(4096, 3585), isFalse, reason: 'one byte short');
      expect(worthCompressing(4096, 4096), isFalse);
      expect(worthCompressing(0, 0), isTrue);
    });
  });

  // ------------------------------------------------------------------
  // Untrusted input. `spec/14-security.md` section 9: a decompressor is the
  // classic place to write past the end of a buffer on a crafted length, and
  // every one of these is a byte string an attacker can put in a file.
  // ------------------------------------------------------------------
  group('a crafted block is refused, never trusted', () {
    test('literals that overrun the source', () {
      // token says 15+ literals, continuation says 255 more, and the block
      // ends immediately.
      expect(() => lz4Decompress(Uint8List.fromList([0xF0, 0xFF]), 4096),
          throwsA(isA<CorruptionException>()));
    });

    test('literals that overrun the destination', () {
      final src = Uint8List.fromList([0x50, 1, 2, 3, 4, 5]);
      expect(() => lz4Decompress(src, 2), throwsA(isA<CorruptionException>()));
    });

    test('a match offset pointing before the start of the output', () {
      // 0 literals, then offset 0x0010 with nothing decoded yet.
      expect(() => lz4Decompress(Uint8List.fromList([0x0F, 0x10, 0x00, 0x00]), 64),
          throwsA(isA<CorruptionException>()));
    });

    test('a match offset of zero', () {
      expect(
          () => lz4Decompress(
              Uint8List.fromList([0x10, 0x41, 0x00, 0x00]), 64),
          throwsA(isA<CorruptionException>()));
    });

    test('a match length that overruns the output', () {
      // one literal, then a match of 4 + 15 + 255 + ... past the end
      expect(
          () => lz4Decompress(
              Uint8List.fromList([0x1F, 0x41, 0x01, 0x00, 0xFF, 0xFF, 0x00]), 8),
          throwsA(isA<CorruptionException>()));
    });

    test('a block that decodes to the wrong length is refused', () {
      final src = _documentish(1000);
      final block = lz4Compress(src);
      expect(() => lz4Decompress(block, 999),
          throwsA(isA<CorruptionException>()));
      expect(() => lz4Decompress(block, 1001),
          throwsA(isA<CorruptionException>()));
    });

    test('truncation at every length is refused or decoded, never a crash', () {
      final block = lz4Compress(_documentish(2000));
      for (var cut = 0; cut < block.length; cut++) {
        try {
          lz4Decompress(Uint8List.sublistView(block, 0, cut), 2000);
          fail('a truncated block decoded to the full length at cut $cut');
        } on CorruptionException {
          // the only acceptable outcome
        }
      }
    });

    test('a bit flipped anywhere is refused or wrong, never out of bounds', () {
      final block = lz4Compress(_documentish(2000));
      var refused = 0;
      var decoded = 0;
      for (var i = 0; i < block.length; i++) {
        for (final bit in [0x01, 0x80]) {
          final bad = Uint8List.fromList(block)..[i] ^= bit;
          try {
            lz4Decompress(bad, 2000);
            decoded++;
          } on CorruptionException {
            refused++;
          }
        }
      }
      expect(refused + decoded, block.length * 2,
          reason: 'every mutation must end in one of the two, and nothing else');
      expect(refused, greaterThan(0),
          reason: 'if nothing is ever refused the checks are not running');
    });
  });

  // ------------------------------------------------------------------
  // The page seam. These are the tests defect 58 says to write: look at the
  // stored bytes, because a page round-trips perfectly when nothing happened.
  // ------------------------------------------------------------------
  group('the page seam', () {
    PageStore storeWith(int codec) =>
        PageStore(pageSize: 4096)..pageCodec = codec;

    Uint8List pageOf(Uint8List payload, {int extentPages = 1}) {
      final page = Uint8List(4096);
      page.setRange(PageHeader.size, PageHeader.size + payload.length, payload);
      PageHeader(
        pageType: PageType.btreeLeaf,
        treeId: 17,
        commitId: 1,
        extentPages: extentPages,
        payloadLen: payload.length,
      ).writeInto(page);
      return page;
    }

    test('a compressible page is STORED compressed, and says so', () {
      final store = storeWith(Codec.lz4);
      final id = store.alloc();
      final payload = _documentish(4000);
      store.write(id, pageOf(payload));

      // The stored bytes, not the decoded ones.
      final stored = store.readClear(id);
      final h = PageHeader.read(stored, pageId: id);
      expect(h.isCompressed, isTrue, reason: 'the flag must be set');
      expect(h.codecOrReserved, Codec.lz4, reason: 'and it must name the codec');
      expect(h.payloadLen, payload.length,
          reason: 'payload_len keeps section 3 meaning: uncompressed length');
      expect(h.storedLen, lessThan(payload.length),
          reason: 'stored_len is what the page actually holds');
      expect(h.storedLen, greaterThan(0));

      // The repetitions are gone. Not all of them: LZ4 emits the first
      // occurrence as *literals* and encodes only the repeats as matches, so
      // exactly one copy survives verbatim. Compression is not
      // confidentiality -- that is what section 5.2 is for -- and asserting
      // the needle is absent would be asserting something false.
      expect(_count(stored, '"name":"widget"'.codeUnits), 1,
          reason: 'the literal survives once; every repeat must be a match');
      expect(_count(pageOf(payload), '"name":"widget"'.codeUnits),
          greaterThan(50),
          reason: 'the control: uncompressed, the page holds it many times');

      // The read path gives back exactly what went in, with a clean header.
      final back = store.read(id);
      final bh = PageHeader.read(back, pageId: id);
      expect(bh.isCompressed, isFalse,
          reason: 'the header a caller sees describes the plaintext');
      expect(bh.storedLen, 0);
      expect(Uint8List.sublistView(back, PageHeader.size,
              PageHeader.size + payload.length),
          payload);
    });

    test('with the codec off, nothing is compressed', () {
      final store = storeWith(Codec.none);
      final id = store.alloc();
      final payload = _documentish(4000);
      store.write(id, pageOf(payload));
      final h = PageHeader.read(store.readClear(id), pageId: id);
      expect(h.isCompressed, isFalse);
      expect(_count(store.readClear(id), '"name":"widget"'.codeUnits),
          greaterThan(50),
          reason: 'the control: without the codec every copy IS there, so the '
              'test above is measuring the codec and not something else');
    });

    test('an incompressible page is stored as it is, never larger', () {
      final store = storeWith(Codec.lz4);
      final id = store.alloc();
      final payload = _incompressible(4000);
      store.write(id, pageOf(payload));
      final h = PageHeader.read(store.readClear(id), pageId: id);
      expect(h.isCompressed, isFalse,
          reason: 'section 7: only if compression saves >= 12.5 %');
      expect(store.read(id).sublist(PageHeader.size, PageHeader.size + 4000),
          payload);
    });

    test('a page inside a multi-page extent is never compressed', () {
      // An extent is a contiguous byte range whose reader may parse pages at
      // fixed offsets rather than fetching them one at a time -- which one of
      // the three implementations does. Compressing a page inside one moves
      // every byte after its header without telling that reader, and the
      // failure shows up as "segment header magic mismatch" in the *other*
      // language, several steps later. This is the test for that.
      final store = storeWith(Codec.lz4);
      final id = store.allocExtent(3);
      final payload = _documentish(4000);
      store.write(id, pageOf(payload, extentPages: 3));
      final h = PageHeader.read(store.readClear(id), pageId: id);
      expect(h.isCompressed, isFalse,
          reason: 'extent_pages > 1 means the payload is not this page alone');
    });

    test('writeExtent never compresses, whatever the header says', () {
      // The guard above is on the header; this one is on the call path,
      // because `writeExtent` routing through `write` is exactly how it was
      // got wrong, and an interior page carries extent_pages = 1.
      final store = storeWith(Codec.lz4);
      final start = store.allocExtent(2);
      final extent = Uint8List(2 * 4096)
        ..setRange(0, 4096, pageOf(_documentish(4000), extentPages: 2))
        ..setRange(4096, 8192, pageOf(_documentish(4000)));
      store.writeExtent(start, extent);
      for (var i = 0; i < 2; i++) {
        final h = PageHeader.read(store.readClear(start + i), pageId: start + i);
        expect(h.isCompressed, isFalse, reason: 'page $i of the extent');
      }
    });

    test('a value-log head page is never compressed', () {
      // Section 6.2 appends records into the head page's own tail, so its
      // bytes are not a payload that can be rewritten.
      final store = storeWith(Codec.lz4);
      final id = store.alloc();
      final page = Uint8List(4096);
      final payload = _documentish(64);
      page.setRange(PageHeader.size, PageHeader.size + payload.length, payload);
      PageHeader(
        pageType: PageType.vlogSegment,
        treeId: 0,
        commitId: 1,
        payloadLen: payload.length,
      ).writeInto(page);
      store.write(id, page);
      expect(PageHeader.read(store.readClear(id), pageId: id).isCompressed,
          isFalse);
    });

    test('an unknown codec id on a page is refused, not guessed at', () {
      final store = storeWith(Codec.lz4);
      final id = store.alloc();
      final payload = _documentish(4000);
      store.write(id, pageOf(payload));
      // Rewrite the header with a codec nobody defines.
      final stored = store.readClear(id);
      final h = PageHeader.read(stored, pageId: id);
      PageHeader(
        pageType: h.pageType,
        flags: h.flags,
        codecOrReserved: 77,
        treeId: h.treeId,
        commitId: h.commitId,
        extentPages: h.extentPages,
        payloadLen: h.payloadLen,
        storedLen: h.storedLen,
      ).writeInto(stored);
      store.writeClear(id, stored);
      expect(() => store.read(id), throwsA(isA<CryptandException>()));
    });
  });

  // ------------------------------------------------------------------
  // The read path must not rot now that no profile writes a compressed page.
  //
  // `01-container.md` section 7 keeps `page_codec` at 0 in every profile,
  // because a compressed page occupies the same fixed-size slot and saves
  // nothing -- measured identical in bytes to device, page count and file
  // size. That makes the *reader* the part with no natural exercise: nothing
  // this implementation writes will produce a compressed page again, so the
  // only thing standing between a conforming file from another SDK and
  // "cell pointers overrun the payload" is a test that writes one on purpose.
  //
  // Which is exactly the defect that started all of this.
  // ------------------------------------------------------------------
  group('no profile writes one, and the reader still decodes one', () {
    test('every profile defaults page_codec to 0', () {
      for (final p in Profile.values) {
        expect(p.pageCodec, Codec.none,
            reason: '${p.name} defaults to a page codec that saves nothing');
      }
    });

    test('a compressed page is decoded by a reader whose default is 0', () {
      final store = PageStore(pageSize: 4096)..pageCodec = Codec.lz4;
      final id = store.alloc();
      final payload = _documentish(4000);
      final page = Uint8List(4096)
        ..setRange(PageHeader.size, PageHeader.size + payload.length, payload);
      PageHeader(
        pageType: PageType.btreeLeaf,
        treeId: 17,
        commitId: 1,
        extentPages: 1,
        payloadLen: payload.length,
      ).writeInto(page);
      store.write(id, page);
      expect(PageHeader.read(store.readClear(id), pageId: id).isCompressed, isTrue,
          reason: 'the fixture must actually be compressed, or this proves nothing');

      // The read path must consult the *page's* own flag and never the
      // reader's default -- which is the whole of section 7's "a file may
      // hold a mixture".
      store.pageCodec = Codec.none;
      expect(
          Uint8List.sublistView(
              store.read(id), PageHeader.size, PageHeader.size + payload.length),
          payload,
          reason: 'a reader whose default is 0 must still decode a compressed page');
    });
  });

  // ------------------------------------------------------------------
  // The space claim. Section 7 exists to make files smaller; a test that only
  // proves correctness lets the benefit quietly go to zero.
  // ------------------------------------------------------------------
  group('it is worth doing', () {
    test('a page of document-shaped bytes stores in under half a page', () {
      final store = PageStore(pageSize: 4096)..pageCodec = Codec.lz4;
      final id = store.alloc();
      final payload = _documentish(4000);
      final page = Uint8List(4096)
        ..setRange(PageHeader.size, PageHeader.size + payload.length, payload);
      PageHeader(
        pageType: PageType.btreeLeaf,
        treeId: 17,
        commitId: 1,
        extentPages: 1,
        payloadLen: payload.length,
      ).writeInto(page);
      store.write(id, page);
      final stored = PageHeader.read(store.readClear(id), pageId: id).storedLen;
      expect(stored, lessThan(payload.length ~/ 2),
          reason: 'stored $stored of ${payload.length} bytes');
    });
  });
}

int _count(Uint8List haystack, List<int> needle) {
  var n = 0;
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    n++;
  }
  return n;
}
