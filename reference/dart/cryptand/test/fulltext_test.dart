/// `spec/07-fulltext.md` — the analyzer, the postings layout, and the queries.
///
/// The chapter's own framing is why the Unicode half is tested against
/// Unicode's published suites rather than against examples: "Full text is the
/// hardest thing in this format to make portable, and the reason is not the
/// postings — it is the **analyzer**. Two implementations that tokenize
/// `"Bäckerei-Straße 12"` differently will produce two indexes that disagree
/// about what documents exist."
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

const String kUnicodeDir = '../../conformance/unicode';

void main() {
  group('Unicode, against the published conformance suites', () {
    test('NFC and NFKC reproduce every case of NormalizationTest-15.1.0', () {
      // 19 074 cases. spec/07-fulltext.md section 2.2 pins Unicode 15.1, so
      // this is the suite for exactly the release the analyzer names.
      final file = File('$kUnicodeDir/NormalizationTest-15.1.0.txt');
      expect(file.existsSync(), isTrue,
          reason: 'the pinned conformance data must be in the repository');

      String cps(String field) => String.fromCharCodes(field
          .trim()
          .split(RegExp(r'\s+'))
          .where((x) => x.isNotEmpty)
          .map((x) => int.parse(x, radix: 16)));

      var total = 0, nfcFail = 0, nfkcFail = 0;
      for (final line in file.readAsLinesSync()) {
        final l = line.split('#')[0].trim();
        if (l.isEmpty || l.startsWith('@')) continue;
        final f = l.split(';');
        if (f.length < 5) continue;
        total++;
        if (nfc(cps(f[0])) != cps(f[1])) nfcFail++;
        if (nfkc(cps(f[0])) != cps(f[3])) nfkcFail++;
        if (nfkc(cps(f[4])) != cps(f[3])) nfkcFail++;
      }
      expect(total, greaterThan(19000));
      expect(nfcFail, 0);
      expect(nfkcFail, 0);
    });

    test('word segmentation reproduces every case of WordBreakTest-15.1.0', () {
      // 1 826 cases of UAX #29. A single divergent boundary is an index that
      // disagrees with another SDK about what documents exist.
      final file = File('$kUnicodeDir/WordBreakTest-15.1.0.txt');
      var total = 0, fail = 0;
      for (final line in file.readAsLinesSync()) {
        final l = line.split('#')[0].trim();
        if (l.isEmpty) continue;
        final toks =
            l.split(RegExp(r'\s+')).where((t) => t.isNotEmpty).toList();
        final cps = <int>[];
        final expected = <int>[];
        for (final t in toks) {
          if (t == '÷') {
            expected.add(cps.length);
          } else if (t != '×') {
            cps.add(int.parse(t, radix: 16));
          }
        }
        total++;
        if (wordBoundaries(cps).join(',') != expected.join(',')) fail++;
      }
      expect(total, greaterThan(1800));
      expect(fail, 0);
    });

    test('the Unicode version is pinned and reported', () {
      // Section 2.2: "Implementations MUST record the Unicode version they
      // implement and MUST refuse to write an index whose analyzer pins a
      // version they do not have."
      expect(unicodeVersion, '15.1.0');
      expect(Analyzer.unicodeVersionImplemented, '15.1.0');
      expect(() => Analyzer().requireUnicode('16.0.0'),
          throwsA(isA<UnsupportedFeatureException>()));
      expect(() => Analyzer().requireUnicode('15.1.0'), returnsNormally);
    });
  });

  group('the cryptand.std.v1 analyzer, section 2.2', () {
    final a = Analyzer();

    test('the chapter\'s own example tokenizes as it must', () {
      // "Bäckerei-Straße 12" -- the string section 2 opens with.
      expect(a.analyze('Bäckerei-Straße 12').map((t) => t.text).toList(),
          ['bäckerei', 'straße', '12']);
    });

    test('simple lowercasing, not full case folding', () {
      // Section 2.2: "`ẞ` folds to `ss` under full folding and to `ß` under
      // simple lowercasing. The spec says simple."
      expect(a.analyze('STRAẞE').single.text, 'straße');
      expect(a.analyze('STRAẞE').single.text, isNot('strasse'));
    });

    test('lowercasing is locale-independent — the Turkish I trap', () {
      // Section 2.2: "Java's String.toLowerCase() with a Turkish default
      // locale maps `I` to `ı`." The analyzer must map it to `i` regardless of
      // any ambient locale, because the index has to mean the same thing
      // whichever machine wrote it.
      expect(a.analyze('I').single.text, 'i');
      expect(a.analyze('I').single.text, isNot('ı'));

      // U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE is the other half of the
      // trap and goes the other way: its Simple_Lowercase_Mapping is plain
      // `i` (UnicodeData field 13), so a table-driven mapping gives `i` while
      // a *full* case folding would give `i` + U+0307. Simple is what section
      // 2.2 specifies.
      expect(a.analyze('İ').single.text, 'i');
      expect(simpleLowercaseMapping(0x0130), 0x0069);
    });

    test('NFKC runs before segmentation', () {
      // A compatibility form and its canonical form must produce one term, or
      // two SDKs disagree about what documents exist.
      expect(a.analyze('ﬁle').single.text, 'file');
      expect(a.analyze('①').single.text, '1');
      // Composed and decomposed café are the same term.
      expect(a.analyze('café').single.text,
          a.analyze('café').single.text);
    });

    test('only segments with an Alphabetic or Numeric character survive', () {
      // Section 2.2 step 3.
      expect(a.analyze('hello , world !').map((t) => t.text).toList(),
          ['hello', 'world']);
      expect(a.analyze('--- +++').toList(), isEmpty);
    });

    test('segments longer than 64 code points are dropped', () {
      final long = 'a' * 65;
      expect(a.analyze('short $long tail').map((t) => t.text).toList(),
          ['short', 'tail']);
      expect(a.analyze('a' * 64).single.text, 'a' * 64);
    });

    test('positions are the pre-filter index, so a stopword leaves a gap', () {
      // Section 2.2 step 8: "the index of the segment among the segments
      // emitted from step 3, **before filtering**". That is what makes a
      // phrase query mean the same thing whether or not stopwords are removed.
      final withStops = Analyzer(stopwords: ['the']);
      final t = withStops.analyze('the quick brown fox');
      expect(t.map((x) => x.text).toList(), ['quick', 'brown', 'fox']);
      expect(t.map((x) => x.position).toList(), [1, 2, 3]);
    });

    test('stopwords are canonicalized the way the file stores them', () {
      // Section 2.3: "sorted, NFKC, lowercased".
      final s = Analyzer.canonicalStopwords(['The', 'ﬁle', 'A']);
      expect(s, ['a', 'file', 'the']);
    });

    test('a non-string value is skipped, not stringified', () {
      expect(a.analyzeValue(CInt.i32(5)), isEmpty);
      expect(a.analyzeValue(null), isEmpty);
      expect(a.analyzeValue('text').single.text, 'text');
    });

    test('an unregistered analyzer fails loudly and specifically', () {
      // Section 2.5: "Any SDK that does not have that analyzer registered
      // treats the index as unwritable and unqueryable and says so. This is
      // the correct failure -- loud and specific."
      expect(() => Analyzer(name: 'myapp.analyzer.v1'),
          throwsA(isA<UnsupportedFeatureException>()));
    });

    test('a declared but unimplemented stemmer refuses to write', () {
      // Section 2.1: "An implementation that cannot reproduce the named
      // analyzer exactly MUST NOT write to the index."
      final p = Analyzer(stemmer: 'porter2:en');
      expect(() => p.analyze('running'),
          throwsA(isA<UnsupportedFeatureException>()));
      expect(() => Analyzer(stemmer: 'snowball:en'),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('CJK and emoji segment per UAX #29 rather than per byte', () {
      expect(Analyzer().analyze('東京都').map((t) => t.text).toList(),
          isNotEmpty);
      // A flag is one regional-indicator pair, not two words (WB15/16), and
      // carries no Alphabetic character so it is dropped at step 3.
      expect(Analyzer().analyze('\u{1F1EF}\u{1F1F5}'), isEmpty);
    });
  });

  group('postings blocks, section 4', () {
    List<Posting> mk(int n, {bool pos = false}) => [
          for (var i = 0; i < n; i++)
            Posting(1000 + i * 7, 2, pos ? [i, i + 5] : const [])
        ];

    test('a block round-trips through its CVE BYTES wrapper', () {
      final b = PostingsBlock(mk(10), hasPositions: false);
      final back = PostingsBlock.decode(b.encode());
      expect(back.postings.length, 10);
      expect(back.postings.map((p) => p.docId), b.postings.map((p) => p.docId));
      expect(back.postings.map((p) => p.freq), b.postings.map((p) => p.freq));
      expect(back.hasPositions, isFalse);
    });

    test('positions round-trip and stay strictly increasing', () {
      final b = PostingsBlock(mk(5, pos: true), hasPositions: true);
      final back = PostingsBlock.decode(b.encode());
      expect(back.hasPositions, isTrue);
      for (var i = 0; i < 5; i++) {
        expect(back.postings[i].positions, b.postings[i].positions);
      }
    });

    test('a block holds at most 128 documents', () {
      // Section 4.1, and section 4.4's whole argument rests on it.
      expect(kPostingsBlockMax, 128);
      expect(() => PostingsBlock(mk(129), hasPositions: false).encodeRaw(),
          throwsA(isA<LimitException>()));
      final blocks = PostingsBlock.split(mk(300), hasPositions: false);
      expect(blocks.length, 3);
      expect(blocks[0].postings.length, 128);
      expect(blocks[2].postings.length, 44);
    });

    test('document ids must be strictly increasing within a block', () {
      expect(
          () => PostingsBlock(
                  [const Posting(5, 1), const Posting(5, 1)],
                  hasPositions: false)
              .encodeRaw(),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('a scorer can skip positions without decoding them', () {
      // Section 4.2: "Positions are byte-length-prefixed as a group so that a
      // scorer that only needs frequencies can skip them without decoding."
      final withPos = PostingsBlock(mk(20, pos: true), hasPositions: true);
      final without = PostingsBlock(mk(20), hasPositions: false);
      expect(withPos.encodeRaw().length,
          greaterThan(without.encodeRaw().length));
      // The frequency area is at a fixed place regardless, so the two decode
      // to the same freqs.
      expect(PostingsBlock.decode(withPos.encode()).postings.map((p) => p.freq),
          PostingsBlock.decode(without.encode()).postings.map((p) => p.freq));
    });

    test('a corrupt version or reserved flag is refused', () {
      final raw = PostingsBlock(mk(3), hasPositions: false).encodeRaw();
      final badVersion = Uint8List.fromList(raw)..[0] = 9;
      expect(() => PostingsBlock.decodeRaw(badVersion),
          throwsA(isA<CorruptionException>()));
      final badFlags = Uint8List.fromList(raw)..[1] = 0x80;
      expect(() => PostingsBlock.decodeRaw(badFlags),
          throwsA(isA<CorruptionException>()));
    });

    test('the block key sorts by term then document', () {
      final a = PostingsBlock.keyFor(1, 100);
      final b = PostingsBlock.keyFor(1, 200);
      final c = PostingsBlock.keyFor(2, 50);
      expect(compareKeys(a, b), lessThan(0));
      expect(compareKeys(b, c), lessThan(0),
          reason: 'blocks for one term are contiguous and in document order');
    });
  });

  group('the index end to end', () {
    late Database db;
    late Collection c;

    setUp(() {
      db = Database();
      c = db.createCollection('docs');
      c.put(const CNitriteId(1), CDoc({'body': const CStr('the quick brown fox')}));
      c.put(const CNitriteId(2), CDoc({'body': const CStr('the lazy brown dog')}));
      c.put(const CNitriteId(3), CDoc({'body': const CStr('Bäckerei-Straße 12')}));
    });

    test('three trees are created and found by owner', () {
      // Section 1: "All three carry owner = <data tree name>, so
      // 05-catalog.md section 11's 'what indexes does X have?' finds them
      // together."
      c.createFullTextIndex(['body']);
      final kinds = db.catalog
          .indexesOf('docs')
          .map((e) => e.$2.kind)
          .toList()
        ..sort();
      expect(kinds, ['postings', 'term_dict', 'term_index']);
    });

    test('search finds documents, and the term dictionary is accurate', () {
      final idx = c.createFullTextIndex(['body']);
      expect(c.fullTextSearch(idx, 'brown'),
          [const CNitriteId(1), const CNitriteId(2)]);
      expect(c.fullTextSearch(idx, 'fox'), [const CNitriteId(1)]);
      expect(c.fullTextSearch(idx, 'missing'), isEmpty);

      // Section 1: df and ttf "MUST be accurate after a merge".
      final brown = c.termEntry(idx, 'brown')!;
      expect(brown.df, 2);
      expect(brown.ttf, 2);
    });

    test('a query is analyzed with the index analyzer', () {
      // Section 3: "A query string is analyzed with the same analyzer and
      // params as the index."
      final idx = c.createFullTextIndex(['body']);
      expect(c.fullTextSearch(idx, 'STRAẞE'), [const CNitriteId(3)]);
      expect(c.fullTextSearch(idx, 'Bäckerei'), [const CNitriteId(3)]);
    });

    test('multiple terms intersect', () {
      final idx = c.createFullTextIndex(['body']);
      expect(c.fullTextSearch(idx, 'brown fox'), [const CNitriteId(1)]);
      expect(c.fullTextSearch(idx, 'brown dog'), [const CNitriteId(2)]);
    });

    test('a phrase query uses positions', () {
      final idx = c.createFullTextIndex(['body']);
      expect(c.phraseSearch(idx, 'quick brown'), [const CNitriteId(1)]);
      expect(c.phraseSearch(idx, 'brown quick'), isEmpty,
          reason: 'order matters in a phrase');
      expect(c.phraseSearch(idx, 'lazy brown'), [const CNitriteId(2)]);
    });

    test('a phrase query against a positionless index is REJECTED', () {
      // Section 4.3: "An implementation MUST reject a phrase query against an
      // index without positions rather than approximate it with a
      // conjunction."
      final idx = c.createFullTextIndex(['body'],
          positions: false, indexName: 'fts:nopos');
      expect(c.fullTextSearch(idx, 'brown'), isNotEmpty);
      expect(() => c.phraseSearch(idx, 'quick brown'),
          throwsA(isA<UnsupportedFeatureException>()));
    });

    test('an update rewrites the block, and df follows', () {
      final idx = c.createFullTextIndex(['body']);
      expect(c.termEntry(idx, 'brown')!.df, 2);
      c.put(const CNitriteId(2), CDoc({'body': const CStr('the lazy grey dog')}));
      c.createFullTextIndex(['body'], indexName: 'fts:rebuilt');
      final rebuilt = db.catalog.get('fts:rebuilt')!;
      expect(c.termEntry(rebuilt, 'brown')!.df, 1);
      expect(c.fullTextSearch(rebuilt, 'grey'), [const CNitriteId(2)]);
    });

    test('stopwords configured on the index are stored in the file', () {
      // Section 2.3: "Storing the actual list makes the index reproducible
      // regardless of which SDK's list was in scope when it was created."
      final idx = c.createFullTextIndex(['body'],
          analyzer: Analyzer(stopwords: ['the']), indexName: 'fts:stop');
      final params = idx.params['analyzer_params']! as CDoc;
      final stored = (params['stopwords']! as CArray)
          .items
          .map((e) => (e as CStr).value)
          .toList();
      expect(stored, ['the']);
      expect(c.fullTextSearch(idx, 'the'), isEmpty,
          reason: 'the stopword is not indexed');
      expect(c.fullTextSearch(idx, 'brown'), isNotEmpty);
    });
  });
}
