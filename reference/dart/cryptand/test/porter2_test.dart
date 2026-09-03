/// The Porter2 stemmer — `spec/07-fulltext.md` §2.4.
///
/// The headline test is the whole published vocabulary. §2.4 chose Snowball
/// because "it has an unambiguous published algorithm and existing
/// implementations in every relevant language", and the way to hold an
/// implementation to that is the algorithm's own 42 649-word corpus, not a
/// handful of examples.
library;

import 'dart:io';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

const String kDir = '../../conformance/snowball';

void main() {
  group('the published Snowball vocabulary', () {
    test('all 42 649 words stem exactly as Snowball says they must', () {
      final voc = File('$kDir/voc-3.1.0.txt').readAsLinesSync();
      final out = File('$kDir/output-3.1.0.txt').readAsLinesSync();
      expect(voc.length, out.length);
      expect(voc.length, greaterThan(42000));

      var failures = 0;
      final examples = <String>[];
      for (var i = 0; i < voc.length; i++) {
        final w = voc[i].trim();
        if (w.isEmpty) continue;
        final got = porter2Stem(w);
        if (got != out[i].trim()) {
          failures++;
          if (examples.length < 5) {
            examples.add('$w -> $got, want ${out[i].trim()}');
          }
        }
      }
      expect(failures, 0, reason: examples.join('; '));
    });
  });

  group('the version is part of the algorithm, section 2.4', () {
    test('the Snowball release is pinned and reported', () {
      expect(snowballVersion, '3.1.0');
      expect(Stemmer.porter2English, 'porter2:en:3.1.0');
    });

    test('the 3.0.0 behavioural changes are present', () {
      // Every one of these is a documented change at Snowball 3.0.0, and each
      // is a word that stems differently on an earlier release. They are the
      // evidence that "porter2" alone does not pin behaviour.
      expect(porter2Stem('past'), 'past');
      expect(porter2Stem('paste'), 'paste', reason: 'not conflated with past');
      expect(porter2Stem('universe'), 'univers');
      expect(porter2Stem('university'), 'universiti',
          reason: 'not conflated with universe');
      expect(porter2Stem('lateral'), 'lateral');
      expect(porter2Stem('later'), 'later');
      expect(porter2Stem('emerge'), 'emerg');
      expect(porter2Stem('emergency'), 'emergenc');
      expect(porter2Stem('organ'), 'organ');
      expect(porter2Stem('organic'), 'organic');
      expect(porter2Stem('geologist'), 'geolog', reason: '-ogist -> -og');
      expect(porter2Stem('evening'), 'evening', reason: 'not "even"');
    });

    test('the 3.1.0 changes are present, including the reversal', () {
      // 3.0.0 removed the skis exception; 3.1.0 restored it. A stemmer name
      // without a version cannot distinguish the two.
      expect(porter2Stem('skis'), 'ski');
      // 3.1.0 added the R1 exception for words starting "inter".
      expect(porter2Stem('inter'), 'inter');
      // The point of the exception: internal must NOT collapse to intern.
      // With R1 starting after "inter", neither "al" nor "n" is removable.
      expect(porter2Stem('internal'), 'internal');
      expect(porter2Stem('intern'), 'intern');
    });

    test('the R1 prefix exceptions stop the classic over-stemming', () {
      // The gener case, from the algorithm's own worked example.
      expect(porter2Stem('generate'), 'generat');
      expect(porter2Stem('generates'), 'generat');
      expect(porter2Stem('generating'), 'generat');
      expect(porter2Stem('general'), 'general');
      expect(porter2Stem('generally'), 'general');
      expect(porter2Stem('generic'), 'generic');
      expect(porter2Stem('generous'), 'generous');
    });
  });

  group('the documented worked examples', () {
    test('step 1a', () {
      expect(porter2Stem('ties'), 'tie');
      expect(porter2Stem('cries'), 'cri');
      expect(porter2Stem('gas'), 'gas');
      expect(porter2Stem('this'), 'this');
      expect(porter2Stem('gaps'), 'gap');
      expect(porter2Stem('kiwis'), 'kiwi');
    });

    test('step 1b, including the undoubling exceptions', () {
      // The chapter's worked example is the INTERMEDIATE after step 1b —
      // "luxuriat -> luxuriate" — which later steps then reduce, since "ate"
      // is in R2. The published vocabulary is the authority on the final form.
      expect(porter2Stem('luxuriate'), 'luxuri');
      expect(porter2Stem('luxuriated'), 'luxuri');
      expect(porter2Stem('hopping'), 'hop');
      expect(porter2Stem('hoping'), 'hope');
      // add, egg and off are not undoubled.
      expect(porter2Stem('adding'), 'add');
      expect(porter2Stem('egged'), 'egg');
      // dying -> die, and herring is left alone.
      expect(porter2Stem('dying'), 'die');
      expect(porter2Stem('lying'), 'lie');
      expect(porter2Stem('tying'), 'tie');
      expect(porter2Stem('herring'), 'herring');
      expect(porter2Stem('inning'), 'inning');
      // proceed / exceed / succeed are not past participles.
      expect(porter2Stem('proceed'), 'proceed');
      expect(porter2Stem('exceed'), 'exceed');
      expect(porter2Stem('succeed'), 'succeed');
      expect(porter2Stem('agreed'), 'agre');
    });

    test('step 1c leaves short words alone', () {
      expect(porter2Stem('cry'), 'cri');
      expect(porter2Stem('by'), 'by');
      expect(porter2Stem('say'), 'say');
    });

    test('the exception table bypasses the algorithm', () {
      expect(porter2Stem('skies'), 'sky');
      expect(porter2Stem('idly'), 'idl');
      expect(porter2Stem('gently'), 'gentl');
      expect(porter2Stem('ugly'), 'ugli');
      expect(porter2Stem('early'), 'earli');
      expect(porter2Stem('only'), 'onli');
      expect(porter2Stem('singly'), 'singl');
      for (final invariant in ['sky', 'news', 'howe', 'atlas', 'cosmos',
                               'bias', 'andes']) {
        expect(porter2Stem(invariant), invariant);
      }
    });

    test('a word of two letters or fewer is left as is', () {
      for (final w in ['a', 'an', 'be', 'it', '']) {
        expect(porter2Stem(w), w);
      }
    });
  });

  group('in the analyzer', () {
    test('stemming happens at step 7, after lowercasing', () {
      final a = Analyzer(stemmer: Stemmer.porter2English);
      expect(a.analyze('RUNNING quickly').map((t) => t.text).toList(),
          ['run', 'quick']);
    });

    test('a stopword is dropped before the stemmer sees it', () {
      // Section 2.2 order: step 6 drops stopwords, step 7 stems.
      final a = Analyzer(
          stopwords: ['the'], stemmer: Stemmer.porter2English);
      final t = a.analyze('the running dogs');
      expect(t.map((x) => x.text).toList(), ['run', 'dog']);
      expect(t.map((x) => x.position).toList(), [1, 2],
          reason: 'positions still count the dropped stopword');
    });

    test('an index and a query stem the same way', () {
      // Section 3: "A query string is analyzed with the same analyzer and
      // params as the index" -- which is what makes stemming useful at all.
      final a = Analyzer(stemmer: Stemmer.porter2English);
      expect(a.analyze('connections').single.text,
          a.analyze('connected').single.text);
    });
  });
}
