/// The `cryptand.std.v1` analyzer — `spec/07-fulltext.md` §2.
///
/// §2.1 is the rule that makes this file's exactness load-bearing:
///
/// > "An implementation that **cannot reproduce the named analyzer exactly**
/// > MUST NOT write to the index... The alternative — letting each SDK tokenize
/// > with whatever its ecosystem provides — produces an index that is silently
/// > wrong in a way no checksum catches."
///
/// So the pipeline below is §2.2's eight steps in order, with nothing added and
/// nothing delegated to the host's string library. The three traps §2.2 names
/// are each handled where they arise:
///
///   * locale-sensitive lowercasing — `Simple_Lowercase_Mapping` from the
///     Unicode tables, never `String.toLowerCase()`;
///   * full case folding — not used; `ẞ` lowercases to `ß`, not to `ss`;
///   * Unicode version drift — the tables are pinned to 15.1.0 and
///     [Analyzer.unicodeVersion] reports it, so an index naming an analyzer
///     whose version this build does not have is refused rather than written.
library;

import 'errors.dart';
import 'porter2.dart';
import 'unicode.dart';
import 'unicode_tables.dart' show unicodeVersion;

/// One emitted token.
final class Token {
  const Token(this.text, this.position);

  final String text;

  /// §2.2 step 8: "the index of the segment among the segments emitted from
  /// step 3, **before filtering**".
  ///
  /// Positions therefore count dropped stopwords and over-length segments,
  /// which is what makes a phrase query mean the same thing whether or not a
  /// stopword list was configured.
  final int position;

  @override
  bool operator ==(Object other) =>
      other is Token && other.text == text && other.position == position;

  @override
  int get hashCode => Object.hash(text, position);

  @override
  String toString() => '$text@$position';
}

/// §2.4.
///
/// **The version is part of the name, and §2.4 originally did not say so.**
/// "`porter2` (Snowball) is specified because it has an unambiguous published
/// algorithm" — which is true of a given Snowball *release* and not of the name
/// alone. The algorithm's own change log records behavioural changes at 3.0.0
/// (`past`/`paste`, `universe`/`university`, `lateral`/`later`,
/// `emerge`/`emergency`, `organ`/`organic`, `-ogist` → `-og`) and at 3.1.0 —
/// and one of those *reverses* a 3.0.0 change: "Removed exception for skis",
/// then "Restored exception for skis which is needed".
///
/// Two SDKs on different Snowball releases therefore produce different stems,
/// hence different terms, hence indexes that disagree about what documents
/// exist — the exact failure §2 exists to prevent, and the one §2.2 already
/// solved for Unicode by pinning 15.1. So the stored form is
/// `porter2:<lang>:<snowball version>`.
class Stemmer {
  static const String none = 'none';

  /// The pinned form this build implements.
  static const String porter2English = 'porter2:en:$snowballVersion';

  static bool isPorter2(String s) => s.startsWith('porter2:');

  /// `(language, version)` for a `porter2:…` name, or null when unpinned.
  static (String, String)? parsePorter2(String s) {
    final parts = s.split(':');
    if (parts.length != 3 || parts[0] != 'porter2') return null;
    return (parts[1], parts[2]);
  }
}

/// The analyzer named in a full-text index descriptor.
final class Analyzer {
  Analyzer({
    this.name = std,
    List<String>? stopwords,
    this.stemmer = Stemmer.none,
    this.maxCodePoints = 64,
  }) : stopwords = {...?stopwords} {
    if (name != std) {
      // §2.5: an unregistered analyzer is unwritable and unqueryable, and the
      // implementation "says so. This is the correct failure — loud and
      // specific."
      throw UnsupportedFeatureException(
          'analyzer "$name" is not registered in this implementation; it can '
          'neither write nor query this index (spec/07-fulltext.md section 2.5)');
    }
    if (stemmer != Stemmer.none) {
      if (!Stemmer.isPorter2(stemmer)) {
        throw InvalidArgumentException(
            'stemmer "$stemmer" is neither "none" nor '
            '"porter2:<lang>:<version>" (spec/07-fulltext.md section 2.4)');
      }
      final parsed = Stemmer.parsePorter2(stemmer);
      if (parsed == null) {
        throw InvalidArgumentException(
            'stemmer "$stemmer" does not pin a Snowball version. Snowball '
            'releases stem the same word differently — 3.0.0 removed the '
            '"skis" exception and 3.1.0 restored it — so an unpinned name '
            'cannot make two SDKs agree on what terms a document has. Use '
            '"porter2:<lang>:<version>", e.g. '
            '"${Stemmer.porter2English}" (spec/07-fulltext.md section 2.4)');
      }
      if (parsed.$1 != 'en') {
        throw UnsupportedFeatureException(
            'this build implements Snowball English only; the index asks for '
            '"${parsed.$1}". Per section 2.1 an implementation that cannot '
            'reproduce the named analyzer MUST NOT write to the index');
      }
      if (parsed.$2 != snowballVersion) {
        throw UnsupportedFeatureException(
            'this build implements Snowball $snowballVersion; the index pins '
            '${parsed.$2}. Refusing it — a rule that changed between those '
            'releases would silently change what terms a document has '
            '(spec/07-fulltext.md section 2.4)');
      }
    }
  }

  /// §2.2's normative default. Every Level-2 implementation MUST implement it
  /// exactly.
  static const String std = 'cryptand.std.v1';

  final String name;

  /// §2.3: "If a stopword set is configured it is stored **in the database**,
  /// not in the implementation" — because "Nitrite ships per-language stopword
  /// lists in all three SDKs today, and they are not identical."
  final Set<String> stopwords;

  final String stemmer;

  /// §2.2 step 5.
  final int maxCodePoints;

  /// The Unicode version this build implements, §2.2.
  static String get unicodeVersionImplemented => unicodeVersion;

  /// §2.2: "Implementations MUST record the Unicode version they implement and
  /// MUST refuse to write an index whose analyzer pins a version they do not
  /// have."
  void requireUnicode(String pinned) {
    if (pinned != unicodeVersion) {
      throw UnsupportedFeatureException(
          'this build implements Unicode $unicodeVersion; the index pins '
          '$pinned. Refusing to write it — a boundary that moved between '
          'those releases would silently change what documents exist '
          '(spec/07-fulltext.md section 2.2)');
    }
  }

  /// The eight steps of §2.2.
  List<Token> analyze(String text) {
    // Step 2. (Step 1, the UTF-8 decode, is the caller's — a Dart String is
    // already decoded, and a non-string value is skipped by [analyzeValue].)
    final normalized = nfkc(text);
    final cps = normalized.runes.toList();

    // Step 3: segment, keeping only segments with at least one Alphabetic or
    // Numeric_Type != None character.
    final bounds = wordBoundaries(cps);
    final segments = <String>[];
    for (var i = 0; i + 1 < bounds.length; i++) {
      final lo = bounds[i], hi = bounds[i + 1];
      var keep = false;
      for (var j = lo; j < hi; j++) {
        if (isAlphabetic(cps[j]) || hasNumericType(cps[j])) {
          keep = true;
          break;
        }
      }
      if (keep) segments.add(String.fromCharCodes(cps.sublist(lo, hi)));
    }

    final out = <Token>[];
    for (var position = 0; position < segments.length; position++) {
      // Step 4: simple, non-tailored, locale-independent lowercasing.
      final lowered = String.fromCharCodes(
          segments[position].runes.map(simpleLowercaseMapping));

      // Step 5.
      if (lowered.runes.length > maxCodePoints) continue;

      // Step 6.
      if (stopwords.contains(lowered)) continue;

      // Step 7.
      final stemmed = _stem(lowered);
      if (stemmed.isEmpty) continue;

      // Step 8: the position is the *pre-filter* index, so dropping a stopword
      // leaves a gap rather than shifting everything after it.
      out.add(Token(stemmed, position));
    }
    return out;
  }

  /// Analyzes one field value. §2.2 step 1: "Non-string values are skipped."
  List<Token> analyzeValue(Object? value) =>
      value is String ? analyze(value) : const [];

  String _stem(String s) => stemmer == Stemmer.none ? s : porter2Stem(s);

  /// §2.3: the stored form is "sorted, NFKC, lowercased".
  static List<String> canonicalStopwords(Iterable<String> words) {
    final out = <String>{};
    for (final w in words) {
      out.add(String.fromCharCodes(nfkc(w).runes.map(simpleLowercaseMapping)));
    }
    final list = out.toList()..sort();
    return list;
  }
}
