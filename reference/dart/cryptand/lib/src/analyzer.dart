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
class Stemmer {
  static const String none = 'none';

  /// §2.4: "`porter2` (Snowball) is specified because it has an unambiguous
  /// published algorithm and existing implementations in every relevant
  /// language."
  static bool isPorter2(String s) => s.startsWith('porter2:');
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
    if (stemmer != Stemmer.none && !Stemmer.isPorter2(stemmer)) {
      throw InvalidArgumentException(
          'stemmer "$stemmer" is neither "none" nor "porter2:<lang>" '
          '(spec/07-fulltext.md section 2.4)');
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

  String _stem(String s) {
    if (stemmer == Stemmer.none) return s;
    // §2.4 names porter2 as the only specified stemmer. Implementing it is a
    // separate published algorithm; declaring it unimplemented is the honest
    // state, and §2.1's rule then applies — this analyzer configuration is
    // neither writable nor queryable here.
    throw UnsupportedFeatureException(
        'stemmer "$stemmer" is specified but not implemented in this build; '
        'per spec/07-fulltext.md section 2.1 an implementation that cannot '
        'reproduce the named analyzer MUST NOT write to the index');
  }

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
