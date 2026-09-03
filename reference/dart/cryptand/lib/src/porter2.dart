/// The Porter2 (Snowball English) stemmer — `spec/07-fulltext.md` §2.4.
///
/// §2.4 names it because "it has an unambiguous published algorithm and
/// existing implementations in every relevant language". That is true of a
/// **given Snowball release** and not of the name alone: the algorithm's own
/// change log records behavioural changes at 3.0.0 (`past`/`paste`,
/// `universe`/`university`, `lateral`/`later`, `emerge`/`emergency`,
/// `organ`/`organic`, `-ogist` → `-og`) and at 3.1.0, one of which *reverses*
/// a 3.0.0 change — "Removed exception for skis" then "Restored exception for
/// skis which is needed".
///
/// So a stemmer name without a version is exactly the hazard §2.2 already
/// solved for Unicode, and [snowballVersion] is this implementation's answer:
/// the release is pinned, reported, and checked.
///
/// Implemented from the Snowball source published at
/// <https://snowballstem.org/algorithms/english/stemmer.html> and verified
/// against the project's own 42 649-word vocabulary in
/// `test/porter2_test.dart`.
library;

/// The Snowball release this implementation reproduces.
const String snowballVersion = '3.1.0';

const String _vowels = 'aeiouy';

bool _isVowel(int c) => _vowels.codeUnitAt(0) == c ||
    c == 0x61 || c == 0x65 || c == 0x69 || c == 0x6F || c == 0x75 || c == 0x79;

/// `v_WXY` = vowels plus `w`, `x`, `Y`. A "non-v_WXY" is anything outside it.
bool _isVowelOrWXY(int c) =>
    _isVowel(c) || c == 0x77 /* w */ || c == 0x78 /* x */ || c == 0x59 /* Y */;

/// `valid_LI` — `cdeghkmnrt`.
bool _isValidLi(int c) =>
    c == 0x63 || c == 0x64 || c == 0x65 || c == 0x67 || c == 0x68 ||
    c == 0x6B || c == 0x6D || c == 0x6E || c == 0x72 || c == 0x74;

const List<String> _doubles = ['bb', 'dd', 'ff', 'gg', 'mm', 'nn', 'pp', 'rr', 'tt'];

/// The `exception1` table: whole words that bypass the algorithm entirely.
const Map<String, String> _exception1 = {
  'skis': 'ski',
  'skies': 'sky',
  'idly': 'idl',
  'gently': 'gentl',
  'ugly': 'ugli',
  'early': 'earli',
  'only': 'onli',
  'singly': 'singl',
  // Invariant forms: not plural, and not to be stemmed.
  'sky': 'sky',
  'news': 'news',
  'howe': 'howe',
  'atlas': 'atlas',
  'cosmos': 'cosmos',
  'bias': 'bias',
  'andes': 'andes',
};

/// Prefixes after which R1 begins immediately, to stop over-stemming.
///
/// The classic case is `gener`: without this, generate/general/generic/
/// generous all collapse to `gener`. 3.0.0 and 3.1.0 added the rest.
const List<String> _r1Exceptions = [
  'gener', 'commun', 'arsen', 'past', 'univers', 'later', 'emerg', 'organ',
  'inter',
];

/// Stems [word] with Snowball English [snowballVersion].
///
/// The input is expected already lowercased — `spec/07-fulltext.md` §2.2 runs
/// the stemmer at step 7, after step 4's `Simple_Lowercase_Mapping`.
String porter2Stem(String word) {
  final exception = _exception1[word];
  if (exception != null) return exception;
  if (word.length < 3) return word;

  var w = _prelude(word);
  final regions = _markRegions(w);
  final p1 = regions.$1, p2 = regions.$2;

  w = _step1a(w);
  w = _step1b(w, p1);
  w = _step1c(w);
  w = _step2(w, p1);
  w = _step3(w, p1, p2);
  w = _step4(w, p2);
  w = _step5(w, p1, p2);

  // Postlude: turn any remaining Y back into y.
  return w.replaceAll('Y', 'y');
}

/// Remove a leading apostrophe; mark an initial `y`, and any `y` after a
/// vowel, as `Y` so it counts as a consonant for the rest of the algorithm.
String _prelude(String word) {
  var w = word;
  if (w.startsWith("'")) w = w.substring(1);
  if (w.isEmpty) return w;
  final u = w.codeUnits.toList();
  if (u[0] == 0x79) u[0] = 0x59;
  for (var i = 1; i < u.length; i++) {
    if (u[i] == 0x79 && _isVowel(u[i - 1])) u[i] = 0x59;
  }
  return String.fromCharCodes(u);
}

/// The index after the first non-vowel that follows a vowel, from [start],
/// or -1 when there is none.
int _afterVowelThenNonVowel(String w, int start) {
  var i = start;
  while (i < w.length && !_isVowel(w.codeUnitAt(i))) {
    i++;
  }
  while (i < w.length && _isVowel(w.codeUnitAt(i))) {
    i++;
  }
  return i < w.length ? i + 1 : -1;
}

(int, int) _markRegions(String w) {
  var p1 = w.length, p2 = w.length;
  int cursor;
  final pre = _r1Exceptions.where(w.startsWith).toList();
  if (pre.isNotEmpty) {
    cursor = pre.first.length;
  } else {
    cursor = _afterVowelThenNonVowel(w, 0);
    if (cursor < 0) return (p1, p2);
  }
  p1 = cursor;
  final second = _afterVowelThenNonVowel(w, cursor);
  if (second >= 0) p2 = second;
  return (p1, p2);
}

/// A short syllable at the end of the word.
bool _endsShortSyllable(String w) {
  if (w.endsWith('past')) return true;
  final n = w.length;
  if (n >= 3) {
    final a = w.codeUnitAt(n - 3), b = w.codeUnitAt(n - 2), c = w.codeUnitAt(n - 1);
    if (!_isVowel(a) && _isVowel(b) && !_isVowelOrWXY(c)) return true;
  }
  if (n == 2) {
    return _isVowel(w.codeUnitAt(0)) && !_isVowel(w.codeUnitAt(1));
  }
  return false;
}

/// "A word is called short if it ends in a short syllable, and if R1 is null."
bool _isShort(String w, int p1) => p1 >= w.length && _endsShortSyllable(w);

String _step1a(String w) {
  // Step 0, folded in as the Snowball source does: the longest of ' 's 's'.
  for (final s in ["'s'", "'s", "'"]) {
    if (w.endsWith(s)) {
      w = w.substring(0, w.length - s.length);
      break;
    }
  }

  if (w.endsWith('sses')) return '${w.substring(0, w.length - 4)}ss';
  if (w.endsWith('ied') || w.endsWith('ies')) {
    final stem = w.substring(0, w.length - 3);
    // "replace by i if preceded by more than one letter, otherwise by ie
    //  (so ties -> tie, cries -> cri)"
    return stem.length > 1 ? '${stem}i' : '${stem}ie';
  }
  if (w.endsWith('us') || w.endsWith('ss')) return w;
  if (w.endsWith('s')) {
    // "delete if the preceding word part contains a vowel not immediately
    //  before the s (so gas and this retain the s, gaps and kiwis lose it)"
    for (var i = 0; i + 2 < w.length; i++) {
      if (_isVowel(w.codeUnitAt(i))) return w.substring(0, w.length - 1);
    }
  }
  return w;
}

String _step1b(String w, int p1) {
  for (final s in ['eedly', 'eed']) {
    if (w.endsWith(s)) {
      final start = w.length - s.length;
      if (start < p1) return w; // not in R1
      final before = w.substring(0, start);
      // 3.0.0: proceed/exceed/succeed are not past participles.
      if (before == 'proc' || before == 'exc' || before == 'succ') return w;
      return '${before}ee';
    }
  }

  String? suffix;
  for (final s in ['ingly', 'edly', 'ing', 'ed']) {
    if (w.endsWith(s)) {
      suffix = s;
      break;
    }
  }
  if (suffix == null) return w;

  if (suffix == 'ing') {
    final before = w.substring(0, w.length - 3);
    // dying -> die, lying -> lie, tying -> tie, vying -> vie.
    if (before.length == 2 &&
        before.codeUnitAt(1) == 0x79 &&
        !_isVowel(before.codeUnitAt(0))) {
      return '${before.substring(0, 1)}ie';
    }
    // Leave inning, outing, canning, herring, earring, evening alone.
    if (const ['inn', 'out', 'cann', 'herr', 'earr', 'even'].contains(before)) {
      return w;
    }
  }

  final stem = w.substring(0, w.length - suffix.length);
  var hasVowel = false;
  for (var i = 0; i < stem.length; i++) {
    if (_isVowel(stem.codeUnitAt(i))) {
      hasVowel = true;
      break;
    }
  }
  if (!hasVowel) return w;

  if (stem.endsWith('at') || stem.endsWith('bl') || stem.endsWith('iz')) {
    return '${stem}e';
  }
  for (final d in _doubles) {
    if (stem.endsWith(d)) {
      // 3.0.0: "Don't undouble if preceded by exactly a, e or o" — so add,
      // egg and off are unchanged while hopp becomes hop.
      if (stem.length == 3) {
        final c = stem.codeUnitAt(0);
        if (c == 0x61 || c == 0x65 || c == 0x6F) return stem;
      }
      return stem.substring(0, stem.length - 1);
    }
  }
  if (_isShort(stem, p1)) return '${stem}e';
  return stem;
}

String _step1c(String w) {
  final n = w.length;
  if (n < 3) return w;
  final last = w.codeUnitAt(n - 1);
  if (last != 0x79 && last != 0x59) return w;
  if (_isVowel(w.codeUnitAt(n - 2))) return w;
  // "not the first letter of the word"
  if (n - 2 == 0) return w;
  return '${w.substring(0, n - 1)}i';
}

/// Longest-suffix replacement within a region.
String? _replaceIn(String w, int region, List<(String, String)> table) {
  for (final (suffix, replacement) in table) {
    if (!w.endsWith(suffix)) continue;
    final start = w.length - suffix.length;
    if (start < region) return w; // matched, but not in the region: stop
    return w.substring(0, start) + replacement;
  }
  return null;
}

String _step2(String w, int p1) {
  const table = <(String, String)>[
    ('ational', 'ate'), ('fulness', 'ful'), ('ousness', 'ous'),
    ('iveness', 'ive'), ('ization', 'ize'), ('lessli', 'less'),
    ('tional', 'tion'), ('biliti', 'ble'), ('ousli', 'ous'),
    ('entli', 'ent'), ('ation', 'ate'), ('alism', 'al'), ('aliti', 'al'),
    ('iviti', 'ive'), ('fulli', 'ful'), ('ogist', 'og'),
    ('enci', 'ence'), ('anci', 'ance'), ('abli', 'able'), ('izer', 'ize'),
    ('ator', 'ate'), ('alli', 'al'), ('bli', 'ble'),
  ];
  final r = _replaceIn(w, p1, table);
  if (r != null) return r;

  if (w.endsWith('ogi')) {
    final start = w.length - 3;
    if (start < p1) return w;
    // "replace by og if preceded by l"
    if (start > 0 && w.codeUnitAt(start - 1) == 0x6C) {
      return '${w.substring(0, start)}og';
    }
    return w;
  }
  if (w.endsWith('li')) {
    final start = w.length - 2;
    if (start < p1) return w;
    if (start > 0 && _isValidLi(w.codeUnitAt(start - 1))) {
      return w.substring(0, start);
    }
  }
  return w;
}

String _step3(String w, int p1, int p2) {
  const table = <(String, String)>[
    ('ational', 'ate'), ('tional', 'tion'), ('alize', 'al'),
    ('icate', 'ic'), ('iciti', 'ic'), ('ical', 'ic'),
    ('ness', ''), ('ful', ''),
  ];
  final r = _replaceIn(w, p1, table);
  if (r != null) return r;

  if (w.endsWith('ative')) {
    final start = w.length - 5;
    if (start < p1) return w;
    // "delete if in R2"
    if (start >= p2) return w.substring(0, start);
  }
  return w;
}

String _step4(String w, int p2) {
  const table = <(String, String)>[
    ('ement', ''), ('able', ''), ('ible', ''), ('ance', ''), ('ence', ''),
    ('ment', ''), ('ant', ''), ('ent', ''), ('ism', ''), ('ate', ''),
    ('iti', ''), ('ous', ''), ('ive', ''), ('ize', ''),
    ('al', ''), ('er', ''), ('ic', ''),
  ];
  final r = _replaceIn(w, p2, table);
  if (r != null) return r;

  if (w.endsWith('ion')) {
    final start = w.length - 3;
    if (start < p2) return w;
    if (start > 0) {
      final c = w.codeUnitAt(start - 1);
      if (c == 0x73 /* s */ || c == 0x74 /* t */) return w.substring(0, start);
    }
  }
  return w;
}

String _step5(String w, int p1, int p2) {
  if (w.endsWith('e')) {
    final start = w.length - 1;
    // "delete if in R2, or in R1 and not preceded by a short syllable"
    if (start >= p2) return w.substring(0, start);
    if (start >= p1 && !_endsShortSyllable(w.substring(0, start))) {
      return w.substring(0, start);
    }
    return w;
  }
  if (w.endsWith('l')) {
    final start = w.length - 1;
    if (start >= p2 && start > 0 && w.codeUnitAt(start - 1) == 0x6C) {
      return w.substring(0, start);
    }
  }
  return w;
}
