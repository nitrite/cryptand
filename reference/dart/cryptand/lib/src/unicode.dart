/// The Unicode operations `spec/07-fulltext.md` §2.2 requires, at the version
/// it pins.
///
/// The chapter's first sentence is why this file exists: "Full text is the
/// hardest thing in this format to make portable, and the reason is not the
/// postings — it is the **analyzer**. Two implementations that tokenize
/// `"Bäckerei-Straße 12"` differently will produce two indexes that disagree
/// about what documents exist."
///
/// Dart's standard library supplies none of NFKC, UAX #29 word segmentation, or
/// `Simple_Lowercase_Mapping`. `String.toLowerCase` is close but not the same
/// thing, and "close" is exactly what produces two indexes that disagree. So
/// all three are implemented here against generated Unicode 15.1 tables, and
/// verified against Unicode's own published conformance suites —
/// `NormalizationTest.txt` and `WordBreakTest.txt` — in
/// `test/unicode_test.dart`.
library;

import 'unicode_tables.dart';

/// Word_Break property values, UAX #29.
class WB {
  static final Map<String, int> _byName = {
    for (var i = 0; i < wbNames.length; i++) wbNames[i]: i
  };

  static int of(String name) => _byName[name]!;

  static final int aLetter = of('ALetter');
  static final int cr = of('CR');
  static final int doubleQuote = of('Double_Quote');
  static final int extend = of('Extend');
  static final int extendNumLet = of('ExtendNumLet');
  static final int format = of('Format');
  static final int hebrewLetter = of('Hebrew_Letter');
  static final int katakana = of('Katakana');
  static final int lf = of('LF');
  static final int midLetter = of('MidLetter');
  static final int midNum = of('MidNum');
  static final int midNumLet = of('MidNumLet');
  static final int newline = of('Newline');
  static final int numeric = of('Numeric');
  static final int regionalIndicator = of('Regional_Indicator');
  static final int singleQuote = of('Single_Quote');
  static final int wSegSpace = of('WSegSpace');
  static final int zwj = of('ZWJ');

  /// Anything with no Word_Break property.
  static const int other = -1;
}

/// Binary search over a flat `(lo, hi, value)` triple table.
int _lookup3(List<int> table, int cp, int fallback) {
  var lo = 0, hi = table.length ~/ 3 - 1;
  while (lo <= hi) {
    final mid = (lo + hi) >> 1;
    final s = table[mid * 3], e = table[mid * 3 + 1];
    if (cp < s) {
      hi = mid - 1;
    } else if (cp > e) {
      lo = mid + 1;
    } else {
      return table[mid * 3 + 2];
    }
  }
  return fallback;
}

/// Binary search over a flat `(lo, hi)` pair table.
bool _inRanges(List<int> table, int cp) {
  var lo = 0, hi = table.length ~/ 2 - 1;
  while (lo <= hi) {
    final mid = (lo + hi) >> 1;
    if (cp < table[mid * 2]) {
      hi = mid - 1;
    } else if (cp > table[mid * 2 + 1]) {
      lo = mid + 1;
    } else {
      return true;
    }
  }
  return false;
}

/// Binary search over a flat `(key, value)` pair table.
int _lookupMap(List<int> table, int cp, int fallback) {
  var lo = 0, hi = table.length ~/ 2 - 1;
  while (lo <= hi) {
    final mid = (lo + hi) >> 1;
    final k = table[mid * 2];
    if (cp < k) {
      hi = mid - 1;
    } else if (cp > k) {
      lo = mid + 1;
    } else {
      return table[mid * 2 + 1];
    }
  }
  return fallback;
}

int wordBreakProperty(int cp) => _lookup3(wbRanges, cp, WB.other);
bool isExtendedPictographic(int cp) => _inRanges(extendedPictographic, cp);

/// The step-3 filter of §2.2: "keeping only segments that contain at least one
/// character with the Unicode property Alphabetic or Numeric_Type != None".
bool isAlphabetic(int cp) => _inRanges(alphabetic, cp);
bool hasNumericType(int cp) => _inRanges(numericType, cp);

int combiningClass(int cp) => _lookupMap(cccMap, cp, 0);

/// `Simple_Lowercase_Mapping`, §2.2 step 4.
///
/// **Not** full case folding and **not** a locale-sensitive `toLowerCase()`.
/// §2.2 names both traps: Java's `toLowerCase()` under a Turkish locale maps
/// `I` to `ı`, and full folding maps `ẞ` to `ss` where simple lowercasing maps
/// it to `ß`.
int simpleLowercaseMapping(int cp) => _lookupMap(simpleLowercase, cp, cp);

// ---------------------------------------------------------------------------
// Normalization — NFKC
// ---------------------------------------------------------------------------

const int _sBase = 0xAC00, _lBase = 0x1100, _vBase = 0x1161, _tBase = 0x11A7;
const int _lCount = 19, _vCount = 21, _tCount = 28;
const int _nCount = _vCount * _tCount, _sCount = _lCount * _nCount;

/// Index into [decompFlat] for [cp], or -1.
///
/// The flat table is sorted by code point but its entries are variable length,
/// so an offset index is built once rather than scanned per lookup.
int _decompIndex(int cp) => _decompOffsets[cp] ?? -1;

final Map<int, int> _decompOffsets = () {
  final m = <int, int>{};
  var i = 0;
  while (i < decompFlat.length) {
    m[decompFlat[i]] = i;
    i += 3 + decompFlat[i + 2];
  }
  return m;
}();

/// Canonical composition pairs, `(first << 21) | second` → composed.
///
/// A canonical decomposition forms a composition pair unless the character is
/// a composition exclusion, is a singleton decomposition, or has a non-starter
/// first character — the three exclusions of UAX #15.
final Map<int, int> _compositions = () {
  final m = <int, int>{};
  var i = 0;
  while (i < decompFlat.length) {
    final cp = decompFlat[i];
    final compat = decompFlat[i + 1] == 1;
    final len = decompFlat[i + 2];
    if (!compat && len == 2) {
      final a = decompFlat[i + 3], b = decompFlat[i + 4];
      if (_lookupMap(compositionExclusions, cp, 0) == 0 &&
          combiningClass(a) == 0) {
        m[(a << 21) | b] = cp;
      }
    }
    i += 3 + len;
  }
  return m;
}();

void _decomposeInto(int cp, bool compat, List<int> out) {
  // Hangul is algorithmic, not tabular.
  if (cp >= _sBase && cp < _sBase + _sCount) {
    final s = cp - _sBase;
    out.add(_lBase + s ~/ _nCount);
    out.add(_vBase + (s % _nCount) ~/ _tCount);
    final t = s % _tCount;
    if (t != 0) out.add(_tBase + t);
    return;
  }
  final idx = _decompIndex(cp);
  if (idx < 0) {
    out.add(cp);
    return;
  }
  final isCompat = decompFlat[idx + 1] == 1;
  if (isCompat && !compat) {
    out.add(cp);
    return;
  }
  final len = decompFlat[idx + 2];
  for (var k = 0; k < len; k++) {
    _decomposeInto(decompFlat[idx + 3 + k], compat, out);
  }
}

/// Canonical ordering: a stable sort of each run of non-starters by
/// combining class.
void _canonicalOrder(List<int> cps) {
  for (var i = 1; i < cps.length; i++) {
    final ccc = combiningClass(cps[i]);
    if (ccc == 0) continue;
    var j = i;
    while (j > 0) {
      final prev = combiningClass(cps[j - 1]);
      if (prev == 0 || prev <= ccc) break;
      final t = cps[j];
      cps[j] = cps[j - 1];
      cps[j - 1] = t;
      j--;
    }
  }
}

/// Canonical composition, UAX #15.
///
/// The classic algorithm: walk the decomposed string keeping the position of
/// the last starter, and compose into it whenever the next character is not
/// *blocked* — blocked meaning some character between them has a combining
/// class greater than or equal to its own.
List<int> _compose(List<int> cps) {
  if (cps.isEmpty) return cps;
  final buf = [...cps];
  var starterPos = 0;
  var starterCh = buf[0];
  var lastClass = combiningClass(starterCh);
  if (lastClass != 0) lastClass = 256; // nothing composes onto a non-starter
  var compPos = 1;

  for (var decompPos = 1; decompPos < buf.length; decompPos++) {
    final ch = buf[decompPos];
    final chClass = combiningClass(ch);
    final composite = _composePair(starterCh, ch);
    if (composite != null && (lastClass < chClass || lastClass == 0)) {
      buf[starterPos] = composite;
      starterCh = composite;
    } else {
      if (chClass == 0) {
        starterPos = compPos;
        starterCh = ch;
      }
      lastClass = chClass;
      buf[compPos++] = ch;
    }
  }
  return buf.sublist(0, compPos);
}

int? _composePair(int a, int b) {
  // Hangul, algorithmic.
  final lIndex = a - _lBase;
  if (lIndex >= 0 && lIndex < _lCount) {
    final vIndex = b - _vBase;
    if (vIndex >= 0 && vIndex < _vCount) {
      return _sBase + (lIndex * _vCount + vIndex) * _tCount;
    }
  }
  final sIndex = a - _sBase;
  if (sIndex >= 0 && sIndex < _sCount && sIndex % _tCount == 0) {
    final tIndex = b - _tBase;
    if (tIndex > 0 && tIndex < _tCount) return a + tIndex;
  }
  return _compositions[(a << 21) | b];
}

/// NFKC, §2.2 step 2.
String nfkc(String s) => _normalize(s, compat: true);

/// NFC, for completeness and because the conformance suite exercises both.
String nfc(String s) => _normalize(s, compat: false);

String _normalize(String s, {required bool compat}) {
  final cps = <int>[];
  for (final cp in s.runes) {
    _decomposeInto(cp, compat, cps);
  }
  _canonicalOrder(cps);
  return String.fromCharCodes(_compose(cps));
}

// ---------------------------------------------------------------------------
// UAX #29 word segmentation
// ---------------------------------------------------------------------------

bool _isIgnorable(int p) =>
    p == WB.extend || p == WB.format || p == WB.zwj;

bool _isAHLetter(int p) => p == WB.aLetter || p == WB.hebrewLetter;
bool _isMidNumLetQ(int p) => p == WB.midNumLet || p == WB.singleQuote;

/// Word boundaries per UAX #29, at the Unicode version [unicodeVersion] pins.
///
/// Returns the code-point offsets at which a word boundary occurs, always
/// including 0 and `cps.length` (rules WB1 and WB2).
///
/// Rule WB4 — "X (Extend | Format | ZWJ)* → X" — is why the left- and
/// right-context helpers below skip those three properties: after WB1–WB3d
/// have had their say on the raw characters, every remaining rule sees the
/// string as though the ignorable characters were not there.
List<int> wordBoundaries(List<int> cps) {
  final n = cps.length;
  if (n == 0) return [0];
  final props = [for (final c in cps) wordBreakProperty(c)];

  /// The nearest non-ignorable index at or before [i], or -1. The walk stops
  /// at a hard line break, because WB3a/WB3b have already broken there and
  /// WB4 must not reach across it.
  int prevNI(int i) {
    var j = i;
    while (j >= 0) {
      final p = props[j];
      if (!_isIgnorable(p)) return j;
      if (p == WB.newline || p == WB.cr || p == WB.lf) return j;
      j--;
    }
    return -1;
  }

  /// The nearest non-ignorable index at or after [i], or -1.
  int nextNI(int i) {
    var j = i;
    while (j < n) {
      if (!_isIgnorable(props[j])) return j;
      j++;
    }
    return -1;
  }

  bool breakAt(int i) {
    final a = props[i - 1], b = props[i];

    // WB3: CR × LF
    if (a == WB.cr && b == WB.lf) return false;
    // WB3a: (Newline | CR | LF) ÷
    if (a == WB.newline || a == WB.cr || a == WB.lf) return true;
    // WB3b: ÷ (Newline | CR | LF)
    if (b == WB.newline || b == WB.cr || b == WB.lf) return true;
    // WB3c: ZWJ × \p{Extended_Pictographic}
    if (a == WB.zwj && isExtendedPictographic(cps[i])) return false;
    // WB3d: WSegSpace × WSegSpace
    if (a == WB.wSegSpace && b == WB.wSegSpace) return false;
    // WB4: X (Extend | Format | ZWJ)* → X
    if (_isIgnorable(b)) return false;

    final li = prevNI(i - 1);
    if (li < 0) return true;
    final l = props[li];
    final l2i = li > 0 ? prevNI(li - 1) : -1;
    final l2 = l2i >= 0 ? props[l2i] : WB.other;
    final ri = nextNI(i + 1);
    final r = ri >= 0 ? props[ri] : WB.other;

    // WB5
    if (_isAHLetter(l) && _isAHLetter(b)) return false;
    // WB6
    if (_isAHLetter(l) &&
        (b == WB.midLetter || _isMidNumLetQ(b)) &&
        _isAHLetter(r)) {
      return false;
    }
    // WB7
    if (_isAHLetter(b) &&
        (l == WB.midLetter || _isMidNumLetQ(l)) &&
        _isAHLetter(l2)) {
      return false;
    }
    // WB7a
    if (l == WB.hebrewLetter && b == WB.singleQuote) return false;
    // WB7b
    if (l == WB.hebrewLetter &&
        b == WB.doubleQuote &&
        r == WB.hebrewLetter) {
      return false;
    }
    // WB7c
    if (l == WB.doubleQuote &&
        b == WB.hebrewLetter &&
        l2 == WB.hebrewLetter) {
      return false;
    }
    // WB8
    if (l == WB.numeric && b == WB.numeric) return false;
    // WB9
    if (_isAHLetter(l) && b == WB.numeric) return false;
    // WB10
    if (l == WB.numeric && _isAHLetter(b)) return false;
    // WB11
    if (b == WB.numeric &&
        (l == WB.midNum || _isMidNumLetQ(l)) &&
        l2 == WB.numeric) {
      return false;
    }
    // WB12
    if (l == WB.numeric &&
        (b == WB.midNum || _isMidNumLetQ(b)) &&
        r == WB.numeric) {
      return false;
    }
    // WB13
    if (l == WB.katakana && b == WB.katakana) return false;
    // WB13a
    if ((_isAHLetter(l) ||
            l == WB.numeric ||
            l == WB.katakana ||
            l == WB.extendNumLet) &&
        b == WB.extendNumLet) {
      return false;
    }
    // WB13b
    if (l == WB.extendNumLet &&
        (_isAHLetter(b) || b == WB.numeric || b == WB.katakana)) {
      return false;
    }
    // WB15 and WB16: break only between an even number of regional indicators,
    // so a flag sequence stays whole.
    if (l == WB.regionalIndicator && b == WB.regionalIndicator) {
      var count = 0;
      var j = li;
      while (j >= 0) {
        if (_isIgnorable(props[j])) {
          j--;
          continue;
        }
        if (props[j] != WB.regionalIndicator) break;
        count++;
        j--;
      }
      if (count.isOdd) return false;
    }
    // WB999
    return true;
  }

  final out = <int>[0];
  for (var i = 1; i < n; i++) {
    if (breakAt(i)) out.add(i);
  }
  out.add(n);
  return out;
}
