# Regenerating `lib/src/unicode_tables.dart`

`spec/07-fulltext.md` §2.2 pins the analyzer to **Unicode 15.1**, so the tables
are generated from that release and nothing else:

> "The analyzer name pins behaviour, so `cryptand.std.v1` also pins **Unicode
> 15.1** segmentation and case data. A later Unicode revision that changes a
> boundary requires `cryptand.std.v2`, not a silent upgrade."

Source files, all from `https://www.unicode.org/Public/15.1.0/ucd/`:

| file | supplies |
|---|---|
| `UnicodeData.txt` | canonical combining class, `Simple_Lowercase_Mapping`, decomposition mappings |
| `auxiliary/WordBreakProperty.txt` | the Word_Break property (UAX #29) |
| `DerivedCoreProperties.txt` | `Alphabetic` |
| `extracted/DerivedNumericType.txt` | `Numeric_Type != None` |
| `CompositionExclusions.txt` | the NFC/NFKC composition exclusions |
| `emoji/emoji-data.txt` | `Extended_Pictographic`, for rule WB3c |

The two conformance suites live in `../../conformance/unicode/` and are run by
`test/fulltext_test.dart` as ordinary tests:

| file | cases |
|---|---|
| `NormalizationTest-15.1.0.txt` | 19 074 — NFC and NFKC |
| `WordBreakTest-15.1.0.txt` | 1 826 — word boundaries |

**Bumping the Unicode version is a format change, not a maintenance task.** A
boundary that moves between releases silently changes what documents an index
contains, which is why §2.2 requires a new analyzer name rather than a new
table. If these files are regenerated from a later UCD, the analyzer becomes
`cryptand.std.v2` and existing indexes keep naming `v1`.
