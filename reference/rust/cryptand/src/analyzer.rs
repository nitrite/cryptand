//! The `cryptand.std.v1` analyzer — `07-fulltext.md` §2.
//!
//! §2.1 is the rule that makes this file's exactness load-bearing:
//!
//! > "An implementation that **cannot reproduce the named analyzer exactly**
//! > MUST NOT write to the index... The alternative — letting each SDK tokenize
//! > with whatever its ecosystem provides — produces an index that is silently
//! > wrong in a way no checksum catches."
//!
//! The three traps §2.2 names are each handled where they arise: locale-
//! sensitive lowercasing (never `str::to_lowercase`), full case folding (not
//! used — `ẞ` lowercases to `ß`, not `ss`), and Unicode version drift (the
//! tables are pinned and reported).

use std::collections::BTreeSet;

use crate::error::{invalid, Error, Result};
use crate::porter2::{stem as porter2_stem, SNOWBALL_VERSION};
use crate::unicode::{
    has_numeric_type, is_alphabetic, nfkc, simple_lowercase_mapping, word_boundaries,
};
use crate::unicode_tables::UNICODE_VERSION;

/// One emitted token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    /// §2.2 step 8: "the index of the segment among the segments emitted from
    /// step 3, **before filtering**". Positions therefore count dropped
    /// stopwords and over-length segments, which is what makes a phrase query
    /// mean the same thing whether or not a stopword list was configured.
    pub position: usize,
}

/// §2.2's normative default. Every Level-2 implementation MUST implement it
/// exactly.
pub const STD: &str = "cryptand.std.v1";
pub const STEMMER_NONE: &str = "none";

/// The pinned form this build implements.
pub fn porter2_english() -> String {
    format!("porter2:en:{SNOWBALL_VERSION}")
}

/// `(language, version)` for a `porter2:...` name, or `None` when unpinned.
pub fn parse_porter2(s: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 || parts[0] != "porter2" {
        return None;
    }
    Some((parts[1], parts[2]))
}

pub struct Analyzer {
    pub name: String,
    /// §2.3: a configured stopword set is stored **in the database**, not in
    /// the implementation, because the SDKs' per-language lists are not
    /// identical.
    pub stopwords: BTreeSet<String>,
    pub stemmer: String,
    /// §2.2 step 5.
    pub max_code_points: usize,
}

impl Default for Analyzer {
    fn default() -> Self {
        Analyzer {
            name: STD.to_string(),
            stopwords: BTreeSet::new(),
            stemmer: STEMMER_NONE.to_string(),
            max_code_points: 64,
        }
    }
}

impl Analyzer {
    pub fn new(name: &str, stopwords: Vec<String>, stemmer: &str) -> Result<Analyzer> {
        if name != STD {
            // §2.5: an unregistered analyzer is unwritable and unqueryable, and
            // the implementation says so. That is the correct failure — loud
            // and specific.
            return Err(Error::Invalid(format!(
                "analyzer \"{name}\" is not registered in this implementation; it can neither \
                 write nor query this index (spec/07-fulltext.md section 2.5)"
            )));
        }
        if stemmer != STEMMER_NONE {
            if !stemmer.starts_with("porter2:") {
                return invalid(format!(
                    "stemmer \"{stemmer}\" is neither \"none\" nor \
                     \"porter2:<lang>:<version>\" (spec/07-fulltext.md section 2.4)"
                ));
            }
            let Some((lang, version)) = parse_porter2(stemmer) else {
                return invalid(format!(
                    "stemmer \"{stemmer}\" does not pin a Snowball version. Snowball releases \
                     stem the same word differently — 3.0.0 removed the \"skis\" exception and \
                     3.1.0 restored it — so an unpinned name cannot make two SDKs agree on what \
                     terms a document has. Use \"{}\" (spec/07-fulltext.md section 2.4)",
                    porter2_english()
                ));
            };
            if lang != "en" {
                return invalid(format!(
                    "this build implements Snowball English only; the index asks for \"{lang}\". \
                     Per section 2.1 an implementation that cannot reproduce the named analyzer \
                     MUST NOT write to the index"
                ));
            }
            if version != SNOWBALL_VERSION {
                return invalid(format!(
                    "this build implements Snowball {SNOWBALL_VERSION}; the index pins {version}. \
                     Refusing it — a rule that changed between those releases would silently \
                     change what terms a document has (spec/07-fulltext.md section 2.4)"
                ));
            }
        }
        Ok(Analyzer {
            name: name.to_string(),
            stopwords: canonical_stopwords(stopwords).into_iter().collect(),
            stemmer: stemmer.to_string(),
            max_code_points: 64,
        })
    }

    pub fn unicode_version(&self) -> &'static str {
        UNICODE_VERSION
    }

    /// §2.2: an implementation MUST record the Unicode version it implements
    /// and MUST refuse to write an index whose analyzer pins one it lacks.
    pub fn require_unicode(&self, pinned: &str) -> Result<()> {
        if pinned != UNICODE_VERSION {
            return invalid(format!(
                "this build implements Unicode {UNICODE_VERSION}; the index pins {pinned}. \
                 Refusing to write it — a boundary that moved between those releases would \
                 silently change what documents exist (spec/07-fulltext.md section 2.2)"
            ));
        }
        Ok(())
    }

    /// The eight steps of §2.2.
    pub fn analyze(&self, text: &str) -> Vec<Token> {
        // Step 2. (Step 1, the UTF-8 decode, is the caller's; a non-string
        // value is skipped by `analyze_value`.)
        let normalized = nfkc(text);
        let cps: Vec<u32> = normalized.chars().map(|c| c as u32).collect();

        // Step 3: segment, keeping only segments with at least one Alphabetic
        // or Numeric_Type != None character.
        let bounds = word_boundaries(&cps);
        let mut segments: Vec<String> = Vec::new();
        for w in bounds.windows(2) {
            let (lo, hi) = (w[0], w[1]);
            if (lo..hi).any(|j| is_alphabetic(cps[j]) || has_numeric_type(cps[j])) {
                segments.push(cps[lo..hi].iter().filter_map(|&c| char::from_u32(c)).collect());
            }
        }

        let mut out = Vec::new();
        for (position, seg) in segments.iter().enumerate() {
            // Step 4: simple, non-tailored, locale-independent lowercasing.
            let lowered: String = seg
                .chars()
                .filter_map(|c| char::from_u32(simple_lowercase_mapping(c as u32)))
                .collect();
            // Step 5.
            if lowered.chars().count() > self.max_code_points {
                continue;
            }
            // Step 6.
            if self.stopwords.contains(&lowered) {
                continue;
            }
            // Step 7.
            let stemmed = self.stem(&lowered);
            if stemmed.is_empty() {
                continue;
            }
            // Step 8: the position is the *pre-filter* index, so dropping a
            // stopword leaves a gap rather than shifting everything after it.
            out.push(Token { text: stemmed, position });
        }
        out
    }

    fn stem(&self, s: &str) -> String {
        if self.stemmer == STEMMER_NONE {
            s.to_string()
        } else {
            porter2_stem(s)
        }
    }
}

/// §2.3: the stored form is "sorted, NFKC, lowercased".
pub fn canonical_stopwords<I: IntoIterator<Item = String>>(words: I) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for w in words {
        set.insert(
            nfkc(&w)
                .chars()
                .filter_map(|c| char::from_u32(simple_lowercase_mapping(c as u32)))
                .collect(),
        );
    }
    set.into_iter().collect()
}
