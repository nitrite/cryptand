//! The Porter2 (Snowball English) stemmer — `07-fulltext.md` §2.4.
//!
//! §2.4 names it because "it has an unambiguous published algorithm and
//! existing implementations in every relevant language". That is true of a
//! **given Snowball release** and not of the name alone: the change log records
//! behavioural changes at 3.0.0 (`past`/`paste`, `universe`/`university`,
//! `lateral`/`later`, `emerge`/`emergency`, `organ`/`organic`, `-ogist` → `-og`)
//! and at 3.1.0, one of which *reverses* a 3.0.0 change — "Removed exception
//! for skis" then "Restored exception for skis which is needed".
//!
//! So a stemmer name without a version is exactly the hazard §2.2 already
//! solved for Unicode, and [`SNOWBALL_VERSION`] is this implementation's
//! answer: the release is pinned, reported, and checked.

/// The Snowball release this implementation reproduces.
pub const SNOWBALL_VERSION: &str = "3.1.0";

fn is_vowel(c: u8) -> bool {
    matches!(c, b'a' | b'e' | b'i' | b'o' | b'u' | b'y')
}

/// `v_WXY` = vowels plus `w`, `x`, `Y`.
fn is_vowel_or_wxy(c: u8) -> bool {
    is_vowel(c) || c == b'w' || c == b'x' || c == b'Y'
}

/// `valid_LI` — `cdeghkmnrt`.
fn is_valid_li(c: u8) -> bool {
    matches!(c, b'c' | b'd' | b'e' | b'g' | b'h' | b'k' | b'm' | b'n' | b'r' | b't')
}

const DOUBLES: [&str; 9] = ["bb", "dd", "ff", "gg", "mm", "nn", "pp", "rr", "tt"];

/// Whole words that bypass the algorithm entirely.
const EXCEPTION1: [(&str, &str); 16] = [
    ("skis", "ski"),
    ("skies", "sky"),
    ("idly", "idl"),
    ("gently", "gentl"),
    ("ugly", "ugli"),
    ("early", "earli"),
    ("only", "onli"),
    ("singly", "singl"),
    // Invariant forms: not plural, and not to be stemmed.
    ("sky", "sky"),
    ("news", "news"),
    ("howe", "howe"),
    ("atlas", "atlas"),
    ("cosmos", "cosmos"),
    ("bias", "bias"),
    ("andes", "andes"),
    ("", ""),
];

/// Prefixes after which R1 begins immediately, to stop over-stemming. The
/// classic case is `gener`: without it generate/general/generic/generous all
/// collapse to `gener`.
const R1_EXCEPTIONS: [&str; 9] =
    ["gener", "commun", "arsen", "past", "univers", "later", "emerg", "organ", "inter"];

/// Stems `word`, which is expected already lowercased — §2.2 runs the stemmer
/// at step 7, after step 4's `Simple_Lowercase_Mapping`.
pub fn stem(word: &str) -> String {
    for (k, v) in EXCEPTION1 {
        if !k.is_empty() && k == word {
            return v.to_string();
        }
    }
    if word.chars().count() < 3 {
        return word.to_string();
    }
    let mut w = prelude(word);
    let (p1, p2) = mark_regions(&w);
    w = step1a(w);
    w = step1b(w, p1);
    w = step1c(w);
    w = step2(w, p1);
    w = step3(w, p1, p2);
    w = step4(w, p2);
    w = step5(w, p1, p2);
    w.replace('Y', "y")
}

/// Remove a leading apostrophe; mark an initial `y`, and any `y` after a
/// vowel, as `Y` so it counts as a consonant for the rest of the algorithm.
fn prelude(word: &str) -> String {
    let w = word.strip_prefix('\'').unwrap_or(word);
    if w.is_empty() {
        return String::new();
    }
    let mut u: Vec<char> = w.chars().collect();
    if u[0] == 'y' {
        u[0] = 'Y';
    }
    for i in 1..u.len() {
        if u[i] == 'y' && (u[i - 1] as u32) < 128 && is_vowel(u[i - 1] as u8) {
            u[i] = 'Y';
        }
    }
    u.into_iter().collect()
}

fn at(w: &str, i: usize) -> u8 {
    w.as_bytes().get(i).copied().unwrap_or(0)
}

/// The index after the first non-vowel that follows a vowel, from `start`.
fn after_vowel_then_non_vowel(w: &str, start: usize) -> Option<usize> {
    let b = w.as_bytes();
    let mut i = start;
    while i < b.len() && !is_vowel(b[i]) {
        i += 1;
    }
    while i < b.len() && is_vowel(b[i]) {
        i += 1;
    }
    if i < b.len() {
        Some(i + 1)
    } else {
        None
    }
}

fn mark_regions(w: &str) -> (usize, usize) {
    let n = w.len();
    let cursor = match R1_EXCEPTIONS.iter().find(|p| w.starts_with(**p)) {
        Some(p) => p.len(),
        None => match after_vowel_then_non_vowel(w, 0) {
            Some(c) => c,
            None => return (n, n),
        },
    };
    let p2 = after_vowel_then_non_vowel(w, cursor).unwrap_or(n);
    (cursor, p2)
}

fn ends_short_syllable(w: &str) -> bool {
    if w.ends_with("past") {
        return true;
    }
    let n = w.len();
    if n >= 3 {
        let (a, b, c) = (at(w, n - 3), at(w, n - 2), at(w, n - 1));
        if !is_vowel(a) && is_vowel(b) && !is_vowel_or_wxy(c) {
            return true;
        }
    }
    if n == 2 {
        return is_vowel(at(w, 0)) && !is_vowel(at(w, 1));
    }
    false
}

/// "A word is called short if it ends in a short syllable, and if R1 is null."
fn is_short(w: &str, p1: usize) -> bool {
    p1 >= w.len() && ends_short_syllable(w)
}

fn step1a(mut w: String) -> String {
    // Step 0, folded in as the Snowball source does: the longest of ' 's 's'.
    for s in ["'s'", "'s", "'"] {
        if w.ends_with(s) {
            w.truncate(w.len() - s.len());
            break;
        }
    }
    if w.ends_with("sses") {
        w.truncate(w.len() - 4);
        w.push_str("ss");
        return w;
    }
    if w.ends_with("ied") || w.ends_with("ies") {
        let stem_len = w.len() - 3;
        w.truncate(stem_len);
        // "replace by i if preceded by more than one letter, otherwise by ie".
        if stem_len > 1 {
            w.push('i');
        } else {
            w.push_str("ie");
        }
        return w;
    }
    if w.ends_with("us") || w.ends_with("ss") {
        return w;
    }
    if w.ends_with('s') {
        // "delete if the preceding word part contains a vowel not immediately
        //  before the s (so gas and this retain the s, gaps and kiwis lose it)"
        let b = w.as_bytes();
        for i in 0..b.len().saturating_sub(2) {
            if is_vowel(b[i]) {
                w.truncate(w.len() - 1);
                return w;
            }
        }
    }
    w
}

fn step1b(w: String, p1: usize) -> String {
    for s in ["eedly", "eed"] {
        if w.ends_with(s) {
            let start = w.len() - s.len();
            if start < p1 {
                return w; // not in R1
            }
            let before = &w[..start];
            // 3.0.0: proceed/exceed/succeed are not past participles.
            if before == "proc" || before == "exc" || before == "succ" {
                return w;
            }
            return format!("{before}ee");
        }
    }
    let mut suffix = None;
    for s in ["ingly", "edly", "ing", "ed"] {
        if w.ends_with(s) {
            suffix = Some(s);
            break;
        }
    }
    let Some(suffix) = suffix else { return w };

    if suffix == "ing" {
        let before = &w[..w.len() - 3];
        // dying -> die, lying -> lie, tying -> tie, vying -> vie.
        if before.len() == 2 && at(before, 1) == b'y' && !is_vowel(at(before, 0)) {
            return format!("{}ie", &before[..1]);
        }
        if ["inn", "out", "cann", "herr", "earr", "even"].contains(&before) {
            return w;
        }
    }
    let stem = &w[..w.len() - suffix.len()];
    if !stem.bytes().any(is_vowel) {
        return w;
    }
    if stem.ends_with("at") || stem.ends_with("bl") || stem.ends_with("iz") {
        return format!("{stem}e");
    }
    for d in DOUBLES {
        if stem.ends_with(d) {
            // 3.0.0: "Don't undouble if preceded by exactly a, e or o" — so
            // add, egg and off are unchanged while hopp becomes hop.
            if stem.len() == 3 && matches!(at(stem, 0), b'a' | b'e' | b'o') {
                return stem.to_string();
            }
            return stem[..stem.len() - 1].to_string();
        }
    }
    if is_short(stem, p1) {
        return format!("{stem}e");
    }
    stem.to_string()
}

fn step1c(w: String) -> String {
    let n = w.len();
    if n < 3 {
        return w;
    }
    let last = at(&w, n - 1);
    if last != b'y' && last != b'Y' {
        return w;
    }
    if is_vowel(at(&w, n - 2)) {
        return w;
    }
    if n - 2 == 0 {
        return w; // "not the first letter of the word"
    }
    format!("{}i", &w[..n - 1])
}

/// Longest-suffix replacement within a region. `Some(w)` unchanged means the
/// suffix matched but fell outside the region, which stops the search.
fn replace_in(w: &str, region: usize, table: &[(&str, &str)]) -> Option<String> {
    for (suffix, replacement) in table {
        if !w.ends_with(suffix) {
            continue;
        }
        let start = w.len() - suffix.len();
        if start < region {
            return Some(w.to_string());
        }
        return Some(format!("{}{}", &w[..start], replacement));
    }
    None
}

fn step2(w: String, p1: usize) -> String {
    const TABLE: [(&str, &str); 23] = [
        ("ational", "ate"),
        ("fulness", "ful"),
        ("ousness", "ous"),
        ("iveness", "ive"),
        ("ization", "ize"),
        ("lessli", "less"),
        ("tional", "tion"),
        ("biliti", "ble"),
        ("ousli", "ous"),
        ("entli", "ent"),
        ("ation", "ate"),
        ("alism", "al"),
        ("aliti", "al"),
        ("iviti", "ive"),
        ("fulli", "ful"),
        ("ogist", "og"),
        ("enci", "ence"),
        ("anci", "ance"),
        ("abli", "able"),
        ("izer", "ize"),
        ("ator", "ate"),
        ("alli", "al"),
        ("bli", "ble"),
    ];
    if let Some(r) = replace_in(&w, p1, &TABLE) {
        return r;
    }
    if w.ends_with("ogi") {
        let start = w.len() - 3;
        if start < p1 {
            return w;
        }
        // "replace by og if preceded by l"
        if start > 0 && at(&w, start - 1) == b'l' {
            return format!("{}og", &w[..start]);
        }
        return w;
    }
    if w.ends_with("li") {
        let start = w.len() - 2;
        if start < p1 {
            return w;
        }
        if start > 0 && is_valid_li(at(&w, start - 1)) {
            return w[..start].to_string();
        }
    }
    w
}

fn step3(w: String, p1: usize, p2: usize) -> String {
    const TABLE: [(&str, &str); 8] = [
        ("ational", "ate"),
        ("tional", "tion"),
        ("alize", "al"),
        ("icate", "ic"),
        ("iciti", "ic"),
        ("ical", "ic"),
        ("ness", ""),
        ("ful", ""),
    ];
    if let Some(r) = replace_in(&w, p1, &TABLE) {
        return r;
    }
    if w.ends_with("ative") {
        let start = w.len() - 5;
        if start < p1 {
            return w;
        }
        if start >= p2 {
            return w[..start].to_string(); // "delete if in R2"
        }
    }
    w
}

fn step4(w: String, p2: usize) -> String {
    const TABLE: [(&str, &str); 17] = [
        ("ement", ""),
        ("able", ""),
        ("ible", ""),
        ("ance", ""),
        ("ence", ""),
        ("ment", ""),
        ("ant", ""),
        ("ent", ""),
        ("ism", ""),
        ("ate", ""),
        ("iti", ""),
        ("ous", ""),
        ("ive", ""),
        ("ize", ""),
        ("al", ""),
        ("er", ""),
        ("ic", ""),
    ];
    if let Some(r) = replace_in(&w, p2, &TABLE) {
        return r;
    }
    if w.ends_with("ion") {
        let start = w.len() - 3;
        if start < p2 {
            return w;
        }
        if start > 0 && matches!(at(&w, start - 1), b's' | b't') {
            return w[..start].to_string();
        }
    }
    w
}

fn step5(w: String, p1: usize, p2: usize) -> String {
    if w.ends_with('e') {
        let start = w.len() - 1;
        // "delete if in R2, or in R1 and not preceded by a short syllable"
        if start >= p2 {
            return w[..start].to_string();
        }
        if start >= p1 && !ends_short_syllable(&w[..start]) {
            return w[..start].to_string();
        }
        return w;
    }
    if w.ends_with('l') {
        let start = w.len() - 1;
        if start >= p2 && start > 0 && at(&w, start - 1) == b'l' {
            return w[..start].to_string();
        }
    }
    w
}
