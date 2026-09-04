//! The Unicode operations `07-fulltext.md` §2.2 requires, at the version it
//! pins.
//!
//! The chapter's first sentence is why this file exists: "Full text is the
//! hardest thing in this format to make portable, and the reason is not the
//! postings — it is the **analyzer**. Two implementations that tokenize
//! `"Bäckerei-Straße 12"` differently will produce two indexes that disagree
//! about what documents exist."
//!
//! Verified against Unicode's own published conformance suites —
//! `NormalizationTest.txt` and `WordBreakTest.txt` — in `tests/unicode.rs`.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::unicode_tables::*;

/// Word_Break property values, UAX #29, as indices into [`WB_NAMES`].
pub mod wb {
    pub const A_LETTER: i32 = 0;
    pub const CR: i32 = 1;
    pub const DOUBLE_QUOTE: i32 = 2;
    pub const EXTEND: i32 = 3;
    pub const EXTEND_NUM_LET: i32 = 4;
    pub const FORMAT: i32 = 5;
    pub const HEBREW_LETTER: i32 = 6;
    pub const KATAKANA: i32 = 7;
    pub const LF: i32 = 8;
    pub const MID_LETTER: i32 = 9;
    pub const MID_NUM: i32 = 10;
    pub const MID_NUM_LET: i32 = 11;
    pub const NEWLINE: i32 = 12;
    pub const NUMERIC: i32 = 13;
    pub const REGIONAL_INDICATOR: i32 = 14;
    pub const SINGLE_QUOTE: i32 = 15;
    pub const W_SEG_SPACE: i32 = 16;
    pub const ZWJ: i32 = 17;
    /// Anything with no Word_Break property.
    pub const OTHER: i32 = -1;
}

fn lookup3(table: &[u32], cp: u32, fallback: i32) -> i32 {
    let (mut lo, mut hi) = (0isize, (table.len() / 3) as isize - 1);
    while lo <= hi {
        let mid = ((lo + hi) / 2) as usize;
        if cp < table[mid * 3] {
            hi = mid as isize - 1;
        } else if cp > table[mid * 3 + 1] {
            lo = mid as isize + 1;
        } else {
            return table[mid * 3 + 2] as i32;
        }
    }
    fallback
}

fn in_ranges(table: &[u32], cp: u32) -> bool {
    let (mut lo, mut hi) = (0isize, (table.len() / 2) as isize - 1);
    while lo <= hi {
        let mid = ((lo + hi) / 2) as usize;
        if cp < table[mid * 2] {
            hi = mid as isize - 1;
        } else if cp > table[mid * 2 + 1] {
            lo = mid as isize + 1;
        } else {
            return true;
        }
    }
    false
}

fn lookup_map(table: &[u32], cp: u32, fallback: u32) -> u32 {
    let (mut lo, mut hi) = (0isize, (table.len() / 2) as isize - 1);
    while lo <= hi {
        let mid = ((lo + hi) / 2) as usize;
        let k = table[mid * 2];
        if cp < k {
            hi = mid as isize - 1;
        } else if cp > k {
            lo = mid as isize + 1;
        } else {
            return table[mid * 2 + 1];
        }
    }
    fallback
}

pub fn word_break_property(cp: u32) -> i32 {
    lookup3(&WB_RANGES, cp, wb::OTHER)
}

pub fn is_extended_pictographic(cp: u32) -> bool {
    in_ranges(&EXTENDED_PICTOGRAPHIC, cp)
}

/// The step-3 filter of §2.2: keep only segments containing at least one
/// character with Alphabetic or Numeric_Type != None.
pub fn is_alphabetic(cp: u32) -> bool {
    in_ranges(&ALPHABETIC, cp)
}

pub fn has_numeric_type(cp: u32) -> bool {
    in_ranges(&NUMERIC_TYPE, cp)
}

pub fn combining_class(cp: u32) -> u32 {
    lookup_map(&CCC_MAP, cp, 0)
}

/// `Simple_Lowercase_Mapping`, §2.2 step 4.
///
/// **Not** full case folding and **not** a locale-sensitive `to_lowercase()`.
/// §2.2 names both traps: Java's `toLowerCase()` under a Turkish locale maps
/// `I` to `ı`, and full folding maps `ẞ` to `ss` where simple lowercasing maps
/// it to `ß`.
pub fn simple_lowercase_mapping(cp: u32) -> u32 {
    lookup_map(&SIMPLE_LOWERCASE, cp, cp)
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

/// The flat table is sorted by code point but its entries are variable length,
/// so an offset index is built once rather than scanned per lookup.
fn decomp_offsets() -> &'static HashMap<u32, usize> {
    static M: OnceLock<HashMap<u32, usize>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m = HashMap::new();
        let mut i = 0usize;
        while i < DECOMP_FLAT.len() {
            m.insert(DECOMP_FLAT[i], i);
            i += 3 + DECOMP_FLAT[i + 2] as usize;
        }
        m
    })
}

/// Canonical composition pairs, `(first << 21) | second` → composed.
///
/// A canonical decomposition forms a composition pair unless the character is
/// a composition exclusion, is a singleton decomposition, or has a non-starter
/// first character — the three exclusions of UAX #15.
fn compositions() -> &'static HashMap<u64, u32> {
    static M: OnceLock<HashMap<u64, u32>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m = HashMap::new();
        let mut i = 0usize;
        while i < DECOMP_FLAT.len() {
            let cp = DECOMP_FLAT[i];
            let compat = DECOMP_FLAT[i + 1] == 1;
            let len = DECOMP_FLAT[i + 2] as usize;
            if !compat && len == 2 {
                let (a, b) = (DECOMP_FLAT[i + 3], DECOMP_FLAT[i + 4]);
                if lookup_map(&COMPOSITION_EXCLUSIONS, cp, 0) == 0 && combining_class(a) == 0 {
                    m.insert(((a as u64) << 21) | b as u64, cp);
                }
            }
            i += 3 + len;
        }
        m
    })
}

fn decompose_into(cp: u32, compat: bool, out: &mut Vec<u32>) {
    // Hangul is algorithmic, not tabular.
    if (S_BASE..S_BASE + S_COUNT).contains(&cp) {
        let s = cp - S_BASE;
        out.push(L_BASE + s / N_COUNT);
        out.push(V_BASE + (s % N_COUNT) / T_COUNT);
        let t = s % T_COUNT;
        if t != 0 {
            out.push(T_BASE + t);
        }
        return;
    }
    let Some(&idx) = decomp_offsets().get(&cp) else {
        out.push(cp);
        return;
    };
    let is_compat = DECOMP_FLAT[idx + 1] == 1;
    if is_compat && !compat {
        out.push(cp);
        return;
    }
    let len = DECOMP_FLAT[idx + 2] as usize;
    for k in 0..len {
        decompose_into(DECOMP_FLAT[idx + 3 + k], compat, out);
    }
}

/// Canonical ordering: a stable sort of each run of non-starters by combining
/// class.
fn canonical_order(cps: &mut [u32]) {
    for i in 1..cps.len() {
        let ccc = combining_class(cps[i]);
        if ccc == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 {
            let prev = combining_class(cps[j - 1]);
            if prev == 0 || prev <= ccc {
                break;
            }
            cps.swap(j, j - 1);
            j -= 1;
        }
    }
}

fn compose_pair(a: u32, b: u32) -> Option<u32> {
    // Hangul, algorithmic.
    if a >= L_BASE {
        let l_index = a - L_BASE;
        if l_index < L_COUNT && b >= V_BASE {
            let v_index = b - V_BASE;
            if v_index < V_COUNT {
                return Some(S_BASE + (l_index * V_COUNT + v_index) * T_COUNT);
            }
        }
    }
    if a >= S_BASE {
        let s_index = a - S_BASE;
        if s_index < S_COUNT && s_index % T_COUNT == 0 && b > T_BASE {
            let t_index = b - T_BASE;
            if t_index < T_COUNT {
                return Some(a + t_index);
            }
        }
    }
    compositions().get(&(((a as u64) << 21) | b as u64)).copied()
}

/// Canonical composition, UAX #15: walk the decomposed string keeping the
/// position of the last starter, and compose into it whenever the next
/// character is not *blocked*.
fn compose(mut buf: Vec<u32>) -> Vec<u32> {
    if buf.is_empty() {
        return buf;
    }
    let mut starter_pos = 0usize;
    let mut starter_ch = buf[0];
    let mut last_class = combining_class(starter_ch);
    if last_class != 0 {
        last_class = 256; // nothing composes onto a non-starter
    }
    let mut comp_pos = 1usize;
    for decomp_pos in 1..buf.len() {
        let ch = buf[decomp_pos];
        let ch_class = combining_class(ch);
        match compose_pair(starter_ch, ch) {
            Some(composite) if last_class < ch_class || last_class == 0 => {
                buf[starter_pos] = composite;
                starter_ch = composite;
            }
            _ => {
                if ch_class == 0 {
                    starter_pos = comp_pos;
                    starter_ch = ch;
                }
                last_class = ch_class;
                buf[comp_pos] = ch;
                comp_pos += 1;
            }
        }
    }
    buf.truncate(comp_pos);
    buf
}

fn normalize(s: &str, compat: bool) -> String {
    let mut cps = Vec::with_capacity(s.len());
    for c in s.chars() {
        decompose_into(c as u32, compat, &mut cps);
    }
    canonical_order(&mut cps);
    compose(cps).into_iter().filter_map(char::from_u32).collect()
}

/// NFKC, §2.2 step 2.
pub fn nfkc(s: &str) -> String {
    normalize(s, true)
}

/// NFC, for completeness and because the conformance suite exercises both.
pub fn nfc(s: &str) -> String {
    normalize(s, false)
}

// ---------------------------------------------------------------------------
// UAX #29 word segmentation
// ---------------------------------------------------------------------------

fn is_ignorable(p: i32) -> bool {
    p == wb::EXTEND || p == wb::FORMAT || p == wb::ZWJ
}
fn is_ah_letter(p: i32) -> bool {
    p == wb::A_LETTER || p == wb::HEBREW_LETTER
}
fn is_mid_num_let_q(p: i32) -> bool {
    p == wb::MID_NUM_LET || p == wb::SINGLE_QUOTE
}

/// Word boundaries per UAX #29, at the pinned Unicode version.
///
/// Returns the code-point offsets at which a word boundary occurs, always
/// including 0 and `cps.len()` (rules WB1 and WB2).
///
/// Rule WB4 — "X (Extend | Format | ZWJ)* → X" — is why the context helpers
/// skip those three properties: after WB1–WB3d have had their say on the raw
/// characters, every remaining rule sees the string as though the ignorable
/// characters were not there.
pub fn word_boundaries(cps: &[u32]) -> Vec<usize> {
    let n = cps.len();
    if n == 0 {
        return vec![0];
    }
    let props: Vec<i32> = cps.iter().map(|&c| word_break_property(c)).collect();

    // The nearest non-ignorable index at or before `i`. The walk stops at a
    // hard line break, because WB3a/WB3b have already broken there and WB4
    // must not reach across it.
    let prev_ni = |i: isize| -> isize {
        let mut j = i;
        while j >= 0 {
            let p = props[j as usize];
            if !is_ignorable(p) {
                return j;
            }
            if p == wb::NEWLINE || p == wb::CR || p == wb::LF {
                return j;
            }
            j -= 1;
        }
        -1
    };
    let next_ni = |i: usize| -> isize {
        let mut j = i;
        while j < n {
            if !is_ignorable(props[j]) {
                return j as isize;
            }
            j += 1;
        }
        -1
    };

    let break_at = |i: usize| -> bool {
        let (a, b) = (props[i - 1], props[i]);
        // WB3: CR x LF
        if a == wb::CR && b == wb::LF {
            return false;
        }
        // WB3a: (Newline | CR | LF) div
        if a == wb::NEWLINE || a == wb::CR || a == wb::LF {
            return true;
        }
        // WB3b: div (Newline | CR | LF)
        if b == wb::NEWLINE || b == wb::CR || b == wb::LF {
            return true;
        }
        // WB3c: ZWJ x Extended_Pictographic
        if a == wb::ZWJ && is_extended_pictographic(cps[i]) {
            return false;
        }
        // WB3d: WSegSpace x WSegSpace
        if a == wb::W_SEG_SPACE && b == wb::W_SEG_SPACE {
            return false;
        }
        // WB4
        if is_ignorable(b) {
            return false;
        }
        let li = prev_ni(i as isize - 1);
        if li < 0 {
            return true;
        }
        let l = props[li as usize];
        let l2i = if li > 0 { prev_ni(li - 1) } else { -1 };
        let l2 = if l2i >= 0 { props[l2i as usize] } else { wb::OTHER };
        let ri = next_ni(i + 1);
        let r = if ri >= 0 { props[ri as usize] } else { wb::OTHER };

        if is_ah_letter(l) && is_ah_letter(b) {
            return false; // WB5
        }
        if is_ah_letter(l) && (b == wb::MID_LETTER || is_mid_num_let_q(b)) && is_ah_letter(r) {
            return false; // WB6
        }
        if is_ah_letter(b) && (l == wb::MID_LETTER || is_mid_num_let_q(l)) && is_ah_letter(l2) {
            return false; // WB7
        }
        if l == wb::HEBREW_LETTER && b == wb::SINGLE_QUOTE {
            return false; // WB7a
        }
        if l == wb::HEBREW_LETTER && b == wb::DOUBLE_QUOTE && r == wb::HEBREW_LETTER {
            return false; // WB7b
        }
        if l == wb::DOUBLE_QUOTE && b == wb::HEBREW_LETTER && l2 == wb::HEBREW_LETTER {
            return false; // WB7c
        }
        if l == wb::NUMERIC && b == wb::NUMERIC {
            return false; // WB8
        }
        if is_ah_letter(l) && b == wb::NUMERIC {
            return false; // WB9
        }
        if l == wb::NUMERIC && is_ah_letter(b) {
            return false; // WB10
        }
        if b == wb::NUMERIC && (l == wb::MID_NUM || is_mid_num_let_q(l)) && l2 == wb::NUMERIC {
            return false; // WB11
        }
        if l == wb::NUMERIC && (b == wb::MID_NUM || is_mid_num_let_q(b)) && r == wb::NUMERIC {
            return false; // WB12
        }
        if l == wb::KATAKANA && b == wb::KATAKANA {
            return false; // WB13
        }
        if (is_ah_letter(l) || l == wb::NUMERIC || l == wb::KATAKANA || l == wb::EXTEND_NUM_LET)
            && b == wb::EXTEND_NUM_LET
        {
            return false; // WB13a
        }
        if l == wb::EXTEND_NUM_LET && (is_ah_letter(b) || b == wb::NUMERIC || b == wb::KATAKANA) {
            return false; // WB13b
        }
        // WB15 and WB16: break only between an even number of regional
        // indicators, so a flag sequence stays whole.
        if l == wb::REGIONAL_INDICATOR && b == wb::REGIONAL_INDICATOR {
            let mut count = 0usize;
            let mut j = li;
            while j >= 0 {
                if is_ignorable(props[j as usize]) {
                    j -= 1;
                    continue;
                }
                if props[j as usize] != wb::REGIONAL_INDICATOR {
                    break;
                }
                count += 1;
                j -= 1;
            }
            if count % 2 == 1 {
                return false;
            }
        }
        true // WB999
    };

    let mut out = vec![0usize];
    for i in 1..n {
        if break_at(i) {
            out.push(i);
        }
    }
    out.push(n);
    out
}
