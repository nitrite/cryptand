//! Level 2 — `07-fulltext.md`. The analyzer vector group (which the
//! byte-layer-only crate deliberately did not port), Unicode's own published
//! conformance suites, and Snowball's own vocabulary.
//!
//! §2 opens by saying why this matters: "Two implementations that tokenize
//! `"Bäckerei-Straße 12"` differently will produce two indexes that disagree
//! about what documents exist."

mod support;

use cryptand::analyzer::{canonical_stopwords, porter2_english, Analyzer, Token, STD};
use cryptand::fulltext::{
    check_block, phrase_matches, split_blocks, Posting, PostingsBlock, TermEntry, BLOCK_MAX,
};
use cryptand::porter2::{stem, SNOWBALL_VERSION};
use cryptand::unicode::{nfc, nfkc, word_boundaries};
use cryptand::unicode_tables::UNICODE_VERSION;
use support::{read_vector, vectors_dir};

fn from_cps(cps: &[u32]) -> String {
    cps.iter().filter_map(|&c| char::from_u32(c)).collect()
}

// ---------------------------------------------------------------------------
// analyzer/std_v1 -- the tenth vector group
// ---------------------------------------------------------------------------

#[test]
fn every_analyzer_case_reproduces_its_token_and_position_stream() {
    let v = read_vector("analyzer/std_v1.json");
    assert_eq!(v["analyzer"].as_str().unwrap(), STD);
    assert_eq!(v["unicode_version"].as_str().unwrap(), UNICODE_VERSION);
    let mut checked = 0;
    for case in v["cases"].as_array().unwrap() {
        let stopwords: Vec<String> = case["stopwords"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        let stemmer = case["stemmer"].as_str().unwrap_or("none").to_string();
        let a = match Analyzer::new(STD, stopwords, &stemmer) {
            Ok(a) => a,
            Err(e) => panic!("{}: {e}", case["note"]),
        };
        let input: Vec<u32> =
            case["input_cps"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect();
        let got = a.analyze(&from_cps(&input));
        let want: Vec<Token> = case["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| Token {
                text: from_cps(
                    &t["text_cps"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_u64().unwrap() as u32)
                        .collect::<Vec<u32>>(),
                ),
                position: t["position"].as_u64().unwrap() as usize,
            })
            .collect();
        assert_eq!(got, want, "case: {}", case["note"]);
        checked += 1;
    }
    assert!(checked >= 14, "the vector set shrank: {checked} cases");
}

#[test]
fn a_dropped_stopword_leaves_a_gap_not_a_shift() {
    // §2.2 step 8: the position is the **pre-filter** segment index. Impossible
    // to detect later without re-indexing, so it has its own test.
    let a = Analyzer::new(STD, vec!["the".into()], "none").unwrap();
    let t = a.analyze("the quick fox");
    assert_eq!(t.iter().map(|x| x.position).collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn lowercasing_is_simple_not_full_folding() {
    // §2.2: `ẞ` folds to `ss` under full folding and to `ß` under simple
    // lowercasing. The spec says simple.
    let a = Analyzer::default();
    let t = a.analyze("\u{1E9E}");
    assert_eq!(t[0].text, "\u{00DF}");
}

#[test]
fn an_unregistered_analyzer_is_refused_loudly() {
    // §2.5: "This is the correct failure — loud and specific."
    assert!(Analyzer::new("myapp.analyzer.v1", vec![], "none").is_err());
}

#[test]
fn an_unpinned_porter2_name_is_rejected() {
    // §2.4: an implementation MUST reject an unpinned `porter2:<lang>` — it
    // cannot be made to mean one thing, and guessing a release is how two SDKs
    // come to disagree without either being able to detect it.
    assert!(Analyzer::new(STD, vec![], "porter2:en").is_err());
    assert!(Analyzer::new(STD, vec![], "porter2:en:2.2.0").is_err());
    assert!(Analyzer::new(STD, vec![], &porter2_english()).is_ok());
}

#[test]
fn stopwords_are_stored_canonically() {
    // §2.3: "sorted, NFKC, lowercased".
    let w = canonical_stopwords(vec!["The".into(), "AND".into(), "the".into()]);
    assert_eq!(w, vec!["and".to_string(), "the".to_string()]);
}

// ---------------------------------------------------------------------------
// Unicode's own published suites
// ---------------------------------------------------------------------------

#[test]
fn unicode_normalization_test_passes() {
    let path = vectors_dir().join("unicode/NormalizationTest-15.1.0.txt");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut cases = 0;
    let mut failures = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() || line.starts_with('@') {
            continue;
        }
        let cols: Vec<&str> = line.split(';').collect();
        if cols.len() < 5 {
            continue;
        }
        let col = |i: usize| -> String {
            cols[i]
                .split_whitespace()
                .map(|h| char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap())
                .collect()
        };
        let (c1, c2, c3, c4, c5) = (col(0), col(1), col(2), col(3), col(4));
        // NFC(c1) == NFC(c2) == NFC(c3) == c2, NFKC(c1..c5) == c4.
        for s in [&c1, &c2, &c3] {
            if nfc(s) != c2 {
                failures.push(format!("NFC({s:?}) != {c2:?}"));
            }
        }
        for s in [&c4, &c5] {
            if nfc(s) != c4 {
                failures.push(format!("NFC({s:?}) != {c4:?}"));
            }
        }
        for s in [&c1, &c2, &c3, &c4, &c5] {
            if nfkc(s) != c4 {
                failures.push(format!("NFKC({s:?}) != {c4:?}"));
            }
        }
        cases += 1;
    }
    assert!(cases > 18000, "only {cases} normalization cases parsed");
    assert!(failures.is_empty(), "{cases} cases, {} failures, first: {:?}", failures.len(), &failures[..failures.len().min(5)]);
}

#[test]
fn unicode_word_break_test_passes() {
    let path = vectors_dir().join("unicode/WordBreakTest-15.1.0.txt");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut cases = 0;
    let mut failures = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let mut cps: Vec<u32> = Vec::new();
        let mut want: Vec<usize> = Vec::new();
        for tok in line.split_whitespace() {
            match tok {
                "\u{00F7}" => want.push(cps.len()),
                "\u{00D7}" => {}
                h => cps.push(u32::from_str_radix(h, 16).unwrap()),
            }
        }
        let got = word_boundaries(&cps);
        if got != want {
            failures.push(format!("{line}\n  want {want:?}\n  got  {got:?}"));
        }
        cases += 1;
    }
    assert!(cases > 1800, "only {cases} word-break cases parsed");
    assert!(failures.is_empty(), "{cases} cases, {} failures, first:\n{}", failures.len(), failures.first().cloned().unwrap_or_default());
}

#[test]
fn the_snowball_vocabulary_stems_as_published() {
    let dir = vectors_dir().join("snowball");
    let voc = std::fs::read_to_string(dir.join(format!("voc-{SNOWBALL_VERSION}.txt"))).unwrap();
    let out = std::fs::read_to_string(dir.join(format!("output-{SNOWBALL_VERSION}.txt"))).unwrap();
    let words: Vec<&str> = voc.lines().collect();
    let stems: Vec<&str> = out.lines().collect();
    assert_eq!(words.len(), stems.len(), "vocabulary and output disagree in length");
    let mut wrong = Vec::new();
    for (w, s) in words.iter().zip(stems.iter()) {
        let got = stem(w);
        if got != *s {
            wrong.push(format!("{w} -> {got}, published {s}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} words stem differently, first 10: {:?}",
        wrong.len(),
        words.len(),
        &wrong[..wrong.len().min(10)]
    );
}

// ---------------------------------------------------------------------------
// §4 -- postings
// ---------------------------------------------------------------------------

#[test]
fn a_postings_block_round_trips_with_and_without_positions() {
    for positions in [false, true] {
        let b = PostingsBlock {
            postings: vec![
                Posting { doc: 100, freq: 2, positions: if positions { vec![0, 7] } else { vec![] } },
                Posting { doc: 250, freq: 1, positions: if positions { vec![3] } else { vec![] } },
                Posting { doc: 251, freq: 3, positions: if positions { vec![1, 2, 9] } else { vec![] } },
            ],
            has_positions: positions,
        };
        let bytes = b.encode_value().unwrap();
        assert_eq!(PostingsBlock::decode_value(&bytes).unwrap(), b);
        check_block(&b, 100).unwrap();
    }
}

#[test]
fn blocks_hold_at_most_128_documents() {
    let postings: Vec<Posting> =
        (0..300).map(|i| Posting { doc: i, freq: 1, positions: vec![] }).collect();
    let blocks = split_blocks(postings, false);
    assert_eq!(blocks.len(), 3);
    assert!(blocks.iter().all(|b| b.postings.len() <= BLOCK_MAX));
    check_block(&blocks[0], 0).unwrap();
    check_block(&blocks[1], BLOCK_MAX as i64).unwrap();
}

#[test]
fn a_phrase_query_needs_adjacent_positions() {
    // "quick fox" matches at 0/1 but "fox quick" does not.
    assert!(phrase_matches(&[vec![0, 5], vec![1, 9]]));
    assert!(!phrase_matches(&[vec![1, 9], vec![0, 5]]));
}

#[test]
fn a_term_entry_round_trips() {
    let t = TermEntry { id: 7, df: 3, ttf: 11 };
    assert_eq!(TermEntry::decode(&t.encode()).unwrap(), t);
}
