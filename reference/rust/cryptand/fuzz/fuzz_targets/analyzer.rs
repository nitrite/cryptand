#![no_main]
use cryptand::analyzer::{porter2_english, Analyzer, STD};
use cryptand::unicode;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let n = unicode::nfkc(s);
    assert_eq!(unicode::nfkc(&n), n, "NFKC is not idempotent");
    let c = unicode::nfc(s);
    assert_eq!(unicode::nfc(&c), c, "NFC is not idempotent");
    let _ = Analyzer::new(STD, vec!["the".into()], &porter2_english()).unwrap().analyze(s);
});
