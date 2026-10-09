#![no_main]
use cryptand::wkb;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(g) = wkb::decode(data) {
        let _ = g.envelope();
        if let Ok(e) = wkb::encode(&g) {
            let g2 = wkb::decode(&e).expect("re-encoded geometry decodes");
            assert_eq!(wkb::encode(&g2).unwrap(), e, "WKB encode is not stable");
        }
    }
});
