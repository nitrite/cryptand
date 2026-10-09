#![no_main]
use cryptand::cve;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let dict = |id: u32| (id < 4).then(|| format!("name{id}"));
    if let Ok(v) = cve::decode_all(data, &dict) {
        // A decoded value re-encodes to bytes that decode to the same encoding.
        let e = cve::encode(&v);
        let again = cve::decode_all(&e, &dict).expect("re-encoded value decodes");
        assert_eq!(cve::encode(&again), e, "CVE encode is not stable");
    }
});
