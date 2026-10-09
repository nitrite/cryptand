#![no_main]
use cryptand::container::Superblock;
use cryptand::security::Keyslot;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = Superblock::parse(data);
    for c in data.chunks(64) {
        let _ = Keyslot::parse(c);
    }
    let _ = Keyslot::parse(data);
});
