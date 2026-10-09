#![no_main]
#[path = "common.rs"]
mod common;

/// The conformance corpus key (`manifest.json`, v1.0-encrypted.cryptand).
const KEY: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32,
];

libfuzzer_sys::fuzz_target!(|data: &[u8]| common::exercise(data, Some(&KEY)));
