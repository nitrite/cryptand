# Primitive KATs (PLAN M4.2)

Shared by the Rust, Java and Dart test suites. Hex strings throughout.

| file | source | rows |
|---|---|---|
| `chacha20_poly1305.json` | Wycheproof via RustCrypto `chacha20poly1305-0.10.1/tests/data` | key, nonce, aad, msg, ct (ct‖tag), valid (01/00) |
| `xchacha20_poly1305.json` | same | same, 24-byte nonce |
| `hkdf_sha256.json` | Wycheproof via `hkdf-0.12.4/tests/data` (valid cases, okm up to 255·32) | ikm, salt, info, okm |
| `hmac_sha256.json` | Wycheproof via `hmac-0.12/tests/data`; tag may be a left truncation | key, msg, tag |
| `blake2b_keyed.json` | BLAKE2 reference `blake2b-kat.txt` (keyed) via `blake2-0.10.6/tests/data` | key, msg, tag (64 bytes) |
| `blake2b_unkeyed.json` | CPython `hashlib.blake2b` (BLAKE2 reference C), msg byte i = i mod 251, lengths around the 128-byte block, digest 32 and 64; last row RFC 7693 "abc" | msg, digest |
| `argon2id.json` | RFC 9106 §5.3 , phc-winner-argon2 `test.c`, and two RustCrypto-derived rows with m not a multiple of 4p; v=0x13, p ∈ {1,2,3,4} | m in KiB |

Regenerate the blb-derived files with `blb2json.py` (see its header).
