//! CRC-32C (`00-conventions.md` §6) and CFH-64 (`04-segments.md` §2.4.1).

/// Castagnoli, polynomial 0x1EDC6F41, reflected, init/final xor 0xFFFFFFFF.
/// Reflected form means the table is built from the reversed polynomial.
pub fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78; // reverse of 0x1EDC6F41
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    !crc
}

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const M1: u64 = 0xBF58_476D_1CE4_E5B9;
const M2: u64 = 0x94D0_49BB_1331_11EB;

/// The filter hash, and only the filter hash (`04-segments.md` §2.4.1).
pub fn cfh64(key: &[u8]) -> u64 {
    let mut h = P1 ^ (key.len() as u64).wrapping_mul(P2);
    let mut i = 0usize;
    while key.len() - i >= 8 {
        let w = u64::from_le_bytes(key[i..i + 8].try_into().unwrap());
        h ^= w.wrapping_mul(P2);
        h = h.rotate_left(31).wrapping_mul(P1);
        i += 8;
    }
    let mut tail: u64 = 0;
    while i < key.len() {
        tail = (tail << 8) | key[i] as u64;
        i += 1;
    }
    h ^= tail.wrapping_mul(P3);
    h = h.rotate_left(27).wrapping_mul(P1);
    h = (h ^ (h >> 30)).wrapping_mul(M1);
    h = (h ^ (h >> 27)).wrapping_mul(M2);
    h ^ (h >> 31)
}
