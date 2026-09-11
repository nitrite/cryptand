//! CRC-32C (`00-conventions.md` §6) and CFH-64 (`04-segments.md` §2.4.1).

/// Castagnoli, polynomial 0x1EDC6F41, reflected, init/final xor 0xFFFFFFFF.
/// Reflected form means the table is built from the reversed polynomial.
/// CRC-32C tables for slicing-by-8, built at compile time.
///
/// **This was a bit-at-a-time loop** — eight shift-and-xor iterations per byte,
/// no table and no instruction. `00-conventions.md` §6 chose CRC-32C *because*
/// "it is hardware-accelerated on every current ARM and x86, and because every
/// target language already has it", and this implementation was the one shape
/// that gets none of that: the Java reference delegates to `java.util.zip.CRC32C`,
/// which the JIT compiles to the hardware instruction, and the Dart one has had
/// a byte table since it was written.
///
/// It is not a small cost, because every page carries a checksum over its whole
/// `page_size` bytes and it is computed on every write and verified on every
/// read that misses the cache. Measured on the cross-language CRUD matrix, a
/// flush of 20 000 documents spent **41.8 ms of its 45.9 ms inside
/// `SegmentBuilder::add`**, and essentially all of that was this function
/// running over the 13.6 MB of pages the builder emitted — 109 million loop
/// iterations for what is now a table lookup per byte, eight bytes at a time.
///
/// The tables are the portable path. On ARMv8 with `FEAT_CRC32` (every Apple
/// Silicon and every current server ARM) and on x86-64 with SSE4.2, the
/// instruction is used instead, through `std::arch` and runtime detection: the
/// table was measured at **28 % of segment building** once the rest of the
/// write path was fixed, because every emitted page is checksummed whole. The
/// tables are `const`, so they cost no start-up time and no synchronisation.
const fn crc_tables() -> [[u32; 256]; 8] {
    const POLY: u32 = 0x82F6_3B78; // reverse of 0x1EDC6F41
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut n = 1;
    while n < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[n - 1][i];
            t[n][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            i += 1;
        }
        n += 1;
    }
    t
}

static CRC_T: [[u32; 256]; 8] = crc_tables();

pub fn crc32c(data: &[u8]) -> u32 {
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("crc") {
        // SAFETY: the feature the function is compiled for was just detected.
        return unsafe { crc32c_arm(data) };
    }
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.2") {
        // SAFETY: as above.
        return unsafe { crc32c_x86(data) };
    }
    crc32c_table(data)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn crc32c_arm(data: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32cb, __crc32cd};
    let mut crc = 0xFFFF_FFFFu32;
    let mut words = data.chunks_exact(8);
    for w in &mut words {
        crc = __crc32cd(crc, u64::from_le_bytes(w.try_into().unwrap()));
    }
    for &b in words.remainder() {
        crc = __crc32cb(crc, b);
    }
    !crc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_x86(data: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut crc = 0xFFFF_FFFFu64;
    let mut words = data.chunks_exact(8);
    for w in &mut words {
        crc = _mm_crc32_u64(crc, u64::from_le_bytes(w.try_into().unwrap()));
    }
    let mut crc = crc as u32;
    for &b in words.remainder() {
        crc = _mm_crc32_u8(crc, b);
    }
    !crc
}

fn crc32c_table(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    let mut d = data;
    while d.len() >= 8 {
        let w0 = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) ^ crc;
        let w1 = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
        crc = CRC_T[7][(w0 & 0xFF) as usize]
            ^ CRC_T[6][((w0 >> 8) & 0xFF) as usize]
            ^ CRC_T[5][((w0 >> 16) & 0xFF) as usize]
            ^ CRC_T[4][((w0 >> 24) & 0xFF) as usize]
            ^ CRC_T[3][(w1 & 0xFF) as usize]
            ^ CRC_T[2][((w1 >> 8) & 0xFF) as usize]
            ^ CRC_T[1][((w1 >> 16) & 0xFF) as usize]
            ^ CRC_T[0][((w1 >> 24) & 0xFF) as usize];
        d = &d[8..];
    }
    for &b in d {
        crc = CRC_T[0][((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_instruction_and_the_table_agree() {
        // The standard CRC-32C check value.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        let data: Vec<u8> = (0..4200u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        for start in 0..9 {
            for len in (0..80).chain([4096 - 4, 4096]) {
                let d = &data[start..start + len];
                assert_eq!(crc32c(d), crc32c_table(d), "offset {start}, length {len}");
            }
        }
    }
}
