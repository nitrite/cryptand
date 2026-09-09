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
/// Slicing-by-8 rather than an intrinsic: the crate has no runtime dependencies
/// by design and `std::arch` would need per-architecture code and runtime
/// feature detection for the same order of magnitude. The tables are `const`, so
/// they cost no start-up time and no synchronisation.
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
