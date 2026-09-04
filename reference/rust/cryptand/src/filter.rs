//! The blocked Bloom filter of `04-segments.md` §2.4, specified to the bit
//! because a filter that disagrees between languages loses keys silently.

use crate::hash::cfh64;

pub const BLOCK_BITS: usize = 512;
pub const BLOCK_BYTES: usize = BLOCK_BITS / 8;
pub const MAGIC: u32 = 0x4346_5031; // "CFP1"

pub fn probes_for(bits_per_key: u32) -> u32 {
    let k = (bits_per_key as f64 * std::f64::consts::LN_2).round() as i64;
    k.clamp(1, 16) as u32
}

pub fn block_count_for(distinct_keys: u64, bits_per_key: u32) -> u64 {
    let bits = distinct_keys * bits_per_key as u64;
    std::cmp::max(1, bits.div_ceil(BLOCK_BITS as u64))
}

/// The filter's key domain: `u32be(tree_id) || CKE(key)`, excluding seq and op
/// so that every version of a key shares one entry.
pub fn user_key_prefix(tree_id: u32, cke: &[u8]) -> Vec<u8> {
    let mut v = tree_id.to_be_bytes().to_vec();
    v.extend_from_slice(cke);
    v
}

pub struct BlockedBloom {
    pub blocks: Vec<u8>,
    pub block_count: u64,
    pub bits_per_key: u32,
    pub probes: u32,
    pub distinct_keys: u64,
}

impl BlockedBloom {
    pub fn build(keys: &[Vec<u8>], bits_per_key: u32, distinct_keys: u64) -> BlockedBloom {
        let block_count = block_count_for(distinct_keys, bits_per_key);
        let probes = probes_for(bits_per_key);
        let mut f = BlockedBloom {
            blocks: vec![0u8; block_count as usize * BLOCK_BYTES],
            block_count,
            bits_per_key,
            probes,
            distinct_keys,
        };
        for k in keys {
            f.add(k);
        }
        f
    }

    fn locate(&self, key: &[u8]) -> (usize, u32, u32) {
        let hash = cfh64(key);
        let h1 = (hash & 0xFFFF_FFFF) as u32;
        let h2 = ((hash >> 32) as u32) | 1; // forced odd, so the probes spread
        let block = ((h1 as u64 * self.block_count) >> 32) as usize;
        (block, h1, h2)
    }

    pub fn add(&mut self, key: &[u8]) {
        let (block, h1, h2) = self.locate(key);
        for i in 0..self.probes {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) % BLOCK_BITS as u32;
            let byte = block * BLOCK_BYTES + (bit / 8) as usize;
            self.blocks[byte] |= 1 << (bit % 8);
        }
    }

    pub fn may_contain(&self, key: &[u8]) -> bool {
        let (block, h1, h2) = self.locate(key);
        (0..self.probes).all(|i| {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) % BLOCK_BITS as u32;
            let byte = block * BLOCK_BYTES + (bit / 8) as usize;
            self.blocks[byte] & (1 << (bit % 8)) != 0
        })
    }

    /// The filter page payload, after the 40-byte page header.
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + self.blocks.len());
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&(self.block_count as u32).to_le_bytes());
        out.extend_from_slice(&(self.bits_per_key as u16).to_le_bytes());
        out.extend_from_slice(&(self.probes as u16).to_le_bytes());
        out.extend_from_slice(&self.distinct_keys.to_le_bytes());
        out.extend_from_slice(&self.blocks);
        out
    }
}
