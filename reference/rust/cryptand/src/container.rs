//! `01-container.md` — the superblock (§2), the page header (§3), page types
//! (§4) and the feature bits of `11-conformance.md` §2. Read **and** write:
//! this crate is a writer, unlike `cryptand-conformance`.

use crate::error::{corrupt, Error, Result};
use crate::hash::crc32c;

pub const SUPERBLOCK_BYTES: usize = 4096;
pub const PAGE_HEADER_BYTES: usize = 40;
pub const MAGIC: &[u8; 8] = b"CRYPTAND";
pub const VERSION_MAJOR: u16 = 1;
pub const VERSION_MINOR: u16 = 0;

/// §2's field table, by offset. Named so a test can check the table rather
/// than this code's reading of it.
pub mod sb {
    pub const MAGIC: usize = 0;
    pub const VERSION_MAJOR: usize = 8;
    pub const VERSION_MINOR: usize = 10;
    pub const WRITE_VERSION_MINOR: usize = 12;
    pub const PAGE_SIZE_LOG2: usize = 14;
    pub const COMMIT_ID: usize = 16;
    pub const FEATURES_REQUIRED: usize = 24;
    pub const FEATURES_OPTIONAL: usize = 32;
    pub const PAGE_COUNT: usize = 40;
    pub const VISIBLE_SEQ: usize = 48;
    pub const NEXT_SEQ: usize = 56;
    pub const CATALOG_ROOT: usize = 64;
    pub const FREELIST_ROOT: usize = 72;
    pub const ATTRIBUTES_ROOT: usize = 80;
    pub const MANIFEST_ROOT: usize = 88;
    pub const VLOG_STATS_ROOT: usize = 96;
    pub const MIN_RETAINED_COMMIT: usize = 104;
    pub const MIN_RETAINED_SEQ: usize = 112;
    pub const NEXT_TREE_ID: usize = 120;
    pub const NEXT_SEGMENT_ID: usize = 128;
    pub const NEXT_VLOG_SEGMENT_ID: usize = 136;
    pub const CREATED_UTC_MS: usize = 144;
    pub const MODIFIED_UTC_MS: usize = 152;
    pub const DATABASE_UUID: usize = 160;
    pub const DURABILITY_ACHIEVED: usize = 176;
    pub const PAGE_CODEC: usize = 177;
    pub const CIPHER: usize = 178;
    pub const LEVEL_COUNT: usize = 179;
    pub const FANOUT: usize = 180;
    pub const L0_TRIGGER: usize = 181;
    pub const TIER_WIDTH: usize = 182;
    pub const MEMTABLE_SHARDS: usize = 183;
    pub const VLOG_MIN: usize = 184;
    pub const BLOB_THRESHOLD: usize = 188;
    pub const VLOG_SEGMENT_BYTES: usize = 192;
    pub const VLOG_SPACE_TARGET_PCT: usize = 196;
    pub const LIVE_KEY_BYTES: usize = 200;
    pub const LIVE_VALUE_BYTES: usize = 208;
    pub const PROFILE: usize = 216;
    pub const OVERLAP_BOUND: usize = 217;
    pub const LOCALITY_DEBT_PCT: usize = 218;
    pub const FILTER_BITS_UPPER: usize = 219;
    pub const FILTER_BITS_LAST: usize = 220;
    pub const READAHEAD_WINDOW: usize = 224;
    pub const SEGMENT_TARGET_BYTES: usize = 228;
    pub const CHECKPOINT_ROOT: usize = 232;
    pub const CHANGEFEED_ROOT: usize = 240;
    pub const WRITER_ID: usize = 256;
    pub const NEXT_NONCE: usize = 288;
    pub const SB_MAC: usize = 296;
    pub const KEYSLOTS: usize = 3512;
    pub const CHECKSUM: usize = 4092;
}

pub mod ph {
    pub const CHECKSUM: usize = 0;
    pub const PAGE_TYPE: usize = 4;
    pub const FLAGS: usize = 5;
    pub const CODEC_OR_RESERVED: usize = 6;
    pub const TREE_ID: usize = 8;
    pub const EXTENT_PAGES: usize = 12;
    pub const COMMIT_ID: usize = 16;
    pub const PAYLOAD_LEN: usize = 24;
    /// `14-security.md` §5.2 — the number of payload bytes actually
    /// *stored* on the page, after compression and after encryption.
    /// Zero means "same as `payload_len`", which is every page that is
    /// neither compressed nor encrypted, so no existing byte moves.
    pub const STORED_LEN: usize = 28;
    pub const NONCE: usize = 32;
}

/// §4.
pub mod page_type {
    pub const FREE: u8 = 0;
    pub const BTREE_INTERNAL: u8 = 1;
    pub const BTREE_LEAF: u8 = 2;
    pub const OVERFLOW: u8 = 3;
    pub const BLOB: u8 = 4;
    pub const SEGMENT_HEADER: u8 = 5;
    pub const SEGMENT_FILTER: u8 = 6;
    pub const VLOG_SEGMENT: u8 = 7;
    pub const RTREE_INTERNAL: u8 = 8;
    pub const RTREE_LEAF: u8 = 9;
    pub const VECTOR_REGION: u8 = 10;
    pub const POSTINGS_BLOCK: u8 = 11;
}

/// §3's `flags`.
pub mod page_flags {
    pub const COMPRESSED: u8 = 1;
    pub const ENCRYPTED: u8 = 2;
    pub const HAS_OVERFLOW: u8 = 4;
    pub const EXTENT_HEAD: u8 = 8;
}

/// `11-conformance.md` §2.
pub mod feature {
    pub const CORE: u32 = 0;
    pub const DOCUMENTS: u32 = 1;
    pub const TEXT: u32 = 2;
    pub const SPATIAL: u32 = 3;
    pub const VECTOR: u32 = 4;
    pub const ZSTD: u32 = 5;
    pub const CIPHER: u32 = 6;
    pub const HASH64: u32 = 7;
    pub const DEC128: u32 = 8;
    pub const MULTIPROC: u32 = 9;
    pub const DEDUP: u32 = 10;
    pub const MULTIPROC_READ: u32 = 11;
    pub const ZDICT: u32 = 12;
    pub const TTL: u32 = 13;
    pub const CHANGEFEED: u32 = 14;
    pub const CHECKPOINTS: u32 = 15;

    pub fn bit(b: u32) -> u64 {
        1u64 << b
    }
}

/// Every bit this implementation knows how to interpret. `11-conformance.md`
/// §3: an unknown bit in `features_required` is a refusal, so this set is the
/// implementation's declared reach and nothing else.
pub const KNOWN_FEATURES: u64 = {
    let mut m = 0u64;
    let mut b = 0;
    while b <= 15 {
        m |= 1u64 << b;
        b += 1;
    }
    m
};

/// The `0xFFFFFFFF` of `00-conventions.md` §7 — the "no owning tree" sentinel.
pub const NO_TREE: u32 = 0xFFFF_FFFF;

pub fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
pub fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
pub fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
pub fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// `12-profiles.md` §1. Advisory in the file (§3): a reader uses the *values*
/// in the superblock, never the name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Profile {
    Custom,
    Mobile,
    Tablet,
    Desktop,
    Server,
}

impl Profile {
    pub fn code(self) -> u8 {
        match self {
            Profile::Custom => 0,
            Profile::Mobile => 1,
            Profile::Tablet => 2,
            Profile::Desktop => 3,
            Profile::Server => 4,
        }
    }
    pub fn from_code(c: u8) -> Profile {
        match c {
            1 => Profile::Mobile,
            2 => Profile::Tablet,
            3 => Profile::Desktop,
            4 => Profile::Server,
            _ => Profile::Custom,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Profile::Custom => "custom",
            Profile::Mobile => "mobile",
            Profile::Tablet => "tablet",
            Profile::Desktop => "desktop",
            Profile::Server => "server",
        }
    }
}

/// `10-transactions.md` §7 — what was *performed*, never what was requested.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Durability {
    None = 0,
    Os = 1,
    Sync = 2,
    Full = 3,
}

impl Durability {
    pub fn from_code(c: u8) -> Durability {
        match c {
            1 => Durability::Os,
            2 => Durability::Sync,
            3 => Durability::Full,
            _ => Durability::None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Durability::None => "none",
            Durability::Os => "os",
            Durability::Sync => "sync",
            Durability::Full => "full",
        }
    }
}

/// §2, in full. Every tuning constant is its own field — never derived from
/// `profile` — which is what makes a phone-written and a server-written file
/// the same format.
#[derive(Clone, Debug)]
pub struct Superblock {
    pub version_major: u16,
    pub version_minor: u16,
    pub write_version_minor: u16,
    pub page_size_log2: u16,
    pub commit_id: u64,
    pub features_required: u64,
    pub features_optional: u64,
    pub page_count: u64,
    pub visible_seq: u64,
    pub next_seq: u64,
    pub catalog_root: u64,
    pub freelist_root: u64,
    pub attributes_root: u64,
    pub manifest_root: u64,
    pub vlog_stats_root: u64,
    pub min_retained_commit: u64,
    pub min_retained_seq: u64,
    pub next_tree_id: u64,
    pub next_segment_id: u64,
    pub next_vlog_segment_id: u64,
    pub created_utc_ms: i64,
    pub modified_utc_ms: i64,
    pub database_uuid: [u8; 16],
    pub durability_achieved: u8,
    pub page_codec: u8,
    pub cipher: u8,
    pub level_count: u8,
    pub fanout: u8,
    pub l0_trigger: u8,
    pub tier_width: u8,
    pub memtable_shards: u8,
    pub vlog_min: u32,
    pub blob_threshold: u32,
    pub vlog_segment_bytes: u32,
    pub vlog_space_target_pct: u32,
    pub live_key_bytes: u64,
    pub live_value_bytes: u64,
    pub profile: u8,
    pub overlap_bound: u8,
    pub locality_debt_pct: u8,
    pub filter_bits_upper: u8,
    pub filter_bits_last: u8,
    pub readahead_window: u32,
    pub segment_target_bytes: u32,
    pub checkpoint_root: u64,
    pub changefeed_root: u64,
    pub writer_id: String,
    pub next_nonce: u64,
    pub sb_mac: [u8; 32],
    pub keyslots: [u8; 576],
    /// `11-conformance.md` §4 rule 5: a *rewriter* preserves reserved bytes; a
    /// *creator* writes zeros. Carrying the whole image is how that is kept.
    pub reserved: Vec<(usize, Vec<u8>)>,
}

impl Default for Superblock {
    fn default() -> Self {
        Superblock {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            write_version_minor: VERSION_MINOR,
            page_size_log2: 12,
            commit_id: 1,
            features_required: feature::bit(feature::CORE),
            features_optional: 0,
            page_count: 2,
            visible_seq: 0,
            next_seq: 1,
            catalog_root: 0,
            freelist_root: 0,
            attributes_root: 0,
            manifest_root: 0,
            vlog_stats_root: 0,
            min_retained_commit: 0,
            min_retained_seq: 0,
            next_tree_id: 16,
            next_segment_id: 1,
            next_vlog_segment_id: 1,
            created_utc_ms: 0,
            modified_utc_ms: 0,
            database_uuid: [0; 16],
            durability_achieved: 0,
            page_codec: 0,
            cipher: 0,
            level_count: 4,
            fanout: 8,
            l0_trigger: 4,
            tier_width: 4,
            memtable_shards: 8,
            vlog_min: 256,
            blob_threshold: 262144,
            vlog_segment_bytes: 64 << 20,
            vlog_space_target_pct: 150,
            live_key_bytes: 0,
            live_value_bytes: 0,
            profile: Profile::Desktop.code(),
            overlap_bound: 2,
            locality_debt_pct: 20,
            filter_bits_upper: 16,
            filter_bits_last: 10,
            readahead_window: 256,
            segment_target_bytes: 32 << 20,
            checkpoint_root: 0,
            changefeed_root: 0,
            writer_id: String::new(),
            next_nonce: 0,
            sb_mac: [0; 32],
            keyslots: [0; 576],
            reserved: Vec::new(),
        }
    }
}

impl Superblock {
    pub fn page_size(&self) -> usize {
        1usize << self.page_size_log2
    }

    /// §2.1 steps 2, 5 and `00-conventions.md` §8's `vlog_min` cap, which a
    /// reader MUST treat as corruption rather than as a tuning mistake.
    pub fn parse(b: &[u8]) -> Result<Superblock> {
        if b.len() < SUPERBLOCK_BYTES {
            return corrupt("superblock shorter than 4096 bytes");
        }
        if &b[sb::MAGIC..sb::MAGIC + 8] != MAGIC {
            return corrupt("not a Cryptand file: bad magic");
        }
        if crc32c(&b[0..sb::CHECKSUM]) != u32le(b, sb::CHECKSUM) {
            return corrupt("superblock checksum mismatch");
        }
        let version_major = u16le(b, sb::VERSION_MAJOR);
        if version_major != VERSION_MAJOR {
            return Err(Error::UnsupportedVersion(format!(
                "format major version {version_major} > {VERSION_MAJOR}"
            )));
        }
        let log2 = u16le(b, sb::PAGE_SIZE_LOG2);
        if !(12..=16).contains(&log2) {
            return corrupt(format!("page_size_log2 {log2} outside 12..16"));
        }
        let page_size = 1u32 << log2;
        let vlog_min = u32le(b, sb::VLOG_MIN);
        if vlog_min > page_size / 4 {
            return corrupt("vlog_min above page_size / 4");
        }
        let mut keyslots = [0u8; 576];
        keyslots.copy_from_slice(&b[sb::KEYSLOTS..sb::KEYSLOTS + 576]);
        Ok(Superblock {
            version_major,
            version_minor: u16le(b, sb::VERSION_MINOR),
            write_version_minor: u16le(b, sb::WRITE_VERSION_MINOR),
            page_size_log2: log2,
            commit_id: u64le(b, sb::COMMIT_ID),
            features_required: u64le(b, sb::FEATURES_REQUIRED),
            features_optional: u64le(b, sb::FEATURES_OPTIONAL),
            page_count: u64le(b, sb::PAGE_COUNT),
            visible_seq: u64le(b, sb::VISIBLE_SEQ),
            next_seq: u64le(b, sb::NEXT_SEQ),
            catalog_root: u64le(b, sb::CATALOG_ROOT),
            freelist_root: u64le(b, sb::FREELIST_ROOT),
            attributes_root: u64le(b, sb::ATTRIBUTES_ROOT),
            manifest_root: u64le(b, sb::MANIFEST_ROOT),
            vlog_stats_root: u64le(b, sb::VLOG_STATS_ROOT),
            min_retained_commit: u64le(b, sb::MIN_RETAINED_COMMIT),
            min_retained_seq: u64le(b, sb::MIN_RETAINED_SEQ),
            next_tree_id: u64le(b, sb::NEXT_TREE_ID),
            next_segment_id: u64le(b, sb::NEXT_SEGMENT_ID),
            next_vlog_segment_id: u64le(b, sb::NEXT_VLOG_SEGMENT_ID),
            created_utc_ms: u64le(b, sb::CREATED_UTC_MS) as i64,
            modified_utc_ms: u64le(b, sb::MODIFIED_UTC_MS) as i64,
            database_uuid: b[sb::DATABASE_UUID..sb::DATABASE_UUID + 16].try_into().unwrap(),
            durability_achieved: b[sb::DURABILITY_ACHIEVED],
            page_codec: b[sb::PAGE_CODEC],
            cipher: b[sb::CIPHER],
            level_count: b[sb::LEVEL_COUNT],
            fanout: b[sb::FANOUT],
            l0_trigger: b[sb::L0_TRIGGER],
            tier_width: b[sb::TIER_WIDTH],
            memtable_shards: b[sb::MEMTABLE_SHARDS],
            vlog_min,
            blob_threshold: u32le(b, sb::BLOB_THRESHOLD),
            vlog_segment_bytes: u32le(b, sb::VLOG_SEGMENT_BYTES),
            vlog_space_target_pct: u32le(b, sb::VLOG_SPACE_TARGET_PCT),
            live_key_bytes: u64le(b, sb::LIVE_KEY_BYTES),
            live_value_bytes: u64le(b, sb::LIVE_VALUE_BYTES),
            profile: b[sb::PROFILE],
            overlap_bound: b[sb::OVERLAP_BOUND],
            locality_debt_pct: b[sb::LOCALITY_DEBT_PCT],
            filter_bits_upper: b[sb::FILTER_BITS_UPPER],
            filter_bits_last: b[sb::FILTER_BITS_LAST],
            readahead_window: u32le(b, sb::READAHEAD_WINDOW),
            segment_target_bytes: u32le(b, sb::SEGMENT_TARGET_BYTES),
            checkpoint_root: u64le(b, sb::CHECKPOINT_ROOT),
            changefeed_root: u64le(b, sb::CHANGEFEED_ROOT),
            writer_id: String::from_utf8_lossy(&b[sb::WRITER_ID..sb::WRITER_ID + 32])
                .trim_end_matches('\0')
                .to_string(),
            next_nonce: u64le(b, sb::NEXT_NONCE),
            sb_mac: b[sb::SB_MAC..sb::SB_MAC + 32].try_into().unwrap(),
            keyslots,
            reserved: vec![
                (221, b[221..224].to_vec()),
                (248, b[248..256].to_vec()),
                (328, b[328..3512].to_vec()),
                (4088, b[4088..4092].to_vec()),
            ],
        })
    }

    /// Serializes to exactly 4096 bytes with the CRC as the last field.
    /// `sb_mac` is left as carried; `14-security.md` §6.2 has the writer set it
    /// *before* the checksum, which [`crate::security::seal_superblock`] does.
    pub fn encode(&self) -> [u8; SUPERBLOCK_BYTES] {
        let mut b = [0u8; SUPERBLOCK_BYTES];
        b[sb::MAGIC..sb::MAGIC + 8].copy_from_slice(MAGIC);
        put_u16(&mut b, sb::VERSION_MAJOR, self.version_major);
        put_u16(&mut b, sb::VERSION_MINOR, self.version_minor);
        put_u16(&mut b, sb::WRITE_VERSION_MINOR, self.write_version_minor);
        put_u16(&mut b, sb::PAGE_SIZE_LOG2, self.page_size_log2);
        put_u64(&mut b, sb::COMMIT_ID, self.commit_id);
        put_u64(&mut b, sb::FEATURES_REQUIRED, self.features_required);
        put_u64(&mut b, sb::FEATURES_OPTIONAL, self.features_optional);
        put_u64(&mut b, sb::PAGE_COUNT, self.page_count);
        put_u64(&mut b, sb::VISIBLE_SEQ, self.visible_seq);
        put_u64(&mut b, sb::NEXT_SEQ, self.next_seq);
        put_u64(&mut b, sb::CATALOG_ROOT, self.catalog_root);
        put_u64(&mut b, sb::FREELIST_ROOT, self.freelist_root);
        put_u64(&mut b, sb::ATTRIBUTES_ROOT, self.attributes_root);
        put_u64(&mut b, sb::MANIFEST_ROOT, self.manifest_root);
        put_u64(&mut b, sb::VLOG_STATS_ROOT, self.vlog_stats_root);
        put_u64(&mut b, sb::MIN_RETAINED_COMMIT, self.min_retained_commit);
        put_u64(&mut b, sb::MIN_RETAINED_SEQ, self.min_retained_seq);
        put_u64(&mut b, sb::NEXT_TREE_ID, self.next_tree_id);
        put_u64(&mut b, sb::NEXT_SEGMENT_ID, self.next_segment_id);
        put_u64(&mut b, sb::NEXT_VLOG_SEGMENT_ID, self.next_vlog_segment_id);
        put_u64(&mut b, sb::CREATED_UTC_MS, self.created_utc_ms as u64);
        put_u64(&mut b, sb::MODIFIED_UTC_MS, self.modified_utc_ms as u64);
        b[sb::DATABASE_UUID..sb::DATABASE_UUID + 16].copy_from_slice(&self.database_uuid);
        b[sb::DURABILITY_ACHIEVED] = self.durability_achieved;
        b[sb::PAGE_CODEC] = self.page_codec;
        b[sb::CIPHER] = self.cipher;
        b[sb::LEVEL_COUNT] = self.level_count;
        b[sb::FANOUT] = self.fanout;
        b[sb::L0_TRIGGER] = self.l0_trigger;
        b[sb::TIER_WIDTH] = self.tier_width;
        b[sb::MEMTABLE_SHARDS] = self.memtable_shards;
        put_u32(&mut b, sb::VLOG_MIN, self.vlog_min);
        put_u32(&mut b, sb::BLOB_THRESHOLD, self.blob_threshold);
        put_u32(&mut b, sb::VLOG_SEGMENT_BYTES, self.vlog_segment_bytes);
        put_u32(&mut b, sb::VLOG_SPACE_TARGET_PCT, self.vlog_space_target_pct);
        put_u64(&mut b, sb::LIVE_KEY_BYTES, self.live_key_bytes);
        put_u64(&mut b, sb::LIVE_VALUE_BYTES, self.live_value_bytes);
        b[sb::PROFILE] = self.profile;
        b[sb::OVERLAP_BOUND] = self.overlap_bound;
        b[sb::LOCALITY_DEBT_PCT] = self.locality_debt_pct;
        b[sb::FILTER_BITS_UPPER] = self.filter_bits_upper;
        b[sb::FILTER_BITS_LAST] = self.filter_bits_last;
        put_u32(&mut b, sb::READAHEAD_WINDOW, self.readahead_window);
        put_u32(&mut b, sb::SEGMENT_TARGET_BYTES, self.segment_target_bytes);
        put_u64(&mut b, sb::CHECKPOINT_ROOT, self.checkpoint_root);
        put_u64(&mut b, sb::CHANGEFEED_ROOT, self.changefeed_root);
        let w = self.writer_id.as_bytes();
        let n = w.len().min(32);
        b[sb::WRITER_ID..sb::WRITER_ID + n].copy_from_slice(&w[..n]);
        put_u64(&mut b, sb::NEXT_NONCE, self.next_nonce);
        b[sb::SB_MAC..sb::SB_MAC + 32].copy_from_slice(&self.sb_mac);
        b[sb::KEYSLOTS..sb::KEYSLOTS + 576].copy_from_slice(&self.keyslots);
        // §4 rule 5 of `11-conformance.md`: copy reserved bytes forward.
        for (at, bytes) in &self.reserved {
            b[*at..*at + bytes.len()].copy_from_slice(bytes);
        }
        let crc = crc32c(&b[0..sb::CHECKSUM]);
        put_u32(&mut b, sb::CHECKSUM, crc);
        b
    }

    /// §2.1 step 5.
    pub fn check_features(&self) -> Result<()> {
        let unknown = self.features_required & !KNOWN_FEATURES;
        if unknown != 0 {
            return Err(Error::UnknownFeature { bit: unknown.trailing_zeros() });
        }
        Ok(())
    }

    /// §2.1 step 6 — a file whose `write_version_minor` exceeds ours opens
    /// read-only, it is not refused (`00-conventions.md` §9).
    pub fn writable(&self) -> bool {
        self.write_version_minor <= VERSION_MINOR
    }

    pub fn set_feature(&mut self, bit: u32, required: bool) {
        if required {
            self.features_required |= feature::bit(bit);
        } else {
            self.features_optional |= feature::bit(bit);
        }
    }
}

/// §3, the 40-byte header every page but the two superblocks begins with.
#[derive(Clone, Copy, Debug)]
pub struct PageHeader {
    pub checksum: u32,
    pub page_type: u8,
    pub flags: u8,
    pub codec: u16,
    pub tree_id: u32,
    pub extent_pages: u32,
    pub commit_id: u64,
    pub payload_len: u32,
    /// `14-security.md` §5.2. `01-container.md` §3 defines `payload_len` as the
    /// "uncompressed, unencrypted payload length" while §5.2 says the AEAD tag
    /// "is inside `payload_len`" — the two cannot both hold, and neither is
    /// implementable alone: a decryptor needs the exact stored length (Poly1305
    /// covers exactly the ciphertext) and a decompressor needs the plaintext
    /// length. Both are kept, `payload_len` meaning what §3 says and this
    /// field, in the reserved u32 at offset 28, meaning what §5.2 needs.
    pub stored_len: u32,
    pub nonce: u64,
}

/// `01-container.md` §3 fixes `extent_pages` at "**1** for an ordinary page;
/// > 1 for a multi-page extent head", so the default cannot be `u32::default()`.
///
/// It was, via `#[derive(Default)]` plus `..Default::default()` at every
/// ordinary-page construction site — so this implementation wrote a **0** into
/// that field on every B+tree page, every filter page and every segment leaf it
/// has ever produced. Nothing here noticed, because nothing here reads the
/// field on a page it already knows is one page long. The Java implementation
/// found it, could not refuse it without making files it had to read unopenable,
/// and carries a written-out accommodation for it to this day; the Dart
/// implementation's §9.1 bounds check refused it outright, which is what a
/// reader that trusts §3 does.
///
/// It matters beyond tidiness for one reason: `14-security.md` §5.2 makes the
/// 40-byte page header the AEAD's **AAD**, so the byte is authenticated. Two
/// SDKs that disagree about what belongs in it cannot decrypt each other's
/// pages at all — and the field being pure redundancy on an ordinary page is
/// exactly why the disagreement stays invisible until encryption is turned on.
impl Default for PageHeader {
    fn default() -> PageHeader {
        PageHeader {
            checksum: 0,
            page_type: 0,
            flags: 0,
            codec: 0,
            tree_id: 0,
            extent_pages: 1,
            commit_id: 0,
            payload_len: 0,
            stored_len: 0,
            nonce: 0,
        }
    }
}

impl PageHeader {
    pub fn parse(b: &[u8]) -> Result<PageHeader> {
        if b.len() < PAGE_HEADER_BYTES {
            return corrupt("page header shorter than 40 bytes");
        }
        Ok(PageHeader {
            checksum: u32le(b, ph::CHECKSUM),
            page_type: b[ph::PAGE_TYPE],
            flags: b[ph::FLAGS],
            codec: u16le(b, ph::CODEC_OR_RESERVED),
            tree_id: u32le(b, ph::TREE_ID),
            extent_pages: u32le(b, ph::EXTENT_PAGES),
            commit_id: u64le(b, ph::COMMIT_ID),
            payload_len: u32le(b, ph::PAYLOAD_LEN),
            stored_len: u32le(b, ph::STORED_LEN),
            nonce: u64le(b, ph::NONCE),
        })
    }

    /// Writes the header into a whole page and recomputes the CRC over
    /// `4..page_size-1` **as stored** (`00-conventions.md` §6).
    pub fn write_into(&self, page: &mut [u8]) {
        page[ph::PAGE_TYPE] = self.page_type;
        page[ph::FLAGS] = self.flags;
        put_u16(page, ph::CODEC_OR_RESERVED, self.codec);
        put_u32(page, ph::TREE_ID, self.tree_id);
        put_u32(page, ph::EXTENT_PAGES, self.extent_pages);
        put_u64(page, ph::COMMIT_ID, self.commit_id);
        put_u32(page, ph::PAYLOAD_LEN, self.payload_len);
        put_u32(page, ph::STORED_LEN, self.stored_len);
        put_u64(page, ph::NONCE, self.nonce);
        let end = PageHeader::checksum_range_end(page, self);
        let crc = crc32c(&page[4..end]);
        put_u32(page, ph::CHECKSUM, crc);
    }

    /// §3: `checksum` verifies before decompression and before decryption, so
    /// a corrupt page is never fed to a codec or a cipher.
    ///
    /// **A value-log head page is the one exception, and the spec does not
    /// state it.** `04-segments.md` §6.2 fixes `data_offset` at 104, so a
    /// segment's records begin *inside its head page* — which `01-container.md`
    /// §1 explicitly permits ("an append into the open tail of a value-log
    /// segment"). A checksum over the whole page would therefore be stale from
    /// the first append onward: the page would fail its own checksum for the
    /// entire life of the segment. §3's carve-out — "a verifier MUST use the
    /// extent's mechanism for these pages" — is only satisfiable if the head
    /// page's checksum covers its immutable header region, `4 .. data_offset`,
    /// and the records are covered by their own per-record `crc32c`.
    pub fn verify(page: &[u8], page_id: u64) -> Result<PageHeader> {
        let h = PageHeader::parse(page)?;
        let end = PageHeader::checksum_range_end(page, &h);
        if crc32c(&page[4..end]) != h.checksum {
            return corrupt(format!("page {page_id} checksum mismatch"));
        }
        h.check_bounds(page.len(), page_id)?;
        Ok(h)
    }

    /// `14-security.md` §9.1 — "a decoder MUST bounds-check against the
    /// containing page or extent **before allocating**".
    ///
    /// The three length fields come straight out of the file and every one of
    /// them is an offset into a buffer somewhere. There was no check here at
    /// all: the shared conformance corpus's `v1.0-corrupt-huge-len.cryptand`
    /// sets `payload_len` to `0xFFFF_FFFC` with the checksum repaired, and this
    /// reader **opened, read and verified it clean**. Nothing crashed, because
    /// a Rust slice refuses an out-of-range index rather than reading past it —
    /// but §9.1 requires a *typed corruption error*, and silently proceeding on
    /// a length an attacker chose is not one. Memory safety made the failure
    /// quiet; it did not make it correct.
    ///
    /// The bound is the **extent**, not the page: §3 lets a multi-page extent
    /// head declare a payload that runs across its interior pages, and
    /// `extent_pages` says how far.
    ///
    /// `extent_pages = 0` is refused only on an extent head. Elsewhere the
    /// field is pure redundancy — the page is one page by definition — and this
    /// implementation itself wrote 0 there on every ordinary page for as long
    /// as `PageHeader` derived `Default`, so refusing it outright would make
    /// files it wrote unopenable.
    ///
    /// **The arithmetic must not overflow.** `extent_pages` and `page_size` are
    /// both `u32`-wide and their product does not fit a `u32`; computing the
    /// capacity by multiplication in a 32-bit type wraps, and a wrapped
    /// capacity turns the check into an accept. It is written below as a sum in
    /// `u64` for that reason.
    pub fn check_bounds(&self, page_bytes: usize, page_id: u64) -> Result<()> {
        let extent_head = self.flags & page_flags::EXTENT_HEAD != 0;
        if self.extent_pages == 0 && extent_head {
            return corrupt(format!(
                "page {page_id}: extent_pages is 0 on an extent head, which is the                  only record of the extent's length"
            ));
        }
        let pages = self.extent_pages.max(1) as u64;
        let capacity = (page_bytes as u64).saturating_sub(PAGE_HEADER_BYTES as u64)
            + (pages - 1) * page_bytes as u64;
        if self.payload_len as u64 > capacity {
            return corrupt(format!(
                "page {page_id}: payload_len {} is past its {pages}-page extent ({capacity} usable)",
                self.payload_len
            ));
        }
        if self.stored_len as u64 > capacity {
            return corrupt(format!(
                "page {page_id}: stored_len {} is past its {pages}-page extent ({capacity} usable)",
                self.stored_len
            ));
        }
        Ok(())
    }

    /// The end of the checksummed range for this page.
    pub fn checksum_range_end(page: &[u8], h: &PageHeader) -> usize {
        if h.page_type == page_type::VLOG_SEGMENT && page.len() >= PAGE_HEADER_BYTES + 36 {
            let data_offset = u32le(page, PAGE_HEADER_BYTES + 32) as usize;
            if data_offset > PAGE_HEADER_BYTES && data_offset <= page.len() {
                return data_offset;
            }
        }
        page.len()
    }

    pub fn encrypted(&self) -> bool {
        self.flags & page_flags::ENCRYPTED != 0
    }
    pub fn compressed(&self) -> bool {
        self.flags & page_flags::COMPRESSED != 0
    }
    /// The bytes actually on the page, which is what a cipher and a codec both
    /// have to be handed.
    pub fn stored(&self) -> usize {
        if self.stored_len != 0 {
            self.stored_len as usize
        } else {
            self.payload_len as usize
        }
    }
}
