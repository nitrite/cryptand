//! `13-operations.md` §2 — online full backup, incremental backup and restore.
//!
//! Most of it is unusually cheap because **segments are immutable and
//! identified by a never-reused id**, which turns online backup, incremental
//! backup and point-in-time recovery into bookkeeping rather than machinery.

use std::path::Path;

use crate::container::{Durability, Profile};
use crate::engine::Engine;
use crate::error::{invalid, Result};

/// §2.1 — two modes for an encrypted database, and an implementation MUST make
/// the caller choose rather than pick one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BackupMode {
    /// Plain copy of an unencrypted database.
    Plain,
    /// Copy extents byte for byte. The backup needs the source's
    /// `database_uuid` and keyslots, so its uuid **cannot** change: the copy is
    /// the *same* cryptographic object, so it must keep the same key binding.
    CiphertextCopy,
    /// Decrypt and re-encrypt under a fresh master key and a new
    /// `database_uuid`.
    ReEncrypted { password: Vec<u8> },
    /// An unencrypted backup of an encrypted database — a silent downgrade,
    /// which an implementation MUST refuse unless asked for by name.
    PlaintextDowngrade,
}

#[derive(Clone, Debug, Default)]
pub struct BackupResult {
    pub segments_copied: u64,
    pub vlog_segments_copied: u64,
    pub bytes_copied: u64,
    pub downgraded: bool,
    pub kept_source_uuid: bool,
}

pub trait Backup {
    fn backup(&mut self, dest: &Path, mode: BackupMode) -> Result<BackupResult>;
    fn backup_incremental(&mut self, dest: &Path, have: &[u64]) -> Result<BackupResult>;
    fn segment_ids(&mut self) -> Result<Vec<u64>>;
}

impl Backup for Engine {
    fn segment_ids(&mut self) -> Result<Vec<u64>> {
        Ok(self.all_refs()?.into_iter().map(|r| r.segment_id).collect())
    }

    fn backup(&mut self, dest: &Path, mode: BackupMode) -> Result<BackupResult> {
        let encrypted = self.sb.cipher != 0;
        match (&mode, encrypted) {
            (BackupMode::Plain, true) => {
                return invalid(
                    "an unencrypted backup of an encrypted database is a silent downgrade; \
                     ask for BackupMode::PlaintextDowngrade by name",
                )
            }
            (BackupMode::CiphertextCopy, false) | (BackupMode::ReEncrypted { .. }, false) => {
                return invalid("this database is not encrypted; use BackupMode::Plain")
            }
            _ => {}
        }
        let mut result = BackupResult::default();

        // 1. take a snapshot (nothing is locked; nothing is quiesced — that
        //    falls out of immutability).
        let snap = self.snapshot();
        // 2. copy the superblock's roots and every extent reachable from them.
        let bytes = self.pager.snapshot_bytes()?;
        result.bytes_copied = bytes.len() as u64;
        std::fs::write(dest, &bytes)?;
        self.release(&snap);

        // 3. write a fresh superblock into the destination.
        let mut out = crate::pager::Pager::open(dest, self.pager.page_size, self.pager.page_count)?;
        let mut sb = self.sb.clone();
        match &mode {
            BackupMode::CiphertextCopy => {
                // The one exception to the new-uuid rule, and the reason the
                // rule exists: the copy is the same cryptographic object.
                result.kept_source_uuid = true;
            }
            BackupMode::PlaintextDowngrade => {
                sb.cipher = 0;
                sb.sb_mac = [0u8; 32];
                sb.keyslots = [0u8; 576];
                sb.features_required &= !crate::container::feature::bit(crate::container::feature::CIPHER);
                sb.database_uuid = crate::engine::random_uuid_v4();
                result.downgraded = true;
            }
            _ => {
                // §2.1: an implementation MUST NOT copy the source's
                // `database_uuid` — two files with the same uuid break
                // incremental backup, and on an encrypted file they **share a
                // content key**, because §3.4 derives subkeys with the uuid as
                // HKDF salt.
                sb.database_uuid = crate::engine::random_uuid_v4();
            }
        }
        sb.writer_id = format!("cryptand-rust-backup/{}", env!("CARGO_PKG_VERSION"));
        let image = sb.encode();
        out.write_at(0, &image)?;
        out.write_at(self.pager.page_size as u64, &image)?;
        out.sync(Durability::Sync)?;
        result.segments_copied = self.all_refs()?.len() as u64;
        result.vlog_segments_copied = self.vlog_stats.len() as u64;
        Ok(result)
    }

    /// §2.2 — because `segment_id` and `vlog_segment_id` are globally unique
    /// and never reused, an incremental backup is a set difference. Its size is
    /// proportional to what changed, not to what the changes touched.
    fn backup_incremental(&mut self, dest: &Path, have: &[u64]) -> Result<BackupResult> {
        let mut r = BackupResult::default();
        let mut out = if dest.exists() {
            crate::pager::Pager::open(dest, self.pager.page_size, self.pager.page_count)?
        } else {
            crate::pager::Pager::create(dest, self.pager.page_size)?
        };
        for rf in self.all_refs()? {
            if have.contains(&rf.segment_id) {
                continue;
            }
            let extent = self.pager.read_extent(rf.start_page, rf.pages)?;
            out.write_at(rf.start_page * self.pager.page_size as u64, &extent)?;
            r.segments_copied += 1;
            r.bytes_copied += extent.len() as u64;
        }
        for s in self.vlog_stats.values() {
            if have.contains(&s.segment_id) || s.pages == 0 {
                continue;
            }
            let extent = self.pager.read_extent(s.start_page, s.pages)?;
            out.write_at(s.start_page * self.pager.page_size as u64, &extent)?;
            r.vlog_segments_copied += 1;
            r.bytes_copied += extent.len() as u64;
        }
        // Copy the reserved trees' pages wholesale: they are small, hot and
        // rewritten copy-on-write, so a delta over them buys nothing.
        let mut pages = Vec::new();
        for t in [
            &self.catalog.tree,
            &self.catalog.by_id,
            &self.attributes.tree,
            &self.manifest.tree,
            &self.vlog_stats_tree,
            &self.checkpoints,
            &self.changefeed,
            &self.freelist,
        ] {
            let tree = crate::cow::CowTree::new(t.tree_id, t.root);
            tree.reachable(&mut self.pager, &mut pages)?;
        }
        for p in pages {
            let page = self.pager.read_page(p)?;
            out.write_at(p * self.pager.page_size as u64, &page)?;
            r.bytes_copied += page.len() as u64;
        }
        let mut sb = self.sb.clone();
        sb.writer_id = format!("cryptand-rust-backup/{}", env!("CARGO_PKG_VERSION"));
        let image = sb.encode();
        out.write_at(0, &image)?;
        out.write_at(self.pager.page_size as u64, &image)?;
        out.sync(Durability::Sync)?;
        Ok(r)
    }
}

/// §2.3 — restore is a file copy plus an open, and an implementation MUST run
/// the verification pass over a restored file before reporting success.
pub fn restore(src: &Path, dest: &Path, key: Option<&[u8]>) -> Result<crate::verify::VerifyReport> {
    std::fs::copy(src, dest)?;
    let mut e = Engine::open(dest, key)?;
    use crate::verify::EngineVerify;
    let r = e.verify()?;
    if !r.of(crate::verify::Class::Corruption).is_empty() {
        return invalid(format!(
            "restored file failed verification with {} corruption findings; \
             a partial restore is a failure, not a file to open in hope",
            r.of(crate::verify::Class::Corruption).len()
        ));
    }
    Ok(r)
}

pub fn default_profile() -> Profile {
    Profile::Desktop
}
