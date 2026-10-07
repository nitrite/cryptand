//! `13-operations.md` §5 `encrypt()` and `14-security.md` §8.3/§8.4: turning
//! encryption on in place (F-072).
//!
//! `encrypt()` switches the mode — `cipher = 1`, a keyslot, the open value-log
//! segments sealed — in one commit. From then on every page and every new
//! value-log segment is written encrypted, and a reader decides per page
//! (`flags.ENCRYPTED`), per value-log segment (head byte 39) and per blob
//! (its head page), never from `cipher`. [`ConvertApi::convert_step`] then
//! rewrites what is still plaintext, one kind of object per step; a file
//! interrupted anywhere is a valid file and the next call carries on.
//!
//! A plaintext page may be full to `page_size − 40`, which leaves no room for
//! the 16-byte tag, so pages are re-laid (compaction, tree rebuilds), never
//! re-sealed in place.

use std::collections::HashSet;

use crate::container::{feature, Durability, PageHeader};
use crate::engine::Engine;
use crate::error::{invalid, Result};
use crate::security::{keyslot, make_keyslot, random_bytes, KeyRing};
use crate::spaceapi::Step;

/// 14 §8.3: "an implementation MUST expose the fraction converted". Counted
/// in objects, each rewritten whole: segments, tree pages, value-log segments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Conversion {
    pub converted: u64,
    pub remaining: u64,
}

impl Conversion {
    pub fn done(&self) -> bool {
        self.remaining == 0
    }
    pub fn fraction(&self) -> f64 {
        let all = self.converted + self.remaining;
        if all == 0 { 1.0 } else { self.converted as f64 / all as f64 }
    }
}

/// The explicit confirmation `decrypt()` requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmDecrypt {
    No,
    RemoveEncryption,
}

pub trait ConvertApi {
    /// Turns encryption on: `kdf` 0 is a raw 32-byte key, 1 Argon2id.
    fn encrypt(&mut self, credential: &[u8], kdf: u8, t_cost: u32, m_cost_kib: u32, lanes: u32) -> Result<()>;
    /// 14 §8.3's mirror, which "MUST make the user confirm it, because it is a
    /// silent downgrade of everything": refused unless `confirm` is
    /// [`ConfirmDecrypt::RemoveEncryption`]. Switches the write mode to
    /// plaintext; `cipher` and the keyslots stay until [`ConvertApi::convert_step`]
    /// has rewritten every encrypted object, then one step clears them.
    /// Not persisted: after a reopen, call it again to carry on.
    fn decrypt(&mut self, confirm: ConfirmDecrypt) -> Result<()>;
    /// Rewrites one kind of object not yet in the target mode, then commits.
    fn convert_step(&mut self) -> Result<Step>;
    /// What is converted and what is not, read from the objects themselves.
    fn conversion(&mut self) -> Result<Conversion>;
    /// True only when the file is encrypted and nothing plaintext remains
    /// (14 §8.3: never a reassuring answer while plaintext remains).
    fn fully_encrypted(&mut self) -> Result<bool>;
}

struct Census {
    /// Objects not yet in the target mode (`plain_*` when encrypting).
    plain_segments: Vec<crate::manifest::SegmentRef>,
    plain_tree_pages: u64,
    plain_vlog: Vec<u64>,
    converted: u64,
}

fn census(e: &mut Engine) -> Result<Census> {
    // The target: encrypted, unless `decrypt()` is under way.
    let want = !e.pager.write_clear;
    let mut c = Census { plain_segments: Vec::new(), plain_tree_pages: 0, plain_vlog: Vec::new(), converted: 0 };
    for r in e.all_refs()? {
        if page_encrypted(e, r.start_page)? == want {
            c.converted += 1;
        } else {
            c.plain_segments.push(r);
        }
    }
    let mut pages = Vec::new();
    for t in [
        &e.catalog.tree,
        &e.catalog.by_id,
        &e.attributes.tree,
        &e.manifest.tree,
        &e.vlog_stats_tree,
        &e.checkpoints,
        &e.changefeed,
    ] {
        t.reachable(&mut e.pager, &mut pages)?;
    }
    for p in pages.into_iter().collect::<HashSet<_>>() {
        if page_encrypted(e, p)? == want {
            c.converted += 1;
        } else {
            c.plain_tree_pages += 1;
        }
    }
    let ids: Vec<u64> = e.vlog_stats.values().filter(|s| !s.retired() && s.pages > 0).map(|s| s.segment_id).collect();
    for id in ids {
        if e.vlog_encrypted(id)? == want {
            c.converted += 1;
        } else {
            c.plain_vlog.push(id);
        }
    }
    Ok(c)
}

fn page_encrypted(e: &mut Engine, page: u64) -> Result<bool> {
    Ok(PageHeader::parse(&e.pager.read_page_clear(page)?)?.encrypted())
}

impl ConvertApi for Engine {
    fn encrypt(&mut self, credential: &[u8], kdf: u8, t_cost: u32, m_cost_kib: u32, lanes: u32) -> Result<()> {
        if self.sb.cipher != 0 {
            return invalid("the file is already encrypted");
        }
        // A compaction in flight laid its pages out for plaintext; finish it
        // before the tag reserve changes under it.
        self.drain_compaction()?;
        // Their records would be the wrong kind for an encrypted tail.
        self.seal_unsealed_vlog_segments()?;
        let master = random_bytes::<32>();
        let slot = make_keyslot(&master, &self.sb.database_uuid, 0, credential, kdf, t_cost, m_cost_kib, lanes, "keyslot 0")?;
        self.sb.keyslots[..keyslot::SIZE].copy_from_slice(&slot.encode());
        self.sb.cipher = 1;
        self.sb.set_feature(feature::CIPHER, true);
        self.keys = Some(KeyRing::from_master(master, self.sb.database_uuid, 0));
        self.commit(Durability::Sync)?;
        Ok(())
    }

    fn decrypt(&mut self, confirm: ConfirmDecrypt) -> Result<()> {
        if confirm != ConfirmDecrypt::RemoveEncryption {
            return invalid("decrypt() removes encryption from the whole file; it needs ConfirmDecrypt::RemoveEncryption");
        }
        if self.sb.cipher == 0 || self.keys.is_none() {
            return invalid("the file is not encrypted, or is not unlocked");
        }
        self.drain_compaction()?;
        self.seal_unsealed_vlog_segments()?;
        self.arm()?; // the cipher stays installed: encrypted pages must still read
        self.pager.write_clear = true;
        self.commit(Durability::Sync)?;
        Ok(())
    }

    // ponytail: one step is one whole kind of object (all plaintext segments,
    // all tree pages, all plaintext value-log segments), not a slice bounded by
    // `max_foreground_stall_ms` (12 §4). Slice each phase if a large file's
    // conversion stalls a foreground caller.
    fn convert_step(&mut self) -> Result<Step> {
        if self.sb.cipher == 0 || self.keys.is_none() {
            return invalid("the file is not encrypted, or is not unlocked; call encrypt() first");
        }
        let c = census(self)?;
        if !c.plain_segments.is_empty() {
            // Same-level compactions: the outputs are laid out with the tag
            // reserved and sealed; nothing moves between levels.
            let mut by_level: std::collections::BTreeMap<u8, Vec<_>> = Default::default();
            for r in c.plain_segments {
                by_level.entry(r.level).or_default().push(r);
            }
            for (level, inputs) in by_level {
                if let Some(mut job) = self.begin_compaction(inputs, level)? {
                    while self.step_compaction(&mut job, None)? {}
                    self.finish_compaction(job)?;
                }
            }
        } else if c.plain_tree_pages > 0 {
            self.relocate_trees()?;
        } else if !c.plain_vlog.is_empty() {
            self.rewrite_vlog_segments(c.plain_vlog)?;
            // The rewrite moved pointers through the memtable.
            self.flush()?;
        } else if self.pager.write_clear {
            // Nothing encrypted remains: one superblock drops the cipher and
            // the keyslots together, so no file ever says `cipher = 0` while
            // carrying keyslots (14 §6.1). Twice, so neither slot keeps them.
            self.sb.keyslots.fill(0);
            self.sb.cipher = 0;
            self.sb.features_required &= !feature::bit(feature::CIPHER);
            self.sb.features_optional &= !feature::bit(feature::CIPHER);
            // Key dropped first: with `cipher = 0`, `sb_mac` is written as
            // zero (14 §6.2), and Dart refuses a plaintext superblock with one.
            self.keys = None;
            self.sb.sb_mac = [0; 32];
            self.pager.crypto = None;
            self.pager.write_clear = false;
            self.commit(Durability::Sync)?;
            self.commit(Durability::Sync)?;
            return Ok(Step::Done);
        } else {
            return Ok(Step::Done);
        }
        self.commit(Durability::Sync)?;
        Ok(if self.conversion()?.done() && !self.pager.write_clear { Step::Done } else { Step::More })
    }

    fn conversion(&mut self) -> Result<Conversion> {
        let c = census(self)?;
        let remaining = c.plain_segments.len() as u64 + c.plain_tree_pages + c.plain_vlog.len() as u64;
        Ok(Conversion { converted: c.converted, remaining })
    }

    fn fully_encrypted(&mut self) -> Result<bool> {
        Ok(self.sb.cipher != 0 && !self.pager.write_clear && self.conversion()?.done())
    }
}
