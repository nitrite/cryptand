//! `13-operations.md` §1 — checkpoints: named, retained snapshots in tree 8.

use crate::catalog::tree_id;
use crate::cke;
use crate::container::feature;
use crate::cve;
use crate::engine::{Engine, Snapshot};
use crate::error::{invalid, Result};
use crate::value::{NumType, Value};

#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub name: String,
    pub commit_id: u64,
    pub seq: u64,
    pub created: i64,
    pub catalog_root: u64,
    pub freelist_root: u64,
    pub attributes_root: u64,
    pub manifest_root: u64,
    pub vlog_stats_root: u64,
    pub changefeed_root: u64,
    pub expires: Option<i64>,
}

fn u64v(v: u64) -> Value {
    Value::Int { w: NumType::U64, neg: false, mag: v as u128 }
}

impl Checkpoint {
    pub fn encode(&self) -> Vec<u8> {
        let mut f = vec![
            ("commit_id".to_string(), u64v(self.commit_id)),
            ("seq".to_string(), u64v(self.seq)),
            ("created".to_string(), Value::Timestamp(self.created)),
            ("catalog_root".to_string(), u64v(self.catalog_root)),
            ("freelist_root".to_string(), u64v(self.freelist_root)),
            ("attributes_root".to_string(), u64v(self.attributes_root)),
            ("manifest_root".to_string(), u64v(self.manifest_root)),
            ("vlog_stats_root".to_string(), u64v(self.vlog_stats_root)),
            ("changefeed_root".to_string(), u64v(self.changefeed_root)),
        ];
        if let Some(x) = self.expires {
            f.push(("expires".to_string(), Value::Timestamp(x)));
        }
        cve::encode(&Value::Doc(f))
    }

    pub fn decode(name: String, v: &[u8]) -> Result<Checkpoint> {
        let d = cve::decode_all(v, &|_| None)?;
        let u = |f: &str| -> u64 {
            match d.field(f) {
                Some(Value::Int { mag, .. }) => *mag as u64,
                _ => 0,
            }
        };
        Ok(Checkpoint {
            name,
            commit_id: u("commit_id"),
            seq: u("seq"),
            created: match d.field("created") {
                Some(Value::Timestamp(t)) => *t,
                _ => 0,
            },
            catalog_root: u("catalog_root"),
            freelist_root: u("freelist_root"),
            attributes_root: u("attributes_root"),
            manifest_root: u("manifest_root"),
            vlog_stats_root: u("vlog_stats_root"),
            changefeed_root: u("changefeed_root"),
            expires: match d.field("expires") {
                Some(Value::Timestamp(t)) => Some(*t),
                _ => None,
            },
        })
    }

    pub fn as_snapshot(&self) -> Snapshot {
        Snapshot {
            seq: self.seq,
            commit_id: self.commit_id,
            catalog_root: self.catalog_root,
            freelist_root: self.freelist_root,
            attributes_root: self.attributes_root,
            manifest_root: self.manifest_root,
            vlog_stats_root: self.vlog_stats_root,
            // Deliberately NOT captured: restoring a checkpoint must not delete
            // the other checkpoints, so a restore keeps the *current*
            // `checkpoint_root` and replaces the other eight.
            checkpoint_root: 0,
            changefeed_root: self.changefeed_root,
            created_ms: self.created,
        }
    }
}

fn key_of(name: &str) -> Vec<u8> {
    cke::encode(&Value::Str(name.to_string())).expect("STR is CKE-encodable")
}

pub trait Checkpoints {
    fn create_checkpoint(&mut self, name: &str, expires: Option<i64>) -> Result<Checkpoint>;
    fn checkpoint(&mut self, name: &str) -> Result<Option<Checkpoint>>;
    fn list_checkpoints(&mut self) -> Result<Vec<Checkpoint>>;
    fn drop_checkpoint(&mut self, name: &str) -> Result<bool>;
    fn drop_expired_checkpoints(&mut self, now_ms: i64) -> Result<Vec<String>>;
    fn restore_checkpoint(&mut self, name: &str) -> Result<()>;
    fn checkpoint_would_pin(&mut self) -> u64;
}

impl Checkpoints for Engine {
    fn create_checkpoint(&mut self, name: &str, expires: Option<i64>) -> Result<Checkpoint> {
        let s = self.snapshot();
        self.release(&s);
        let c = Checkpoint {
            name: name.to_string(),
            commit_id: s.commit_id,
            seq: s.seq,
            created: s.created_ms,
            catalog_root: s.catalog_root,
            freelist_root: s.freelist_root,
            attributes_root: s.attributes_root,
            manifest_root: s.manifest_root,
            vlog_stats_root: s.vlog_stats_root,
            changefeed_root: s.changefeed_root,
            expires,
        };
        let mut t = std::mem::replace(&mut self.checkpoints, crate::cow::CowTree::new(tree_id::CHECKPOINTS, 0));
        t.commit_id = self.sb.commit_id;
        let r = t.put(&mut self.pager, &key_of(name), &c.encode());
        self.checkpoints = t;
        r?;
        self.sb.set_feature(feature::CHECKPOINTS, false);
        self.refresh_checkpoint_floors()?;
        Ok(c)
    }

    fn checkpoint(&mut self, name: &str) -> Result<Option<Checkpoint>> {
        let t = std::mem::replace(&mut self.checkpoints, crate::cow::CowTree::new(tree_id::CHECKPOINTS, 0));
        let v = t.get(&mut self.pager, &key_of(name));
        self.checkpoints = t;
        match v? {
            Some(v) => Ok(Some(Checkpoint::decode(name.to_string(), &v)?)),
            None => Ok(None),
        }
    }

    fn list_checkpoints(&mut self) -> Result<Vec<Checkpoint>> {
        let t = std::mem::replace(&mut self.checkpoints, crate::cow::CowTree::new(tree_id::CHECKPOINTS, 0));
        let rows = t.scan(&mut self.pager, None, None);
        self.checkpoints = t;
        let mut out = Vec::new();
        for (k, v) in rows? {
            let name = match cke::decode_all(&k)? {
                Value::Str(s) => s,
                _ => continue,
            };
            out.push(Checkpoint::decode(name, &v)?);
        }
        Ok(out)
    }

    fn drop_checkpoint(&mut self, name: &str) -> Result<bool> {
        let mut t = std::mem::replace(&mut self.checkpoints, crate::cow::CowTree::new(tree_id::CHECKPOINTS, 0));
        t.commit_id = self.sb.commit_id;
        let r = t.remove(&mut self.pager, &key_of(name));
        self.checkpoints = t;
        let removed = r?;
        self.refresh_checkpoint_floors()?;
        Ok(removed)
    }

    /// §1 — honour `expires` and drop the checkpoint automatically past it.
    fn drop_expired_checkpoints(&mut self, now_ms: i64) -> Result<Vec<String>> {
        let mut dropped = Vec::new();
        for c in self.list_checkpoints()? {
            if matches!(c.expires, Some(x) if x <= now_ms) {
                self.drop_checkpoint(&c.name)?;
                dropped.push(c.name);
            }
        }
        Ok(dropped)
    }

    /// §1 — restore rewrites the superblock to the checkpoint's roots.
    /// **Restore rolls back roots, never counters**: `next_seq`,
    /// `next_tree_id`, `next_segment_id`, `next_vlog_segment_id` and —
    /// critically — `next_nonce` keep their current values, because rolling
    /// `next_nonce` back would hand out nonce values the abandoned commits
    /// already used, against pages still in the file.
    fn restore_checkpoint(&mut self, name: &str) -> Result<()> {
        let Some(c) = self.checkpoint(name)? else {
            return invalid(format!("no checkpoint named \"{name}\""));
        };
        self.catalog.tree.root = c.catalog_root;
        self.freelist.root = c.freelist_root;
        self.attributes.tree.root = c.attributes_root;
        self.manifest.tree.root = c.manifest_root;
        self.vlog_stats_tree.root = c.vlog_stats_root;
        self.changefeed.root = c.changefeed_root;
        self.visible_seq = c.seq;
        self.commit(crate::container::Durability::Sync)?;
        Ok(())
    }

    /// §1 — an implementation MUST report the space each checkpoint pins.
    fn checkpoint_would_pin(&mut self) -> u64 {
        let alloc: u64 =
            self.vlog_stats.values().map(|s| s.pages as u64 * self.pager.page_size as u64).sum();
        let live: u64 = self.vlog_stats.values().map(|s| s.live_bytes).sum();
        alloc.saturating_sub(live)
    }
}
