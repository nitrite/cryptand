//! `13-operations.md` §7 — the change feed, reserved tree 9.
//!
//! Optional and off by default: it costs a write per mutation and most
//! databases do not sync. Entries are appended in the same batch as the
//! mutation, so the feed is exactly consistent with the data.

use crate::catalog::tree_id;
use crate::cke;
use crate::cow::CowTree;
use crate::cve;
use crate::engine::Engine;
use crate::error::Result;
use crate::value::{NumType, Value};

#[derive(Clone, Debug)]
pub struct Change {
    pub tree_id: u32,
    pub seq: u64,
    pub op: String,
    pub key: Vec<u8>,
    pub id: Option<i64>,
}

pub fn feed_key(tree: u32, seq: u64) -> Vec<u8> {
    cke::encode(&Value::Array(vec![
        Value::Int { w: NumType::U32, neg: false, mag: tree as u128 },
        Value::Int { w: NumType::U64, neg: false, mag: seq as u128 },
    ]))
    .expect("U32 and U64 are CKE-encodable")
}

pub trait ChangeFeed {
    fn enable_change_feed(&mut self, tree: u32);
    /// `read_changes(tree, from_seq)` is a range scan, and because the key is
    /// `(tree_id, seq)` it is sequential.
    fn read_changes(&mut self, tree: u32, from_seq: u64) -> Result<Vec<Change>>;
    /// Retention is `changefeed_retain_seq` or `changefeed_retain_ms`,
    /// whichever is reached first; compaction drops entries past it.
    fn trim_change_feed(&mut self, tree: u32, below_seq: u64) -> Result<usize>;
}

impl ChangeFeed for Engine {
    fn enable_change_feed(&mut self, tree: u32) {
        self.changefeed_trees.insert(tree);
    }

    fn read_changes(&mut self, tree: u32, from_seq: u64) -> Result<Vec<Change>> {
        let lower = feed_key(tree, from_seq);
        let upper = feed_key(tree.saturating_add(1), 0);
        let t = std::mem::replace(&mut self.changefeed, CowTree::new(tree_id::CHANGE_FEED, 0));
        let rows = t.scan(&mut self.pager, Some(&lower), Some(&upper));
        self.changefeed = t;
        let mut out = Vec::new();
        for (k, v) in rows? {
            let Value::Array(items) = cke::decode_all(&k)? else { continue };
            let num = |v: &Value| match v {
                Value::Int { mag, .. } => *mag as u64,
                _ => 0,
            };
            let d = cve::decode_all(&v, &|_| None)?;
            out.push(Change {
                tree_id: num(&items[0]) as u32,
                seq: num(&items[1]),
                op: match d.field("op") {
                    Some(Value::Str(s)) => s.clone(),
                    _ => String::new(),
                },
                key: match d.field("key") {
                    Some(Value::Bytes(b)) => b.clone(),
                    _ => Vec::new(),
                },
                id: match d.field("id") {
                    Some(Value::NitriteId(i)) => Some(*i),
                    _ => None,
                },
            });
        }
        Ok(out)
    }

    fn trim_change_feed(&mut self, tree: u32, below_seq: u64) -> Result<usize> {
        let doomed: Vec<u64> = self
            .read_changes(tree, 0)?
            .into_iter()
            .filter(|c| c.seq < below_seq)
            .map(|c| c.seq)
            .collect();
        let mut t = std::mem::replace(&mut self.changefeed, CowTree::new(tree_id::CHANGE_FEED, 0));
        t.commit_id = self.sb.commit_id;
        let mut n = 0;
        for seq in &doomed {
            if t.remove(&mut self.pager, &feed_key(tree, *seq))? {
                n += 1;
            }
        }
        self.changefeed = t;
        Ok(n)
    }
}
