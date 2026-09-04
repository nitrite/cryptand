//! `04-segments.md` §3.2 — the manifest: reserved tree 6, a plain
//! copy-on-write B+tree keyed `CKE(Array[U8 level, U8 group, BYTES
//! min_internal_key])`.
//!
//! The manifest is what makes the level policy *not* part of the format. It
//! records only a segment's level, group, key range and seq range, and a
//! reader answers "which segments at level L can hold key k" with
//! `overlap_bound` seeks.

use crate::cke;
use crate::cow::CowTree;
use crate::cve;
use crate::error::{invalid, Result};
use crate::pager::Pager;
use crate::segment::{seg_flags, Segment};
use crate::value::{NumType, Value};

/// One segment's manifest entry, §3.2.
#[derive(Clone, Debug)]
pub struct SegmentRef {
    pub segment_id: u64,
    pub level: u8,
    pub group: u8,
    pub min_key: Vec<u8>,
    pub max_key: Vec<u8>,
    pub min_seq: u64,
    pub max_seq: u64,
    pub entries: u64,
    pub tombstones: u64,
    pub has_range_deletes: bool,
    pub start_page: u64,
    pub pages: u32,
    pub root: u64,
    pub filter: u64,
    pub min_expiry: u64,
    pub value_bytes: u64,
    pub vlog_bytes: u64,
    pub trees: Vec<u32>,
}

impl SegmentRef {
    pub fn of(s: &Segment, level: u8, group: u8, start_page: u64) -> SegmentRef {
        let h = &s.header;
        let mut trees: Vec<u32> = h.tree_span.iter().map(|(t, _)| *t).collect();
        trees.sort_unstable();
        SegmentRef {
            segment_id: h.segment_id,
            level,
            group,
            min_key: h.min_key.clone(),
            max_key: h.max_key.clone(),
            min_seq: h.min_seq,
            max_seq: h.max_seq,
            entries: h.entry_count,
            tombstones: h.tombstone_count,
            has_range_deletes: h.flags & seg_flags::HAS_RANGE_DELETES != 0,
            start_page,
            pages: s.page_count() as u32,
            root: h.root_page,
            filter: h.filter_page,
            min_expiry: h.min_expiry,
            value_bytes: h.value_bytes,
            vlog_bytes: h.vlog_bytes,
            trees,
        }
    }

    /// §4.1's first mechanism, and the reason it costs no I/O: the test runs
    /// on the manifest entry, not on the segment.
    pub fn covers(&self, user_key_prefix: &[u8]) -> bool {
        if user_key_prefix > &self.max_key[..] {
            return false;
        }
        if let Some(sup) = cke::successor(user_key_prefix) {
            if sup[..] <= self.min_key[..] {
                return false;
            }
        }
        true
    }

    pub fn key(&self) -> Vec<u8> {
        manifest_key(self.level, self.group, &self.min_key)
    }

    pub fn encode(&self) -> Vec<u8> {
        let u64v = |v: u64| Value::Int { w: NumType::U64, neg: false, mag: v as u128 };
        let doc = Value::Doc(vec![
            ("segment_id".into(), u64v(self.segment_id)),
            ("start_page".into(), u64v(self.start_page)),
            ("pages".into(), Value::Int { w: NumType::U32, neg: false, mag: self.pages as u128 }),
            ("root".into(), u64v(self.root)),
            ("filter".into(), u64v(self.filter)),
            ("min_seq".into(), u64v(self.min_seq)),
            ("max_seq".into(), u64v(self.max_seq)),
            ("entries".into(), u64v(self.entries)),
            ("tombstones".into(), u64v(self.tombstones)),
            ("min_expiry".into(), u64v(self.min_expiry)),
            ("min_key".into(), Value::Bytes(self.min_key.clone())),
            ("max_key".into(), Value::Bytes(self.max_key.clone())),
            ("value_bytes".into(), u64v(self.value_bytes)),
            ("vlog_bytes".into(), u64v(self.vlog_bytes)),
            ("range_deletes".into(), Value::Bool(self.has_range_deletes)),
            (
                "trees".into(),
                Value::Array(
                    self.trees
                        .iter()
                        .map(|&t| Value::Int { w: NumType::U32, neg: false, mag: t as u128 })
                        .collect(),
                ),
            ),
        ]);
        cve::encode(&doc)
    }

    pub fn decode(key: &[u8], value: &[u8]) -> Result<SegmentRef> {
        let k = cke::decode_all(key)?;
        let Value::Array(items) = k else { return invalid("manifest key is not an ARRAY") };
        let d = cve::decode_all(value, &|_| None)?;
        let u = |f: &str| -> u64 {
            match d.field(f) {
                Some(Value::Int { mag, .. }) => *mag as u64,
                _ => 0,
            }
        };
        let bytes = |f: &str| -> Vec<u8> {
            match d.field(f) {
                Some(Value::Bytes(b)) => b.clone(),
                _ => Vec::new(),
            }
        };
        let num = |v: &Value| -> u64 {
            match v {
                Value::Int { mag, .. } => *mag as u64,
                _ => 0,
            }
        };
        Ok(SegmentRef {
            level: num(&items[0]) as u8,
            group: num(&items[1]) as u8,
            segment_id: u("segment_id"),
            start_page: u("start_page"),
            pages: u("pages") as u32,
            root: u("root"),
            filter: u("filter"),
            min_seq: u("min_seq"),
            max_seq: u("max_seq"),
            entries: u("entries"),
            tombstones: u("tombstones"),
            min_expiry: u("min_expiry"),
            min_key: bytes("min_key"),
            max_key: bytes("max_key"),
            value_bytes: u("value_bytes"),
            vlog_bytes: u("vlog_bytes"),
            has_range_deletes: matches!(d.field("range_deletes"), Some(Value::Bool(true))),
            trees: match d.field("trees") {
                Some(Value::Array(items)) => items.iter().map(|v| num(v) as u32).collect(),
                _ => Vec::new(),
            },
        })
    }
}

pub fn manifest_key(level: u8, group: u8, min_internal_key: &[u8]) -> Vec<u8> {
    cke::encode(&Value::Array(vec![
        Value::Int { w: NumType::U8, neg: false, mag: level as u128 },
        Value::Int { w: NumType::U8, neg: false, mag: group as u128 },
        Value::Bytes(min_internal_key.to_vec()),
    ]))
    .expect("manifest key components are all CKE-encodable")
}

/// Tree 6.
pub struct Manifest {
    pub tree: CowTree,
}

impl Manifest {
    pub fn new(root: u64) -> Manifest {
        Manifest { tree: CowTree::new(crate::catalog::tree_id::MANIFEST, root) }
    }

    pub fn root(&self) -> u64 {
        self.tree.root
    }

    /// Two segments in one `(level, group)` cannot share a `min_internal_key`:
    /// every entry carries a distinct seq, so two segments' first entries
    /// differ. A collision would silently unlink a live segment — losing every
    /// key in it with no checksum able to see it — so it is refused here.
    pub fn add(&mut self, pager: &mut Pager, r: &SegmentRef) -> Result<()> {
        let k = r.key();
        if self.tree.get(pager, &k)?.is_some() {
            return invalid(format!(
                "manifest already holds a segment at level {} group {} with this min_key",
                r.level, r.group
            ));
        }
        self.tree.put(pager, &k, &r.encode())
    }

    pub fn remove(&mut self, pager: &mut Pager, r: &SegmentRef) -> Result<bool> {
        self.tree.remove(pager, &r.key())
    }

    pub fn all(&self, pager: &mut Pager) -> Result<Vec<SegmentRef>> {
        self.tree
            .scan(pager, None, None)?
            .into_iter()
            .map(|(k, v)| SegmentRef::decode(&k, &v))
            .collect()
    }

    pub fn group(&self, pager: &mut Pager, level: u8, group: u8) -> Result<Vec<SegmentRef>> {
        let lower = manifest_key(level, group, &[]);
        let upper = manifest_key(level, group.saturating_add(1), &[]);
        self.tree
            .scan(pager, Some(&lower), Some(&upper))?
            .into_iter()
            .map(|(k, v)| SegmentRef::decode(&k, &v))
            .collect()
    }

    pub fn level(&self, pager: &mut Pager, level: u8) -> Result<Vec<SegmentRef>> {
        let lower = manifest_key(level, 0, &[]);
        let upper = manifest_key(level.saturating_add(1), 0, &[]);
        self.tree
            .scan(pager, Some(&lower), Some(&upper))?
            .into_iter()
            .map(|(k, v)| SegmentRef::decode(&k, &v))
            .collect()
    }

    /// The segments of one group that can hold `user_key_prefix`. Within a
    /// group the segments are disjoint, so this yields **at most one** — which
    /// is the whole point of range partitioning (§3.1).
    pub fn covering(
        &self,
        pager: &mut Pager,
        level: u8,
        group: u8,
        user_key_prefix: &[u8],
    ) -> Result<Vec<SegmentRef>> {
        Ok(self
            .group(pager, level, group)?
            .into_iter()
            .filter(|r| r.covers(user_key_prefix))
            .collect())
    }
}
