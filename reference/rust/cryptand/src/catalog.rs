//! `05-catalog.md` — what the trees in a Cryptand file *mean*.
//!
//! Two rules drive the shape of this file:
//!
//!   * **Tree names are arbitrary UTF-8** (§1). No escaping, no mangling, no
//!     reserved characters. A collection may be called `"orders|2026+eu"`.
//!   * **Unknown fields survive a rewrite** (§3, `11-conformance.md` §4). A
//!     descriptor is therefore *held* as its decoded document and re-encoded
//!     from it, so a field this implementation has never heard of comes back
//!     out unchanged rather than being dropped by a round trip.

use crate::cke;
use crate::cow::CowTree;
use crate::cve;
use crate::error::{invalid, Result};
use crate::pager::Pager;
use crate::value::{NumType, Value};

/// §2 — the reserved tree ids.
pub mod tree_id {
    pub const CATALOG: u32 = 0;
    pub const FREE_SPACE: u32 = 1;
    pub const ATTRIBUTES: u32 = 2;
    pub const TREE_INDEX: u32 = 3;
    pub const REPAIR_LOG: u32 = 4;
    pub const USERS: u32 = 5;
    pub const MANIFEST: u32 = 6;
    pub const VLOG_STATS: u32 = 7;
    pub const CHECKPOINTS: u32 = 8;
    pub const CHANGE_FEED: u32 = 9;
    pub const FIRST_USER_TREE: u32 = 16;
}

/// §4 — `kind`.
pub mod kind {
    pub const DATA: &str = "data";
    pub const NAME_DICT: &str = "name_dict";
    pub const INDEX: &str = "index";
    pub const TERM_DICT: &str = "term_dict";
    pub const TERM_INDEX: &str = "term_index";
    pub const POSTINGS: &str = "postings";
    pub const RTREE: &str = "rtree";
    pub const VECTOR_GRAPH: &str = "vector_graph";
    pub const KV: &str = "kv";
    pub const INTERNAL: &str = "internal";

    /// §3 — the kinds whose data lives in manifest segments rather than in a
    /// copy-on-write tree rooted at `root`.
    pub const LEVELLED: [&str; 8] =
        [DATA, INDEX, KV, NAME_DICT, POSTINGS, TERM_DICT, TERM_INDEX, VECTOR_GRAPH];

    pub const KNOWN: [&str; 10] = [
        DATA, NAME_DICT, INDEX, TERM_DICT, TERM_INDEX, POSTINGS, RTREE, VECTOR_GRAPH, KV, INTERNAL,
    ];

    /// §11 — the kinds that make a tree an index of its owner.
    pub const INDEX_KINDS: [&str; 6] =
        [INDEX, TERM_DICT, TERM_INDEX, POSTINGS, RTREE, VECTOR_GRAPH];

    pub fn is_levelled(k: &str) -> bool {
        LEVELLED.contains(&k)
    }
    pub fn is_known(k: &str) -> bool {
        KNOWN.contains(&k)
    }
    pub fn is_index(k: &str) -> bool {
        INDEX_KINDS.contains(&k)
    }
}

/// §10 — lower snake case, no hyphens. These five are the only portable names.
pub mod index_type {
    pub const UNIQUE: &str = "unique";
    pub const NON_UNIQUE: &str = "non_unique";
    pub const FULL_TEXT: &str = "full_text";
    pub const SPATIAL: &str = "spatial";
    pub const VECTOR: &str = "vector";
    pub const PORTABLE: [&str; 5] = [FULL_TEXT, NON_UNIQUE, SPATIAL, UNIQUE, VECTOR];

    pub fn is_portable(t: &str) -> bool {
        PORTABLE.contains(&t)
    }
}

/// §5 — `params.type` on a `data` tree.
pub mod data_tree_type {
    pub const COLLECTION: &str = "collection";
    pub const REPOSITORY: &str = "repository";
}

/// One tree descriptor, §3, backed by the decoded document so unknown fields
/// round-trip.
#[derive(Clone, Debug)]
pub struct TreeDescriptor {
    pub doc: Vec<(String, Value)>,
}

fn u32v(v: u32) -> Value {
    Value::Int { w: NumType::U32, neg: false, mag: v as u128 }
}
fn u64v(v: u64) -> Value {
    Value::Int { w: NumType::U64, neg: false, mag: v as u128 }
}

impl TreeDescriptor {
    pub fn create(
        tree_id: u32,
        kind_name: &str,
        owner: Option<&str>,
        name_dict: Option<u32>,
        key_kind: Option<&str>,
        features: u64,
        params: Vec<(String, Value)>,
        created_ms: i64,
    ) -> TreeDescriptor {
        let mut f: Vec<(String, Value)> = vec![
            ("tree_id".into(), u32v(tree_id)),
            ("kind".into(), Value::Str(kind_name.into())),
            ("levelled".into(), Value::Bool(kind::is_levelled(kind_name))),
            ("entries".into(), u64v(0)),
            ("created".into(), Value::Timestamp(created_ms)),
            ("features".into(), u64v(features)),
        ];
        if let Some(k) = key_kind {
            f.push(("key_kind".into(), Value::Str(k.into())));
        }
        if let Some(o) = owner {
            f.push(("owner".into(), Value::Str(o.into())));
        }
        if let Some(n) = name_dict {
            f.push(("name_dict".into(), u32v(n)));
        }
        if !params.is_empty() {
            f.push(("params".into(), Value::Doc(params)));
        }
        TreeDescriptor { doc: f }
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.doc.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    fn uint(&self, name: &str) -> Option<u64> {
        match self.get(name) {
            Some(Value::Int { mag, .. }) => Some(*mag as u64),
            _ => None,
        }
    }

    pub fn tree_id(&self) -> u32 {
        self.uint("tree_id").unwrap_or(0) as u32
    }
    pub fn kind(&self) -> &str {
        match self.get("kind") {
            Some(Value::Str(s)) => s,
            _ => "",
        }
    }
    pub fn levelled(&self) -> bool {
        matches!(self.get("levelled"), Some(Value::Bool(true)))
    }
    pub fn entries(&self) -> u64 {
        self.uint("entries").unwrap_or(0)
    }
    pub fn features(&self) -> u64 {
        self.uint("features").unwrap_or(0)
    }
    pub fn root(&self) -> Option<u64> {
        self.uint("root")
    }
    pub fn name_dict(&self) -> Option<u32> {
        self.uint("name_dict").map(|v| v as u32)
    }
    pub fn stale_from(&self) -> Option<u64> {
        self.uint("stale_from")
    }
    pub fn owner(&self) -> Option<&str> {
        match self.get("owner") {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }
    pub fn key_kind(&self) -> Option<&str> {
        match self.get("key_kind") {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// §3.1 — every per-tree *policy* field, at the top level of one document.
    pub fn params(&self) -> &[(String, Value)] {
        match self.get("params") {
            Some(Value::Doc(f)) => f,
            _ => &[],
        }
    }

    pub fn param(&self, name: &str) -> Option<&Value> {
        self.params().iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    pub fn param_str(&self, name: &str) -> Option<&str> {
        match self.param(name) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn param_bool(&self, name: &str) -> bool {
        matches!(self.param(name), Some(Value::Bool(true)))
    }

    pub fn param_u64(&self, name: &str) -> Option<u64> {
        match self.param(name) {
            Some(Value::Int { mag, .. }) => Some(*mag as u64),
            _ => None,
        }
    }

    /// A copy with `changes` applied and every other field — including ones
    /// this implementation does not understand — left exactly as it was.
    pub fn with(&self, changes: Vec<(&str, Option<Value>)>) -> TreeDescriptor {
        let mut f = self.doc.clone();
        for (name, value) in changes {
            match value {
                None => f.retain(|(k, _)| k != name),
                Some(v) => match f.iter_mut().find(|(k, _)| k == name) {
                    Some(slot) => slot.1 = v,
                    None => f.push((name.to_string(), v)),
                },
            }
        }
        TreeDescriptor { doc: f }
    }

    pub fn with_param(&self, name: &str, value: Option<Value>) -> TreeDescriptor {
        let mut p: Vec<(String, Value)> = self.params().to_vec();
        match value {
            None => p.retain(|(k, _)| k != name),
            Some(v) => match p.iter_mut().find(|(k, _)| k == name) {
                Some(slot) => slot.1 = v,
                None => p.push((name.to_string(), v)),
            },
        }
        self.with(vec![("params", Some(Value::Doc(p)))])
    }

    pub fn encode(&self) -> Vec<u8> {
        cve::encode(&Value::Doc(self.doc.clone()))
    }

    pub fn decode(bytes: &[u8]) -> Result<TreeDescriptor> {
        match cve::decode_all(bytes, &|_| None)? {
            Value::Doc(f) => Ok(TreeDescriptor { doc: f }),
            _ => invalid("a tree descriptor is a CVE document"),
        }
    }
}

pub fn name_key(name: &str) -> Vec<u8> {
    cke::encode(&Value::Str(name.to_string())).expect("STR is CKE-encodable")
}

pub fn id_key(tree_id: u32) -> Vec<u8> {
    cke::encode(&u32v(tree_id)).expect("U32 is CKE-encodable")
}

/// Tree 0, and the reverse map in tree 3.
pub struct Catalog {
    pub tree: CowTree,
    /// Tree 3: `CKE(U32 tree_id) -> CVE STR name`, the reverse of the catalog.
    pub by_id: CowTree,
    /// §1: tree ids are **never reused**, so a stale reference is detectably
    /// dangling rather than silently pointing at a different tree.
    pub next_tree_id: u64,
}

impl Catalog {
    pub fn new(catalog_root: u64, tree_index_root: u64, next_tree_id: u64) -> Catalog {
        Catalog {
            tree: CowTree::new(tree_id::CATALOG, catalog_root),
            by_id: CowTree::new(tree_id::TREE_INDEX, tree_index_root),
            next_tree_id,
        }
    }

    pub fn create(
        &mut self,
        pager: &mut Pager,
        name: &str,
        kind_name: &str,
        owner: Option<&str>,
        name_dict: Option<u32>,
        key_kind: Option<&str>,
        features: u64,
        params: Vec<(String, Value)>,
        created_ms: i64,
    ) -> Result<TreeDescriptor> {
        if name.is_empty() {
            return invalid("a tree name cannot be empty");
        }
        if self.tree.get(pager, &name_key(name))?.is_some() {
            return invalid(format!("tree \"{name}\" already exists"));
        }
        if self.next_tree_id > crate::limits::MAX_TREE_ID {
            return invalid("next_tree_id would exceed 0xFFFFFFFE");
        }
        let id = self.next_tree_id as u32;
        self.next_tree_id += 1;
        let d = TreeDescriptor::create(
            id, kind_name, owner, name_dict, key_kind, features, params, created_ms,
        );
        self.put(pager, name, &d)?;
        Ok(d)
    }

    pub fn put(&mut self, pager: &mut Pager, name: &str, d: &TreeDescriptor) -> Result<()> {
        self.tree.put(pager, &name_key(name), &d.encode())?;
        self.by_id.put(pager, &id_key(d.tree_id()), &cve::encode(&Value::Str(name.to_string())))
    }

    pub fn get(&self, pager: &mut Pager, name: &str) -> Result<Option<TreeDescriptor>> {
        match self.tree.get(pager, &name_key(name))? {
            Some(v) => Ok(Some(TreeDescriptor::decode(&v)?)),
            None => Ok(None),
        }
    }

    pub fn name_of(&self, pager: &mut Pager, id: u32) -> Result<Option<String>> {
        match self.by_id.get(pager, &id_key(id))? {
            Some(v) => match cve::decode_all(&v, &|_| None)? {
                Value::Str(s) => Ok(Some(s)),
                _ => invalid("tree 3 value is not a CVE STR"),
            },
            None => Ok(None),
        }
    }

    /// §4: "A reader that does not recognize a `kind` MUST treat the tree as
    /// opaque: it may be listed and copied, it MUST NOT be deleted, and it
    /// MUST NOT be interpreted."
    pub fn drop(&mut self, pager: &mut Pager, name: &str) -> Result<()> {
        let Some(d) = self.get(pager, name)? else { return Ok(()) };
        if !kind::is_known(d.kind()) {
            return invalid(format!(
                "tree \"{name}\" has unrecognized kind \"{}\" and MUST NOT be deleted \
                 (spec/05-catalog.md section 4)",
                d.kind()
            ));
        }
        self.tree.remove(pager, &name_key(name))?;
        self.by_id.remove(pager, &id_key(d.tree_id()))?;
        Ok(())
    }

    pub fn all(&self, pager: &mut Pager) -> Result<Vec<(String, TreeDescriptor)>> {
        let mut out = Vec::new();
        for (k, v) in self.tree.scan(pager, None, None)? {
            let name = match cke::decode_all(&k)? {
                Value::Str(s) => s,
                _ => return invalid("a catalog key is CKE(STR name)"),
            };
            out.push((name, TreeDescriptor::decode(&v)?));
        }
        Ok(out)
    }

    /// Bootstraps tree 3 by scanning the catalog, §2.
    pub fn rebuild_tree_index(&mut self, pager: &mut Pager) -> Result<()> {
        for (name, d) in self.all(pager)? {
            self.by_id.put(pager, &id_key(d.tree_id()), &cve::encode(&Value::Str(name)))?;
        }
        Ok(())
    }

    /// §11 — the enumerations a reader must support, given only the catalog.
    pub fn collections(&self, pager: &mut Pager) -> Result<Vec<String>> {
        Ok(self
            .all(pager)?
            .into_iter()
            .filter(|(_, d)| {
                d.kind() == kind::DATA && d.param_str("type") == Some(data_tree_type::COLLECTION)
            })
            .map(|(n, _)| n)
            .collect())
    }

    pub fn repositories(&self, pager: &mut Pager, keyed: bool) -> Result<Vec<String>> {
        Ok(self
            .all(pager)?
            .into_iter()
            .filter(|(_, d)| {
                d.kind() == kind::DATA
                    && d.param_str("type") == Some(data_tree_type::REPOSITORY)
                    && d.param("key").is_some() == keyed
            })
            .map(|(n, _)| n)
            .collect())
    }

    pub fn indexes_of(&self, pager: &mut Pager, owner: &str) -> Result<Vec<(String, TreeDescriptor)>> {
        Ok(self
            .all(pager)?
            .into_iter()
            .filter(|(_, d)| d.owner() == Some(owner) && kind::is_index(d.kind()))
            .collect())
    }

    pub fn stale_indexes(&self, pager: &mut Pager) -> Result<Vec<(String, TreeDescriptor)>> {
        Ok(self.all(pager)?.into_iter().filter(|(_, d)| d.stale_from().is_some()).collect())
    }

    /// §11's last row: the union of every tree's `features`.
    pub fn required_features(&self, pager: &mut Pager) -> Result<u64> {
        Ok(self.all(pager)?.iter().fold(0u64, |acc, (_, d)| acc | d.features()))
    }
}

/// §6 — tree 2, replacing `$nitrite_meta_map`. Key is the tree's name.
pub struct Attributes {
    pub tree: CowTree,
}

/// §7 — store metadata lives in the attributes entry for this reserved name.
pub const STORE_ATTRIBUTES_KEY: &str = "$store";

impl Attributes {
    pub fn new(root: u64) -> Attributes {
        Attributes { tree: CowTree::new(tree_id::ATTRIBUTES, root) }
    }

    pub fn get(&self, pager: &mut Pager, name: &str) -> Result<Option<Vec<(String, Value)>>> {
        match self.tree.get(pager, &name_key(name))? {
            Some(v) => match cve::decode_all(&v, &|_| None)? {
                Value::Doc(f) => Ok(Some(f)),
                _ => invalid("an attributes value is a CVE document"),
            },
            None => Ok(None),
        }
    }

    /// §6: `last_modified_at` MUST be updated in the same commit as the
    /// mutation it describes — batch atomicity makes that free.
    pub fn put(
        &mut self,
        pager: &mut Pager,
        name: &str,
        fields: Vec<(String, Value)>,
    ) -> Result<()> {
        self.tree.put(pager, &name_key(name), &cve::encode(&Value::Doc(fields)))
    }

    pub fn touch(&mut self, pager: &mut Pager, name: &str, now_ms: i64) -> Result<()> {
        let mut f = self.get(pager, name)?.unwrap_or_else(|| {
            vec![
                ("name".into(), Value::Str(name.to_string())),
                ("created_at".into(), Value::Timestamp(now_ms)),
            ]
        });
        match f.iter_mut().find(|(k, _)| k == "last_modified_at") {
            Some(slot) => slot.1 = Value::Timestamp(now_ms),
            None => f.push(("last_modified_at".into(), Value::Timestamp(now_ms))),
        }
        self.put(pager, name, f)
    }

    pub fn all(&self, pager: &mut Pager) -> Result<Vec<(String, Vec<(String, Value)>)>> {
        let mut out = Vec::new();
        for (k, v) in self.tree.scan(pager, None, None)? {
            let name = match cke::decode_all(&k)? {
                Value::Str(s) => s,
                _ => continue,
            };
            if let Value::Doc(f) = cve::decode_all(&v, &|_| None)? {
                out.push((name, f));
            }
        }
        Ok(out)
    }
}

/// §10 — the five portable index type names, as a flat table for the vectors.
pub const PORTABLE_INDEX_TYPES: [&str; 5] = index_type::PORTABLE;

/// §3 — the kinds whose data lives in manifest segments.
pub const LEVELLED_KINDS: [&str; 8] = kind::LEVELLED;
