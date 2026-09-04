//! The logical Nitrite model over the engine: collections, documents, name
//! dictionaries and index maintenance — `05-catalog.md` and `06-indexes.md`.
//!
//! Index maintenance and the document write go into the **same batch** and
//! therefore the same commit (`06-indexes.md` §8), so an index can never be
//! transiently out of step with its collection in a durable state.

use std::collections::BTreeMap;
use std::path::Path;

use crate::catalog::{data_tree_type, index_type, kind};
use crate::cke;
use crate::container::{feature, Durability, Profile};
use crate::cve;
use crate::engine::Engine;
use crate::error::{invalid, Error, Result};
use crate::index;
use crate::value::{NumType, Value};

pub struct Database {
    pub engine: Engine,
}

/// `02-value-encoding.md` §5.4 — the reserved fields, which SHOULD occupy
/// `name_id` 1–5 in every data tree's dictionary so they encode in one byte.
pub const RESERVED_FIELDS: [&str; 5] = ["_id", "_revision", "_modified", "_source", "_type"];

/// §5.3 — a per-tree field-name dictionary. `name_id` is allocated append-only
/// and is **never reused**, so a stale cached dictionary is never *wrong*, only
/// incomplete.
#[derive(Clone, Debug, Default)]
pub struct NameDict {
    pub by_name: BTreeMap<String, u32>,
    pub by_id: BTreeMap<u32, String>,
    pub next_id: u32,
}

impl NameDict {
    pub fn new() -> NameDict {
        let mut d = NameDict { by_name: BTreeMap::new(), by_id: BTreeMap::new(), next_id: 1 };
        for f in RESERVED_FIELDS {
            d.intern(f);
        }
        d
    }
    pub fn intern(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.by_name.get(name) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.by_name.insert(name.to_string(), id);
        self.by_id.insert(id, name.to_string());
        id
    }
}

impl Database {
    pub fn create(path: &Path, profile: Profile) -> Result<Database> {
        Ok(Database { engine: Engine::create(path, profile)? })
    }

    pub fn create_in_memory(profile: Profile) -> Result<Database> {
        Ok(Database { engine: Engine::create_in_memory(profile)? })
    }

    pub fn open(path: &Path, key: Option<&[u8]>) -> Result<Database> {
        Ok(Database { engine: Engine::open(path, key)? })
    }

    pub fn commit(&mut self, d: Durability) -> Result<u64> {
        self.engine.flush()?;
        self.engine.commit(d)
    }

    pub fn close(&mut self) -> Result<()> {
        self.engine.close(true)
    }

    /// §5 — a collection is a `data` tree with `params.type = "collection"`,
    /// and a name dictionary tree beside it.
    pub fn collection(&mut self, name: &str) -> Result<Collection> {
        if let Some(d) = self.engine.catalog.get(&mut self.engine.pager, name)? {
            let dict_tree = d.name_dict().unwrap_or(0);
            let dict = self.load_dict(dict_tree)?;
            return Ok(Collection { name: name.to_string(), tree: d.tree_id(), dict_tree, dict });
        }
        let now = crate::engine::now_millis();
        let dict_name = format!("{name}$names");
        let mut cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new(0, 0, 16));
        let dict_desc = cat.create(
            &mut self.engine.pager,
            &dict_name,
            kind::NAME_DICT,
            Some(name),
            None,
            Some("u32"),
            0,
            vec![],
            now,
        );
        self.engine.catalog = cat;
        let dict_tree = dict_desc?.tree_id();

        let mut cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new(0, 0, 16));
        let desc = cat.create(
            &mut self.engine.pager,
            name,
            kind::DATA,
            None,
            Some(dict_tree),
            Some("nitrite_id"),
            0,
            vec![("type".into(), Value::Str(data_tree_type::COLLECTION.into()))],
            now,
        );
        self.engine.catalog = cat;
        let desc = desc?;
        self.engine.sb.set_feature(feature::DOCUMENTS, true);
        let mut c = Collection {
            name: name.to_string(),
            tree: desc.tree_id(),
            dict_tree,
            dict: NameDict::new(),
        };
        c.persist_dict(&mut self.engine)?;
        // §6 — the attributes entry, created and touched in the same commit.
        let mut attrs =
            std::mem::replace(&mut self.engine.attributes, crate::catalog::Attributes::new(0));
        let r = attrs.touch(&mut self.engine.pager, name, now);
        self.engine.attributes = attrs;
        r?;
        Ok(c)
    }

    fn load_dict(&mut self, dict_tree: u32) -> Result<NameDict> {
        let mut d = NameDict { by_name: BTreeMap::new(), by_id: BTreeMap::new(), next_id: 1 };
        if dict_tree == 0 {
            return Ok(NameDict::new());
        }
        for (k, v) in self.engine.scan_tree(dict_tree, None, None, None, true)? {
            let id = match cke::decode_all(&k)? {
                Value::Int { mag, .. } => mag as u32,
                _ => continue,
            };
            if let Value::Str(name) = cve::decode_all(&v, &|_| None)? {
                d.by_name.insert(name.clone(), id);
                d.by_id.insert(id, name);
                d.next_id = d.next_id.max(id + 1);
            }
        }
        if d.by_id.is_empty() {
            return Ok(NameDict::new());
        }
        Ok(d)
    }

    /// §11 — the enumerations a reader must support, given only the catalog.
    pub fn collections(&mut self) -> Result<Vec<String>> {
        let cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new(0, 0, 16));
        let r = cat.collections(&mut self.engine.pager);
        self.engine.catalog = cat;
        r
    }
}

pub struct Collection {
    pub name: String,
    pub tree: u32,
    pub dict_tree: u32,
    pub dict: NameDict,
}

impl Collection {
    /// §5.3 — a writer MUST write new dictionary entries in the **same commit**
    /// as the document that first uses them. Atomicity of the batch guarantees
    /// this is not a window.
    fn persist_dict(&mut self, e: &mut Engine) -> Result<()> {
        for (id, name) in self.dict.by_id.clone() {
            let key = Value::Int { w: NumType::U32, neg: false, mag: id as u128 };
            let existing = e.get(self.dict_tree, &key)?;
            if existing.is_none() {
                e.put(self.dict_tree, &key, &cve::encode(&Value::Str(name)))?;
            }
        }
        Ok(())
    }

    /// §5.4 — `_id` MUST be present, MUST be `NITRITE_ID`, and MUST equal the
    /// tree key of the entry. A reader finding a mismatch MUST report
    /// corruption.
    pub fn insert(&mut self, e: &mut Engine, doc: &Value) -> Result<i64> {
        let Value::Doc(fields) = doc else { return invalid("a collection stores CVE documents") };
        let Some(Value::NitriteId(id)) = doc.field("_id") else {
            return invalid("a document in a collection data tree MUST carry an `_id` of type NITRITE_ID");
        };
        let id = *id;
        for (name, _) in fields {
            self.dict.intern(name);
        }
        self.persist_dict(e)?;
        let dict = self.dict.by_name.clone();
        let bytes = cve::encode_with_dict(doc, &|n| dict.get(n).copied());
        e.put(self.tree, &Value::NitriteId(id), &bytes)?;
        Ok(id)
    }

    pub fn get(&self, e: &mut Engine, id: i64) -> Result<Option<Value>> {
        let Some(bytes) = e.get(self.tree, &Value::NitriteId(id))? else { return Ok(None) };
        let by_id = self.dict.by_id.clone();
        let doc = cve::decode_all(&bytes, &|i| by_id.get(&i).cloned())?;
        // §5.4 — the reader-side half of the `_id` rule.
        match doc.field("_id") {
            Some(Value::NitriteId(x)) if *x == id => {}
            _ => {
                return Err(Error::Corrupt(format!(
                    "document at key {id} carries a different `_id`"
                )))
            }
        }
        Ok(Some(doc))
    }

    pub fn remove(&self, e: &mut Engine, id: i64) -> Result<()> {
        e.remove(self.tree, &Value::NitriteId(id))?;
        Ok(())
    }

    /// §2.5's `clear()` — one range delete rather than O(n) tombstones.
    pub fn clear(&self, e: &mut Engine) -> Result<()> {
        e.remove_range(self.tree, &Value::NitriteId(i64::MIN), &Value::NitriteId(i64::MAX))?;
        Ok(())
    }

    pub fn scan(&self, e: &mut Engine) -> Result<Vec<Value>> {
        let by_id = self.dict.by_id.clone();
        let mut out = Vec::new();
        for (_k, v) in e.scan_tree(self.tree, None, None, None, true)? {
            out.push(cve::decode_all(&v, &|i| by_id.get(&i).cloned())?);
        }
        Ok(out)
    }
}

/// An index over a collection — `06-indexes.md` §2.
#[derive(Clone, Debug)]
pub struct IndexDescriptor {
    pub name: String,
    pub tree: u32,
    pub data_tree: u32,
    pub fields: Vec<String>,
    pub index_type: String,
    pub sparse: bool,
}

impl IndexDescriptor {
    pub fn unique(&self) -> bool {
        // §2: uniqueness is `index_type == "unique"` and nothing else. An
        // earlier draft also carried a `"unique": BOOL`; two records of one
        // fact drift, so the boolean is gone.
        self.index_type == index_type::UNIQUE
    }
}

pub trait Indexing {
    fn create_index(
        &mut self,
        collection: &Collection,
        fields: &[&str],
        index_type: &str,
        sparse: bool,
    ) -> Result<IndexDescriptor>;
    fn index_document(&mut self, idx: &IndexDescriptor, doc: &Value) -> Result<usize>;
    fn unindex_document(&mut self, idx: &IndexDescriptor, doc: &Value) -> Result<usize>;
    fn index_scan(&mut self, idx: &IndexDescriptor, scan: &index::IndexScan) -> Result<Vec<i64>>;
}

impl Indexing for Database {
    fn create_index(
        &mut self,
        collection: &Collection,
        fields: &[&str],
        index_type_name: &str,
        sparse: bool,
    ) -> Result<IndexDescriptor> {
        if !index_type::is_portable(index_type_name) {
            return invalid(format!(
                "index_type \"{index_type_name}\" is not one of the five portable names; a \
                 non-portable type needs a vendor feature bit on the tree \
                 (spec/05-catalog.md section 10)"
            ));
        }
        let name = format!("idx:{}:{}:{}", collection.name, fields.join(","), index_type_name);
        let now = crate::engine::now_millis();
        let params = vec![
            ("index_type".to_string(), Value::Str(index_type_name.to_string())),
            (
                "data_tree".to_string(),
                Value::Int { w: NumType::U32, neg: false, mag: collection.tree as u128 },
            ),
            (
                "fields".to_string(),
                Value::Array(fields.iter().map(|f| Value::Str(f.to_string())).collect()),
            ),
            ("sparse".to_string(), Value::Bool(sparse)),
        ];
        let mut cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new(0, 0, 16));
        let d = cat.create(
            &mut self.engine.pager,
            &name,
            kind::INDEX,
            Some(&collection.name),
            None,
            Some("array"),
            0,
            params,
            now,
        );
        self.engine.catalog = cat;
        let d = d?;
        Ok(IndexDescriptor {
            name,
            tree: d.tree_id(),
            data_tree: collection.tree,
            fields: fields.iter().map(|s| s.to_string()).collect(),
            index_type: index_type_name.to_string(),
            sparse,
        })
    }

    fn index_document(&mut self, idx: &IndexDescriptor, doc: &Value) -> Result<usize> {
        let Some(Value::NitriteId(id)) = doc.field("_id") else {
            return invalid("indexing needs a document with an `_id`");
        };
        let keys = index::index_keys(doc, &idx.fields, idx.sparse, *id)?;
        if idx.unique() {
            for k in &keys {
                let (values, _) = index::entry_values(k)?;
                let head: Vec<Value> = values.clone();
                if !index::uniqueness_applies(&head) {
                    continue;
                }
                let scan = index::scan_prefix(&head)?;
                let hits = self.index_scan(idx, &scan)?;
                if hits.iter().any(|h| h != id) {
                    return Err(Error::Invalid(format!(
                        "unique index \"{}\" already holds these values for document {}",
                        idx.name, hits[0]
                    )));
                }
            }
        }
        for k in &keys {
            let key = cke::decode_all(k)?;
            self.engine.put_empty(idx.tree, &key)?;
        }
        Ok(keys.len())
    }

    fn unindex_document(&mut self, idx: &IndexDescriptor, doc: &Value) -> Result<usize> {
        let Some(Value::NitriteId(id)) = doc.field("_id") else {
            return invalid("unindexing needs a document with an `_id`");
        };
        let keys = index::index_keys(doc, &idx.fields, idx.sparse, *id)?;
        for k in &keys {
            let key = cke::decode_all(k)?;
            self.engine.remove(idx.tree, &key)?;
        }
        Ok(keys.len())
    }

    fn index_scan(&mut self, idx: &IndexDescriptor, scan: &index::IndexScan) -> Result<Vec<i64>> {
        let rows = self.engine.scan_tree(
            idx.tree,
            Some(&scan.lower),
            scan.upper.as_deref(),
            None,
            false,
        )?;
        rows.iter().map(|(k, _)| index::entry_id(k)).collect()
    }
}
