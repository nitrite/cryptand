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
    /// The greatest `name_id` already written to the dictionary tree.
    ///
    /// `persist_dict` used to re-probe **every** entry on **every** insert —
    /// one `Engine::get` per name in the dictionary, per document — so writing
    /// a 20-field document cost 20 engine lookups that could only ever answer
    /// "already there". A high-water mark is exact here for the reason the type
    /// comment above already gives: ids are "allocated append-only and never
    /// reused", so everything at or below this has been written and everything
    /// above it has not.
    pub persisted_upto: u32,
}

impl NameDict {
    pub fn new() -> NameDict {
        let mut d = NameDict {
            by_name: BTreeMap::new(),
            by_id: BTreeMap::new(),
            next_id: 1,
            persisted_upto: 0,
        };
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
        let id = self.engine.commit(d)?;
        // F-080: one L0 segment per commit and nothing ever compacting them
        // grew a one-put-per-commit file linearly (1000 commits, 3 267
        // pages). One bounded step, as `Store`'s committer runs; the commit
        // above is already durable, so a compaction error is not its error.
        let _ = self.engine.maybe_compact(None);
        Ok(id)
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
            self.open_indexes(name)?;
            return Ok(Collection { name: name.to_string(), tree: d.tree_id(), dict_tree, dict });
        }
        let now = crate::engine::now_millis();
        let dict_name = format!("{name}$names");
        let mut cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new((0, 0), 16));
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

        let mut cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new((0, 0), 16));
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
            std::mem::replace(&mut self.engine.attributes, crate::catalog::Attributes::new((0, 0)));
        let r = attrs.touch(&mut self.engine.pager, name, now);
        self.engine.attributes = attrs;
        r?;
        Ok(c)
    }

    fn load_dict(&mut self, dict_tree: u32) -> Result<NameDict> {
        // F-200: seeded with §5.4's reserved fields at 1-5, as Java and Dart
        // hold them. Java persists only the names after them, so a Java
        // document's `_id` (name_id 1) read as "unknown name_id 1". A
        // persisted entry still wins over a seeded one.
        let mut d = NameDict::new();
        d.persisted_upto = 0;
        if dict_tree == 0 {
            return Ok(d);
        }
        for (k, v) in self.engine.scan_tree(dict_tree, None, None, None, true)? {
            let id = match cke::decode_all(&k)? {
                Value::Int { mag, .. } => mag as u32,
                _ => continue,
            };
            if let Value::Str(name) = cve::decode_all(&v, &|_| None)? {
                if let Some(old) = d.by_id.insert(id, name.clone()) {
                    d.by_name.remove(&old);
                }
                d.by_name.insert(name, id);
                d.next_id = d.next_id.max(id + 1);
                d.persisted_upto = d.persisted_upto.max(id);
            }
        }
        Ok(d)
    }

    /// Opens `owner`'s spatial and vector indexes into the engine, which
    /// commits them with every commit and maintains them on every
    /// [`Collection::insert`] and [`Collection::remove`].
    fn open_indexes(&mut self, owner: &str) -> Result<()> {
        let cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new((0, 0), 16));
        let all = cat.all(&mut self.engine.pager);
        self.engine.catalog = cat;
        for (n, d) in all? {
            if d.owner() != Some(owner) {
                continue;
            }
            if d.kind() == kind::RTREE && !self.engine.spatial_indexes.iter().any(|i| i.name == n) {
                let ix = crate::rtree::SpatialIndex::open(&mut self.engine, &n, d)?;
                self.engine.spatial_indexes.push(ix);
            } else if d.kind() == kind::VECTOR_GRAPH && !self.engine.vector_indexes.iter().any(|i| i.name == n) {
                let ix = crate::vector::VectorIndex::open(&mut self.engine, &n, d)?;
                self.engine.vector_indexes.push(ix);
            }
        }
        Ok(())
    }

    fn unique_name(&mut self, base: &str) -> Result<String> {
        let mut name = base.to_string();
        for i in 2.. {
            if self.engine.catalog.get(&mut self.engine.pager, &name)?.is_none() {
                break;
            }
            name = format!("{base}-{i}");
        }
        Ok(name)
    }

    fn create_tree(
        &mut self,
        name: &str,
        kind_name: &str,
        owner: &str,
        key_kind: Option<&str>,
        features: u64,
        params: Vec<(String, Value)>,
    ) -> Result<crate::catalog::TreeDescriptor> {
        let mut cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new((0, 0), 16));
        let d = cat.create(
            &mut self.engine.pager,
            name,
            kind_name,
            Some(owner),
            None,
            key_kind,
            features,
            params,
            crate::engine::now_millis(),
        );
        self.engine.catalog = cat;
        d
    }

    /// Creates a spatial index over a geometry field and populates it,
    /// `08-spatial.md` §2. `dimensions = 3` always means Z, never M.
    pub fn create_spatial_index(&mut self, c: &Collection, field: &str, dimensions: u8, srid: Option<u32>) -> Result<String> {
        if !(2..=4).contains(&dimensions) {
            return invalid(format!("dimensions {dimensions} outside 2..4"));
        }
        let name = self.unique_name(&format!("idx:{}:{field}:spatial", c.name))?;
        let mut params = vec![
            ("index_type".to_string(), Value::Str(index_type::SPATIAL.into())),
            ("data_tree".to_string(), Value::int(NumType::U32, c.tree as i128)),
            ("field".to_string(), Value::Str(field.into())),
            ("dimensions".to_string(), Value::int(NumType::U8, dimensions as i128)),
        ];
        if let Some(s) = srid {
            params.push(("srid".to_string(), Value::int(NumType::U32, s as i128)));
        }
        let d = self.create_tree(&name, kind::RTREE, &c.name, Some("opaque"), feature::bit(feature::SPATIAL), params)?;
        let d = d.with_root((0, 0));
        self.engine.catalog.put(&mut self.engine.pager, &name, &d)?;
        let mut ix = crate::rtree::SpatialIndex::open(&mut self.engine, &name, d)?;
        for doc in c.scan(&mut self.engine)? {
            if let Some(Value::NitriteId(id)) = doc.field("_id") {
                ix.put(&mut self.engine, *id, &doc, None, None)?;
            }
        }
        self.engine.spatial_indexes.push(ix);
        self.commit(Durability::Sync)?;
        Ok(name)
    }

    /// Creates a vector index over a `VECTOR` field, `09-vector.md` §5, with
    /// both slot maps named in the descriptor.
    pub fn create_vector_index(&mut self, c: &Collection, field: &str, dim: u32, metric: &str, initial_slots: u64) -> Result<String> {
        crate::vector::Metric::parse(metric)?;
        let name = self.unique_name(&format!("idx:{}:{field}:vector", c.name))?;
        let graph = self.create_tree(&name, kind::VECTOR_GRAPH, &c.name, Some("array"), feature::bit(feature::VECTOR), vec![])?;
        let slots = self.create_tree(&format!("{name}:slots"), kind::KV, &name, None, 0, vec![])?;
        let docs = self.create_tree(&format!("{name}:docs"), kind::KV, &name, None, 0, vec![])?;
        let region = crate::vector::Region::create(&mut self.engine.pager, dim, crate::vector::DType::F32, initial_slots.max(2))?;
        let u = |w: NumType, v: u64| Value::int(w, v as i128);
        let params = vec![
            ("index_type".to_string(), Value::Str(index_type::VECTOR.into())),
            ("data_tree".to_string(), u(NumType::U32, c.tree as u64)),
            ("field".to_string(), Value::Str(field.into())),
            ("dim".to_string(), u(NumType::U32, dim as u64)),
            ("metric".to_string(), Value::Str(metric.into())),
            ("algorithm".to_string(), Value::Str("vamana".into())),
            ("precision".to_string(), Value::Str("f32".into())),
            ("vector_region".to_string(), u(NumType::U64, region.start_page)),
            ("entry_points".to_string(), Value::Array(vec![])),
            ("max_level".to_string(), u(NumType::U8, 0)),
            ("m".to_string(), u(NumType::U16, 32)),
            ("ef_construction".to_string(), u(NumType::U16, 200)),
            ("neighbours_sorted".to_string(), Value::Bool(false)),
            ("slot_to_doc".to_string(), u(NumType::U32, slots.tree_id() as u64)),
            ("doc_to_slot".to_string(), u(NumType::U32, docs.tree_id() as u64)),
            // §3: adjacency records are read randomly and hot.
            ("inline_values".to_string(), Value::Bool(true)),
        ];
        // As Java: the adjacency is a copy-on-write tree rooted at `root`
        // (F-196), so `levelled` is false whatever 05 §3's kind table says.
        let d = graph
            .with(vec![("levelled", Some(Value::Bool(false))), ("params", Some(Value::Doc(params)))])
            .with_root((0, 0));
        self.engine.catalog.put(&mut self.engine.pager, &name, &d)?;
        let mut ix = crate::vector::VectorIndex::open(&mut self.engine, &name, d)?;
        for doc in c.scan(&mut self.engine)? {
            if let Some(Value::NitriteId(id)) = doc.field("_id") {
                ix.put(&mut self.engine, *id, &doc)?;
            }
        }
        self.engine.vector_indexes.push(ix);
        self.commit(Durability::Sync)?;
        Ok(name)
    }

    /// Runs `f` on the open spatial index `name`.
    pub fn with_spatial<T>(
        &mut self,
        name: &str,
        f: impl FnOnce(&mut crate::rtree::SpatialIndex, &mut Engine) -> Result<T>,
    ) -> Result<T> {
        let mut all = std::mem::take(&mut self.engine.spatial_indexes);
        let r = match all.iter_mut().find(|i| i.name == name) {
            Some(ix) => f(ix, &mut self.engine),
            None => invalid(format!("no open spatial index {name}")),
        };
        self.engine.spatial_indexes = all;
        r
    }

    /// Runs `f` on the open vector index `name`.
    pub fn with_vector<T>(
        &mut self,
        name: &str,
        f: impl FnOnce(&mut crate::vector::VectorIndex, &mut Engine) -> Result<T>,
    ) -> Result<T> {
        let mut all = std::mem::take(&mut self.engine.vector_indexes);
        let r = match all.iter_mut().find(|i| i.name == name) {
            Some(ix) => f(ix, &mut self.engine),
            None => invalid(format!("no open vector index {name}")),
        };
        self.engine.vector_indexes = all;
        r
    }

    /// §11 — the enumerations a reader must support, given only the catalog.
    pub fn collections(&mut self) -> Result<Vec<String>> {
        let cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new((0, 0), 16));
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
        let from = self.dict.persisted_upto;
        // Only the ids interned since the last call. The previous form cloned
        // the whole dictionary and issued one `Engine::get` per entry on every
        // insert, so the write path carried an O(dictionary) cost per document
        // whose answer, after the first document, was always "already there".
        let pending: Vec<(u32, String)> = self
            .dict
            .by_id
            .range((std::ops::Bound::Excluded(from), std::ops::Bound::Unbounded))
            .map(|(id, name)| (*id, name.clone()))
            .collect();
        for (id, name) in pending {
            let key = Value::Int { w: NumType::U32, neg: false, mag: id as u128 };
            e.put(self.dict_tree, &key, &cve::encode(&Value::Str(name)))?;
            self.dict.persisted_upto = self.dict.persisted_upto.max(id);
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
        // §4's writer rules, at the one seam where a caller's value reaches the
        // encoder. A map key with no CKE encoding, or a duplicated one,
        // produces a file Dart and Java both refuse to open — their readers
        // check exactly this — so writing it would be a silent interop break.
        cve::check_writable(doc)?;
        if self.indexed(e) {
            let previous = self.get(e, id)?;
            self.maintain(e, id, Some(doc), previous.as_ref())?;
        }
        // F-200: a collection with no dictionary tree (Dart created them so)
        // gets its names inline; interning wrote the rows into tree 0.
        let bytes = if self.dict_tree == 0 {
            cve::encode_with_dict(doc, &|_| None)
        } else {
            for (name, _) in fields {
                self.dict.intern(name);
            }
            self.persist_dict(e)?;
            let dict = &self.dict.by_name;
            cve::encode_with_dict(doc, &|n| dict.get(n).copied())
        };
        e.put(self.tree, &Value::NitriteId(id), &bytes)?;
        e.publish_if_due()?;
        Ok(id)
    }

    pub fn get(&self, e: &mut Engine, id: i64) -> Result<Option<Value>> {
        let Some(bytes) = e.get(self.tree, &Value::NitriteId(id))? else { return Ok(None) };
        let by_id = &self.dict.by_id;
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
        if self.indexed(e) {
            let Some(previous) = self.get(e, id)? else { return Ok(()) };
            self.maintain(e, id, None, Some(&previous))?;
        }
        e.remove(self.tree, &Value::NitriteId(id))?;
        e.publish_if_due()
    }

    /// Whether the engine holds a spatial or vector index of this collection.
    fn indexed(&self, e: &Engine) -> bool {
        e.spatial_indexes.iter().any(|i| i.owner == self.name) || e.vector_indexes.iter().any(|i| i.owner == self.name)
    }

    /// The spatial and vector index side of a write; `doc` None is a delete.
    fn maintain(&self, e: &mut Engine, id: i64, doc: Option<&Value>, previous: Option<&Value>) -> Result<()> {
        let mut sp = std::mem::take(&mut e.spatial_indexes);
        let mut vx = std::mem::take(&mut e.vector_indexes);
        let r = (|| {
            for ix in sp.iter_mut().filter(|i| i.owner == self.name) {
                match doc {
                    Some(d) => ix.put(e, id, d, previous, None)?,
                    None => ix.remove(e, id, previous)?,
                }
            }
            for ix in vx.iter_mut().filter(|i| i.owner == self.name) {
                match doc {
                    Some(d) => ix.put(e, id, d)?,
                    None => ix.remove(e, id)?,
                }
            }
            Ok(())
        })();
        e.spatial_indexes = sp;
        e.vector_indexes = vx;
        r
    }

    /// §2.5's `clear()` — one range delete rather than O(n) tombstones.
    /// F-198: with a spatial or vector index each document is retracted from
    /// it first; a vector search returns slots, so a stale one would name a
    /// document that is gone (§8). ponytail: O(n) removes then; a whole-index
    /// clear is the upgrade if a large indexed clear matters.
    pub fn clear(&self, e: &mut Engine) -> Result<()> {
        if self.indexed(e) {
            for doc in self.scan(e)? {
                if let Some(Value::NitriteId(id)) = doc.field("_id") {
                    self.maintain(e, *id, None, Some(&doc))?;
                }
            }
        }
        e.remove_range(self.tree, &Value::NitriteId(i64::MIN), &Value::NitriteId(i64::MAX))?;
        e.publish_if_due()
    }

    pub fn scan(&self, e: &mut Engine) -> Result<Vec<Value>> {
        let by_id = &self.dict.by_id;
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

    /// `13-operations.md` §9 — recompute `params.stats` for an index tree.
    ///
    /// §9 maintains these "at compaction, ... free, because that compaction
    /// already touches every key". This is the same walk, exposed so the
    /// statistics can be refreshed on demand: a scan of the index tree in key
    /// order, which is exactly what a last-level compaction of it would do.
    ///
    /// The result is **advisory** and is stored under `params.stats`.
    fn analyze(&mut self, idx: &IndexDescriptor) -> Result<crate::stats::IndexStats>;

    /// The statistics stored for an index, or `None` when none have been
    /// computed. §9: "Statistics are advisory. They may be stale or absent."
    fn stats_of(&mut self, idx: &IndexDescriptor) -> Result<Option<crate::stats::IndexStats>>;

    /// Picks the most selective index among `candidates` — `06-indexes.md`
    /// §7.1.
    ///
    /// This is the decision Nitrite's `FindPlan` makes today from static
    /// descriptor properties — whether an index is unique and how many fields
    /// it covers — which "routinely picks a unique index on a field the query
    /// barely constrains over a non-unique index that would eliminate 99 % of
    /// the collection". With statistics it is made on evidence.
    ///
    /// `None` when no candidate has statistics, which a planner MUST treat as
    /// "choose some other way" rather than as an error.
    fn most_selective<'a>(
        &mut self,
        candidates: &'a [IndexDescriptor],
    ) -> Result<Option<&'a IndexDescriptor>>;
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
        let mut cat = std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new((0, 0), 16));
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

    fn analyze(&mut self, idx: &IndexDescriptor) -> Result<crate::stats::IndexStats> {
        // F-183: two streamed passes, a count and then the bounds, so no key
        // is held past its own step.
        let mut total = 0u64;
        let mut c = self.engine.scan_cursor(idx.tree, None, None, None, false)?;
        while c.next(&mut self.engine)?.is_some() {
            total += 1;
        }
        let mut b = crate::stats::StatsBuilder::new(total);
        let mut c = self.engine.scan_cursor(idx.tree, None, None, None, false)?;
        while let Some((k, _)) = c.next(&mut self.engine)? {
            let k = &k;
            // §9's `null_count`: an entry is null when any indexed value is.
            // `sparse` indexes never hold one, which is the whole difference
            // between a sparse index and a dense one.
            let is_null = match index::entry_values(k) {
                Ok((values, _)) => values.iter().any(|v| matches!(v, Value::Null)),
                Err(_) => false,
            };
            b.add(k, is_null);
        }
        // The descriptor is one cell of a copy-on-write B+tree, so
        // `params.stats` MUST fit one page (§9, defect 37). The budget is the
        // page less what the rest of the descriptor already costs; half a page
        // is a deliberately conservative floor, and §9's remedy for exceeding
        // it is to drop alternate buckets rather than to truncate the range.
        let budget = self.engine.pager.page_size / 2;
        let stats = b.build(self.engine.visible_seq, budget);

        let mut cat =
            std::mem::replace(&mut self.engine.catalog, crate::catalog::Catalog::new((0, 0), 16));
        let r = (|| -> Result<()> {
            let Some(mut d) = cat.get(&mut self.engine.pager, &idx.name)? else {
                return invalid(format!("no catalog entry for index {}", idx.name));
            };
            let mut params: Vec<(String, Value)> = match d.get("params") {
                Some(Value::Doc(f)) => f.clone(),
                _ => Vec::new(),
            };
            params.retain(|(k, _)| k != "stats");
            params.push(("stats".to_string(), stats.to_value()));
            d.doc.retain(|(k, _)| k != "params");
            d.doc.push(("params".to_string(), Value::Doc(params)));
            cat.put(&mut self.engine.pager, &idx.name, &d)
        })();
        self.engine.catalog = cat;
        r?;
        Ok(stats)
    }

    fn stats_of(&mut self, idx: &IndexDescriptor) -> Result<Option<crate::stats::IndexStats>> {
        let Some(d) = self.engine.catalog.get(&mut self.engine.pager, &idx.name)? else {
            return Ok(None);
        };
        let Some(Value::Doc(params)) = d.get("params") else {
            return Ok(None);
        };
        Ok(params
            .iter()
            .find(|(k, _)| k == "stats")
            .map(|(_, v)| crate::stats::IndexStats::from_value(v)))
    }

    fn most_selective<'a>(
        &mut self,
        candidates: &'a [IndexDescriptor],
    ) -> Result<Option<&'a IndexDescriptor>> {
        let mut best: Option<&IndexDescriptor> = None;
        let mut best_sel = f64::INFINITY;
        for c in candidates {
            let Some(s) = self.stats_of(c)? else { continue };
            let Some(sel) = crate::stats::selectivity(&s) else { continue };
            if sel < best_sel {
                best_sel = sel;
                best = Some(c);
            }
        }
        Ok(best)
    }
}
