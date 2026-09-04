//! One half of `11-conformance.md` §6's mandatory round-trip gate:
//!
//! > "for each golden file, open it in implementation A, mutate it, close it,
//! > open it in B, verify, mutate, close, reopen in A. **This is the actual
//! > product claim and it must be tested as such.**"
//!
//! The other half is `reference/dart/cryptand/tool/interop.dart`, which
//! implements the same four commands over the same fixture. Neither reads the
//! other's source; both read `spec/`.
//!
//! Commands: `write`, `read`, `mutate <tag>`, `verify`.

use std::path::PathBuf;
use std::process::ExitCode;

use cryptand::catalog::{data_tree_type, index_type, kind, Catalog};
use cryptand::cke;
use cryptand::container::{Durability, Profile};
use cryptand::cve;
use cryptand::engine::Engine;
use cryptand::hash::crc32c;
use cryptand::value::{NumType, Value};
use cryptand::verify::{Class, EngineVerify};

/// The fixture, defined once and reproduced independently on both sides.
pub const COLLECTION: &str = "orders";
pub const NAME_DICT: &str = "orders$names";
pub const INDEX: &str = "idx:orders:country:non_unique";
pub const N: i64 = 400;
pub const COUNTRIES: [&str; 5] = ["de", "fr", "uk", "in", "us"];

/// A document is `{_id, seq, country, note}`. Every tenth `note` is 900 bytes,
/// which is above `desktop`'s `vlog_min` of 256, so the fixture exercises both
/// the inline and the separated value path.
pub fn document(i: i64, note: Option<Vec<u8>>) -> Value {
    let note = note.unwrap_or_else(|| {
        let len = if i % 10 == 0 { 900 } else { 40 };
        vec![(i % 251) as u8; len]
    });
    Value::Doc(vec![
        ("_id".into(), Value::NitriteId(i)),
        ("seq".into(), Value::Int { w: NumType::I32, neg: i < 0, mag: i.unsigned_abs() as u128 }),
        ("country".into(), Value::Str(COUNTRIES[(i % 5) as usize].to_string())),
        ("note".into(), Value::Bytes(note)),
    ])
}

/// The canonical digest both implementations compute over the visible state.
/// CRC-32C because `00-conventions.md` §6 already makes it mandatory
/// everywhere, so neither side needs a primitive the other lacks.
pub fn digest(rows: &[(i64, String, Vec<u8>)]) -> u32 {
    let mut b = Vec::new();
    for (id, country, note) in rows {
        b.extend_from_slice(&id.to_le_bytes());
        b.extend_from_slice(&(country.len() as u32).to_le_bytes());
        b.extend_from_slice(country.as_bytes());
        b.extend_from_slice(&(note.len() as u32).to_le_bytes());
        b.extend_from_slice(&note[..note.len().min(8)]);
    }
    crc32c(&b)
}

struct Db {
    e: Engine,
    data: u32,
    dict: u32,
    index: u32,
    names: std::collections::BTreeMap<String, u32>,
    by_id: std::collections::BTreeMap<u32, String>,
}

fn tree_id_of(e: &mut Engine, name: &str) -> Option<u32> {
    let cat = std::mem::replace(&mut e.catalog, Catalog::new(0, 0, 16));
    let d = cat.get(&mut e.pager, name);
    e.catalog = cat;
    d.ok().flatten().map(|d| d.tree_id())
}

/// §5.3 — the per-tree field-name dictionary, read back from its own tree.
fn load_dict(e: &mut Engine, dict: u32) -> (std::collections::BTreeMap<String, u32>, std::collections::BTreeMap<u32, String>) {
    let mut by_name = std::collections::BTreeMap::new();
    let mut by_id = std::collections::BTreeMap::new();
    for (k, v) in e.scan_tree(dict, None, None, None, true).unwrap_or_default() {
        let Ok(Value::Int { mag, .. }) = cke::decode_all(&k) else { continue };
        if let Ok(Value::Str(name)) = cve::decode_all(&v, &|_| None) {
            by_name.insert(name.clone(), mag as u32);
            by_id.insert(mag as u32, name);
        }
    }
    (by_name, by_id)
}

fn open(path: &str) -> cryptand::Result<Db> {
    let mut e = Engine::open(&PathBuf::from(path), None)?;
    let data = tree_id_of(&mut e, COLLECTION)
        .ok_or_else(|| cryptand::Error::Corrupt(format!("no collection {COLLECTION}")))?;
    let dict = tree_id_of(&mut e, NAME_DICT)
        .ok_or_else(|| cryptand::Error::Corrupt(format!("no name dictionary {NAME_DICT}")))?;
    let index = tree_id_of(&mut e, INDEX).unwrap_or(0);
    let (names, by_id) = load_dict(&mut e, dict);
    Ok(Db { e, data, dict, index, names, by_id })
}

fn intern(db: &mut Db, name: &str) -> cryptand::Result<u32> {
    if let Some(&id) = db.names.get(name) {
        return Ok(id);
    }
    let id = db.names.values().copied().max().unwrap_or(0) + 1;
    db.names.insert(name.to_string(), id);
    db.by_id.insert(id, name.to_string());
    // §5.3: a writer MUST write new dictionary entries in the **same commit**
    // as the document that first uses them.
    let key = Value::Int { w: NumType::U32, neg: false, mag: id as u128 };
    let v = cve::encode(&Value::Str(name.to_string()));
    db.e.put(db.dict, &key, &v)?;
    Ok(id)
}

fn put(db: &mut Db, doc: &Value) -> cryptand::Result<()> {
    let Some(Value::NitriteId(id)) = doc.field("_id") else {
        return cryptand::invalid("a document needs an `_id`");
    };
    let id = *id;
    if let Value::Doc(fields) = doc {
        for (name, _) in fields {
            intern(db, name)?;
        }
    }
    // Remove the previous index entries before writing the new ones (§8).
    if db.index != 0 {
        if let Some(prev) = read_one(db, id)? {
            for k in cryptand::index::index_keys(&prev, &["country".into()], false, id)? {
                let key = cke::decode_all(&k)?;
                db.e.remove(db.index, &key)?;
            }
        }
        for k in cryptand::index::index_keys(doc, &["country".into()], false, id)? {
            let key = cke::decode_all(&k)?;
            db.e.put_empty(db.index, &key)?;
        }
    }
    let names = db.names.clone();
    let bytes = cve::encode_with_dict(doc, &|n| names.get(n).copied());
    db.e.put(db.data, &Value::NitriteId(id), &bytes)?;
    Ok(())
}

fn read_one(db: &mut Db, id: i64) -> cryptand::Result<Option<Value>> {
    let Some(bytes) = db.e.get(db.data, &Value::NitriteId(id))? else { return Ok(None) };
    let by_id = db.by_id.clone();
    Ok(Some(cve::decode_all(&bytes, &|i| by_id.get(&i).cloned())?))
}

fn rows(db: &mut Db) -> cryptand::Result<Vec<(i64, String, Vec<u8>)>> {
    let by_id = db.by_id.clone();
    let mut out = Vec::new();
    for (k, v) in db.e.scan_tree(db.data, None, None, None, true)? {
        let Value::NitriteId(id) = cke::decode_all(&k)? else { continue };
        let doc = cve::decode_all(&v, &|i| by_id.get(&i).cloned())?;
        let country = match doc.field("country") {
            Some(Value::Str(s)) => s.clone(),
            _ => String::new(),
        };
        let note = match doc.field("note") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => Vec::new(),
        };
        // §5.4: `_id` MUST equal the tree key of the entry.
        match doc.field("_id") {
            Some(Value::NitriteId(x)) if *x == id => {}
            other => {
                return cryptand::corrupt(format!("document at key {id} carries _id {other:?}"))
            }
        }
        out.push((id, country, note));
    }
    out.sort_by_key(|r| r.0);
    Ok(out)
}

fn cmd_write(path: &str) -> cryptand::Result<()> {
    let _ = std::fs::remove_file(path);
    let mut e = Engine::create(&PathBuf::from(path), Profile::Desktop)?;
    let now = cryptand::engine::now_millis();
    let mut cat = std::mem::replace(&mut e.catalog, Catalog::new(0, 0, 16));
    let dict = cat
        .create(&mut e.pager, NAME_DICT, kind::NAME_DICT, Some(COLLECTION), None, Some("u32"), 0, vec![], now)?
        .tree_id();
    let data = cat
        .create(
            &mut e.pager,
            COLLECTION,
            kind::DATA,
            None,
            Some(dict),
            Some("nitrite_id"),
            0,
            vec![("type".into(), Value::Str(data_tree_type::COLLECTION.into()))],
            now,
        )?
        .tree_id();
    let index = cat
        .create(
            &mut e.pager,
            INDEX,
            kind::INDEX,
            Some(COLLECTION),
            None,
            Some("array"),
            0,
            vec![
                ("index_type".into(), Value::Str(index_type::NON_UNIQUE.into())),
                ("data_tree".into(), Value::Int { w: NumType::U32, neg: false, mag: data as u128 }),
                ("fields".into(), Value::Array(vec![Value::Str("country".into())])),
                ("sparse".into(), Value::Bool(false)),
            ],
            now,
        )?
        .tree_id();
    e.catalog = cat;
    e.sb.set_feature(cryptand::container::feature::DOCUMENTS, true);

    let mut db = Db { e, data, dict, index, names: Default::default(), by_id: Default::default() };
    // §5.4: the reserved names SHOULD occupy `name_id` 1..5 in every data tree.
    for n in ["_id", "_revision", "_modified", "_source", "_type"] {
        intern(&mut db, n)?;
    }
    for i in 0..N {
        put(&mut db, &document(i, None))?;
        if i % 120 == 119 {
            db.e.flush()?;
        }
    }
    db.e.flush()?;
    db.e.close(true)?;
    println!("wrote {N} documents to {path}");
    Ok(())
}

fn cmd_read(path: &str) -> cryptand::Result<()> {
    let mut db = open(path)?;
    let rows = rows(&mut db)?;
    println!("docs={}", rows.len());
    println!("digest={:08x}", digest(&rows));
    println!("dict={}", db.names.len());
    println!("writer={}", db.e.sb.writer_id);
    println!("page_size={}", db.e.page_size());
    println!("commit_id={}", db.e.sb.commit_id);
    println!("segments={}", db.e.all_refs()?.len());
    println!("vlog_segments={}", db.e.vlog_stats.len());
    let cat = std::mem::replace(&mut db.e.catalog, Catalog::new(0, 0, 16));
    let mut names: Vec<String> = cat.all(&mut db.e.pager)?.into_iter().map(|(n, _)| n).collect();
    db.e.catalog = cat;
    names.sort();
    println!("trees={}", names.join(","));
    if db.index != 0 {
        // §7 — the index must answer a prefix scan over what the other side
        // wrote, or the two SDKs disagree about the same bytes.
        let scan = cryptand::index::scan_prefix(&[Value::Str("de".into())])?;
        let hits = db
            .e
            .scan_tree(db.index, Some(&scan.lower), scan.upper.as_deref(), None, false)?
            .len();
        println!("index_de={hits}");
    }
    Ok(())
}

fn cmd_mutate(path: &str, tag: &str) -> cryptand::Result<()> {
    let mut db = open(path)?;
    let mut updated = 0;
    let mut deleted = 0;
    for i in 0..N {
        if i % 13 == 0 {
            if let Some(prev) = read_one(&mut db, i)? {
                if db.index != 0 {
                    for k in cryptand::index::index_keys(&prev, &["country".into()], false, i)? {
                        let key = cke::decode_all(&k)?;
                        db.e.remove(db.index, &key)?;
                    }
                }
                db.e.remove(db.data, &Value::NitriteId(i))?;
                deleted += 1;
            }
        } else if i % 7 == 0 {
            let mut note = tag.as_bytes().to_vec();
            note.resize(300, b'.');
            put(&mut db, &document(i, Some(note)))?;
            updated += 1;
        }
    }
    // New documents, so the other side sees ids it never wrote.
    for i in N..N + 50 {
        put(&mut db, &document(i, None))?;
    }
    // A field name neither the fixture nor the other side has seen, which
    // exercises §5.3's "a reader MAY cache the whole dictionary; on
    // encountering an unknown `name_id` it MUST re-read the dictionary tree".
    let extra = format!("touched_by_{tag}");
    intern(&mut db, &extra)?;
    db.e.flush()?;
    db.e.commit(Durability::Sync)?;
    db.e.close(true)?;
    println!("mutated by {tag}: {updated} updated, {deleted} deleted, 50 inserted");
    Ok(())
}

fn cmd_verify(path: &str) -> cryptand::Result<ExitCode> {
    let mut e = Engine::open(&PathBuf::from(path), None)?;
    let r = e.verify()?;
    println!(
        "verify: {} segments, {} entries, {} findings",
        r.segments,
        r.entries,
        r.findings.len()
    );
    for f in &r.findings {
        println!("  {:?}: {}", f.class, f.what);
    }
    Ok(if r.of(Class::Corruption).is_empty() && r.of(Class::Tampering).is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(|s| s.as_str()) {
        Some("write") if args.len() >= 2 => cmd_write(&args[1]).map(|_| ExitCode::SUCCESS),
        Some("read") if args.len() >= 2 => cmd_read(&args[1]).map(|_| ExitCode::SUCCESS),
        Some("mutate") if args.len() >= 3 => {
            cmd_mutate(&args[1], &args[2]).map(|_| ExitCode::SUCCESS)
        }
        Some("verify") if args.len() >= 2 => cmd_verify(&args[1]),
        _ => {
            eprintln!("interop write|read|mutate <tag>|verify <file>");
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
