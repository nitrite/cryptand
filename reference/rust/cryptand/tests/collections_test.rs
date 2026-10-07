//! Level 1 — `05-catalog.md` and `06-indexes.md`: documents, name
//! dictionaries, the catalog's enumerations, and one index layout for all
//! three index types.

mod support;
use support::*;

use cryptand::catalog::{data_tree_type, index_type, kind};
use cryptand::container::{Durability, Profile};
use cryptand::database::{Database, Indexing};
use cryptand::index::{self, Cmp};
use cryptand::value::{NumType, Value};
use cryptand::verify::{Class, EngineVerify};

#[test]
fn a_collection_name_needs_no_escaping_at_all() {
    // §1 retires, permanently, Fjall's `| -> _P_` substitution, Hive's base64
    // box keys, and every "reserved character" rule. A collection may be named
    // `"orders|2026+eu"` and nothing downstream cares.
    let (_t, mut db) = db("names", Profile::Desktop);
    let odd = "orders|2026+eu";
    let c = db.collection(odd).unwrap();
    db.engine.flush().unwrap();
    db.commit(Durability::Sync).unwrap();
    assert!(db.collections().unwrap().contains(&odd.to_string()));
    assert_eq!(db.collection(odd).unwrap().tree, c.tree);
}

#[test]
fn a_document_round_trips_through_the_name_dictionary() {
    let (_t, mut db) = db("doc", Profile::Desktop);
    let mut c = db.collection("people").unwrap();
    let d = doc(
        7,
        vec![
            ("name", str_value("Ada")),
            ("age", i32v(36)),
            ("tags", Value::Array(vec![str_value("maths"), str_value("engines")])),
        ],
    );
    c.insert(&mut db.engine, &d).unwrap();
    db.engine.flush().unwrap();
    let back = c.get(&mut db.engine, 7).unwrap().unwrap();
    assert_eq!(back.field("name"), Some(&str_value("Ada")));
    assert_eq!(back.field("age").map(|v| matches!(v, Value::Int { .. })), Some(true));

    // §5.3 — the dictionary is written in the same commit and the reserved
    // fields occupy 1..5, so `_id` encodes in one byte.
    assert_eq!(c.dict.by_name["_id"], 1);
    assert_eq!(c.dict.by_name["_type"], 5);
    assert!(c.dict.by_name["name"] > 5);
    // The whole document is smaller than the same document with inline names.
    let inline = cryptand::cve::encode(&d);
    let dict = c.dict.by_name.clone();
    let with_dict = cryptand::cve::encode_with_dict(&d, &|n| dict.get(n).copied());
    assert!(with_dict.len() < inline.len(), "the dictionary did not save space");
}

#[test]
fn a_document_whose_id_does_not_match_its_key_is_corruption() {
    // §5.4 — `_id` MUST equal the tree key of the entry, and a reader finding a
    // mismatch MUST report corruption.
    let (_t, mut db) = db("idmismatch", Profile::Desktop);
    let mut c = db.collection("c").unwrap();
    c.insert(&mut db.engine, &doc(1, vec![("v", i32v(1))])).unwrap();
    // Write a document carrying a different `_id` under key 2.
    let dict = c.dict.by_name.clone();
    let bytes =
        cryptand::cve::encode_with_dict(&doc(999, vec![("v", i32v(1))]), &|n| dict.get(n).copied());
    db.engine.put(c.tree, &Value::NitriteId(2), &bytes).unwrap();
    db.engine.flush().unwrap();
    assert!(matches!(c.get(&mut db.engine, 2), Err(cryptand::Error::Corrupt(_))));
}

#[test]
fn an_insert_and_its_index_entries_land_in_one_commit() {
    // §8 of `06-indexes.md` — "An index can never be transiently out of step
    // with its collection in a durable state."
    let (_t, mut db) = db("index", Profile::Desktop);
    let mut c = db.collection("orders").unwrap();
    let idx = db.create_index(&c, &["country", "city"], index_type::NON_UNIQUE, false).unwrap();
    for (id, country, city) in [
        (1i64, "de", "berlin"),
        (2, "de", "munich"),
        (3, "fr", "paris"),
        (4, "de", "berlin"),
    ] {
        let d = doc(id, vec![("country", str_value(country)), ("city", str_value(city))]);
        c.insert(&mut db.engine, &d).unwrap();
        db.index_document(&idx, &d).unwrap();
    }
    db.engine.flush().unwrap();
    db.commit(Durability::Sync).unwrap();

    // A prefix query is a range scan: one seek for `country`, one for
    // `(country, city)`.
    let de = db.index_scan(&idx, &index::scan_prefix(&[str_value("de")]).unwrap()).unwrap();
    // The scan is already in index order — (de, berlin, 1), (de, berlin, 4),
    // (de, munich, 2) — which is §7.1's "sorted output falls out for free when
    // the sort key is an index prefix", not the id order.
    assert_eq!(de, vec![1, 4, 2]);
    let berlin = db
        .index_scan(&idx, &index::scan_prefix(&[str_value("de"), str_value("berlin")]).unwrap())
        .unwrap();
    assert_eq!(berlin, vec![1, 4]);
    // `starts_with` on the second element.
    let b = db
        .index_scan(&idx, &index::scan_starts_with(&[str_value("de")], "b").unwrap())
        .unwrap();
    assert_eq!(b, vec![1, 4]);
    assert!(db.engine.verify().unwrap().of(Class::Corruption).is_empty());
}

#[test]
fn an_array_field_produces_one_entry_per_element() {
    // §4 — and duplicate elements produce one entry, not two.
    let (_t, mut db) = db("arrayindex", Profile::Desktop);
    let mut c = db.collection("posts").unwrap();
    let idx = db.create_index(&c, &["tags"], index_type::NON_UNIQUE, false).unwrap();
    let d = doc(
        7,
        vec![(
            "tags",
            Value::Array(vec![str_value("red"), str_value("blue"), str_value("red")]),
        )],
    );
    c.insert(&mut db.engine, &d).unwrap();
    assert_eq!(db.index_document(&idx, &d).unwrap(), 2, "the duplicate must collapse");
    db.engine.flush().unwrap();
    let red = db.index_scan(&idx, &index::scan_prefix(&[str_value("red")]).unwrap()).unwrap();
    assert_eq!(red, vec![7]);
    // Removal removes all of them.
    db.unindex_document(&idx, &d).unwrap();
    db.engine.flush().unwrap();
    assert!(db.index_scan(&idx, &index::scan_prefix(&[str_value("red")]).unwrap()).unwrap().is_empty());
}

#[test]
fn a_numeric_index_answers_eq_across_every_numeric_type() {
    // §7's numeric rows are the ones to get right: a bound built from the full
    // `CKE(v)` cuts *between numeric types* rather than between numeric values.
    let (_t, mut db) = db("numeric", Profile::Desktop);
    let mut c = db.collection("m").unwrap();
    let idx = db.create_index(&c, &["v"], index_type::NON_UNIQUE, false).unwrap();
    let widths = [
        (1i64, Value::int(NumType::I8, 5)),
        (2, Value::int(NumType::I32, 5)),
        (3, Value::int(NumType::U64, 5)),
        (4, Value::Float { w: NumType::F64, v: 5.0 }),
        (5, Value::int(NumType::I32, 6)),
        (6, Value::int(NumType::I32, 4)),
    ];
    for (id, v) in &widths {
        let d = doc(*id, vec![("v", v.clone())]);
        c.insert(&mut db.engine, &d).unwrap();
        db.index_document(&idx, &d).unwrap();
    }
    db.engine.flush().unwrap();

    let five = Value::int(NumType::I32, 5);
    let eq = db.index_scan(&idx, &index::scan_prefix_numeric(&[five.clone()]).unwrap()).unwrap();
    assert_eq!(eq, vec![1, 2, 3, 4], "eq(5) must match every numeric type equal to 5");
    // A type-exact equality is still a point lookup.
    let exact = db.index_scan(&idx, &index::scan_prefix(&[five.clone()]).unwrap()).unwrap();
    assert_eq!(exact, vec![2]);
    // `> 5` excludes every representation of 5 and includes 6.
    let gt = db.index_scan(&idx, &index::scan_range(&[], Cmp::Gt, &five).unwrap()).unwrap();
    assert_eq!(gt, vec![5]);
    // `>= 5` includes all four fives, including the I8 whose type code sorts
    // below I32's — the case a `CKE(v)` bound would miss.
    let ge = db.index_scan(&idx, &index::scan_range(&[], Cmp::Ge, &five).unwrap()).unwrap();
    assert_eq!(ge, vec![1, 2, 3, 4, 5]);
    let lt = db.index_scan(&idx, &index::scan_range(&[], Cmp::Lt, &five).unwrap()).unwrap();
    assert_eq!(lt, vec![6]);
}

#[test]
fn a_unique_index_refuses_a_duplicate_but_treats_every_null_as_distinct() {
    // §3 — "the uniqueness check of §1 is **skipped** whenever any of `v1..vk`
    // is `NULL`; it is not that the check runs and passes."
    let (_t, mut db) = db("unique", Profile::Desktop);
    let mut c = db.collection("u").unwrap();
    let idx = db.create_index(&c, &["email"], index_type::UNIQUE, false).unwrap();
    let a = doc(1, vec![("email", str_value("a@x"))]);
    c.insert(&mut db.engine, &a).unwrap();
    db.index_document(&idx, &a).unwrap();
    db.engine.flush().unwrap();

    let dup = doc(2, vec![("email", str_value("a@x"))]);
    c.insert(&mut db.engine, &dup).unwrap();
    assert!(db.index_document(&idx, &dup).is_err(), "a duplicate must be refused");

    // Two documents with the field absent are both indexed as NULL and both
    // accepted.
    for id in [10i64, 11] {
        let d = doc(id, vec![("other", i32v(1))]);
        c.insert(&mut db.engine, &d).unwrap();
        db.index_document(&idx, &d).unwrap();
        db.engine.flush().unwrap();
    }
    let nulls = db.index_scan(&idx, &index::scan_prefix(&[Value::Null]).unwrap()).unwrap();
    assert_eq!(nulls, vec![10, 11]);
}

#[test]
fn a_sparse_index_skips_an_absent_field_entirely() {
    let (_t, mut db) = db("sparse", Profile::Desktop);
    let mut c = db.collection("s").unwrap();
    let idx = db.create_index(&c, &["opt"], index_type::NON_UNIQUE, true).unwrap();
    let with = doc(1, vec![("opt", str_value("yes"))]);
    let without = doc(2, vec![("other", i32v(1))]);
    for d in [&with, &without] {
        c.insert(&mut db.engine, d).unwrap();
        db.index_document(&idx, d).unwrap();
    }
    db.engine.flush().unwrap();
    assert_eq!(db.index_document(&idx, &without).unwrap(), 0);
    let all = db.engine.scan_tree(idx.tree, None, None, None, false).unwrap();
    assert_eq!(all.len(), 1, "the sparse index holds only the document that has the field");
}

#[test]
fn a_value_with_no_key_encoding_cannot_be_indexed_and_says_which() {
    // §6 — the error names the field and the type. `DEC128` is the surprising
    // member: it is a number, and `03-key-encoding.md` §4.4 has the reason.
    for v in [
        Value::Dec128([0u8; 16]),
        Value::Doc(vec![]),
        Value::Geometry(vec![]),
        Value::VectorF32(vec![]),
        Value::Regex("a".into(), "".into()),
    ] {
        let e = index::check_indexable(&v).unwrap_err();
        assert!(format!("{e}").contains("cannot be indexed"), "{e}");
    }
    // BYTES **is** indexable in Cryptand, unlike `nitrite-rust` today.
    assert!(index::check_indexable(&Value::Bytes(vec![1, 2, 3])).is_ok());
}

#[test]
fn the_catalog_answers_every_enumeration_of_section_11() {
    let (_t, mut db) = db("enumerate", Profile::Desktop);
    let c = db.collection("orders").unwrap();
    db.create_index(&c, &["country"], index_type::NON_UNIQUE, false).unwrap();
    db.create_index(&c, &["sku"], index_type::UNIQUE, false).unwrap();
    db.engine.flush().unwrap();
    db.commit(Durability::Sync).unwrap();

    let cat = std::mem::replace(&mut db.engine.catalog, cryptand::catalog::Catalog::new(0, 0, 16));
    let pager = &mut db.engine.pager;
    assert_eq!(cat.collections(pager).unwrap(), vec!["orders".to_string()]);
    assert!(cat.repositories(pager, false).unwrap().is_empty());
    let indexes = cat.indexes_of(pager, "orders").unwrap();
    assert_eq!(indexes.len(), 2);
    assert!(indexes.iter().all(|(_, d)| d.kind() == kind::INDEX));
    assert!(cat.stale_indexes(pager).unwrap().is_empty());
    // A `data` tree carries `params.type`, which is the structured truth; the
    // name is for humans.
    let d = cat.get(pager, "orders").unwrap().unwrap();
    assert_eq!(d.param_str("type"), Some(data_tree_type::COLLECTION));
    db.engine.catalog = cat;
}

#[test]
fn an_unknown_tree_kind_is_listed_copied_and_never_deleted() {
    // §4 — "A reader that does not recognize a `kind` MUST treat the tree as
    // opaque: it may be listed and copied, it MUST NOT be deleted, and it MUST
    // NOT be interpreted."
    let (_t, mut db) = db("opaque", Profile::Desktop);
    let now = cryptand::engine::now_millis();
    let mut cat = std::mem::replace(&mut db.engine.catalog, cryptand::catalog::Catalog::new(0, 0, 16));
    cat.create(&mut db.engine.pager, "future", "quantum_index", None, None, None, 0, vec![], now)
        .unwrap();
    let err = cat.drop(&mut db.engine.pager, "future").unwrap_err();
    assert!(format!("{err}").contains("MUST NOT be deleted"), "{err}");
    assert!(cat.get(&mut db.engine.pager, "future").unwrap().is_some());
    db.engine.catalog = cat;
}

#[test]
fn an_unknown_descriptor_field_survives_a_rewrite() {
    // `11-conformance.md` §4 rule 2 — without this, one save from a Dart app
    // silently deletes a Java application's fields.
    let (_t, mut db) = db("preserve", Profile::Desktop);
    let now = cryptand::engine::now_millis();
    let mut cat = std::mem::replace(&mut db.engine.catalog, cryptand::catalog::Catalog::new(0, 0, 16));
    let d = cat
        .create(&mut db.engine.pager, "t", kind::KV, None, None, None, 0, vec![], now)
        .unwrap();
    let extended = d.with(vec![("from_the_future", Some(str_value("keep me")))]);
    cat.put(&mut db.engine.pager, "t", &extended).unwrap();
    // A round trip through a rewriter that has never heard of the field.
    let read = cat.get(&mut db.engine.pager, "t").unwrap().unwrap();
    let rewritten = read.with(vec![("entries", Some(Value::Int { w: NumType::U64, neg: false, mag: 9 }))]);
    cat.put(&mut db.engine.pager, "t", &rewritten).unwrap();
    let back = cat.get(&mut db.engine.pager, "t").unwrap().unwrap();
    assert_eq!(back.get("from_the_future"), Some(&str_value("keep me")));
    db.engine.catalog = cat;
}

#[test]
fn field_paths_traverse_and_flatten_arrays() {
    // §5 — "so `orders.items.sku` indexes every sku in every item of every
    // order", and `\.` is the only escaping in the format.
    assert_eq!(index::parse_field_path("a.b.c"), vec!["a", "b", "c"]);
    assert_eq!(index::parse_field_path(r"a\.b.c"), vec!["a.b", "c"]);
    assert_eq!(index::parse_field_path(r"a\\b"), vec![r"a\b"]);

    let d = Value::Doc(vec![(
        "orders".into(),
        Value::Array(vec![
            Value::Doc(vec![(
                "items".into(),
                Value::Array(vec![
                    Value::Doc(vec![("sku".into(), str_value("A"))]),
                    Value::Doc(vec![("sku".into(), str_value("B"))]),
                ]),
            )]),
            Value::Doc(vec![(
                "items".into(),
                Value::Array(vec![Value::Doc(vec![("sku".into(), str_value("C"))])]),
            )]),
        ]),
    )]);
    let path = index::parse_field_path("orders.items.sku");
    let got = index::resolve(&d, &path).unwrap();
    assert_eq!(got, vec![str_value("A"), str_value("B"), str_value("C")]);
}

#[test]
fn the_cartesian_product_of_two_array_fields_is_capped() {
    // §4 — "A writer MUST cap this at 1024 entries per document and report an
    // error beyond it rather than write an unbounded number of index rows."
    let big = Value::Array((0..40).map(|i| i32v(i)).collect());
    let d = Value::Doc(vec![
        ("_id".into(), Value::NitriteId(1)),
        ("a".into(), big.clone()),
        ("b".into(), big),
    ]);
    let r = index::index_keys(&d, &["a".into(), "b".into()], false, 1);
    assert!(r.is_err(), "1600 combinations must be refused, not written");
    assert!(format!("{}", r.unwrap_err()).contains("1024"));
}

#[test]
fn a_clear_is_one_range_delete_not_n_tombstones() {
    let (_t, mut db) = db("clear", Profile::Desktop);
    let mut c = db.collection("c").unwrap();
    for i in 0..500i64 {
        c.insert(&mut db.engine, &doc(i, vec![("v", i32v(i as i32))])).unwrap();
    }
    db.engine.flush().unwrap();
    let seq_before = db.engine.next_seq;
    c.clear(&mut db.engine).unwrap();
    assert_eq!(db.engine.next_seq, seq_before + 1, "clear() must be O(1) writes");
    db.engine.flush().unwrap();
    assert!(c.scan(&mut db.engine).unwrap().is_empty());
}

/// `05-catalog.md` §5.3 — "a writer MUST write new dictionary entries in the
/// **same commit** as the document that first uses them."
///
/// `persist_dict` re-probed every dictionary entry on every insert, one
/// `Engine::get` per name per document. It is now driven by a high-water mark,
/// which is exact because §5.3's `name_id` is "allocated append-only and never
/// reused" — but a high-water mark is precisely the kind of optimisation that
/// is correct until a name is interned on a path that does not advance it, and
/// then silently writes a document referring to a `name_id` no reader can
/// resolve.
///
/// So this reopens the database in a **fresh** `Database`, which reloads the
/// dictionary from tree bytes and shares nothing with the writer's in-memory
/// copy, and reads every document back.
#[test]
fn every_field_name_survives_a_reopen_after_incremental_interning() {
    let t = TempDb::new("dict_persist");
    // Each document introduces a field name the previous ones did not, so the
    // dictionary grows on every insert rather than only on the first.
    {
        let mut db = Database::create(&t.path, Profile::Desktop).unwrap();
        let mut c = db.collection("orders").unwrap();
        for i in 0..40i64 {
            let d = doc(
                i,
                vec![
                    ("common", str_value("x")),
                    // A name unique to this document.
                    (Box::leak(format!("f{i}").into_boxed_str()), i32v(i as i32)),
                ],
            );
            c.insert(&mut db.engine, &d).unwrap();
        }
        db.engine.flush().unwrap();
        db.commit(Durability::Sync).unwrap();
    }

    let mut db = Database::open(&t.path, None).unwrap();
    let c = db.collection("orders").unwrap();
    for i in 0..40i64 {
        let got = c
            .get(&mut db.engine, i)
            .unwrap()
            .unwrap_or_else(|| panic!("document {i} is missing after a reopen"));
        // The per-document field must resolve to its NAME, not to a dangling
        // `name_id`. A dictionary entry that was never written shows up here.
        assert!(
            got.field(&format!("f{i}")).is_some(),
            "document {i} lost the field name only it introduced: {got:?}"
        );
        assert!(got.field("common").is_some(), "document {i} lost the shared field name");
    }
    assert_eq!(c.scan(&mut db.engine).unwrap().len(), 40);
}

#[test]
fn an_empty_array_has_no_entries_and_an_unresolved_traversal_is_null() {
    // F-058/F-059: §4 gives an empty array zero entries; §5 makes a path no
    // array element resolves an absent field, indexed as NULL.
    let empty = doc(1, vec![("tags", Value::Array(vec![]))]);
    assert!(index::index_keys(&empty, &["tags".into()], false, 1).unwrap().is_empty());
    let nested = doc(1, vec![("a", Value::Array(vec![str_value("x")]))]);
    let keys = index::index_keys(&nested, &["a.b".into()], false, 1).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(index::entry_values(&keys[0]).unwrap().0, vec![Value::Null]);
}
