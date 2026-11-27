//! `07-fulltext.md`: the maintained full-text index (`cryptand::text`).

mod support;

use cryptand::container::Profile;
use cryptand::database::Database;
use cryptand::container::Durability;
use cryptand::value::{NumType, Value};
use support::TempDb;

fn doc(id: i64, body: &str) -> Value {
    Value::Doc(vec![
        ("_id".into(), Value::NitriteId(id)),
        ("n".into(), Value::int(NumType::I64, id as i128)),
        ("body".into(), Value::Str(body.into())),
    ])
}

#[test]
fn a_text_index_answers_terms_and_phrases_through_writes_and_a_reopen() {
    let t = TempDb::new("text_index");
    let name;
    {
        let mut db = Database::create(&t.path, Profile::Desktop).unwrap();
        let mut c = db.collection("notes").unwrap();
        c.insert(&mut db.engine, &doc(1, "The quick brown fox")).unwrap();
        name = db.create_text_index(&c, &["body"], vec!["the".into()], "none", true).unwrap();
        // 300 documents with "common" span three blocks (§4.1: <= 128 each).
        for id in 2..=301 {
            c.insert(&mut db.engine, &doc(id, &format!("common word{} brown dog", id % 7))).unwrap();
        }
        c.insert(&mut db.engine, &doc(5, "lazy fox jumps")).unwrap(); // update
        c.remove(&mut db.engine, 6).unwrap();
        db.commit(Durability::Sync).unwrap();
        db.close().unwrap();
    }
    let mut db = Database::open(&t.path, None).unwrap();
    let c = db.collection("notes").unwrap();
    let docs = c.scan(&mut db.engine).unwrap();
    db.with_text(&name, |ix, e| {
        assert_eq!(ix.search(e, "fox")?, vec![1, 5]);
        assert_eq!(ix.search(e, "THE fox")?, vec![1, 5], "stopword dropped from the query too");
        assert_eq!(ix.search(e, "common")?.len(), 298, "300 minus the update and the delete");
        assert!(!ix.search(e, "common")?.contains(&6));
        assert_eq!(ix.phrase(e, "brown dog")?.len(), 298);
        assert_eq!(ix.phrase(e, "dog brown")?, Vec::<i64>::new());
        assert_eq!(ix.phrase(e, "quick brown")?, vec![1]);
        let findings = ix.verify(e, &docs)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_phrase_query_without_positions_is_refused() {
    let t = TempDb::new("text_nopos");
    let mut db = Database::create(&t.path, Profile::Desktop).unwrap();
    let mut c = db.collection("notes").unwrap();
    c.insert(&mut db.engine, &doc(1, "red apple")).unwrap();
    let name = db.create_text_index(&c, &["body"], vec![], "none", false).unwrap();
    db.with_text(&name, |ix, e| {
        assert_eq!(ix.search(e, "apple")?, vec![1]);
        assert!(ix.phrase(e, "red apple").is_err());
        Ok(())
    })
    .unwrap();
}
