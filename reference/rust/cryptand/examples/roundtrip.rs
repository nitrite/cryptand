//! Create an encrypted `.cryptand` file, write documents through a collection,
//! close it, reopen it with the key, and read them back.
//!
//! The same file can be opened by the Dart reference implementation
//! (`reference/dart/cryptand`) — see `reference/conformance/interop/`.
//!
//! Run with: `cargo run --example roundtrip`

use cryptand::container::{Durability, Profile};
use cryptand::database::Database;
use cryptand::engine::Engine;
use cryptand::value::{NumType, Value};

fn main() -> cryptand::Result<()> {
    let dir = std::env::temp_dir().join("cryptand-example");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("people.cryptand");
    let _ = std::fs::remove_file(&path);

    // A 32-byte content key. In a real application this comes from a platform
    // keystore or an Argon2id-derived password (see spec/14-security.md).
    let key = [7u8; 32];

    // --- write ----------------------------------------------------------
    // kdf = 0: use the key as given. t_cost/m_cost/lanes are unused then.
    let engine = Engine::create_encrypted(&path, Profile::Desktop, &key, 0, 0, 0, 0)?;
    let mut db = Database { engine };
    let mut people = db.collection("people")?;
    for i in 0..100 {
        people.insert(
            &mut db.engine,
            &Value::Doc(vec![
                ("_id".into(), Value::NitriteId(i)),
                ("name".into(), Value::Str(format!("person-{i}"))),
                ("age".into(), Value::int(NumType::I32, 20 + i as i128 % 50)),
            ]),
        )?;
    }
    db.commit(Durability::Sync)?;
    db.close()?;

    // --- read back -----------------------------------------------------
    let mut reopened = Database::open(&path, Some(&key))?;
    let people = reopened.collection("people")?;
    let doc = people.get(&mut reopened.engine, 42)?.expect("id 42");
    println!("id 42 -> {:?}", doc.field("name"));
    println!("documents: {}", people.scan(&mut reopened.engine)?.len());

    // The wrong key is refused.
    assert!(Database::open(&path, Some(&[0u8; 32])).is_err());
    println!("wrong key rejected");

    std::fs::remove_file(&path).ok();
    Ok(())
}
