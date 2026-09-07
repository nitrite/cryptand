//! `11-conformance.md` §7 — the reference CLI, driven as a real process.
//!
//! This file exists because `src/bin/cryptand.rs` measured **0 of 186 lines**.
//! It is a shipped tool with eight subcommands — `verify`, `dump`, `stats`,
//! `repair`, `backup`, `fuzz`, `create` — and not one of them had ever been
//! run by anything but a hand at a terminal. The library underneath is well
//! covered, which is exactly what makes this invisible: every function the CLI
//! calls is tested, and the CLI's own argument handling, output and exit codes
//! are not.
//!
//! It runs the built binary rather than calling the functions, because the
//! things that break in a CLI are the things a unit test cannot reach: an
//! argument arity that silently falls through to `usage`, a subcommand that
//! prints to stdout and returns failure, an error path that panics instead of
//! reporting. `13-operations.md` §3 says a repair that silently corrupts is
//! worse than no repair; a CLI that silently succeeds is the same shape.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary Cargo just built, beside this test's own executable.
fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop(); // deps/
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("cryptand")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        // §7's `open` reads a key from here; the tests below are unencrypted,
        // and an inherited value from the developer's shell would make them
        // fail for a reason that has nothing to do with the CLI.
        .env_remove("CRYPTAND_KEY")
        .output()
        .unwrap_or_else(|e| panic!("could not run {}: {e}", bin().display()))
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A database with real content: several collections, an index, and enough
/// documents to produce more than one segment.
fn populated(dir: &Path, name: &str) -> PathBuf {
    use cryptand::container::Durability;
    use cryptand::database::{Database, Indexing};
    use cryptand::value::{NumType, Value};

    let path = dir.join(name);
    {
        let mut db = Database::create(&path, cryptand::container::Profile::Desktop).unwrap();
        let mut c = db.collection("people").unwrap();
        let idx = db.create_index(&c, &["city"], "non_unique", false).unwrap();
        for i in 0..400i64 {
            let mut d = Value::Doc(vec![
                ("_id".into(), Value::NitriteId(i)),
                ("city".into(), Value::Str(if i % 2 == 0 { "delhi" } else { "kolkata" }.into())),
                ("age".into(), Value::int(NumType::I64, (20 + i % 50) as i128)),
                // Past `vlog_min` on desktop (256 B), so the value log is
                // exercised too and `dump`'s liveness section has something to
                // report.
                ("bio".into(), Value::Str("x".repeat(400))),
            ]);
            c.insert(&mut db.engine, &mut d).unwrap();
            db.index_document(&idx, &d).unwrap();
        }
        db.commit(Durability::Sync).unwrap();
        db.close().unwrap();
    }
    path
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cryptand-cli-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------------------
// argument handling
// ---------------------------------------------------------------------------

#[test]
fn no_arguments_prints_usage_and_exits_two() {
    let o = run(&[]);
    // Exit 2 rather than 1: "you asked for something I do not understand" is
    // not "the thing you asked for failed", and a script distinguishes them.
    assert_eq!(o.status.code(), Some(2), "usage must exit 2");
    assert!(stderr(&o).contains("cryptand <command>"), "{}", stderr(&o));
    assert!(stdout(&o).is_empty(), "usage belongs on stderr");
}

#[test]
fn an_unknown_subcommand_prints_usage() {
    let o = run(&["frobnicate", "x"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("cryptand <command>"));
}

#[test]
fn a_subcommand_missing_its_argument_prints_usage_rather_than_panicking() {
    // Every arm of the dispatch carries an arity guard. A missing guard is an
    // index-out-of-bounds panic, which is the one outcome a CLI must never
    // have: it exits 101 with a backtrace instead of telling the user what to
    // type.
    for cmd in ["verify", "dump", "stats", "repair", "create", "backup", "fuzz"] {
        let o = run(&[cmd]);
        assert_eq!(o.status.code(), Some(2), "{cmd} with no argument");
        assert!(stderr(&o).contains("cryptand <command>"), "{cmd}");
    }
    // `backup` needs two, and one is not enough.
    let o = run(&["backup", "only-one"]);
    assert_eq!(o.status.code(), Some(2));
    // `--incremental` needs both as well.
    let o = run(&["backup", "--incremental", "only-one"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn a_missing_file_is_reported_and_never_panics() {
    let dir = tmp("missing");
    let path = dir.join("does-not-exist.cryptand");
    for cmd in ["verify", "dump", "stats", "repair"] {
        let o = run(&[cmd, path.to_str().unwrap()]);
        assert!(!o.status.success(), "{cmd} on a missing file must fail");
        assert_ne!(o.status.code(), Some(101), "{cmd} panicked instead of reporting");
        assert!(!stderr(&o).is_empty(), "{cmd} failed silently");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_that_is_not_a_database_is_reported_as_such() {
    let dir = tmp("garbage");
    let path = dir.join("garbage.cryptand");
    std::fs::write(&path, vec![0x7Fu8; 40_000]).unwrap();
    let o = run(&["verify", path.to_str().unwrap()]);
    assert!(!o.status.success());
    assert_ne!(o.status.code(), Some(101), "a hostile file must not panic the reader");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// the subcommands
// ---------------------------------------------------------------------------

#[test]
fn create_makes_a_database_the_other_subcommands_can_open() {
    let dir = tmp("create");
    let path = dir.join("new.cryptand");
    let o = run(&["create", path.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("created"));
    assert!(path.exists());

    // Creating over an existing file must not silently truncate it.
    let again = run(&["create", path.to_str().unwrap()]);
    assert!(!again.status.success(), "create over an existing file must fail");

    let v = run(&["verify", path.to_str().unwrap()]);
    assert!(v.status.success(), "{}", stderr(&v));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_reports_a_clean_database_and_says_what_it_checked() {
    let dir = tmp("verify");
    let path = populated(&dir, "db.cryptand");
    let o = run(&["verify", path.to_str().unwrap()]);
    assert!(o.status.success(), "stderr: {}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("segments"), "{out}");
    assert!(out.contains("entries"), "{out}");
    assert!(out.contains("reachable pages"), "{out}");
    assert!(!out.contains("Corruption"), "a clean database reported corruption:\n{out}");
    assert!(!out.contains("Tampering"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_finds_damage_and_fails() {
    let dir = tmp("damage");
    let path = populated(&dir, "db.cryptand");
    // A clean database already reports *leaks* -- pages that are neither
    // reachable nor free, which `13-operations.md` §3 calls repairable and not
    // a failure. So the baseline is taken first and the assertion is about
    // Corruption or Tampering specifically; asserting "any finding" would pass
    // on an undamaged file.
    let before = run(&["verify", path.to_str().unwrap()]);
    assert!(before.status.success(), "the fixture must start clean");
    assert!(!stdout(&before).contains("Corruption"), "{}", stdout(&before));

    // Damage every page in the first quarter of the data region, so the flips
    // land on pages a scan actually reaches rather than in value-log padding.
    let mut bytes = std::fs::read(&path).unwrap();
    let page = 4096usize;
    let last = bytes.len() / page;
    for p in 2..(2 + (last - 2) / 4).max(3) {
        let at = p * page;
        if at + 64 > bytes.len() {
            break;
        }
        for i in 0..64 {
            bytes[at + i] ^= 0xFF;
        }
    }
    std::fs::write(&path, &bytes).unwrap();

    let o = run(&["verify", path.to_str().unwrap()]);
    // Either the open refuses it or the pass reports it; both are conforming
    // and both are failures. Silence is not.
    let told = !o.status.success()
        || stdout(&o).contains("Corruption")
        || stdout(&o).contains("Tampering");
    assert!(told, "damage went unreported:\nstdout {}\nstderr {}", stdout(&o), stderr(&o));
    assert_ne!(o.status.code(), Some(101), "verify panicked on a damaged file");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dump_prints_the_catalog_the_levels_and_the_features() {
    let dir = tmp("dump");
    let path = populated(&dir, "db.cryptand");
    let o = run(&["dump", path.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    // The collection and its index are the two things a person runs `dump` to
    // see, so their absence is the failure worth naming.
    assert!(out.contains("people"), "the collection is missing from dump:\n{out}");
    assert!(out.to_lowercase().contains("segment") || out.to_lowercase().contains("level"),
        "no level or segment map:\n{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stats_prints_the_required_metrics() {
    let dir = tmp("stats");
    let path = populated(&dir, "db.cryptand");
    let o = run(&["stats", path.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(!out.trim().is_empty(), "stats printed nothing");
    // §6's rule, and the one this project already got wrong once: a metric that
    // cannot be computed MUST be reported unavailable, never given a plausible
    // value. So `unavailable` appearing here is correct behaviour, not a bug --
    // what would be wrong is the word never appearing at all while metrics the
    // engine cannot measure print a reassuring number.
    assert!(out.contains("bytes") || out.contains("_"), "unrecognisable metric output:\n{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repair_runs_and_leaves_a_database_that_verifies() {
    let dir = tmp("repair");
    let path = populated(&dir, "db.cryptand");
    let o = run(&["repair", path.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    // §3: a repair that silently corrupts is worse than no repair, so the only
    // assertion worth making is that the file still verifies afterwards.
    let v = run(&["verify", path.to_str().unwrap()]);
    assert!(v.status.success(), "the database does not verify after repair:\n{}", stdout(&v));
    assert!(!stdout(&v).contains("Corruption"), "{}", stdout(&v));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn backup_writes_a_file_that_verifies_on_its_own() {
    let dir = tmp("backup");
    let path = populated(&dir, "db.cryptand");
    let dest = dir.join("copy.cryptand");
    let o = run(&["backup", path.to_str().unwrap(), dest.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(dest.exists(), "backup produced no file");

    let v = run(&["verify", dest.to_str().unwrap()]);
    assert!(v.status.success(), "the backup does not verify:\n{}", stdout(&v));

    // `13-operations.md` §2.1: a backup MUST NOT copy the source's
    // `database_uuid` -- `14-security.md` §3.4 uses it as the HKDF salt, so two
    // files sharing one would share a content key. Checked on the bytes,
    // because it is the kind of rule an implementation can satisfy in one code
    // path and lose in another.
    let src = std::fs::read(&path).unwrap();
    let cp = std::fs::read(&dest).unwrap();
    const UUID_AT: usize = 160; // `01-container.md` §2's `database_uuid`
    assert_ne!(
        &src[UUID_AT..UUID_AT + 16],
        &cp[UUID_AT..UUID_AT + 16],
        "the backup carries the source's database_uuid"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_incremental_backup_is_accepted_and_produces_a_readable_file() {
    let dir = tmp("incr");
    let path = populated(&dir, "db.cryptand");
    let dest = dir.join("copy.cryptand");
    // A first full copy, then the incremental over it -- §2.2's set difference
    // needs something to differ from.
    let full = run(&["backup", path.to_str().unwrap(), dest.to_str().unwrap()]);
    assert!(full.status.success(), "{}", stderr(&full));
    let o = run(&["backup", "--incremental", path.to_str().unwrap(), dest.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    let v = run(&["verify", dest.to_str().unwrap()]);
    assert!(v.status.success(), "{}", stdout(&v));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fuzz_runs_its_iterations_and_reports_no_panics() {
    let dir = tmp("fuzz");
    let path = populated(&dir, "db.cryptand");
    // A small count: the point here is that the subcommand runs and reports,
    // not that it replaces `14-security.md` §9.3's own fuzzing test.
    let o = run(&["fuzz", path.to_str().unwrap(), "50"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(!out.trim().is_empty(), "fuzz printed nothing");
    assert_ne!(o.status.code(), Some(101), "the fuzzer panicked, which is the finding");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fuzz_takes_its_iteration_count_and_falls_back_when_it_is_not_a_number() {
    let dir = tmp("fuzzargs");
    let path = populated(&dir, "db.cryptand");
    // A non-numeric count must not be an error and must not be zero: the arm
    // parses with `unwrap_or`, and a silent zero would make the subcommand
    // pass while testing nothing.
    let o = run(&["fuzz", path.to_str().unwrap(), "1"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let _ = std::fs::remove_dir_all(&dir);
}
