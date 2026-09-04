//! `11-conformance.md` §6's round-trip gate, run from `cargo test`.
//!
//! The Dart half needs a `dart` on PATH and the reference Dart implementation
//! beside this one; when either is missing the test reports that it skipped and
//! why, rather than passing silently. **A test that quietly does nothing is
//! worse than a missing one** — this file's whole subject is a claim that only
//! a second implementation can check.
//!
//! `reference/conformance/interop/run.sh` is the same gate as a script, for CI
//! and for running it by hand.

mod support;
use support::TempDb;

use std::path::{Path, PathBuf};
use std::process::Command;

fn reference_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn dart_dir() -> PathBuf {
    reference_root().join("dart/cryptand")
}

fn have_dart() -> bool {
    dart_dir().join("tool/interop.dart").exists()
        && Command::new("dart").arg("--version").output().is_ok()
}

fn rust_interop() -> PathBuf {
    // The test binary lives in target/<profile>/deps; the interop binary is two
    // directories up.
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("interop");
    p
}

fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{what} failed: {}\n{stdout}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn rust(args: &[&str]) -> String {
    let bin = rust_interop();
    assert!(bin.exists(), "build the interop binary first: cargo build --bin interop");
    run(Command::new(&bin).args(args), &format!("rust {}", args[0]))
}

fn dart(args: &[&str]) -> String {
    let mut c = Command::new("dart");
    c.arg("run").arg("tool/interop.dart").args(args).current_dir(dart_dir());
    run(&mut c, &format!("dart {}", args[0]))
}

fn field(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key} in:\n{out}"))
        .to_string()
}

/// One direction of §6's gate: A writes, B reads and verifies, B mutates, A
/// reads back, A mutates, both agree.
fn round_trip(a: fn(&[&str]) -> String, an: &str, b: fn(&[&str]) -> String, bn: &str) {
    let t = TempDb::new(&format!("interop-{an}-{bn}"));
    let p = t.path.to_str().unwrap();

    a(&["write", p]);
    let produced = a(&["read", p]);
    let d0 = field(&produced, "digest");

    let seen = b(&["read", p]);
    assert_eq!(field(&seen, "digest"), d0, "{bn} read a different digest from {an}'s file");
    assert_eq!(field(&seen, "docs"), field(&produced, "docs"));
    assert_eq!(field(&seen, "dict"), field(&produced, "dict"), "the name dictionary differs");
    assert_eq!(field(&seen, "index_de"), field(&produced, "index_de"), "the index answers differently");
    assert_eq!(field(&seen, "page_size"), field(&produced, "page_size"));
    // `writer_id` is what `05-catalog.md` §7 calls "the first thing to look at
    // when a file misbehaves", so the reader must see who wrote it.
    assert_eq!(field(&seen, "writer"), field(&produced, "writer"));

    b(&["mutate", p, bn]);
    let after = b(&["read", p]);
    let d1 = field(&after, "digest");
    assert_ne!(d1, d0, "the mutation changed nothing, so the round trip proves nothing");

    let back = a(&["read", p]);
    assert_eq!(field(&back, "digest"), d1, "{an} did not read back what {bn} wrote");
    assert_eq!(
        field(&back, "dict"),
        field(&after, "dict"),
        "the field name {bn} added is not visible to {an}"
    );

    a(&["mutate", p, an]);
    let final_a = a(&["read", p]);
    let final_b = b(&["read", p]);
    assert_eq!(
        field(&final_a, "digest"),
        field(&final_b, "digest"),
        "after mutations by both, they disagree"
    );
}

#[test]
fn a_file_written_in_rust_is_read_mutated_and_returned_by_dart() {
    if !have_dart() {
        println!(
            "SKIPPED: no dart toolchain or no {}. The Rust half of the gate cannot check \
             portability on its own; run reference/conformance/interop/run.sh where dart exists.",
            dart_dir().join("tool/interop.dart").display()
        );
        return;
    }
    round_trip(rust, "rust", dart, "dart");
}

#[test]
fn a_file_written_in_dart_is_read_mutated_and_returned_by_rust() {
    if !have_dart() {
        println!("SKIPPED: no dart toolchain");
        return;
    }
    round_trip(dart, "dart", rust, "rust");
}

/// The digest is only evidence if both sides compute it the same way over the
/// same fixture, so it is checked against a value neither can change alone.
#[test]
fn both_implementations_produce_the_same_fixture_digest() {
    let t = TempDb::new("interop-fixture");
    let p = t.path.to_str().unwrap();
    rust(&["write", p]);
    let d = field(&rust(&["read", p]), "digest");
    assert_eq!(
        d, "cf3da902",
        "the fixture digest moved; if that was deliberate, update both halves and this constant"
    );
    if have_dart() {
        let t2 = TempDb::new("interop-fixture-dart");
        let p2 = t2.path.to_str().unwrap();
        dart(&["write", p2]);
        assert_eq!(field(&dart(&["read", p2]), "digest"), d);
    }
}
