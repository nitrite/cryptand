//! PLAN 4.7: files the engine creates are owner-only; the lock sidecar never
//! follows a symlink.
#![cfg(unix)]

mod support;

use std::os::unix::fs::PermissionsExt;

use cryptand::container::Profile;
use cryptand::engine::Engine;
use cryptand::multiproc::{sidecar_path, Sidecar};
use support::TempDb;

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn created_files_are_owner_only() {
    let t = TempDb::new("perm-create");
    drop(Engine::create(&t.path, Profile::Desktop).unwrap());
    assert_eq!(mode(&t.path), 0o600);

    let side = sidecar_path(&t.path);
    drop(Sidecar::create(&side, 2, 2000).unwrap());
    assert_eq!(mode(&side), 0o600);

    // fs::copy carries the source's mode; restore must not.
    std::fs::set_permissions(&t.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let dest = TempDb::new("perm-restore");
    cryptand::backup::restore(&t.path, &dest.path, None).unwrap();
    assert_eq!(mode(&dest.path), 0o600);
}

#[test]
fn sidecar_refuses_a_symlink() {
    let t = TempDb::new("perm-link");
    let victim = TempDb::new("perm-victim");
    std::fs::write(&victim.path, b"keep").unwrap();
    let side = sidecar_path(&t.path);
    std::os::unix::fs::symlink(&victim.path, &side).unwrap();
    assert!(Sidecar::create(&side, 2, 2000).is_err());
    assert!(Sidecar::open(&side, 2000).is_err());
    assert_eq!(std::fs::read(&victim.path).unwrap(), b"keep");
    std::fs::remove_file(&side).unwrap();
}
