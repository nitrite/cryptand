//! `13-operations.md` §8, PLAN A1.5: readers in other processes. The reader is
//! this test binary re-run as `mp_child` with `CRYPTAND_MP_CHILD` set.

mod support;
use support::*;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::multiproc::{ReaderMode, Sidecar, VolatileReason, DEFAULT_READER_HEARTBEAT_MS, STALE_MULTIPLIER};
use cryptand::spaceapi::SpaceApi;
use cryptand::value::Value;

const ROWS: i64 = 5_000;
const TREE: u32 = 16;

/// A process for §8 tests, here and across languages
/// (`reference/conformance/interop/multiproc.py`); a no-op in a normal run.
/// `CRYPTAND_MP_ROLE=writer`: create, populate, print `ready`; on a line,
/// churn and print the floor; on a line, close. Otherwise a reader: print the
/// mode; on a line, scan and print rows/bad; on a line, exit.
#[test]
fn mp_child() {
    let Some(path) = std::env::var_os("CRYPTAND_MP_CHILD") else { return };
    let mut line = String::new();
    if std::env::var("CRYPTAND_MP_ROLE").as_deref() == Ok("writer") {
        let mut e = Engine::create(Path::new(&path), Profile::Desktop).unwrap();
        populate(&mut e);
        println!("ready commit={}", e.sb.commit_id);
        std::io::stdin().read_line(&mut line).unwrap();
        churn(&mut e);
        println!("churned floor={}", e.sb.min_retained_commit);
        std::io::stdin().read_line(&mut line).unwrap();
        e.close(true).unwrap();
        return;
    }
    let mut e = Engine::open_read_only(Path::new(&path), None).unwrap();
    match e.multiproc().unwrap().reader_mode().unwrap() {
        ReaderMode::Slotted(s) => println!("mode=slotted index={} commit={}", s.index, s.commit_id),
        ReaderMode::Volatile(why) => println!("mode=volatile reason={why:?}"),
    }
    std::io::stdin().read_line(&mut line).unwrap();
    match e.scan_tree(TREE, None, None, None, true) {
        Ok(rows) => {
            let bad = rows.iter().filter(|(_, v)| *v != vec![1u8; 200]).count();
            println!("rows={} bad={bad}", rows.len());
        }
        Err(err) => println!("error={err}"),
    }
    line.clear();
    std::io::stdin().read_line(&mut line).unwrap();
}

struct Reader {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Reader {
    fn spawn(db: &Path) -> Reader {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["mp_child", "--exact", "--nocapture", "--test-threads=1"])
            .env("CRYPTAND_MP_CHILD", db)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Reader { child, stdin, out }
    }

    /// The next line the child itself printed (skipping libtest's).
    fn line(&mut self, prefix: &str) -> String {
        loop {
            let mut l = String::new();
            assert!(self.out.read_line(&mut l).unwrap() > 0, "reader exited before `{prefix}`");
            if let Some(i) = l.find(prefix) {
                return l[i..].trim().to_string();
            }
        }
    }

    fn go(&mut self) {
        self.stdin.write_all(b"go\n").unwrap();
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn populated(tag: &str) -> (TempDb, Engine) {
    let (t, mut e) = engine(tag, Profile::Desktop);
    populate(&mut e);
    (t, e)
}

fn populate(e: &mut Engine) {
    for i in 0..ROWS {
        e.put(TREE, &Value::NitriteId(i), &[1u8; 200]).unwrap();
    }
    e.flush().unwrap();
    e.commit(Durability::Sync).unwrap();
}

/// Overwrite every row, compact and shrink, committing throughout: every
/// extent of the reader's snapshot is freed and, unpinned, reused.
fn churn(e: &mut Engine) {
    for round in 2..6u8 {
        for i in 0..ROWS {
            e.put(TREE, &Value::NitriteId(i), &[round; 200]).unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        e.compact().unwrap();
        e.commit(Durability::Sync).unwrap();
    }
    e.shrink().unwrap();
    e.commit(Durability::Sync).unwrap();
}

#[test]
fn a_pinned_reader_process_scans_its_snapshot_while_the_writer_reclaims() {
    let (t, mut e) = populated("mp-pin");
    let pinned = e.sb.commit_id;
    let mut r = Reader::spawn(&t.path);
    let mode = r.line("mode=");
    assert!(mode.starts_with("mode=slotted"), "{mode}");
    assert!(mode.ends_with(&format!("commit={pinned}")), "{mode}");
    churn(&mut e);
    assert!(e.sb.min_retained_commit < pinned, "the live slot must hold the floor below {pinned}");
    r.go();
    assert_eq!(r.line("rows="), format!("rows={ROWS} bad=0"));
    e.close(true).unwrap();
}

#[test]
fn a_killed_readers_slot_is_reclaimed_after_three_heartbeats() {
    let (t, mut e) = populated("mp-kill");
    let pinned = e.sb.commit_id;
    let mut r = Reader::spawn(&t.path);
    assert!(r.line("mode=").starts_with("mode=slotted"));
    r.child.kill().unwrap();
    r.child.wait().unwrap();
    e.commit(Durability::Sync).unwrap();
    assert!(e.sb.min_retained_commit < pinned, "a fresh dead slot still pins");
    std::thread::sleep(std::time::Duration::from_millis(STALE_MULTIPLIER * DEFAULT_READER_HEARTBEAT_MS + 500));
    e.commit(Durability::Sync).unwrap();
    assert!(e.sb.min_retained_commit >= pinned, "floor {} still pinned", e.sb.min_retained_commit);
    let sc = Sidecar::open_reader(&t.path, DEFAULT_READER_HEARTBEAT_MS).unwrap().unwrap();
    assert!(sc.slots().unwrap().iter().all(|s| s.is_free()));
    e.close(true).unwrap();
}

#[test]
fn racing_reader_processes_claim_distinct_slots() {
    let (t, mut e) = populated("mp-race");
    let mut readers: Vec<Reader> = (0..8).map(|_| Reader::spawn(&t.path)).collect();
    let mut idx: Vec<String> = readers
        .iter_mut()
        .map(|r| {
            r.line("mode=slotted").split(' ').nth(1).unwrap().to_string()
        })
        .collect();
    idx.sort();
    idx.dedup();
    assert_eq!(idx.len(), 8, "{idx:?}");
    e.close(true).unwrap();
}

#[test]
fn two_readers_in_one_process_keep_their_own_slots() {
    // §8: a slot is a reader's while pid AND commit_id match.
    let (t, mut e) = populated("mp-same-pid");
    let a = Engine::open_read_only(&t.path, None).unwrap();
    e.put(TREE, &Value::NitriteId(0), &[9u8; 200]).unwrap();
    e.commit(Durability::Sync).unwrap();
    let b = Engine::open_read_only(&t.path, None).unwrap();
    let live = |n: usize| {
        let sc = Sidecar::open_reader(&t.path, DEFAULT_READER_HEARTBEAT_MS).unwrap().unwrap();
        assert_eq!(sc.slots().unwrap().iter().filter(|s| !s.is_free()).count(), n);
    };
    live(2);
    drop(a);
    live(1);
    let Some(ReaderMode::Slotted(slot)) = b.multiproc().unwrap().reader_mode() else { panic!() };
    assert_eq!(slot.commit_id, e.sb.commit_id);
    drop(b);
    live(0);
    e.close(true).unwrap();
    // Closed: no live writer, rule 5.
    let sc = Sidecar::open_reader(&t.path, DEFAULT_READER_HEARTBEAT_MS).unwrap().unwrap();
    assert_eq!(sc.writer_pid().unwrap(), 0);
}

#[test]
fn a_full_sidecar_opens_volatile_and_says_why() {
    let (t, mut e) = populated("mp-full");
    let held: Vec<Engine> = (0..64).map(|_| Engine::open_read_only(&t.path, None).unwrap()).collect();
    let mut v = Engine::open_read_only(&t.path, None).unwrap();
    assert_eq!(v.multiproc().unwrap().reader_mode(), Some(ReaderMode::Volatile(VolatileReason::SidecarFull)));
    // Rule 4: revalidated before each operation; fine while nothing moved past it.
    assert_eq!(v.scan_tree(TREE, None, None, None, true).unwrap().len(), ROWS as usize);
    drop(held);
    churn(&mut e);
    assert!(v.scan_tree(TREE, None, None, None, true).is_err(), "volatile reader read reclaimed pages");
    e.close(true).unwrap();
}

#[cfg(unix)]
#[test]
fn a_read_only_sidecar_opens_volatile_and_says_why() {
    use std::os::unix::fs::PermissionsExt;
    let (t, mut e) = populated("mp-ro");
    e.close(true).unwrap();
    let lock = cryptand::multiproc::sidecar_path(&t.path);
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o400)).unwrap();
    let r = Engine::open_read_only(&t.path, None).unwrap();
    assert_eq!(r.multiproc().unwrap().reader_mode(), Some(ReaderMode::Volatile(VolatileReason::SidecarReadOnly)));
    assert!(!r.multiproc().unwrap().writer_alive());
}

#[test]
fn a_reader_with_no_sidecar_creates_one_with_no_writer() {
    let (t, mut e) = populated("mp-none");
    e.close(true).unwrap();
    std::fs::remove_file(cryptand::multiproc::sidecar_path(&t.path)).unwrap();
    let r = Engine::open_read_only(&t.path, None).unwrap();
    assert!(matches!(r.multiproc().unwrap().reader_mode(), Some(ReaderMode::Slotted(_))));
    assert!(!r.multiproc().unwrap().writer_alive());
}
