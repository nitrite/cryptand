//! `13-operations.md` §8 — multi-process readers. The parts that need separate
//! processes are run with separate processes; the rest is in-process because it
//! is about the protocol's arithmetic, not its concurrency.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use cryptand_write::multiproc::{
    attach, sidecar_path, ReaderMode, Sidecar, VolatileReason, DEFAULT_READER_HEARTBEAT_MS,
    STALE_MULTIPLIER,
};

const INTERVAL: u64 = 200;

struct Dir(std::path::PathBuf);

impl Dir {
    fn new() -> Dir {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "cryptand-mp-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("db.cryptand")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn writer(dir: &Dir, slots: u32) -> Sidecar {
    Sidecar::create(&sidecar_path(&dir.db()), slots, INTERVAL).unwrap()
}

fn reader(dir: &Dir) -> Sidecar {
    Sidecar::open(&sidecar_path(&dir.db()), INTERVAL).unwrap()
}

// ---------------------------------------------------------------------------
// The arithmetic: rules 1, 2 and 3
// ---------------------------------------------------------------------------

#[test]
fn a_live_slot_pins_the_writers_retention_floor() {
    let dir = Dir::new();
    let sc = writer(&dir, 8);
    let now = 10_000;
    // Rule 2: the minimum over the writer's own snapshots AND every live slot.
    assert_eq!(sc.min_retained_commit(500, now).unwrap(), 500, "no readers, no pin");
    let a = sc.claim(300, now).unwrap().unwrap();
    let b = sc.claim(700, now).unwrap().unwrap();
    assert_ne!(a.index, b.index);
    assert_eq!(sc.min_retained_commit(500, now).unwrap(), 300, "the oldest reader is the floor");
    sc.release(&a).unwrap();
    assert_eq!(sc.min_retained_commit(500, now).unwrap(), 500, "releasing lifts the floor");
    sc.release(&b).unwrap();
    assert!(sc.slots().unwrap().iter().all(|s| s.is_free()));
}

#[test]
fn a_stale_slot_stops_pinning_and_is_reclaimed() {
    let dir = Dir::new();
    let sc = writer(&dir, 4);
    let claimed_at = 10_000;
    let slot = sc.claim(300, claimed_at).unwrap().unwrap();

    let still_fresh = claimed_at + STALE_MULTIPLIER * INTERVAL;
    assert_eq!(sc.min_retained_commit(500, still_fresh).unwrap(), 300);
    assert!(sc.reclaim_stale(still_fresh).unwrap().is_empty());

    let aged_out = still_fresh + 1;
    // A crashed reader must not hold the file's space forever: rule 3 says the
    // slot is reclaimable, so rule 2's floor stops honouring it.
    assert_eq!(sc.min_retained_commit(500, aged_out).unwrap(), 500);
    assert_eq!(sc.reclaim_stale(aged_out).unwrap(), vec![slot.index]);
    assert!(sc.read_slot(slot.index).unwrap().is_free());
}

#[test]
fn a_reader_learns_from_its_own_heartbeat_that_its_slot_was_reclaimed() {
    let dir = Dir::new();
    let sc = writer(&dir, 4);
    let slot = sc.claim(300, 10_000).unwrap().unwrap();
    assert!(sc.heartbeat(&slot, 10_100).unwrap(), "a live slot refreshes");

    sc.reclaim_stale(10_100 + STALE_MULTIPLIER * INTERVAL + 1).unwrap();
    assert!(
        !sc.heartbeat(&slot, 99_999).unwrap(),
        "rule 3: the reader MUST detect the reclaim -- its own pid is no longer present"
    );
    // And a refused heartbeat must not resurrect the slot behind the writer.
    assert!(sc.read_slot(slot.index).unwrap().is_free());
}

#[test]
fn a_claimer_reuses_a_stale_slot() {
    let dir = Dir::new();
    let sc = writer(&dir, 1);
    let first = sc.claim(300, 10_000).unwrap().unwrap();
    assert!(sc.claim(400, 10_000).unwrap().is_none(), "the only slot is taken");
    let after = 10_000 + STALE_MULTIPLIER * INTERVAL + 1;
    let second = sc.claim(400, after).unwrap().expect("a stale slot is a free slot");
    assert_eq!(second.index, first.index);
    assert_eq!(sc.min_retained_commit(500, after).unwrap(), 400);
}

// ---------------------------------------------------------------------------
// Rule 4: volatile mode
// ---------------------------------------------------------------------------

#[test]
fn a_full_sidecar_falls_back_to_volatile_and_pins_nothing() {
    let dir = Dir::new();
    let sc = writer(&dir, 1);
    let held = sc.claim(300, 10_000).unwrap().unwrap();
    let mode = attach(&sc, 250, 10_000).unwrap();
    assert_eq!(mode, ReaderMode::Volatile(VolatileReason::SidecarFull));
    assert!(mode.must_revalidate_superblock());
    assert_eq!(
        sc.min_retained_commit(500, 10_000).unwrap(),
        300,
        "the volatile reader's 250 pins nothing"
    );
    sc.release(&held).unwrap();
}

#[test]
fn a_read_only_sidecar_opens_volatile_and_says_so() {
    let dir = Dir::new();
    let path = sidecar_path(&dir.db());
    {
        let _ = writer(&dir, 4);
    }
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).unwrap();

    let sc = Sidecar::open(&path, INTERVAL).unwrap();
    let mode = attach(&sc, 250, 10_000).unwrap();
    assert_eq!(
        mode,
        ReaderMode::Volatile(VolatileReason::SidecarReadOnly),
        "a reader that cannot write the sidecar is volatile, and says which kind"
    );
    assert!(mode.is_volatile() && mode.must_revalidate_superblock());
    assert!(sc.slots().unwrap().iter().all(|s| s.is_free()), "and it wrote nothing");

    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(false);
    std::fs::set_permissions(&path, perms).unwrap();
}

// ---------------------------------------------------------------------------
// The part that needs processes
// ---------------------------------------------------------------------------

fn spawn_reader(dir: &Dir, commit_id: u64, hold_ms: u64, extra: &[&str]) -> (Child, BufReader<std::process::ChildStdout>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mp_reader"));
    cmd.arg(sidecar_path(&dir.db()))
        .arg(commit_id.to_string())
        .arg(hold_ms.to_string())
        .arg("--interval")
        .arg(INTERVAL.to_string())
        .args(extra)
        .stdout(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn a reader process");
    let out = BufReader::new(child.stdout.take().unwrap());
    (child, out)
}

fn line(out: &mut BufReader<std::process::ChildStdout>) -> String {
    let mut s = String::new();
    out.read_line(&mut s).unwrap();
    s.trim().to_string()
}

#[test]
fn separate_processes_claim_distinct_slots_and_pin_the_retention_floor() {
    let dir = Dir::new();
    let sc = writer(&dir, 8);
    let commits = [900u64, 400, 1200];
    let mut children = Vec::new();
    let mut indices = Vec::new();
    for c in commits {
        let (child, mut out) = spawn_reader(&dir, c, 3_000, &[]);
        let first = line(&mut out);
        assert!(first.starts_with("mode=slotted"), "got {first:?}");
        indices.push(first.split("index=").nth(1).unwrap().split(' ').next().unwrap().to_string());
        children.push((child, out));
    }
    let mut sorted = indices.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), commits.len(), "two processes claimed the same slot");

    let now = cryptand_write::multiproc::now_ms();
    let live: Vec<_> = sc.slots().unwrap().into_iter().filter(|s| !s.is_free()).collect();
    assert_eq!(live.len(), 3);
    assert!(live.iter().all(|s| s.pid != std::process::id() as u64), "the readers are other processes");
    // Rule 2, across process boundaries: the writer's floor is the oldest
    // commit any reader pinned, not its own.
    assert_eq!(sc.min_retained_commit(5_000, now).unwrap(), 400);

    for (mut child, mut out) in children {
        assert_eq!(line(&mut out), "released");
        assert!(child.wait().unwrap().success());
    }
    assert!(
        sc.slots().unwrap().iter().all(|s| s.is_free()),
        "every reader released its slot on exit"
    );
    assert_eq!(sc.min_retained_commit(5_000, cryptand_write::multiproc::now_ms()).unwrap(), 5_000);
}

#[test]
fn a_reader_process_that_stops_beating_is_reclaimed_and_the_floor_lifts() {
    let dir = Dir::new();
    let sc = writer(&dir, 4);
    // This reader claims a slot and then never refreshes it -- a crashed or
    // wedged process, which is the realistic failure mode.
    let (mut child, mut out) = spawn_reader(&dir, 100, 5_000, &["--no-heartbeat"]);
    assert!(line(&mut out).starts_with("mode=slotted"));

    let now = cryptand_write::multiproc::now_ms();
    assert_eq!(sc.min_retained_commit(5_000, now).unwrap(), 100, "while it is fresh, it pins");

    std::thread::sleep(std::time::Duration::from_millis(STALE_MULTIPLIER * INTERVAL + 300));
    let later = cryptand_write::multiproc::now_ms();
    assert_eq!(sc.min_retained_commit(5_000, later).unwrap(), 5_000, "a silent reader stops pinning");
    assert_eq!(sc.reclaim_stale(later).unwrap().len(), 1);

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn racing_processes_never_double_claim_a_slot() {
    let dir = Dir::new();
    let slots = 12u32;
    let sc = writer(&dir, slots);
    let mut children = Vec::new();
    for i in 0..slots {
        children.push(spawn_reader(&dir, 1_000 + i as u64, 2_000, &[]));
    }
    let mut claimed = Vec::new();
    for (_, out) in children.iter_mut() {
        let l = line(out);
        assert!(l.starts_with("mode=slotted"), "the sidecar has a slot for each: {l:?}");
        claimed.push(l.split("index=").nth(1).unwrap().split(' ').next().unwrap().to_string());
    }
    let mut sorted = claimed.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        slots as usize,
        "{slots} processes racing produced {} distinct slots",
        sorted.len()
    );
    for (mut child, _) in children {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn the_default_heartbeat_interval_is_the_one_the_chapter_names() {
    assert_eq!(DEFAULT_READER_HEARTBEAT_MS, 2000);
    assert_eq!(STALE_MULTIPLIER, 3);
}

// ---------------------------------------------------------------------------
// The header fields no rule used, and the failure that follows from that
// ---------------------------------------------------------------------------

#[test]
fn a_dead_writer_is_visible_to_a_reader() {
    let dir = Dir::new();
    let sc = writer(&dir, 4);
    let now = cryptand_write::multiproc::now_ms();
    assert!(sc.writer_alive(now).unwrap(), "the process that created it is the writer");
    assert_eq!(sc.writer_pid().unwrap(), std::process::id() as u64);
    // The header's two fields exist for exactly this question, and until it can
    // be asked a reader cannot tell a live database from an abandoned one.
    assert!(!sc.writer_alive(now + STALE_MULTIPLIER * INTERVAL + 1).unwrap());
    sc.refresh_writer(now + STALE_MULTIPLIER * INTERVAL + 1).unwrap();
    assert!(sc.writer_alive(now + STALE_MULTIPLIER * INTERVAL + 1).unwrap());
}

#[test]
fn with_no_live_writer_a_claimer_still_recycles_dead_slots() {
    // The failure this prevents: rule 3 attributes reclamation to the writer.
    // With the writer gone, nothing reclaims, the sidecar fills with dead
    // readers, and every later reader silently degrades to volatile mode --
    // a downgrade rule 4 requires be reported, arriving for a reason the
    // reader cannot see.
    let dir = Dir::new();
    let sc = writer(&dir, 2);
    let t0 = 10_000;
    let dead_a = sc.claim(100, t0).unwrap().unwrap();
    let dead_b = sc.claim(200, t0).unwrap().unwrap();
    assert!(attach(&sc, 300, t0).unwrap().is_volatile(), "full while both are fresh");

    let later = t0 + STALE_MULTIPLIER * INTERVAL + 1;
    // No writer runs reclaim_stale here -- this is the abandoned-database case.
    let fresh = attach(&sc, 300, later).unwrap();
    assert_eq!(
        fresh,
        ReaderMode::Slotted(cryptand_write::multiproc::ReaderSlot {
            index: dead_a.index,
            pid: std::process::id() as u64,
            commit_id: 300
        }),
        "a claimer treats a stale slot as free, so a dead writer cannot strand every reader"
    );
    assert_ne!(dead_b.index, dead_a.index);
}
