//! A reading **process** for `13-operations.md` §8. The tests spawn several of
//! these; there is no other way to exercise a protocol whose whole subject is
//! coordination between processes.
//!
//!     mp_reader <sidecar> <commit_id> <hold_ms> [--no-heartbeat]

use cryptand_write::multiproc::{attach, now_ms, ReaderMode, Sidecar, DEFAULT_READER_HEARTBEAT_MS};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = std::path::PathBuf::from(&args[1]);
    let commit_id: u64 = args[2].parse().unwrap();
    let hold_ms: u64 = args[3].parse().unwrap();
    let beat = !args.iter().any(|a| a == "--no-heartbeat");
    let interval = args
        .iter()
        .position(|a| a == "--interval")
        .map(|i| args[i + 1].parse().unwrap())
        .unwrap_or(DEFAULT_READER_HEARTBEAT_MS);

    let sidecar = Sidecar::open(&path, interval).expect("the writer created the sidecar");
    let mode = attach(&sidecar, commit_id, now_ms()).expect("attach");
    match mode {
        ReaderMode::Slotted(slot) => println!("mode=slotted index={} pid={}", slot.index, slot.pid),
        // §8 rule 4: a volatile reader MUST report that it is in volatile mode.
        ReaderMode::Volatile(why) => println!("mode=volatile reason={why:?}"),
    }
    if !sidecar.writer_alive(now_ms()).unwrap() {
        // Nothing will reclaim extents, and nothing will reclaim slots either.
        println!("writer=absent");
    }
    let started = std::time::Instant::now();
    while started.elapsed().as_millis() < hold_ms as u128 {
        std::thread::sleep(std::time::Duration::from_millis(interval / 4));
        if let ReaderMode::Slotted(slot) = mode {
            if beat && !sidecar.heartbeat(&slot, now_ms()).unwrap() {
                // Rule 3: the slot was reclaimed. A reader MUST reopen rather
                // than continue against possibly-freed extents.
                println!("reclaimed");
                return;
            }
        }
    }
    if let ReaderMode::Slotted(slot) = mode {
        sidecar.release(&slot).unwrap();
    }
    println!("released");
}
