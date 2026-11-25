//! F-226: a compaction reuses one output buffer. A fresh output-sized Vec per
//! output, freed after its write, was kept resident by macOS malloc's large-block
//! cache (soak RSS 1.3 GB on a ~200 MB live heap). Own file: it needs its own
//! global allocator.
mod support;
use support::*;

use cryptand::container::{Durability, Profile};
use cryptand::engine::Engine;
use cryptand::value::Value;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

static ON: AtomicBool = AtomicBool::new(false);
static BIG: AtomicUsize = AtomicUsize::new(0);
struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() >= 1 << 20 && ON.load(Relaxed) {
            BIG.fetch_add(1, Relaxed);
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Counting = Counting;

#[test]
fn f226_compaction_outputs_share_one_buffer() {
    let t = TempDb::new("f226");
    let mut e = Engine::create(&t.path, Profile::Mobile).unwrap(); // 2 MiB outputs
    let doc = vec![7u8; 900];
    for round in 0..2u8 {
        for i in 0..14_000i64 {
            e.put(16, &Value::NitriteId(i), &[&doc[..], &[round]].concat()).unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Os).unwrap();
    }
    ON.store(true, Relaxed);
    e.compact().unwrap();
    ON.store(false, Relaxed);
    let big = BIG.load(Relaxed);
    assert!(big <= 3, "{big} allocations of >= 1 MiB in one compaction of ~20 outputs");
}
