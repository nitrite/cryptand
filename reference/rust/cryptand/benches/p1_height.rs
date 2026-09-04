//! **P1 — B+tree height.** `design/performance-model.md` §1 costs the read path
//! against a predicted height; `04-segments.md` §2.2's leaf cell is the term
//! that decides it, and the two bytes §2.2 saves are what put height <= 4 below
//! 619M documents in the Dart reference's measurement.
//!
//! Run: `cargo run --release --bin p1_height [entries]`

#[path = "harness.rs"]
mod harness;
use harness::*;

use cryptand::cke;
use cryptand::segment::{internal_key, op, value_kind, SegEntry, Segment, SegmentBuilder};
use cryptand::value::Value;

fn height_of(seg: &Segment) -> usize {
    let mut h = 1;
    let mut page = seg.header.root_page;
    loop {
        let node = seg.node(page).unwrap();
        if node.is_leaf {
            return h;
        }
        h += 1;
        page = node.child_at(0).unwrap().0;
    }
}

fn main() {
    let n = arg(0, 200_000);
    for page_size in [4096usize, 8192] {
        for pointer in [true, false] {
            let mut b = SegmentBuilder::new(page_size, 1, 0, 0, 0).unwrap();
            for i in 0..n as i64 {
                let cke = cke::encode(&Value::NitriteId(i)).unwrap();
                let (kind, value) = if pointer {
                    (value_kind::VLOG, vec![0u8; 16])
                } else {
                    (value_kind::INLINE, vec![0u8; 100])
                };
                b.add(SegEntry::new(internal_key(16, &cke, i as u64, op::PUT), kind, value)).unwrap();
            }
            let pages = b.page_count();
            let seg = Segment::open(b.build().unwrap(), page_size).unwrap();
            let leaf_bytes = pages as f64 * page_size as f64 / n as f64;
            row(
                &format!(
                    "page {page_size}  {}",
                    if pointer { "separated (16-byte pointer)" } else { "inline 100 B" }
                ),
                format!(
                    "height {}  {pages} pages  {leaf_bytes:.1} B/entry  \
                     {:.0} entries/leaf",
                    height_of(&seg),
                    page_size as f64 / (leaf_bytes.max(1.0))
                ),
            );
        }
    }
    // The height a real database reaches, extrapolated from the measured
    // fan-out rather than from the model's constant.
    let mut b = SegmentBuilder::new(4096, 1, 0, 0, 0).unwrap();
    for i in 0..n as i64 {
        let cke = cke::encode(&Value::NitriteId(i)).unwrap();
        b.add(SegEntry::new(internal_key(16, &cke, i as u64, op::PUT), value_kind::VLOG, vec![0u8; 16]))
            .unwrap();
    }
    let seg = Segment::open(b.build().unwrap(), 4096).unwrap();
    let leaves = {
        let mut count = 0u64;
        let mut stack = vec![seg.header.root_page];
        while let Some(p) = stack.pop() {
            let node = seg.node(p).unwrap();
            if node.is_leaf {
                count += 1;
            } else {
                for i in 0..node.cell_count {
                    stack.push(node.child_at(i).unwrap().0);
                }
            }
        }
        count
    };
    let per_leaf = n as f64 / leaves as f64;
    // The **full** internal fan-out, not the root's: the root of a tree that is
    // not a whole power of the fan-out is underfilled, and extrapolating from
    // it understates the height a real database reaches by an order of
    // magnitude.
    let fanout = {
        let mut best = 1usize;
        let mut stack = vec![seg.header.root_page];
        while let Some(p) = stack.pop() {
            let node = seg.node(p).unwrap();
            if node.is_leaf {
                continue;
            }
            best = best.max(node.cell_count);
            for i in 0..node.cell_count {
                stack.push(node.child_at(i).unwrap().0);
            }
        }
        best as f64
    };
    row("entries per leaf (4 KiB, separated)", format!("{per_leaf:.1}"));
    row("full internal fan-out", format!("{fanout:.0}"));
    for h in 2..=5u32 {
        row(
            &format!("documents reachable at height {h}"),
            format!("{:.3e}", per_leaf * fanout.powi(h as i32 - 1)),
        );
    }
}
