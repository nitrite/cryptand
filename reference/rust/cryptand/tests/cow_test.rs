//! Copy-on-write tree page accounting.

use std::collections::HashSet;

use cryptand::cow::CowTree;
use cryptand::pager::Pager;

/// F-065: `publish` wrote an emptied node's page before unlinking it, so a
/// remove that emptied a non-root page leaked one page per occurrence.
#[test]
fn every_page_is_reachable_or_freed_also_when_a_leaf_empties() {
    let mut pager = Pager::in_memory(4096);
    let mut t = CowTree::new(2, 0, 0);
    let key = |i: usize| format!("k{i:04}").into_bytes();
    let check = |t: &CowTree, pager: &mut Pager, when: &str| {
        let mut live = Vec::new();
        t.reachable(pager, &mut live).unwrap();
        let mut known: HashSet<u64> = live.into_iter().collect();
        known.extend(t.freed.iter().copied());
        for e in pager.free_list() {
            known.extend(e.start_page..e.start_page + e.pages as u64);
        }
        for p in 2..pager.page_count {
            assert!(known.contains(&p), "page {p} leaked {when}");
        }
    };
    for i in 0..400 {
        t.put(&mut pager, &key(i), &[0u8; 200]).unwrap();
    }
    assert!(t.height(&mut pager).unwrap() > 1);
    check(&t, &mut pager, "after the inserts");
    // In key order, so leaves empty one at a time.
    for i in 0..400 {
        t.remove(&mut pager, &key(i)).unwrap();
        check(&t, &mut pager, &format!("after removing key {i}"));
    }
}

/// F-214: unencrypted, every nonce is 0, so a page the tree wrote, freed and
/// then rebuilt onto (`relocate`, as `shrink` does) kept its old cached node,
/// and `get` read the value from before the rebuild.
#[test]
fn a_rebuild_onto_a_reused_page_reads_the_new_node() {
    let mut pager = Pager::in_memory(4096);
    pager.low_first = true;
    let mut t = CowTree::new(2, 0, 0);
    t.put(&mut pager, b"k", b"old").unwrap();
    t.relocate(&mut pager).unwrap();
    t.put(&mut pager, b"k", b"new").unwrap();
    for p in std::mem::take(&mut t.freed) {
        pager.free_extent(p, 1, 0);
    }
    t.relocate(&mut pager).unwrap();
    assert_eq!(t.get(&mut pager, b"k").unwrap().as_deref(), Some(&b"new"[..]));
}
