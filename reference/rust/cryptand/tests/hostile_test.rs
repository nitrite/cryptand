//! `14-security.md` §9.1 — a decoder fed a hostile file MUST fail with a typed
//! corruption error "rather than an allocation failure, a panic, an abort, or
//! an unbounded recursion".
//!
//! Every case here is a *file* an attacker can produce, not a synthetic call
//! into a private constructor: the bytes are built by this implementation's own
//! writer, one field is edited, and the page checksum is repaired — which §9.4
//! says is trivially done by anyone who edits the file, so a test that skipped
//! it would be testing the CRC rather than the decoder.

use cryptand::container::{page_type, PageHeader, PAGE_HEADER_BYTES};
use cryptand::cke;
use cryptand::segment::{internal_key, op, value_kind, SegEntry, Segment, SegmentBuilder};
use cryptand::value::Value;

const T: u32 = 16;
const PAGE: usize = 4096;

/// A one-page-filter segment holding `n` keys.
fn segment_with_filter(n: i64) -> Vec<u8> {
    let mut b = SegmentBuilder::new(PAGE, 1, 0, 0, 10).unwrap();
    for i in 0..n {
        let c = cke::encode(&Value::NitriteId(i)).unwrap();
        b.add(SegEntry::new(
            internal_key(T, &c, i as u64 + 1, op::PUT),
            value_kind::INLINE,
            b"v".to_vec(),
        ))
        .unwrap();
    }
    b.build().unwrap()
}

/// Rewrites the u32 at `off` inside the first `SEGMENT_FILTER` page's payload
/// and repairs that page's checksum, leaving a file that passes every check
/// except the one under test.
fn patch_filter_u32(extent: &mut [u8], off: usize, v: u32) {
    let pages = extent.len() / PAGE;
    for p in 0..pages {
        let at = p * PAGE;
        let Ok(h) = PageHeader::parse(&extent[at..at + PAGE]) else { continue };
        if h.page_type != page_type::SEGMENT_FILTER {
            continue;
        }
        let f = at + PAGE_HEADER_BYTES + off;
        extent[f..f + 4].copy_from_slice(&v.to_le_bytes());
        let (head, page) = extent.split_at_mut(at);
        let _ = head;
        h.write_into(&mut page[..PAGE]);
        return;
    }
    panic!("the fixture has no filter page");
}

// ---------------------------------------------------------------------------
// The filter header, `04-segments.md` §2.4
// ---------------------------------------------------------------------------

/// `block_count = 0` divides the filter's block index by nothing: every probe
/// addresses byte 0 of a zero-length block array. Dart and Java both refuse the
/// value at parse; this asserts Rust does too, rather than indexing out of
/// bounds inside `may_contain`.
#[test]
fn a_filter_declaring_zero_blocks_is_refused_and_does_not_panic() {
    let mut e = segment_with_filter(64);
    patch_filter_u32(&mut e, 4, 0);
    let seg = Segment::open(e, PAGE).unwrap();

    let err = match seg.filter() {
        Err(e) => e,
        Ok(_) => panic!("a filter declaring zero blocks was accepted"),
    };
    assert!(
        format!("{err}").contains("block_count"),
        "expected a named block_count error, got {err}"
    );
    // The public probe path must not panic either: it swallows the error and
    // answers "maybe", which is always a sound answer for a Bloom filter.
    let probe = cryptand::filter::user_key_prefix(T, &cke::encode(&Value::NitriteId(1)).unwrap());
    assert!(seg.may_contain(&probe));
}

/// `probes` is read from the file and a reader MUST use the stored value rather
/// than recomputing it, so it is attacker-controlled loop count. §2.4 bounds it
/// at 1..16; Dart and Java enforce that.
#[test]
fn a_filter_declaring_an_out_of_range_probe_count_is_refused() {
    for probes in [0u32, 17, 65535] {
        let mut e = segment_with_filter(64);
        // `probes` is the u16 at payload offset 10; patch the u32 at 8 to keep
        // `bits_per_key` (offset 8, u16) as it was.
        let bits = {
            let seg = Segment::open(segment_with_filter(64), PAGE).unwrap();
            seg.filter().ok().flatten().unwrap().bits_per_key
        };
        patch_filter_u32(&mut e, 8, (bits & 0xFFFF) | (probes << 16));
        let seg = Segment::open(e, PAGE).unwrap();
        let err = match seg.filter() {
            Err(e) => e,
            Ok(_) => panic!("probes={probes} was accepted"),
        };
        assert!(
            format!("{err}").contains("probes"),
            "probes={probes} expected a named probes error, got {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// The exhaustive field-boundary sweep, `14-security.md` §9.1 and §9.3
// ---------------------------------------------------------------------------
//
// §9.3 requires structure-aware fuzzing, and `cryptand fuzz` provides it. What
// random mutation cannot do is *reliably* reach one named 4-byte field: the
// filter's `block_count` is a specific u32 at a specific offset, and a run of
// 3 000 random mutations over this corpus finds it perhaps one time in six.
// That is not a fuzzer to strengthen; it is the wrong instrument for the
// question. Bugs of this class live at the *boundaries* of a named field, and
// the boundaries are enumerable.
//
// So this sweep is deterministic and exhaustive rather than random: for one
// page of every `page_type` present in the file, every u32-aligned slot in the
// 40-byte header and the first 32 bytes of payload is set to each of six
// boundary values, the page checksum is repaired, and the file is opened,
// verified, scanned and point-read.
//
// The contract asserted is exactly §9.1's: a typed error or a clean read.
// Never a panic, never an abort, never an unbounded allocation.

use cryptand::container::{Superblock, PAGE_HEADER_BYTES as PHB};
use cryptand::engine::Engine;
use cryptand::verify::EngineVerify;
use std::path::{Path, PathBuf};

const BOUNDARIES: [u32; 6] = [0, 1, 2, 0x7FFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFFF];

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/files/v1.0-core.cryptand")
}

/// Opens, verifies, scans and point-reads — the four decoders a hostile file
/// reaches. Returns `Err` for any typed refusal, which is a pass.
fn exercise(path: &Path) -> cryptand::Result<()> {
    let mut e = Engine::open(path, None)?;
    e.verify()?;
    let cat = std::mem::replace(&mut e.catalog, cryptand::catalog::Catalog::new(0, 0, 16));
    let all = cat.all(&mut e.pager);
    e.catalog = cat;
    for (_, d) in all.unwrap_or_default() {
        let rows = e.scan_tree(d.tree_id(), None, None, None, true);
        for (k, _) in rows.unwrap_or_default().iter().take(8) {
            if let Ok(v) = cryptand::cke::decode_all(k) {
                let _ = e.get(d.tree_id(), &v);
            }
        }
    }
    Ok(())
}

#[test]
fn every_u32_field_at_every_boundary_yields_a_typed_error_and_never_a_panic() {
    let original = std::fs::read(corpus()).expect("the shared conformance corpus");
    let sb = Superblock::parse(&original[..4096]).expect("slot 0 parses");
    let page_size = sb.page_size();
    let pages = original.len() / page_size;

    // One page of each `page_type` present. The decoder is per type, not per
    // page, so a second page of the same type re-tests the same code.
    let mut by_type: std::collections::BTreeMap<u8, usize> = std::collections::BTreeMap::new();
    for p in 2..pages {
        let at = p * page_size;
        let Ok(h) = PageHeader::parse(&original[at..at + page_size]) else { continue };
        if h.page_type == page_type::FREE {
            continue;
        }
        by_type.entry(h.page_type).or_insert(p);
    }
    assert!(
        by_type.len() >= 4,
        "the corpus should cover several page types, saw {:?}",
        by_type.keys().collect::<Vec<_>>()
    );

    // Every u32-aligned slot in the header, and in the first 32 bytes of
    // payload — where every count and length field of every page type lives.
    let slots: Vec<usize> = (0..PHB / 4).chain(PHB / 4..PHB / 4 + 8).map(|i| i * 4).collect();

    let tmp = std::env::temp_dir().join(format!("cryptand-sweep-{}.cryptand", std::process::id()));
    let (mut cases, mut refused, mut accepted) = (0u32, 0u32, 0u32);

    for (&ptype, &page) in &by_type {
        for &slot in &slots {
            for &value in &BOUNDARIES {
                let mut b = original.clone();
                let at = page * page_size + slot;
                if at + 4 > b.len() {
                    continue;
                }
                b[at..at + 4].copy_from_slice(&value.to_le_bytes());
                // Repair the checksum, so the decoder is what refuses the file
                // and not the CRC — §9.4: an attacker recomputes it trivially.
                let off = page * page_size;
                if let Ok(h) = PageHeader::parse(&b[off..off + page_size]) {
                    let end = PageHeader::checksum_range_end(&b[off..off + page_size], &h);
                    let crc = cryptand::hash::crc32c(&b[off + 4..off + end]);
                    b[off..off + 4].copy_from_slice(&crc.to_le_bytes());
                }
                std::fs::write(&tmp, &b).unwrap();

                cases += 1;
                let outcome = std::panic::catch_unwind(|| exercise(&tmp));
                match outcome {
                    Err(_) => panic!(
                        "page_type {ptype}: setting the u32 at offset {slot} to {value:#010x} \
                         panicked. §9.1 requires a typed corruption error."
                    ),
                    Ok(Err(_)) => refused += 1,
                    Ok(Ok(())) => accepted += 1,
                }
            }
        }
    }
    let _ = std::fs::remove_file(&tmp);

    println!(
        "field-boundary sweep: {cases} cases over {} page types — \
         {refused} refused with a named error, {accepted} read cleanly, 0 panics",
        by_type.len()
    );
    assert!(cases > 200, "the sweep did not run: {cases} cases");
    // A control: if nothing was ever refused, the sweep is not reaching a
    // decoder at all and would pass against a reader that validates nothing.
    assert!(refused > 0, "no mutation was refused — the sweep reaches no decoder");
}

// ---------------------------------------------------------------------------
// `04-segments.md` §2.4 — the filter is decoded once per segment, not per probe
// ---------------------------------------------------------------------------

/// A counter, not a stopwatch. `12-profiles.md` §12 costs a filter probe as
/// "exactly one 64-byte block"; decoding the whole filter payload — twice, into
/// two fresh allocations — on every probe is not that.
///
/// This is the control for that fix. It asserts the *mechanism* rather than a
/// wall time, which is `design/performance-model.md` §8's rule and this
/// project's own history with flaky timing guards: a thousand probes must
/// decode the filter exactly once.
#[test]
fn a_thousand_probes_decode_the_filter_once() {
    let seg = Segment::open(segment_with_filter(2000), PAGE).unwrap();
    assert_eq!(seg.filter_parses.load(std::sync::atomic::Ordering::Relaxed), 0);

    let mut admitted = 0;
    for i in 0..1000i64 {
        let c = cke::encode(&Value::NitriteId(i)).unwrap();
        if seg.may_contain(&cryptand::filter::user_key_prefix(T, &c)) {
            admitted += 1;
        }
    }
    // Every key probed is in the segment, so the filter must admit all of them:
    // a cache that returned the wrong answer would show up here rather than
    // only in the count below.
    assert_eq!(admitted, 1000, "the filter rejected a key it contains");
    assert_eq!(
        seg.filter_parses.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the filter payload was decoded more than once across 1000 probes"
    );
}

/// §1: an internal key is `u32be(tree_id) || CKE(key) || u64be(~seq) || u8 op`,
/// so it is never shorter than 13 bytes and never empty. `prefix_len` and
/// `suffix_len` are both read from the file, so a hostile leaf page can declare
/// a zero-length key — and reading its last byte for the `op` was
///
/// ```text
/// panicked at cryptand/src/segment.rs:380:78:
/// called `Option::unwrap()` on a `None` value
/// ```
///
/// which §9.1 forbids. Found by `cryptand fuzz` only after its oracle learned
/// to do a point read; a scan does not call `record_at`.
#[test]
fn a_leaf_cell_with_an_empty_key_is_refused_and_does_not_panic() {
    use cryptand::segment::{encode_node_page, Node};

    for key in [Vec::<u8>::new(), vec![0u8; 12]] {
        let page = encode_node_page(
            PAGE,
            PAGE - cryptand::container::PAGE_HEADER_BYTES,
            true,
            &[key.clone()],
            &[vec![value_kind::INLINE, 1, b'v']],
            1,
            T,
            1,
        )
        .unwrap();
        let node = Node::parse(&page, 0).unwrap();
        let err = match node.record_at(0) {
            Err(e) => e,
            Ok(_) => panic!("a {}-byte internal key was accepted", key.len()),
        };
        assert!(
            format!("{err}").contains("internal key shorter than 13 bytes"),
            "expected the 13-byte minimum to be named, got {err}"
        );
    }
}

/// F-041: a name id above u32 is unknown, not truncated onto a real one.
#[test]
fn a_name_id_above_u32_is_refused_not_aliased() {
    // {name_id 1: null} with the ref replaced by the even uvar 2^33 + 2
    // (id 2^32 + 1, which `as u32` truncated to 1).
    let dict = |id: u32| (id == 1).then(|| "a".to_string());
    let good = [0x22, 0x05, 0x01, 0x01, 0x02, 0x00, 0x00];
    assert!(cryptand::cve::decode_all(&good, &dict).is_ok());
    let bad = [0x22, 0x09, 0x01, 0x01, 0x82, 0x80, 0x80, 0x80, 0x20, 0x00, 0x00];
    assert!(cryptand::cve::decode_all(&bad, &dict).is_err());
}

/// F-105 (M3 fuzz `cve_decode`): a DOC whose field count is near 2^61 sized
/// an allocation from it. §9.1: a typed error, never an allocation failure.
#[test]
fn a_document_declaring_huge_field_count_is_refused_without_allocating() {
    let crash = [
        0x22, 0x0c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xfd, 0xff, 0x32, 0xff, 0xff,
    ];
    let r = cryptand::cve::decode_all(&crash, &|_| None);
    assert!(matches!(r, Err(cryptand::Error::Corrupt(_))), "{r:?}");
    let wide = Value::Doc((0..=cryptand::limits::MAX_FIELDS).map(|i| (format!("f{i}"), Value::Null)).collect());
    assert!(cryptand::cve::check_writable(&wide).is_err(), "a document over the field limit is writable");
}

/// F-106 (M3 fuzz `superblock_keyslot`): a short slice panicked.
#[test]
fn a_short_keyslot_is_refused_not_a_panic() {
    assert!(cryptand::security::Keyslot::parse(&[]).is_err());
}

/// F-108 (M3 fuzz `cve_decode`): a reserved tag's length near 2^64 wrapped
/// the bounds check and panicked on the slice.
#[test]
fn a_length_that_wraps_usize_is_refused_not_a_panic() {
    let crash = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x80, 0x00, 0x00,
    ];
    assert!(cryptand::cve::decode_all(&crash, &|_| None).is_err());
}

/// PLAN M3.5: every minimized fuzz file (page CRCs already repaired, as an
/// attacker would) opens to a typed error or a clean read — never a panic or
/// an allocation past the file (F-107: a segment ref asked for 66 GB).
#[test]
fn every_fuzz_regress_file_is_refused_or_read() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/files/fuzz-regress");
    let mut n = 0;
    for f in std::fs::read_dir(dir).unwrap() {
        let p = f.unwrap().path();
        let tmp = std::env::temp_dir().join(format!("cryptand-regress-{}.cryptand", std::process::id()));
        std::fs::copy(&p, &tmp).unwrap();
        let _ = exercise(&tmp);
        n += 1;
    }
    assert!(n > 0, "the fuzz-regress corpus is empty");
}

/// F-107: an extent length from the file is checked against the file before
/// the buffer exists (16 TB here; without the check the allocation aborts).
#[test]
fn an_extent_past_the_end_of_the_file_is_refused_before_allocating() {
    let mut e = Engine::open_read_only(&corpus(), None).unwrap();
    assert!(e.pager.read_extent(2, u32::MAX).is_err());
    assert!(e.pager.read_extent(u64::MAX / 2, 1).is_err());
}

/// F-109 (M3 fuzz `cke_roundtrip`): a NUMBER whose magnitude does not fit
/// its integer type code decoded, and §8's order then disagreed with memcmp.
#[test]
fn an_integer_that_does_not_fit_its_type_code_is_refused() {
    use cryptand::value::NumType;
    let mut k = cke::encode(&Value::Int { w: NumType::I16, neg: false, mag: 300 }).unwrap();
    *k.last_mut().unwrap() = NumType::I8.type_code();
    assert!(matches!(cke::decode_all(&k), Err(cryptand::Error::Corrupt(_))), "300 decoded as an i8");
    let mut k = cke::encode(&Value::Int { w: NumType::I64, neg: true, mag: 5 }).unwrap();
    *k.last_mut().unwrap() = NumType::U64.type_code();
    assert!(cke::decode_all(&k).is_err(), "-5 decoded as a u64");
    let min = cke::encode(&Value::Int { w: NumType::I8, neg: true, mag: 128 }).unwrap();
    assert!(cke::decode_all(&min).is_ok(), "i8::MIN is an i8");
}

/// Generator for `fuzz-regress/f111-segment-cycle.cryptand` (F-111): a real
/// segment whose root's last child points back at the root. Run once with
/// `cargo test --test hostile_test -- --ignored make_f111`.
#[test]
#[ignore]
fn make_f111_segment_cycle() {
    use cryptand::container::Profile;
    use cryptand::segment::Node;
    let tmp = std::env::temp_dir().join(format!("cryptand-f111-{}.cryptand", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut e = Engine::create(&tmp, Profile::Desktop).unwrap();
    for i in 0..20_000i64 {
        e.put(16, &Value::NitriteId(i), &[7u8; 24]).unwrap();
    }
    e.flush().unwrap();
    e.commit(cryptand::container::Durability::Sync).unwrap();
    let refs = e.all_refs().unwrap();
    drop(e);
    let mut b = std::fs::read(&tmp).unwrap();
    let ps = Superblock::parse(&b[..4096]).unwrap().page_size();
    let r = refs.iter().find(|r| r.pages > 2).expect("a multi-page segment");
    let at = ((r.start_page + r.root) as usize) * ps;
    let off = {
        let n = Node::parse(&b[at..at + ps], r.root).unwrap();
        assert!(!n.is_leaf && n.cell_count >= 2, "root is not internal");
        n.cell_suffix(n.cell_count - 1).unwrap().1
    };
    b[at + off..at + off + 8].copy_from_slice(&r.root.to_le_bytes());
    let page = &mut b[at..at + ps];
    let h = PageHeader::parse(page).unwrap();
    let end = PageHeader::checksum_range_end(page, &h);
    let crc = cryptand::hash::crc32c(&page[4..end]);
    page[..4].copy_from_slice(&crc.to_le_bytes());
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/files/fuzz-regress/f111-segment-cycle.cryptand");
    std::fs::write(out, &b).unwrap();
}
