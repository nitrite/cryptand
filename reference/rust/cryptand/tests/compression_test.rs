//! `01-container.md` §7 — per-page compression.
//!
//! This file exists because §7 was implemented in **no write path in any of the
//! three reference implementations**, while `12-profiles.md` §1 names
//! `page_codec = LZ4` for every profile and §7 calls LZ4 "the default and the
//! only codec a Level-0 implementation MUST support". This crate had a correct
//! `codec.rs` and an `encode_data_page` nothing called; Java could decompress
//! and never compressed; Dart had no LZ4 at all and ignored the `COMPRESSED`
//! flag entirely.
//!
//! Same shape as defect 58 (page encryption absent from both implementations
//! while every test passed), and the same lesson: **test what is in the bytes,
//! not what the API returns.** A page round-trips perfectly when it is not
//! compressed.

use cryptand::codec;
use cryptand::container::{page_flags, page_type, PageHeader, PAGE_HEADER_BYTES};
use cryptand::pager::Pager;

/// A page-sized payload shaped like the documents this format holds: repeated
/// field names and short values.
fn documentish(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 64);
    let mut i = 0u32;
    while out.len() < n {
        out.extend_from_slice(
            format!(r#"{{"_id":{i},"name":"widget","kind":"tool","qty":7}}"#).as_bytes(),
        );
        i += 1;
    }
    out.truncate(n);
    out
}

/// Bytes no codec can shrink. A deterministic LCG, so a failure reproduces.
fn incompressible(n: usize) -> Vec<u8> {
    let mut s = 0x2545_F491_4F6C_DD1Du64;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 33) as u8
        })
        .collect()
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|w| *w == needle).count()
}

// ---------------------------------------------------------------------------
// The block codec on its own.
// ---------------------------------------------------------------------------

#[test]
fn every_shape_round_trips_including_the_degenerate_lengths() {
    let mut shapes: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x41],
        vec![0x41; 4],
        // 11, 12 and 13 straddle the end-of-block guard, which is where an
        // off-by-one in a compressor's limit lands.
        vec![0x41; 11],
        vec![0x41; 12],
        vec![0x41; 13],
        vec![0x41; 4056],
        documentish(4056),
        incompressible(4056),
        (0..4056).map(|i| ((i / 64) % 3) as u8).collect(),
        (0..4056).map(|i| (i % 7) as u8).collect(),
    ];
    shapes.push(documentish(1));
    for src in &shapes {
        let block = match codec::compress(codec::LZ4, src).unwrap() {
            Some(b) => b,
            // `compress` returns None when it is not worth storing; compress
            // unconditionally for the round-trip check.
            None => lz4_flex::block::compress(src),
        };
        let back = codec::decompress(codec::LZ4, &block, src.len()).unwrap();
        assert_eq!(&back, src, "length {}", src.len());
    }
}

#[test]
fn the_twelve_and_a_half_percent_rule_is_exactly_section_7_arithmetic() {
    assert!(codec::worth_compressing(4096, 3584), "saves exactly 1/8");
    assert!(!codec::worth_compressing(4096, 3585), "one byte short");
    assert!(!codec::worth_compressing(4096, 4096));
    assert!(codec::worth_compressing(0, 0));
}

#[test]
fn an_incompressible_payload_is_not_worth_storing_compressed() {
    assert!(codec::compress(codec::LZ4, &incompressible(4056)).unwrap().is_none());
    assert!(codec::compress(codec::LZ4, &documentish(4056)).unwrap().is_some());
}

#[test]
fn an_unknown_or_unbuilt_codec_is_refused_never_guessed_at() {
    assert!(codec::compress(codec::ZSTD, &documentish(64)).is_err());
    assert!(codec::decompress(codec::ZSTD, &[1, 2, 3], 64).is_err());
    assert!(codec::compress(77, &documentish(64)).is_err());
    assert!(codec::decompress(77, &[1, 2, 3], 64).is_err());
    assert!(codec::compress(codec::NONE, &documentish(64)).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Untrusted input. `14-security.md` §9: a decompressor is the classic place to
// write past the end of a buffer on a crafted length, and every byte string
// below is one an attacker can put in a file.
// ---------------------------------------------------------------------------

#[test]
fn a_crafted_block_is_refused_and_never_panics() {
    let crafted: &[&[u8]] = &[
        &[0xF0, 0xFF],                               // literals overrun the source
        &[0x50, 1, 2, 3, 4, 5],                      // literals overrun the output
        &[0x0F, 0x10, 0x00, 0x00],                   // offset before the output
        &[0x10, 0x41, 0x00, 0x00],                   // offset zero
        &[0x1F, 0x41, 0x01, 0x00, 0xFF, 0xFF, 0x00], // match length past the end
        &[0xFF; 64],
        &[0x00],
    ];
    for b in crafted {
        // Err is the required outcome; a panic or an allocation blow-up is not.
        let _ = codec::decompress(codec::LZ4, b, 64);
    }
}

#[test]
fn truncation_at_every_length_is_refused_never_silently_short() {
    let src = documentish(2000);
    let block = codec::compress(codec::LZ4, &src).unwrap().unwrap();
    for cut in 0..block.len() {
        match codec::decompress(codec::LZ4, &block[..cut], src.len()) {
            Ok(got) => panic!("a block truncated at {cut} decoded to {} bytes", got.len()),
            Err(_) => {}
        }
    }
}

#[test]
fn a_bit_flipped_anywhere_is_refused_or_wrong_never_out_of_bounds() {
    let src = documentish(2000);
    let block = codec::compress(codec::LZ4, &src).unwrap().unwrap();
    let mut refused = 0;
    let mut decoded = 0;
    for i in 0..block.len() {
        for bit in [0x01u8, 0x80] {
            let mut bad = block.clone();
            bad[i] ^= bit;
            match codec::decompress(codec::LZ4, &bad, src.len()) {
                Ok(_) => decoded += 1,
                Err(_) => refused += 1,
            }
        }
    }
    assert_eq!(refused + decoded, block.len() * 2);
    assert!(refused > 0, "if nothing is ever refused the checks are not running");
}

// ---------------------------------------------------------------------------
// The page seam. These are the tests defect 58 says to write: look at the
// stored bytes, because a page round-trips perfectly when nothing happened.
// ---------------------------------------------------------------------------

fn page_of(payload: &[u8], page_size: usize, extent_pages: u32, ptype: u8) -> Vec<u8> {
    let mut page = vec![0u8; page_size];
    page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + payload.len()].copy_from_slice(payload);
    PageHeader {
        page_type: ptype,
        tree_id: 17,
        extent_pages,
        commit_id: 1,
        payload_len: payload.len() as u32,
        ..Default::default()
    }
    .write_into(&mut page);
    page
}

fn store_with(codec_id: u8) -> Pager {
    let mut p = Pager::in_memory(4096);
    p.page_codec = codec_id;
    p
}

#[test]
fn a_compressible_page_is_stored_compressed_and_says_so() {
    let mut p = store_with(codec::LZ4);
    let id = p.alloc_extent(1).unwrap();
    let payload = documentish(4000);
    p.write_page(id, &page_of(&payload, 4096, 1, page_type::BTREE_LEAF)).unwrap();

    // The stored bytes, not the decoded ones.
    let stored = p.read_page_clear(id).unwrap();
    let h = PageHeader::parse(&stored).unwrap();
    assert!(h.compressed(), "the flag must be set");
    assert_eq!(h.codec as u8, codec::LZ4, "and it must name the codec");
    assert_eq!(
        h.payload_len as usize,
        payload.len(),
        "payload_len keeps §3's meaning: the uncompressed length"
    );
    assert!(h.stored_len > 0 && (h.stored_len as usize) < payload.len());

    // The repetitions are gone. Not all of them: LZ4 emits the first
    // occurrence as *literals* and encodes only the repeats as matches, so
    // exactly one copy survives verbatim. Compression is not confidentiality --
    // that is §5.2's job -- and asserting the needle is absent would be
    // asserting something false.
    assert_eq!(count(&stored, br#""name":"widget""#), 1);
    assert!(
        count(&page_of(&payload, 4096, 1, page_type::BTREE_LEAF), br#""name":"widget""#) > 50,
        "the control: uncompressed, the page holds it many times"
    );

    // And the read path hands back the plaintext, with a header describing it.
    let back = p.read_page(id).unwrap();
    let bh = PageHeader::parse(&back).unwrap();
    assert!(!bh.compressed(), "the header a caller sees describes the plaintext");
    assert_eq!(bh.stored_len, 0);
    assert_eq!(&back[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + payload.len()], &payload[..]);
}

#[test]
fn with_the_codec_off_nothing_is_compressed() {
    let mut p = store_with(codec::NONE);
    let id = p.alloc_extent(1).unwrap();
    let payload = documentish(4000);
    p.write_page(id, &page_of(&payload, 4096, 1, page_type::BTREE_LEAF)).unwrap();
    let stored = p.read_page_clear(id).unwrap();
    assert!(!PageHeader::parse(&stored).unwrap().compressed());
    assert!(
        count(&stored, br#""name":"widget""#) > 50,
        "the control: without the codec every copy IS there, so the test above \
         is measuring the codec and not something else"
    );
}

#[test]
fn an_incompressible_page_is_stored_as_it_is_never_larger() {
    let mut p = store_with(codec::LZ4);
    let id = p.alloc_extent(1).unwrap();
    let payload = incompressible(4000);
    p.write_page(id, &page_of(&payload, 4096, 1, page_type::BTREE_LEAF)).unwrap();
    let h = PageHeader::parse(&p.read_page_clear(id).unwrap()).unwrap();
    assert!(!h.compressed(), "§7: only if compression saves >= 12.5 %");
    let back = p.read_page(id).unwrap();
    assert_eq!(&back[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + payload.len()], &payload[..]);
}

#[test]
fn a_page_inside_a_multi_page_extent_is_never_compressed() {
    // An extent is a contiguous byte range whose reader may hold the whole
    // thing and parse pages at fixed offsets rather than fetching them one at a
    // time -- which `segment.rs` does. Compressing a page inside one moves
    // every byte after its header without telling that reader, and the failure
    // shows up as "segment header magic mismatch" in another language, several
    // steps later. That is exactly what happened.
    let mut p = store_with(codec::LZ4);
    let id = p.alloc_extent(3).unwrap();
    let payload = documentish(4000);
    p.write_page(id, &page_of(&payload, 4096, 3, page_type::SEGMENT_HEADER)).unwrap();
    let h = PageHeader::parse(&p.read_page_clear(id).unwrap()).unwrap();
    assert!(!h.compressed(), "extent_pages > 1 means the payload is not this page alone");
}

#[test]
fn a_value_log_head_page_is_never_compressed() {
    // §6.2 appends records into the head page's own tail, so its bytes are not
    // a payload that can be rewritten.
    let mut p = store_with(codec::LZ4);
    let id = p.alloc_extent(1).unwrap();
    let payload = documentish(64);
    p.write_page(id, &page_of(&payload, 4096, 1, page_type::VLOG_SEGMENT)).unwrap();
    assert!(!PageHeader::parse(&p.read_page_clear(id).unwrap()).unwrap().compressed());
}

#[test]
fn an_already_compressed_page_is_not_compressed_twice() {
    let mut p = store_with(codec::LZ4);
    let id = p.alloc_extent(1).unwrap();
    let payload = documentish(4000);
    let mut page = page_of(&payload, 4096, 1, page_type::BTREE_LEAF);
    let mut h = PageHeader::parse(&page).unwrap();
    h.flags |= page_flags::COMPRESSED;
    h.write_into(&mut page);
    p.write_page(id, &page).unwrap();
    let stored = p.read_page_clear(id).unwrap();
    // It came in claiming to be compressed; the pager must have left the bytes
    // alone rather than compressing them a second time.
    assert_eq!(&stored[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + 32], &page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + 32]);
}

// ---------------------------------------------------------------------------
// The space claim. §7 exists to make files smaller; a test that only proves
// correctness lets the benefit quietly go to zero.
// ---------------------------------------------------------------------------

#[test]
fn a_document_shaped_page_stores_in_under_half_a_page() {
    let mut p = store_with(codec::LZ4);
    let id = p.alloc_extent(1).unwrap();
    let payload = documentish(4000);
    p.write_page(id, &page_of(&payload, 4096, 1, page_type::BTREE_LEAF)).unwrap();
    let h = PageHeader::parse(&p.read_page_clear(id).unwrap()).unwrap();
    assert!(
        (h.stored_len as usize) < payload.len() / 2,
        "stored {} of {} bytes",
        h.stored_len,
        payload.len()
    );
}

// ---------------------------------------------------------------------------
// The shared vectors of `reference/conformance/vectors/codec/lz4.json`.
//
// This is what makes §7 portable rather than merely implemented: a fourth SDK
// checks itself against these bytes with none of the other three present.
//
// **Only the decoder is normative.** Any conforming LZ4 block decompresses to
// the same output whatever produced it, so a reader is checked against these
// and a writer is not: the three implementations compress the same page to
// three different lengths and still read each other's files.
// ---------------------------------------------------------------------------

#[path = "support_v/mod.rs"]
mod support;

#[test]
fn every_recorded_block_decodes_to_its_recorded_plaintext() {
    let v = support::load("codec/lz4");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() > 8, "a vector file that shrank silently measures nothing");
    for c in cases {
        let note = c["note"].as_str().unwrap();
        let plain = support::unhex(c["plain"].as_str().unwrap());
        assert_eq!(
            plain.len() as u64,
            c["plain_len"].as_u64().unwrap(),
            "the vector disagrees with itself: {note}"
        );
        let block = support::unhex(c["lz4"].as_str().unwrap());
        let got = codec::decompress(codec::LZ4, &block, plain.len())
            .unwrap_or_else(|e| panic!("{note}: {e}"));
        assert_eq!(got, plain, "{note}");
    }
}

#[test]
fn this_compressor_emits_blocks_the_vector_can_check() {
    // The writer is free, so the assertion is not byte equality: it is that
    // what this compressor emits decodes to the same plaintext.
    let v = support::load("codec/lz4");
    for c in v["cases"].as_array().unwrap() {
        let plain = support::unhex(c["plain"].as_str().unwrap());
        let block = lz4_flex::block::compress(&plain);
        let got = codec::decompress(codec::LZ4, &block, plain.len()).unwrap();
        assert_eq!(got, plain, "{}", c["note"].as_str().unwrap());
    }
}

#[test]
fn every_block_the_vector_says_to_refuse_is_refused() {
    let v = support::load("codec/lz4");
    let cases = v["refuse"]["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let block = support::unhex(c["lz4"].as_str().unwrap());
        let n = c["plain_len"].as_u64().unwrap() as usize;
        assert!(
            codec::decompress(codec::LZ4, &block, n).is_err(),
            "{}",
            c["why"].as_str().unwrap()
        );
    }
}

#[test]
fn the_threshold_matches_the_recorded_cases() {
    let v = support::load("codec/lz4");
    for c in v["threshold"]["cases"].as_array().unwrap() {
        let raw = c["raw"].as_u64().unwrap() as usize;
        let comp = c["compressed"].as_u64().unwrap() as usize;
        assert_eq!(codec::worth_compressing(raw, comp), c["worth"].as_bool().unwrap(),
            "{raw} -> {comp}");
    }
}
