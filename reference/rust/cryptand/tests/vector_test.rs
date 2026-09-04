//! Level 4 — `09-vector.md`. The durable layout, not the algorithm.

mod support;
use support::*;

use cryptand::container::Profile;
use cryptand::vector::{
    brute_force, distance, Adjacency, Codebook, DType, Metric, Region, RegionHeader,
};

#[test]
fn a_region_round_trips_every_slot_positionally() {
    // §2 — "An implementation that cannot `mmap` reads positionally. The layout
    // is identical; only the access method differs."
    let (_t, mut e) = engine("region", Profile::Desktop);
    let dim = 8u32;
    let mut r = Region::create(&mut e.pager, dim, DType::F32, 64).unwrap();
    assert_eq!(r.header.data_offset % e.page_size() as u64, 0, "data_offset is page-aligned");
    for slot in 1..16u64 {
        let v: Vec<f32> = (0..dim).map(|i| (slot as f32) + i as f32 / 10.0).collect();
        r.write_slot(&mut e.pager, slot, &v).unwrap();
    }
    for slot in 1..16u64 {
        let v = r.read_slot(&mut e.pager, slot).unwrap();
        assert_eq!(v[0], slot as f32);
        assert!((v[7] - (slot as f32 + 0.7)).abs() < 1e-5);
    }
    // Slot 0 is reserved so that `slot_id = 0` is a null pointer.
    assert!(r.write_slot(&mut e.pager, 0, &vec![0.0; 8]).is_err());
    // The header survives a reopen through the ordinary page path.
    let again = Region::open(&mut e.pager, r.start_page).unwrap();
    assert_eq!(again.header.dim, dim);
    assert_eq!(again.header.stride, r.header.stride);
}

#[test]
fn the_stride_is_a_u16_so_a_too_wide_vector_is_refused_not_truncated() {
    // `00-conventions.md` §8: `dim * sizeof(dtype)` MUST be <= 65535. "A model
    // beyond that is served by splitting the vector across two indexes, not by
    // widening the field."
    assert!(RegionHeader::natural_stride(16383, DType::F32).is_ok());
    assert!(RegionHeader::natural_stride(16384, DType::F32).is_err());
    assert!(RegionHeader::natural_stride(32767, DType::F16).is_ok());
}

#[test]
fn an_adjacency_record_round_trips_in_graph_order() {
    // §3 — deltas are zigzag because neighbour ids are **not** sorted in graph
    // order: a proximity graph's list is ordered by distance, not by id.
    let a = Adjacency { neighbours: vec![900, 12, 4001, 3, 77] };
    let bytes = a.encode_value();
    assert_eq!(Adjacency::decode_value(&bytes).unwrap(), a);
    assert_eq!(Adjacency::decode(&a.encode()).unwrap(), a);
}

#[test]
fn a_codebook_round_trips_and_checks_its_dimension() {
    let c = Codebook {
        kind: 1,
        m: 4,
        k: 2,
        sub_dim: 3,
        centroids: (0..24).map(|i| i as f32).collect(),
    };
    let bytes = c.encode();
    let back = Codebook::decode(&bytes).unwrap();
    assert_eq!(back.centroids, c.centroids);
    // §4 — `dim = m * sub_dim` MUST hold.
    assert!(back.check_dim(12).is_ok());
    assert!(back.check_dim(16).is_err());
}

#[test]
fn the_three_metrics_order_as_declared() {
    let a = vec![1.0f32, 0.0];
    let b = vec![1.0f32, 0.0];
    let c = vec![0.0f32, 1.0];
    assert!(distance(Metric::Cosine, &a, &b) < distance(Metric::Cosine, &a, &c));
    assert!(distance(Metric::L2, &a, &b) < distance(Metric::L2, &a, &c));
    assert!(distance(Metric::Dot, &a, &b) < distance(Metric::Dot, &a, &c));
    assert_eq!(Metric::parse("l2").unwrap(), Metric::L2);
    assert!(Metric::parse("hamming").is_err());
}

#[test]
fn brute_force_never_returns_nothing_and_never_returns_a_deleted_document() {
    // §8 — an implementation MAY refuse a graph built by another algorithm,
    // "but it MUST then fall back to a brute-force scan of the vector region,
    // which is always possible and always correct, rather than returning
    // nothing". And a search MUST skip a slot with no document mapping, which
    // is what makes deletes correct immediately (the FreshDiskANN property).
    let (_t, mut e) = engine("brute", Profile::Desktop);
    let dim = 4u32;
    let mut r = Region::create(&mut e.pager, dim, DType::F32, 200).unwrap();
    let mut mapping = std::collections::HashMap::new();
    for slot in 1..100u64 {
        let v: Vec<f32> = (0..dim).map(|i| (slot as f32) * 0.01 + i as f32).collect();
        r.write_slot(&mut e.pager, slot, &v).unwrap();
        mapping.insert(slot, slot as i64);
    }
    // Delete document 50 by removing both mappings (§6).
    mapping.remove(&50);
    let query: Vec<f32> = (0..dim).map(|i| 0.50 + i as f32).collect();
    let live = |s: u64| mapping.get(&s).copied();
    let hits = brute_force(&mut e.pager, &r, &live, &query, Metric::L2, 5).unwrap();
    assert_eq!(hits.len(), 5);
    assert!(!hits.iter().any(|(id, _)| *id == 50), "a slot with no document mapping was returned");
    for w in hits.windows(2) {
        assert!(w[0].1 <= w[1].1, "results must be ordered nearest first");
    }
    // The distances returned are the true distances to the documents returned.
    let got = r.read_slot(&mut e.pager, hits[0].0 as u64).unwrap();
    assert!((distance(Metric::L2, &query, &got) - hits[0].1).abs() < 1e-5);
}

#[test]
fn an_f16_region_decodes_to_the_same_values() {
    let (_t, mut e) = engine("f16", Profile::Desktop);
    let r = Region::create(&mut e.pager, 4, DType::F16, 8).unwrap();
    // Write f16 bits by hand: 1.0, 2.0, -1.0, 0.5.
    let bits: [u16; 4] = [0x3C00, 0x4000, 0xBC00, 0x3800];
    let mut buf = Vec::new();
    for b in bits {
        buf.extend_from_slice(&b.to_le_bytes());
    }
    let at = r.start_page * e.page_size() as u64 + r.header.data_offset + r.header.stride as u64;
    e.pager.write_at(at, &buf).unwrap();
    let v = r.read_slot(&mut e.pager, 1).unwrap();
    assert_eq!(v, vec![1.0, 2.0, -1.0, 0.5]);
}

#[test]
fn a_vector_graph_key_sorts_a_layer_contiguously() {
    // §3 — keying by `(level, slot_id)` puts a layer's adjacency contiguously
    // and makes a layer scan sequential.
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for level in 0..3u8 {
        for slot in [1u64, 2, 10, 100] {
            keys.push(cryptand::vector::adjacency_key(level, slot));
        }
    }
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "the CKE order is already layer-then-slot");
}
