//! `07-fulltext.md` §1, §4 — the three trees and the postings block layout.

use crate::cke;
use crate::cve;
use crate::error::{corrupt, invalid, Result};
use crate::value::{NumType, Value};
use crate::varint::{get_ivar, get_uvar, put_ivar, put_uvar};

/// §4.1 — a term's postings are split into blocks of at most 128 documents.
pub const BLOCK_MAX: usize = 128;
pub const HAS_POSITIONS: u8 = 0x01;

/// §1 — the `term_dict` value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TermEntry {
    pub id: u32,
    /// Document frequency; MUST be accurate after a merge.
    pub df: u32,
    /// Total term frequency.
    pub ttf: u64,
}

impl TermEntry {
    pub fn encode(&self) -> Vec<u8> {
        cve::encode(&Value::Doc(vec![
            ("id".into(), Value::Int { w: NumType::U32, neg: false, mag: self.id as u128 }),
            ("df".into(), Value::Int { w: NumType::U32, neg: false, mag: self.df as u128 }),
            ("ttf".into(), Value::Int { w: NumType::U64, neg: false, mag: self.ttf as u128 }),
        ]))
    }

    pub fn decode(b: &[u8]) -> Result<TermEntry> {
        let d = cve::decode_all(b, &|_| None)?;
        let u = |f: &str| match d.field(f) {
            Some(Value::Int { mag, .. }) => *mag as u64,
            _ => 0,
        };
        Ok(TermEntry { id: u("id") as u32, df: u("df") as u32, ttf: u("ttf") })
    }
}

pub fn term_dict_key(term: &str) -> Vec<u8> {
    cke::encode(&Value::Str(term.to_string())).expect("STR is CKE-encodable")
}

pub fn term_index_key(term_id: u32) -> Vec<u8> {
    cke::encode(&Value::Int { w: NumType::U32, neg: false, mag: term_id as u128 })
        .expect("U32 is CKE-encodable")
}

/// §4.1 — `CKE(Array[U32 term_id, NITRITE_ID first_doc_of_block])`. Blocks for
/// one term are therefore contiguous and in document order, and a posting can
/// be located by seeking directly to a document id.
pub fn postings_key(term_id: u32, first_doc: i64) -> Vec<u8> {
    cke::encode(&Value::Array(vec![
        Value::Int { w: NumType::U32, neg: false, mag: term_id as u128 },
        Value::NitriteId(first_doc),
    ]))
    .expect("U32 and NITRITE_ID are CKE-encodable")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posting {
    pub doc: i64,
    pub freq: u32,
    pub positions: Vec<u32>,
}

/// §4.2 — the block payload, a raw byte layout stored as the payload of a CVE
/// `BYTES` value (tag `0x13`) so that "an INLINE cell holds a CVE value" holds
/// without exception and generic tooling can walk any tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostingsBlock {
    pub postings: Vec<Posting>,
    pub has_positions: bool,
}

impl PostingsBlock {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.postings.is_empty() || self.postings.len() > BLOCK_MAX {
            return invalid(format!(
                "a postings block holds 1..{BLOCK_MAX} documents, got {}",
                self.postings.len()
            ));
        }
        let mut b = Vec::new();
        b.push(1u8); // version
        b.push(if self.has_positions { HAS_POSITIONS } else { 0 });
        b.extend_from_slice(&(self.postings.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.postings[0].doc.to_le_bytes());
        // Document ids inside a block are strictly increasing, so the deltas
        // are positive; zigzag is used anyway so that a future out-of-order
        // writer is representable rather than undefined.
        for w in self.postings.windows(2) {
            put_ivar(&mut b, w[1].doc - w[0].doc);
        }
        for p in &self.postings {
            put_uvar(&mut b, p.freq as u64);
        }
        if self.has_positions {
            // Positions are byte-length-prefixed as a group so that a scorer
            // that only needs frequencies can skip them without decoding.
            let mut pos = Vec::new();
            for p in &self.postings {
                let mut prev = 0u32;
                for (i, &x) in p.positions.iter().enumerate() {
                    put_uvar(&mut pos, if i == 0 { x as u64 } else { (x - prev) as u64 });
                    prev = x;
                }
            }
            put_uvar(&mut b, pos.len() as u64);
            b.extend_from_slice(&pos);
        }
        Ok(b)
    }

    pub fn decode(b: &[u8]) -> Result<PostingsBlock> {
        if b.len() < 12 {
            return corrupt("postings block shorter than its header");
        }
        if b[0] != 1 {
            return corrupt(format!("postings block version {} is not 1", b[0]));
        }
        let has_positions = b[1] & HAS_POSITIONS != 0;
        let count = u16::from_le_bytes(b[2..4].try_into().unwrap()) as usize;
        if count == 0 || count > BLOCK_MAX {
            return corrupt(format!("postings block count {count} outside 1..{BLOCK_MAX}"));
        }
        let first = i64::from_le_bytes(b[4..12].try_into().unwrap());
        let mut at = 12usize;
        let mut docs = Vec::with_capacity(count);
        docs.push(first);
        for _ in 1..count {
            let (d, n) = get_ivar(&b[at..])?;
            at += n;
            docs.push(docs.last().unwrap() + d);
        }
        let mut freqs = Vec::with_capacity(count);
        for _ in 0..count {
            let (f, n) = get_uvar(&b[at..])?;
            at += n;
            freqs.push(f as u32);
        }
        let mut postings: Vec<Posting> = docs
            .into_iter()
            .zip(freqs)
            .map(|(doc, freq)| Posting { doc, freq, positions: Vec::new() })
            .collect();
        if has_positions {
            let (pos_bytes, n) = get_uvar(&b[at..])?;
            at += n;
            let end = crate::limits::bounded(pos_bytes, b.len() - at, "postings positions")? + at;
            let mut p = at;
            for post in postings.iter_mut() {
                let mut prev = 0u32;
                for i in 0..post.freq as usize {
                    if p >= end {
                        return corrupt("postings positions truncated");
                    }
                    let (d, n) = get_uvar(&b[p..])?;
                    p += n;
                    let v = if i == 0 { d as u32 } else { prev + d as u32 };
                    post.positions.push(v);
                    prev = v;
                }
            }
        }
        Ok(PostingsBlock { postings, has_positions })
    }

    /// The CVE `BYTES` wrapper the tree actually stores.
    pub fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(cve::encode(&Value::Bytes(self.encode()?)))
    }

    pub fn decode_value(v: &[u8]) -> Result<PostingsBlock> {
        match cve::decode_all(v, &|_| None)? {
            Value::Bytes(b) => PostingsBlock::decode(&b),
            _ => corrupt("a postings value is a CVE BYTES"),
        }
    }
}

/// §4.1 — split a term's postings into blocks of at most 128 documents.
pub fn split_blocks(mut postings: Vec<Posting>, has_positions: bool) -> Vec<PostingsBlock> {
    postings.sort_by_key(|p| p.doc);
    postings
        .chunks(BLOCK_MAX)
        .map(|c| PostingsBlock { postings: c.to_vec(), has_positions })
        .collect()
}

/// §6 — the verifier's checks over a rebuilt index.
pub fn check_block(b: &PostingsBlock, first_doc: i64) -> Result<()> {
    if b.postings.is_empty() || b.postings.len() > BLOCK_MAX {
        return corrupt("block boundaries violate the <=128 rule");
    }
    if b.postings[0].doc != first_doc {
        return corrupt("block key does not match its first document");
    }
    for w in b.postings.windows(2) {
        if w[1].doc <= w[0].doc {
            return corrupt("document ids inside a block are not strictly increasing");
        }
    }
    if b.has_positions {
        for p in &b.postings {
            for w in p.positions.windows(2) {
                if w[1] <= w[0] {
                    return corrupt("positions inside a document are not strictly increasing");
                }
            }
        }
    }
    Ok(())
}

/// §3 — a phrase query requires positions. An implementation MUST reject one
/// against an index without them rather than approximate it with a
/// conjunction.
pub fn require_positions(has_positions: bool) -> Result<()> {
    if !has_positions {
        return invalid(
            "this index was built without positions, so a phrase query cannot be answered; \
             approximating it with a conjunction would return documents that do not contain \
             the phrase (spec/07-fulltext.md section 4.3)",
        );
    }
    Ok(())
}

/// A phrase match test over the per-document position lists of the phrase's
/// terms, in order.
pub fn phrase_matches(term_positions: &[Vec<u32>]) -> bool {
    let Some(first) = term_positions.first() else { return false };
    first.iter().any(|&start| {
        term_positions
            .iter()
            .enumerate()
            .all(|(i, ps)| ps.contains(&(start + i as u32)))
    })
}
