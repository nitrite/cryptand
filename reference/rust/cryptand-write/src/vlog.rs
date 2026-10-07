//! `04-segments.md` §6.2 — a value-log segment, and the reserve-then-`pwrite`
//! protocol `10-transactions.md` §2.2 requires.
//!
//! The load-bearing property is that a writer takes a byte range with **one
//! `fetch_add`** and writes straight into it: no shared buffer, no writer lock,
//! and no two writers touching the same bytes. That is what makes *N* writers
//! drive *N* independent append streams instead of serializing on a journal.

use std::fs::File;
use crate::posio::PosIo;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cryptand_conformance::hash::crc32c;
use cryptand_conformance::varint::put_uvar;

use crate::prefix::Watermark;
use crate::{Error, Result};

/// §6.2: the head page header plus the 40-byte page header, rounded up to 8.
pub const DATA_OFFSET: u64 = 104;
pub const MAGIC: [u8; 8] = [0x43, 0x52, 0x59, 0x5F, 0x56, 0x4C, 0x47, 0x1A];

/// §6.6 — records are routed by expected lifetime so a segment tends to become
/// garbage all at once. The format records the class; the classifier is the
/// implementation's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeatClass {
    First = 0,
    Warm = 1,
    Hot = 2,
}

pub const HEAT_CLASSES: [HeatClass; 3] = [HeatClass::First, HeatClass::Warm, HeatClass::Hot];

/// One record, encoded per §6.2. Unencrypted: this crate measures the write
/// protocol, and `14-security.md`'s record encryption is exercised by
/// `cryptand-conformance`.
pub fn encode_record(tree_id: u32, key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(key.len() + value.len() + 24);
    body.extend_from_slice(&tree_id.to_le_bytes());
    put_uvar(&mut body, key.len() as u64);
    body.extend_from_slice(key);
    put_uvar(&mut body, value.len() as u64);
    body.extend_from_slice(value);
    let crc = crc32c(&body);
    body.extend_from_slice(&crc.to_le_bytes());

    let mut out = Vec::with_capacity(body.len() + 10);
    // `record_len` counts the bytes that follow it, including the crc32c.
    put_uvar(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    out
}

/// A reserved byte range. Holding one is a promise to `complete` it; dropping
/// one without completing leaves the hole §2.3 invariant 2 is about.
#[derive(Debug, Clone, Copy)]
pub struct Reservation {
    pub offset: u64,
    pub len: u64,
}

pub struct VlogSegment {
    pub segment_id: u64,
    pub heat_class: HeatClass,
    pub capacity: u64,
    file: Arc<File>,
    /// Offset of this extent's record area within the file.
    base: u64,
    /// Bytes reserved so far. The only contended word on the value-log path.
    tail: AtomicU64,
    /// §6.2's `bytes`, which lives in tree 7 in a real engine. Here it is the
    /// same watermark with the same rule and no tree under it.
    durable: Mutex<Watermark>,
    sealed: AtomicBool,
    /// How many `fetch_add`s this segment has served, for the bench.
    pub reservations: AtomicU64,
}

impl VlogSegment {
    pub fn create(
        file: Arc<File>,
        base: u64,
        capacity: u64,
        segment_id: u64,
        heat_class: HeatClass,
        created_seq: u64,
    ) -> Result<Arc<VlogSegment>> {
        let mut head = vec![0u8; DATA_OFFSET as usize];
        // The head page is written once and never rewritten (§6.2), so it holds
        // only the segment's immutable identity. Offsets are from the extent
        // start; the 40-byte page header precedes this header.
        let h = 40usize;
        head[h..h + 8].copy_from_slice(&MAGIC);
        head[h + 8..h + 16].copy_from_slice(&segment_id.to_le_bytes());
        head[h + 16..h + 24].copy_from_slice(&created_seq.to_le_bytes());
        head[h + 24..h + 32].copy_from_slice(&capacity.to_le_bytes());
        head[h + 32..h + 36].copy_from_slice(&(DATA_OFFSET as u32).to_le_bytes());
        head[h + 36] = 0; // tier HOT
        head[h + 37] = heat_class as u8;
        file.write_all_at(&head, base)?;
        Ok(Arc::new(VlogSegment {
            segment_id,
            heat_class,
            capacity,
            file,
            base,
            tail: AtomicU64::new(0),
            durable: Mutex::new(Watermark::new(0)),
            sealed: AtomicBool::new(false),
            reservations: AtomicU64::new(0),
        }))
    }

    /// One `fetch_add`. A reservation past capacity is refused and the tail is
    /// left where it is, so the caller opens a fresh segment.
    pub fn reserve(&self, len: u64) -> Result<Reservation> {
        if self.sealed.load(Ordering::Acquire) {
            return Err(Error::SegmentFull);
        }
        let offset = self.tail.fetch_add(len, Ordering::AcqRel);
        self.reservations.fetch_add(1, Ordering::Relaxed);
        if offset + len > self.capacity {
            self.tail.fetch_sub(len, Ordering::AcqRel);
            return Err(Error::SegmentFull);
        }
        Ok(Reservation { offset, len })
    }

    /// A whole batch coalesced into one reservation and one `pwrite`, which
    /// §6.2 says a writer SHOULD do.
    pub fn write_at(&self, r: Reservation, bytes: &[u8]) -> Result<()> {
        debug_assert_eq!(bytes.len() as u64, r.len);
        self.file.write_all_at(bytes, self.base + DATA_OFFSET + r.offset)?;
        Ok(())
    }

    /// Marks a reservation's bytes as written. The watermark advances only over
    /// a contiguous prefix, so a reservation that never completes pins every
    /// later one below the watermark — which is the point.
    pub fn complete(&self, r: Reservation) -> u64 {
        self.durable.lock().unwrap().complete(r.offset, r.offset + r.len)
    }

    /// §6.2: only records entirely below `bytes` may be referenced by a
    /// `VLOG` pointer. Everything above it is debris.
    pub fn durable_bytes(&self) -> u64 {
        self.durable.lock().unwrap().get()
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.tail.load(Ordering::Acquire)
    }

    /// Ranges written but held back by an incomplete reservation below them.
    pub fn pending_ranges(&self) -> usize {
        self.durable.lock().unwrap().pending()
    }

    /// §6.2: on open, every unsealed segment is sealed at its durable watermark
    /// and a fresh one is opened. A writer MUST NOT append to a segment it did
    /// not itself open — unconditionally, not only when encrypted.
    pub fn seal(&self) -> u64 {
        self.sealed.store(true, Ordering::Release);
        self.durable_bytes()
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed.load(Ordering::Acquire)
    }

    /// Reads a record back, for the tests. Returns `(tree_id, key, value)`.
    pub fn read_record(&self, offset: u64) -> Result<(u32, Vec<u8>, Vec<u8>)> {
        let mut head = [0u8; 10];
        self.file.read_at(&mut head, self.base + DATA_OFFSET + offset)?;
        let (len, n) = cryptand_conformance::varint::get_uvar(&head)
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        let mut body = vec![0u8; len as usize];
        self.file.read_at(&mut body, self.base + DATA_OFFSET + offset + n as u64)?;
        let stored = u32::from_le_bytes(body[body.len() - 4..].try_into().unwrap());
        if crc32c(&body[..body.len() - 4]) != stored {
            return Err(Error::Io(std::io::Error::other("record crc32c mismatch")));
        }
        let tree_id = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let (klen, kn) = cryptand_conformance::varint::get_uvar(&body[4..])
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        let ks = 4 + kn;
        let key = body[ks..ks + klen as usize].to_vec();
        let (vlen, vn) = cryptand_conformance::varint::get_uvar(&body[ks + klen as usize..])
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        let vs = ks + klen as usize + vn;
        Ok((tree_id, key, body[vs..vs + vlen as usize].to_vec()))
    }
}
