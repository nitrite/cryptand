//! `13-operations.md` §5 `rotate_master_key()` (F-072), by copy-and-swap
//! (human 10-07): CFF v1.0 cannot say which master key sealed a page, so a
//! file is never half-rotated. The live file is copied to a sibling, every
//! encrypted object in the sibling is re-sealed under a fresh master key —
//! same counters, same offsets, same lengths, only the key differs — the
//! superblock is rewritten with one new keyslot, and the sibling is renamed
//! over the original. A crash before the rename leaves the original intact
//! and a `.rotate` sibling to discard; after it, the new file is complete.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use crate::container::{Durability, PageHeader, PAGE_HEADER_BYTES};
use crate::engine::Engine;
use crate::error::{invalid, Result};
use crate::posio::PosIo;
use crate::security::{keyslot, make_keyslot, random_bytes, KeyRing};
use crate::segment::value_kind;
use crate::vlog::{self, DATA_OFFSET};

/// Rotates `e`'s master key and returns the database reopened under
/// `credential` (`kdf` 0: a raw 32-byte key; 1: Argon2id). Every other
/// keyslot is dropped: they wrap the old master key.
///
/// ponytail: one synchronous pass over the whole file with 2× its size on
/// disk, not 14 §8.4's bounded background steps, and refused while
/// checkpoints pin extents sealed under the old key. Step it, and walk the
/// checkpoints' extents, when large files need rotating online.
pub fn rotate_master_key(
    mut e: Engine,
    credential: &[u8],
    kdf: u8,
    t_cost: u32,
    m_cost_kib: u32,
    lanes: u32,
) -> Result<Engine> {
    if e.sb.cipher == 0 || e.keys.is_none() || e.pager.write_clear {
        return invalid("rotate_master_key() needs an unlocked, encrypted file not being decrypted");
    }
    let Some(path) = e.pager.path.clone() else {
        return invalid("rotate_master_key() needs a file");
    };
    if !e.checkpoint_commits().is_empty() {
        return invalid("rotate_master_key() refuses while checkpoints exist; drop them first");
    }
    // A quiet, durable state: nothing in flight, nothing in the memtable,
    // every value-log segment sealed.
    e.drain_compaction()?;
    e.flush()?;
    e.seal_unsealed_vlog_segments()?;
    e.commit(Durability::Sync)?;

    // What to re-seal, read from the engine before the copy.
    let ps = e.pager.page_size as u64;
    let mut pages: BTreeSet<u64> = BTreeSet::new();
    let mut blobs: BTreeSet<(u64, u64)> = BTreeSet::new();
    for r in e.all_refs()? {
        pages.extend(r.start_page..r.start_page + r.pages as u64);
        let seg = e.segment(&r)?;
        for rec in seg.iter() {
            let rec = rec?;
            if rec.value_kind == value_kind::BLOB && rec.value.len() == 16 {
                let start = u64::from_le_bytes(rec.value[0..8].try_into().unwrap());
                let len = u32::from_le_bytes(rec.value[8..12].try_into().unwrap()) as u64;
                blobs.insert((start, len));
            }
        }
    }
    let mut tree_pages = Vec::new();
    for t in [
        &e.catalog.tree,
        &e.catalog.by_id,
        &e.attributes.tree,
        &e.manifest.tree,
        &e.vlog_stats_tree,
        &e.checkpoints,
        &e.changefeed,
        &e.freelist,
    ] {
        t.reachable(&mut e.pager, &mut tree_pages)?;
    }
    pages.extend(tree_pages);
    // Index trees rooted in their descriptors (F-079).
    for (_, d) in crate::convert::index_trees(&mut e)? {
        pages.extend(crate::convert::index_tree_pages(&mut e.pager, &d)?);
    }
    // Vector regions (F-072 g): the head page is an ordinary page, the data
    // area is chunked when the head says so.
    let mut regions = Vec::new();
    for (_, _, start) in crate::convert::vector_regions(&mut e)? {
        let r = crate::vector::Region::open(&mut e.pager, start)?;
        pages.insert(start);
        if r.encrypted {
            regions.push((start, r.header.data_offset, r.pages as u64 - 1));
        }
    }
    let mut vlogs = Vec::new();
    let live: Vec<(u64, u64, u64)> = e
        .vlog_stats
        .values()
        .filter(|s| !s.retired() && s.pages > 0)
        .map(|s| (s.segment_id, s.start_page, s.bytes))
        .collect();
    for (id, start, bytes) in live {
        if e.vlog_encrypted(id)? {
            vlogs.push((id, start, bytes));
        }
    }

    let old = e.keys.clone().unwrap();
    let master = random_bytes::<32>();
    let new = KeyRing::from_master(master, e.sb.database_uuid, 0);
    let tmp = sibling(&path);
    let _ = std::fs::remove_file(&tmp);
    std::fs::copy(&path, &tmp)?;
    {
        let f = OpenOptions::new().read(true).write(true).open(&tmp)?;
        let mut buf = vec![0u8; ps as usize];
        // Free extents too: a retained one is still readable by the commit
        // before, and Dart's verify authenticates it. Its bytes may be
        // anything, so only a page that opens under the old key is re-sealed.
        let mut free: BTreeSet<u64> = BTreeSet::new();
        for x in e.pager.free_list() {
            free.extend(x.start_page..x.start_page + x.pages as u64);
        }
        for &p in free.difference(&pages) {
            f.read_exact_at(&mut buf, p * ps)?;
            let Ok(h) = PageHeader::parse(&buf) else { continue };
            if !h.encrypted() || PAGE_HEADER_BYTES + h.stored() > ps as usize {
                continue;
            }
            let end = PAGE_HEADER_BYTES + h.stored();
            let Ok(pt) = old.decrypt_page(p, h.nonce, &buf[..PAGE_HEADER_BYTES], &buf[PAGE_HEADER_BYTES..end]) else {
                continue;
            };
            let ct = new.encrypt_page(p, h.nonce, &buf[..PAGE_HEADER_BYTES], &pt)?;
            buf[PAGE_HEADER_BYTES..end].copy_from_slice(&ct);
            h.write_into(&mut buf);
            f.write_all_at(&buf, p * ps)?;
        }
        for &p in &pages {
            f.read_exact_at(&mut buf, p * ps)?;
            let h = PageHeader::parse(&buf)?;
            if !h.encrypted() {
                continue; // plaintext pages of a converting file stay as they are
            }
            let end = PAGE_HEADER_BYTES + h.stored();
            let pt = old.decrypt_page(p, h.nonce, &buf[..PAGE_HEADER_BYTES], &buf[PAGE_HEADER_BYTES..end])?;
            let ct = new.encrypt_page(p, h.nonce, &buf[..PAGE_HEADER_BYTES], &pt)?;
            buf[PAGE_HEADER_BYTES..end].copy_from_slice(&ct);
            h.write_into(&mut buf); // the CRC covers the payload as stored
            f.write_all_at(&buf, p * ps)?;
        }
        for (id, start, bytes) in vlogs {
            let base = start * ps + DATA_OFFSET as u64;
            let mut off = 0u64;
            while off < bytes {
                let mut head = vec![0u8; ((bytes - off) as usize).min(10)];
                f.read_exact_at(&mut head, base + off)?;
                let (len, n) = crate::varint::get_uvar(&head)?;
                let mut raw = vec![0u8; n + len as usize];
                f.read_exact_at(&mut raw, base + off)?;
                let rec = vlog::decode_record(&raw, true)?;
                let at = DATA_OFFSET as u64 + off;
                let counter = rec.nonce.unwrap_or(0);
                let (k, v) = old.decrypt_vlog(id, at, rec.tree_id, counter, &raw)?;
                let ct = new.encrypt_vlog(id, at, rec.tree_id, counter, &k, &v)?;
                let out = vlog::encode_record_encrypted(rec.tree_id, counter, &ct);
                debug_assert_eq!(out.len(), raw.len());
                f.write_all_at(&out, base + off)?;
                off += rec.total_len as u64;
            }
        }
        for (start, len) in blobs {
            let mut hb = vec![0u8; ps as usize];
            f.read_exact_at(&mut hb, start * ps)?;
            if !PageHeader::parse(&hb)?.encrypted() {
                continue;
            }
            let chunk = ps - 24;
            let (mut done, mut i) = (0u64, 0u64);
            while done < len {
                let at = if i == 0 { PAGE_HEADER_BYTES as u64 } else { 0 };
                let n = (len - done).min(chunk - at);
                let pos = (start + i) * ps + at;
                let mut raw = vec![0u8; 8 + n as usize + 16];
                f.read_exact_at(&mut raw, pos)?;
                let counter = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let pt = old.decrypt_chunk(start, counter, i, &raw[8..])?;
                let ct = new.encrypt_chunk(start, counter, i, &pt)?;
                raw[8..].copy_from_slice(&ct);
                f.write_all_at(&raw, pos)?;
                done += n;
                i += 1;
            }
        }
        for (start, data_offset, chunks) in regions {
            for i in 0..chunks {
                let pos = start * ps + data_offset + i * ps;
                // Allocated, never written: past the end, or all zero.
                if f.read_exact_at(&mut buf, pos).is_err() || buf.iter().all(|&b| b == 0) {
                    continue;
                }
                let counter = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                let pt = old.decrypt_chunk(start, counter, i, &buf[8..])?;
                let ct = new.encrypt_chunk(start, counter, i, &pt)?;
                buf[8..].copy_from_slice(&ct);
                f.write_all_at(&buf, pos)?;
            }
        }
        // One keyslot, under the new master; both superblock slots, so the
        // fallback cannot carry a keyslot for the old one.
        let mut sb = e.sb.clone();
        sb.keyslots.fill(0);
        let slot = make_keyslot(&master, &sb.database_uuid, 0, credential, kdf, t_cost, m_cost_kib, lanes, "keyslot 0")?;
        sb.keyslots[..keyslot::SIZE].copy_from_slice(&slot.encode());
        sb.commit_id += 1;
        let mut image = sb.encode();
        new.seal_superblock(&mut image);
        f.write_all_at(&image, 0)?;
        f.write_all_at(&image, ps)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    if let Some(dir) = path.parent() {
        // The rename itself, durable.
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    // ponytail: between this drop and the reopen another process could take
    // the writer lock on the new file; hold a lock across the swap if that
    // ever matters.
    drop(e);
    Engine::open(&path, Some(credential))
}

fn sibling(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".rotate");
    PathBuf::from(s)
}

