//! `01-container.md` §1 and §6 — the file's page space: superblock slots,
//! extent allocation, and the one rule the whole design rests on:
//!
//! > No page that a live superblock references is ever overwritten.
//!
//! Every write is an append into fresh space or into the open tail of a
//! value-log segment, which is what makes recovery O(1) and torn pages
//! impossible.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::container::{Durability, PageHeader, SUPERBLOCK_BYTES};
use crate::error::{corrupt, invalid, Result};
use crate::limits::check_page_size;

/// §6 — one entry of the free tree (tree 1), keyed `(commit_id, start_page)`
/// so a scan from the beginning yields the oldest, most-reclaimable extents
/// first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeExtent {
    pub commit_id: u64,
    pub start_page: u64,
    pub pages: u32,
}

pub struct Pager {
    file: Option<File>,
    pub path: Option<PathBuf>,
    /// The in-memory mode the tests and the vector generator use. A `Pager`
    /// with no file behaves identically; `page_count` and page identity are
    /// real either way.
    memory: Vec<u8>,
    pub page_size: usize,
    pub page_count: u64,
    free: BTreeMap<(u64, u64), u32>,
    pub min_retained_commit: u64,
    pub page_reads: u64,
    pub page_writes: u64,
    pub bytes_written_device: u64,
    /// Extents preallocated in one grow, so segment extents stay physically
    /// contiguous (§6: "preallocating in large chunks is strongly recommended").
    pub grow_chunk_pages: u64,
}

impl Pager {
    pub fn create(path: &Path, page_size: usize) -> Result<Pager> {
        check_page_size(page_size)?;
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)?;
        let mut p = Pager::new_common(page_size);
        p.file = Some(file);
        p.path = Some(path.to_path_buf());
        p.grow(2)?;
        Ok(p)
    }

    pub fn open(path: &Path, page_size: usize, page_count: u64) -> Result<Pager> {
        check_page_size(page_size)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut p = Pager::new_common(page_size);
        p.file = Some(file);
        p.path = Some(path.to_path_buf());
        p.page_count = page_count;
        Ok(p)
    }

    pub fn in_memory(page_size: usize) -> Pager {
        let mut p = Pager::new_common(page_size);
        p.memory = vec![0u8; 2 * page_size];
        p.page_count = 2;
        p
    }

    fn new_common(page_size: usize) -> Pager {
        Pager {
            file: None,
            path: None,
            memory: Vec::new(),
            page_size,
            page_count: 0,
            free: BTreeMap::new(),
            min_retained_commit: 0,
            page_reads: 0,
            page_writes: 0,
            bytes_written_device: 0,
            grow_chunk_pages: 64,
        }
    }

    pub fn is_file(&self) -> bool {
        self.file.is_some()
    }

    // ---------------------------------------------------------------------
    // §6 — allocation
    // ---------------------------------------------------------------------

    pub fn set_free_list(&mut self, extents: impl IntoIterator<Item = FreeExtent>) {
        self.free.clear();
        for e in extents {
            self.free.insert((e.commit_id, e.start_page), e.pages);
        }
    }

    pub fn free_list(&self) -> Vec<FreeExtent> {
        self.free
            .iter()
            .map(|(&(commit_id, start_page), &pages)| FreeExtent { commit_id, start_page, pages })
            .collect()
    }

    /// §6's reclamation rule: an extent freed at `commit_id = N` may be
    /// reallocated once `N <= min_retained_commit`. Allocation order is
    /// best-fit among those, then extend the file at `page_count`.
    pub fn alloc_extent(&mut self, pages: u32) -> Result<u64> {
        if pages == 0 {
            return invalid("an extent of zero pages");
        }
        let mut best: Option<((u64, u64), u32)> = None;
        for (&k, &n) in self.free.iter() {
            if k.0 > self.min_retained_commit || n < pages {
                continue;
            }
            if best.map_or(true, |(_, bn)| n < bn) {
                best = Some((k, n));
            }
        }
        if let Some((k, n)) = best {
            self.free.remove(&k);
            if n > pages {
                // The remainder stays free at the same commit id.
                self.free.insert((k.0, k.1 + pages as u64), n - pages);
            }
            return Ok(k.1);
        }
        let start = self.page_count;
        self.grow(pages as u64)?;
        Ok(start)
    }

    /// Pages freed at `commit_id`; they become allocatable when
    /// `min_retained_commit` passes them.
    pub fn free_extent(&mut self, start_page: u64, pages: u32, commit_id: u64) {
        if start_page < 2 || pages == 0 {
            return;
        }
        self.free.insert((commit_id, start_page), pages);
    }

    fn grow(&mut self, pages: u64) -> Result<()> {
        let want = self.page_count + pages;
        let target = if self.file.is_some() {
            // §6: an implementation MAY grow the file in chunks larger than the
            // request; `page_count`, not the file length, defines what is in use.
            want.div_ceil(self.grow_chunk_pages) * self.grow_chunk_pages
        } else {
            want
        };
        let bytes = target as usize * self.page_size;
        if let Some(f) = &mut self.file {
            if f.metadata()?.len() < bytes as u64 {
                f.set_len(bytes as u64)?;
            }
        } else if self.memory.len() < bytes {
            self.memory.resize(bytes, 0);
        }
        self.page_count = want;
        Ok(())
    }

    /// Used after a reopen: the file may be longer than `page_count`, and
    /// everything at or beyond it is debris from an interrupted commit
    /// (§2.1 step 7).
    pub fn set_page_count(&mut self, page_count: u64) {
        self.page_count = page_count;
    }

    // ---------------------------------------------------------------------
    // Raw I/O
    // ---------------------------------------------------------------------

    pub fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        match &mut self.file {
            Some(f) => {
                f.seek(SeekFrom::Start(offset))?;
                f.read_exact(&mut buf)?;
            }
            None => {
                let end = offset as usize + len;
                if end > self.memory.len() {
                    return corrupt(format!("read past the store: {offset}+{len}"));
                }
                buf.copy_from_slice(&self.memory[offset as usize..end]);
            }
        }
        Ok(buf)
    }

    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.bytes_written_device += data.len() as u64;
        match &mut self.file {
            Some(f) => {
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(data)?;
            }
            None => {
                let end = offset as usize + data.len();
                if self.memory.len() < end {
                    self.memory.resize(end, 0);
                }
                self.memory[offset as usize..end].copy_from_slice(data);
            }
        }
        Ok(())
    }

    pub fn read_page(&mut self, page_id: u64) -> Result<Vec<u8>> {
        if page_id >= self.page_count {
            return corrupt(format!("page {page_id} is at or beyond page_count"));
        }
        self.page_reads += 1;
        self.read_at(page_id * self.page_size as u64, self.page_size)
    }

    pub fn write_page(&mut self, page_id: u64, page: &[u8]) -> Result<()> {
        if page.len() != self.page_size {
            return invalid(format!("page {page_id} is {} B, expected {}", page.len(), self.page_size));
        }
        self.page_writes += 1;
        self.write_at(page_id * self.page_size as u64, page)
    }

    /// A whole extent, head page included.
    pub fn read_extent(&mut self, start_page: u64, pages: u32) -> Result<Vec<u8>> {
        self.page_reads += pages as u64;
        self.read_at(start_page * self.page_size as u64, pages as usize * self.page_size)
    }

    pub fn write_extent(&mut self, start_page: u64, bytes: &[u8]) -> Result<()> {
        if bytes.len() % self.page_size != 0 {
            return invalid("an extent must be a whole number of pages");
        }
        self.page_writes += (bytes.len() / self.page_size) as u64;
        self.write_at(start_page * self.page_size as u64, bytes)
    }

    /// §3 — verify the checksum before decompression and before decryption.
    pub fn read_verified(&mut self, page_id: u64) -> Result<(PageHeader, Vec<u8>)> {
        let page = self.read_page(page_id)?;
        let h = PageHeader::verify(&page, page_id)?;
        Ok((h, page))
    }

    // ---------------------------------------------------------------------
    // Superblock slots — §1: A if commit_id is odd, B if even
    // ---------------------------------------------------------------------

    pub fn slot_offset(&self, commit_id: u64) -> u64 {
        if commit_id % 2 == 1 {
            0
        } else {
            self.page_size as u64
        }
    }

    pub fn read_slot(&mut self, which: u8) -> Result<Vec<u8>> {
        let off = if which == 0 { 0 } else { self.page_size as u64 };
        self.read_at(off, SUPERBLOCK_BYTES)
    }

    // ---------------------------------------------------------------------
    // `10-transactions.md` §7 — the strongest primitive the platform provides,
    // and a record of what was actually performed.
    // ---------------------------------------------------------------------

    pub fn sync(&mut self, requested: Durability) -> Result<Durability> {
        let Some(f) = &mut self.file else {
            // No file under the store: `none` is the honest report. Claiming a
            // mode not reached is the silent failure §7 exists to prevent.
            return Ok(Durability::None);
        };
        Ok(match requested {
            Durability::None | Durability::Os => requested,
            Durability::Sync => {
                f.sync_data()?;
                Durability::Sync
            }
            Durability::Full => {
                // Rust's `sync_all` issues `F_FULLFSYNC` on Darwin, which is
                // the drive-cache flush `full` means there. Linux and Windows
                // expose no stronger portable call, so `full` and `sync`
                // coincide and the honest record is `sync`.
                f.sync_all()?;
                if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
                    Durability::Full
                } else {
                    Durability::Sync
                }
            }
        })
    }

    /// `10-transactions.md` §4: an implementation MAY truncate to `page_count`
    /// on open; it MUST NOT require truncation to be correct.
    pub fn truncate_to_page_count(&mut self) -> Result<()> {
        let bytes = self.page_count * self.page_size as u64;
        match &mut self.file {
            Some(f) => f.set_len(bytes)?,
            None => self.memory.truncate(bytes as usize),
        }
        Ok(())
    }

    pub fn snapshot_bytes(&mut self) -> Result<Vec<u8>> {
        self.read_at(0, (self.page_count as usize) * self.page_size)
    }
}
