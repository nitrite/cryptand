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

use crate::codec;
use crate::container::{page_flags, page_type, Durability, PageHeader, PAGE_HEADER_BYTES, SUPERBLOCK_BYTES};
use crate::security::{KeyRing, AEAD_TAG_BYTES};
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

/// `14-security.md` §5.2 — the state a page write needs to encrypt: the ring,
/// and the half-open window of nonce values `10-transactions.md` §4.1 rule 1
/// has already published. The window lives here rather than in the engine
/// because the copy-on-write trees write pages with only a `&mut Pager` in
/// hand; a second cursor in the engine would be a second thing to keep true.
pub struct PageCrypto {
    pub ring: KeyRing,
    pub next: u64,
    pub limit: u64,
}

impl PageCrypto {
    /// Never wraps around and never re-issues: `Engine::ensure_nonces` is what
    /// widens the window, and running out is an error rather than a reuse.
    fn take(&mut self) -> Result<u64> {
        if self.next >= self.limit {
            return crate::error::invalid(
                "the published nonce window is exhausted; \
                 Engine::ensure_nonces must widen it before writing pages",
            );
        }
        let n = self.next;
        self.next += 1;
        Ok(n)
    }
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
    /// `01-container.md` §10 — this pager holds the exclusive writer lock.
    pub locked: bool,
    /// `01-container.md` §7's `page_codec`: the **default** for newly written
    /// pages, never a property of the file. A page's own state is in its
    /// `flags.COMPRESSED` and `codec`, so a file may hold a mixture and the
    /// default may change without a rewrite.
    pub page_codec: u8,
    /// `None` on an unencrypted database. `14-security.md` §5.1.
    pub crypto: Option<PageCrypto>,
    /// §8.3 — a converting file holds a mixture, and "that is the one place
    /// where a reassuring answer is a dangerous one", so both are counted at
    /// the only place that knows: the read path.
    pub encrypted_pages: u64,
    pub unencrypted_pages: u64,
}

impl Pager {
    /// Creates a new file, and **refuses to overwrite an existing one**.
    ///
    /// `create_new` rather than `create` + `truncate`: the earlier form
    /// silently destroyed a database on `cryptand create <an existing file>`,
    /// which is a plausible thing for an operator to type and is unrecoverable.
    /// The Java implementation already refused; this one and the Dart one did
    /// not, so two of three reference implementations lost the file.
    ///
    /// The check is here rather than in the caller because it must hold for
    /// every path into creation, and because `create_new` makes it atomic --
    /// an `exists()` test followed by an open is a race, and the race is
    /// between "someone else made this database" and "I deleted it".
    pub fn create(path: &Path, page_size: usize) -> Result<Pager> {
        check_page_size(page_size)?;
        let file = match OpenOptions::new().read(true).write(true).create_new(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return invalid(format!(
                    "{} already exists; use open (spec/01-container.md section 2)",
                    path.display()
                ))
            }
            Err(e) => return Err(e.into()),
        };
        take_writer_lock(&file, path)?;
        let mut p = Pager::new_common(page_size);
        p.file = Some(file);
        p.path = Some(path.to_path_buf());
        p.grow(2)?;
        Ok(p)
    }

    /// Opens for **writing**, which `01-container.md` §10 allows one process at
    /// a time. Use [`Pager::open_shared`] for a probe or a reader.
    pub fn open(path: &Path, page_size: usize, page_count: u64) -> Result<Pager> {
        let mut p = Pager::open_shared(path, page_size, page_count)?;
        take_writer_lock(p.file.as_ref().unwrap(), path)?;
        p.locked = true;
        Ok(p)
    }

    /// No writer lock: the superblock probe of `Engine::open` (which opens the
    /// same file twice before it knows the page size) and every read-only path.
    /// `flock` is per open file description, so a second descriptor in *this*
    /// process is refused exactly like another process's would be.
    pub fn open_shared(path: &Path, page_size: usize, page_count: u64) -> Result<Pager> {
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
            locked: false,
            page_codec: 0,
            crypto: None,
            encrypted_pages: 0,
            unencrypted_pages: 0,
        }
    }

    /// `14-security.md` §5.2 — the payload a page builder may fill. The AEAD
    /// tag has to be reserved *before* the cells are laid out: a page filled to
    /// `page_size - 40` has nowhere to put 16 more bytes, and discovering that
    /// at write time means a page that cannot be written at all.
    pub fn payload_cap(&self) -> usize {
        self.page_size - PAGE_HEADER_BYTES - self.tag_reserve()
    }

    pub fn tag_reserve(&self) -> usize {
        if self.crypto.is_some() {
            AEAD_TAG_BYTES
        } else {
            0
        }
    }

    pub fn is_file(&self) -> bool {
        self.file.is_some()
    }

    /// `01-container.md` §10 — the writer lock is held "for its writing
    /// lifetime", so `close()` gives it up. Dropping the descriptor is the
    /// release; nothing else can do it.
    pub fn release(&mut self) {
        self.file = None;
        self.locked = false;
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
        let raw = self.read_page_clear(page_id)?;
        // §5.2's read order: verify checksum, decrypt, then decompress.
        let plain = if self.crypto.is_some() { self.open_page(page_id, raw)? } else { raw };
        self.inflate_page(page_id, plain)
    }

    /// The page exactly as it is stored. `01-container.md` §9 step 8 — "without
    /// a key, steps 1–7 still run: that is the point of leaving headers in the
    /// clear" — is what this exists for, along with the value-log head page.
    pub fn read_page_clear(&mut self, page_id: u64) -> Result<Vec<u8>> {
        if page_id >= self.page_count {
            return corrupt(format!("page {page_id} is at or beyond page_count"));
        }
        self.page_reads += 1;
        self.read_at(page_id * self.page_size as u64, self.page_size)
    }

    /// Writes a header-bearing page, encrypting its payload when the database
    /// is encrypted (`14-security.md` §5.1's first row).
    pub fn write_page(&mut self, page_id: u64, page: &[u8]) -> Result<()> {
        if page.len() != self.page_size {
            return invalid(format!("page {page_id} is {} B, expected {}", page.len(), self.page_size));
        }
        self.page_writes += 1;
        // §7's order, and §5.2 restates it: compress, then encrypt. The other
        // order compresses ciphertext, which does not compress.
        let deflated = self.deflate_page(page)?;
        let page: &[u8] = deflated.as_deref().unwrap_or(page);
        if self.crypto.is_some() {
            let sealed = self.seal_page(page_id, page)?;
            return self.write_at(page_id * self.page_size as u64, &sealed);
        }
        self.write_at(page_id * self.page_size as u64, page)
    }

    /// §7 — compress a header-bearing page's payload, if the default codec is
    /// set and it is worth it.
    ///
    /// `Ok(None)` means "store it as it is", which is the answer for an
    /// incompressible page as well as for `page_codec = 0`. `payload_len`
    /// keeps the meaning §3 gives it — the uncompressed length — and
    /// `stored_len` becomes what the page actually holds.
    fn deflate_page(&self, page: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.page_codec == codec::NONE {
            return Ok(None);
        }
        let mut h = PageHeader::parse(page)?;
        // A value-log segment's head page is appended into after it is written
        // (§6.2), so its bytes are not a payload that can be rewritten; an
        // already-compressed or already-encrypted page is not ours to touch.
        //
        // And **a page belonging to a multi-page extent is never independently
        // compressed**: an extent is a contiguous byte range (§3 gives its
        // interior pages no header at all) and its reader addresses it by
        // offset rather than through the page seam. `write_extent` here goes
        // straight to `seal_page` and so never reaches this function, but the
        // guard is stated on the header rather than left to the call path --
        // the Dart implementation routes `writeExtent` through `write` and
        // compressed a segment head, which the other two could not then read.
        if h.compressed()
            || h.encrypted()
            || h.extent_pages > 1
            || h.page_type == page_type::VLOG_SEGMENT
        {
            return Ok(None);
        }
        let stored = h.stored();
        if stored == 0 || PAGE_HEADER_BYTES + stored > page.len() {
            return Ok(None);
        }
        let raw = &page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + stored];
        let compressed = match codec::compress(self.page_codec, raw)? {
            Some(c) => c,
            None => return Ok(None),
        };
        // Compressing then encrypting still has to leave room for the tag,
        // which is the whole of defect 59's rule; compression only ever helps
        // there, but the check is cheap and the alternative is a page that
        // cannot be written.
        let room = self.page_size - PAGE_HEADER_BYTES
            - if self.crypto.is_some() { AEAD_TAG_BYTES } else { 0 };
        if compressed.len() > room {
            return Ok(None);
        }
        let mut out = vec![0u8; self.page_size];
        out[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + compressed.len()]
            .copy_from_slice(&compressed);
        h.flags |= page_flags::COMPRESSED;
        h.codec = self.page_codec as u16;
        h.stored_len = compressed.len() as u32;
        h.write_into(&mut out);
        Ok(Some(out))
    }

    /// The read half of §7. The header a caller sees describes the plaintext it
    /// was handed, exactly as [`Pager::open_page`] does for the cipher.
    fn inflate_page(&self, page_id: u64, page: Vec<u8>) -> Result<Vec<u8>> {
        let h = match PageHeader::parse(&page) {
            Ok(h) => h,
            Err(_) => return Ok(page),
        };
        if !h.compressed() {
            return Ok(page);
        }
        // §5.2's read order is decrypt *then* decompress, so a page still
        // holding ciphertext is not a codec's business. This is reachable
        // without a bug: §5.1 keeps headers in the clear precisely so that a
        // keyless reader can verify structure and checksums, and such a reader
        // sees COMPRESSED set over bytes it cannot decrypt. Feeding those to
        // LZ4 is at best an error and at worst a decompression bomb from a
        // file someone else wrote.
        if h.encrypted() {
            return Ok(page);
        }
        let stored = h.stored();
        if PAGE_HEADER_BYTES + stored > page.len() {
            return corrupt(format!("page {page_id} declares {stored} stored bytes"));
        }
        let raw = codec::decompress(
            h.codec as u8,
            &page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + stored],
            h.payload_len as usize,
        )?;
        if PAGE_HEADER_BYTES + raw.len() > self.page_size {
            return corrupt(format!(
                "page {page_id} decompresses to {} bytes, past the page",
                raw.len()
            ));
        }
        let mut out = vec![0u8; self.page_size];
        out[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + raw.len()].copy_from_slice(&raw);
        let mut hh = h;
        hh.flags &= !page_flags::COMPRESSED;
        hh.codec = 0;
        hh.stored_len = 0;
        hh.write_into(&mut out);
        Ok(out)
    }

    /// §5.1 — the two page kinds that stay in the clear: a superblock (which
    /// never comes through here) and a value-log segment's head page, whose
    /// records are appended into its tail and are encrypted per record (§5.3).
    pub fn write_page_clear(&mut self, page_id: u64, page: &[u8]) -> Result<()> {
        if page.len() != self.page_size {
            return invalid(format!("page {page_id} is {} B, expected {}", page.len(), self.page_size));
        }
        self.page_writes += 1;
        self.write_at(page_id * self.page_size as u64, page)
    }

    /// §5.2: compress, then encrypt; the tag is appended to the ciphertext and
    /// the header — with `checksum` zeroed — is the AAD, so `page_type`,
    /// `flags`, `tree_id`, `commit_id`, `extent_pages`, `payload_len` and
    /// `nonce` cannot be edited without detection. The checksum is recomputed
    /// last, over the stored bytes (`00-conventions.md` §6).
    fn seal_page(&mut self, page_id: u64, page: &[u8]) -> Result<Vec<u8>> {
        let mut h = PageHeader::parse(page)?;
        // A page with no payload to protect, or one §5.1 leaves in the clear.
        if h.encrypted() || h.page_type == page_type::VLOG_SEGMENT {
            return Ok(page.to_vec());
        }
        let stored = h.stored();
        if stored == 0 || PAGE_HEADER_BYTES + stored + AEAD_TAG_BYTES > self.page_size {
            return invalid(format!(
                "page {page_id} holds {stored} payload bytes, which leaves no room \
                 for the {AEAD_TAG_BYTES}-byte AEAD tag in a {} B page",
                self.page_size
            ));
        }
        let counter = self.crypto.as_mut().unwrap().take()?;
        let mut out = vec![0u8; self.page_size];
        h.flags |= page_flags::ENCRYPTED;
        h.stored_len = (stored + AEAD_TAG_BYTES) as u32;
        h.nonce = counter;
        h.write_into(&mut out);
        let ct = {
            let ring = &self.crypto.as_ref().unwrap().ring;
            ring.encrypt_page(
                page_id,
                counter,
                &out[..PAGE_HEADER_BYTES],
                &page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + stored],
            )?
        };
        out[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + ct.len()].copy_from_slice(&ct);
        // `write_into` again, because the CRC covers the payload as stored.
        h.write_into(&mut out);
        Ok(out)
    }

    /// The read half of §5.2, and §8.3's mixture: an unencrypted page in an
    /// encrypted file is returned as it is and counted, never guessed at.
    fn open_page(&mut self, page_id: u64, page: Vec<u8>) -> Result<Vec<u8>> {
        let h = match PageHeader::parse(&page) {
            Ok(h) => h,
            Err(_) => return Ok(page),
        };
        if !h.encrypted() {
            self.unencrypted_pages += 1;
            return Ok(page);
        }
        self.encrypted_pages += 1;
        let stored = h.stored();
        if stored < AEAD_TAG_BYTES || PAGE_HEADER_BYTES + stored > page.len() {
            return corrupt(format!("page {page_id} declares {stored} stored bytes"));
        }
        let ring = match &self.crypto {
            Some(c) => &c.ring,
            None => return Err(crate::error::Error::CannotUnlock),
        };
        let pt = ring.decrypt_page(
            page_id,
            h.nonce,
            &page[..PAGE_HEADER_BYTES],
            &page[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + stored],
        )?;
        let mut out = vec![0u8; page.len()];
        out[..PAGE_HEADER_BYTES].copy_from_slice(&page[..PAGE_HEADER_BYTES]);
        out[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + pt.len()].copy_from_slice(&pt);
        // The header a caller sees describes the plaintext it was handed.
        let mut hh = h;
        hh.flags &= !page_flags::ENCRYPTED;
        // A compressed page is still compressed after it is decrypted, and
        // `inflate_page` needs its length. Zeroing this unconditionally --
        // which is what "same as payload_len" means -- handed the decompressor
        // the uncompressed length as the block length.
        hh.stored_len = if h.compressed() { pt.len() as u32 } else { 0 };
        hh.nonce = 0;
        hh.write_into(&mut out);
        Ok(out)
    }

    /// A whole extent, head page included.
    pub fn read_extent(&mut self, start_page: u64, pages: u32) -> Result<Vec<u8>> {
        self.page_reads += pages as u64;
        let raw =
            self.read_at(start_page * self.page_size as u64, pages as usize * self.page_size)?;
        if self.crypto.is_none() {
            return Ok(raw);
        }
        let mut out = Vec::with_capacity(raw.len());
        for i in 0..pages as u64 {
            let at = i as usize * self.page_size;
            let page = raw[at..at + self.page_size].to_vec();
            out.extend_from_slice(&self.open_page(start_page + i, page)?);
        }
        Ok(out)
    }

    /// The extent as stored, for the paths that must work without a key.
    pub fn read_extent_clear(&mut self, start_page: u64, pages: u32) -> Result<Vec<u8>> {
        self.page_reads += pages as u64;
        self.read_at(start_page * self.page_size as u64, pages as usize * self.page_size)
    }

    pub fn write_extent(&mut self, start_page: u64, bytes: &[u8]) -> Result<()> {
        if bytes.len() % self.page_size != 0 {
            return invalid("an extent must be a whole number of pages");
        }
        self.page_writes += (bytes.len() / self.page_size) as u64;
        if self.crypto.is_none() {
            return self.write_at(start_page * self.page_size as u64, bytes);
        }
        let mut out = Vec::with_capacity(bytes.len());
        for i in 0..(bytes.len() / self.page_size) as u64 {
            let at = i as usize * self.page_size;
            let sealed = self.seal_page(start_page + i, &bytes[at..at + self.page_size])?;
            out.extend_from_slice(&sealed);
        }
        self.write_at(start_page * self.page_size as u64, &out)
    }

    // ---------------------------------------------------------------------
    // `14-security.md` §5.4 — extents without page headers
    // ---------------------------------------------------------------------

    /// Plaintext bytes one chunk holds. Unencrypted a chunk *is* a page;
    /// encrypted it is `u64le counter || ciphertext || tag`.
    ///
    /// **The counter is per chunk and per write, not per extent, and this is a
    /// correction to §5.4.** §5.4 fixes a chunk's nonce at
    /// `1 || counter || head_page_id || i` with "`counter` … the extent's
    /// single allocated nonce value", which holds only if every chunk of the
    /// extent is written exactly once. A vector region breaks that on its
    /// first ordinary use: `stride` is far below `page_size`, so two slots
    /// share a chunk and are written at different times, and a slot may be
    /// rewritten outright. Same key, same nonce, two plaintexts — the failure
    /// §4 opens by calling "not a hardening measure; it is the whole thing".
    /// Storing the counter in the clear inside the chunk is what §5.3 already
    /// does for a value-log record, and for the same reason: it is what lets
    /// one chunk be decrypted without reading the rest.
    pub fn chunk_plain_bytes(&self) -> usize {
        if self.crypto.is_some() {
            self.page_size - 8 - AEAD_TAG_BYTES
        } else {
            self.page_size
        }
    }

    /// Physical pages an extent's data area needs for `plain_len` bytes.
    /// §5.4: an encrypted extent needs more pages than `ceil(len / page_size)`.
    pub fn extent_data_pages(&self, plain_len: u64) -> u64 {
        plain_len.div_ceil(self.chunk_plain_bytes() as u64)
    }

    /// Reads `len` plaintext bytes at `plain_off` within an extent's data area.
    pub fn read_extent_data(
        &mut self,
        head_page: u64,
        data_offset: u64,
        plain_off: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let base = head_page * self.page_size as u64 + data_offset;
        if self.crypto.is_none() {
            return self.read_at(base + plain_off, len);
        }
        let cps = self.chunk_plain_bytes() as u64;
        let mut out = Vec::with_capacity(len);
        let mut off = plain_off;
        while out.len() < len {
            let idx = off / cps;
            let within = (off % cps) as usize;
            let raw = self.read_at(base + idx * self.page_size as u64, self.page_size)?;
            let counter = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let pt = {
                let ring = &self.crypto.as_ref().unwrap().ring;
                ring.decrypt_chunk(head_page, counter, idx, &raw[8..])?
            };
            let take = (len - out.len()).min(pt.len().saturating_sub(within));
            if take == 0 {
                return corrupt(format!("extent chunk {idx} is short of the requested bytes"));
            }
            out.extend_from_slice(&pt[within..within + take]);
            off += take as u64;
        }
        Ok(out)
    }

    /// Writes plaintext bytes into an extent's data area. A partial chunk is a
    /// read-modify-write under a **fresh** counter: a chunk is one AEAD message
    /// and patching it in place would reuse its nonce.
    pub fn write_extent_data(
        &mut self,
        head_page: u64,
        data_offset: u64,
        plain_off: u64,
        buf: &[u8],
    ) -> Result<()> {
        let base = head_page * self.page_size as u64 + data_offset;
        if self.crypto.is_none() {
            return self.write_at(base + plain_off, buf);
        }
        let cps = self.chunk_plain_bytes();
        let mut written = 0usize;
        while written < buf.len() {
            let off = plain_off + written as u64;
            let idx = off / cps as u64;
            let within = (off % cps as u64) as usize;
            let take = (buf.len() - written).min(cps - within);
            let at = base + idx * self.page_size as u64;
            let mut chunk = vec![0u8; cps];
            if within != 0 || take != cps {
                if let Ok(raw) = self.read_at(at, self.page_size) {
                    let old = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                    if old != 0 {
                        let ring = &self.crypto.as_ref().unwrap().ring;
                        if let Ok(pt) = ring.decrypt_chunk(head_page, old, idx, &raw[8..]) {
                            let n = pt.len().min(cps);
                            chunk[..n].copy_from_slice(&pt[..n]);
                        }
                    }
                }
            }
            chunk[within..within + take].copy_from_slice(&buf[written..written + take]);
            let counter = self.crypto.as_mut().unwrap().take()?;
            let ct = {
                let ring = &self.crypto.as_ref().unwrap().ring;
                ring.encrypt_chunk(head_page, counter, idx, &chunk)?
            };
            let mut page = Vec::with_capacity(self.page_size);
            page.extend_from_slice(&counter.to_le_bytes());
            page.extend_from_slice(&ct);
            page.resize(self.page_size, 0);
            self.write_at(at, &page)?;
            written += take;
        }
        Ok(())
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

/// `01-container.md` §10 — "one writing **process** per database, enforced by
/// an exclusive advisory lock on the database file (`flock` / `LockFileEx`)
/// held for its writing lifetime", and "a second process opening for writing
/// MUST fail with a clear 'locked by another process' error and MUST NOT fall
/// back to opening anyway".
///
/// The lock lives on the open file description, so it is released when the
/// `File` is dropped — including when the process dies, which is what makes a
/// crashed writer's database openable again with no cleanup step.
fn take_writer_lock(file: &File, path: &Path) -> Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(crate::error::Error::Locked(format!(
            "{} is open for writing by another process",
            path.display()
        ))),
        // §10: "An implementation MUST NOT assume the lock survives a network
        // filesystem." A filesystem that cannot lock is reported, never
        // silently treated as unlocked.
        Err(e) => Err(crate::error::Error::Locked(format!(
            "{} could not be locked ({e}); a network filesystem cannot be \
             opened for writing safely",
            path.display()
        ))),
    }
}
