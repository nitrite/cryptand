/// Copy-on-write B+trees: the reserved trees of `spec/05-catalog.md` §2.
///
/// `spec/04-segments.md` §3.3 is the whole rationale: trees 0–15 are **not**
/// levelled segment sets. They are small, hot and almost entirely cached, and
/// levelling them would mean the manifest needed a manifest. They use the page
/// format of §2.2 — the same encoder, [encodeNodePage] — written
/// copy-on-write: a write copies the path from leaf to root, appends the
/// copied pages, and publishes a new root.
///
/// **What this file simplifies, stated rather than hidden.** An underfull page
/// is never merged with a sibling — only an empty one is unlinked, and a root
/// with one child is collapsed. That is a space effect, not a correctness one.
/// Freed pages *are* reclaimed: [PageStore] keeps §6's free tree, best-fits
/// from it among extents at or below `min_retained_commit`, and extends the
/// file only when nothing fits.
library;

import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'bytes.dart';
import 'container.dart';
import 'security.dart';
import 'cke.dart';
import 'limits.dart';
import 'lz4.dart';
import 'errors.dart';
import 'segment.dart';

/// The file's page space: allocate, read, write.
///
/// In memory, like the segment extents of phase 2 — `REPORT.md` §5 states the
/// limit that follows and it is unchanged here. Page *identity* and page
/// *granularity* are real, which is what the counters measure.
/// `spec/14-security.md` §5.2 — what a page write needs in order to encrypt:
/// the ring, and the half-open window of nonce values §4.1 rule 1 has already
/// published. It lives on the store, not on the engine, because the
/// copy-on-write trees write pages with only a [PageStore] in hand; a second
/// cursor elsewhere would be a second thing to keep true.
final class PageCrypto {
  PageCrypto(this.ring, this.nonces);

  final KeyRing ring;
  final NonceAllocator nonces;
}

/// `spec/01-container.md` §6 — one entry of the free tree (tree 1), keyed
/// `(commit_id, start_page)` so a scan from the beginning yields the oldest,
/// most reclaimable extents first.
final class FreeExtent {
  const FreeExtent(this.commitId, this.startPage, this.pages);

  final int commitId;
  final int startPage;
  final int pages;
}

final class PageStore {
  PageStore({this.pageSize = 4096}) {
    checkPageSize(pageSize);
    // `spec/01-container.md` §1: page 0 is superblock slot A and page 1 is
    // slot B. Both are reserved before anything else is allocated, so a page
    // id means the same thing in memory as it does in a file.
    _pages
      ..add(Uint8List(pageSize))
      ..add(Uint8List(pageSize));
    _pageCount = 2;
  }

  /// Rebuilds a store from the bytes of a file, for `DatabaseFile.open`.
  factory PageStore.fromBytes(Uint8List bytes, {required int pageSize}) {
    checkPageSize(pageSize);
    final s = PageStore(pageSize: pageSize);
    s._pages.clear();
    for (var at = 0; at + pageSize <= bytes.length; at += pageSize) {
      s._pages.add(Uint8List.fromList(
          Uint8List.sublistView(bytes, at, at + pageSize)));
    }
    s._pageCount = s._pages.length;
    return s;
  }

  /// A store backed by an open file. [file] is positioned by page id; the
  /// store never holds the whole page space in memory, which is the difference
  /// between a database and a buffer that happens to be saved.
  PageStore.onFile(this.file, {required this.pageSize, required int pageCount})
      : _pageCount = pageCount {
    checkPageSize(pageSize);
  }

  final int pageSize;

  /// `null` in memory mode. Not owned: whoever opened it closes it, and on a
  /// writing store that close is what releases `spec/01-container.md` §10's
  /// exclusive advisory lock.
  RandomAccessFile? file;

  final List<Uint8List> _pages = [];
  int _pageCount = 0;

  /// §6's free tree, in memory. Keyed `(commit_id, start_page)`.
  final SplayTreeMap<(int, int), int> _free = SplayTreeMap((a, b) =>
      a.$1 != b.$1 ? a.$1.compareTo(b.$1) : a.$2.compareTo(b.$2));

  /// §6's reclamation rule: "an extent freed at `commit_id = N` may be
  /// reallocated once `N <= min_retained_commit`". Until a caller sets this,
  /// nothing is reclaimable, which is the safe direction.
  int minRetainedCommit = 0;

  /// The commit a `free()` is attributed to. Starts at 1 for the same reason
  /// [Engine.commitId] does: commit 0 is the empty database nothing wrote.
  int commitId = 1;

  /// §5.2's page cipher. `null` on an unencrypted database.
  PageCrypto? crypto;

  /// `spec/01-container.md` §7's `page_codec`: the **default** for newly
  /// written pages, never a property of the file. A page's own state is in its
  /// `flags.COMPRESSED` and `codec_or_reserved`, so a file may hold a mixture
  /// and the default may change without a rewrite.
  int pageCodec = Codec.none;

  int pageReads = 0;
  int pageWrites = 0;

  /// §8.3 of `spec/14-security.md` — a converting file holds a mixture, and
  /// "that is the one place where a reassuring answer is a dangerous one", so
  /// both are counted where a page's own flag says which it is.
  int encryptedPages = 0;
  int unencryptedPages = 0;

  int get pageCount => _pageCount;

  /// Extents the free tree holds, whether or not they are reclaimable yet.
  Iterable<FreeExtent> get freeExtents =>
      _free.entries.map((e) => FreeExtent(e.key.$1, e.key.$2, e.value));

  int get freedPages =>
      _free.values.fold(0, (a, b) => a + b);

  /// Bytes the store has allocated, live and orphaned alike.
  int get allocatedBytes => _pageCount * pageSize;

  void resetCounters() {
    pageReads = 0;
    pageWrites = 0;
  }

  /// §5.2 — the payload a page builder may fill. The AEAD tag has to be
  /// reserved *before* the cells are laid out: a page filled to
  /// `page_size - 40` has nowhere to put 16 more bytes, and discovering that
  /// at write time means a page that cannot be written at all.
  int get tagReserve => crypto == null ? 0 : 16;

  int get payloadCap => pageSize - PageHeader.size - tagReserve;

  int alloc() => allocExtent(1);

  /// `spec/01-container.md` §6: allocation unit is the **extent** — one or more
  /// contiguous pages. Returns the first page id.
  ///
  /// Allocation order is §6's: "best-fit from the free tree among extents with
  /// `commit_id <= min_retained_commit`; failing that, extend the file at
  /// `page_count`."
  int allocExtent(int pages) {
    (int, int)? bestKey;
    var bestPages = 1 << 62;
    for (final e in _free.entries) {
      // §6's reclamation rule, and the invariant under it stated where it is
      // enforced rather than left to the caller: an extent freed by a commit
      // that is still the newest one is still named by the live superblock,
      // and "no page that a live superblock references is ever overwritten".
      if (e.key.$1 > minRetainedCommit || e.key.$1 >= commitId) continue;
      if (e.value >= pages && e.value < bestPages) {
        bestKey = e.key;
        bestPages = e.value;
        if (e.value == pages) break;
      }
    }
    if (bestKey != null) {
      _free.remove(bestKey);
      final start = bestKey.$2;
      if (bestPages > pages) {
        // The remainder goes straight back, at the same commit id.
        _free[(bestKey.$1, start + pages)] = bestPages - pages;
      }
      for (var i = 0; i < pages; i++) {
        _zero(start + i);
      }
      return start;
    }
    final start = _pageCount;
    _grow(pages);
    return start;
  }

  /// One page at the end of the file, never out of the free list. For the
  /// tree that records the free list: see [CowTree.rebuildFresh].
  int allocFresh() {
    final start = _pageCount;
    _grow(1);
    return start;
  }

  void _grow(int pages) {
    if (file == null) {
      for (var i = 0; i < pages; i++) {
        _pages.add(Uint8List(pageSize));
      }
      _pageCount = _pages.length;
      return;
    }
    _pageCount += pages;
    final want = _pageCount * pageSize;
    if (file!.lengthSync() < want) file!.truncateSync(want);
  }

  void _zero(int pageId) {
    if (file == null) {
      _pages[pageId] = Uint8List(pageSize);
    } else {
      file!
        ..setPositionSync(pageId * pageSize)
        ..writeFromSync(Uint8List(pageSize));
    }
  }

  /// §6 — records a freed extent under the committing `commit_id`. It becomes
  /// reallocatable only once that id is at or below [minRetainedCommit].
  void freeExtent(int startPage, int pages) {
    if (startPage < 2 || pages <= 0) return;
    _free[(commitId, startPage)] = pages;
  }

  void free(int pageId) {
    if (pageId != 0) freeExtent(pageId, 1);
  }

  /// Replaces the free tree, for a reopen that reads tree 1 back.
  void loadFree(Iterable<FreeExtent> extents) {
    _free.clear();
    for (final e in extents) {
      _free[(e.commitId, e.startPage)] = e.pages;
    }
  }

  /// Used after a reopen: the file may be longer than `page_count`, and
  /// everything at or beyond it is debris from an interrupted commit
  /// (`spec/01-container.md` §2.1 step 7).
  void setPageCount(int pageCount) {
    _pageCount = pageCount;
  }

  /// Writes a whole extent, head page first. The bytes MUST be a whole number
  /// of pages.
  void writeExtent(int startPage, Uint8List extent) {
    if (extent.length % pageSize != 0) {
      throw const InvalidArgumentException(
          'an extent must be a whole number of pages');
    }
    for (var i = 0; i * pageSize < extent.length; i++) {
      writeInExtent(startPage + i,
          Uint8List.sublistView(extent, i * pageSize, (i + 1) * pageSize));
    }
  }

  /// A whole extent with no page cipher: `spec/14-security.md` section 5.1
  /// leaves a value-log segment's head page in the clear, and its interior
  /// pages hold raw records with no page header at all
  /// (`spec/01-container.md` section 3), so neither can go through the page
  /// seam. Their confidentiality comes from section 5.3, per record.
  void writeExtentClear(int startPage, Uint8List extent) {
    if (extent.length % pageSize != 0) {
      throw const InvalidArgumentException(
          'an extent must be a whole number of pages');
    }
    for (var i = 0; i * pageSize < extent.length; i++) {
      writeClear(startPage + i,
          Uint8List.sublistView(extent, i * pageSize, (i + 1) * pageSize));
    }
  }

  /// 14 §9.1 (F-107): an extent named by the file never sizes an allocation
  /// past the page space.
  void _checkExtent(int startPage, int pages) {
    if (startPage < 0 || pages < 0 || startPage + pages > _pageCount) {
      throw CorruptionException(
          'extent $startPage+$pages is past the $_pageCount-page file');
    }
  }

  Uint8List readExtentClear(int startPage, int pages) {
    _checkExtent(startPage, pages);
    final out = Uint8List(pages * pageSize);
    for (var i = 0; i < pages; i++) {
      out.setRange(i * pageSize, (i + 1) * pageSize, readClear(startPage + i));
    }
    return out;
  }

  Uint8List readExtent(int startPage, int pages) {
    _checkExtent(startPage, pages);
    final out = Uint8List(pages * pageSize);
    for (var i = 0; i < pages; i++) {
      out.setRange(i * pageSize, (i + 1) * pageSize, read(startPage + i));
    }
    return out;
  }

  /// The whole page space, for a file written in one go.
  Uint8List toBytes() {
    final out = Uint8List(_pageCount * pageSize);
    if (file == null) {
      for (var i = 0; i < _pages.length; i++) {
        out.setRange(i * pageSize, (i + 1) * pageSize, _pages[i]);
      }
      return out;
    }
    for (var i = 0; i < _pageCount; i++) {
      out.setRange(i * pageSize, (i + 1) * pageSize, _rawRead(i));
    }
    return out;
  }

  Uint8List _rawRead(int pageId) {
    if (file == null) return _pages[pageId];
    final buf = Uint8List(pageSize);
    file!
      ..setPositionSync(pageId * pageSize)
      ..readIntoSync(buf);
    return buf;
  }

  void _rawWrite(int pageId, Uint8List page) {
    if (file == null) {
      _pages[pageId] = page;
      return;
    }
    file!
      ..setPositionSync(pageId * pageSize)
      ..writeFromSync(page);
  }

  Uint8List read(int pageId) {
    final raw = readClear(pageId);
    // §5.2's read order: verify checksum, decrypt, then decompress.
    final plain = crypto == null ? raw : _openPage(pageId, raw);
    return _inflatePage(pageId, plain);
  }

  /// The page exactly as it is stored. `spec/01-container.md` §9 step 8 —
  /// "without a key, steps 1–7 still run: that is the point of leaving headers
  /// in the clear" — is what this exists for, along with the value-log head
  /// page, which §5.1 leaves in the clear.
  Uint8List readClear(int pageId) {
    if (pageId < 1 || pageId >= _pageCount) {
      throw CorruptionException('page $pageId is outside the store');
    }
    pageReads++;
    return _rawRead(pageId);
  }

  void write(int pageId, Uint8List page) {
    if (page.length != pageSize) {
      throw InvalidArgumentException(
          'page $pageId is ${page.length} B, expected $pageSize');
    }
    pageWrites++;
    // §7's order, and §5.2 restates it: compress, then encrypt. The other
    // order compresses ciphertext, which does not compress.
    final deflated = _deflatePage(page) ?? page;
    _rawWrite(pageId, crypto == null ? deflated : _sealPage(pageId, deflated));
  }

  /// A page that belongs to a multi-page extent: encrypted like any other, and
  /// **never compressed**.
  ///
  /// An extent is a contiguous byte range. `spec/01-container.md` §3 gives its
  /// interior pages no header at all, and a reader may hold the whole extent
  /// and parse pages at fixed offsets rather than fetching them one at a time
  /// — which one of the three implementations does. Compressing a page inside
  /// one moves every byte after its header without telling that reader, and
  /// the failure is "segment header magic mismatch" in the *other* language,
  /// several steps later.
  void writeInExtent(int pageId, Uint8List page) {
    if (page.length != pageSize) {
      throw InvalidArgumentException(
          'page $pageId is ${page.length} B, expected $pageSize');
    }
    pageWrites++;
    _rawWrite(pageId, crypto == null ? page : _sealPage(pageId, page));
  }

  /// §7 — compress a header-bearing page's payload, if the default codec is
  /// set and it is worth it. `null` means "store it as it is", which is the
  /// answer for an incompressible page as well as for `page_codec = 0`.
  ///
  /// `payload_len` keeps the meaning §3 gives it — the uncompressed length —
  /// and `stored_len` becomes what the page actually holds.
  Uint8List? _deflatePage(Uint8List page) {
    if (pageCodec == Codec.none) return null;
    final PageHeader h;
    try {
      h = PageHeader.read(page);
    } on CorruptionException {
      return null;
    }
    // A value-log segment's head page is appended into after it is written
    // (§6.2), so its bytes are not a payload that can be rewritten; an
    // already-compressed or already-encrypted page is not ours to touch.
    //
    // And **a page belonging to a multi-page extent is never independently
    // compressed**: an extent is a contiguous byte range (§3 gives its interior
    // pages no header at all), and its reader addresses it by offset rather
    // than through the page seam, so compressing its head page moves every
    // byte after the header without telling anyone. This is a header check
    // rather than a call-path rule on purpose -- `writeExtent` routing through
    // `write` is exactly how it was got wrong, and a check the caller cannot
    // bypass is the only kind that survives that.
    if (h.isCompressed ||
        h.isEncrypted ||
        h.extentPages > 1 ||
        h.pageType == PageType.vlogSegment) {
      return null;
    }
    final stored = h.stored;
    if (stored == 0 || PageHeader.size + stored > page.length) return null;
    final raw = Uint8List.sublistView(page, PageHeader.size,
        PageHeader.size + stored);
    final compressed = compressPayload(pageCodec, raw);
    if (compressed == null) return null;
    // Compressing then encrypting still has to leave room for the tag, which
    // is defect 59's rule. Compression only ever helps there, but the check is
    // cheap and the alternative is a page that cannot be written.
    if (compressed.length > pageSize - PageHeader.size - tagReserve) {
      return null;
    }
    final out = Uint8List(pageSize);
    out.setRange(PageHeader.size, PageHeader.size + compressed.length,
        compressed);
    PageHeader(
      pageType: h.pageType,
      flags: h.flags | PageFlags.compressed,
      codecOrReserved: pageCodec,
      treeId: h.treeId,
      commitId: h.commitId,
      extentPages: h.extentPages,
      payloadLen: h.payloadLen,
      storedLen: compressed.length,
      nonce: h.nonce,
    ).writeInto(out);
    return out;
  }

  /// The read half of §7. The header a caller sees describes the plaintext it
  /// was handed, exactly as [_openPage] does for the cipher.
  Uint8List _inflatePage(int pageId, Uint8List page) {
    final PageHeader h;
    try {
      h = PageHeader.read(page, pageId: pageId);
    } on CorruptionException {
      return page;
    }
    if (!h.isCompressed) return page;
    // §5.2's read order is decrypt *then* decompress, so a page still holding
    // ciphertext is not a codec's business. Reachable without a bug: §5.1
    // keeps headers in the clear precisely so a keyless reader can verify
    // structure and checksums, and such a reader sees COMPRESSED set over
    // bytes it cannot decrypt. Feeding those to LZ4 is at best an error and at
    // worst a decompression bomb from a file someone else wrote.
    if (h.isEncrypted) return page;
    final stored = h.stored;
    if (PageHeader.size + stored > page.length) {
      throw CorruptionException('page $pageId declares $stored stored bytes',
          pageId: pageId);
    }
    final raw = decompressPayload(
        h.codecOrReserved,
        Uint8List.sublistView(
            page, PageHeader.size, PageHeader.size + stored),
        h.payloadLen);
    if (PageHeader.size + raw.length > pageSize) {
      throw CorruptionException(
          'page $pageId decompresses to ${raw.length} bytes, past the page',
          pageId: pageId);
    }
    final out = Uint8List(pageSize);
    out.setRange(PageHeader.size, PageHeader.size + raw.length, raw);
    PageHeader(
      pageType: h.pageType,
      flags: h.flags & ~PageFlags.compressed,
      codecOrReserved: 0,
      treeId: h.treeId,
      commitId: h.commitId,
      extentPages: h.extentPages,
      payloadLen: h.payloadLen,
      nonce: h.nonce,
    ).writeInto(out);
    return out;
  }

  /// §5.1's two clear page kinds: a superblock, which never comes through
  /// here, and a value-log segment's head page, whose records are appended
  /// into its tail and encrypted one by one (§5.3).
  void writeClear(int pageId, Uint8List page) {
    if (page.length != pageSize) {
      throw InvalidArgumentException(
          'page $pageId is ${page.length} B, expected $pageSize');
    }
    pageWrites++;
    _rawWrite(pageId, page);
  }

  /// §5.2: compress, then encrypt; the tag is appended to the ciphertext and
  /// the header — checksum zeroed — is the AAD. The checksum is recomputed
  /// last, over the stored bytes (`spec/00-conventions.md` §6).
  Uint8List _sealPage(int pageId, Uint8List page) {
    final h = PageHeader.read(page, pageId: pageId);
    if (h.isEncrypted || h.pageType == PageType.vlogSegment) return page;
    final stored = h.stored;
    if (stored == 0 || PageHeader.size + stored + 16 > pageSize) {
      throw InvalidArgumentException(
          'page $pageId holds $stored payload bytes, which leaves no room for '
          'the 16-byte AEAD tag in a $pageSize B page');
    }
    final counter = crypto!.nonces.allocate();
    final out = Uint8List(pageSize);
    final sealedHeader = PageHeader(
      pageType: h.pageType,
      flags: h.flags | PageFlags.encrypted,
      codecOrReserved: h.codecOrReserved,
      treeId: h.treeId,
      commitId: h.commitId,
      extentPages: h.extentPages,
      payloadLen: h.payloadLen,
      storedLen: stored + 16,
      nonce: counter,
    )..writeInto(out);
    final ct = encryptPagePayload(
      keys: crypto!.ring,
      pageId: pageId,
      nonceCounter: counter,
      pageHeader40: Uint8List.sublistView(out, 0, PageHeader.size),
      payload: Uint8List.sublistView(page, PageHeader.size,
          PageHeader.size + stored),
    );
    out.setRange(PageHeader.size, PageHeader.size + ct.length, ct);
    // Again, because the CRC covers the payload as stored.
    sealedHeader.writeInto(out);
    return out;
  }

  /// The read half of §5.2. §8.3's mixture: an unencrypted page in an
  /// encrypted file is returned as it is and counted, never guessed at.
  Uint8List _openPage(int pageId, Uint8List page) {
    final PageHeader h;
    try {
      h = PageHeader.read(page, pageId: pageId);
    } on CorruptionException {
      return page;
    }
    if (!h.isEncrypted) {
      unencryptedPages++;
      return page;
    }
    encryptedPages++;
    final stored = h.stored;
    if (stored < 16 || PageHeader.size + stored > page.length) {
      throw CorruptionException('page $pageId declares $stored stored bytes',
          pageId: pageId);
    }
    final pt = decryptPagePayload(
      keys: crypto!.ring,
      pageId: pageId,
      nonceCounter: h.nonce,
      pageHeader40: Uint8List.sublistView(page, 0, PageHeader.size),
      sealed: Uint8List.sublistView(
          page, PageHeader.size, PageHeader.size + stored),
    );
    final out = Uint8List(page.length);
    out.setRange(PageHeader.size, PageHeader.size + pt.length, pt);
    // The header a caller sees describes the plaintext it was handed. A
    // *compressed* page is still compressed after it is decrypted, and
    // `_inflatePage` needs its block length: leaving `storedLen` at 0 -- which
    // is what "same as payload_len" means -- would hand the decompressor the
    // uncompressed length as the block length.
    PageHeader(
      pageType: h.pageType,
      flags: h.flags & ~PageFlags.encrypted,
      codecOrReserved: h.codecOrReserved,
      treeId: h.treeId,
      commitId: h.commitId,
      extentPages: h.extentPages,
      payloadLen: h.payloadLen,
      storedLen: h.isCompressed ? pt.length : 0,
    ).writeInto(out);
    return out;
  }

  /// `spec/10-transactions.md` §7 — the strongest primitive the platform
  /// provides. Reported, never assumed.
  void sync() {
    file?.flushSync();
  }
}

/// One node held for editing: the decoded form of a §2.2 page.
final class _Node {
  _Node(this.isLeaf, this.keys, this.payloads);

  final bool isLeaf;
  final List<Uint8List> keys;
  final List<Uint8List> payloads;

  int get count => keys.length;

  /// `subtree_entries`, which is what makes `skip(n)` cost O(height) (§2.2).
  int get subtreeEntries {
    if (isLeaf) return keys.length;
    var n = 0;
    for (final p in payloads) {
      n += childOf(p).$2;
    }
    return n;
  }

  static _Node decode(Uint8List page, int pageId) {
    final n = Node(page, pageId);
    final keys = <Uint8List>[];
    final payloads = <Uint8List>[];
    for (var i = 0; i < n.cellCount; i++) {
      keys.add(n.keyAt(i));
      final r = n.payloadAt(i);
      if (n.isLeaf) {
        final kindFlags = r.u8();
        if (kindFlags & 0x0F != ValueKind.inline) {
          throw CorruptionException(
              'copy-on-write leaf cell $i has value_kind ${kindFlags & 0x0F}; '
              'reserved trees hold inline values only');
        }
        payloads.add(leafPayload(r.bytesCopy(r.uvar())));
      } else {
        final child = r.u64();
        final entries = r.u64();
        payloads.add(childPayload(child, entries));
      }
    }
    return _Node(n.isLeaf, keys, payloads);
  }

  /// A leaf cell payload: `u8 kind_flags = INLINE || uvar len || value`.
  static Uint8List leafPayload(Uint8List value) => (ByteWriter(value.length + 6)
        ..u8(ValueKind.inline)
        ..uvar(value.length)
        ..bytes(value))
      .takeBytes();

  static Uint8List childPayload(int page, int entries) =>
      (ByteWriter(16)..u64(page)..u64(entries)).takeBytes();

  static Uint8List valueOf(Uint8List payload) {
    final r = ByteReader(payload)..u8();
    return r.bytesCopy(r.uvar());
  }

  static (int, int) childOf(Uint8List payload) {
    final r = ByteReader(payload);
    return (r.u64(), r.u64());
  }
}

/// A reserved tree: a copy-on-write B+tree over [store].
///
/// [root] is the published root page id; 0 means the tree is empty, which is
/// what an unset superblock root field says.
final class CowTree {
  CowTree(this.store, {required this.treeId, this.root = 0});

  final PageStore store;
  final int treeId;
  int root;

  /// Pages written since the last [resetCounters], i.e. the copy-on-write
  /// cost of the edits made. A path copy is `height` pages, not one.
  int pagesCopied = 0;

  void resetCounters() {
    pagesCopied = 0;
    store.resetCounters();
  }

  bool get isEmpty => root == 0;

  int get entryCount =>
      root == 0 ? 0 : _load(root).subtreeEntries;

  _Node _load(int pageId) => _Node.decode(store.read(pageId), pageId);

  int _write(_Node n) => _writeAt(store.alloc(), n);

  int _writeAt(int id, _Node n) {
    store.write(
        id,
        encodeNodePage(
          pageSize: store.pageSize,
          payloadSize: store.payloadCap,
          isLeaf: n.isLeaf,
          keys: n.keys,
          payloads: n.payloads,
          subtreeEntries: n.subtreeEntries,
          treeId: treeId,
        ));
    pagesCopied++;
    return id;
  }

  // -------------------------------------------------------------------------
  // Reading
  // -------------------------------------------------------------------------

  Uint8List? get(Uint8List key) {
    if (root == 0) return null;
    var pageId = root;
    for (var depth = 0;; depth++) {
      _checkDepth(depth, pageId);
      final n = _load(pageId);
      if (n.isLeaf) {
        final i = _find(n.keys, key);
        return i < 0 ? null : _Node.valueOf(n.payloads[i]);
      }
      pageId = _Node.childOf(n.payloads[_descend(n.keys, key)]).$1;
    }
  }

  /// Every entry in `[lower, upper)`, in key order.
  ///
  /// A generator rather than a cursor: §8 makes cursors the only iteration
  /// mechanism over *segments*, where an O(1) `next` is what fixes the paged
  /// scan of `research/nitrite-survey.md` §7. A reserved tree is bounded and
  /// cached, and a recursive walk over it is the same asymptotics with a
  /// tenth of the code.
  Iterable<(Uint8List, Uint8List)> scan(
      {Uint8List? lower, Uint8List? upper}) sync* {
    if (root == 0) return;
    yield* _walk(root, lower, upper, 0, <int>{});
  }

  /// F-113: child pointers come from the file, so every descent is bounded;
  /// a pointer back up would otherwise loop or recurse forever.
  void _checkDepth(int depth, int pageId) {
    if (depth > 100) {
      throw CorruptionException(
          'tree $treeId is deeper than 100 pages at page $pageId; a copy-on-'
          'write tree that deep is a cycle');
    }
  }

  /// F-113: a tree reaches each page once; shared children would make a walk
  /// exponential in the height.
  void _visit(Set<int> seen, int pageId) {
    if (!seen.add(pageId)) {
      throw CorruptionException('tree $treeId reaches page $pageId twice');
    }
  }

  /// Every page this tree occupies, internal and leaf.
  ///
  /// `spec/01-container.md` section 9 step 7 — "reconcile reachable pages
  /// against the free tree and report leaks (neither reachable nor free) and
  /// double-allocations". A verifier cannot do that without asking each tree
  /// which pages it holds, and there was no way to ask.
  Iterable<int> reachablePages() sync* {
    if (root == 0) return;
    yield* _reachable(root, 0, <int>{});
  }

  Iterable<int> _reachable(int pageId, int depth, Set<int> seen) sync* {
    // A cyclic or wildly deep tree is a hostile file's cheapest denial of
    // service, and this walk is reachable from `verify` on a file the caller
    // did not write. The bound is the same one section 8 of
    // `00-conventions.md` puts on nesting.
    if (depth > 100) {
      throw CorruptionException(
          'tree $treeId is deeper than 100 pages at page $pageId; a copy-on-'
          'write tree that deep is a cycle');
    }
    _visit(seen, pageId);
    yield pageId;
    final n = _load(pageId);
    if (n.isLeaf) return;
    for (var i = 0; i < n.count; i++) {
      yield* _reachable(_Node.childOf(n.payloads[i]).$1, depth + 1, seen);
    }
  }

  Iterable<(Uint8List, Uint8List)> _walk(int pageId, Uint8List? lower,
      Uint8List? upper, int depth, Set<int> seen) sync* {
    _checkDepth(depth, pageId);
    _visit(seen, pageId);
    final n = _load(pageId);
    if (n.isLeaf) {
      for (var i = 0; i < n.count; i++) {
        final k = n.keys[i];
        if (lower != null && compareKeys(k, lower) < 0) continue;
        if (upper != null && compareKeys(k, upper) >= 0) return;
        yield (k, _Node.valueOf(n.payloads[i]));
      }
      return;
    }
    final start = lower == null ? 0 : _descend(n.keys, lower);
    for (var i = start; i < n.count; i++) {
      // Separators are lower bounds on their subtree, so a child whose
      // separator is already at or past `upper` holds nothing in range.
      if (upper != null && i > start && compareKeys(n.keys[i], upper) >= 0) {
        return;
      }
      yield* _walk(
          _Node.childOf(n.payloads[i]).$1, lower, upper, depth + 1, seen);
    }
  }

  /// Index of [key], or `-1`.
  static int _find(List<Uint8List> keys, Uint8List key) {
    var lo = 0, hi = keys.length - 1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      final c = compareKeys(keys[mid], key);
      if (c == 0) return mid;
      if (c < 0) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return -1;
  }

  /// Insertion point: the first index whose key is >= [key].
  static int _lowerBound(List<Uint8List> keys, Uint8List key) {
    var lo = 0, hi = keys.length;
    while (lo < hi) {
      final mid = (lo + hi) >> 1;
      if (compareKeys(keys[mid], key) < 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /// The child to descend into: the last separator <= [key], clamped to 0.
  ///
  /// The clamp is what lets a separator be a child's exact minimum key rather
  /// than an artificial `UNBOUNDED_BELOW`: a key below every separator still
  /// belongs in the leftmost subtree, and after it is inserted there that
  /// subtree's minimum is simply lower than its separator. The invariant the
  /// descent needs is only that a separator never *exceeds* its subtree's
  /// minimum.
  static int _descend(List<Uint8List> keys, Uint8List key) {
    var lo = 0, hi = keys.length - 1, ans = -1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      if (compareKeys(keys[mid], key) <= 0) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans < 0 ? 0 : ans;
  }

  // -------------------------------------------------------------------------
  // Writing
  // -------------------------------------------------------------------------

  void put(Uint8List key, Uint8List value) =>
      _edit(key, _Node.leafPayload(value));

  bool remove(Uint8List key) {
    if (root == 0) return false;
    if (get(key) == null) return false;
    _edit(key, null);
    return true;
  }

  /// Inserts, replaces or removes one key and republishes the root.
  void _edit(Uint8List key, Uint8List? payload) {
    if (root == 0) {
      if (payload == null) return;
      // Through _publish, not straight to _write: a first entry too large for
      // a page must be refused by the same check every later one meets.
      _publish([(0, _Node(true, [Uint8List.fromList(key)], [payload]), -1)]);
      return;
    }

    // Descend, remembering the pages to copy on the way back up.
    final path = <(int, _Node, int)>[]; // (pageId, node, childIndex)
    var pageId = root;
    while (true) {
      _checkDepth(path.length, pageId);
      final n = _load(pageId);
      if (n.isLeaf) {
        path.add((pageId, n, -1));
        break;
      }
      final i = _descend(n.keys, key);
      path.add((pageId, n, i));
      pageId = _Node.childOf(n.payloads[i]).$1;
    }

    final leaf = path.last.$2;
    final at = _lowerBound(leaf.keys, key);
    final hit = at < leaf.count && compareKeys(leaf.keys[at], key) == 0;
    if (payload == null) {
      if (!hit) return;
      leaf.keys.removeAt(at);
      leaf.payloads.removeAt(at);
    } else if (hit) {
      leaf.payloads[at] = payload;
    } else {
      leaf.keys.insert(at, Uint8List.fromList(key));
      leaf.payloads.insert(at, payload);
    }

    _publish(path);
  }

  /// Writes the copied path back up, splitting where a page no longer fits.
  void _publish(List<(int, _Node, int)> path) {
    var level = path.length - 1;
    var replacements = _split(path[level].$2);
    store.free(path[level].$1);

    while (level > 0) {
      // An emptied page is unlinked, not written: writing it first allocated
      // a page nothing referenced or freed (F-065).
      final children = [
        for (final n in replacements)
          if (n.count > 0) (_write(n), n)
      ];
      final (parentId, parent, childIndex) = path[level - 1];
      store.free(parentId);

      parent.keys.removeAt(childIndex);
      parent.payloads.removeAt(childIndex);
      for (var i = 0; i < children.length; i++) {
        final (id, n) = children[i];
        parent.keys.insert(childIndex + i, Uint8List.fromList(n.keys.first));
        parent.payloads
            .insert(childIndex + i, _Node.childPayload(id, n.subtreeEntries));
      }
      replacements = _split(parent);
      level--;
    }

    if (replacements.length == 1) {
      final only = replacements.first;
      if (only.count == 0) {
        root = 0;
      } else if (!only.isLeaf && only.count == 1) {
        // A root with one child is a chain of one; its child is already a
        // valid root, so the level is dropped rather than written.
        root = _Node.childOf(only.payloads[0]).$1;
      } else {
        root = _write(only);
      }
      return;
    }
    // The root split: a new level above it.
    final keys = <Uint8List>[];
    final payloads = <Uint8List>[];
    for (final n in replacements) {
      if (n.count == 0) continue;
      keys.add(Uint8List.fromList(n.keys.first));
      payloads.add(_Node.childPayload(_write(n), n.subtreeEntries));
    }
    root = _write(_Node(false, keys, payloads));
  }

  /// Replaces the whole tree with [entries] (sorted, distinct keys), built
  /// bottom-up with **file-extending allocations only**, and without reading
  /// or freeing the old pages; the caller owns those.
  ///
  /// This is tree 1's save path, and the Rust and Java engines' commit path
  /// (`CowTree::rebuild_fresh`). Editing the free tree one `put` at a time
  /// copies a path per entry, and each copy frees pages after the list being
  /// recorded was taken: every save of this implementation leaked them, 14
  /// pages on the cross-language CRUD matrix. Allocating out of that list
  /// would be worse: a page both free and in use, which
  /// `spec/01-container.md` §9 calls a double allocation.
  void rebuildFresh(List<(Uint8List, Uint8List)> entries) {
    if (entries.isEmpty) {
      root = 0;
      return;
    }
    var level = _split(_Node(true, [for (final e in entries) e.$1],
        [for (final e in entries) _Node.leafPayload(e.$2)]));
    while (true) {
      final keys = <Uint8List>[];
      final payloads = <Uint8List>[];
      for (final n in level) {
        final id = _writeAt(store.allocFresh(), n);
        keys.add(n.keys.first);
        payloads.add(_Node.childPayload(id, n.subtreeEntries));
      }
      if (level.length == 1) {
        root = _Node.childOf(payloads.first).$1;
        return;
      }
      level = _split(_Node(false, keys, payloads));
    }
  }

  /// Splits [n] until every part fits one page.
  List<_Node> _split(_Node n) {
    if (n.count == 0 ||
        nodePageBytes(n.keys, n.payloads) <=
            store.payloadCap + PageHeader.size) {
      return [n];
    }
    if (n.count == 1) {
      throw LimitException(
          'a single cell of ${nodePageBytes(n.keys, n.payloads)} B does not '
          'fit a ${store.pageSize} B page');
    }
    final mid = n.count >> 1;
    final left = _Node(n.isLeaf, n.keys.sublist(0, mid), n.payloads.sublist(0, mid));
    final right = _Node(n.isLeaf, n.keys.sublist(mid), n.payloads.sublist(mid));
    return [..._split(left), ..._split(right)];
  }

  /// Height in pages from the root to a leaf, root included. 0 when empty.
  int get height {
    if (root == 0) return 0;
    var h = 1;
    var n = _load(root);
    while (!n.isLeaf) {
      h++;
      n = _load(_Node.childOf(n.payloads[0]).$1);
    }
    return h;
  }
}
