/// Persistence: a whole database as one `.cryptand` file.
///
/// Everything below is `spec/01-container.md` §1's layout with nothing added:
///
/// ```
/// page 0    superblock slot A
/// page 1    superblock slot B
/// page 2+   pages and extents, in allocation order
/// ```
///
/// The engine's [PageStore] already *is* the page space, and a segment or a
/// value-log segment already *is* an extent; what this file adds is giving each
/// extent a real page id, publishing the mutable value-log state into tree 7
/// (§6.7 makes it the authority for exactly this), and writing the superblock.
///
/// It exists so that the cross-language round trip `spec/11-conformance.md` §6
/// makes mandatory — "open it in implementation A, mutate it, close it, open it
/// in B, verify, mutate, close, reopen in A" — is a test that can be run at
/// all. Until a file crosses the boundary, "portable" is a claim about vectors
/// rather than about databases.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'bytes.dart';
import 'catalog.dart' show IndexType;
import 'cke.dart';
import 'crc32c.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'database.dart';
import 'engine.dart';
import 'manifest.dart' show SegmentRef;
import 'errors.dart';
import 'profile.dart';
import 'rtree.dart' show RTreeNode;
import 'security.dart';
import 'txn.dart';
import 'value.dart';
import 'vlog.dart';

/// The keyslot area a database was opened or created with, so a `save` that
/// rewrites the superblock does not drop the credentials with it. Keyed on the
/// engine rather than stored on it because keyslots are file-level state: an
/// in-memory engine has none.
final Expando<Uint8List> _keyslots = Expando('cryptand keyslots');

/// The writer handles this process holds, by resolved path (01 §10).
final Map<String, RandomAccessFile> _writers = {};

/// The tree-7 record last written per value-log segment, so a commit writes
/// only the ones that changed.
final Expando<Map<int, Uint8List>> _vlogWritten = Expando('cryptand tree 7');

bool _sameBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

abstract final class DatabaseFile {
  /// Lays the engine out as a file and writes it.
  ///
  /// The order matters and is the order §1 gives: extents are allocated first,
  /// so their page ids are fixed before anything records them; then the
  /// manifest and tree 7 are written, which appends copy-on-write pages *after*
  /// the extents and so cannot move them; then the superblock, last, because it
  /// is what publishes all of it.
  ///
  /// [writerId] is plaintext on disk even when encrypted (14 section 11): a
  /// product and version only, never a user name or device identifier.
  static void save(Database db, String path,
      {String? writerId, Uint8List? keyslots}) {
    final e = db.engine;
    // M5 step 6: saving to the file the database is open on is a commit.
    final raf = e.store.file;
    if (raf != null && e.publisher != null && _samePath(raf.path, path)) {
      if (writerId != null) e.writerId = writerId;
      if (keyslots != null) _keyslots[e] = keyslots;
      e.commit();
      return;
    }
    // Publishing a superblock is a commit, and §6's reclamation rule is
    // stated over commit ids: this is what makes the previous session's freed
    // extents reallocatable and attributes this one's to a new id.
    e.beginPublish();
    final image = _superblock(db,
            writerId: writerId,
            keyslots: keyslots,
            // The file is written with `flush: true` below.
            achieved: Durability.sync)
        .encode();
    // §6.2 — `sb_mac` authenticates the superblock; without it anyone can set
    // `cipher = 0` or weaken an Argon2id cost and no reader can tell.
    sealSuperblock(image, e.keys);
    final bytes = e.store.toBytes();
    // §1: slot A when `commit_id` is odd, slot B when it is even, so a crash
    // during a superblock write leaves the previous superblock intact. Both
    // slots are written here because a fresh file has no previous superblock
    // to leave intact, and an unreadable slot B would make §2.1 step 3 pick
    // between one valid slot and one absent one on every later open.
    bytes.setRange(0, Sb.size, image);
    bytes.setRange(e.store.pageSize, e.store.pageSize + Sb.size, image);
    _writeOwnerOnly(path, bytes);
  }

  /// M5 step 5, Rust `Engine::commit` step G: [Engine.commit] has written and
  /// synced the data; write the trees, sync them, write the superblock to
  /// the slot `commit_id`'s parity names, and sync again. The other slot
  /// keeps the previous commit for a crash in between.
  static void _publishInPlace(Database db) {
    final e = db.engine;
    final store = e.store;
    final raf = store.file!;
    final sb = _superblock(db, achieved: e.durabilityAchieved);
    final image = sb.encode();
    sealSuperblock(image, e.keys);
    final want = store.pageCount * store.pageSize;
    if (raf.lengthSync() < want) raf.truncateSync(want);
    final durable = e.durabilityAchieved == Durability.sync;
    if (durable) store.sync();
    fileWrite(raf, sb.commitId.isOdd ? 0 : store.pageSize, image);
    if (durable) store.sync();
    // The nonce floor rewrites both slots from this, so it must be the latest.
    e.superblock = sb;
  }

  /// Writes trees 3, 7 and 1 into the store and returns the superblock that
  /// publishes them, for the commit `e.commitId` already names.
  static Superblock _superblock(Database db,
      {String? writerId, Uint8List? keyslots, required Durability achieved}) {
    final e = db.engine;
    final store = e.store;
    // §2 of `spec/05-catalog.md`: tree 3's root lives in its own catalog
    // descriptor. Publishing it is what stops the next open from rebuilding
    // the tree and orphaning this one — a leak per open, and the only thing
    // that ever finds it is another implementation's §9 step 7.
    db.catalog.publishTreeIndex();
    // §4.1 rule 1 applies to a *writer*, and the writer is about to place
    // every extent below. On a file this session created, the floor was
    // published by [create]; on one it opened, by [open]. Nothing here
    // allocates a nonce that a published floor does not already cover.

    // 1–2. M5: every segment is placed in the store when published
    //      (`Engine.place`), so the manifest already holds real placements.
    for (final ref in e.manifest.all) {
      if (ref.startPage == 0) {
        throw StateError('segment ${ref.segmentId} was never placed');
      }
    }

    // 3. The value log: one extent each, and tree 7 for everything mutable
    //    about them (§6.7 — "This tree is the **authority** for everything
    //    mutable about a value-log segment").
    //    M5 step 5: edited, not rebuilt — only the entries whose record
    //    changed since the last commit are written (Rust writes dirty tree-7
    //    entries the same way); the copy-on-write path frees what it replaces.
    final stats = e.outerTrees['tree 7'] ??=
        CowTree(store, treeId: TreeId.vlogStats);
    final written = _vlogWritten[e] ??= {};
    for (final id in written.keys.toList()) {
      if (!e.vlog.segments.containsKey(id)) {
        stats.remove(encodeKey(CInt.of(NumType.u64, id)));
        written.remove(id);
      }
    }
    for (final v in e.vlog.segments.values) {
      final rec = encodeVlogStats(v, startPage: v.startPage);
      final was = written[v.id];
      if (was != null && _sameBytes(was, rec)) continue;
      stats.put(encodeKey(CInt.of(NumType.u64, v.id)), rec);
      written[v.id] = rec;
    }

    // 3b. Tree 1, the free tree (§6). Written last of the trees, because
    //     writing the others is itself what frees pages. Without it a reader
    //     — this one or another SDK's — reconciles reachable pages against an
    //     empty free tree and reports every orphaned page as a leak (§9 step
    //     7), and no later session can ever reuse the space.
    //
    //     It must equal the free list, not accumulate it: an extent *leaves*
    //     the list when it is reclaimed, and a best-fit allocation that takes
    //     part of one moves the remainder to a different key. A tree 1 that
    //     only ever grows is a strict superset of the truth, and the
    //     implementation that wrote it cannot tell — it keeps its own list in
    //     memory. Another implementation then allocates a page tree 1 calls
    //     free, while the live superblock still names it.
    //
    //     And it is rebuilt, not edited, in the order the Rust and Java
    //     engines commit it: release the tree's current pages into the list
    //     at this commit, snapshot the list, then build the snapshot with
    //     file-extending allocations only. Edited in place, every path copy
    //     freed pages after the snapshot was taken, leaked on every save.
    final free = e.freelist;
    for (final p in free.reachablePages().toList()) {
      store.free(p);
    }
    store.coalesceReclaimable();
    List<(Uint8List, Uint8List)> rows() => [
          for (final x in store.freeExtents)
            (
              encodeKey(CArray([
                CInt.of(NumType.u64, x.commitId),
                CInt.of(NumType.u64, x.startPage),
              ])),
              encodeValue(CDoc({'pages': CInt.of(NumType.u32, x.pages)}))
            )
        ]..sort((a, b) => compareKeys(a.$1, b.$1));
    // F-163 (Rust F-080): tree 1 goes into an extent taken off the list
    // before the snapshot; fresh end-of-file pages grew the file each save.
    final need = free.pagesNeeded(rows());
    final taken = need == 0 ? null : store.takeForFreeTree(need);
    if (taken != null && free.pagesNeeded(rows()) == need) {
      free.rebuildFresh(rows(), at: taken.$2);
    } else {
      if (taken != null) store.giveBack(taken, need);
      free.rebuildFresh(rows());
    }

    // 4. The superblock, last.
    return Superblock(
      pageSize: store.pageSize,
      commitId: e.commitId,
      pageCount: store.pageCount,
      visibleSeq: e.visibleSeq,
      nextSeq: e.nextSeq,
      catalogRoot: db.catalogRoot,
      freelistRoot: e.freelist.root,
      attributesRoot: db.attributesRoot,
      manifestRoot: e.manifest.root,
      vlogStatsRoot: stats.root,
      checkpointRoot: e.checkpoints.root,
      changefeedRoot: e.changeFeed.root,
      // F-128, `14-security.md` §5.5: what each root page was sealed under.
      rootNonces: [
        db.catalog.tree.rootNonce,
        e.freelist.rootNonce,
        db.attributes.tree.rootNonce,
        e.manifest.tree.rootNonce,
        stats.rootNonce,
        e.checkpoints.tree.rootNonce,
        e.changeFeed.tree.rootNonce,
      ],
      nextTreeId: db.catalog.nextTreeId,
      nextSegmentId: e.nextSegmentId,
      nextVlogSegmentId: e.vlog.nextId,
      databaseUuid: e.databaseUuid,
      minRetainedCommit: e.minRetainedCommit,
      minRetainedSeq: e.minRetainedSeq,
      // §7 of `spec/10-transactions.md`: record what was **performed**;
      // claiming more than that is the one thing §7 forbids.
      durabilityAchieved: achieved.code,
      levelCount: e.levels.levelCount,
      // `spec/12-profiles.md` §3 — advisory, but it must name the profile
      // this database actually runs, not a constant. A `mobile` database
      // saved as `desktop` reopens with another SDK reading `desktop`'s stall
      // budget and maintenance policy for a phone. `custom` when the engine's
      // constants match no named profile, which §1 provides for exactly here:
      // "a reader uses the *values* in the superblock, never the name".
      profile: e.profile.pageSize == e.pageSize ? e.profile : Profile.custom,
      // `01-container.md` §7 — the codec is a *default* for newly written
      // pages, and it is whatever this store has been writing with, not what
      // this build's profile would choose: a desktop that opens a phone's
      // database keeps writing the codec the phone chose.
      pageCodec: store.pageCodec,
      cipher: e.keys == null ? 0 : 1,
      featuresRequired:
          (1 << Feature.core) | (e.keys == null ? 0 : (1 << Feature.cipher)),
      // F-142: carried, so a commit to a converting file keeps CONVERTING.
      featuresOptional: e.featuresOptional,
      nextNonce: e.nonces?.publishedWatermark ?? 0,
      keyslots: keyslots ?? _keyslots[db.engine],
      vlogMin: e.vlogMin,
      l0Trigger: e.levels.l0Trigger,
      tierWidth: e.levels.tierWidth,
      overlapBound: e.levels.overlapBound,
      vlogSegmentBytes: e.vlog.segmentBytes,
      vlogSpaceTargetPct: e.vlogSpaceTargetPct,
      localityDebtPct: e.localityDebtPct,
      writerId: writerId ?? e.writerId,
      // Set once at creation and carried, as Rust and Java do.
      createdUtcMs: e.superblock?.createdUtcMs ??
          DateTime.now().millisecondsSinceEpoch,
      modifiedUtcMs: DateTime.now().millisecondsSinceEpoch,
    );
  }

  /// Creates an **encrypted** database that is encrypted from its first page.
  ///
  /// Without this there is no way to get one. Turning `cipher` on after the
  /// fact is `spec/14-security.md` §8.3's *conversion*, which leaves every page
  /// written before the switch in the clear — correct, reported by
  /// `unencrypted_pages`, and not what asking for an encrypted database means.
  ///
  /// It is also the only shape in which §4.1 rule 1 can hold: the floor must be
  /// durably published **before** the first nonce is handed out, so the file
  /// has to exist before the first page is encrypted. [credential] is 32 raw
  /// key bytes when [kdf] is `Keyslot.kdfRaw` — a key the host already holds,
  /// which §3.3 defines exactly for this case and which a hardware keystore on
  /// a phone supplies — or a password when it is `Keyslot.kdfArgon2id`.
  static Database create(
    String path, {
    required List<int> credential,
    int kdf = Keyslot.kdfArgon2id,
    Profile profile = Profile.desktop,
    int memtableEntries = 4096,
    int tCost = 3,
    int mCostKib = 65536,
    int parallelism = 1,
    String label = 'keyslot 0',
    int? vlogSegmentBytes,
    int? vlogMin,
  }) {
    vlogMin ??= profile.vlogMin;
    final uuid = randomBytes(16);
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    final master = randomBytes(32);
    final slot = _wrapSlot(master, uuid, 0, credential, kdf, tCost, mCostKib,
        parallelism, label);
    final keyslots = Uint8List(Sb.keyslotSize * Sb.keyslotCount)
      ..setRange(0, Keyslot.size, slot.encode());

    final ring = KeyRing(master, uuid);
    final e = Engine(
        pageSize: profile.pageSize,
        memtableEntries: memtableEntries,
        vlogMin: vlogMin,
        // The profile's value unless the caller names one. A value-log segment
        // extent is *preallocated*, so `mobile`'s 4 MiB is 4 MiB of file for
        // one separated value — which is right for a device and wrong for a
        // conformance fixture that lives in a repository forever.
        vlogSegmentBytes: vlogSegmentBytes ?? profile.vlogSegmentBytes);
    e
      ..setProfile(profile)
      ..databaseUuid = uuid;
    _keyslots[e] = keyslots;

    // The file, and its first superblock, before a single page is encrypted.
    final sb = Superblock(
      pageSize: profile.pageSize,
      commitId: 1,
      pageCount: 2,
      profile: profile,
      pageCodec: profile.pageCodec,
      vlogMin: vlogMin,
      cipher: 1,
      featuresRequired: (1 << Feature.core) | (1 << Feature.cipher),
      databaseUuid: uuid,
      keyslots: keyslots,
      writerId: e.writerId,
      createdUtcMs: DateTime.now().millisecondsSinceEpoch,
      modifiedUtcMs: DateTime.now().millisecondsSinceEpoch,
    );
    final image = sb.encode();
    sealSuperblock(image, ring);
    final blank = Uint8List(2 * profile.pageSize)
      ..setRange(0, Sb.size, image)
      ..setRange(profile.pageSize, profile.pageSize + Sb.size, image);
    // **Refuse to overwrite an existing database.** `writeAsBytesSync` on an
    // existing path truncates it, so `create` on a file that already held a
    // database destroyed it silently — unrecoverable, and a plausible thing
    // for an operator or a script to do. Two of the three reference
    // implementations did this; only the Java one refused.
    //
    // This is a check followed by a write, not an atomic exclusive create:
    // `dart:io` exposes no `O_EXCL`, so a file appearing between the two
    // would still be overwritten. That window is narrow and is not the case
    // this guards — it guards the operator who typed the wrong path — and
    // saying so is better than implying an atomicity this cannot provide.
    // The real defence against two writers is `01-container.md` §10's
    // exclusive advisory lock, which the store takes below.
    if (File(path).existsSync() && File(path).lengthSync() != 0) {
      throw InvalidArgumentException(
          '$path already exists and is not empty; use open '
          '(spec/01-container.md section 2)');
    }
    _writeOwnerOnly(path, blank);
    // M5: from here the store is the file, locked for this session. The
    // store holds only the two blank superblock pages, so handing it the
    // handle is the same as `PageStore.onFile(pageCount: 2)`.
    final raf = File(path).openSync(mode: FileMode.append);
    try {
      _takeWriterLock(raf, path);
    } catch (_) {
      _close(raf);
      rethrow;
    }
    e
      ..store.file = raf
      ..onClose = () => _close(raf);

    // §4.1 rule 1, now that there is somewhere durable to publish to — and
    // before the [Database] below, whose constructor writes the catalog and
    // the store-metadata attributes. Building it first would leave those pages
    // in the clear for the life of the file: §8.3's conversion mixture, on a
    // database nobody converted.
    e
      ..superblock = sb
      ..installKeys(
          ring,
          NonceAllocator.open(
              0,
              (floor) => _publishNonceFloor(raf, e.superblock!, ring, floor)));
    final db = Database(engine: e);
    e.publisher = (_) => _publishInPlace(db);
    return db;
  }

  /// Reads a file back into an engine.
  ///
  /// [key] is the credential of `spec/14-security.md` §3.3: 32 raw bytes for a
  /// `kdf = 0` slot, or a password for an Argon2id slot. An encrypted file
  /// opened without one fails with [CannotUnlockException], which §3.3 requires
  /// to be reported identically for a missing keyslot and a wrong password.
  ///
  /// Pass a mutable sequence — a `Uint8List`, not the code units of a `String`.
  /// §11 forbids offering a password parameter of an immutable string type on a
  /// runtime whose strings are immutable, and Dart's are: a `String` holding a
  /// password survives until collection with no way to clear it.
  ///
  /// **Zeroing on this runtime is best-effort, and §11 requires that to be
  /// said rather than implied.** The Dart VM's collector is generational and
  /// copying: a surviving `Uint8List` is relocated, and each relocation leaves
  /// the old bytes in a region the program can no longer name and therefore
  /// cannot overwrite. `Engine.close` zeroes the master key and every subkey,
  /// and the caller should clear [key] once the database is open — but a copy
  /// the program never sees cannot be zeroed by anyone. §11: "documenting it is
  /// the requirement; achieving what the runtime forbids is not."
  ///
  /// Practically: a heap snapshot of a process that has ever opened an
  /// encrypted database may contain the master key even after a clean close.
  /// Treat process memory as in scope for whatever protects the key file.
  static Database open(String path, {List<int>? key}) => _open(path, key);

  /// `13-operations.md` §5 `rotate_master_key()` (F-072), by copy-and-swap
  /// as Rust and Java: the file is copied to `<path>.rotate`, every encrypted
  /// page and value-log record in the copy is re-sealed under a fresh master
  /// key (same counters, offsets and lengths), the superblock gets one new
  /// keyslot, and the copy is renamed over the original. A crash before the
  /// rename leaves the original intact. Closes [db]; returns the file reopened
  /// under [credential] (`kdf` raw: 32 key bytes; Argon2id: a password).
  ///
  /// Pages are found by scanning the file rather than walking each structure:
  /// a page is re-sealed exactly when its header is intact, says ENCRYPTED and
  /// opens under the old key, which AEAD makes impossible by accident. An
  /// intact encrypted page that does *not* open is tampering, and stops it.
  ///
  /// ponytail: one synchronous pass with 2x the file on disk, refused while
  /// checkpoints exist or a vector region is named (Dart writes none; their
  /// chunks are not pages). Step it, as 14 §8.4 allows, if large files need
  /// rotating online.
  static Database rotateMasterKey(Database db, List<int> credential,
      {int kdf = Keyslot.kdfArgon2id,
      int tCost = 3,
      int mCostKib = 65536,
      int parallelism = 1,
      String label = 'keyslot 0'}) {
    // The credential wraps the new slot and then reopens the file; wrapping
    // zeroes a password (F-135), so keep a copy for the open, zeroed by it.
    final again = Uint8List.fromList(credential);
    try {
      return _rotate(db, credential, again, kdf, tCost, mCostKib, parallelism,
          label);
    } catch (_) {
      _wipe(credential);
      _wipe(again);
      rethrow;
    }
  }

  static Database _rotate(Database db, List<int> credential, Uint8List again,
      int kdf, int tCost, int mCostKib, int parallelism, String label) {
    final e = db.engine;
    final old = e.keys;
    final path = e.store.file?.path;
    if (old == null || path == null || e.publisher == null) {
      throw const InvalidArgumentException(
          'rotateMasterKey() needs an open, unlocked, encrypted file');
    }
    if (e.checkpoints.all.isNotEmpty) {
      throw const InvalidArgumentException(
          'rotateMasterKey() refuses while checkpoints exist; drop them first');
    }
    if (db.catalog.all.any((d) => d.$2.param('vector_region') != null)) {
      throw const UnsupportedFeatureException(
          'rotateMasterKey() does not re-seal vector regions');
    }
    // A quiet, durable state: memtable flushed, value-log segments sealed;
    // close()'s own steps, so the live pages can be read before the handle goes.
    e.commit();
    e.vlog.sealOpen();
    e.commit();
    // F-143: as Rust, only live pages must open under the old key. A dead
    // page may be sealed under a master key since replaced by
    // decrypt-then-encrypt; it is re-sealed only if it opens.
    final live = <int>{
      for (final t in [
        e.manifest.tree,
        e.freelist,
        e.checkpoints.tree,
        e.changeFeed.tree,
        ...e.outerTrees.values,
      ])
        ...t.reachablePages(),
      for (final r in e.manifest.all)
        for (var i = 0; i < r.pages; i++) r.startPage + i,
    };
    e.close(flushMemtable: false);
    final ps = e.pageSize;
    final vlogs = [
      for (final v in e.vlog.segments.values)
        if (v.startPage != 0) v
    ];
    final skip = <int>{0, 1};
    for (final v in vlogs) {
      for (var i = 0; i < v.pageCount; i++) {
        skip.add(v.startPage + i);
      }
    }

    final master = randomBytes(32);
    final uuid = Uint8List.fromList(e.databaseUuid);
    final ring = KeyRing(master, uuid);
    final tmp = '$path.rotate';
    final t = File(tmp);
    if (t.existsSync()) t.deleteSync();
    _writeOwnerOnly(tmp, Uint8List(0));
    final src = File(path).openSync();
    final f = t.openSync(mode: FileMode.append);
    try {
      for (Uint8List b; (b = src.readSync(1 << 20)).isNotEmpty;) {
        f.writeFromSync(b);
      }
      final pageCount = f.lengthSync() ~/ ps;
      Uint8List read(int at, int n) {
        f.setPositionSync(at);
        return f.readSync(n);
      }

      void write(int at, List<int> b) => f
        ..setPositionSync(at)
        ..writeFromSync(b);

      for (var p = 0; p < pageCount; p++) {
        if (skip.contains(p)) continue;
        final buf = read(p * ps, ps);
        final PageHeader h;
        try {
          h = PageHeader.read(buf, pageId: p);
        } on CryptandException {
          continue; // not a page: unwritten, or the middle of an extent
        }
        if (!h.isEncrypted) continue;
        final end = PageHeader.size + h.stored;
        if (end > ps) continue; // not a page
        final header = Uint8List.sublistView(buf, 0, PageHeader.size);
        final Uint8List pt;
        try {
          pt = decryptPagePayload(
              keys: old,
              pageId: p,
              nonceCounter: h.nonce,
              pageHeader40: header,
              sealed: Uint8List.sublistView(buf, PageHeader.size, end));
        } on TamperException {
          if (live.contains(p)) rethrow;
          continue;
        }
        final ct = encryptPagePayload(
            keys: ring,
            pageId: p,
            nonceCounter: h.nonce,
            pageHeader40: header,
            payload: pt);
        buf.setRange(PageHeader.size, end, ct);
        h.writeInto(buf); // the CRC covers the payload as stored
        write(p * ps, buf);
      }

      for (final v in vlogs) {
        final base = v.startPage * ps;
        final raw = read(base, VlogSegment.dataOffset + v.bytes);
        final bd = ByteData.sublistView(raw);
        var off = VlogSegment.dataOffset;
        while (off < raw.length) {
          final r = ByteReader(raw, off, raw.length);
          final len = r.uvar();
          if (len < 5 || len > r.remaining) {
            // F-138: a file value, checked before it places the CRC.
            throw CorruptionException(
                'value-log record at ${v.id}+$off declares $len bytes');
          }
          final body = r.position, crcAt = body + len - 4;
          final next = body + len;
          // F-132: a converting file's plaintext records stay as they are.
          if (crc32c(raw, body, crcAt) != bd.getUint32(crcAt, Endian.little)) {
            final counter = bd.getUint64(body, Endian.little);
            final treeId = bd.getUint32(body + 8, Endian.little);
            final pt = decryptVlogRecord(
                keys: old,
                segmentId: v.id,
                recordOffset: off,
                treeId: treeId,
                nonceCounter: counter,
                ciphertext: Uint8List.sublistView(raw, body + 12, crcAt - 16),
                tag: Uint8List.sublistView(raw, crcAt - 16, crcAt));
            if (pt == null) {
              throw CorruptionException(
                  'value-log record ${v.id}+$off does not open under the key');
            }
            final c = encryptVlogRecord(
                keys: ring,
                segmentId: v.id,
                recordOffset: off,
                treeId: treeId,
                nonceCounter: counter,
                body: pt);
            raw
              ..setRange(body + 12, crcAt - 16, c.ciphertext)
              ..setRange(crcAt - 16, crcAt, c.tag);
            bd.setUint32(crcAt, crc32c(raw, body + 8, crcAt), Endian.little);
            write(base + off, Uint8List.sublistView(raw, off, next));
          }
          off = next;
        }
      }

      // One keyslot under the new master, in both superblock slots, so the
      // fallback cannot carry a keyslot for the old one.
      final sb = Superblock.open(read(0, Sb.size), read(ps, Sb.size));
      final slot = _wrapSlot(master, uuid, 0, credential, kdf, tCost,
          mCostKib, parallelism, label);
      sb.keyslots
        ..fillRange(0, sb.keyslots.length, 0)
        ..setRange(0, Keyslot.size, slot.encode());
      final image = sb.encode();
      sealSuperblock(image, ring);
      write(0, image);
      write(ps, image);
      f.flushSync();
    } finally {
      f.closeSync();
      src.closeSync();
      ring.destroy();
    }
    t.renameSync(path);
    return open(path, key: again);
  }

  /// Opens a database **without writing to the file**.
  ///
  /// `11-conformance.md` §3's reader matrix requires this mode outright — a
  /// file whose `write_version_minor` exceeds what the implementation supports
  /// MUST open read-only rather than be refused — and it is what any reader of
  /// a file it does not own needs: a golden fixture, a file under examination,
  /// a database another process owns.
  ///
  /// The difference from [open] is `14-security.md` §4.1's nonce floor. An
  /// encrypted database's ordinary open publishes `persisted_next_nonce +
  /// 2^20` durably, which rewrites both superblock slots before anything is
  /// read. §4.1's rule is that the floor is published before nonces are
  /// *allocated*, and a handle that never writes a page allocates none — so a
  /// reader needs no floor, and taking one modifies a file it only meant to
  /// look at. Reading the shared conformance corpus rewrote four of its files
  /// on every run this way, `v1.0-security-*` among them, which means it wrote
  /// to files it was about to reject as tampered.
  ///
  /// It takes no writer lock, so several readers may hold one at once.
  static Database openReadOnly(String path, {List<int>? key}) =>
      _open(path, key, readOnly: true);

  /// `14-security.md` §11: a password is zeroed after use, on every exit
  /// path. A raw key belongs to the host (a keystore item) and is left alone,
  /// as in Java.
  static void _wipe(List<int>? credential) {
    if (credential == null) return;
    try {
      credential.fillRange(0, credential.length, 0);
    } on UnsupportedError {
      // ponytail: a const or unmodifiable list cannot be zeroed; §11 asks the
      // caller for a mutable one, and the README says so.
    }
  }

  /// `spec/01-container.md` §10 — "one writing **process** per database,
  /// enforced by an exclusive lock on the single byte at offset 2^62 of the
  /// database file (`fcntl` / `LockFileEx`) held for its writing lifetime", and "a second
  /// process opening for writing MUST fail with a clear 'locked by another
  /// process' error and MUST NOT fall back to opening anyway".
  ///
  /// The lock rides the open file handle, so it is released when the handle
  /// closes — including when the process dies, which is what makes a crashed
  /// writer's database openable again with no cleanup step.
  static const int _lockByte = 1 << 62;

  ///
  /// M5: taken on the store's own handle and held until [Engine.close]
  /// closes it, and registered in [_writers] so this process behaves like
  /// Rust (an open-file-description lock) and Java (`tryLock` throws
  /// `OverlappingFileLockException`): a second writer in the same process is
  /// refused too. POSIX `fcntl` locks are per process, so without the
  /// registry it would be granted; on Windows `LockFileEx` would refuse it.
  static void _takeWriterLock(RandomAccessFile f, String path) {
    final key = File(path).resolveSymbolicLinksSync();
    if (_writers.containsKey(key)) {
      throw LockedException('$path is already open for writing in this process');
    }
    try {
      // One byte far past any data, not the whole file: on Windows a
      // LockFileEx range is mandatory, and a whole-file lock on this handle
      // blocked every read through the data handle (errno 33). Rust and Java
      // take the same byte (F-067), so writers in any two languages exclude
      // each other.
      f.lockSync(FileLock.exclusive, _lockByte, _lockByte + 1);
    } on FileSystemException catch (e) {
      throw LockedException('$path is open for writing by another process, '
          'or lies on a filesystem that cannot lock it (${e.osError?.message ?? e.message})');
    }
    _writers[key] = f;
  }

  /// Closes a handle [_open] or [create] made, and keeps the lock right.
  ///
  /// A writer leaves [_writers]. Any other handle's close drops *every*
  /// `fcntl` lock this process holds on the file (POSIX), so a reader opened
  /// beside a writer in this process takes the writer's lock back — what
  /// Rust's open-file-description lock gives for free. Re-taking it cannot
  /// conflict with ourselves; another process that slipped into the window
  /// makes it throw, which is reported rather than silently writing unlocked.
  static void _close(RandomAccessFile f) {
    final key = _writers.entries
        .where((w) => identical(w.value, f))
        .map((w) => w.key)
        .firstOrNull;
    f.closeSync();
    if (key != null) {
      _writers.remove(key);
      return;
    }
    final String path;
    try {
      path = File(f.path).resolveSymbolicLinksSync();
    } on FileSystemException {
      return; // erased: nothing left to lock
    }
    _writers[path]?.lockSync(FileLock.exclusive, _lockByte, _lockByte + 1);
  }

  static Database _open(String path, List<int>? key, {bool readOnly = false}) {
    // M5: the store reads pages from the file on demand; only the superblock
    // region (slot B is at most 64 KiB in) is read up front.
    final raf = File(path).openSync(mode: readOnly ? FileMode.read : FileMode.append);
    try {
      if (!readOnly) _takeWriterLock(raf, path);
      return _openOn(raf, path, key, readOnly: readOnly)
        ..engine.onClose = () => _close(raf);
    } catch (_) {
      _close(raf);
      rethrow;
    }
  }

  static Database _openOn(RandomAccessFile raf, String path, List<int>? key,
      {required bool readOnly}) {
    final fileLen = raf.lengthSync();
    final head = (1 << 16) + Sb.size;
    raf.setPositionSync(0);
    final bytes = raf.readSync(fileLen < head ? fileLen : head);
    if (bytes.length < 2 * Sb.size) {
      throw const CorruptionException('file is shorter than two superblocks');
    }
    // §2.1 steps 1–3, and the page size is not known until slot A is read.
    final probe =
        Superblock.tryDecode(Uint8List.sublistView(bytes, 0, Sb.size));
    // F-069: with slot A invalid the page size is unknown, and slot B sits at
    // offset page_size. Try every legal size (page_size_log2 12..16) and take
    // a slot only where its own page size names the offset it was found at.
    // Assuming 4096 lost every other file whose slot A was bad, including any
    // crashed before its first close.
    var pageSize = probe?.pageSize ?? 4096;
    if (probe == null) {
      Superblock? best;
      for (var log2 = 12; log2 <= 16; log2++) {
        final size = 1 << log2;
        if (bytes.length < size + Sb.size) continue;
        final b = Superblock.tryDecode(
            Uint8List.sublistView(bytes, size, size + Sb.size));
        if (b != null &&
            b.pageSize == size &&
            (best == null || b.commitId > best.commitId)) {
          best = b;
          pageSize = size;
        }
      }
    }
    if (fileLen < 2 * pageSize) {
      throw const CorruptionException('file is shorter than its two slots');
    }
    final sb = Superblock.open(
      Uint8List.sublistView(bytes, 0, Sb.size),
      Uint8List.sublistView(bytes, pageSize, pageSize + Sb.size),
    );
    // §3 of `spec/11-conformance.md`: an unknown bit in `features_required`
    // is a refusal, named.
    for (var b = 0; b < 64; b++) {
      if (sb.featuresRequired & (1 << b) != 0 &&
          !Feature.names.containsKey(b)) {
        throw UnsupportedFeatureException(
            'this file requires unknown feature bit $b');
      }
    }
    KeyRing? ring;
    // §6.1's attack is to set `cipher = 0` so the next writer stores
    // plaintext, and §5.2 says outright that "a reader MUST NOT infer
    // encryption from `cipher` alone". So the keyslots and the MAC decide,
    // not the byte the attacker can edit: a superblock that still carries
    // either is checked, whatever `cipher` now says.
    final claimsPlain = sb.cipher == 0;
    final hasSlot = sb.keyslots.any((b) => b != 0);
    final hasMac = sb.sbMac.any((b) => b != 0);
    if (claimsPlain && (hasSlot || hasMac)) {
      throw const TamperException(
          'this superblock says cipher = 0 while still carrying keyslots or a '
          'MAC: someone has tried to turn encryption off '
          '(spec/14-security.md section 6.1)');
    }
    // F-137, 14 §6.1: a key on a plaintext file hides the downgrade.
    if (claimsPlain && key != null) {
      throw const InvalidArgumentException(
          'a key was supplied but the file is not encrypted');
    }
    if (sb.cipher != 0) {
      if (key == null) throw const CannotUnlockException();
      final master = _unlockMaster(sb, key);
      if (master == null) throw const CannotUnlockException();
      ring = KeyRing(master, Uint8List.fromList(sb.databaseUuid));
      // §6.2 — verify `sb_mac` before acting on any other field, so an
      // attacker cannot set `cipher = 0` or weaken an Argon2id cost.
      try {
        verifySuperblockMac(ring.macKey, sb.encode());
      } catch (_) {
        ring.destroy();
        rethrow;
      }
    }
    // M4.5, 14 section 11: a failed open zeroes the ring it built.
    try {
      // §2.1 step 7: ignore everything at or beyond `page_count` — debris from
      // an interrupted commit.
      final used = sb.pageCount * sb.pageSize;
      final store = PageStore.onFile(raf,
          pageSize: sb.pageSize,
          pageCount: used > fileLen ? fileLen ~/ sb.pageSize : sb.pageCount)
        // `01-container.md` §7 — the codec is a *default* for newly written
        // pages and comes from the file, not from this build's profile, so a
        // desktop that opens a phone's database keeps writing the codec the
        // phone chose. It has to be set before the first page is read, because
        // an already-compressed page is decompressed on the way out.
        ..pageCodec = sb.pageCodec;

      final e = Engine(
        pageSize: sb.pageSize,
        vlogMin: sb.vlogMin,
        levels: LevelPolicy(
          l0Trigger: sb.l0Trigger,
          tierWidth: sb.tierWidth,
          overlapBound: sb.overlapBound,
          levelCount: sb.levelCount,
          fanout: sb.fanout,
        ),
        vlogSpaceTargetPct: sb.vlogSpaceTargetPct,
        localityDebtPct: sb.localityDebtPct,
        vlogSegmentBytes: sb.vlogSegmentBytes,
        store: store,
        manifestRoot: sb.manifestRoot,
        freelistRoot: sb.freelistRoot,
        checkpointRoot: sb.checkpointRoot,
        changefeedRoot: sb.changefeedRoot,
        rootNonces: sb.rootNonces,
      );
      e
        ..databaseUuid = Uint8List.fromList(sb.databaseUuid)
        ..restoreCounters(
          nextSeq: sb.nextSeq,
          nextSegmentId: sb.nextSegmentId,
          visibleSeq: sb.visibleSeq,
          commitId: sb.commitId,
        );
      if (!e.writers.contains(sb.writerId)) e.writers.add(sb.writerId);
      // §6: `page_size` is fixed at creation, so a name whose page size does not
      // match this file is advisory metadata that cannot be adopted; the values
      // in the superblock are what the engine already runs on.
      if (sb.profile.pageSize == sb.pageSize) e.setProfile(sb.profile);
      e.durabilityAchieved = Durability.fromCode(sb.durabilityAchieved);
      e
        ..superblock = sb
        ..featuresOptional = sb.featuresOptional;
      _keyslots[e] = Uint8List.fromList(sb.keyslots);

      if (ring != null) {
        // §4.1 rule 1: "on open, before allocating anything, a writer MUST
        // durably publish a superblock whose `next_nonce` is
        // `persisted_next_nonce + 2^20`." Rule 1 is what makes the watermark
        // move even for a session that writes nothing else; without it two
        // successive crashed sessions both start at W and hand out the same
        // values. It is published *here*, before the segments below are read
        // and long before anything is written.
        // A read-only handle publishes no floor because it allocates no nonce;
        // see `openReadOnly`. `NonceAllocator.readOnly` hands out nothing, so
        // the absence of a floor cannot turn into a reused nonce.
        e.installKeys(
            ring,
            readOnly
                ? NonceAllocator.readOnly(sb.nextNonce)
                : NonceAllocator.open(sb.nextNonce,
                    (floor) =>
                        _publishNonceFloor(raf, e.superblock!, ring, floor)));
      }

      // §6: the free tree, read back so this session reuses space rather than
      // extending the file for ever. Read before the segment extents so that
      // nothing has allocated yet.
      if (sb.freelistRoot != 0) {
        final extents = <FreeExtent>[];
        for (final (k, v) in e.freelist.scan()) {
          // F-118: narrowed, so a hostile entry is corruption, not a TypeError.
          final a = expectValue<CArray>(decodeKey(k), 'free-list key');
          if (a.items.length < 2) {
            throw const CorruptionException(
                'free-list key has fewer than two parts');
          }
          final d = expectValue<CDoc>(decodeValue(v), 'free-list entry');
          extents.add(FreeExtent(
            expectValue<CInt>(a.items[0], 'free-list key').magnitude.lo,
            expectValue<CInt>(a.items[1], 'free-list key').magnitude.lo,
            expectField<CInt>(d, 'pages', 'free-list entry').magnitude.lo,
          ));
        }
        store.loadFree(extents);
      }

      // Segment extents are read on demand through `Engine.segment` (M5);
      // §9.2's "names a segment with no extent" is checked here, cheaply.
      for (final ref in e.manifest.all) {
        if (ref.pages == 0) {
          throw CorruptionException(
              'manifest entry for segment ${ref.segmentId} has no extent');
        }
      }

      // Value-log segments, from tree 7.
      final stats = CowTree(store,
          treeId: TreeId.vlogStats,
          root: sb.vlogStatsRoot,
          rootNonce: sb.rootNonces[4]);
      e.outerTrees['tree 7'] = stats;
      for (final (k, v) in stats.scan()) {
        final int id;
        final VlogSegment seg;
        // 14 §9.1 (F-117, as F-110): a stats entry of the wrong shape is
        // corruption, not a `TypeError`.
        try {
          id = ((decodeKey(k) as CInt).magnitude).lo;
          final d = decodeValue(v) as CDoc;
          int u(String f) => ((d[f]! as CInt).magnitude).lo;
          bool b(String f) => (d[f] as CBool?)?.value ?? false;
          Uint8List? by(String f) => (d[f] as CBytes?)?.value;
          seg = VlogSegment.fromExtent(
            store,
            u('start_page'),
            u('pages'),
            bytes: u('bytes'),
            records: u('records'),
            sealed: b('sealed'),
            clustered: b('clustered'),
            minKey: by('min_key'),
            maxKey: by('max_key'),
            liveBytes: u('live_bytes'),
            liveRecords: u('live_records'),
          );
        } on TypeError catch (e) {
          throw CorruptionException(
              'value-log stats entry has the wrong shape: $e');
        }
        // §4.3 of `spec/14-security.md` and §4 of `spec/10-transactions.md`: on
        // open, every unsealed value-log segment is sealed at its durable
        // watermark and a fresh segment is opened for new writes. Unencrypted
        // that is housekeeping; encrypted, re-appending would reuse a nonce.
        if (!seg.sealed) seg.seal(claimClustered: seg.clustered);
        if (seg.id != id) {
          // §11 invariant 8b: a head page and a tree-7 entry that disagree on
          // `segment_id` is corruption.
          throw CorruptionException(
              'value-log head page says segment ${seg.id}, tree 7 says $id');
        }
        e.vlog.adopt(seg);
        (_vlogWritten[e] ??= {})[id] = v;
      }
      // F-045: ids are "globally unique, never reused" (04 §2.1). A collected
      // segment has no tree-7 entry, so the highest adopted id can be below the
      // superblock's counter, and reusing one gives a dead pointer a new record.
      e.vlog.reserveIdsBelow(sb.nextVlogSegmentId);

      // Trees 0, 2 and 3, rooted from the superblock like everything else.
      final db = Database(
        engine: e,
        catalogRoot: sb.catalogRoot,
        catalogNonce: sb.rootNonces[0],
        attributesRoot: sb.attributesRoot,
        attributesNonce: sb.rootNonces[2],
        nextTreeId: sb.nextTreeId,
        // §4 rule 2 of `spec/11-conformance.md`: a reopen preserves what the
        // file holds, so it does not overwrite the store metadata another SDK
        // wrote.
        initStoreMetadata: false,
      )..catalog.loadTreeIndex(rebuild: !readOnly);
      if (!readOnly) e.publisher = (_) => _publishInPlace(db);
      return db;
    } catch (_) {
      ring?.destroy();
      rethrow;
    }
  }

  /// §3.3 — tries the raw-key slots with [key] as 32 key bytes, then the
  /// Argon2id slots with it as a password. Both failures report the same
  /// thing, which is the requirement.
  static Uint8List? _unlockMaster(Superblock sb, List<int> key) {
    final uuid = Uint8List.fromList(sb.databaseUuid);
    if (key.length == 32) {
      final k = unlock(
          keyslotArea: sb.keyslots,
          kek: Uint8List.fromList(key),
          databaseUuid: uuid);
      if (k != null) return k;
    }
    final m = unlockWithPassword(
        keyslotArea: sb.keyslots, password: key, databaseUuid: uuid);
    // §11: zero it once it is known to be a password. A 32-byte credential
    // that unlocked nothing may be the host's raw key, so it is left alone.
    if (m != null || key.length != 32) _wipe(key);
    return m;
  }

  /// §4.1's publish: the superblock, with the new floor, made durable before
  /// the value it names is allowed to be handed out.
  ///
  /// Both slots, because the floor is the one field a crash must never see go
  /// backwards, and a slot that still holds the old value is a slot §2.1 step
  /// 3 could pick.
  static void _publishNonceFloor(
      RandomAccessFile f, Superblock sb, KeyRing? ring, int floor) {
    final image = sb.encode();
    final bd = ByteData.view(image.buffer, image.offsetInBytes, image.length);
    bd.setUint64(Sb.nextNonce, floor, Endian.little);
    sealSuperblock(image, ring);
    fileWrite(f, 0, image);
    fileWrite(f, sb.pageSize, image);
    fileSync(f);
  }
}

/// §6.7's record. Every field the chapter lists, with `min_key`/`max_key`
/// present iff `clustered`.
Uint8List encodeVlogStats(VlogSegment v, {required int startPage}) {
  final f = <String, CValue>{
    'bytes': CInt.of(NumType.u64, v.bytes),
    'records': CInt.of(NumType.u64, v.records),
    'sealed': CBool(v.sealed),
    'clustered': CBool(v.clustered),
    'start_page': CInt.of(NumType.u64, startPage),
    'pages': CInt.of(NumType.u32, v.pageCount),
    'live_bytes': CInt.of(NumType.u64, v.liveBytes),
    'live_records': CInt.of(NumType.u64, v.liveRecords),
    'tier': CInt.of(NumType.u8, v.tier),
    'heat': CInt.of(NumType.u8, v.heatClass),
    'created_seq': CInt.of(NumType.u64, v.createdSeq),
    'last_gc_seq': CInt.of(NumType.u64, 0),
  };
  if (v.clustered) {
    if (v.minKey != null) f['min_key'] = CBytes(v.minKey!);
    if (v.maxKey != null) f['max_key'] = CBytes(v.maxKey!);
  }
  return encodeValue(CDoc(f));
}

bool _samePath(String a, String b) {
  try {
    return File(a).resolveSymbolicLinksSync() ==
        File(b).resolveSymbolicLinksSync();
  } on FileSystemException {
    return false;
  }
}

/// PLAN 4.7: every file the engine creates is owner-only (`0600`); the umask
/// can only narrow it. `dart:io` has no mode setter, so libc `chmod` through
/// FFI, before any byte is written. No-op on Windows.
void _writeOwnerOnly(String path, Uint8List bytes) {
  final f = File(path)..createSync();
  if (!Platform.isWindows) {
    final p = path.toNativeUtf8z();
    try {
      if (_chmod(p, 384 /* 0600 */) != 0) {
        throw FileSystemException('chmod 0600 failed', path);
      }
    } finally {
      _free(p);
    }
  }
  f.writeAsBytesSync(bytes, flush: true);
}

final _libc = DynamicLibrary.process();
final _chmod = _libc
    .lookupFunction<Int32 Function(Pointer<Uint8>, Uint32 /* mode_t: u16 on Darwin, u32 on Linux */), int Function(Pointer<Uint8>, int)>('chmod');
final _malloc = _libc
    .lookupFunction<Pointer<Uint8> Function(IntPtr), Pointer<Uint8> Function(int)>('malloc');
final _free = _libc
    .lookupFunction<Void Function(Pointer<Uint8>), void Function(Pointer<Uint8>)>('free');

extension on String {
  Pointer<Uint8> toNativeUtf8z() {
    final units = const Utf8Encoder().convert(this);
    final p = _malloc(units.length + 1);
    p.asTypedList(units.length + 1)
      ..setAll(0, units)
      ..[units.length] = 0;
    return p;
  }
}

/// Wraps [master] for keyslot [index] under [credential] (`kdf` raw: 32 key
/// bytes; Argon2id: a password, zeroed here, F-135).
Keyslot _wrapSlot(Uint8List master, Uint8List uuid, int index,
    List<int> credential, int kdf, int tCost, int mCostKib, int parallelism,
    String label) {
  final salt = randomBytes(32);
  try {
    return wrapMasterKey(
      masterKey: master,
      kek: kdf == Keyslot.kdfRaw
          ? Uint8List.fromList(credential)
          : deriveKek(
              slot: Keyslot(
                state: Keyslot.occupied,
                kdf: kdf,
                tCost: tCost,
                mCostKib: mCostKib,
                parallelism: parallelism,
                salt: salt,
                wrapNonce: Uint8List(24),
                wrappedKey: Uint8List(32),
                wrapTag: Uint8List(16),
                label: label,
              ),
              password: credential),
      databaseUuid: uuid,
      slotIndex: index,
      wrapNonce: randomBytes(24),
      salt: salt,
      kdf: kdf,
      tCost: tCost,
      mCostKib: mCostKib,
      parallelism: parallelism,
      label: label,
    );
  } finally {
    if (kdf != Keyslot.kdfRaw) DatabaseFile._wipe(credential);
  }
}

/// `13-operations.md` §5 keyslot management on an open, encrypted database
/// (F-072): each is a commit; no data page is touched and the master key never
/// changes. Rust `KeyApi`, Java `Engine.addKey`/`removeKey`/`cryptoErase`.
extension KeyApi on Database {
  Uint8List _slots() {
    final e = engine;
    final area = _keyslots[e];
    if (e.keys == null || area == null || e.publisher == null) {
      throw const InvalidArgumentException(
          'the database is not an open, unlocked, encrypted file');
    }
    return area;
  }

  List<bool> _occupied(Uint8List area) => [
        for (var i = 0; i < Sb.keyslotCount; i++)
          Keyslot.decode(
                      Uint8List.sublistView(
                          area, i * Keyslot.size, (i + 1) * Keyslot.size),
                      i)
                  .state ==
              Keyslot.occupied
      ];

  /// Wraps the master key under [credential] in the first free keyslot and
  /// returns its index.
  int addKey(List<int> credential,
      {int kdf = Keyslot.kdfArgon2id,
      int tCost = 3,
      int mCostKib = 65536,
      int parallelism = 1,
      String label = 'password'}) {
    final Uint8List area;
    try {
      area = _slots();
    } catch (_) {
      if (kdf != Keyslot.kdfRaw) DatabaseFile._wipe(credential);
      rethrow;
    }
    final free = _occupied(area).indexOf(false);
    if (free < 0) {
      if (kdf != Keyslot.kdfRaw) DatabaseFile._wipe(credential);
      throw InvalidArgumentException(
          'all ${Sb.keyslotCount} keyslots are occupied');
    }
    final slot = _wrapSlot(engine.keys!.masterKey, engine.databaseUuid, free,
        credential, kdf, tCost, mCostKib, parallelism, label);
    _keyslots[engine] = Uint8List.fromList(area)
      ..setRange(free * Keyslot.size, (free + 1) * Keyslot.size, slot.encode());
    engine.commit();
    return free;
  }

  /// Drops keyslot [index]. Removing the last occupied one is crypto-erase
  /// and MUST be asked for by name (14 §3.3), so it is refused here.
  void removeKey(int index) {
    final area = _slots();
    if (index < 0 || index >= Sb.keyslotCount) {
      throw InvalidArgumentException('keyslot $index does not exist');
    }
    final occ = _occupied(area);
    if (occ[index] && occ.where((o) => o).length <= 1) {
      throw const InvalidArgumentException(
          'removing the last occupied keyslot is crypto-erase; call '
          'cryptoErase() by name');
    }
    // 14 §8.2: zeros, not merely state = 0.
    _keyslots[engine] = Uint8List.fromList(area)
      ..fillRange(index * Keyslot.size, (index + 1) * Keyslot.size, 0);
    engine.commit();
  }

  /// 14 §8.2: zero every keyslot in **both** superblock slots. Irreversible.
  void cryptoErase() {
    final area = _slots();
    _keyslots[engine] = Uint8List(area.length);
    // One commit per superblock slot: either may hold an intact copy.
    engine
      ..commit()
      ..commit();
  }
}

/// 14 §8.3's fraction: objects in the target mode and objects not yet,
/// counted as Rust and Java count them (segments, tree pages, value-log
/// segments), each rewritten whole.
final class Conversion {
  const Conversion(this.converted, this.remaining);
  final int converted;
  final int remaining;
  bool get done => remaining == 0;
  double get fraction {
    final all = converted + remaining;
    return all == 0 ? 1.0 : converted / all;
  }
}

/// `13-operations.md` §5 `encrypt()`/`decrypt()` and 14 §8.3/§8.4 (F-072):
/// encryption turned on or off in place. The switch is one durable
/// superblock; [convertStep] then rewrites what is not yet in the target
/// mode, one kind of object per step. A file interrupted anywhere is valid
/// (CONVERTING is set) and the next call carries on. Rust `ConvertApi`, Java
/// `Engine.encrypt`/`decrypt`/`convertStep`.
///
/// ponytail: one step is one whole kind of object, not a slice bounded by
/// 12 §4's stall budget, as in Rust and Java. Refused on a file holding
/// descriptor-rooted index trees or vector regions (Java writes them, Dart
/// does not; their pages are not Dart's to re-lay).
/// F-079: pages owned through catalog descriptors, for `verifyStructure`:
/// trees rooted in a descriptor (R-trees, vector graphs; Java writes them)
/// walked in their own format, and vector regions (`09-vector.md` §5).
extension IndexClaims on Database {
  List<(int, int, String)> indexClaims() {
    final store = engine.store;
    final out = <(int, int, String)>[];
    for (final (name, d) in catalog.all) {
      final region = (d.param('vector_region') as CInt?)?.magnitude.lo ?? 0;
      if (region != 0) {
        out.add((
          region,
          math.max(1, PageHeader.read(store.readClear(region)).extentPages),
          'vector region of $name'
        ));
      }
      final root = d.root ?? 0;
      if (root == 0 || d.levelled || d.treeId == TreeId.treeIndex) continue;
      final spatial = (d.param('index_type') as CStr?)?.value == IndexType.spatial;
      if (!spatial) {
        for (final p in CowTree(store,
                treeId: d.treeId, root: root, rootNonce: d.rootNonce)
            .reachablePages()) {
          out.add((p, 1, 'index tree $name'));
        }
        continue;
      }
      final stack = [(root, d.rootNonce)];
      final seen = <int>{};
      while (stack.isNotEmpty) {
        final (p, nonce) = stack.removeLast();
        // A hostile file's cycle: claimed once; a double claim is reported.
        if (!seen.add(p)) continue;
        out.add((p, 1, 'index tree $name'));
        final n = RTreeNode.decode(store.readBound(p, nonce));
        if (n.isLeaf) continue;
        for (final e in n.entries) {
          stack.add((e.childPage, e.childNonce));
        }
      }
    }
    return out;
  }
}

extension ConvertApi on Database {
  static const int _converting = 1 << Feature.converting;

  void _requireFile() {
    if (engine.publisher == null || engine.store.file == null) {
      throw const InvalidArgumentException('needs a database open on a file');
    }
    for (final (name, d) in catalog.all) {
      if (d.param('vector_region') != null ||
          ((d.root ?? 0) != 0 &&
              !d.levelled &&
              // Tree 3 is the catalog's own index, in [Engine.outerTrees].
              d.treeId != TreeId.treeIndex)) {
        throw UnsupportedFeatureException(
            '$name: Dart does not convert vector regions or descriptor-rooted '
            'index trees; convert this file with Rust or Java');
      }
    }
  }

  /// Turns encryption on: [credential] is 32 raw key bytes for
  /// `Keyslot.kdfRaw`, a password (zeroed, F-135) for Argon2id.
  void encrypt(List<int> credential,
      {int kdf = Keyslot.kdfArgon2id,
      int tCost = 3,
      int mCostKib = 65536,
      int parallelism = 1,
      String label = 'keyslot 0'}) {
    final e = engine;
    try {
      _requireFile();
      if (e.keys != null || e.superblock!.cipher != 0) {
        throw const InvalidArgumentException('the file is already encrypted');
      }
    } catch (_) {
      if (kdf != Keyslot.kdfRaw) DatabaseFile._wipe(credential);
      rethrow;
    }
    // A quiet state; the open value-log segments sealed so none mixes
    // plaintext and encrypted framing.
    e.commit();
    e.vlog.sealOpen();
    e.commit();
    final master = randomBytes(32);
    final uuid = Uint8List.fromList(e.databaseUuid);
    final slot = _wrapSlot(master, uuid, 0, credential, kdf, tCost, mCostKib,
        parallelism, label);
    final area = Uint8List(Sb.keyslotSize * Sb.keyslotCount)
      ..setRange(0, Keyslot.size, slot.encode());
    _keyslots[e] = area;
    e.featuresOptional |= _converting;
    // The switch is durable before the first nonce is handed out (14 §4.1
    // rule 1): the floor publish installKeys makes writes this superblock,
    // cipher = 1 with its keyslot, sealed, to both slots.
    final image = e.superblock!.encode();
    final bd = ByteData.sublistView(image);
    bd
      ..setUint8(Sb.cipher, 1)
      ..setUint64(
          Sb.featuresRequired,
          e.superblock!.featuresRequired | (1 << Feature.cipher),
          Endian.little)
      ..setUint64(Sb.featuresOptional, e.featuresOptional, Endian.little);
    image.setRange(Sb.keyslots, Sb.keyslots + area.length, area);
    bd.setUint32(Sb.checksum, crc32c(image, 0, Sb.checksum), Endian.little);
    final sb = Superblock.tryDecode(image)!;
    final ring = KeyRing(master, uuid);
    final raf = e.store.file!;
    e
      ..superblock = sb
      ..installKeys(
          ring,
          NonceAllocator.open(sb.nextNonce,
              (floor) => DatabaseFile._publishNonceFloor(
                  raf, e.superblock!, ring, floor)));
    e.commit();
  }

  /// 14 §8.3's mirror, which "MUST make the user confirm it": refused unless
  /// [confirmRemoveEncryption]. New writes go plaintext; the cipher and the
  /// keyslots stay until [convertStep] has rewritten every encrypted object.
  /// Not persisted: after a reopen, call it again to carry on.
  void decrypt({bool confirmRemoveEncryption = false}) {
    if (!confirmRemoveEncryption) {
      throw const InvalidArgumentException(
          'decrypt() removes encryption from the whole file; it needs '
          'confirmRemoveEncryption: true');
    }
    _requireFile();
    final e = engine;
    final ring = e.keys, nonces = e.nonces;
    if (ring == null || nonces == null) {
      throw const InvalidArgumentException(
          'the file is not encrypted, or is not unlocked');
    }
    e.commit();
    e.vlog.sealOpen();
    e.featuresOptional |= _converting;
    e.installKeys(ring, nonces); // strict off: plaintext is now expected
    e.store.writePlain = true;
    e.vlog.writePlain = true;
    e.commit();
  }

  bool get _decrypting => engine.store.writePlain;

  /// The objects not yet in the target mode, read from the objects.
  ({int converted, List<SegmentRef> segments, int treePages, int vlogs})
      _census() {
    final e = engine;
    final store = e.store;
    final want = !_decrypting;
    bool sealed(int page) =>
        PageHeader.read(store.readClear(page), pageId: page).isEncrypted;
    var converted = 0, treePages = 0, vlogs = 0;
    final segments = <SegmentRef>[];
    for (final r in e.manifest.all) {
      if (r.startPage == 0) continue;
      if (sealed(r.startPage) == want) {
        converted++;
      } else {
        segments.add(r);
      }
    }
    final pages = <int>{
      for (final t in [
        e.manifest.tree,
        e.freelist,
        e.checkpoints.tree,
        e.changeFeed.tree,
        ...e.outerTrees.values,
      ])
        ...t.reachablePages()
    };
    for (final p in pages) {
      if (sealed(p) == want) {
        converted++;
      } else {
        treePages++;
      }
    }
    for (final v in e.vlog.segments.values) {
      if (v.startPage == 0 || v.bytes == 0) continue;
      // F-132: byte 39 is not written (F-076), so the first record says.
      final at = v.startPage * e.pageSize + VlogSegment.dataOffset;
      final head = store.readAt(at, v.bytes < 10 ? v.bytes : 10);
      final r = ByteReader(head, 0, head.length);
      final len = r.uvar();
      if (len < 5 || len > v.bytes) {
        throw CorruptionException('value-log segment ${v.id} first record');
      }
      final raw = store.readAt(at + r.position, len);
      final plain = crc32c(raw, 0, len - 4) ==
          ByteData.sublistView(raw).getUint32(len - 4, Endian.little);
      if (plain != want) {
        converted++;
      } else {
        vlogs++;
      }
    }
    return (
      converted: converted,
      segments: segments,
      treePages: treePages,
      vlogs: vlogs
    );
  }

  Conversion conversion() {
    final c = _census();
    return Conversion(
        c.converted, c.segments.length + c.treePages + c.vlogs);
  }

  /// True only when the file is encrypted and nothing plaintext remains
  /// (14 §8.3: never a reassuring answer while plaintext remains).
  bool get fullyEncrypted =>
      engine.store.strict && !_decrypting && conversion().done;

  /// Rewrites one kind of object not yet in the target mode, then commits.
  /// Returns true while more steps are needed.
  bool convertStep() {
    _requireFile();
    final e = engine;
    if (e.keys == null) {
      throw const InvalidArgumentException(
          'the file is not encrypted, or is not unlocked; call encrypt() first');
    }
    e.commit();
    final c = _census();
    if (c.segments.isNotEmpty || c.vlogs > 0) {
      // Every segment, every level, into the last level in one job, values
      // moved (recluster): never a subset, or stale versions win (Rust M2.1).
      final all = [for (var l = 0; l <= e.lastLevel; l++) ...e.refsAt(l)];
      final job = e.beginCompaction(all, e.lastLevel, forceRecluster: true);
      if (job != null) {
        while (!e.stepCompaction(job)) {}
        e.finishCompaction(job);
      }
    } else if (c.treePages > 0) {
      for (final t in [
        e.manifest.tree,
        e.checkpoints.tree,
        e.changeFeed.tree,
        ...e.outerTrees.values,
      ]) {
        t.relocate();
      }
    } else if (_decrypting) {
      // Nothing encrypted remains: one superblock drops the cipher and the
      // keyslots together (14 §6.1), twice so neither slot keeps them; with
      // cipher = 0 `sb_mac` is written as zero (§6.2).
      _keyslots[e] = Uint8List(Sb.keyslotSize * Sb.keyslotCount);
      e.featuresOptional &= ~(_converting | (1 << Feature.cipher));
      e
        ..destroyKeys()
        ..commit()
        ..commit();
      e.store.writePlain = false;
      e.vlog.writePlain = false;
      return false;
    } else {
      // F-127: nothing plaintext remains; the MAC'd superblock now says so,
      // and from here a plaintext object is tampering.
      if (e.featuresOptional & _converting != 0) {
        e.featuresOptional &= ~_converting;
        e
          ..installKeys(e.keys!, e.nonces!)
          ..commit();
      }
      return false;
    }
    e.commit();
    return true;
  }
}
