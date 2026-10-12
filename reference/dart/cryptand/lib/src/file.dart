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
import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'database.dart';
import 'engine.dart';
import 'errors.dart';
import 'profile.dart';
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
    raf
      ..setPositionSync(sb.commitId.isOdd ? 0 : store.pageSize)
      ..writeFromSync(image);
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
    free.rebuildFresh([
      for (final x in store.freeExtents)
        (
          encodeKey(CArray([
            CInt.of(NumType.u64, x.commitId),
            CInt.of(NumType.u64, x.startPage),
          ])),
          encodeValue(CDoc({'pages': CInt.of(NumType.u32, x.pages)}))
        )
    ]..sort((a, b) => compareKeys(a.$1, b.$1)));

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
    final salt = randomBytes(32);
    final Keyslot slot;
    try {
      slot = wrapMasterKey(
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
        slotIndex: 0,
        wrapNonce: randomBytes(24),
        salt: salt,
        kdf: kdf,
        tCost: tCost,
        mCostKib: mCostKib,
        parallelism: parallelism,
        label: label,
      );
    } finally {
      if (kdf != Keyslot.kdfRaw) _wipe(credential);
    }
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
      e.superblock = sb;
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
      )..catalog.loadTreeIndex();
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
    f
      ..setPositionSync(0)
      ..writeFromSync(image)
      ..setPositionSync(sb.pageSize)
      ..writeFromSync(image)
      ..flushSync();
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
