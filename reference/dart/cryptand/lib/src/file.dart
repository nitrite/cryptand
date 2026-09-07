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

import 'dart:io';
import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'database.dart';
import 'engine.dart';
import 'errors.dart';
import 'manifest.dart';
import 'profile.dart';
import 'security.dart';
import 'txn.dart';
import 'segment.dart';
import 'value.dart';
import 'vlog.dart';

/// Reads and writes a database file.
String _hex(Uint8List b) {
  final sb = StringBuffer();
  for (final x in b) {
    sb.write(x.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

/// The keyslot area a database was opened or created with, so a `save` that
/// rewrites the superblock does not drop the credentials with it. Keyed on the
/// engine rather than stored on it because keyslots are file-level state: an
/// in-memory engine has none.
final Expando<Uint8List> _keyslots = Expando('cryptand keyslots');

abstract final class DatabaseFile {
  /// Lays the engine out as a file and writes it.
  ///
  /// The order matters and is the order §1 gives: extents are allocated first,
  /// so their page ids are fixed before anything records them; then the
  /// manifest and tree 7 are written, which appends copy-on-write pages *after*
  /// the extents and so cannot move them; then the superblock, last, because it
  /// is what publishes all of it.
  static void save(Database db, String path,
      {String? writerId, Uint8List? keyslots}) {
    final e = db.engine;
    final store = e.store;
    // Publishing a superblock is a commit, and §6's reclamation rule is
    // stated over commit ids: this is what makes the previous session's freed
    // extents reallocatable and attributes this one's to a new id.
    e.beginPublish();
    // §2 of `spec/05-catalog.md`: tree 3's root lives in its own catalog
    // descriptor. Publishing it is what stops the next open from rebuilding
    // the tree and orphaning this one — a leak per open, and the only thing
    // that ever finds it is another implementation's §9 step 7.
    db.catalog.publishTreeIndex();
    // §4.1 rule 1 applies to a *writer*, and the writer is about to place
    // every extent below. On a file this session created, the floor was
    // published by [create]; on one it opened, by [open]. Nothing here
    // allocates a nonce that a published floor does not already cover.

    // 1. Every segment the manifest names becomes an extent at a real page id.
    final refs = e.manifest.all.toList();
    final placed = <SegmentRef>[];
    var moved = false;
    for (final ref in refs) {
      final seg = e.extents[ref.segmentId];
      if (seg == null) {
        throw StateError('manifest names segment ${ref.segmentId}, '
            'which this engine does not hold');
      }
      // A segment that already has an extent keeps it. Segments are immutable
      // (§2), so re-placing one would append a second copy of bytes that
      // cannot have changed.
      if (ref.startPage != 0 && ref.pages == seg.pageCount) {
        placed.add(ref);
        continue;
      }
      final start = store.allocExtent(seg.pageCount);
      store.writeExtent(start, seg.extent);
      placed.add(_withPlacement(ref, start, seg.pageCount));
      moved = true;
    }

    // 2. Republish the manifest with the real placements, if any changed.
    //    Removing before adding, because a re-placed entry keeps its key.
    if (moved) {
      for (final ref in refs) {
        e.manifest.remove(ref);
      }
      for (final ref in placed) {
        e.manifest.add(ref);
      }
    }

    // 3. The value log: one extent each, and tree 7 for everything mutable
    //    about them (§6.7 — "This tree is the **authority** for everything
    //    mutable about a value-log segment").
    final stats = CowTree(store, treeId: TreeId.vlogStats);
    for (final v in e.vlog.segments.values) {
      if (v.startPage == 0) {
        v.startPage = store.allocExtent(v.pageCount);
      }
      store.writeExtentClear(v.startPage, v.extent);
      stats.put(
        encodeKey(CInt.of(NumType.u64, v.id)),
        encodeVlogStats(v, startPage: v.startPage),
      );
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
    final free = e.freelist;
    final want = {
      for (final x in store.freeExtents)
        encodeKey(CArray([
          CInt.of(NumType.u64, x.commitId),
          CInt.of(NumType.u64, x.startPage),
        ])): encodeValue(CDoc({'pages': CInt.of(NumType.u32, x.pages)}))
    };
    final wantKeys = {for (final k in want.keys) _hex(k)};
    for (final (k, _) in free.scan().toList()) {
      if (!wantKeys.contains(_hex(k))) free.remove(k);
    }
    for (final entry in want.entries) {
      free.put(entry.key, entry.value);
    }

    // 4. The superblock, last.
    final sb = Superblock(
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
      nextTreeId: db.catalog.nextTreeId,
      nextSegmentId: e.nextSegmentId,
      nextVlogSegmentId: e.vlog.nextId,
      databaseUuid: e.databaseUuid,
      minRetainedCommit: e.minRetainedCommit,
      minRetainedSeq: e.minRetainedSeq,
      // §7 of `spec/10-transactions.md`: record what was **performed**. The
      // file is written with `flush: true` below, which is `Durability.sync`;
      // claiming more than that is the one thing §7 forbids.
      durabilityAchieved: Durability.sync.code,
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
      createdUtcMs: DateTime.now().millisecondsSinceEpoch,
      modifiedUtcMs: DateTime.now().millisecondsSinceEpoch,
    );

    final bytes = store.toBytes();
    final image = sb.encode();
    // §6.2 — `sb_mac` authenticates the superblock; without it anyone can set
    // `cipher = 0` or weaken an Argon2id cost and no reader can tell.
    sealSuperblock(image, e.keys);
    // §1: slot A when `commit_id` is odd, slot B when it is even, so a crash
    // during a superblock write leaves the previous superblock intact. Both
    // slots are written here because a fresh file has no previous superblock
    // to leave intact, and an unreadable slot B would make §2.1 step 3 pick
    // between one valid slot and one absent one on every later open.
    bytes.setRange(0, Sb.size, image);
    bytes.setRange(store.pageSize, store.pageSize + Sb.size, image);
    File(path).writeAsBytesSync(bytes, flush: true);
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
  }) {
    final uuid = randomBytes(16);
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    final master = randomBytes(32);
    final salt = randomBytes(32);
    final slot = wrapMasterKey(
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
    final keyslots = Uint8List(Sb.keyslotSize * Sb.keyslotCount)
      ..setRange(0, Keyslot.size, slot.encode());

    final ring = KeyRing(master, uuid);
    final e = Engine(
        pageSize: profile.pageSize,
        memtableEntries: memtableEntries,
        vlogMin: profile.vlogMin);
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
      vlogMin: profile.vlogMin,
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
    File(path).writeAsBytesSync(blank, flush: true);

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
              0, (floor) => _publishNonceFloor(path, sb, ring, floor)));
    return Database(engine: e);
  }

  /// Reads a file back into an engine.
  ///
  /// [key] is the credential of `spec/14-security.md` §3.3: 32 raw bytes for a
  /// `kdf = 0` slot, or a password for an Argon2id slot. An encrypted file
  /// opened without one fails with [CannotUnlockException], which §3.3 requires
  /// to be reported identically for a missing keyslot and a wrong password.
  static Database open(String path, {List<int>? key}) {
    final lock = _takeWriterLock(path);
    try {
      return _open(path, key);
    } finally {
      lock.closeSync();
    }
  }

  /// `spec/01-container.md` §10 — "one writing **process** per database,
  /// enforced by an exclusive advisory lock on the database file
  /// (`flock` / `LockFileEx`) held for its writing lifetime", and "a second
  /// process opening for writing MUST fail with a clear 'locked by another
  /// process' error and MUST NOT fall back to opening anyway".
  ///
  /// The lock rides the open file handle, so it is released when the handle
  /// closes — including when the process dies, which is what makes a crashed
  /// writer's database openable again with no cleanup step.
  static RandomAccessFile _takeWriterLock(String path) {
    final f = File(path).openSync(mode: FileMode.append);
    try {
      f.lockSync(FileLock.exclusive);
    } on FileSystemException catch (e) {
      f.closeSync();
      throw LockedException('$path is open for writing by another process, '
          'or lies on a filesystem that cannot lock it (${e.osError?.message ?? e.message})');
    }
    return f;
  }

  static Database _open(String path, List<int>? key) {
    final bytes = File(path).readAsBytesSync();
    if (bytes.length < 2 * Sb.size) {
      throw const CorruptionException('file is shorter than two superblocks');
    }
    // §2.1 steps 1–3, and the page size is not known until slot A is read.
    final probe = Superblock.tryDecode(Uint8List.sublistView(bytes, 0, Sb.size));
    final pageSize = probe?.pageSize ?? 4096;
    if (bytes.length < 2 * pageSize) {
      throw const CorruptionException('file is shorter than its two slots');
    }
    final sb = Superblock.open(
      Uint8List.sublistView(bytes, 0, Sb.size),
      Uint8List.sublistView(bytes, pageSize, pageSize + Sb.size),
    );
    // §3 of `spec/11-conformance.md`: an unknown bit in `features_required`
    // is a refusal, named.
    for (var b = 0; b < 64; b++) {
      if (sb.featuresRequired & (1 << b) != 0 && !Feature.names.containsKey(b)) {
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
    if (sb.cipher != 0) {
      if (key == null) throw const CannotUnlockException();
      final master = _unlockMaster(sb, key);
      if (master == null) throw const CannotUnlockException();
      ring = KeyRing(master, Uint8List.fromList(sb.databaseUuid));
      // §6.2 — verify `sb_mac` before acting on any other field, so an
      // attacker cannot set `cipher = 0` or weaken an Argon2id cost.
      verifySuperblockMac(ring.macKey, sb.encode());
    }
    // §2.1 step 7: ignore everything at or beyond `page_count` — debris from
    // an interrupted commit.
    final used = sb.pageCount * sb.pageSize;
    final store = PageStore.fromBytes(
        Uint8List.sublistView(bytes, 0, used > bytes.length ? bytes.length : used),
        pageSize: sb.pageSize)
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
      e.installKeys(
          ring,
          NonceAllocator.open(
              sb.nextNonce, (floor) => _publishNonceFloor(path, sb, ring, floor)));
    }

    // §6: the free tree, read back so this session reuses space rather than
    // extending the file for ever. Read before the segment extents so that
    // nothing has allocated yet.
    if (sb.freelistRoot != 0) {
      final extents = <FreeExtent>[];
      for (final (k, v) in e.freelist.scan()) {
        final a = decodeKey(k) as CArray;
        final d = decodeValue(v) as CDoc;
        extents.add(FreeExtent(
          ((a.items[0] as CInt).magnitude).lo,
          ((a.items[1] as CInt).magnitude).lo,
          ((d['pages']! as CInt).magnitude).lo,
        ));
      }
      store.loadFree(extents);
    }

    // Segment extents, addressed by the manifest's `start_page`/`pages`.
    for (final ref in e.manifest.all) {
      if (ref.pages == 0) {
        throw CorruptionException(
            'manifest entry for segment ${ref.segmentId} has no extent');
      }
      e.extents[ref.segmentId] =
          Segment(store.readExtent(ref.startPage, ref.pages), sb.pageSize);
    }

    // Value-log segments, from tree 7.
    final stats = CowTree(store, treeId: TreeId.vlogStats, root: sb.vlogStatsRoot);
    for (final (k, v) in stats.scan()) {
      final id = ((decodeKey(k) as CInt).magnitude).lo;
      final d = decodeValue(v) as CDoc;
      int u(String f) => ((d[f]! as CInt).magnitude).lo;
      bool b(String f) => (d[f] as CBool?)?.value ?? false;
      Uint8List? by(String f) => (d[f] as CBytes?)?.value;
      final extent = store.readExtentClear(u('start_page'), u('pages'));
      final seg = VlogSegment.fromExtent(
        extent,
        sb.pageSize,
        bytes: u('bytes'),
        records: u('records'),
        sealed: b('sealed'),
        clustered: b('clustered'),
        minKey: by('min_key'),
        maxKey: by('max_key'),
        liveBytes: u('live_bytes'),
        liveRecords: u('live_records'),
      );
      seg.startPage = u('start_page');
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
    }

    // Trees 0, 2 and 3, rooted from the superblock like everything else.
    return Database(
      engine: e,
      catalogRoot: sb.catalogRoot,
      attributesRoot: sb.attributesRoot,
      nextTreeId: sb.nextTreeId,
      // §4 rule 2 of `spec/11-conformance.md`: a reopen preserves what the
      // file holds, so it does not overwrite the store metadata another SDK
      // wrote.
      initStoreMetadata: false,
    )..catalog.loadTreeIndex();
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
    return unlockWithPassword(
        keyslotArea: sb.keyslots, password: key, databaseUuid: uuid);
  }

  /// §4.1's publish: the superblock, with the new floor, made durable before
  /// the value it names is allowed to be handed out.
  ///
  /// Both slots, because the floor is the one field a crash must never see go
  /// backwards, and a slot that still holds the old value is a slot §2.1 step
  /// 3 could pick.
  static void _publishNonceFloor(
      String path, Superblock sb, KeyRing? ring, int floor) {
    final image = sb.encode();
    final bd = ByteData.view(image.buffer, image.offsetInBytes, image.length);
    bd.setUint64(Sb.nextNonce, floor, Endian.little);
    sealSuperblock(image, ring);
    final f = File(path).openSync(mode: FileMode.writeOnlyAppend);
    try {
      f
        ..setPositionSync(0)
        ..writeFromSync(image)
        ..setPositionSync(sb.pageSize)
        ..writeFromSync(image)
        ..flushSync();
    } finally {
      f.closeSync();
    }
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

SegmentRef _withPlacement(SegmentRef r, int startPage, int pages) => SegmentRef(
      segmentId: r.segmentId,
      level: r.level,
      group: r.group,
      minKey: r.minKey,
      maxKey: r.maxKey,
      minSeq: r.minSeq,
      maxSeq: r.maxSeq,
      entries: r.entries,
      tombstones: r.tombstones,
      hasRangeDeletes: r.hasRangeDeletes,
      startPage: startPage,
      pages: pages,
      root: r.root,
      filter: r.filter,
      minExpiry: r.minExpiry,
      valueBytes: r.valueBytes,
      vlogBytes: r.vlogBytes,
      trees: r.trees,
    );
