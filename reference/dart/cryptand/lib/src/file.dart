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
import 'segment.dart';
import 'value.dart';
import 'vlog.dart';

/// Reads and writes a database file.
abstract final class DatabaseFile {
  /// Lays the engine out as a file and writes it.
  ///
  /// The order matters and is the order §1 gives: extents are allocated first,
  /// so their page ids are fixed before anything records them; then the
  /// manifest and tree 7 are written, which appends copy-on-write pages *after*
  /// the extents and so cannot move them; then the superblock, last, because it
  /// is what publishes all of it.
  static void save(Database db, String path, {String? writerId}) {
    final e = db.engine;
    final store = e.store;

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
      store.writeExtent(v.startPage, v.extent);
      stats.put(
        encodeKey(CInt.of(NumType.u64, v.id)),
        encodeVlogStats(v, startPage: v.startPage),
      );
    }

    // 4. The superblock, last.
    final sb = Superblock(
      pageSize: store.pageSize,
      commitId: e.commitId,
      pageCount: store.pageCount,
      visibleSeq: e.visibleSeq,
      nextSeq: e.nextSeq,
      catalogRoot: db.catalogRoot,
      freelistRoot: 0,
      attributesRoot: db.attributesRoot,
      manifestRoot: e.manifest.root,
      vlogStatsRoot: stats.root,
      checkpointRoot: e.checkpoints.root,
      changefeedRoot: e.changeFeed.root,
      nextTreeId: db.catalog.nextTreeId,
      nextSegmentId: e.nextSegmentId,
      nextVlogSegmentId: e.vlog.nextId,
      databaseUuid: e.databaseUuid,
      // §7 of `spec/10-transactions.md`: record what was *performed*.
      durabilityAchieved: 2,
      levelCount: e.levels.levelCount,
      profile: Profile.desktop,
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
    // §1: slot A when `commit_id` is odd, slot B when it is even, so a crash
    // during a superblock write leaves the previous superblock intact. Both
    // slots are written here because a fresh file has no previous superblock
    // to leave intact, and an unreadable slot B would make §2.1 step 3 pick
    // between one valid slot and one absent one on every later open.
    bytes.setRange(0, Sb.size, image);
    bytes.setRange(store.pageSize, store.pageSize + Sb.size, image);
    File(path).writeAsBytesSync(bytes, flush: true);
  }

  /// Reads a file back into an engine.
  static Database open(String path) {
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
    if (sb.cipher != 0) {
      throw const UnsupportedFeatureException(
          'this reader opens unencrypted files only');
    }
    // §2.1 step 7: ignore everything at or beyond `page_count` — debris from
    // an interrupted commit.
    final used = sb.pageCount * sb.pageSize;
    final store = PageStore.fromBytes(
        Uint8List.sublistView(bytes, 0, used > bytes.length ? bytes.length : used),
        pageSize: sb.pageSize);

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
      final extent = store.readExtent(u('start_page'), u('pages'));
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
    );
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
