/// The container: superblock, page header, page types.
/// `spec/01-container.md`.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'crc32c.dart';
import 'errors.dart';
import 'limits.dart';

/// Page types, `spec/01-container.md` section 4.
class PageType {
  static const int free = 0;
  static const int btreeInternal = 1;
  static const int btreeLeaf = 2;
  static const int overflow = 3;
  static const int blob = 4;
  static const int segmentHeader = 5;
  static const int segmentFilter = 6;
  static const int vlogSegment = 7;
  static const int rtreeInternal = 8;
  static const int rtreeLeaf = 9;
  static const int vectorRegion = 10;
  static const int postingsBlock = 11;

  /// 192-255 are implementation-private: a reader MUST ignore these pages and
  /// MUST NOT reuse their space unless it owns the feature bit that allocated
  /// them.
  static bool isPrivate(int t) => t >= 192;

  /// 12-191 are reserved for future minor versions.
  static bool isReserved(int t) => t >= 12 && t < 192;
}

/// Page header flags, section 3.
class PageFlags {
  static const int compressed = 0x01;
  static const int encrypted = 0x02;
  static const int hasOverflow = 0x04;
  static const int extentHead = 0x08;
}

/// Page codec ids, `spec/01-container.md` section 7.
///
/// LZ4 is the default and the only codec a Level-0 implementation MUST
/// support. Zstd is feature bit `ZSTD`; this implementation does not set it, so
/// it never writes `page_codec = 2` and refuses a page carrying it rather than
/// guessing.
class Codec {
  static const int none = 0;
  static const int lz4 = 1;
  static const int zstd = 2;
}

/// Feature bits, `spec/11-conformance.md` section 2.
class Feature {
  static const int core = 0;
  static const int documents = 1;
  static const int text = 2;
  static const int spatial = 3;
  static const int vector = 4;
  static const int zstd = 5;
  static const int cipher = 6;
  static const int hash64 = 7;
  static const int dec128 = 8;
  static const int multiproc = 9;
  static const int dedup = 10;
  static const int multiprocRead = 11;
  static const int zdict = 12;
  static const int ttl = 13;
  static const int changefeed = 14;
  static const int checkpoints = 15;

  static const Map<int, String> names = {
    core: 'CORE',
    documents: 'DOCUMENTS',
    text: 'TEXT',
    spatial: 'SPATIAL',
    vector: 'VECTOR',
    zstd: 'ZSTD',
    cipher: 'CIPHER',
    hash64: 'HASH64',
    dec128: 'DEC128',
    multiproc: 'MULTIPROC',
    dedup: 'DEDUP',
    multiprocRead: 'MULTIPROC_READ',
    zdict: 'ZDICT',
    ttl: 'TTL',
    changefeed: 'CHANGEFEED',
    checkpoints: 'CHECKPOINTS',
  };

  /// Every bit this implementation understands, as a mask.
  static int get knownMask {
    var m = 0;
    for (final b in names.keys) {
      m |= 1 << b;
    }
    return m;
  }
}

/// Reserved tree ids, `spec/05-catalog.md` section 2.
class TreeId {
  static const int catalog = 0;
  static const int freeSpace = 1;
  static const int attributes = 2;
  static const int treeIndex = 3;
  static const int repairLog = 4;
  static const int users = 5;
  static const int manifest = 6;
  static const int vlogStats = 7;
  static const int checkpoints = 8;
  static const int changeFeed = 9;

  /// Ids 0-15 are reserved, and 0xFFFFFFFF is the page-header "no owning tree"
  /// sentinel (`spec/00-conventions.md` section 7).
  static const int firstUserTree = 16;
  static const int noTree = 0xFFFFFFFF;
}

/// Field offsets of the superblock, `spec/01-container.md` section 2.
///
/// Held as named constants rather than computed, so `superblock_test.dart` can
/// assert the layout is exactly what the spec table says. An offset that drifts
/// is a file two SDKs disagree about.
class Sb {
  static const int magic = 0;
  static const int versionMajor = 8;
  static const int versionMinor = 10;
  static const int writeVersionMinor = 12;
  static const int pageSizeLog2 = 14;
  static const int commitId = 16;
  static const int featuresRequired = 24;
  static const int featuresOptional = 32;
  static const int pageCount = 40;
  static const int visibleSeq = 48;
  static const int nextSeq = 56;
  static const int catalogRoot = 64;
  static const int freelistRoot = 72;
  static const int attributesRoot = 80;
  static const int manifestRoot = 88;
  static const int vlogStatsRoot = 96;
  static const int minRetainedCommit = 104;
  static const int minRetainedSeq = 112;
  static const int nextTreeId = 120;
  static const int nextSegmentId = 128;
  static const int nextVlogSegmentId = 136;
  static const int createdUtcMs = 144;
  static const int modifiedUtcMs = 152;
  static const int databaseUuid = 160;
  static const int durabilityAchieved = 176;
  static const int pageCodec = 177;
  static const int cipher = 178;
  static const int levelCount = 179;
  static const int fanout = 180;
  static const int l0Trigger = 181;
  static const int tierWidth = 182;
  static const int memtableShards = 183;
  static const int vlogMin = 184;
  static const int blobThreshold = 188;
  static const int vlogSegmentBytes = 192;
  static const int vlogSpaceTargetPct = 196;
  static const int liveKeyBytes = 200;
  static const int liveValueBytes = 208;
  static const int profile = 216;
  static const int overlapBound = 217;
  static const int localityDebtPct = 218;
  static const int filterBitsUpper = 219;
  static const int filterBitsLast = 220;
  static const int readaheadWindow = 224;
  static const int segmentTargetBytes = 228;
  static const int checkpointRoot = 232;
  static const int changefeedRoot = 240;
  static const int writerId = 256;
  // Security area, spec/14-security.md.
  static const int nextNonce = 288;
  static const int sbMac = 296;
  static const int keyslots = 3512;
  static const int checksum = 4092;

  /// The superblock is exactly 4096 bytes regardless of `page_size`.
  static const int size = 4096;

  static const int keyslotSize = 144;
  static const int keyslotCount = 4;
  static const List<int> magicBytes = [0x43, 0x52, 0x59, 0x50, 0x54, 0x41, 0x4E, 0x44];
}

/// Device profiles, `spec/12-profiles.md` section 1.
enum Profile {
  custom(0, 4096, 1024, 2, 4, 2, 1, 2 << 20, 4 << 20, 120, 20, 128, 12, 10),
  mobile(1, 4096, 1024, 2, 4, 2, 1, 2 << 20, 4 << 20, 120, 20, 128, 12, 10),
  tablet(2, 4096, 1024, 4, 6, 3, 2, 8 << 20, 16 << 20, 130, 20, 256, 14, 10),
  desktop(3, 8192, 256, 4, 8, 4, 2, 32 << 20, 64 << 20, 150, 20, 256, 16, 10),
  server(4, 16384, 256, 8, 10, 6, 3, 128 << 20, 256 << 20, 150, 25, 1024, 16, 10);

  const Profile(
    this.code,
    this.pageSize,
    this.vlogMin,
    this.l0Trigger,
    this.fanout,
    this.tierWidth,
    this.overlapBound,
    this.segmentTargetBytes,
    this.vlogSegmentBytes,
    this.vlogSpaceTargetPct,
    this.localityDebtPct,
    this.readaheadWindow,
    this.filterBitsUpper,
    this.filterBitsLast,
  );

  final int code;
  final int pageSize;
  final int vlogMin;
  final int l0Trigger;
  final int fanout;
  final int tierWidth;
  final int overlapBound;
  final int segmentTargetBytes;
  final int vlogSegmentBytes;
  final int vlogSpaceTargetPct;
  final int localityDebtPct;
  final int readaheadWindow;
  final int filterBitsUpper;
  final int filterBitsLast;

  /// `spec/12-profiles.md` §1's `page_codec` row and `01-container.md` §7:
  /// LZ4 is the default and **the only codec a Level-0 implementation MUST
  /// support**. Zstd is feature bit `ZSTD`; this implementation does not set
  /// it, so every profile names LZ4 and the heavier last-level codec §7
  /// recommends from `tablet` upward is left to a build that has one.
  ///
  /// It lives on the enum rather than in `profile.dart`'s behavioural
  /// extension because it is a *superblock field*, and the vector generator
  /// needs it without importing the engine.
  int get pageCodec => Codec.lz4;

  int get blobThreshold => switch (this) {
        Profile.mobile || Profile.custom => 65536,
        Profile.tablet => 131072,
        _ => 262144,
      };
}

/// The superblock, `spec/01-container.md` section 2.
final class Superblock {
  Superblock({
    required this.pageSize,
    required this.commitId,
    this.versionMinor = 0,
    this.writeVersionMinor = 0,
    this.featuresRequired = 1, // CORE
    this.featuresOptional = 0,
    this.pageCount = 2,
    this.visibleSeq = 0,
    this.nextSeq = 1,
    this.catalogRoot = 0,
    this.freelistRoot = 0,
    this.attributesRoot = 0,
    this.manifestRoot = 0,
    this.vlogStatsRoot = 0,
    this.checkpointRoot = 0,
    this.changefeedRoot = 0,
    this.minRetainedCommit = 0,
    this.minRetainedSeq = 0,
    this.nextTreeId = TreeId.firstUserTree,
    this.nextSegmentId = 1,
    this.nextVlogSegmentId = 1,
    this.createdUtcMs = 0,
    this.modifiedUtcMs = 0,
    Uint8List? databaseUuid,
    this.durabilityAchieved = 2,
    this.pageCodec = 0,
    this.cipher = 0,
    this.levelCount = 1,
    this.profile = Profile.desktop,
    this.liveKeyBytes = 0,
    this.liveValueBytes = 0,
    this.writerId = 'cryptand-dart/0.1.0-phase1',
    this.nextNonce = 0,
    Uint8List? sbMac,
    Uint8List? keyslots,
    int? vlogMin,
    int? blobThreshold,
    int? vlogSegmentBytes,
    int? vlogSpaceTargetPct,
    int? fanout,
    int? l0Trigger,
    int? tierWidth,
    int? overlapBound,
    int? localityDebtPct,
    int? filterBitsUpper,
    int? filterBitsLast,
    int? readaheadWindow,
    int? segmentTargetBytes,
    this.memtableShards = 1,
  })  : databaseUuid = databaseUuid ?? Uint8List(16),
        sbMac = sbMac ?? Uint8List(32),
        keyslots = keyslots ?? Uint8List(Sb.keyslotSize * Sb.keyslotCount),
        vlogMin = vlogMin ?? profile.vlogMin,
        blobThreshold = blobThreshold ?? profile.blobThreshold,
        vlogSegmentBytes = vlogSegmentBytes ?? profile.vlogSegmentBytes,
        vlogSpaceTargetPct = vlogSpaceTargetPct ?? profile.vlogSpaceTargetPct,
        fanout = fanout ?? profile.fanout,
        l0Trigger = l0Trigger ?? profile.l0Trigger,
        tierWidth = tierWidth ?? profile.tierWidth,
        overlapBound = overlapBound ?? profile.overlapBound,
        localityDebtPct = localityDebtPct ?? profile.localityDebtPct,
        filterBitsUpper = filterBitsUpper ?? profile.filterBitsUpper,
        filterBitsLast = filterBitsLast ?? profile.filterBitsLast,
        readaheadWindow = readaheadWindow ?? profile.readaheadWindow,
        segmentTargetBytes = segmentTargetBytes ?? profile.segmentTargetBytes {
    checkPageSize(pageSize);
    // spec/00-conventions.md section 8: vlog_min MUST be <= page_size / 4.
    checkVlogMin(this.vlogMin, pageSize);
    if (commitId < 1) {
      throw const InvalidArgumentException('commit_id starts at 1');
    }
    if (this.databaseUuid.length != 16) {
      throw const InvalidArgumentException('database_uuid is 16 bytes');
    }
    if (this.sbMac.length != 32) {
      throw const InvalidArgumentException('sb_mac is 32 bytes');
    }
    if (this.keyslots.length != Sb.keyslotSize * Sb.keyslotCount) {
      throw const InvalidArgumentException('keyslots area is 576 bytes');
    }
    if (levelCount < 1 || levelCount > 16) {
      throw InvalidArgumentException('level_count $levelCount outside 1..16');
    }
  }

  final int pageSize;
  final int commitId;
  final int versionMinor;
  final int writeVersionMinor;
  final int featuresRequired;
  final int featuresOptional;
  final int pageCount;
  final int visibleSeq;
  final int nextSeq;
  final int catalogRoot;
  final int freelistRoot;
  final int attributesRoot;
  final int manifestRoot;
  final int vlogStatsRoot;
  final int checkpointRoot;
  final int changefeedRoot;
  final int minRetainedCommit;
  final int minRetainedSeq;
  final int nextTreeId;
  final int nextSegmentId;
  final int nextVlogSegmentId;
  final int createdUtcMs;
  final int modifiedUtcMs;
  final Uint8List databaseUuid;
  final int durabilityAchieved;
  final int pageCodec;
  final int cipher;
  final int levelCount;
  final Profile profile;
  final int liveKeyBytes;
  final int liveValueBytes;
  final String writerId;
  final int nextNonce;
  final Uint8List sbMac;
  final Uint8List keyslots;
  final int vlogMin;
  final int blobThreshold;
  final int vlogSegmentBytes;
  final int vlogSpaceTargetPct;
  final int fanout;
  final int l0Trigger;
  final int tierWidth;
  final int overlapBound;
  final int localityDebtPct;
  final int filterBitsUpper;
  final int filterBitsLast;
  final int readaheadWindow;
  final int segmentTargetBytes;
  final int memtableShards;

  /// Which of the two slots this commit writes.
  ///
  /// Section 1: "the commit at commit_id = N writes slot A if N is odd, slot B
  /// if N is even".
  int get slot => commitId.isOdd ? 0 : 1;

  /// Byte offset of this commit's slot in the file.
  int slotOffset() => slot == 0 ? 0 : pageSize;

  Uint8List encode() {
    final buf = Uint8List(Sb.size);
    final bd = ByteData.view(buf.buffer);
    buf.setRange(Sb.magic, Sb.magic + 8, Sb.magicBytes);
    bd
      ..setUint16(Sb.versionMajor, 1, Endian.little)
      ..setUint16(Sb.versionMinor, versionMinor, Endian.little)
      ..setUint16(Sb.writeVersionMinor, writeVersionMinor, Endian.little)
      ..setUint16(Sb.pageSizeLog2, pageSize.bitLength - 1, Endian.little)
      ..setUint64(Sb.commitId, commitId, Endian.little)
      ..setUint64(Sb.featuresRequired, featuresRequired, Endian.little)
      ..setUint64(Sb.featuresOptional, featuresOptional, Endian.little)
      ..setUint64(Sb.pageCount, pageCount, Endian.little)
      ..setUint64(Sb.visibleSeq, visibleSeq, Endian.little)
      ..setUint64(Sb.nextSeq, nextSeq, Endian.little)
      ..setUint64(Sb.catalogRoot, catalogRoot, Endian.little)
      ..setUint64(Sb.freelistRoot, freelistRoot, Endian.little)
      ..setUint64(Sb.attributesRoot, attributesRoot, Endian.little)
      ..setUint64(Sb.manifestRoot, manifestRoot, Endian.little)
      ..setUint64(Sb.vlogStatsRoot, vlogStatsRoot, Endian.little)
      ..setUint64(Sb.minRetainedCommit, minRetainedCommit, Endian.little)
      ..setUint64(Sb.minRetainedSeq, minRetainedSeq, Endian.little)
      ..setUint64(Sb.nextTreeId, nextTreeId, Endian.little)
      ..setUint64(Sb.nextSegmentId, nextSegmentId, Endian.little)
      ..setUint64(Sb.nextVlogSegmentId, nextVlogSegmentId, Endian.little)
      ..setUint64(Sb.createdUtcMs, createdUtcMs, Endian.little)
      ..setUint64(Sb.modifiedUtcMs, modifiedUtcMs, Endian.little);
    buf.setRange(Sb.databaseUuid, Sb.databaseUuid + 16, databaseUuid);
    bd
      ..setUint8(Sb.durabilityAchieved, durabilityAchieved)
      ..setUint8(Sb.pageCodec, pageCodec)
      ..setUint8(Sb.cipher, cipher)
      ..setUint8(Sb.levelCount, levelCount)
      ..setUint8(Sb.fanout, fanout)
      ..setUint8(Sb.l0Trigger, l0Trigger)
      ..setUint8(Sb.tierWidth, tierWidth)
      ..setUint8(Sb.memtableShards, memtableShards)
      ..setUint32(Sb.vlogMin, vlogMin, Endian.little)
      ..setUint32(Sb.blobThreshold, blobThreshold, Endian.little)
      ..setUint32(Sb.vlogSegmentBytes, vlogSegmentBytes, Endian.little)
      ..setUint32(Sb.vlogSpaceTargetPct, vlogSpaceTargetPct, Endian.little)
      ..setUint64(Sb.liveKeyBytes, liveKeyBytes, Endian.little)
      ..setUint64(Sb.liveValueBytes, liveValueBytes, Endian.little)
      ..setUint8(Sb.profile, profile.code)
      ..setUint8(Sb.overlapBound, overlapBound)
      ..setUint8(Sb.localityDebtPct, localityDebtPct)
      ..setUint8(Sb.filterBitsUpper, filterBitsUpper)
      ..setUint8(Sb.filterBitsLast, filterBitsLast)
      ..setUint32(Sb.readaheadWindow, readaheadWindow, Endian.little)
      ..setUint32(Sb.segmentTargetBytes, segmentTargetBytes, Endian.little)
      ..setUint64(Sb.checkpointRoot, checkpointRoot, Endian.little)
      ..setUint64(Sb.changefeedRoot, changefeedRoot, Endian.little);
    final id = encodeUtf8Strict(writerId);
    if (id.length > 32) {
      throw const InvalidArgumentException('writer_id exceeds 32 bytes');
    }
    buf.setRange(Sb.writerId, Sb.writerId + id.length, id);
    bd.setUint64(Sb.nextNonce, nextNonce, Endian.little);
    buf
      ..setRange(Sb.sbMac, Sb.sbMac + 32, sbMac)
      ..setRange(Sb.keyslots, Sb.keyslots + keyslots.length, keyslots);
    // Section 2: "checksum | CRC-32C over bytes 0..4091".
    bd.setUint32(Sb.checksum, crc32c(buf, 0, Sb.checksum), Endian.little);
    return buf;
  }

  /// Parses one slot. Returns null when the slot is not a valid superblock,
  /// which section 2.1 step 3 treats as "prefer the other slot".
  static Superblock? tryDecode(Uint8List buf) {
    if (buf.length < Sb.size) return null;
    for (var i = 0; i < 8; i++) {
      if (buf[Sb.magic + i] != Sb.magicBytes[i]) return null;
    }
    final bd = ByteData.view(buf.buffer, buf.offsetInBytes, Sb.size);
    if (bd.getUint32(Sb.checksum, Endian.little) !=
        crc32c(buf, 0, Sb.checksum)) {
      return null;
    }
    if (bd.getUint16(Sb.versionMajor, Endian.little) != 1) return null;
    final log2 = bd.getUint16(Sb.pageSizeLog2, Endian.little);
    if (log2 < 12 || log2 > 16) return null;
    final pageSize = 1 << log2;
    final commitId = bd.getUint64(Sb.commitId, Endian.little);
    if (commitId < 1) return null;

    return Superblock(
      pageSize: pageSize,
      commitId: commitId,
      versionMinor: bd.getUint16(Sb.versionMinor, Endian.little),
      writeVersionMinor: bd.getUint16(Sb.writeVersionMinor, Endian.little),
      featuresRequired: bd.getUint64(Sb.featuresRequired, Endian.little),
      featuresOptional: bd.getUint64(Sb.featuresOptional, Endian.little),
      pageCount: bd.getUint64(Sb.pageCount, Endian.little),
      visibleSeq: bd.getUint64(Sb.visibleSeq, Endian.little),
      nextSeq: bd.getUint64(Sb.nextSeq, Endian.little),
      catalogRoot: bd.getUint64(Sb.catalogRoot, Endian.little),
      freelistRoot: bd.getUint64(Sb.freelistRoot, Endian.little),
      attributesRoot: bd.getUint64(Sb.attributesRoot, Endian.little),
      manifestRoot: bd.getUint64(Sb.manifestRoot, Endian.little),
      vlogStatsRoot: bd.getUint64(Sb.vlogStatsRoot, Endian.little),
      checkpointRoot: bd.getUint64(Sb.checkpointRoot, Endian.little),
      changefeedRoot: bd.getUint64(Sb.changefeedRoot, Endian.little),
      minRetainedCommit: bd.getUint64(Sb.minRetainedCommit, Endian.little),
      minRetainedSeq: bd.getUint64(Sb.minRetainedSeq, Endian.little),
      nextTreeId: bd.getUint64(Sb.nextTreeId, Endian.little),
      nextSegmentId: bd.getUint64(Sb.nextSegmentId, Endian.little),
      nextVlogSegmentId: bd.getUint64(Sb.nextVlogSegmentId, Endian.little),
      createdUtcMs: bd.getUint64(Sb.createdUtcMs, Endian.little),
      modifiedUtcMs: bd.getUint64(Sb.modifiedUtcMs, Endian.little),
      databaseUuid:
          Uint8List.fromList(buf.sublist(Sb.databaseUuid, Sb.databaseUuid + 16)),
      durabilityAchieved: bd.getUint8(Sb.durabilityAchieved),
      pageCodec: bd.getUint8(Sb.pageCodec),
      cipher: bd.getUint8(Sb.cipher),
      levelCount: bd.getUint8(Sb.levelCount),
      profile: Profile.values.firstWhere(
          (p) => p.code == bd.getUint8(Sb.profile),
          orElse: () => Profile.custom),
      liveKeyBytes: bd.getUint64(Sb.liveKeyBytes, Endian.little),
      liveValueBytes: bd.getUint64(Sb.liveValueBytes, Endian.little),
      writerId: _readWriterId(buf),
      nextNonce: bd.getUint64(Sb.nextNonce, Endian.little),
      sbMac: Uint8List.fromList(buf.sublist(Sb.sbMac, Sb.sbMac + 32)),
      keyslots: Uint8List.fromList(buf.sublist(
          Sb.keyslots, Sb.keyslots + Sb.keyslotSize * Sb.keyslotCount)),
      vlogMin: bd.getUint32(Sb.vlogMin, Endian.little),
      blobThreshold: bd.getUint32(Sb.blobThreshold, Endian.little),
      vlogSegmentBytes: bd.getUint32(Sb.vlogSegmentBytes, Endian.little),
      vlogSpaceTargetPct: bd.getUint32(Sb.vlogSpaceTargetPct, Endian.little),
      fanout: bd.getUint8(Sb.fanout),
      l0Trigger: bd.getUint8(Sb.l0Trigger),
      tierWidth: bd.getUint8(Sb.tierWidth),
      overlapBound: bd.getUint8(Sb.overlapBound),
      localityDebtPct: bd.getUint8(Sb.localityDebtPct),
      filterBitsUpper: bd.getUint8(Sb.filterBitsUpper),
      filterBitsLast: bd.getUint8(Sb.filterBitsLast),
      readaheadWindow: bd.getUint32(Sb.readaheadWindow, Endian.little),
      segmentTargetBytes: bd.getUint32(Sb.segmentTargetBytes, Endian.little),
      memtableShards: bd.getUint8(Sb.memtableShards),
    );
  }

  static String _readWriterId(Uint8List buf) {
    var end = Sb.writerId;
    while (end < Sb.writerId + 32 && buf[end] != 0) {
      end++;
    }
    return String.fromCharCodes(buf.sublist(Sb.writerId, end));
  }

  /// Section 2.1, the open procedure.
  ///
  /// Steps 4 (verify `sb_mac`) and 8 (nonce floor, seal open value-log
  /// segments) belong to a writer holding a key; this phase-1 reference
  /// implements the structural steps.
  static Superblock open(Uint8List slotA, Uint8List slotB,
      {int supportedMinor = 0}) {
    final a = tryDecode(slotA);
    final b = tryDecode(slotB);
    if (a == null && b == null) {
      throw const CorruptionException(
          'neither superblock slot is valid: not a Cryptand database, or '
          'corrupt beyond container-level repair');
    }
    final chosen = a == null
        ? b!
        : (b == null ? a : (a.commitId >= b.commitId ? a : b));

    final unknown = chosen.featuresRequired & ~Feature.knownMask;
    if (unknown != 0) {
      final bit = unknown.bitLength - 1;
      throw UnsupportedFeatureException(
          'unknown required feature bit $bit '
          '(${Feature.names[bit] ?? "unnamed"}); refusing to open');
    }
    return chosen;
  }

  bool get readOnlyForThisImplementation => false;
}

/// The 32-byte page header, `spec/01-container.md` section 3.
final class PageHeader {
  const PageHeader({
    required this.pageType,
    this.flags = 0,
    this.codecOrReserved = 0,
    this.treeId = TreeId.noTree,
    this.commitId = 0,
    this.extentPages = 1,
    this.payloadLen = 0,
    this.storedLen = 0,
    this.nonce = 0,
  });

  /// 40 bytes, `spec/01-container.md` section 3.
  static const int size = 40;

  final int pageType;
  final int flags;
  final int codecOrReserved;
  final int treeId;
  final int commitId;
  final int extentPages;
  final int payloadLen;

  /// `spec/14-security.md` section 5.2, in the reserved u32 at offset 28: the
  /// number of payload bytes actually *stored* on the page, after compression
  /// and after encryption. Zero means "same as [payloadLen]", which is every
  /// page that is neither, so no existing byte moves.
  ///
  /// Both fields are needed and the spec named only one. Section 3 of
  /// `spec/01-container.md` defines `payload_len` as the "uncompressed,
  /// unencrypted payload length" while section 5.2 of `spec/14-security.md`
  /// says the AEAD tag "is inside `payload_len`" — the two cannot both hold,
  /// and neither is implementable alone: a decryptor needs the exact stored
  /// length, because Poly1305 covers exactly the ciphertext, and a
  /// decompressor needs the plaintext length.
  final int storedLen;

  /// The allocated `next_nonce` value when `flags.ENCRYPTED`, 0 otherwise.
  /// `spec/14-security.md` section 4.2.
  final int nonce;

  /// The bytes actually on the page, which is what a cipher and a codec both
  /// have to be handed.
  int get stored => storedLen != 0 ? storedLen : payloadLen;

  bool get isEncrypted => flags & PageFlags.encrypted != 0;

  bool get isCompressed => flags & PageFlags.compressed != 0;

  /// Writes the header into [page] and computes the checksum over bytes
  /// `4..page.length-1`, as stored.
  void writeInto(Uint8List page) {
    if (page.length < size) {
      throw const InvalidArgumentException('page shorter than its header');
    }
    final bd = ByteData.view(page.buffer, page.offsetInBytes, page.length);
    bd
      ..setUint8(4, pageType)
      ..setUint8(5, flags)
      ..setUint16(6, codecOrReserved, Endian.little)
      ..setUint32(8, treeId, Endian.little)
      ..setUint32(12, extentPages, Endian.little)
      ..setUint64(16, commitId, Endian.little)
      ..setUint32(24, payloadLen, Endian.little)
      ..setUint32(28, storedLen, Endian.little)
      ..setUint64(32, nonce, Endian.little)
      ..setUint32(0, crc32c(page, 4, checksumEnd(page, pageType)), Endian.little);
  }

  /// The end of the checksummed range for a page of [pageType].
  ///
  /// **A value-log head page is the one exception, and the spec does not state
  /// it.** `spec/04-segments.md` section 6.2 fixes `data_offset` at 104, so a
  /// segment's records begin *inside its head page* — which
  /// `spec/01-container.md` section 1 explicitly permits ("an append into the
  /// open tail of a value-log segment"). A checksum over the whole page would
  /// therefore be stale from the first append onward: the page would fail its
  /// own checksum for the entire life of the segment. Section 3's carve-out —
  /// "a verifier MUST use the extent's mechanism for these pages" — is only
  /// satisfiable if the head page's checksum covers its immutable header
  /// region, `4 .. data_offset`, and the records are covered by their own
  /// per-record `crc32c`.
  static int checksumEnd(Uint8List page, int pageType) {
    if (pageType == PageType.vlogSegment && page.length >= size + 36) {
      final off = ByteData.view(page.buffer, page.offsetInBytes, page.length)
          .getUint32(size + 32, Endian.little);
      if (off > size && off <= page.length) return off;
    }
    return page.length;
  }

  /// Reads and verifies a page header. Throws [CorruptionException] on a
  /// checksum mismatch, naming the page.
  static PageHeader read(Uint8List page, {int? pageId}) {
    if (page.length < size) {
      throw const CorruptionException('page shorter than its header');
    }
    final bd = ByteData.view(page.buffer, page.offsetInBytes, page.length);
    final stored = bd.getUint32(0, Endian.little);
    final actual = crc32c(page, 4, checksumEnd(page, bd.getUint8(4)));
    if (stored != actual) {
      throw CorruptionException(
          'page checksum mismatch: stored 0x${stored.toRadixString(16)}, '
          'computed 0x${actual.toRadixString(16)}',
          pageId: pageId);
    }
    return PageHeader(
      pageType: bd.getUint8(4),
      flags: bd.getUint8(5),
      codecOrReserved: bd.getUint16(6, Endian.little),
      treeId: bd.getUint32(8, Endian.little),
      extentPages: bd.getUint32(12, Endian.little),
      commitId: bd.getUint64(16, Endian.little),
      payloadLen: bd.getUint32(24, Endian.little),
      storedLen: bd.getUint32(28, Endian.little),
      nonce: bd.getUint64(32, Endian.little),
    );
  }
}
