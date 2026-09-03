/// Cryptand File Format (CFF) v1.0 — reference implementation, phase 1.
///
/// The normative source is `cryptand/spec/`. Where this code and the spec
/// disagree, **the spec wins and this code is wrong**
/// (`spec/11-conformance.md` section 7).
///
/// `REPORT.md` states what is implemented, what is not, and every place a
/// measurement differs from a claim in `cryptand/design/`.
library;

export 'src/aead.dart'
    show
        chacha20,
        chacha20Block,
        chacha20Poly1305Decrypt,
        chacha20Poly1305Encrypt,
        hchacha20,
        poly1305,
        xchacha20Poly1305Decrypt,
        xchacha20Poly1305Encrypt;
export 'src/argon2.dart' show Argon2Result, argon2id, kArgon2Version;
export 'src/blake2b.dart' show Blake2b, blake2b;
export 'src/bytes.dart' show ByteReader, ByteWriter, encodeUtf8Strict;
export 'src/cke.dart'
    show
        Group,
        KeyRange,
        Keys,
        SignClass,
        TemporalClass,
        compareKeys,
        decodeKey,
        encodeKey,
        isKeyEncodable;
export 'src/compare.dart' show compareNumeric, compareValues, isOrdered;
export 'src/container.dart'
    show Feature, PageFlags, PageHeader, PageType, Profile, Sb, Superblock, TreeId;
export 'src/analyzer.dart' show Analyzer, Stemmer, Token;
export 'src/porter2.dart' show porter2Stem, snowballVersion;
export 'src/backup.dart' show Backup, BackupMode, BackupResult;
export 'src/changefeed.dart' show Change, ChangeFeed;
export 'src/catalog.dart'
    show
        Attributes,
        Catalog,
        DataTreeType,
        IndexType,
        TreeDescriptor,
        TreeKind;
export 'src/checkpoint.dart' show Checkpoint, CheckpointStore;
export 'src/cow.dart' show CowTree, PageStore;
export 'src/crc32c.dart' show crc32c;
export 'src/database.dart' show Collection, Database, kFormatVersion;
export 'src/cve.dart'
    show DocFlags, DocView, NameDict, decodeValue, encodeValue, readValue, writeDoc, writeValue;
export 'src/engine.dart'
    show
        CompactionJob,
        Engine,
        LevelPolicy,
        LocalityPolicy,
        ScanResult,
        percentile;
export 'src/verify.dart' show EngineVerify, Finding, VerifyReport;
export 'src/txn.dart'
    show
        Backpressure,
        Bound,
        Durability,
        Isolation,
        Snapshot,
        StoreEvent,
        StoreEventKind,
        Transaction,
        TxnWrite;
export 'src/manifest.dart' show Manifest, SegmentRef, manifestKey;
export 'src/metrics.dart' show EngineMetrics, Metrics;
export 'src/errors.dart';
export 'src/index.dart'
    show
        IndexDescriptor,
        IndexScan,
        indexEntryId,
        indexEntryValues,
        indexKeysFor,
        kMaxIndexEntriesPerDocument,
        resolvePath,
        splitFieldPath,
        uniquenessApplies;
export 'src/fulltext.dart'
    show Posting, PostingsBlock, TermEntry, kPostingsBlockMax;
export 'src/unicode.dart'
    show
        combiningClass,
        hasNumericType,
        isAlphabetic,
        isExtendedPictographic,
        nfc,
        nfkc,
        simpleLowercaseMapping,
        wordBoundaries,
        wordBreakProperty;
export 'src/unicode_tables.dart' show unicodeVersion;
export 'src/geometry_ops.dart' show Spatial;
export 'src/rtree.dart'
    show
        RTree,
        RTreeEntry,
        RTreeFlags,
        RTreeNode,
        SpatialEntry,
        entryStride,
        maxEntriesFor;
export 'src/vector.dart'
    show
        Adjacency,
        Codebook,
        RegionDType,
        VectorIndex,
        VectorMetric,
        VectorRegion,
        VectorRegionHeader,
        vectorDistance;
export 'src/wkb.dart'
    show
        Coord,
        Envelope,
        EwkbFlags,
        Geometry,
        GeometryType,
        decodeWkb,
        encodeWkb;
export 'src/filter.dart'
    show BlockedBloom, Hash64, blockCountFor, cfh64, kBlockBits, probesFor;
export 'src/limits.dart';
export 'src/security.dart'
    show
        KeyRing,
        Keyslot,
        NonceAllocator,
        NonceDomain,
        Purpose,
        buildNonce,
        constantTimeEquals,
        decryptPagePayload,
        decryptVlogRecord,
        deriveKek,
        deriveSubkey,
        encryptPagePayload,
        encryptVlogRecord,
        hkdf,
        hmacSha256,
        kNonceGap,
        sha256,
        unlock,
        unlockWithPassword,
        unwrapMasterKey,
        vlogAad,
        wrapMasterKey,
        superblockMac,
        verifySuperblockMac;
export 'src/profile.dart'
    show
        EngineProfile,
        HostHints,
        InvalidProfileChange,
        ProfileBehaviour,
        StallSample;
export 'src/repair.dart' show EngineRepair, RepairReport;
export 'src/spaceapi.dart' show EngineSpaceApi, MaintenanceStep;
export 'src/stats.dart'
    show HistogramBucket, HyperLogLog, IndexStats, StatsBuilder;
export 'src/segment.dart'
    show
        Node,
        Op,
        SegEntry,
        SegFlags,
        SegRecord,
        RangeDelete,
        Segment,
        SegmentBuilder,
        SegmentCursor,
        SegmentHeader,
        ValueKind,
        encodeNodePage,
        nodePageBytes,
        kHasExpiry,
        kPointerBytes,
        internalKey,
        parseInternalKey,
        shortestSeparator,
        userKeyPrefix;
export 'src/u128.dart' show U128, clz64;
export 'src/vlog.dart'
    show HeatClass, ValueLog, VlogPointer, VlogSegment, VlogTier;
export 'src/value.dart';
