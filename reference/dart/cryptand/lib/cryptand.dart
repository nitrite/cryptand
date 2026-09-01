/// Cryptand File Format (CFF) v1.0 — reference implementation, phase 1.
///
/// The normative source is `cryptand/spec/`. Where this code and the spec
/// disagree, **the spec wins and this code is wrong**
/// (`spec/11-conformance.md` section 7).
///
/// `REPORT.md` states what is implemented, what is not, and every place a
/// measurement differs from a claim in `cryptand/design/`.
library;

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
export 'src/crc32c.dart' show crc32c;
export 'src/cve.dart'
    show DocFlags, DocView, NameDict, decodeValue, encodeValue, readValue, writeDoc, writeValue;
export 'src/errors.dart';
export 'src/filter.dart'
    show BlockedBloom, Hash64, blockCountFor, crcHash64, kBlockBits, probesFor;
export 'src/limits.dart';
export 'src/security.dart'
    show
        Keyslot,
        NonceAllocator,
        NonceDomain,
        Purpose,
        buildNonce,
        constantTimeEquals,
        deriveSubkey,
        hkdf,
        hmacSha256,
        kNonceGap,
        sha256,
        superblockMac,
        verifySuperblockMac;
export 'src/segment.dart'
    show
        Node,
        Op,
        SegEntry,
        SegFlags,
        SegRecord,
        Segment,
        SegmentBuilder,
        SegmentCursor,
        SegmentHeader,
        ValueKind,
        internalKey,
        parseInternalKey,
        shortestSeparator,
        userKeyPrefix;
export 'src/u128.dart' show U128, clz64;
export 'src/value.dart';
