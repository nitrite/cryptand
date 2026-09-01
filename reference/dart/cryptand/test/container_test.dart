import 'dart:typed_data';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/crc32c.dart';
import 'package:cryptand/src/errors.dart';
import 'package:test/test.dart';

void main() {
  group('superblock layout', () {
    // Every offset below is copied from the table in
    // spec/01-container.md section 2. If the spec table and this list ever
    // disagree, a file written by one SDK is unreadable by another.
    test('field offsets and widths tile 0..4095 with no gap or overlap', () {
      final fields = <(String, int, int)>[
        ('magic', Sb.magic, 8),
        ('version_major', Sb.versionMajor, 2),
        ('version_minor', Sb.versionMinor, 2),
        ('write_version_minor', Sb.writeVersionMinor, 2),
        ('page_size_log2', Sb.pageSizeLog2, 2),
        ('commit_id', Sb.commitId, 8),
        ('features_required', Sb.featuresRequired, 8),
        ('features_optional', Sb.featuresOptional, 8),
        ('page_count', Sb.pageCount, 8),
        ('visible_seq', Sb.visibleSeq, 8),
        ('next_seq', Sb.nextSeq, 8),
        ('catalog_root', Sb.catalogRoot, 8),
        ('freelist_root', Sb.freelistRoot, 8),
        ('attributes_root', Sb.attributesRoot, 8),
        ('manifest_root', Sb.manifestRoot, 8),
        ('vlog_stats_root', Sb.vlogStatsRoot, 8),
        ('min_retained_commit', Sb.minRetainedCommit, 8),
        ('min_retained_seq', Sb.minRetainedSeq, 8),
        ('next_tree_id', Sb.nextTreeId, 8),
        ('next_segment_id', Sb.nextSegmentId, 8),
        ('next_vlog_segment_id', Sb.nextVlogSegmentId, 8),
        ('created_utc_ms', Sb.createdUtcMs, 8),
        ('modified_utc_ms', Sb.modifiedUtcMs, 8),
        ('database_uuid', Sb.databaseUuid, 16),
        ('durability_achieved', Sb.durabilityAchieved, 1),
        ('page_codec', Sb.pageCodec, 1),
        ('cipher', Sb.cipher, 1),
        ('level_count', Sb.levelCount, 1),
        ('fanout', Sb.fanout, 1),
        ('l0_trigger', Sb.l0Trigger, 1),
        ('tier_width', Sb.tierWidth, 1),
        ('memtable_shards', Sb.memtableShards, 1),
        ('vlog_min', Sb.vlogMin, 4),
        ('blob_threshold', Sb.blobThreshold, 4),
        ('vlog_segment_bytes', Sb.vlogSegmentBytes, 4),
        ('vlog_space_target_pct', Sb.vlogSpaceTargetPct, 4),
        ('live_key_bytes', Sb.liveKeyBytes, 8),
        ('live_value_bytes', Sb.liveValueBytes, 8),
        ('profile', Sb.profile, 1),
        ('overlap_bound', Sb.overlapBound, 1),
        ('locality_debt_pct', Sb.localityDebtPct, 1),
        ('filter_bits_upper', Sb.filterBitsUpper, 1),
        ('filter_bits_last', Sb.filterBitsLast, 1),
        ('reserved(221)', 221, 3),
        ('readahead_window', Sb.readaheadWindow, 4),
        ('segment_target_bytes', Sb.segmentTargetBytes, 4),
        ('checkpoint_root', Sb.checkpointRoot, 8),
        ('changefeed_root', Sb.changefeedRoot, 8),
        ('reserved(248)', 248, 8),
        ('writer_id', Sb.writerId, 32),
        ('next_nonce', Sb.nextNonce, 8),
        ('sb_mac', Sb.sbMac, 32),
        ('reserved(328)', 328, 3184),
        ('keyslots', Sb.keyslots, Sb.keyslotSize * Sb.keyslotCount),
        ('reserved(4088)', 4088, 4),
        ('checksum', Sb.checksum, 4),
      ];
      fields.sort((a, b) => a.$2.compareTo(b.$2));
      var cursor = 0;
      for (final (name, off, size) in fields) {
        expect(off, cursor, reason: '$name should start at $cursor');
        cursor = off + size;
      }
      expect(cursor, Sb.size, reason: 'the superblock must tile exactly 4096 B');
    });

    test('keyslots are 4 x 144 and end where the reserved tail begins', () {
      expect(Sb.keyslotSize * Sb.keyslotCount, 576);
      expect(Sb.keyslots + 576, 4088);
    });
  });

  group('page header', () {
    test('is 40 bytes and its fields tile it', () {
      final fields = <(String, int, int)>[
        ('checksum', 0, 4),
        ('page_type', 4, 1),
        ('flags', 5, 1),
        ('codec_or_reserved', 6, 2),
        ('tree_id', 8, 4),
        ('extent_pages', 12, 4),
        ('commit_id', 16, 8),
        ('payload_len', 24, 4),
        ('reserved', 28, 4),
        ('nonce', 32, 8),
      ];
      var cursor = 0;
      for (final (name, off, size) in fields) {
        expect(off, cursor, reason: name);
        cursor = off + size;
      }
      expect(cursor, PageHeader.size);
      expect(PageHeader.size, 40);
    });

    test('round-trips and verifies its checksum', () {
      final page = Uint8List(4096);
      const h = PageHeader(
        pageType: PageType.btreeLeaf,
        flags: PageFlags.encrypted,
        codecOrReserved: 1,
        treeId: 17,
        commitId: 0x0102030405060708,
        extentPages: 3,
        payloadLen: 4000,
        nonce: 0xCAFEBABEDEADBEEF,
      );
      h.writeInto(page);
      final back = PageHeader.read(page, pageId: 5);
      expect(back.pageType, PageType.btreeLeaf);
      expect(back.flags, PageFlags.encrypted);
      expect(back.treeId, 17);
      expect(back.commitId, 0x0102030405060708);
      expect(back.extentPages, 3);
      expect(back.payloadLen, 4000);
      expect(back.nonce, 0xCAFEBABEDEADBEEF);
    });

    test('a single flipped payload bit is caught and names the page', () {
      final page = Uint8List(4096);
      const PageHeader(pageType: PageType.btreeLeaf).writeInto(page);
      page[2000] ^= 0x01;
      expect(
          () => PageHeader.read(page, pageId: 42),
          throwsA(isA<CorruptionException>()
              .having((e) => e.pageId, 'pageId', 42)));
    });

    test('the checksum covers bytes 4 onwards, as stored', () {
      final page = Uint8List(4096);
      const PageHeader(pageType: PageType.blob).writeInto(page);
      final bd = ByteData.view(page.buffer);
      expect(bd.getUint32(0, Endian.little), crc32c(page, 4, page.length));
    });
  });

  group('open procedure', () {
    Uint8List slot(int commitId, {int pageSize = 4096, int required = 1}) =>
        Superblock(
          pageSize: pageSize,
          commitId: commitId,
          featuresRequired: required,
        ).encode();

    test('chooses the valid slot with the greater commit_id', () {
      // spec/01-container.md section 2.1 step 3.
      expect(Superblock.open(slot(7), slot(8)).commitId, 8);
      expect(Superblock.open(slot(9), slot(8)).commitId, 9);
    });

    test('a torn slot is ignored and the other one wins', () {
      final a = slot(9);
      a[100] ^= 0xFF; // break slot A's checksum
      expect(Superblock.open(a, slot(8)).commitId, 8);
    });

    test('two invalid slots is not a Cryptand database', () {
      expect(() => Superblock.open(Uint8List(4096), Uint8List(4096)),
          throwsA(isA<CorruptionException>()));
    });

    test('an unknown required feature bit refuses to open and names the bit',
        () {
      final withUnknown = slot(3, required: 1 | (1 << 40));
      expect(
          () => Superblock.open(withUnknown, Uint8List(4096)),
          throwsA(isA<UnsupportedFeatureException>()
              .having((e) => e.message, 'message', contains('40'))));
    });

    test('an unknown OPTIONAL feature bit opens normally', () {
      final sb = Superblock(
        pageSize: 4096,
        commitId: 3,
        featuresOptional: 1 << 40,
      ).encode();
      expect(Superblock.open(sb, Uint8List(4096)).featuresOptional, 1 << 40);
    });

    test('slot alternation follows commit parity', () {
      expect(Superblock(pageSize: 4096, commitId: 1).slot, 0);
      expect(Superblock(pageSize: 4096, commitId: 2).slot, 1);
      expect(Superblock(pageSize: 8192, commitId: 2).slotOffset(), 8192);
    });
  });

  group('profile constants match spec/12-profiles.md section 1', () {
    test('vlog_min never exceeds page_size / 4', () {
      // The invariant of spec/00-conventions.md section 8, which is the whole
      // reason mobile is 1024 and not 4096.
      for (final p in Profile.values) {
        expect(p.vlogMin, lessThanOrEqualTo(p.pageSize ~/ 4),
            reason: '${p.name}: vlog_min ${p.vlogMin} vs page ${p.pageSize}');
      }
    });

    test('the table matches the spec row for row', () {
      expect(Profile.mobile.pageSize, 4096);
      expect(Profile.mobile.vlogMin, 1024);
      expect(Profile.mobile.overlapBound, 1);
      expect(Profile.mobile.l0Trigger, 2);
      expect(Profile.tablet.vlogMin, 1024);
      expect(Profile.desktop.pageSize, 8192);
      expect(Profile.desktop.vlogMin, 256);
      expect(Profile.desktop.fanout, 8);
      expect(Profile.desktop.filterBitsUpper, 16);
      expect(Profile.desktop.filterBitsLast, 10);
      expect(Profile.server.pageSize, 16384);
      expect(Profile.server.tierWidth, 6);
      expect(Profile.server.readaheadWindow, 1024);
    });

    test('a superblock rejects a vlog_min above the cap', () {
      expect(
          () => Superblock(pageSize: 4096, commitId: 1, vlogMin: 4096),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => Superblock(pageSize: 4096, commitId: 1, vlogMin: 1024),
          returnsNormally);
    });
  });

  test('every constant a reader needs survives a round trip', () {
    final sb = Superblock(
      pageSize: 16384,
      commitId: 12345,
      profile: Profile.server,
      levelCount: 4,
      visibleSeq: 999,
      nextSeq: 1000,
      manifestRoot: 77,
      nextNonce: 1 << 40,
      databaseUuid: Uint8List.fromList(List.generate(16, (i) => i)),
      writerId: 'cryptand-dart/test',
    );
    final back = Superblock.tryDecode(sb.encode())!;
    expect(back.pageSize, 16384);
    expect(back.commitId, 12345);
    expect(back.profile, Profile.server);
    expect(back.vlogMin, 256);
    expect(back.fanout, 10);
    expect(back.overlapBound, 3);
    expect(back.levelCount, 4);
    expect(back.visibleSeq, 999);
    expect(back.manifestRoot, 77);
    expect(back.nextNonce, 1 << 40);
    expect(back.writerId, 'cryptand-dart/test');
    expect(back.databaseUuid, sb.databaseUuid);
  });
}
