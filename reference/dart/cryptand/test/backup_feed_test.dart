/// `spec/13-operations.md` §2 (backup), §5 (the space-management API) and
/// §7 (the change feed).
///
/// Two of §2's rules are security rules, and both are tested here rather than
/// described: a backup must not copy the source's `database_uuid`, because on
/// an encrypted file that shares a content key; and the ciphertext copy is the
/// one exception, for exactly that reason.
library;

import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

import '../bench/harness.dart';

const int tree = 17;
Uint8List doc(NameDict d, int i) => encodeValue(benchDoc(i), dict: d);
Uint8List uuid(int seed) =>
    Uint8List.fromList([for (var i = 0; i < 16; i++) (seed * 31 + i) & 0xFF]);

void main() {
  late NameDict dict;
  setUp(() => dict = benchDict());

  Engine seeded({int n = 600}) {
    final e = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50)
      ..databaseUuid = uuid(1);
    for (var i = 0; i < n; i++) {
      e.put(tree, CNitriteId(i), doc(dict, i));
    }
    e.compact();
    return e;
  }

  group('backup, section 2', () {
    test('a full backup copies every segment and reads identically', () {
      final src = seeded();
      final dst = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      final r = Backup.full(src, dst, newUuid: uuid(2));

      expect(r.segmentsCopied, greaterThan(1));
      expect(r.verified, isTrue);
      expect(dst.scanTree(tree).length, src.scanTree(tree).length);
      for (var i = 0; i < 600; i += 37) {
        expect(dst.get(tree, CNitriteId(i)), src.get(tree, CNitriteId(i)));
      }
    });

    test('the source stays open and writable throughout', () {
      // Section 2.1: "Nothing is locked; nothing is quiesced. That falls out of
      // immutability -- every extent the backup reads is one nothing will ever
      // modify."
      final src = seeded();
      final dst = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      Backup.full(src, dst, newUuid: uuid(2));
      src.put(tree, const CNitriteId(9999), doc(dict, 1));
      src.flush();
      expect(src.get(tree, const CNitriteId(9999)), isNotNull);
      expect(dst.get(tree, const CNitriteId(9999)), isNull,
          reason: 'the backup is a snapshot, not a mirror');
    });

    test('a backup MUST NOT copy the source database_uuid', () {
      // Section 2.1: "two files with the same uuid break incremental backup and
      // confuse tooling -- and, on an encrypted file, they share a content key
      // (spec/14-security.md section 3.4 derives subkeys with the uuid as HKDF
      // salt), which makes a nonce that repeats across the two files a real
      // collision."
      final src = seeded(n: 50);
      final dst = Engine(memtableEntries: 100, vlogMin: 1024);
      expect(() => Backup.full(src, dst, newUuid: src.databaseUuid),
          throwsA(isA<InvalidArgumentException>()));
      final r = Backup.full(src, dst, newUuid: uuid(2));
      expect(r.databaseUuid, isNot(src.databaseUuid));
    });

    test('a ciphertext copy is the exception, and says why', () {
      // Section 2.1: "The ciphertext copy is the exception to the new-uuid
      // rule, and the reason is exactly why the rule exists: the copy is the
      // SAME cryptographic object, so it must keep the same key binding."
      final src = seeded(n: 50);
      final dst = Engine(memtableEntries: 100, vlogMin: 1024);
      final r = Backup.full(src, dst,
          mode: BackupMode.ciphertextCopy, newUuid: uuid(2));
      expect(r.databaseUuid, src.databaseUuid);
      expect(r.warnings.join(' '), contains('MUST NOT be opened for writing'));
      expect(r.warnings.join(' '), contains('next_nonce'));
    });

    test('an unencrypted backup of an encrypted database must be asked for',
        () {
      // Section 2.1: "An unencrypted backup of an encrypted database is a
      // silent downgrade. An implementation MUST refuse it unless the caller
      // asks for it by name, and MUST report it in the result."
      final src = seeded(n: 50);
      final dst = Engine(memtableEntries: 100, vlogMin: 1024);
      expect(
          () => Backup.full(src, dst,
              mode: BackupMode.decryptedDowngrade, newUuid: uuid(2)),
          throwsA(isA<InvalidArgumentException>()));
      final r = Backup.full(src, dst,
          mode: BackupMode.decryptedDowngrade,
          newUuid: uuid(2),
          allowDowngrade: true);
      expect(r.warnings.join(' '), contains('UNENCRYPTED'));
    });

    test('the writers list is carried over plus the backup tool', () {
      final src = seeded(n: 50);
      src.writers.add('rust-1.0');
      final dst = Engine(memtableEntries: 100, vlogMin: 1024);
      final r = Backup.full(src, dst, newUuid: uuid(2), backupToolId: 'cli-backup');
      expect(r.writers, containsAll(['cryptand-dart', 'rust-1.0', 'cli-backup']));
    });

    test('an incremental backup copies only what changed', () {
      // Section 2.2: "an incremental backup's size is proportional to what
      // changed, not to what the changes touched" -- the property an LSM's
      // immutable segments give and an in-place B-tree cannot.
      final src = seeded(n: 600);
      final dst = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      final first = Backup.full(src, dst, newUuid: uuid(2));
      expect(first.segmentsCopied, greaterThan(1));

      // A second incremental with nothing changed copies nothing at all.
      final noop = Backup.incremental(src, dst);
      expect(noop.segmentsCopied, 0);
      expect(noop.segmentsSkipped, first.segmentsCopied);

      // Now change a little and back up again.
      for (var i = 0; i < 20; i++) {
        src.put(tree, CNitriteId(i), doc(dict, 900 + i));
      }
      src.flush();
      final delta = Backup.incremental(src, dst);
      expect(delta.segmentsCopied, greaterThan(0));
      expect(delta.segmentsCopied, lessThan(first.segmentsCopied),
          reason: 'proportional to what changed');
      expect(dst.get(tree, const CNitriteId(0)), doc(dict, 900));
    });

    test('a segment deleted at the source is dropped at the destination', () {
      final src = seeded(n: 600);
      final dst = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      Backup.full(src, dst, newUuid: uuid(2));
      final before = dst.refsAt(dst.lastLevel).length;
      src.compact(); // rewrites the last level into different segment ids
      final r = Backup.incremental(src, dst);
      expect(dst.refsAt(dst.lastLevel).length, greaterThan(0));
      expect(dst.scanTree(tree).length, src.scanTree(tree).length);
      expect(before, greaterThan(0));
      expect(r.verified, isTrue);
    });

    test('a compacting backup is smaller and still verifies', () {
      // Section 2.1: "A compacting backup is usually smaller than the source,
      // and it is the recommended way to reclaim space fully."
      final src = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50)
        ..databaseUuid = uuid(1);
      for (var round = 0; round < 4; round++) {
        for (var i = 0; i < 200; i++) {
          src.put(tree, CNitriteId(i), doc(dict, i + round * 1000));
        }
        src.flush();
      }
      src.drainCompaction();
      final dst = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      final r = Backup.full(src, dst, newUuid: uuid(2), compacting: true);
      expect(r.verified, isTrue);
      expect(dst.scanTree(tree).length, 200);
    });

    test('verification runs before success is reported', () {
      // Section 2.3: "An implementation MUST run the verification pass over a
      // restored file before reporting success."
      final src = seeded(n: 200);
      final dst = Engine(memtableEntries: 100, vlogMin: 1024, segmentEntries: 50);
      final r = Backup.full(src, dst, newUuid: uuid(2));
      expect(r.verified, isTrue);
      expect(dst.verifyStructure().isClean, isTrue);
    });
  });

  group('the change feed, section 7', () {
    test('it is off by default, because it costs a write per mutation', () {
      final e = Engine(memtableEntries: 100);
      for (var i = 0; i < 50; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      expect(e.changeFeed.all, isEmpty);
    });

    test('entries land in the same batch as the mutation', () {
      final e = Engine(memtableEntries: 100)..changeFeedTrees.add(tree);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.remove(tree, const CNitriteId(2));
      e.removeRange(tree, const CNitriteId(10), const CNitriteId(20));

      final changes = e.changeFeed.read(tree).toList();
      expect(changes.map((c) => c.op), ['put', 'delete', 'range_delete']);
      // Seqs are the mutation's own, so the feed and the data cannot drift.
      expect(changes.map((c) => c.seq).toList(), [1, 2, 3]);
      expect(changes.first.id, const CNitriteId(1));
    });

    test('read_changes(tree, from_seq) is a sequential range scan', () {
      final e = Engine(memtableEntries: 1000)..changeFeedTrees.add(tree);
      for (var i = 0; i < 100; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      final from50 = e.changeFeed.read(tree, fromSeq: 50).toList();
      expect(from50.first.seq, 50);
      expect(from50.length, 51);
      // Already in seq order: "the feed just makes it addressable in seq
      // order", so a replication layer never sorts.
      final seqs = from50.map((c) => c.seq).toList();
      expect(seqs, equals([...seqs]..sort()));
    });

    test('the feed is per tree', () {
      final e = Engine(memtableEntries: 1000)..changeFeedTrees.add(tree);
      e.put(tree, const CNitriteId(1), doc(dict, 1));
      e.put(18, const CNitriteId(1), doc(dict, 1)); // not enrolled
      expect(e.changeFeed.read(tree).length, 1);
      expect(e.changeFeed.read(18), isEmpty);
    });

    test('retention drops entries past changefeed_retain_seq', () {
      final e = Engine(memtableEntries: 1000)..changeFeedTrees.add(tree);
      e.changeFeed.retainSeq = 20;
      for (var i = 0; i < 100; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      final dropped = e.changeFeed.prune(newestSeq: 100);
      expect(dropped, greaterThan(0));
      expect(e.changeFeed.all.every((c) => c.seq >= 80), isTrue);
    });
  });

  group('the space-management API, section 5', () {
    test('compactStep is incremental and reports when more remains', () {
      // Section 5: "all MUST be incremental and resumable... None may block
      // longer than max_foreground_stall_ms per step."
      final e = Engine(memtableEntries: 100, vlogMin: 1024)
        ..compactionStepBytes = 4096;
      for (var i = 0; i < 2000; i++) {
        e.put(tree, CNitriteId(i), doc(dict, i));
      }
      var steps = 0;
      while (!e.compactStep().done && steps < 1000) {
        steps++;
      }
      expect(steps, greaterThan(0), reason: 'it really took several steps');
      expect(e.scanTree(tree).length, 2000);
      expect(e.verifyStructure().isClean, isTrue);
    });

    test('collect and cluster report what they did', () {
      final e = Engine(memtableEntries: 100, vlogMin: 128);
      for (var i = 0; i < 400; i++) {
        e.put(tree, CNitriteId(i % 40), doc(dict, i));
      }
      e.compact();
      expect(e.collect().done, isTrue);
      final c = e.cluster();
      expect(c.done, isTrue,
          reason: 'locality_debt is inside its bound after a compaction');
    });

    test('remove_key refuses to remove the last slot of an encrypted file', () {
      // Section 5 and spec/14-security.md section 3.3: "An implementation MUST
      // refuse to remove the LAST occupied slot while cipher != 0 -- that is
      // crypto-erase, and it MUST be asked for by name."
      final e = Engine();
      final area = Uint8List(Keyslot.size * 4);
      final slot = Keyslot(
          state: Keyslot.occupied,
          kdf: Keyslot.kdfRaw,
          tCost: 0,
          mCostKib: 0,
          parallelism: 0,
          salt: Uint8List(32),
          wrapNonce: Uint8List(24),
          wrappedKey: Uint8List(32),
          wrapTag: Uint8List(16),
          label: 'k');
      area.setRange(0, Keyslot.size, slot.encode());

      expect(() => e.removeKey(area, 0, encrypted: true),
          throwsA(isA<InvalidArgumentException>()));
      // On an unencrypted file there is nothing to lose.
      expect(() => e.removeKey(area, 0, encrypted: false), returnsNormally);
    });

    test('crypto_erase zeroes every slot, irreversibly', () {
      final e = Engine();
      final area = Uint8List(Keyslot.size * 4)..fillRange(0, 64, 0xAB);
      final erased = e.cryptoErase(area);
      expect(erased.every((b) => b == 0), isTrue);
    });
  });
}
