/// The file layer: `spec/01-container.md` §1's layout, written and read back.
///
/// Until a database is a file, `spec/11-conformance.md` §6's round-trip gate —
/// "open it in implementation A, mutate it, close it, open it in B" — is not a
/// test that can be run at all.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

const int t = 16;

String tmp(String tag) {
  final d = Directory.systemTemp.createTempSync('cryptand-file-$tag-');
  return '${d.path}/db.cryptand';
}

Database fresh({int memtableEntries = 200}) =>
    Database(engine: Engine(memtableEntries: memtableEntries, vlogMin: 256));

void main() {
  encryptionTests();
  lockTests();
  test('M4.5 / 14 section 11: the credential is zeroed and never in error text',
      () {
    const marker = 'M45-marker-pw-7c1f';
    Uint8List pw() => Uint8List.fromList(marker.codeUnits);
    bool wiped(List<int> b) => b.every((x) => x == 0);
    final texts = <String>[];
    final path = tmp('m45');
    final c = pw();
    final db = DatabaseFile.create(path,
        credential: c, tCost: 2, mCostKib: 16384, profile: Profile.desktop);
    expect(wiped(c), isTrue, reason: 'create left the credential');
    DatabaseFile.save(db, path);
    texts.add(db.toString());
    db.engine.close();

    final wrong = Uint8List.fromList('${marker}x'.codeUnits);
    try {
      DatabaseFile.open(path, key: wrong);
      fail('a wrong password opened the file');
    } on CannotUnlockException catch (e, st) {
      texts
        ..add(e.toString())
        ..add(st.toString());
    }
    expect(wiped(wrong), isTrue, reason: 'a failed open left the credential');

    final ok = pw();
    final back = DatabaseFile.open(path, key: ok);
    expect(wiped(ok), isTrue, reason: 'open left the credential');
    texts.add(back.toString());
    final ro = pw();
    DatabaseFile.openReadOnly(path, key: ro);
    expect(wiped(ro), isTrue, reason: 'openReadOnly left the credential');

    final plain = tmp('m45-plain');
    DatabaseFile.save(fresh(), plain);
    // F-137, 14 section 6.1: a key on a plaintext file is refused.
    for (final o in [DatabaseFile.open, DatabaseFile.openReadOnly]) {
      try {
        o(plain, key: pw());
        fail('F-137: a key on a plaintext file opened it');
      } on InvalidArgumentException catch (e, st) {
        texts
          ..add(e.toString())
          ..add(st.toString());
      }
    }

    final hex = pw().map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    for (final t in texts) {
      expect(t.contains(marker) || t.toLowerCase().contains(hex), isFalse,
          reason: 'secret in: $t');
    }
  });

  test('a database round-trips through a file', () {
    final path = tmp('roundtrip');
    final db = fresh();
    for (var i = 0; i < 500; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList('v$i'.codeUnits));
      if (i % 200 == 199) db.engine.flush();
    }
    db.engine.flush();
    DatabaseFile.save(db, path);

    final back = DatabaseFile.open(path);
    for (var i = 0; i < 500; i++) {
      expect(back.engine.get(t, CNitriteId(i)), isNotNull, reason: 'id $i');
      expect(String.fromCharCodes(back.engine.get(t, CNitriteId(i))!), 'v$i');
    }
    expect(back.engine.scanTree(t).length, 500);
  });

  test('M5 step 5: save on the open file commits in place, slots alternate',
      () {
    final path = tmp('inplace');
    final db = fresh();
    db.engine.put(t, CNitriteId(1), Uint8List.fromList('one'.codeUnits));
    db.engine.flush();
    DatabaseFile.save(db, path);
    final back = DatabaseFile.open(path);
    back.engine.put(t, CNitriteId(2), Uint8List.fromList('two'.codeUnits));
    back.engine.flush();
    DatabaseFile.save(back, path);
    // Without close's own commit, which would fill the other slot too.
    back.engine.close(flushMemtable: false);
    int cid(int at) {
      final f = File(path).openSync()..setPositionSync(at + Sb.commitId);
      final b = f.readSync(8);
      f.closeSync();
      return ByteData.sublistView(b).getUint64(0, Endian.little);
    }
    final a = cid(0), b = cid(4096);
    expect(a, isNot(b), reason: 'the in-place commit wrote one slot only');
    // Destroy the newer slot: the older commit is still whole.
    final raf = File(path).openSync(mode: FileMode.append)
      ..setPositionSync(a > b ? 0 : 4096)
      ..writeFromSync(Uint8List(Sb.size));
    raf.closeSync();
    final old = DatabaseFile.open(path);
    expect(String.fromCharCodes(old.engine.get(t, CNitriteId(1))!), 'one');
    expect(old.engine.get(t, CNitriteId(2)), isNull);
    old.engine.close();
  });

  test('M5 step 5: Engine.commit is durable on its own, no save', () {
    final path = tmp('commit');
    DatabaseFile.save(fresh(), path);
    final db = DatabaseFile.open(path);
    db.engine.put(t, CNitriteId(1), Uint8List(600)); // through the value log
    db.engine.commit(durability: Durability.os);
    expect(db.engine.durabilityAchieved, Durability.os);
    db.engine.put(t, CNitriteId(2), Uint8List.fromList('two'.codeUnits));
    db.engine.commit(durability: Durability.full);
    // §7: Dart has no F_FULLFSYNC, so `full` is performed as `sync`.
    expect(db.engine.durabilityAchieved, Durability.sync);
    // As after a kill: the handle is never closed.
    final back = DatabaseFile.openReadOnly(path);
    expect(back.engine.get(t, CNitriteId(1)), Uint8List(600));
    expect(String.fromCharCodes(back.engine.get(t, CNitriteId(2))!), 'two');
    expect(back.engine.durabilityAchieved, Durability.sync);
    db.engine.close();
  });

  test('created_utc_ms is set once and carried, as Rust and Java', () {
    final path = tmp('created');
    DatabaseFile.save(fresh(), path);
    List<int> created() {
      final b = ByteData.sublistView(File(path).readAsBytesSync());
      return [
        for (final slot in [0, 4096])
          b.getUint64(slot + Sb.createdUtcMs, Endian.little)
      ];
    }
    final first = created()[0];
    sleep(const Duration(milliseconds: 5));
    final db = DatabaseFile.open(path);
    db.engine.put(t, CNitriteId(1), Uint8List(1));
    db.engine.close();
    expect(created(), [first, first]);
  });

  test('M5: an encrypted database is on its file from create', () {
    final path = tmp('createfile');
    Uint8List pw() => Uint8List.fromList(List.filled(32, 7));
    final db = DatabaseFile.create(path,
        credential: pw(), kdf: Keyslot.kdfRaw, vlogSegmentBytes: 1 << 16);
    db.engine.put(t, CNitriteId(1), Uint8List.fromList('one'.codeUnits));
    db.engine.commit();
    final back = DatabaseFile.openReadOnly(path, key: pw());
    expect(String.fromCharCodes(back.engine.get(t, CNitriteId(1))!), 'one');
    db.engine.close();
  });

  test('F-069: a file whose slot A is invalid opens from slot B', () {
    // Slot B sits at offset page_size, which a reader cannot know when slot A
    // is invalid; all three readers assumed 4096 and lost an 8 KiB file.
    final path = tmp('f069');
    final db = Database(
        engine: Engine(memtableEntries: 200, vlogMin: 256, pageSize: 8192));
    db.engine.put(t, CNitriteId(1), Uint8List.fromList('one'.codeUnits));
    db.engine.flush();
    DatabaseFile.save(db, path);
    DatabaseFile.save(db, path); // both slots written, then A destroyed
    final raf = File(path).openSync(mode: FileMode.append);
    raf.setPositionSync(0);
    raf.writeFromSync(Uint8List(Sb.size));
    raf.closeSync();
    final back = DatabaseFile.open(path);
    expect(String.fromCharCodes(back.engine.get(t, CNitriteId(1))!), 'one');
  });

  test('F-045: a reopen continues value-log ids from the superblock', () {
    // 04 section 2.1: segment ids are "globally unique, never reused". A file
    // whose newest segment was collected has no tree-7 entry for it, so the
    // counter in the superblock is the only record that the id was used.
    final path = tmp('vlogid');
    final db = fresh();
    db.engine.put(t, const CNitriteId(1), Uint8List(4000));
    db.engine.flush();
    DatabaseFile.save(db, path);
    final b = File(path).readAsBytesSync();
    final bd = ByteData.sublistView(b);
    const nextVlogSegmentId = 136, checksum = 4092; // 01-container section 2
    final next = bd.getUint64(nextVlogSegmentId, Endian.little) + 5;
    for (final slot in [0, 4096]) {
      bd.setUint64(slot + nextVlogSegmentId, next, Endian.little);
      bd.setUint32(
          slot + checksum, crc32c(b, slot, slot + checksum), Endian.little);
    }
    File(path).writeAsBytesSync(b, flush: true);
    final back = DatabaseFile.open(path);
    back.engine.put(t, const CNitriteId(2), Uint8List(4000));
    expect(back.engine.vlog.segments.keys, contains(next));
  });

  test('a separated value survives the file, and its watermark with it', () {
    final path = tmp('vlog');
    final db = fresh();
    final big = Uint8List(4000)..fillRange(0, 4000, 7);
    for (var i = 0; i < 20; i++) {
      db.engine.put(t, CNitriteId(i), big);
    }
    db.engine.flush();
    DatabaseFile.save(db, path);

    final back = DatabaseFile.open(path);
    // §6.2: a pointer past the durable `bytes` watermark is corruption, so a
    // watermark that did not survive the file would fail every read.
    expect(back.engine.vlog.segments, isNotEmpty);
    for (final s in back.engine.vlog.segments.values) {
      expect(s.bytes, greaterThan(0));
      expect(s.sealed, isTrue,
          reason: 'spec/14-security.md section 4.3: a segment this session did '
              'not open is sealed');
    }
    for (var i = 0; i < 20; i++) {
      expect(back.engine.get(t, CNitriteId(i)), big);
    }
  });

  test('the value-log head page is a page: header, type and checksum', () {
    final path = tmp('vloghead');
    final db = fresh();
    db.engine.put(t, CNitriteId(1), Uint8List(4000)..fillRange(0, 4000, 3));
    db.engine.flush();
    DatabaseFile.save(db, path);

    final bytes = File(path).readAsBytesSync();
    final sb = Superblock.open(Uint8List.sublistView(bytes, 0, Sb.size),
        Uint8List.sublistView(bytes, 4096, 4096 + Sb.size));
    var found = 0;
    for (var p = 2; p < sb.pageCount; p++) {
      final page =
          Uint8List.sublistView(bytes, p * sb.pageSize, (p + 1) * sb.pageSize);
      if (page[4] != PageType.vlogSegment) continue;
      // Reading it verifies the checksum, which is the point: without a page
      // header a repair pass scanning for VLOG_SEGMENT pages
      // (spec/13-operations.md section 3) cannot find the segment at all.
      final h = PageHeader.read(page);
      expect(h.flags & PageFlags.extentHead, PageFlags.extentHead);
      expect(h.extentPages, greaterThan(0));
      expect(h.treeId, TreeId.noTree);
      found++;
    }
    expect(found, greaterThan(0), reason: 'no value-log head page was written');
  });

  test('the catalog and its collections survive the file', () {
    final path = tmp('catalog');
    final db = fresh();
    final c = db.createCollection('orders|2026+eu');
    c.put(
        CNitriteId(1),
        CDoc({
          '_id': CNitriteId(1),
          'country': const CStr('de'),
          'total': CInt.of(NumType.i32, 42),
        }));
    db.engine.flush();
    DatabaseFile.save(db, path);

    final back = DatabaseFile.open(path);
    expect(back.catalog.get('orders|2026+eu'), isNotNull);
    final names = [
      for (final (name, d) in back.catalog.all)
        if (d.kind == TreeKind.data && d.paramStr('type') == 'collection') name
    ];
    expect(names, contains('orders|2026+eu'));
    final doc = back.collection('orders|2026+eu')!.get(CNitriteId(1));
    expect(doc, isNotNull);
    expect((doc!['country']! as CStr).value, 'de');
  });

  test('page 0 and page 1 are the two superblock slots', () {
    final path = tmp('slots');
    final db = fresh();
    db.engine.put(t, CNitriteId(1), Uint8List.fromList([1]));
    db.engine.flush();
    DatabaseFile.save(db, path);
    final bytes = File(path).readAsBytesSync();
    for (final at in [0, 4096]) {
      final sb =
          Superblock.tryDecode(Uint8List.sublistView(bytes, at, at + Sb.size));
      expect(sb, isNotNull, reason: 'slot at $at');
      expect(sb!.pageCount * sb.pageSize, bytes.length);
    }
  });

  test('M5: segments past the cache budget are evicted and read back', () {
    final path = tmp('evict');
    final db = fresh();
    db.engine.pageCacheBytes = 1; // one resident segment
    for (var i = 0; i < 100; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList([i]));
      if (i % 10 == 9) db.engine.flush();
    }
    for (var i = 0; i < 100; i++) {
      expect(db.engine.get(t, CNitriteId(i)), [i]);
    }
    expect(db.engine.manifest.all.length, greaterThan(1));
    expect(db.engine.extents.length, 1);
    expect(db.engine.cacheEvictions, greaterThan(0));
    DatabaseFile.save(db, path);
    final back = DatabaseFile.open(path);
    back.engine.pageCacheBytes = 1;
    for (var i = 0; i < 100; i++) {
      expect(back.engine.get(t, CNitriteId(i)), [i]);
    }
    expect(back.engine.cacheEvictions, greaterThan(0));
  });

  test('a reopen preserves every extent, byte for byte', () {
    final path = tmp('stable');
    final db = fresh();
    for (var i = 0; i < 100; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList([i]));
    }
    db.engine.flush();
    DatabaseFile.save(db, path);

    final reopened = DatabaseFile.open(path);
    final second = '$path.2';
    DatabaseFile.save(reopened, second);

    // **Not** a byte-for-byte comparison of the whole page space, and the
    // earlier version of this test was one. Tree 1, the free tree of
    // `spec/01-container.md` §6, is itself state: the first save records what
    // the first session's copy-on-write writes orphaned, the second records
    // what the second session's did, and the two are legitimately different.
    // Asserting whole-file equality asserted that no free tree exists.
    //
    // What must hold is that every extent survives unchanged — segments are
    // immutable (§2), so a reopen that rewrote one would be rewriting bytes
    // that cannot have changed.
    final back = DatabaseFile.open(second);
    for (final r in back.engine.manifest.all) {
      final was = reopened.engine.segment(r);
      expect(back.engine.segment(r).extent, was.extent,
          reason: 'segment ${r.segmentId} is immutable');
    }
    for (var i = 0; i < 100; i++) {
      expect(back.engine.get(t, CNitriteId(i)), [i]);
    }
  });

  test('saving leaks no page, save after save and open after open', () {
    // `spec/01-container.md` §9 step 7. Two leaks, both per save and both
    // silent, because a leak is not unsound: tree 1 was edited in place and
    // its own path copies freed pages after the list it records was taken
    // (14 pages on the cross-language CRUD matrix), and tree 7 was rebuilt
    // from nothing without freeing the copy the file already held.
    final path = tmp('noleak');
    final db = fresh();
    final big = Uint8List(4000)..fillRange(0, 4000, 7);
    for (var i = 0; i < 60; i++) {
      db.engine.put(t, CNitriteId(i), i.isEven ? big : Uint8List.fromList([i]));
      if (i % 20 == 19) db.engine.flush();
    }
    db.engine.flush();
    for (var i = 0; i < 30; i++) {
      db.createCollection('c$i');
    }
    DatabaseFile.save(db, path);
    DatabaseFile.save(db, path);

    for (var round = 0; round < 3; round++) {
      final back = DatabaseFile.open(path);
      expect(back.engine.vlog.segments, isNotEmpty,
          reason: 'tree 7 has something to rebuild');
      back.engine.put(t, CNitriteId(1000 + round), big);
      back.engine.flush();
      back.createCollection('d$round');
      DatabaseFile.save(back, path);
      back.engine.close();

      final check = DatabaseFile.open(path);
      final leaks = check.engine.verifyStructure().of(FindingClass.leak);
      expect(leaks, isEmpty, reason: 'round $round: ${leaks.join('\n')}');
      check.engine.close();
    }

    // And a value-log segment the file placed, emptied and collected after a
    // reopen: its extent has to go back to the page space.
    final back = DatabaseFile.open(path);
    final placed = back.engine.vlog.segments.length;
    for (var i = 0; i < 1003; i++) {
      back.engine.put(t, CNitriteId(i), Uint8List.fromList([1]));
    }
    back.engine.compact();
    expect(back.engine.vlog.segments.length, lessThan(placed),
        reason: 'a placed segment was collected');
    DatabaseFile.save(back, path);
    back.engine.close();
    final leaks =
        DatabaseFile.open(path).engine.verifyStructure().of(FindingClass.leak);
    expect(leaks, isEmpty, reason: leaks.join('\n'));
  });

  test('the free tree is written, read back, and its space reused', () {
    // `spec/01-container.md` §6 and §9 step 7. Without tree 1 in the file,
    // another SDK reconciling reachable pages against an empty free tree
    // reports every orphaned page as a leak, and no later session can ever
    // reuse the space: the file only grows.
    final path = tmp('freetree');
    final db = fresh();
    for (var i = 0; i < 400; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList([i & 0xFF]));
      if (i % 100 == 99) db.engine.flush();
    }
    db.engine.flush();
    // Churn the catalog so the copy-on-write trees orphan pages.
    for (var i = 0; i < 60; i++) {
      db.createCollection('c$i');
    }
    DatabaseFile.save(db, path);
    expect(db.engine.store.freedPages, greaterThan(0),
        reason:
            'copy-on-write orphaned pages, so there is a free tree to write');

    final back = DatabaseFile.open(path);
    expect(back.engine.store.freeExtents, isNotEmpty,
        reason: 'the free tree survived the file');

    // §6's reclamation rule: an extent freed at commit N is reallocatable once
    // N <= min_retained_commit, which a reopened database's commit id clears.
    final before = back.engine.store.pageCount;
    final freeBefore = back.engine.store.freedPages;
    for (var i = 0; i < 40; i++) {
      back.createCollection('d$i');
    }
    expect(back.engine.store.freedPages, lessThan(freeBefore + 40),
        reason: 'space was reused rather than only accumulated');
    expect(back.engine.store.pageCount - before, lessThan(freeBefore + 40),
        reason: 'the file grew by less than the writes, because it reused');
  });
}

// ---------------------------------------------------------------------------
// `spec/14-security.md` §5 — what is encrypted.
//
// These exist because "the file is encrypted" was true of its superblock and of
// nothing else: every inline value, every key, every index entry and every
// B+tree page sat in the clear under a `cipher = 1` superblock, and the file
// layer refused to open one at all. The failure is silent by construction — the
// database opens, reads and verifies perfectly.
// ---------------------------------------------------------------------------

void encryptionTests() {
  const key = [
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
  ];

  test('create refuses to overwrite a database that is already there', () {
    // `writeAsBytesSync` truncates, so `create` on an existing path used to
    // destroy the database silently and unrecoverably. Two of the three
    // reference implementations did this; only the Java one refused. It is a
    // plausible thing for an operator or a deploy script to do, and there is
    // no undo.
    final path = tmp('nooverwrite');
    final db = DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw);
    db.engine.put(t, CNitriteId(1), Uint8List.fromList('keep me'.codeUnits));
    db.engine.flush();
    DatabaseFile.save(db, path);
    db.engine.close();
    final before = File(path).lengthSync();
    expect(before, greaterThan(0));

    expect(
        () => DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw),
        throwsA(isA<InvalidArgumentException>()));

    // And the refusal left the file alone rather than half-writing it.
    expect(File(path).lengthSync(), before);
    final back = DatabaseFile.open(path, key: key);
    expect(back.engine.get(t, CNitriteId(1)), isNotNull,
        reason: 'the original data must still be there');
  });

  test('an encrypted database round-trips and refuses the wrong key', () {
    final path = tmp('aead');
    final db = DatabaseFile.create(path,
        credential: key, kdf: Keyslot.kdfRaw, memtableEntries: 200);
    for (var i = 0; i < 300; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList('v$i'.codeUnits));
      if (i % 100 == 99) db.engine.flush();
    }
    db.engine.flush();
    DatabaseFile.save(db, path);
    db.engine.close();

    final back = DatabaseFile.open(path, key: key);
    for (var i = 0; i < 300; i++) {
      expect(String.fromCharCodes(back.engine.get(t, CNitriteId(i))!), 'v$i');
    }
    // §3.3 and `spec/00-conventions.md` §9: "cannot unlock", reported
    // identically for a missing keyslot and a wrong key.
    back.engine.close();
    expect(() => DatabaseFile.open(path, key: List.filled(32, 8)),
        throwsA(isA<CannotUnlockException>()));
    expect(
        () => DatabaseFile.open(path), throwsA(isA<CannotUnlockException>()));
  });

  test('no inline value or key survives in the clear', () {
    final path = tmp('cleartext');
    final db = DatabaseFile.create(path,
        credential: key, kdf: Keyslot.kdfRaw, memtableEntries: 100);
    // Below desktop's vlog_min of 256, so these live in a segment leaf cell,
    // which is page payload.
    for (var i = 0; i < 80; i++) {
      db.engine.put(t, CStr('KEYNEEDLE-${i.toString().padLeft(4, '0')}'),
          Uint8List.fromList('VALUENEEDLE'.codeUnits));
    }
    db.engine.flush();
    DatabaseFile.save(db, path);
    db.engine.close();

    final raw = File(path).readAsBytesSync();
    for (final needle in ['VALUENEEDLE', 'KEYNEEDLE-0007']) {
      final bytes = needle.codeUnits;
      var hits = 0;
      for (var i = 0; i + bytes.length <= raw.length; i++) {
        var ok = true;
        for (var j = 0; j < bytes.length; j++) {
          if (raw[i + j] != bytes[j]) {
            ok = false;
            break;
          }
        }
        if (ok) hits++;
      }
      expect(hits, 0, reason: '"$needle" is on disk in the clear');
    }
    final back = DatabaseFile.open(path, key: key);
    expect(
        String.fromCharCodes(back.engine.get(t, const CStr('KEYNEEDLE-0007'))!),
        'VALUENEEDLE');
  });

  test('a separated value is encrypted per record, and its framing is not', () {
    // §5.3: `record_len`, the counter and the trailing crc32c stay in the clear
    // so a segment can be walked, and its damage bounded, without the key.
    final path = tmp('vlogaead');
    final db = DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw);
    final big = Uint8List(900)..fillRange(0, 900, 0xAB);
    for (var i = 0; i < 20; i++) {
      db.engine.put(t, CNitriteId(i), big);
    }
    db.engine.flush();
    DatabaseFile.save(db, path);
    db.engine.close();

    final raw = File(path).readAsBytesSync();
    var run = 0, longest = 0;
    for (final b in raw) {
      run = b == 0xAB ? run + 1 : 0;
      if (run > longest) longest = run;
    }
    expect(longest, lessThan(900), reason: 'a separated value is in the clear');

    final back = DatabaseFile.open(path, key: key);
    expect(back.engine.get(t, const CNitriteId(7)), big);
  });

  test('every data page carries the encrypted flag and a distinct nonce', () {
    // §5.2: "`flags.ENCRYPTED` MUST be set. A reader MUST NOT infer encryption
    // from `cipher` alone." And §4: a repeated nonce is the whole failure.
    final path = tmp('flags');
    final db = DatabaseFile.create(path,
        credential: key, kdf: Keyslot.kdfRaw, memtableEntries: 100);
    for (var i = 0; i < 200; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList([i & 0xFF]));
      if (i % 100 == 99) db.engine.flush();
    }
    db.engine.flush();
    DatabaseFile.save(db, path);

    final raw = File(path).readAsBytesSync();
    const ps = 8192;
    final seen = <int>{};
    var encrypted = 0;
    for (var p = 2; (p + 1) * ps <= raw.length; p++) {
      final page = Uint8List.sublistView(raw, p * ps, (p + 1) * ps);
      if (page.every((b) => b == 0)) continue;
      final PageHeader h;
      try {
        h = PageHeader.read(page, pageId: p);
      } on CryptandException {
        continue; // an interior extent page carries no header (section 3)
      }
      // §5.1's clear page kinds.
      if (h.pageType == PageType.vlogSegment || h.pageType == PageType.free) {
        continue;
      }
      expect(h.isEncrypted, isTrue,
          reason: 'page $p (type ${h.pageType}) is stored in the clear');
      expect(seen.add(h.nonce), isTrue,
          reason: 'nonce ${h.nonce} is used by two pages');
      encrypted++;
    }
    expect(encrypted, greaterThan(4), reason: 'the probe found nothing');
  });

  test('the nonce floor is published before anything is allocated', () {
    // §4.1 rule 1: "on open, before allocating anything, a writer MUST durably
    // publish a superblock whose next_nonce is persisted_next_nonce + 2^20."
    // Rule 1 is what makes the watermark move for a session that writes
    // nothing else; without it two successive crashed sessions both start at
    // W and hand out the same values.
    final path = tmp('nonce');
    final db = DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw);
    for (var i = 0; i < 40; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList([i]));
    }
    db.engine.flush();
    DatabaseFile.save(db, path);
    db.engine.close();

    final floors = <int>[];
    for (var round = 1; round < 4; round++) {
      // The kill: opened, written, never saved.
      final e = DatabaseFile.open(path, key: key);
      floors.add(e.engine.nonces!.publishedWatermark);
      for (var i = 0; i < 40; i++) {
        e.engine.put(t, CNitriteId(round * 1000 + i), Uint8List.fromList([i]));
      }
      e.engine.flush();
      e.engine.close(flushMemtable: false); // the kill: nothing published
    }
    for (var i = 1; i < floors.length; i++) {
      expect(floors[i], greaterThanOrEqualTo(floors[i - 1] + kNonceGap),
          reason: 'the published floor did not move: $floors');
    }
  });

  test('editing the superblock is reported as tampering, not corruption', () {
    // §6.1's attack: set `cipher = 0` so the next writer stores plaintext.
    // None of it touches an encrypted byte and all of it is invisible without
    // the MAC.
    final path = tmp('tamper');
    final db = DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw);
    db.engine
        .put(t, const CNitriteId(1), Uint8List.fromList('secret'.codeUnits));
    db.engine.flush();
    DatabaseFile.save(db, path);
    db.engine.close();

    final raw = File(path).readAsBytesSync();
    for (final slot in [0, 8192]) {
      raw[slot + Sb.cipher] = 0;
      final view = Uint8List.sublistView(raw, slot, slot + Sb.size);
      ByteData.view(view.buffer, view.offsetInBytes, view.length)
          .setUint32(Sb.checksum, crc32c(view, 0, Sb.checksum), Endian.little);
    }
    File(path).writeAsBytesSync(raw, flush: true);
    // `cipher = 0` now, so the reader would not even ask for a key — which is
    // exactly the downgrade. The MAC is what refuses it, and §6.2 requires the
    // refusal to be its own class: "your disk has a bad sector" and "someone
    // edited your database" call for different responses.
    expect(() => DatabaseFile.open(path, key: key),
        throwsA(isA<TamperException>()));
  });
}

// ---------------------------------------------------------------------------
// `spec/01-container.md` §10 — one writing process per database.
// ---------------------------------------------------------------------------

void lockTests() {
  test('a second writing process is refused by name and never falls back', () {
    // "a second process opening for writing MUST fail with a clear 'locked by
    // another process' error and MUST NOT fall back to opening anyway."
    //
    // A real second process, because `RandomAccessFile.lockSync` is a POSIX
    // `fcntl` lock and those are held **per process**: a second handle inside
    // this one is granted the lock, so a same-process assertion would test
    // nothing and pass. §10's rule is about processes, and the only honest
    // test of it is another process — the same conclusion
    // `spec/13-operations.md` §8's multi-process readers reached.
    final path = tmp('writerlock');
    final db = fresh();
    db.engine.put(t, const CNitriteId(1), Uint8List.fromList([1]));
    db.engine.flush();
    DatabaseFile.save(db, path);

    final held = File(path).openSync(mode: FileMode.append)
      ..lockSync(FileLock.exclusive);
    try {
      final r = Process.runSync(
          Platform.resolvedExecutable, ['run', 'tool/lock_probe.dart', path]);
      expect(r.stdout.toString().trim(), 'locked',
          reason: 'stderr: ${r.stderr}');
    } finally {
      held.closeSync();
    }
    // Released, and the database opens again with no cleanup step.
    final after = Process.runSync(
        Platform.resolvedExecutable, ['run', 'tool/lock_probe.dart', path]);
    expect(after.stdout.toString().trim(), 'opened');
    expect(DatabaseFile.open(path).engine.get(t, const CNitriteId(1)), [1]);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('M5: an open database holds the writer lock until close', () {
    final path = tmp('heldlock');
    DatabaseFile.save(fresh(), path);
    final db = DatabaseFile.open(path);
    String probe() => Process.runSync(
            Platform.resolvedExecutable, ['run', 'tool/lock_probe.dart', path])
        .stdout
        .toString()
        .trim();
    expect(probe(), 'locked');
    // Refused in this process too, as Rust and Java refuse it.
    expect(() => DatabaseFile.open(path), throwsA(isA<LockedException>()));
    // A reader's close here must not drop the writer's fcntl lock.
    DatabaseFile.openReadOnly(path).engine.close();
    expect(probe(), 'locked');
    db.engine.close();
    expect(probe(), 'opened');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('an encrypted database reports what it observed, never a plausible 0',
      () {
    // `spec/13-operations.md` §6 and `spec/14-security.md` §8.3: "that is the
    // one place where a reassuring answer is a dangerous one". A metric that
    // cannot be computed is reported unavailable by name.
    const key = [
      9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, //
      9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9
    ];
    final path = tmp('metrics');
    final db = DatabaseFile.create(path,
        credential: key, kdf: Keyslot.kdfRaw, memtableEntries: 100);
    for (var i = 0; i < 200; i++) {
      db.engine.put(t, CNitriteId(i), Uint8List.fromList([i & 0xFF]));
      if (i % 100 == 99) db.engine.flush();
    }
    db.engine.flush();
    DatabaseFile.save(db, path);
    db.engine.close();

    final back = DatabaseFile.open(path, key: key);
    for (var i = 0; i < 200; i++) {
      back.engine.get(t, CNitriteId(i));
    }
    final m = back.engine.metrics();
    expect(m.isAvailable('unencrypted_pages'), isTrue);
    expect(m.encryptedPages, greaterThan(0),
        reason: 'pages were read and they were encrypted');
    expect(m.unencryptedPages, 0,
        reason: 'created encrypted, so there is no conversion mixture');
    expect(m.claimsEncryptionFalsely, isFalse);
    expect(m.nonceFloor, greaterThanOrEqualTo(kNonceGap));

    // An unencrypted database says so by name rather than reporting 0, which
    // would read as "fully encrypted".
    final plain = fresh();
    expect(plain.engine.metrics().isAvailable('unencrypted_pages'), isFalse);
  });

  test('F-072: addKey, removeKey and cryptoErase on the open file', () {
    Uint8List k(int b) => Uint8List(32)..fillRange(0, 32, b);
    final path = tmp('keyapi');
    var db = DatabaseFile.create(path,
        credential: k(1), kdf: Keyslot.kdfRaw, profile: Profile.desktop);
    expect(db.addKey(k(2), kdf: Keyslot.kdfRaw), 1);
    db.engine.close();
    db = DatabaseFile.open(path, key: k(2)); // the new slot unlocks
    db.removeKey(0);
    expect(() => db.removeKey(1), throwsA(isA<InvalidArgumentException>()),
        reason: 'the last slot is crypto-erase, by name only');
    db.engine.close();
    expect(() => DatabaseFile.open(path, key: k(1)),
        throwsA(isA<CannotUnlockException>()));
    db = DatabaseFile.open(path, key: k(2));
    db.cryptoErase();
    db.engine.close();
    expect(() => DatabaseFile.open(path, key: k(2)),
        throwsA(isA<CannotUnlockException>()));
    final raw = File(path).readAsBytesSync();
    for (final slot in [0, Profile.desktop.pageSize]) {
      final at = slot + Sb.keyslots;
      expect(raw.sublist(at, at + Sb.keyslotSize * Sb.keyslotCount)
          .every((b) => b == 0), isTrue, reason: 'slot at $slot kept a key');
    }
  });

  test('F-144: decrypt finishes while a snapshot pins an old value-log version',
      () {
    Uint8List k(int b) => Uint8List(32)..fillRange(0, 32, b);
    final path = tmp('f144');
    final db = DatabaseFile.create(path,
        credential: k(1), kdf: Keyslot.kdfRaw, profile: Profile.desktop);
    final e = db.engine;
    final snap = e.snapshot();
    e.put(2, CBytes(Uint8List.fromList([0x30])), Uint8List(4222)); // value log
    e.put(2, CBytes(Uint8List.fromList([0x30])), Uint8List(41));
    db.decrypt(confirmRemoveEncryption: true);
    var steps = 0;
    while (db.convertStep()) {
      expect(++steps, lessThan(10),
          reason: '${db.conversion().remaining} objects never convert');
    }
    e
      ..release(snap)
      ..close();
  });

  test('F-094/F-096: conversions of a small database stay small', () {
    Uint8List k(int b) => Uint8List(32)..fillRange(0, 32, b);
    final path = tmp('f096');
    final db = DatabaseFile.create(path,
        credential: k(1), kdf: Keyslot.kdfRaw, profile: Profile.desktop);
    final c = db.createCollection('c');
    for (var round = 0; round < 3; round++) {
      c.put(CStr('a$round'), CDoc({'v': CStr('x' * 5000)})); // value log
      db.decrypt(confirmRemoveEncryption: true);
      while (db.convertStep()) {}
      c.put(CStr('b$round'), CDoc({'v': CStr('y' * 5000)}));
      db.encrypt(k(1), kdf: Keyslot.kdfRaw);
      while (db.convertStep()) {}
    }
    db.engine.compact();
    for (var round = 0; round < 3; round++) {
      expect(c.get(CStr('a$round')), CDoc({'v': CStr('x' * 5000)}));
      expect(c.get(CStr('b$round')), CDoc({'v': CStr('y' * 5000)}));
    }
    db.engine.close();
    expect(File(path).lengthSync(), lessThan(32 << 20)); // 202 MB before
  });

  test('F-143: rotation after decrypt then encrypt skips dead pages of the old key',
      () {
    Uint8List k(int b) => Uint8List(32)..fillRange(0, 32, b);
    final path = tmp('f143');
    var db = DatabaseFile.create(path,
        credential: k(1), kdf: Keyslot.kdfRaw, profile: Profile.desktop);
    final c = db.createCollection('c');
    for (var i = 0; i < 50; i++) {
      c.put(CStr('k$i'), CDoc({'i': CStr('v$i')}));
    }
    db.engine.commit();
    db.decrypt(confirmRemoveEncryption: true);
    while (db.convertStep()) {}
    db.encrypt(k(2), kdf: Keyslot.kdfRaw); // a new master key
    while (db.convertStep()) {}
    db = DatabaseFile.rotateMasterKey(db, k(3), kdf: Keyslot.kdfRaw);
    db.engine.close();
    db = DatabaseFile.open(path, key: k(3));
    for (var i = 0; i < 50; i++) {
      expect(db.collection('c')!.get(CStr('k$i')), CDoc({'i': CStr('v$i')}));
    }
    db.engine.close();
  });

  test('F-072: rotateMasterKey re-seals pages and value-log records', () {
    Uint8List k(int b) => Uint8List(32)..fillRange(0, 32, b);
    final path = tmp('rotate');
    var db = DatabaseFile.create(path,
        credential: k(1), kdf: Keyslot.kdfRaw, profile: Profile.desktop);
    final c = db.createCollection('c');
    CDoc doc(int i, int n) => CDoc({'i': CStr('x' * n + '$i')});
    for (var i = 0; i < 300; i++) {
      c.put(CStr('k$i'), doc(i, i.isEven ? 3000 : 10)); // even: value log
    }
    db.engine.commit();
    for (var i = 0; i < 300; i += 3) {
      c.put(CStr('k$i'), doc(i, 20)); // frees pages sealed under the old key
    }
    db.engine.commit();
    final before = File(path).readAsBytesSync();
    db = DatabaseFile.rotateMasterKey(db, k(2), kdf: Keyslot.kdfRaw);
    db.engine.close();
    expect(File('$path.rotate').existsSync(), isFalse);
    expect(() => DatabaseFile.open(path, key: k(1)),
        throwsA(isA<CannotUnlockException>()));
    db = DatabaseFile.open(path, key: k(2));
    final back = db.collection('c')!;
    for (var i = 0; i < 300; i++) {
      final n = i % 3 == 0 ? 20 : (i.isEven ? 3000 : 10);
      expect(back.get(CStr('k$i')), doc(i, n), reason: 'k$i');
    }
    expect(db.engine.verifyStructure().findings, isEmpty);
    db.engine.close();
    // Every sealed byte changed: no page payload survives the rotation.
    final after = File(path).readAsBytesSync();
    var same = 0, sealed = 0;
    for (var p = 2; p < before.length ~/ 4096; p++) {
      final a = before.sublist(p * 4096 + 40, p * 4096 + 72);
      if (before[p * 4096 + 5] & 0x02 == 0) continue; // ENCRYPTED only
      sealed++;
      if (_eq(a, after.sublist(p * 4096 + 40, p * 4096 + 72))) same++;
    }
    expect(sealed, greaterThan(10));
    expect(same, 0, reason: '$same pages kept their old ciphertext');
  });

  test('F-142: a commit to a converting file keeps CONVERTING', () {
    final path = tmp('converting');
    File('../../conformance/files/v1.0-security-converting.cryptand')
        .copySync(path);
    final key = [for (var b = 1; b <= 32; b++) b];
    var db = DatabaseFile.open(path, key: key);
    db.createCollection('more').put(const CStr('k'), CDoc(const {}));
    db.engine.close();
    db = DatabaseFile.open(path, key: [for (var b = 1; b <= 32; b++) b]);
    expect(db.engine.superblock!.featuresOptional & (1 << Feature.converting),
        isNot(0));
    expect(db.engine.verifyStructure().findings, isEmpty);
    db.engine.close();
  });

  test('F-072: encrypt and decrypt in place, interrupted and resumed', () {
    Uint8List k() => Uint8List(32)..fillRange(0, 32, 7);
    final path = tmp('convert');
    DatabaseFile.save(Database(engine: Engine())..createCollection('c'), path);
    var db = DatabaseFile.open(path);
    CDoc doc(int i) => CDoc({'i': CStr('v' * (i.isEven ? 2000 : 8) + '$i')});
    for (var i = 0; i < 400; i++) {
      db.collection('c')!.put(CStr('k$i'), doc(i));
    }
    db.engine.close();
    void check(Database d) {
      final c = d.collection('c')!;
      for (var i = 0; i < 400; i++) {
        expect(c.get(CStr('k$i')), doc(i), reason: 'k$i');
      }
      expect(d.engine.verifyStructure().findings, isEmpty);
    }

    db = DatabaseFile.open(path);
    db.encrypt(k(), kdf: Keyslot.kdfRaw);
    expect(db.fullyEncrypted, isFalse);
    expect(db.conversion().done, isFalse);
    expect(db.convertStep(), isTrue);
    db.engine.close(); // interrupted: a valid, half-converted file
    expect(() => DatabaseFile.open(path), throwsA(isA<CannotUnlockException>()));
    db = DatabaseFile.open(path, key: k());
    expect(db.engine.featuresOptional & (1 << Feature.converting), isNot(0));
    check(db);
    var steps = 0;
    while (db.convertStep()) {
      expect(++steps, lessThan(10));
    }
    expect(db.fullyEncrypted, isTrue);
    expect(db.conversion().fraction, 1.0);
    db.engine.close();
    db = DatabaseFile.open(path, key: k());
    expect(db.engine.featuresOptional & (1 << Feature.converting), 0);
    expect(db.engine.store.strict, isTrue);
    check(db);

    expect(() => db.decrypt(), throwsA(isA<InvalidArgumentException>()));
    db.decrypt(confirmRemoveEncryption: true);
    steps = 0;
    while (db.convertStep()) {
      expect(++steps, lessThan(10));
    }
    db.engine.close();
    db = DatabaseFile.open(path); // no key: plaintext again
    expect(db.engine.superblock!.cipher, 0);
    check(db);
    db.engine.close();
  });
}

bool _eq(List<int> a, List<int> b) {
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
