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

Database fresh({int memtableEntries = 200}) => Database(
    engine: Engine(memtableEntries: memtableEntries, vlogMin: 256));

void main() {
  encryptionTests();
  lockTests();
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
    db.engine
        .put(t, CNitriteId(1), Uint8List(4000)..fillRange(0, 4000, 3));
    db.engine.flush();
    DatabaseFile.save(db, path);

    final bytes = File(path).readAsBytesSync();
    final sb = Superblock.open(Uint8List.sublistView(bytes, 0, Sb.size),
        Uint8List.sublistView(bytes, 4096, 4096 + Sb.size));
    var found = 0;
    for (var p = 2; p < sb.pageCount; p++) {
      final page = Uint8List.sublistView(
          bytes, p * sb.pageSize, (p + 1) * sb.pageSize);
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
      final was = reopened.engine.extents[r.segmentId];
      expect(was, isNotNull, reason: 'segment ${r.segmentId} survived');
      expect(back.engine.extents[r.segmentId]!.extent, was!.extent,
          reason: 'segment ${r.segmentId} is immutable');
    }
    for (var i = 0; i < 100; i++) {
      expect(back.engine.get(t, CNitriteId(i)), [i]);
    }
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
        reason: 'copy-on-write orphaned pages, so there is a free tree to write');

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

    final back = DatabaseFile.open(path, key: key);
    for (var i = 0; i < 300; i++) {
      expect(String.fromCharCodes(back.engine.get(t, CNitriteId(i))!), 'v$i');
    }
    // §3.3 and `spec/00-conventions.md` §9: "cannot unlock", reported
    // identically for a missing keyslot and a wrong key.
    expect(() => DatabaseFile.open(path, key: List.filled(32, 8)),
        throwsA(isA<CannotUnlockException>()));
    expect(() => DatabaseFile.open(path), throwsA(isA<CannotUnlockException>()));
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
    expect(String.fromCharCodes(back.engine.get(t, const CStr('KEYNEEDLE-0007'))!),
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

    final floors = <int>[];
    for (var round = 1; round < 4; round++) {
      // The kill: opened, written, never saved.
      final e = DatabaseFile.open(path, key: key);
      floors.add(e.engine.nonces!.publishedWatermark);
      for (var i = 0; i < 40; i++) {
        e.engine.put(t, CNitriteId(round * 1000 + i), Uint8List.fromList([i]));
      }
      e.engine.flush();
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
    db.engine.put(t, const CNitriteId(1), Uint8List.fromList('secret'.codeUnits));
    db.engine.flush();
    DatabaseFile.save(db, path);

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
}
