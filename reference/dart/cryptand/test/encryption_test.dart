/// Encryption wired into the page, record and keyslot paths of
/// `spec/14-security.md` section 5 and 3.3.
library;

import 'dart:typed_data';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/security.dart';
import 'package:test/test.dart';

Uint8List seq(int n, [int from = 0]) =>
    Uint8List.fromList(List.generate(n, (i) => (from + i) & 0xFF));

void main() {
  final master = seq(32);
  final uuid = seq(16, 0xA0);
  final keys = KeyRing(Uint8List.fromList(master), uuid);

  group('page encryption, section 5.2', () {
    Uint8List headerFor({int treeId = 17, int nonce = 7}) {
      final page = Uint8List(4096);
      PageHeader(
        pageType: PageType.btreeLeaf,
        flags: PageFlags.encrypted,
        treeId: treeId,
        commitId: 9,
        payloadLen: 100,
        nonce: nonce,
      ).writeInto(page);
      return Uint8List.fromList(Uint8List.sublistView(page, 0, PageHeader.size));
    }

    test('round-trips a payload', () {
      final header = headerFor();
      final payload = seq(100);
      final sealed = encryptPagePayload(
          keys: keys,
          pageId: 42,
          nonceCounter: 7,
          pageHeader40: header,
          payload: payload);
      expect(sealed.length, payload.length + 16,
          reason: 'the tag is appended and is inside payload_len');
      final back = decryptPagePayload(
          keys: keys,
          pageId: 42,
          nonceCounter: 7,
          pageHeader40: header,
          sealed: sealed);
      expect(back, payload);
    });

    test('a page moved to another offset does not decrypt', () {
      // Threat T3, splicing: the nonce binds the ciphertext to its page id.
      final header = headerFor();
      final sealed = encryptPagePayload(
          keys: keys,
          pageId: 42,
          nonceCounter: 7,
          pageHeader40: header,
          payload: seq(100));
      expect(
          () => decryptPagePayload(
              keys: keys,
              pageId: 43,
              nonceCounter: 7,
              pageHeader40: header,
              sealed: sealed),
          throwsA(isA<TamperException>()));
    });

    test('relabelling the page header fails, which is what the AAD is for', () {
      final sealed = encryptPagePayload(
          keys: keys,
          pageId: 42,
          nonceCounter: 7,
          pageHeader40: headerFor(treeId: 17),
          payload: seq(100));
      expect(
          () => decryptPagePayload(
              keys: keys,
              pageId: 42,
              nonceCounter: 7,
              pageHeader40: headerFor(treeId: 18),
              sealed: sealed),
          throwsA(isA<TamperException>()),
          reason: 'an attacker must not be able to move a page between trees');
    });

    test('the checksum bytes are excluded from the AAD', () {
      // The checksum is computed AFTER encryption, so it cannot be part of
      // what the tag covers.
      final h1 = headerFor();
      final h2 = Uint8List.fromList(h1);
      for (var i = 0; i < 4; i++) {
        h2[i] = 0xFF;
      }
      final sealed = encryptPagePayload(
          keys: keys,
          pageId: 1,
          nonceCounter: 1,
          pageHeader40: h1,
          payload: seq(32));
      expect(
          decryptPagePayload(
              keys: keys,
              pageId: 1,
              nonceCounter: 1,
              pageHeader40: h2,
              sealed: sealed),
          seq(32));
    });

    test('a flipped ciphertext byte is tampering, not corruption', () {
      final header = headerFor();
      final sealed = encryptPagePayload(
          keys: keys,
          pageId: 1,
          nonceCounter: 1,
          pageHeader40: header,
          payload: seq(64));
      sealed[10] ^= 0x01;
      expect(
          () => decryptPagePayload(
              keys: keys,
              pageId: 1,
              nonceCounter: 1,
              pageHeader40: header,
              sealed: sealed),
          throwsA(isA<TamperException>()));
    });

    test('two pages under one key never share a keystream', () {
      // The nonce counter is what guarantees it (section 4).
      final header = headerFor();
      final a = encryptPagePayload(
          keys: keys,
          pageId: 1,
          nonceCounter: 1,
          pageHeader40: header,
          payload: Uint8List(64));
      final b = encryptPagePayload(
          keys: keys,
          pageId: 1,
          nonceCounter: 2,
          pageHeader40: header,
          payload: Uint8List(64));
      expect(a, isNot(b));
    });
  });

  group('value-log record encryption, section 5.3', () {
    test('round-trips and binds segment, offset and tree', () {
      final body = seq(48);
      final r = encryptVlogRecord(
          keys: keys,
          segmentId: 5,
          recordOffset: 4096,
          treeId: 17,
          nonceCounter: 11,
          body: body);
      expect(
          decryptVlogRecord(
              keys: keys,
              segmentId: 5,
              recordOffset: 4096,
              treeId: 17,
              nonceCounter: 11,
              ciphertext: r.ciphertext,
              tag: r.tag),
          body);
      // Any of the three bound values changing must fail.
      for (final wrong in [
        (6, 4096, 17),
        (5, 8192, 17),
        (5, 4096, 18),
      ]) {
        expect(
            decryptVlogRecord(
                keys: keys,
                segmentId: wrong.$1,
                recordOffset: wrong.$2,
                treeId: wrong.$3,
                nonceCounter: 11,
                ciphertext: r.ciphertext,
                tag: r.tag),
            isNull,
            reason: 'binding $wrong should not verify');
      }
    });

    test('a record decrypts alone, without reading its neighbours', () {
      // This is what keeps key-value separation worth having: a point read
      // must not have to scan the segment. Section 5.3.
      final bodies = [for (var i = 0; i < 5; i++) seq(32, i * 8)];
      final sealed = <({Uint8List ciphertext, Uint8List tag})>[];
      for (var i = 0; i < bodies.length; i++) {
        sealed.add(encryptVlogRecord(
            keys: keys,
            segmentId: 5,
            recordOffset: i * 512,
            treeId: 17,
            nonceCounter: 100 + i,
            body: bodies[i]));
      }
      // Decrypt only the middle one.
      expect(
          decryptVlogRecord(
              keys: keys,
              segmentId: 5,
              recordOffset: 2 * 512,
              treeId: 17,
              nonceCounter: 102,
              ciphertext: sealed[2].ciphertext,
              tag: sealed[2].tag),
          bodies[2]);
    });
  });

  group('keyslots, section 3.3', () {
    final kek = seq(32, 0x50);

    test('wrap and unwrap round-trip', () {
      final slot = wrapMasterKey(
        masterKey: Uint8List.fromList(master),
        kek: kek,
        databaseUuid: uuid,
        slotIndex: 0,
        wrapNonce: seq(24, 0x10),
        salt: seq(32, 0x20),
        kdf: Keyslot.kdfRaw,
        tCost: 0,
        mCostKib: 0,
        parallelism: 0,
        label: 'keyring',
      );
      expect(slot.wrappedKey.length, 32);
      expect(slot.wrapTag.length, 16);
      expect(
          unwrapMasterKey(
              slot: slot, kek: kek, databaseUuid: uuid, slotIndex: 0),
          master);
    });

    test('the wrong key returns null rather than garbage', () {
      final slot = wrapMasterKey(
        masterKey: Uint8List.fromList(master),
        kek: kek,
        databaseUuid: uuid,
        slotIndex: 0,
        wrapNonce: seq(24, 0x10),
        salt: seq(32),
        kdf: Keyslot.kdfRaw,
        tCost: 0,
        mCostKib: 0,
        parallelism: 0,
      );
      expect(
          unwrapMasterKey(
              slot: slot,
              kek: seq(32, 0x51),
              databaseUuid: uuid,
              slotIndex: 0),
          isNull);
    });

    test('a slot lifted from another database does not unwrap -- threat T3',
        () {
      final slot = wrapMasterKey(
        masterKey: Uint8List.fromList(master),
        kek: kek,
        databaseUuid: uuid,
        slotIndex: 0,
        wrapNonce: seq(24, 0x10),
        salt: seq(32),
        kdf: Keyslot.kdfRaw,
        tCost: 0,
        mCostKib: 0,
        parallelism: 0,
      );
      expect(
          unwrapMasterKey(
              slot: slot,
              kek: kek,
              databaseUuid: seq(16, 0xB0), // a different file
              slotIndex: 0),
          isNull);
      expect(
          unwrapMasterKey(
              slot: slot,
              kek: kek,
              databaseUuid: uuid,
              slotIndex: 1), // grafted into another slot
          isNull);
    });

    test('unlock tries every slot and reports one failure for all of them', () {
      final area = Uint8List(Sb.keyslotSize * Sb.keyslotCount);
      // Slot 2 holds the real key; 0 and 1 are empty, 3 holds another key.
      final good = wrapMasterKey(
        masterKey: Uint8List.fromList(master),
        kek: kek,
        databaseUuid: uuid,
        slotIndex: 2,
        wrapNonce: seq(24, 0x30),
        salt: seq(32),
        kdf: Keyslot.kdfRaw,
        tCost: 0,
        mCostKib: 0,
        parallelism: 0,
        label: 'keyring',
      );
      area.setRange(2 * Keyslot.size, 3 * Keyslot.size, good.encode());
      expect(unlock(keyslotArea: area, kek: kek, databaseUuid: uuid), master);
      expect(
          unlock(keyslotArea: area, kek: seq(32, 9), databaseUuid: uuid), isNull,
          reason: 'wrong key and no-such-slot must be indistinguishable');
    });

    test('crypto-erase makes the file unrecoverable in one write', () {
      // Section 8.2: zeroing the keyslots is the only erase that means
      // anything on flash.
      final area = Uint8List(Sb.keyslotSize * Sb.keyslotCount);
      final slot = wrapMasterKey(
        masterKey: Uint8List.fromList(master),
        kek: kek,
        databaseUuid: uuid,
        slotIndex: 0,
        wrapNonce: seq(24),
        salt: seq(32),
        kdf: Keyslot.kdfRaw,
        tCost: 0,
        mCostKib: 0,
        parallelism: 0,
      );
      area.setRange(0, Keyslot.size, slot.encode());
      expect(unlock(keyslotArea: area, kek: kek, databaseUuid: uuid), master);
      area.fillRange(0, area.length, 0);
      expect(unlock(keyslotArea: area, kek: kek, databaseUuid: uuid), isNull);
    });
  });

  group('the key ring', () {
    test('gives each purpose its own key', () {
      final k = KeyRing(Uint8List.fromList(master), uuid);
      expect(k.pageKey, isNot(k.vlogKey));
      expect(k.pageKey, isNot(k.macKey));
      expect(k.vlogKey, isNot(k.macKey));
    });

    test('destroy zeroes every key', () {
      // Section 11: keys are held in mutable byte arrays and zeroed on close.
      final k = KeyRing(Uint8List.fromList(master), uuid);
      k.destroy();
      expect(k.pageKey.every((b) => b == 0), isTrue);
      expect(k.vlogKey.every((b) => b == 0), isTrue);
      expect(k.macKey.every((b) => b == 0), isTrue);
      expect(k.masterKey.every((b) => b == 0), isTrue);
    });
  });
}
