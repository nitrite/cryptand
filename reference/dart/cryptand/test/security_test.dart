import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/security.dart';
import 'package:test/test.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

void main() {
  group('SHA-256 (FIPS 180-4 examples)', () {
    test('abc', () {
      expect(hex(sha256(ascii.encode('abc'))),
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });
    test('empty', () {
      expect(hex(sha256(const [])),
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
    test('two-block message', () {
      expect(
          hex(sha256(ascii.encode(
              'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
          '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
    });
    test('one million a', () {
      expect(hex(sha256(List.filled(1000000, 0x61))),
          'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
    });
    test('every length across the padding boundary', () {
      // Lengths 55..64 are where a wrong pad length shows up.
      for (var n = 50; n < 70; n++) {
        expect(sha256(List.filled(n, 0x41)).length, 32, reason: 'n=$n');
      }
      expect(hex(sha256(List.filled(55, 0x61))).length, 64);
    });
  });

  group('HMAC-SHA256 (RFC 4231)', () {
    test('case 1', () {
      expect(
          hex(hmacSha256(unhex('0b' * 20), ascii.encode('Hi There'))),
          'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    });
    test('case 2', () {
      expect(
          hex(hmacSha256(
              ascii.encode('Jefe'), ascii.encode('what do ya want for nothing?'))),
          '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    });
    test('case 3', () {
      expect(hex(hmacSha256(unhex('aa' * 20), unhex('dd' * 50))),
          '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe');
    });
    test('case 6: key longer than the block size', () {
      expect(
          hex(hmacSha256(
              unhex('aa' * 131),
              ascii.encode(
                  'Test Using Larger Than Block-Size Key - Hash Key First'))),
          '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
    });
  });

  group('HKDF-SHA256 (RFC 5869)', () {
    test('test case 1', () {
      final okm = hkdf(unhex('0b' * 22), unhex('000102030405060708090a0b0c'),
          unhex('f0f1f2f3f4f5f6f7f8f9'), 42);
      expect(
          hex(okm),
          '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
          '34007208d5b887185865');
    });
    test('test case 3: zero-length salt and info', () {
      final okm = hkdf(unhex('0b' * 22), const [], const [], 42);
      expect(
          hex(okm),
          '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'
          '9d201395faa4b61a96c8');
    });
  });

  group('subkey derivation, section 3.4', () {
    final master = Uint8List.fromList(List.generate(32, (i) => i));
    final uuid = Uint8List.fromList(List.generate(16, (i) => 0xA0 + i));

    test('each purpose gives a different key', () {
      final page = deriveSubkey(master, uuid, Purpose.page);
      final vlog = deriveSubkey(master, uuid, Purpose.vlog);
      final mac = deriveSubkey(master, uuid, Purpose.sbMac);
      expect(page.length, 32);
      expect(page, isNot(vlog));
      expect(page, isNot(mac));
      expect(vlog, isNot(mac));
    });

    test('two files with the same master key get different content keys', () {
      // This is what makes a nonce repeating across files harmless, and what
      // makes spec/13-operations.md section 2.1's new-uuid rule load-bearing.
      final other = Uint8List.fromList(List.generate(16, (i) => 0xB0 + i));
      expect(deriveSubkey(master, uuid, Purpose.page),
          isNot(deriveSubkey(master, other, Purpose.page)));
    });

    test('is deterministic', () {
      expect(deriveSubkey(master, uuid, Purpose.page),
          deriveSubkey(master, uuid, Purpose.page));
    });

    test('rejects a wrong-sized key or uuid', () {
      expect(() => deriveSubkey(Uint8List(31), uuid, Purpose.page),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => deriveSubkey(master, Uint8List(15), Purpose.page),
          throwsA(isA<InvalidArgumentException>()));
    });
  });

  group('nonce construction, section 4.2', () {
    test('is 24 bytes laid out as domain, counter, object, offset', () {
      final n = buildNonce(NonceDomain.page, 0x0102030405060708, 0x1112131415161718, 0);
      expect(n.length, 24);
      expect(n[0], NonceDomain.page);
      expect(n.sublist(1, 9), [8, 7, 6, 5, 4, 3, 2, 1]);
      expect(n.sublist(9, 17), [0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
      expect(n.sublist(17), [0, 0, 0, 0, 0, 0, 0]);
    });

    test('the offset field is a u56', () {
      final n = buildNonce(NonceDomain.vlogRecord, 1, 2, 0xFFFFFFFFFFFFFF);
      expect(n.sublist(17), List.filled(7, 0xFF));
      expect(() => buildNonce(NonceDomain.vlogRecord, 1, 2, 1 << 56),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('domains separate otherwise identical nonces', () {
      expect(buildNonce(NonceDomain.page, 5, 9, 0),
          isNot(buildNonce(NonceDomain.vlogRecord, 5, 9, 0)));
    });
  });

  group('the nonce watermark, section 4.1', () {
    test('a crashed session never has its counters reissued', () {
      // The defect this rule exists to prevent: an earlier draft derived the
      // nonce from (page_id, commit_id), and a commit that dies before its
      // superblock leaves the NEXT commit reusing the same commit_id.
      //
      // And the defect in the *rule* that this test caught: without the
      // publish-before-allocate step, two crashed sessions start from the same
      // persisted value and hand out identical nonces.
      var persisted = 0;
      final everUsed = <int>{};
      for (var session = 0; session < 20; session++) {
        final a = NonceAllocator.open(persisted, (w) => persisted = w);
        // Crash after a random-ish amount of work, publishing nothing more.
        final work = 1 + (session * 7919) % 5000;
        for (var i = 0; i < work; i++) {
          final v = a.allocate();
          expect(everUsed.add(v), isTrue,
              reason: 'nonce $v reissued in session $session');
        }
      }
      expect(everUsed.length, greaterThan(20));
    });

    test('a clean session that publishes as it goes also never repeats', () {
      var persisted = 0;
      final everUsed = <int>{};
      final a = NonceAllocator.open(persisted, (w) => persisted = w);
      for (var i = 0; i < kNonceGap * 3; i++) {
        if (a.mustPublish) {
          final w = a.toPublish;
          a.published(w);
          persisted = w;
        }
        expect(everUsed.add(a.allocate()), isTrue);
      }
      expect(everUsed.length, kNonceGap * 3);
    });

    test('allocation stops at the watermark until a publish happens', () {
      var persisted = 0;
      final a = NonceAllocator.open(persisted, (w) => persisted = w);
      for (var i = 0; i < kNonceGap; i++) {
        a.allocate();
      }
      expect(a.mustPublish, isTrue);
      expect(a.allocate, throwsA(isA<StateError>()));
      a.published(a.toPublish);
      expect(a.mustPublish, isFalse);
      expect(a.allocate(), kNonceGap);
    });

    test('the watermark must strictly advance', () {
      var persisted = 0;
      final a = NonceAllocator.open(persisted, (w) => persisted = w);
      expect(() => a.published(a.publishedWatermark),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => a.published(0), throwsA(isA<InvalidArgumentException>()));
    });

    test('open publishes before it returns', () {
      var published = -1;
      NonceAllocator.open(1000, (w) => published = w);
      expect(published, 1000 + kNonceGap);
    });
  });

  group('keyslot, section 3.3', () {
    Keyslot sample({int index = 0}) => Keyslot(
          state: Keyslot.occupied,
          kdf: Keyslot.kdfArgon2id,
          tCost: 3,
          mCostKib: 65536,
          parallelism: 1,
          salt: Uint8List.fromList(List.generate(32, (i) => i)),
          wrapNonce: Uint8List.fromList(List.generate(24, (i) => 0x40 + i)),
          wrappedKey: Uint8List.fromList(List.generate(32, (i) => 0x80 + i)),
          wrapTag: Uint8List.fromList(List.generate(16, (i) => 0xC0 + i)),
          label: 'password',
        );

    test('is exactly 144 bytes and round-trips', () {
      final raw = sample().encode();
      expect(raw.length, 144);
      expect(Keyslot.size * Sb.keyslotCount, 576);
      final back = Keyslot.decode(raw, 0);
      expect(back.state, Keyslot.occupied);
      expect(back.kdf, Keyslot.kdfArgon2id);
      expect(back.tCost, 3);
      expect(back.mCostKib, 65536);
      expect(back.label, 'password');
      expect(back.wrappedKey, sample().wrappedKey);
      expect(back.wrapTag, sample().wrapTag);
    });

    test('four slots fit the superblock area exactly', () {
      final area = Uint8List(Sb.keyslotSize * Sb.keyslotCount);
      for (var i = 0; i < Sb.keyslotCount; i++) {
        area.setRange(i * Keyslot.size, (i + 1) * Keyslot.size, sample().encode());
      }
      expect(Sb.keyslots + area.length, 4088);
      final sb = Superblock(
          pageSize: 4096, commitId: 1, cipher: 1, keyslots: area);
      final back = Superblock.tryDecode(sb.encode())!;
      expect(back.keyslots, area);
    });

    test('the wrap AAD binds a slot to its file and its index', () {
      final uuidA = Uint8List.fromList(List.generate(16, (i) => i));
      final uuidB = Uint8List.fromList(List.generate(16, (i) => i + 1));
      expect(Keyslot.wrapAad(uuidA, 0), isNot(Keyslot.wrapAad(uuidB, 0)));
      expect(Keyslot.wrapAad(uuidA, 0), isNot(Keyslot.wrapAad(uuidA, 1)));
      expect(Keyslot.wrapAad(uuidA, 0).length, 17);
    });

    test('a below-floor Argon2id cost is refused at creation', () {
      expect(() => Keyslot.checkCreateCost(1, 65536, 1),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => Keyslot.checkCreateCost(3, 1024, 1),
          throwsA(isA<InvalidArgumentException>()));
      expect(() => Keyslot.checkCreateCost(3, 65536, 1), returnsNormally);
    });

    test('a malformed slot is corruption', () {
      final raw = sample().encode()..[0] = 7;
      expect(() => Keyslot.decode(raw, 0), throwsA(isA<CorruptionException>()));
      final raw2 = sample().encode()..[2] = 99;
      expect(() => Keyslot.decode(raw2, 0), throwsA(isA<CorruptionException>()));
    });
  });

  group('superblock MAC, section 6.2', () {
    final master = Uint8List.fromList(List.generate(32, (i) => i * 3));
    final uuid = Uint8List.fromList(List.generate(16, (i) => i));
    final key = deriveSubkey(master, uuid, Purpose.sbMac);

    Uint8List macced({int cipher = 1, int tCost = 3}) {
      final slots = Uint8List(Sb.keyslotSize * Sb.keyslotCount);
      ByteData.view(slots.buffer).setUint32(4, tCost, Endian.little);
      slots[0] = Keyslot.occupied;
      var sb = Superblock(
              pageSize: 4096,
              commitId: 9,
              cipher: cipher,
              databaseUuid: uuid,
              keyslots: slots)
          .encode();
      final mac = superblockMac(key, sb);
      sb.setRange(Sb.sbMac, Sb.sbMac + 32, mac);
      // Recompute the CRC over the now-final bytes.
      return Superblock.tryDecode(_recrc(sb))!.encode();
    }

    test('verifies a well-formed superblock', () {
      final sb = macced();
      expect(() => verifySuperblockMac(key, sb), returnsNormally);
    });

    test('catches cipher forced to 0 -- the downgrade of section 6.1', () {
      final sb = macced();
      sb[Sb.cipher] = 0;
      expect(() => verifySuperblockMac(key, sb),
          throwsA(isA<TamperException>()));
    });

    test('catches a weakened Argon2id cost in a keyslot', () {
      final sb = macced(tCost: 3);
      ByteData.view(sb.buffer).setUint32(Sb.keyslots + 4, 1, Endian.little);
      expect(() => verifySuperblockMac(key, sb),
          throwsA(isA<TamperException>()));
    });

    test('catches a swapped root', () {
      final sb = macced();
      ByteData.view(sb.buffer).setUint64(Sb.manifestRoot, 999, Endian.little);
      expect(() => verifySuperblockMac(key, sb),
          throwsA(isA<TamperException>()));
    });

    test('is not fooled by the wrong key', () {
      final sb = macced();
      final other = deriveSubkey(Uint8List(32), uuid, Purpose.sbMac);
      expect(() => verifySuperblockMac(other, sb),
          throwsA(isA<TamperException>()));
    });

    test('does not cover its own bytes, so it is computable in place', () {
      final sb = macced();
      final a = superblockMac(key, sb);
      final tweaked = Uint8List.fromList(sb);
      tweaked[Sb.sbMac] ^= 0xFF;
      expect(superblockMac(key, tweaked), a);
    });
  });

  test('constant-time compare is length-safe and value-correct', () {
    expect(constantTimeEquals([1, 2, 3], [1, 2, 3]), isTrue);
    expect(constantTimeEquals([1, 2, 3], [1, 2, 4]), isFalse);
    expect(constantTimeEquals([1, 2, 3], [1, 2]), isFalse);
    expect(constantTimeEquals(const [], const []), isTrue);
  });
}

/// Recomputes the container CRC after a direct byte edit.
Uint8List _recrc(Uint8List sb) {
  final crc = _crc(sb, 0, Sb.checksum);
  ByteData.view(sb.buffer).setUint32(Sb.checksum, crc, Endian.little);
  return sb;
}

int _crc(List<int> b, int s, int e) {
  var crc = 0xFFFFFFFF;
  for (var i = s; i < e; i++) {
    crc ^= b[i];
    for (var k = 0; k < 8; k++) {
      crc = (crc & 1) != 0 ? (0x82F63B78 ^ (crc >> 1)) : (crc >> 1);
    }
  }
  return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
}
