/// Argon2id against RFC 9106's own test vector.
///
/// This test is the evidence for `spec/00-conventions.md` §1.1: naming a
/// standard algorithm is what makes a format portable, because the
/// implementation can then be checked against a published vector set rather
/// than against another implementation. Argon2id is implemented here in pure
/// Dart with no dependency; if the vector below passes, any SDK that follows
/// RFC 9106 derives the same key from the same password, which is the only
/// thing `spec/14-security.md` §3.2 actually requires.
library;

import 'dart:typed_data';

import 'package:cryptand/src/argon2.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/security.dart';
import 'package:test/test.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List filled(int n, int v) => Uint8List(n)..fillRange(0, n, v);

void main() {
  group('RFC 9106 section 5.3 — the Argon2id test vector', () {
    // Memory 32 KiB, passes 3, parallelism 4 lanes, tag length 32.
    // Password[32] = 01 x32, Salt[16] = 02 x16, Secret[8] = 03 x8,
    // Associated data[12] = 04 x12.
    late Argon2Result r;
    setUp(() {
      r = argon2id(
        password: filled(32, 0x01),
        salt: filled(16, 0x02),
        secret: filled(8, 0x03),
        associatedData: filled(12, 0x04),
        memoryKiB: 32,
        passes: 3,
        parallelism: 4,
        tagLength: 32,
      );
    });

    test('the pre-hashing digest H_0 reproduces', () {
      // Publishing this intermediate is what lets two implementations that
      // disagree on the tag find out whether they disagree about the inputs
      // or about the memory filling.
      expect(
          hex(r.h0),
          '2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8'
          '546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997');
    });

    test('the 32-byte tag reproduces byte for byte', () {
      // RFC 9106 section 5.3:
      //   Tag: 0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0
      //        1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
      expect(
          hex(r.tag),
          '0d640df58d78766c08c037a34a8b53c9'
          'd01ef0452d75b65eb52520e96b01e659');
      expect(r.tag.length, 32);
    });
  });

  group('parameters and guards', () {
    test('memory below 8*p is refused', () {
      expect(
          () => argon2id(
              password: const [1],
              salt: filled(16, 2),
              memoryKiB: 8,
              passes: 1,
              parallelism: 4),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('changing any input changes the tag', () {
      Uint8List t({
        List<int>? pw,
        List<int>? salt,
        int m = 32,
        int p = 3,
        int lanes = 4,
      }) =>
          argon2id(
            password: pw ?? filled(32, 1),
            salt: salt ?? filled(16, 2),
            memoryKiB: m,
            passes: p,
            parallelism: lanes,
          ).tag;

      final base = hex(t());
      expect(hex(t(pw: filled(32, 9))), isNot(base));
      expect(hex(t(salt: filled(16, 9))), isNot(base));
      expect(hex(t(m: 64)), isNot(base));
      expect(hex(t(p: 4)), isNot(base));
      expect(hex(t(lanes: 2)), isNot(base));
    });

    test('the tag length is honoured and is not a truncation', () {
      final a = argon2id(
          password: filled(32, 1),
          salt: filled(16, 2),
          memoryKiB: 32,
          passes: 1,
          parallelism: 1,
          tagLength: 32);
      final b = argon2id(
          password: filled(32, 1),
          salt: filled(16, 2),
          memoryKiB: 32,
          passes: 1,
          parallelism: 1,
          tagLength: 64);
      expect(a.tag.length, 32);
      expect(b.tag.length, 64);
      // H' folds the length into the hash, so a longer tag is not a
      // superstring of a shorter one.
      expect(hex(b.tag).substring(0, 64), isNot(hex(a.tag)));
    });
  });

  group('the keyslot password path, spec/14-security.md sections 3.2 and 3.3', () {
    // Phase 1 through 3 could only exercise this path with kdf=0, a
    // host-supplied key. With Argon2id verified, the password path is real.
    Uint8List rnd(int n, int seed) =>
        Uint8List.fromList([for (var i = 0; i < n; i++) (seed * 31 + i * 7) & 0xFF]);

    late Uint8List uuid;
    late Uint8List master;
    late Uint8List area;

    setUp(() {
      uuid = rnd(16, 3);
      master = rnd(32, 5);
      // A deliberately cheap cost: this is a correctness test, not a
      // hardness test, and section 3.2's real floor is measured in section
      // P11 rather than asserted here.
      final slot = wrapMasterKey(
        masterKey: master,
        kek: deriveKek(
          slot: Keyslot(
              state: Keyslot.occupied,
              kdf: Keyslot.kdfArgon2id,
              tCost: 2,
              mCostKib: 16384,
              parallelism: 1,
              salt: rnd(32, 11),
              wrapNonce: rnd(24, 13),
              wrappedKey: Uint8List(32),
              wrapTag: Uint8List(16),
              label: 'password'),
          password: 'correct horse battery staple'.codeUnits,
        ),
        databaseUuid: uuid,
        slotIndex: 0,
        wrapNonce: rnd(24, 13),
        salt: rnd(32, 11),
        tCost: 2,
        mCostKib: 16384,
        parallelism: 1,
      );
      area = Uint8List(Keyslot.size * 4)..setRange(0, Keyslot.size, slot.encode());
    });

    test('the right password recovers the master key', () {
      expect(
          unlockWithPassword(
              keyslotArea: area,
              password: 'correct horse battery staple'.codeUnits,
              databaseUuid: uuid),
          master);
    });

    test('a wrong password yields null, not an error', () {
      // Section 3.3: a failure across all slots is "wrong key", and an
      // implementation MUST NOT distinguish "no such slot" from "bad
      // password" in what it reports.
      expect(
          unlockWithPassword(
              keyslotArea: area,
              password: 'correct horse battery stapl3'.codeUnits,
              databaseUuid: uuid),
          isNull);
      expect(
          unlockWithPassword(
              keyslotArea: Uint8List(Keyslot.size * 4),
              password: 'correct horse battery staple'.codeUnits,
              databaseUuid: uuid),
          isNull);
    });

    test('a slot lifted from another database does not unwrap — threat T3', () {
      expect(
          unlockWithPassword(
              keyslotArea: area,
              password: 'correct horse battery staple'.codeUnits,
              databaseUuid: rnd(16, 99)),
          isNull);
    });

    test('a kdf=0 slot refuses a password', () {
      final raw = Keyslot(
          state: Keyslot.occupied,
          kdf: Keyslot.kdfRaw,
          tCost: 0,
          mCostKib: 0,
          parallelism: 0,
          salt: Uint8List(32),
          wrapNonce: rnd(24, 1),
          wrappedKey: Uint8List(32),
          wrapTag: Uint8List(16),
          label: 'keyring');
      expect(() => deriveKek(slot: raw, password: 'x'.codeUnits),
          throwsA(isA<InvalidArgumentException>()));
    });

    test('the parameters used on open come from the slot', () {
      // Deriving under different parameters produces a different KEK, which
      // is why section 3.2 says an implementation that cannot meet the slot's
      // numbers MUST fail rather than derive a different key.
      Keyslot slotWith(int t, int m) => Keyslot(
          state: Keyslot.occupied,
          kdf: Keyslot.kdfArgon2id,
          tCost: t,
          mCostKib: m,
          parallelism: 1,
          salt: rnd(32, 11),
          wrapNonce: rnd(24, 13),
          wrappedKey: Uint8List(32),
          wrapTag: Uint8List(16),
          label: 'password');
      final a = deriveKek(slot: slotWith(2, 16384), password: 'pw'.codeUnits);
      final b = deriveKek(slot: slotWith(3, 16384), password: 'pw'.codeUnits);
      final c = deriveKek(slot: slotWith(2, 32768), password: 'pw'.codeUnits);
      expect(hex(a), isNot(hex(b)));
      expect(hex(a), isNot(hex(c)));
    });
  });
}
