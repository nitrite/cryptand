/// RFC 8439 and draft-irtf-cfrg-xchacha test vectors.
///
/// This file is the verification. Reproducing a published ciphertext byte for
/// byte from an independent derivation is what makes it safe to ship the AEAD
/// at all; `REPORT.md` explains why phase 1 declined to ship one without it.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptand/src/aead.dart';
import 'package:test/test.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List unhex(String s) {
  final t = s.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  return Uint8List.fromList(
      [for (var i = 0; i < t.length; i += 2) int.parse(t.substring(i, i + 2), radix: 16)]);
}

/// key 00:01:02 ... 1f, used by most of the RFC's examples.
final Uint8List kSeqKey =
    Uint8List.fromList(List.generate(32, (i) => i));

void main() {
  group('ChaCha20 block function (RFC 8439 section 2.3.2)', () {
    test('the published block reproduces', () {
      final block = chacha20Block(
          kSeqKey, unhex('000000090000004a00000000'), 1);
      expect(
          hex(block),
          '10f1e7e4d13b5915500fdd1fa32071c4'
          'c7d1f4c733c068030422aa9ac3d46c4e'
          'd2826446079faa0914c2d705d98b02a2'
          'b5129cd1de164eb9cbd083e8a2503c4e');
    });
  });

  group('ChaCha20 encryption (RFC 8439 section 2.4.2)', () {
    const plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        'only one tip for the future, sunscreen would be it.';

    test('the published ciphertext reproduces', () {
      final ct = chacha20(
          kSeqKey, unhex('000000000000004a00000000'), 1, utf8.encode(plaintext));
      expect(
          hex(ct),
          '6e2e359a2568f98041ba0728dd0d6981'
          'e97e7aec1d4360c20a27afccfd9fae0b'
          'f91b65c5524733ab8f593dabcd62b357'
          '1639d624e65152ab8f530c359f0861d8'
          '07ca0dbf500d6a6156a38e088a22b65e'
          '52bc514d16ccf806818ce91ab7793736'
          '5af90bbf74a35be6b40b8eedf2785e42'
          '874d');
    });

    test('decryption is the same operation', () {
      final nonce = unhex('000000000000004a00000000');
      final ct = chacha20(kSeqKey, nonce, 1, utf8.encode(plaintext));
      expect(utf8.decode(chacha20(kSeqKey, nonce, 1, ct)), plaintext);
    });

    test('crosses block boundaries correctly at every length', () {
      final nonce = unhex('000000000000004a00000000');
      final data = Uint8List.fromList(List.generate(200, (i) => i & 0xFF));
      final full = chacha20(kSeqKey, nonce, 1, data);
      for (var n = 0; n <= 200; n++) {
        final part = chacha20(kSeqKey, nonce, 1, data.sublist(0, n));
        expect(hex(part), hex(Uint8List.sublistView(full, 0, n)),
            reason: 'length $n');
      }
    });
  });

  group('Poly1305 (RFC 8439 section 2.5.2)', () {
    test('the published tag reproduces', () {
      final key = unhex(
          '85d6be7857556d337f4452fe42d506a8'
          '0103808afb0db2fd4abff6af4149f51b');
      final tag = poly1305(key, utf8.encode('Cryptographic Forum Research Group'));
      expect(hex(tag), 'a8061dc1305136c6c22b8baf0c0127a9');
    });

    test('an empty message', () {
      // RFC 8439 A.3 test vector 1: an all-zero key over 64 zero bytes gives
      // an all-zero tag.
      final tag = poly1305(Uint8List(32), Uint8List(64));
      expect(hex(tag), '00000000000000000000000000000000');
    });

    test('RFC 8439 A.3 vector 2: r = 0, s carries the whole tag', () {
      final key = unhex(
          '00000000000000000000000000000000'
          '36e5f6b5c5e06070f0efca96227a863e');
      final msg = utf8.encode(
          'Any submission to the IETF intended by the Contributor for '
          'publication as all or part of an IETF Internet-Draft or RFC and '
          'any statement made within the context of an IETF activity is '
          'considered an "IETF Contribution". Such statements include oral '
          'statements in IETF sessions, as well as written and electronic '
          'communications made at any time or place, which are addressed to');
      expect(hex(poly1305(key, msg)), '36e5f6b5c5e06070f0efca96227a863e');
    });

    test('block-boundary lengths all produce a 16-byte tag', () {
      final key = unhex(
          '85d6be7857556d337f4452fe42d506a8'
          '0103808afb0db2fd4abff6af4149f51b');
      for (final n in [0, 1, 15, 16, 17, 31, 32, 33, 64, 65]) {
        expect(poly1305(key, List.filled(n, 0x41)).length, 16, reason: 'n=$n');
      }
    });
  });

  group('ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8.2)', () {
    final key = unhex(
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f');
    final nonce = unhex('070000004041424344454647');
    final aad = unhex('50515253c0c1c2c3c4c5c6c7');
    const plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        'only one tip for the future, sunscreen would be it.';

    test('the published ciphertext and tag reproduce', () {
      final r = chacha20Poly1305Encrypt(
          key: key, nonce12: nonce, plaintext: utf8.encode(plaintext), aad: aad);
      expect(
          hex(r.ciphertext),
          'd31a8d34648e60db7b86afbc53ef7ec2'
          'a4aded51296e08fea9e2b5a736ee62d6'
          '3dbea45e8ca9671282fafb69da92728b'
          '1a71de0a9e060b2905d6a5b67ecd3b36'
          '92ddbd7f2d778b8c9803aee328091b58'
          'fab324e4fad675945585808b4831d7bc'
          '3ff4def08e4b7a9de576d26586cec64b'
          '6116');
      expect(hex(r.tag), '1ae10b594f09e26a7e902ecbd0600691');
    });

    test('decryption returns the plaintext', () {
      final r = chacha20Poly1305Encrypt(
          key: key, nonce12: nonce, plaintext: utf8.encode(plaintext), aad: aad);
      final back = chacha20Poly1305Decrypt(
          key: key,
          nonce12: nonce,
          ciphertext: r.ciphertext,
          tag: r.tag,
          aad: aad);
      expect(back, isNotNull);
      expect(utf8.decode(back!), plaintext);
    });

    test('a flipped ciphertext bit fails the tag', () {
      final r = chacha20Poly1305Encrypt(
          key: key, nonce12: nonce, plaintext: utf8.encode(plaintext), aad: aad);
      final broken = Uint8List.fromList(r.ciphertext)..[10] ^= 0x01;
      expect(
          chacha20Poly1305Decrypt(
              key: key,
              nonce12: nonce,
              ciphertext: broken,
              tag: r.tag,
              aad: aad),
          isNull);
    });

    test('a flipped AAD bit fails the tag', () {
      // This is what binds a page to its header in spec/14-security.md
      // section 5.2: an attacker cannot relabel an index page as a data page.
      final r = chacha20Poly1305Encrypt(
          key: key, nonce12: nonce, plaintext: utf8.encode(plaintext), aad: aad);
      final otherAad = Uint8List.fromList(aad)..[0] ^= 0x01;
      expect(
          chacha20Poly1305Decrypt(
              key: key,
              nonce12: nonce,
              ciphertext: r.ciphertext,
              tag: r.tag,
              aad: otherAad),
          isNull);
    });

    test('a flipped tag bit fails', () {
      final r = chacha20Poly1305Encrypt(
          key: key, nonce12: nonce, plaintext: utf8.encode(plaintext), aad: aad);
      final t = Uint8List.fromList(r.tag)..[15] ^= 0x80;
      expect(
          chacha20Poly1305Decrypt(
              key: key,
              nonce12: nonce,
              ciphertext: r.ciphertext,
              tag: t,
              aad: aad),
          isNull);
    });
  });

  group('HChaCha20 (draft-irtf-cfrg-xchacha section 2.2.1)', () {
    test('the published subkey reproduces', () {
      final out = hchacha20(kSeqKey, unhex('000000090000004a0000000031415927'));
      expect(
          hex(out),
          '82413b4227b27bfed30e42508a877d73'
          'a0f9e4d58a74a853c12ec41326d3ecdc');
    });
  });

  group('XChaCha20-Poly1305', () {
    final key = unhex(
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f');

    test('round-trips with a 24-byte nonce', () {
      final nonce = Uint8List.fromList(List.generate(24, (i) => 0x40 + i));
      const msg = 'a Cryptand page payload, encrypted';
      final r = xchacha20Poly1305Encrypt(
          key: key, nonce24: nonce, plaintext: utf8.encode(msg), aad: [1, 2, 3]);
      final back = xchacha20Poly1305Decrypt(
          key: key,
          nonce24: nonce,
          ciphertext: r.ciphertext,
          tag: r.tag,
          aad: [1, 2, 3]);
      expect(utf8.decode(back!), msg);
    });

    test('is HChaCha20 then ChaCha20-Poly1305, as the draft defines it', () {
      final nonce = Uint8List.fromList(List.generate(24, (i) => 0x40 + i));
      final subkey = hchacha20(key, nonce.sublist(0, 16));
      final n12 = Uint8List(12)..setRange(4, 12, nonce.sublist(16, 24));
      final direct = chacha20Poly1305Encrypt(
          key: subkey, nonce12: n12, plaintext: [1, 2, 3, 4], aad: [9]);
      final viaX = xchacha20Poly1305Encrypt(
          key: key, nonce24: nonce, plaintext: [1, 2, 3, 4], aad: [9]);
      expect(hex(viaX.ciphertext), hex(direct.ciphertext));
      expect(hex(viaX.tag), hex(direct.tag));
    });

    test('a different nonce gives different ciphertext for the same plaintext',
        () {
      // The property spec/14-security.md section 4 exists to guarantee: two
      // encryptions under one key must never share a nonce.
      final a = xchacha20Poly1305Encrypt(
          key: key, nonce24: Uint8List(24), plaintext: [1, 2, 3]);
      final b = xchacha20Poly1305Encrypt(
          key: key,
          nonce24: Uint8List(24)..[0] = 1,
          plaintext: [1, 2, 3]);
      expect(hex(a.ciphertext), isNot(hex(b.ciphertext)));
    });

    test('the empty message still authenticates', () {
      final nonce = Uint8List(24);
      final r = xchacha20Poly1305Encrypt(
          key: key, nonce24: nonce, plaintext: const []);
      expect(r.ciphertext, isEmpty);
      expect(r.tag.length, 16);
      expect(
          xchacha20Poly1305Decrypt(
              key: key, nonce24: nonce, ciphertext: const [], tag: r.tag),
          isEmpty);
    });
  });
}
