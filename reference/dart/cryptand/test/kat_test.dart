// PLAN M4.2: the primitive KATs in conformance/vectors/kat, shared with the
// Rust and Java suites. Dart hand-rolls every primitive, SHA-256 included.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/src/aead.dart';
import 'package:cryptand/src/argon2.dart';
import 'package:cryptand/src/blake2b.dart';
import 'package:cryptand/src/security.dart';
import 'package:test/test.dart';

List<Map<String, Object?>> rows(String name) {
  final r = (jsonDecode(File('../../conformance/vectors/kat/$name').readAsStringSync()) as List)
      .cast<Map<String, Object?>>();
  expect(r, isNotEmpty, reason: name);
  return r;
}

Uint8List h(Map<String, Object?> r, String k) {
  final s = r[k]! as String;
  return Uint8List.fromList(
      [for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);
}

void main() {
  for (final x in [false, true]) {
    final file = x ? 'xchacha20_poly1305.json' : 'chacha20_poly1305.json';
    test('$file (Wycheproof)', () {
      var i = 0;
      for (final r in rows(file)) {
        final at = 'row ${i++}';
        final key = h(r, 'key'), nonce = h(r, 'nonce'), aad = h(r, 'aad'), ct = h(r, 'ct');
        final body = ct.sublist(0, ct.length - 16), tag = ct.sublist(ct.length - 16);
        final got = x
            ? xchacha20Poly1305Decrypt(key: key, nonce24: nonce, ciphertext: body, tag: tag, aad: aad)
            : chacha20Poly1305Decrypt(key: key, nonce12: nonce, ciphertext: body, tag: tag, aad: aad);
        if (r['valid'] == '01') {
          expect(got, h(r, 'msg'), reason: at);
        } else {
          expect(got, isNull, reason: at);
        }
      }
    });
  }

  test('hkdf_sha256.json (Wycheproof)', () {
    var i = 0;
    for (final r in rows('hkdf_sha256.json')) {
      final okm = h(r, 'okm');
      expect(hkdf(h(r, 'ikm'), h(r, 'salt'), h(r, 'info'), okm.length), okm, reason: 'row ${i++}');
    }
  });

  test('hmac_sha256.json (Wycheproof)', () {
    var i = 0;
    for (final r in rows('hmac_sha256.json')) {
      final tag = h(r, 'tag');
      expect(hmacSha256(h(r, 'key'), h(r, 'msg')).sublist(0, tag.length), tag, reason: 'row ${i++}');
    }
  });

  test('blake2b reference KATs, keyed and unkeyed', () {
    var i = 0;
    for (final r in rows('blake2b_keyed.json')) {
      expect(blake2b(h(r, 'msg'), key: h(r, 'key')), h(r, 'tag'), reason: 'keyed row ${i++}');
    }
    i = 0;
    for (final r in rows('blake2b_unkeyed.json')) {
      final d = h(r, 'digest');
      expect(blake2b(h(r, 'msg'), digestLength: d.length), d, reason: 'unkeyed row ${i++}');
    }
  });

  test('argon2id.json (RFC 9106 and the reference test.c)', () {
    for (final r in rows('argon2id.json')) {
      final tag = h(r, 'tag');
      final got = argon2id(
          password: h(r, 'password'), salt: h(r, 'salt'), secret: h(r, 'secret'),
          associatedData: h(r, 'ad'), passes: r['t']! as int, memoryKiB: r['m']! as int,
          parallelism: r['p']! as int, tagLength: tag.length);
      expect(got.tag, tag, reason: '${r['source']} t=${r['t']} m=${r['m']} p=${r['p']}');
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
}
