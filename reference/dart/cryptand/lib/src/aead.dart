/// ChaCha20, Poly1305, and the XChaCha20-Poly1305 AEAD of
/// `spec/14-security.md` section 2.
///
/// RFC 8439 for ChaCha20, Poly1305 and the AEAD construction;
/// draft-irtf-cfrg-xchacha for HChaCha20 and the extended nonce.
///
/// **On shipping this at all.** Phase 1 of this reference deliberately omitted
/// the AEAD, on the grounds that an unverified one in a *reference*
/// implementation bakes its errors into the contract three SDKs are written
/// against. That reasoning still holds — what changed is the verification.
/// `test/aead_test.dart` checks this code against the published vectors of
/// RFC 8439 sections 2.3.2, 2.4.2, 2.5.2, 2.6.2, 2.8.2 and A.*, and of
/// draft-irtf-cfrg-xchacha section 2.2.1. Reproducing a published ciphertext
/// byte for byte from an independent derivation is the verification; without
/// those vectors passing, this file should not be used.
library;

import 'dart:typed_data';

import 'errors.dart';

const int _mask32 = 0xFFFFFFFF;

int _rotl32(int x, int n) => ((x << n) | ((x & _mask32) >>> (32 - n))) & _mask32;

/// The ChaCha20 quarter round, RFC 8439 section 2.1.
void _quarterRound(Int32List s, int a, int b, int c, int d) {
  var sa = s[a], sb = s[b], sc = s[c], sd = s[d];
  sa = (sa + sb) & _mask32;
  sd = _rotl32(sd ^ sa, 16);
  sc = (sc + sd) & _mask32;
  sb = _rotl32(sb ^ sc, 12);
  sa = (sa + sb) & _mask32;
  sd = _rotl32(sd ^ sa, 8);
  sc = (sc + sd) & _mask32;
  sb = _rotl32(sb ^ sc, 7);
  s[a] = sa;
  s[b] = sb;
  s[c] = sc;
  s[d] = sd;
}

void _rounds(Int32List s) {
  for (var i = 0; i < 10; i++) {
    _quarterRound(s, 0, 4, 8, 12);
    _quarterRound(s, 1, 5, 9, 13);
    _quarterRound(s, 2, 6, 10, 14);
    _quarterRound(s, 3, 7, 11, 15);
    _quarterRound(s, 0, 5, 10, 15);
    _quarterRound(s, 1, 6, 11, 12);
    _quarterRound(s, 2, 7, 8, 13);
    _quarterRound(s, 3, 4, 9, 14);
  }
}

/// The ChaCha20 constants: "expand 32-byte k".
const List<int> _sigma = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];

int _le32(List<int> b, int o) =>
    (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) & _mask32;

Int32List _initState(List<int> key, List<int> nonce12, int counter) {
  final s = Int32List(16);
  for (var i = 0; i < 4; i++) {
    s[i] = _sigma[i];
  }
  for (var i = 0; i < 8; i++) {
    s[4 + i] = _le32(key, i * 4);
  }
  s[12] = counter & _mask32;
  for (var i = 0; i < 3; i++) {
    s[13 + i] = _le32(nonce12, i * 4);
  }
  return s;
}

/// One 64-byte ChaCha20 keystream block, RFC 8439 section 2.3.
Uint8List chacha20Block(List<int> key, List<int> nonce12, int counter) {
  if (key.length != 32) {
    throw const InvalidArgumentException('ChaCha20 key is 32 bytes');
  }
  if (nonce12.length != 12) {
    throw const InvalidArgumentException('ChaCha20 nonce is 12 bytes');
  }
  final start = _initState(key, nonce12, counter);
  final s = Int32List.fromList(start);
  _rounds(s);
  final out = Uint8List(64);
  for (var i = 0; i < 16; i++) {
    final w = (s[i] + start[i]) & _mask32;
    out[i * 4] = w & 0xFF;
    out[i * 4 + 1] = (w >>> 8) & 0xFF;
    out[i * 4 + 2] = (w >>> 16) & 0xFF;
    out[i * 4 + 3] = (w >>> 24) & 0xFF;
  }
  return out;
}

/// ChaCha20 encryption, RFC 8439 section 2.4. Its own inverse.
Uint8List chacha20(
    List<int> key, List<int> nonce12, int counter, List<int> data) {
  final out = Uint8List(data.length);
  var block = Uint8List(0);
  var blockIndex = -1;
  for (var i = 0; i < data.length; i++) {
    final b = i >> 6;
    if (b != blockIndex) {
      block = chacha20Block(key, nonce12, (counter + b) & _mask32);
      blockIndex = b;
    }
    out[i] = data[i] ^ block[i & 63];
  }
  return out;
}

/// HChaCha20, draft-irtf-cfrg-xchacha section 2.2.
///
/// Twenty rounds over a state built from the key and a 16-byte nonce, with
/// **no** final addition of the initial state, returning words 0-3 and 12-15.
/// That omission is the whole construction: it makes the output a
/// non-invertible function of the key.
Uint8List hchacha20(List<int> key, List<int> nonce16) {
  if (key.length != 32) {
    throw const InvalidArgumentException('HChaCha20 key is 32 bytes');
  }
  if (nonce16.length != 16) {
    throw const InvalidArgumentException('HChaCha20 nonce is 16 bytes');
  }
  final s = Int32List(16);
  for (var i = 0; i < 4; i++) {
    s[i] = _sigma[i];
  }
  for (var i = 0; i < 8; i++) {
    s[4 + i] = _le32(key, i * 4);
  }
  for (var i = 0; i < 4; i++) {
    s[12 + i] = _le32(nonce16, i * 4);
  }
  _rounds(s);
  final out = Uint8List(32);
  void put(int slot, int w) {
    out[slot * 4] = w & 0xFF;
    out[slot * 4 + 1] = (w >>> 8) & 0xFF;
    out[slot * 4 + 2] = (w >>> 16) & 0xFF;
    out[slot * 4 + 3] = (w >>> 24) & 0xFF;
  }

  for (var i = 0; i < 4; i++) {
    put(i, s[i] & _mask32);
    put(4 + i, s[12 + i] & _mask32);
  }
  return out;
}

/// Poly1305, RFC 8439 section 2.5.
///
/// The accumulator is five 26-bit limbs, so every partial product stays under
/// 2^57 and fits a signed 64-bit integer without a wider type. That is the
/// same shape a Java implementation uses on `long`, and the reason this file
/// does not need `BigInt` any more than `cke.dart` does.
Uint8List poly1305(List<int> key32, List<int> message) {
  if (key32.length != 32) {
    throw const InvalidArgumentException('Poly1305 key is 32 bytes');
  }
  // r, clamped per RFC 8439 section 2.5.
  final t0 = _le32(key32, 0), t1 = _le32(key32, 4);
  final t2 = _le32(key32, 8), t3 = _le32(key32, 12);
  final r = <int>[
    t0 & 0x3FFFFFF,
    ((t0 >>> 26) | (t1 << 6)) & 0x3FFFF03,
    ((t1 >>> 20) | (t2 << 12)) & 0x3FFC0FF,
    ((t2 >>> 14) | (t3 << 18)) & 0x3F03FFF,
    ((t3 >>> 8)) & 0x00FFFFF,
  ];
  final s = <int>[for (var i = 1; i < 5; i++) r[i] * 5];
  final h = <int>[0, 0, 0, 0, 0];

  var i = 0;
  final n = message.length;
  final block = Uint8List(17);
  while (i < n) {
    final take = (n - i) < 16 ? (n - i) : 16;
    for (var j = 0; j < 16; j++) {
      block[j] = j < take ? message[i + j] : 0;
    }
    // Append the 1 bit: at 16 bytes for a full block, just past the data for
    // a short final one.
    if (take == 16) {
      block[16] = 1;
    } else {
      block[take] = 1;
      for (var j = take + 1; j < 17; j++) {
        block[j] = 0;
      }
    }
    final b0 = _le32(block, 0), b1 = _le32(block, 4);
    final b2 = _le32(block, 8), b3 = _le32(block, 12);
    h[0] += b0 & 0x3FFFFFF;
    h[1] += ((b0 >>> 26) | (b1 << 6)) & 0x3FFFFFF;
    h[2] += ((b1 >>> 20) | (b2 << 12)) & 0x3FFFFFF;
    h[3] += ((b2 >>> 14) | (b3 << 18)) & 0x3FFFFFF;
    h[4] += (b3 >>> 8) | (block[16] << 24);

    final d0 = h[0] * r[0] + h[1] * s[3] + h[2] * s[2] + h[3] * s[1] + h[4] * s[0];
    final d1 = h[0] * r[1] + h[1] * r[0] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1];
    final d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[3] + h[4] * s[2];
    final d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[3];
    final d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];

    var c = d0 >> 26;
    h[0] = d0 & 0x3FFFFFF;
    var v = d1 + c;
    c = v >> 26;
    h[1] = v & 0x3FFFFFF;
    v = d2 + c;
    c = v >> 26;
    h[2] = v & 0x3FFFFFF;
    v = d3 + c;
    c = v >> 26;
    h[3] = v & 0x3FFFFFF;
    v = d4 + c;
    c = v >> 26;
    h[4] = v & 0x3FFFFFF;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3FFFFFF;
    h[1] += c;

    i += take;
  }

  // Final carry propagation.
  var c = h[1] >> 26;
  h[1] &= 0x3FFFFFF;
  h[2] += c;
  c = h[2] >> 26;
  h[2] &= 0x3FFFFFF;
  h[3] += c;
  c = h[3] >> 26;
  h[3] &= 0x3FFFFFF;
  h[4] += c;
  c = h[4] >> 26;
  h[4] &= 0x3FFFFFF;
  h[0] += c * 5;
  c = h[0] >> 26;
  h[0] &= 0x3FFFFFF;
  h[1] += c;

  // Compute h + -p, and select it if there was no borrow.
  final g = <int>[0, 0, 0, 0, 0];
  g[0] = h[0] + 5;
  c = g[0] >> 26;
  g[0] &= 0x3FFFFFF;
  for (var j = 1; j < 4; j++) {
    g[j] = h[j] + c;
    c = g[j] >> 26;
    g[j] &= 0x3FFFFFF;
  }
  g[4] = h[4] + c - (1 << 26);

  var mask = (g[4] >> 63) & 1; // 1 when g is negative, i.e. h < p
  final keep = mask;
  mask = keep - 1; // 0 when h < p, all ones otherwise
  for (var j = 0; j < 5; j++) {
    h[j] = (h[j] & ~mask) | (g[j] & mask);
  }

  // Serialize h + s (the second half of the key) as 16 little-endian bytes.
  var f0 = (h[0] | (h[1] << 26)) & _mask32;
  var f1 = ((h[1] >>> 6) | (h[2] << 20)) & _mask32;
  var f2 = ((h[2] >>> 12) | (h[3] << 14)) & _mask32;
  var f3 = ((h[3] >>> 18) | (h[4] << 8)) & _mask32;

  var carry = 0;
  var sum = f0 + _le32(key32, 16) + carry;
  f0 = sum & _mask32;
  carry = (sum >>> 32) & 1;
  sum = f1 + _le32(key32, 20) + carry;
  f1 = sum & _mask32;
  carry = (sum >>> 32) & 1;
  sum = f2 + _le32(key32, 24) + carry;
  f2 = sum & _mask32;
  carry = (sum >>> 32) & 1;
  sum = f3 + _le32(key32, 28) + carry;
  f3 = sum & _mask32;

  final tag = Uint8List(16);
  for (final e in [(0, f0), (4, f1), (8, f2), (12, f3)]) {
    tag[e.$1] = e.$2 & 0xFF;
    tag[e.$1 + 1] = (e.$2 >>> 8) & 0xFF;
    tag[e.$1 + 2] = (e.$2 >>> 16) & 0xFF;
    tag[e.$1 + 3] = (e.$2 >>> 24) & 0xFF;
  }
  return tag;
}

/// The AEAD tag input of RFC 8439 section 2.8:
/// `aad || pad16 || ciphertext || pad16 || len(aad) || len(ciphertext)`.
Uint8List _macData(List<int> aad, List<int> ciphertext) {
  int pad(int n) => (16 - (n % 16)) % 16;
  final out = Uint8List(
      aad.length + pad(aad.length) + ciphertext.length + pad(ciphertext.length) + 16);
  var p = 0;
  out.setRange(p, p + aad.length, aad);
  p += aad.length + pad(aad.length);
  out.setRange(p, p + ciphertext.length, ciphertext);
  p += ciphertext.length + pad(ciphertext.length);
  final bd = ByteData.view(out.buffer, out.offsetInBytes);
  bd.setUint64(p, aad.length, Endian.little);
  bd.setUint64(p + 8, ciphertext.length, Endian.little);
  return out;
}

/// ChaCha20-Poly1305 AEAD, RFC 8439 section 2.8. Nonce is 12 bytes.
({Uint8List ciphertext, Uint8List tag}) chacha20Poly1305Encrypt({
  required List<int> key,
  required List<int> nonce12,
  required List<int> plaintext,
  List<int> aad = const [],
}) {
  final polyKey = Uint8List.sublistView(chacha20Block(key, nonce12, 0), 0, 32);
  final ct = chacha20(key, nonce12, 1, plaintext);
  return (ciphertext: ct, tag: poly1305(polyKey, _macData(aad, ct)));
}

/// Verifies and decrypts. Returns null on a tag mismatch — callers MUST treat
/// that as tampering, never as corruption (`spec/14-security.md` section 6.2).
Uint8List? chacha20Poly1305Decrypt({
  required List<int> key,
  required List<int> nonce12,
  required List<int> ciphertext,
  required List<int> tag,
  List<int> aad = const [],
}) {
  final polyKey = Uint8List.sublistView(chacha20Block(key, nonce12, 0), 0, 32);
  final expected = poly1305(polyKey, _macData(aad, ciphertext));
  if (!_ctEquals(expected, tag)) return null;
  return chacha20(key, nonce12, 1, ciphertext);
}

/// XChaCha20-Poly1305, the AEAD `spec/14-security.md` section 2 names.
///
/// The 24-byte nonce is what lets `spec/14-security.md` section 4.2
/// *construct* nonces from a counter and an object id rather than keeping a
/// table of them, which is the whole reason the extended variant is specified
/// rather than plain ChaCha20-Poly1305.
({Uint8List ciphertext, Uint8List tag}) xchacha20Poly1305Encrypt({
  required List<int> key,
  required List<int> nonce24,
  required List<int> plaintext,
  List<int> aad = const [],
}) {
  final (subkey, n12) = _xSplit(key, nonce24);
  return chacha20Poly1305Encrypt(
      key: subkey, nonce12: n12, plaintext: plaintext, aad: aad);
}

Uint8List? xchacha20Poly1305Decrypt({
  required List<int> key,
  required List<int> nonce24,
  required List<int> ciphertext,
  required List<int> tag,
  List<int> aad = const [],
}) {
  final (subkey, n12) = _xSplit(key, nonce24);
  return chacha20Poly1305Decrypt(
      key: subkey, nonce12: n12, ciphertext: ciphertext, tag: tag, aad: aad);
}

(Uint8List, Uint8List) _xSplit(List<int> key, List<int> nonce24) {
  if (nonce24.length != 24) {
    throw const InvalidArgumentException('XChaCha20 nonce is 24 bytes');
  }
  final subkey = hchacha20(key, nonce24.sublist(0, 16));
  final n12 = Uint8List(12)..setRange(4, 12, nonce24.sublist(16, 24));
  return (subkey, n12);
}

bool _ctEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}
