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

// F-176: the state is a Uint32List (stores truncate, so only additions before
// a rotate are masked), one keystream block is reused for the whole message
// and XORed straight into the output, and Poly1305 streams over the AAD and
// ciphertext instead of copying them into one MAC buffer.

int _rotl32(int x, int n) => ((x << n) | (x >>> (32 - n))) & _mask32;

/// The ChaCha20 quarter round, RFC 8439 section 2.1.
@pragma('vm:prefer-inline')
void _quarterRound(Uint32List s, int a, int b, int c, int d) {
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

void _rounds(Uint32List s) {
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

@pragma('vm:prefer-inline')
int _le32(Uint8List b, int o) =>
    b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);

Uint8List _bytes(List<int> b) => b is Uint8List ? b : Uint8List.fromList(b);

Uint32List _initState(Uint8List key, Uint8List nonce12, int counter) {
  final s = Uint32List(16);
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

// Unrolled onto locals (F-176): the rounds of [_rounds] without a list access.
/// One keystream block into [ks] as 16 words.
void _block(Uint32List start, Uint32List ks) {
  var x0 = start[0],
      x1 = start[1],
      x2 = start[2],
      x3 = start[3],
      x4 = start[4],
      x5 = start[5],
      x6 = start[6],
      x7 = start[7],
      x8 = start[8],
      x9 = start[9],
      x10 = start[10],
      x11 = start[11],
      x12 = start[12],
      x13 = start[13],
      x14 = start[14],
      x15 = start[15];
  int t;
  for (var i = 0; i < 10; i++) {
    x0 = (x0 + x4) & _mask32;
    t = x12 ^ x0;
    x12 = ((t << 16) | (t >>> 16)) & _mask32;
    x8 = (x8 + x12) & _mask32;
    t = x4 ^ x8;
    x4 = ((t << 12) | (t >>> 20)) & _mask32;
    x0 = (x0 + x4) & _mask32;
    t = x12 ^ x0;
    x12 = ((t << 8) | (t >>> 24)) & _mask32;
    x8 = (x8 + x12) & _mask32;
    t = x4 ^ x8;
    x4 = ((t << 7) | (t >>> 25)) & _mask32;
    x1 = (x1 + x5) & _mask32;
    t = x13 ^ x1;
    x13 = ((t << 16) | (t >>> 16)) & _mask32;
    x9 = (x9 + x13) & _mask32;
    t = x5 ^ x9;
    x5 = ((t << 12) | (t >>> 20)) & _mask32;
    x1 = (x1 + x5) & _mask32;
    t = x13 ^ x1;
    x13 = ((t << 8) | (t >>> 24)) & _mask32;
    x9 = (x9 + x13) & _mask32;
    t = x5 ^ x9;
    x5 = ((t << 7) | (t >>> 25)) & _mask32;
    x2 = (x2 + x6) & _mask32;
    t = x14 ^ x2;
    x14 = ((t << 16) | (t >>> 16)) & _mask32;
    x10 = (x10 + x14) & _mask32;
    t = x6 ^ x10;
    x6 = ((t << 12) | (t >>> 20)) & _mask32;
    x2 = (x2 + x6) & _mask32;
    t = x14 ^ x2;
    x14 = ((t << 8) | (t >>> 24)) & _mask32;
    x10 = (x10 + x14) & _mask32;
    t = x6 ^ x10;
    x6 = ((t << 7) | (t >>> 25)) & _mask32;
    x3 = (x3 + x7) & _mask32;
    t = x15 ^ x3;
    x15 = ((t << 16) | (t >>> 16)) & _mask32;
    x11 = (x11 + x15) & _mask32;
    t = x7 ^ x11;
    x7 = ((t << 12) | (t >>> 20)) & _mask32;
    x3 = (x3 + x7) & _mask32;
    t = x15 ^ x3;
    x15 = ((t << 8) | (t >>> 24)) & _mask32;
    x11 = (x11 + x15) & _mask32;
    t = x7 ^ x11;
    x7 = ((t << 7) | (t >>> 25)) & _mask32;
    x0 = (x0 + x5) & _mask32;
    t = x15 ^ x0;
    x15 = ((t << 16) | (t >>> 16)) & _mask32;
    x10 = (x10 + x15) & _mask32;
    t = x5 ^ x10;
    x5 = ((t << 12) | (t >>> 20)) & _mask32;
    x0 = (x0 + x5) & _mask32;
    t = x15 ^ x0;
    x15 = ((t << 8) | (t >>> 24)) & _mask32;
    x10 = (x10 + x15) & _mask32;
    t = x5 ^ x10;
    x5 = ((t << 7) | (t >>> 25)) & _mask32;
    x1 = (x1 + x6) & _mask32;
    t = x12 ^ x1;
    x12 = ((t << 16) | (t >>> 16)) & _mask32;
    x11 = (x11 + x12) & _mask32;
    t = x6 ^ x11;
    x6 = ((t << 12) | (t >>> 20)) & _mask32;
    x1 = (x1 + x6) & _mask32;
    t = x12 ^ x1;
    x12 = ((t << 8) | (t >>> 24)) & _mask32;
    x11 = (x11 + x12) & _mask32;
    t = x6 ^ x11;
    x6 = ((t << 7) | (t >>> 25)) & _mask32;
    x2 = (x2 + x7) & _mask32;
    t = x13 ^ x2;
    x13 = ((t << 16) | (t >>> 16)) & _mask32;
    x8 = (x8 + x13) & _mask32;
    t = x7 ^ x8;
    x7 = ((t << 12) | (t >>> 20)) & _mask32;
    x2 = (x2 + x7) & _mask32;
    t = x13 ^ x2;
    x13 = ((t << 8) | (t >>> 24)) & _mask32;
    x8 = (x8 + x13) & _mask32;
    t = x7 ^ x8;
    x7 = ((t << 7) | (t >>> 25)) & _mask32;
    x3 = (x3 + x4) & _mask32;
    t = x14 ^ x3;
    x14 = ((t << 16) | (t >>> 16)) & _mask32;
    x9 = (x9 + x14) & _mask32;
    t = x4 ^ x9;
    x4 = ((t << 12) | (t >>> 20)) & _mask32;
    x3 = (x3 + x4) & _mask32;
    t = x14 ^ x3;
    x14 = ((t << 8) | (t >>> 24)) & _mask32;
    x9 = (x9 + x14) & _mask32;
    t = x4 ^ x9;
    x4 = ((t << 7) | (t >>> 25)) & _mask32;
  }
  ks[0] = (x0 + start[0]) & _mask32;
  ks[1] = (x1 + start[1]) & _mask32;
  ks[2] = (x2 + start[2]) & _mask32;
  ks[3] = (x3 + start[3]) & _mask32;
  ks[4] = (x4 + start[4]) & _mask32;
  ks[5] = (x5 + start[5]) & _mask32;
  ks[6] = (x6 + start[6]) & _mask32;
  ks[7] = (x7 + start[7]) & _mask32;
  ks[8] = (x8 + start[8]) & _mask32;
  ks[9] = (x9 + start[9]) & _mask32;
  ks[10] = (x10 + start[10]) & _mask32;
  ks[11] = (x11 + start[11]) & _mask32;
  ks[12] = (x12 + start[12]) & _mask32;
  ks[13] = (x13 + start[13]) & _mask32;
  ks[14] = (x14 + start[14]) & _mask32;
  ks[15] = (x15 + start[15]) & _mask32;
}

@pragma('vm:prefer-inline')
void _put(Uint8List out, int o, int w) {
  out[o] = w;
  out[o + 1] = w >>> 8;
  out[o + 2] = w >>> 16;
  out[o + 3] = w >>> 24;
}

void _checkKeyNonce(List<int> key, List<int> nonce12) {
  if (key.length != 32) {
    throw const InvalidArgumentException('ChaCha20 key is 32 bytes');
  }
  if (nonce12.length != 12) {
    throw const InvalidArgumentException('ChaCha20 nonce is 12 bytes');
  }
}

/// One 64-byte ChaCha20 keystream block, RFC 8439 section 2.3.
Uint8List chacha20Block(List<int> key, List<int> nonce12, int counter) {
  _checkKeyNonce(key, nonce12);
  final ks = Uint32List(16);
  _block(_initState(_bytes(key), _bytes(nonce12), counter), ks);
  final out = Uint8List(64);
  for (var i = 0; i < 16; i++) {
    _put(out, i * 4, ks[i]);
  }
  return out;
}

/// ChaCha20 encryption, RFC 8439 section 2.4. Its own inverse.
Uint8List chacha20(
    List<int> key, List<int> nonce12, int counter, List<int> data) {
  _checkKeyNonce(key, nonce12);
  final input = _bytes(data);
  final n = input.length;
  final out = Uint8List(n);
  final start = _initState(_bytes(key), _bytes(nonce12), counter);
  final ks = Uint32List(16);
  final ks8 = Uint8List(64);
  // Whole blocks a word at a time where both sides are 4-aligned on a
  // little-endian host (every platform Dart ships on); bytes otherwise.
  final words = Endian.host == Endian.little && input.offsetInBytes % 4 == 0;
  final in32 =
      words ? input.buffer.asUint32List(input.offsetInBytes, n >> 2) : null;
  final out32 = words ? out.buffer.asUint32List(0, n >> 2) : null;
  for (var off = 0; off < n; off += 64) {
    _block(start, ks);
    start[12] = (start[12] + 1) & _mask32;
    if (words && n - off >= 64) {
      final w = off >> 2;
      for (var j = 0; j < 16; j++) {
        out32![w + j] = in32![w + j] ^ ks[j];
      }
      continue;
    }
    for (var i = 0; i < 16; i++) {
      _put(ks8, i * 4, ks[i]);
    }
    final m = n - off < 64 ? n - off : 64;
    for (var j = 0; j < m; j++) {
      out[off + j] = input[off + j] ^ ks8[j];
    }
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
  final k = _bytes(key), nn = _bytes(nonce16);
  final s = Uint32List(16);
  for (var i = 0; i < 4; i++) {
    s[i] = _sigma[i];
  }
  for (var i = 0; i < 8; i++) {
    s[4 + i] = _le32(k, i * 4);
  }
  for (var i = 0; i < 4; i++) {
    s[12 + i] = _le32(nn, i * 4);
  }
  _rounds(s);
  final out = Uint8List(32);
  void put(int slot, int w) {
    out[slot * 4] = w;
    out[slot * 4 + 1] = w >>> 8;
    out[slot * 4 + 2] = w >>> 16;
    out[slot * 4 + 3] = w >>> 24;
  }

  for (var i = 0; i < 4; i++) {
    put(i, s[i]);
    put(4 + i, s[12 + i]);
  }
  return out;
}

/// Poly1305, RFC 8439 section 2.5, fed incrementally.
///
/// The accumulator is five 26-bit limbs, so every partial product stays under
/// 2^57 and fits a signed 64-bit integer without a wider type. That is the
/// same shape a Java implementation uses on `long`, and the reason this file
/// does not need `BigInt` any more than `cke.dart` does.
final class _Poly1305 {
  _Poly1305(Uint8List key32) : _key = key32 {
    // r, clamped per RFC 8439 section 2.5.
    final t0 = _le32(key32, 0), t1 = _le32(key32, 4);
    final t2 = _le32(key32, 8), t3 = _le32(key32, 12);
    _r0 = t0 & 0x3FFFFFF;
    _r1 = ((t0 >>> 26) | (t1 << 6)) & 0x3FFFF03;
    _r2 = ((t1 >>> 20) | (t2 << 12)) & 0x3FFC0FF;
    _r3 = ((t2 >>> 14) | (t3 << 18)) & 0x3F03FFF;
    _r4 = (t3 >>> 8) & 0x00FFFFF;
  }

  final Uint8List _key;
  late final int _r0, _r1, _r2, _r3, _r4;
  int _h0 = 0, _h1 = 0, _h2 = 0, _h3 = 0, _h4 = 0;
  final Uint8List _tail = Uint8List(16);

  /// One 16-byte block at [o] of [b]; [hibit] is 1 << 24 for a full block.
  void _blockAt(Uint8List b, int o, int hibit) {
    final r0 = _r0, r1 = _r1, r2 = _r2, r3 = _r3, r4 = _r4;
    final s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    final b0 = _le32(b, o), b1 = _le32(b, o + 4);
    final b2 = _le32(b, o + 8), b3 = _le32(b, o + 12);
    final h0 = _h0 + (b0 & 0x3FFFFFF);
    final h1 = _h1 + (((b0 >>> 26) | (b1 << 6)) & 0x3FFFFFF);
    final h2 = _h2 + (((b1 >>> 20) | (b2 << 12)) & 0x3FFFFFF);
    final h3 = _h3 + (((b2 >>> 14) | (b3 << 18)) & 0x3FFFFFF);
    final h4 = _h4 + ((b3 >>> 8) | hibit);

    final d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    final d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    final d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    final d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    final d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    var c = d0 >> 26;
    var n0 = d0 & 0x3FFFFFF;
    var v = d1 + c;
    c = v >> 26;
    final n1 = v & 0x3FFFFFF;
    v = d2 + c;
    c = v >> 26;
    _h2 = v & 0x3FFFFFF;
    v = d3 + c;
    c = v >> 26;
    _h3 = v & 0x3FFFFFF;
    v = d4 + c;
    c = v >> 26;
    _h4 = v & 0x3FFFFFF;
    n0 += c * 5;
    c = n0 >> 26;
    _h0 = n0 & 0x3FFFFFF;
    _h1 = n1 + c;
  }

  /// [b] from [from] to [to] as whole blocks, the last one zero-padded: the
  /// RFC 8439 section 2.8 `pad16`, so each call ends on a block boundary.
  void addPadded(Uint8List b, int from, int to) {
    var o = from;
    while (to - o >= 16) {
      _blockAt(b, o, 1 << 24);
      o += 16;
    }
    if (o < to) {
      _tail.fillRange(0, 16, 0);
      _tail.setRange(0, to - o, b, o);
      _blockAt(_tail, 0, 1 << 24);
    }
  }

  /// A final short block of [n] bytes (the bare Poly1305 of section 2.5): the
  /// 1 bit goes just past the data rather than at byte 16.
  void addShort(Uint8List b, int o, int n) {
    final t = Uint8List(32)..setRange(0, n, b, o);
    t[n] = 1;
    _blockAt(t, 0, 0);
  }

  Uint8List finish() {
    var h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4;
    // Final carry propagation.
    var c = h1 >> 26;
    h1 &= 0x3FFFFFF;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3FFFFFF;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3FFFFFF;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3FFFFFF;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3FFFFFF;
    h1 += c;

    // Compute h + -p, and select it if there was no borrow.
    var g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3FFFFFF;
    var g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3FFFFFF;
    var g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3FFFFFF;
    var g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3FFFFFF;
    final g4 = h4 + c - (1 << 26);

    // 0 when h < p (g negative), all ones otherwise.
    final mask = ((g4 >> 63) & 1) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // Serialize h + s (the second half of the key) as 16 little-endian bytes.
    final f = [
      (h0 | (h1 << 26)) & _mask32,
      ((h1 >>> 6) | (h2 << 20)) & _mask32,
      ((h2 >>> 12) | (h3 << 14)) & _mask32,
      ((h3 >>> 18) | (h4 << 8)) & _mask32,
    ];
    final tag = Uint8List(16);
    var carry = 0;
    for (var i = 0; i < 4; i++) {
      final sum = f[i] + _le32(_key, 16 + i * 4) + carry;
      carry = (sum >>> 32) & 1;
      tag[i * 4] = sum;
      tag[i * 4 + 1] = sum >>> 8;
      tag[i * 4 + 2] = sum >>> 16;
      tag[i * 4 + 3] = sum >>> 24;
    }
    return tag;
  }
}

/// Poly1305, RFC 8439 section 2.5.
Uint8List poly1305(List<int> key32, List<int> message) {
  if (key32.length != 32) {
    throw const InvalidArgumentException('Poly1305 key is 32 bytes');
  }
  final m = _bytes(message);
  final p = _Poly1305(_bytes(key32));
  final whole = m.length & ~15;
  p.addPadded(m, 0, whole);
  if (whole < m.length) p.addShort(m, whole, m.length - whole);
  return p.finish();
}

/// The AEAD tag of RFC 8439 section 2.8 over
/// `aad || pad16 || ciphertext || pad16 || len(aad) || len(ciphertext)`,
/// fed in place.
Uint8List _aeadTag(Uint8List polyKey, Uint8List aad, Uint8List ciphertext) {
  final p = _Poly1305(polyKey)
    ..addPadded(aad, 0, aad.length)
    ..addPadded(ciphertext, 0, ciphertext.length);
  final lens = Uint8List(16);
  ByteData.view(lens.buffer)
    ..setUint64(0, aad.length, Endian.little)
    ..setUint64(8, ciphertext.length, Endian.little);
  p.addPadded(lens, 0, 16);
  return p.finish();
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
  return (ciphertext: ct, tag: _aeadTag(polyKey, _bytes(aad), ct));
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
  final expected = _aeadTag(polyKey, _bytes(aad), _bytes(ciphertext));
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
