/// Argon2id, RFC 9106 — the password-stretching primitive of
/// `spec/14-security.md` §2 and §3.2.
///
/// **This file is the worked answer to "isn't naming an algorithm a language
/// dependency?"** (`spec/00-conventions.md` §1.1). Argon2id is a published
/// standard with a published vector set; it is implemented here in pure Dart
/// from RFC 9106 §3, with no dependency, in a few hundred lines, and
/// `test/argon2_test.dart` reproduces the RFC's §5.3 vector — the pre-hashing
/// digest H_0 *and* the final tag — byte for byte. Naming Argon2id is what
/// lets any SDK do the same and arrive at the same keys; describing it as "a
/// memory-hard KDF" would have two SDKs derive different keys from one
/// password and neither able to open the other's file.
///
/// Only Argon2id (`y = 2`) is implemented. `14-security.md` §3.2 permits no
/// other type, and an unused Argon2d path is a hazard rather than a feature.
library;

import 'dart:typed_data';

import 'blake2b.dart';
import 'errors.dart';

/// RFC 9106 §3.1: the version this format uses. 0x13 = 19.
const int kArgon2Version = 0x13;

/// Argon2id, RFC 9106 §3.4.1.3.
const int _typeArgon2id = 2;

const int _blockBytes = 1024;
const int _words = _blockBytes ~/ 8; // 128
const int _syncPoints = 4; // SL

int _rotr(int x, int n) => (x >>> n) | (x << (64 - n));

/// `LE32`.
void _le32(BytesBuilder b, int v) => b.add([
      v & 0xFF,
      (v >>> 8) & 0xFF,
      (v >>> 16) & 0xFF,
      (v >>> 24) & 0xFF,
    ]);

/// The variable-length hash `H'`, RFC 9106 §3.3.
Uint8List _hPrime(int outLen, List<int> input) {
  final pre = BytesBuilder()
    ..add([
      outLen & 0xFF,
      (outLen >>> 8) & 0xFF,
      (outLen >>> 16) & 0xFF,
      (outLen >>> 24) & 0xFF,
    ])
    ..add(input);
  if (outLen <= 64) return blake2b(pre.takeBytes(), digestLength: outLen);

  final out = Uint8List(outLen);
  final r = ((outLen + 31) ~/ 32) - 2;
  var v = blake2b(pre.takeBytes());
  out.setRange(0, 32, v);
  for (var i = 1; i < r; i++) {
    v = blake2b(v);
    out.setRange(i * 32, i * 32 + 32, v);
  }
  final tail = blake2b(v, digestLength: outLen - 32 * r);
  out.setRange(32 * r, outLen, tail);
  return out;
}

/// `GB`, RFC 9106 §3.6 — BLAKE2b's mixing function with the extra
/// 64-bit multiply that is "the only difference from the original BLAKE2b
/// design".
void _gb(Int64List v, int a, int b, int c, int d) {
  // a = (a + b + 2 * trunc(a) * trunc(b)) mod 2^64, where trunc is the low
  // 32 bits. The doubled product is what raises ASIC circuit depth.
  v[a] = v[a] + v[b] + 2 * (v[a] & 0xFFFFFFFF) * (v[b] & 0xFFFFFFFF);
  v[d] = _rotr(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d] + 2 * (v[c] & 0xFFFFFFFF) * (v[d] & 0xFFFFFFFF);
  v[b] = _rotr(v[b] ^ v[c], 24);
  v[a] = v[a] + v[b] + 2 * (v[a] & 0xFFFFFFFF) * (v[b] & 0xFFFFFFFF);
  v[d] = _rotr(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d] + 2 * (v[c] & 0xFFFFFFFF) * (v[d] & 0xFFFFFFFF);
  v[b] = _rotr(v[b] ^ v[c], 63);
}

/// Permutation `P` over sixteen consecutive words, RFC 9106 §3.6.
void _p(Int64List v, int o, int stride) {
  int at(int i) => o + i * stride;
  _gb(v, at(0), at(4), at(8), at(12));
  _gb(v, at(1), at(5), at(9), at(13));
  _gb(v, at(2), at(6), at(10), at(14));
  _gb(v, at(3), at(7), at(11), at(15));
  _gb(v, at(0), at(5), at(10), at(15));
  _gb(v, at(1), at(6), at(11), at(12));
  _gb(v, at(2), at(7), at(8), at(13));
  _gb(v, at(3), at(4), at(9), at(14));
}

/// The compression function `G`, RFC 9106 §3.5.
///
/// `out = Z XOR R` where `R = X XOR Y`, `P` applied rowwise then columnwise.
/// [xorInto] is step 6's variant: on passes after the first, the new block is
/// XORed into the old one rather than replacing it.
void _g(Int64List x, int xo, Int64List y, int yo, Int64List out, int oo,
    {required bool xorInto}) {
  final r = Int64List(_words);
  for (var i = 0; i < _words; i++) {
    r[i] = x[xo + i] ^ y[yo + i];
  }
  final z = Int64List.fromList(r);
  // Rows: eight 16-word groups, contiguous.
  for (var i = 0; i < 8; i++) {
    _p(z, i * 16, 1);
  }
  // Columns: 2-word registers striding by 16 words.
  for (var i = 0; i < 8; i++) {
    _p2(z, i * 2);
  }
  if (xorInto) {
    for (var i = 0; i < _words; i++) {
      out[oo + i] ^= z[i] ^ r[i];
    }
  } else {
    for (var i = 0; i < _words; i++) {
      out[oo + i] = z[i] ^ r[i];
    }
  }
}

/// The columnwise half of §3.5.
///
/// A column is eight **16-byte registers** — pairs of 64-bit words — taken
/// every 16 words, so the sixteen words fed to `P` are
/// `(base, base+1, base+16, base+17, …)`, not a fixed stride. Getting this
/// wrong still produces a plausible avalanche and a wrong tag, which is
/// exactly why the RFC vector is the test rather than a self-consistency check.
void _p2(Int64List v, int base) {
  final idx = List<int>.filled(16, 0);
  for (var i = 0; i < 8; i++) {
    idx[i * 2] = base + i * 16;
    idx[i * 2 + 1] = base + i * 16 + 1;
  }
  _gb(v, idx[0], idx[4], idx[8], idx[12]);
  _gb(v, idx[1], idx[5], idx[9], idx[13]);
  _gb(v, idx[2], idx[6], idx[10], idx[14]);
  _gb(v, idx[3], idx[7], idx[11], idx[15]);
  _gb(v, idx[0], idx[5], idx[10], idx[15]);
  _gb(v, idx[1], idx[6], idx[11], idx[12]);
  _gb(v, idx[2], idx[7], idx[8], idx[13]);
  _gb(v, idx[3], idx[4], idx[9], idx[14]);
}

/// The result of one Argon2id derivation, plus the intermediate the RFC
/// publishes so an implementation can be located when it disagrees.
final class Argon2Result {
  const Argon2Result(this.tag, this.h0);
  final Uint8List tag;

  /// `H_0`, RFC 9106 §3.2 step 1 — the "pre-hashing digest" of §5.3. Exposed
  /// because when two implementations disagree on the tag, this says whether
  /// they disagree about the *inputs* or about the memory filling.
  final Uint8List h0;
}

/// Argon2id, RFC 9106.
///
/// [memoryKiB] is `m`, [passes] is `t`, [parallelism] is `p`. [secret] is the
/// optional key `K` and [associatedData` is `X`; `14-security.md` §3.2 uses
/// neither, and both are here because `H_0` includes their length fields
/// whether or not they are present.
Argon2Result argon2id({
  required List<int> password,
  required List<int> salt,
  required int memoryKiB,
  required int passes,
  required int parallelism,
  int tagLength = 32,
  List<int> secret = const [],
  List<int> associatedData = const [],
}) {
  if (parallelism < 1 || parallelism > 0xFFFFFF) {
    throw InvalidArgumentException('Argon2 parallelism $parallelism is out of range');
  }
  if (passes < 1) {
    throw InvalidArgumentException('Argon2 passes $passes must be at least 1');
  }
  if (tagLength < 4) {
    throw InvalidArgumentException('Argon2 tag length $tagLength is below 4');
  }
  if (memoryKiB < 8 * parallelism) {
    throw InvalidArgumentException(
        'Argon2 memory $memoryKiB KiB is below the 8*p minimum for p=$parallelism');
  }

  // Step 1: H_0.
  final pre = BytesBuilder();
  _le32(pre, parallelism);
  _le32(pre, tagLength);
  _le32(pre, memoryKiB);
  _le32(pre, passes);
  _le32(pre, kArgon2Version);
  _le32(pre, _typeArgon2id);
  _le32(pre, password.length);
  pre.add(password);
  _le32(pre, salt.length);
  pre.add(salt);
  _le32(pre, secret.length);
  pre.add(secret);
  _le32(pre, associatedData.length);
  pre.add(associatedData);
  final h0 = blake2b(pre.takeBytes());

  // Step 2: m' = 4 * p * floor(m / 4p), organized as p lanes of q columns.
  final blocks = 4 * parallelism * (memoryKiB ~/ (4 * parallelism));
  final q = blocks ~/ parallelism;
  final segment = q ~/ _syncPoints;
  final b = Int64List(blocks * _words);

  void loadBlock(Uint8List src, int blockIndex) {
    final bd = ByteData.view(src.buffer, src.offsetInBytes, src.length);
    for (var i = 0; i < _words; i++) {
      b[blockIndex * _words + i] = bd.getInt64(i * 8, Endian.little);
    }
  }

  // Steps 3 and 4: the first two blocks of every lane.
  for (var lane = 0; lane < parallelism; lane++) {
    for (var col = 0; col < 2; col++) {
      final input = BytesBuilder()
        ..add(h0);
      _le32(input, col);
      _le32(input, lane);
      loadBlock(_hPrime(_blockBytes, input.takeBytes()), lane * q + col);
    }
  }

  // Steps 5 and 6: fill the rest, slicewise.
  final zBlock = Int64List(_words);
  final addrBlock = Int64List(_words);
  final inputBlock = Int64List(_words);
  final zero = Int64List(_words);

  for (var pass = 0; pass < passes; pass++) {
    for (var slice = 0; slice < _syncPoints; slice++) {
      for (var lane = 0; lane < parallelism; lane++) {
        // §3.4.1.3: Argon2id uses the data-independent (Argon2i) addressing
        // for the first two slices of the first pass, and the data-dependent
        // (Argon2d) addressing everywhere else. That split is the whole point
        // of the "id" variant and is the single easiest thing to get wrong.
        final dataIndependent = pass == 0 && slice < 2;
        var addrIndex = 0;
        if (dataIndependent) {
          for (var i = 0; i < _words; i++) {
            inputBlock[i] = 0;
          }
          inputBlock[0] = pass;
          inputBlock[1] = lane;
          inputBlock[2] = slice;
          inputBlock[3] = blocks;
          inputBlock[4] = passes;
          inputBlock[5] = _typeArgon2id;
        }

        void nextAddressBlock() {
          inputBlock[6] = inputBlock[6] + 1;
          _g(zero, 0, inputBlock, 0, zBlock, 0, xorInto: false);
          _g(zero, 0, zBlock, 0, addrBlock, 0, xorInto: false);
        }

        final startCol = (pass == 0 && slice == 0) ? 2 : 0;
        for (var i = startCol; i < segment; i++) {
          final col = slice * segment + i;
          final prev = col == 0 ? (lane * q + q - 1) : (lane * q + col - 1);

          int j1, j2;
          if (dataIndependent) {
            if (addrIndex % _words == 0) {
              nextAddressBlock();
              addrIndex = 0;
            }
            final w = addrBlock[addrIndex++];
            j1 = w & 0xFFFFFFFF;
            j2 = (w >>> 32) & 0xFFFFFFFF;
          } else {
            final w = b[prev * _words];
            j1 = w & 0xFFFFFFFF;
            j2 = (w >>> 32) & 0xFFFFFFFF;
          }

          // §3.4.2.
          final refLane =
              (pass == 0 && slice == 0) ? lane : (j2 % parallelism);
          final sameLane = refLane == lane;

          int refAreaSize;
          if (pass == 0) {
            if (slice == 0 || sameLane) {
              refAreaSize = col - 1;
            } else {
              refAreaSize = slice * segment - (i == 0 ? 1 : 0);
            }
          } else {
            if (sameLane) {
              refAreaSize = q - segment + i - 1;
            } else {
              refAreaSize = q - segment - (i == 0 ? 1 : 0);
            }
          }

          // J_1 -> |W|(1 - J_1^2 / 2^64), via the integer approximation of
          // Figure 13.
          final x = (j1 * j1) >>> 32;
          final y = (refAreaSize * x) >>> 32;
          final zz = refAreaSize - 1 - y;

          final startPos = (pass != 0 && slice != _syncPoints - 1)
              ? (slice + 1) * segment
              : 0;
          final refCol = (startPos + zz) % q;

          _g(b, prev * _words, b, (refLane * q + refCol) * _words, b,
              (lane * q + col) * _words,
              xorInto: pass != 0);
        }
      }
    }
  }

  // Step 7: C is the XOR of the last column.
  final c = Int64List(_words);
  for (var lane = 0; lane < parallelism; lane++) {
    final off = (lane * q + q - 1) * _words;
    for (var i = 0; i < _words; i++) {
      c[i] ^= b[off + i];
    }
  }
  final cBytes = Uint8List(_blockBytes);
  final cd = ByteData.view(cBytes.buffer);
  for (var i = 0; i < _words; i++) {
    cd.setInt64(i * 8, c[i], Endian.little);
  }

  // Step 8.
  return Argon2Result(_hPrime(tagLength, cBytes), h0);
}
