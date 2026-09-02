/// BLAKE2b, RFC 7693.
///
/// Present for one reason: Argon2id is defined over it
/// (`spec/14-security.md` §2, RFC 9106 §3.2). It is not otherwise part of the
/// format, and nothing else in this implementation calls it.
///
/// Implemented from RFC 7693 §2.6, §2.7 and §3, and verified in
/// `test/blake2b_test.dart` against the RFC's own vectors — the unkeyed
/// `BLAKE2b-512("abc")` digest of Appendix A **and** the twelve intermediate
/// working vectors `v[0..15]` that appendix prints per round. Checking the
/// intermediate rounds matters here: a digest can come out right with a
/// transposed SIGMA row for a short single-block message, and Argon2 drives
/// this function over inputs where it would not.
library;

import 'dart:typed_data';

import 'errors.dart';

/// RFC 7693 §2.6: the same IV as SHA-512.
const List<int> _iv = [
  0x6A09E667F3BCC908, -0x4498517A7B3558C5, // BB67AE8584CAA73B
  0x3C6EF372FE94F82B, -0x5AB00AC5A0E2C90F, // A54FF53A5F1D36F1
  0x510E527FADE682D1, -0x64FA9773D4C193E1, // 9B05688C2B3E6C1F
  0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

/// RFC 7693 §2.7. Rounds 10 and 11 reuse rows 0 and 1.
const List<List<int>> _sigma = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

int _rotr(int x, int n) => (x >>> n) | (x << (64 - n));

/// A streaming BLAKE2b, keyed or unkeyed.
final class Blake2b {
  Blake2b({int digestLength = 64, List<int>? key, this.trace = false})
      : _outLen = digestLength {
    if (digestLength < 1 || digestLength > 64) {
      throw InvalidArgumentException(
          'BLAKE2b digest length $digestLength is outside 1..64');
    }
    final kk = key?.length ?? 0;
    if (kk > 64) {
      throw const InvalidArgumentException('BLAKE2b key exceeds 64 bytes');
    }
    for (var i = 0; i < 8; i++) {
      _h[i] = _iv[i];
    }
    // §3.3: h[0] ^= 0x01010000 ^ (kk << 8) ^ nn.
    _h[0] ^= 0x01010000 ^ (kk << 8) ^ digestLength;
    if (kk > 0) {
      // A keyed hash prepends one zero-padded block of key material.
      final block = Uint8List(128)..setRange(0, kk, key!);
      update(block);
    }
  }

  /// Record the working vector before every round. Test-only: RFC 7693
  /// Appendix A prints `v[0..15]` at each of the thirteen points around the
  /// twelve rounds, and matching all of them is what distinguishes a correct
  /// SIGMA from one that merely yields a correct digest on a one-block
  /// message — which is the case Argon2 never runs.
  final bool trace;

  /// Snapshots taken when [trace] is set: 13 per compression, `v` before
  /// round 0 through `v` after round 11.
  final List<Int64List> roundTrace = [];

  final int _outLen;
  final Int64List _h = Int64List(8);
  final Uint8List _buf = Uint8List(128);
  final Int64List _v = Int64List(16);
  final Int64List _m = Int64List(16);
  int _bufLen = 0;
  int _counter = 0;
  bool _done = false;

  void _g(int a, int b, int c, int d, int x, int y) {
    final v = _v;
    v[a] = v[a] + v[b] + x;
    v[d] = _rotr(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = _rotr(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = _rotr(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = _rotr(v[b] ^ v[c], 63);
  }

  /// RFC 7693 §3.2. [last] sets the finalization flag `f0`.
  void _compress(Uint8List block, int offset, bool last) {
    final bd = ByteData.view(block.buffer, block.offsetInBytes, block.length);
    for (var i = 0; i < 16; i++) {
      _m[i] = bd.getInt64(offset + i * 8, Endian.little);
    }
    for (var i = 0; i < 8; i++) {
      _v[i] = _h[i];
      _v[i + 8] = _iv[i];
    }
    // The counter is the byte offset at the END of this block; this
    // implementation caps inputs below 2^63 bytes, so t1 stays zero.
    _v[12] ^= _counter;
    if (last) _v[14] = ~_v[14];

    for (var r = 0; r < 12; r++) {
      if (trace) roundTrace.add(Int64List.fromList(_v));
      final s = _sigma[r % 10];
      _g(0, 4, 8, 12, _m[s[0]], _m[s[1]]);
      _g(1, 5, 9, 13, _m[s[2]], _m[s[3]]);
      _g(2, 6, 10, 14, _m[s[4]], _m[s[5]]);
      _g(3, 7, 11, 15, _m[s[6]], _m[s[7]]);
      _g(0, 5, 10, 15, _m[s[8]], _m[s[9]]);
      _g(1, 6, 11, 12, _m[s[10]], _m[s[11]]);
      _g(2, 7, 8, 13, _m[s[12]], _m[s[13]]);
      _g(3, 4, 9, 14, _m[s[14]], _m[s[15]]);
    }
    if (trace) roundTrace.add(Int64List.fromList(_v));
    for (var i = 0; i < 8; i++) {
      _h[i] ^= _v[i] ^ _v[i + 8];
    }
  }

  void update(List<int> data) {
    if (_done) throw StateError('BLAKE2b already finalized');
    var i = 0;
    while (i < data.length) {
      if (_bufLen == 128) {
        // Never compress the buffer until we know more input follows: the
        // final block takes the finalization flag and must not be compressed
        // as an ordinary one.
        _counter += 128;
        _compress(_buf, 0, false);
        _bufLen = 0;
      }
      final take = (128 - _bufLen) < (data.length - i)
          ? (128 - _bufLen)
          : (data.length - i);
      _buf.setRange(_bufLen, _bufLen + take, data, i);
      _bufLen += take;
      i += take;
    }
  }

  Uint8List digest() {
    if (_done) throw StateError('BLAKE2b already finalized');
    _done = true;
    _counter += _bufLen;
    for (var i = _bufLen; i < 128; i++) {
      _buf[i] = 0;
    }
    _compress(_buf, 0, true);
    final out = Uint8List(_outLen);
    final bd = ByteData.view(out.buffer);
    for (var i = 0; i < _outLen; i += 8) {
      final word = _h[i ~/ 8];
      final n = _outLen - i < 8 ? _outLen - i : 8;
      if (n == 8) {
        bd.setInt64(i, word, Endian.little);
      } else {
        for (var b = 0; b < n; b++) {
          out[i + b] = (word >>> (8 * b)) & 0xFF;
        }
      }
    }
    return out;
  }

  /// The final chaining state `h[0..7]`, which RFC 7693 Appendix A prints as
  /// big-endian words while the digest is those words little-endian.
  Int64List get chainingState => _h;
}

Uint8List blake2b(List<int> data, {int digestLength = 64, List<int>? key}) =>
    (Blake2b(digestLength: digestLength, key: key)..update(data)).digest();
