/// LZ4 **block** format — `spec/01-container.md` section 7, codec id 1.
///
/// Raw block, no frame header: `payload_len` in the page header gives the
/// decompressed size, so the block carries no length of its own. LZ4 is the
/// default codec and **the only one a Level-0 implementation MUST support**;
/// Zstd is its own feature bit.
///
/// A block is a sequence of `(literals, match)` sequences:
///
/// ```text
///   u8    token       -- high nibble literal length, low nibble match length-4
///   [u8]* extra literal length, 255-terminated continuation
///   bytes literals
///   u16le offset      -- absent iff this is the last sequence
///   [u8]* extra match length
/// ```
///
/// **Only the decoder is normative.** Section 7 pins the bytes a reader must be
/// able to decode, not the bytes a writer must produce: any conforming LZ4
/// block decompresses to the same output whatever produced it, so three
/// implementations may compress a page to three different lengths and still
/// read each other's files. That is the same freedom `08-spatial.md` section
/// 2.3 gives the R-tree split algorithm, and for the same reason.
///
/// The compressor here is a plain single-table hash matcher. It is not fast and
/// does not try to be.
library;

import 'dart:typed_data';

import 'container.dart';
import 'errors.dart';

const int _minMatch = 4;

/// The last five bytes of a block are always literals, and the last match must
/// start at least twelve bytes before the end.
///
/// These are the LZ4 *end-of-block restrictions*. A decoder that reads a block
/// safely does not need them, but the widely-deployed fast decoders take a
/// shortcut that does, and the point of writing an LZ4 block is that somebody
/// else's decoder reads it. Honouring them costs a handful of literal bytes on
/// the tail of a page and removes the question entirely.
const int _lastLiterals = 5;
const int _matchEndGuard = 12;
const int _hashBits = 14;

/// Section 7: "a page is stored compressed only if compression saves >= 12.5 %".
///
/// Measured against the payload being compressed, not against the whole page:
/// the 40-byte header is never compressed, so including it would make the
/// threshold depend on the page size.
bool worthCompressing(int raw, int compressed) => compressed + raw ~/ 8 <= raw;

/// An upper bound on the compressed size, for sizing a scratch buffer.
///
/// The worst case is an incompressible input, which is emitted as literals: one
/// token, the 255-continuation length bytes, and the input itself.
int maxCompressedLength(int n) => n + n ~/ 255 + 16;

/// Decompresses an LZ4 block whose plaintext is exactly [decompressedLen]
/// bytes.
///
/// Every length in the block is checked against both buffers before it is used.
/// A page from a file someone else wrote is untrusted input
/// (`spec/14-security.md` section 9), and a decompressor is the classic place
/// to write past the end of a buffer on a crafted length.
Uint8List lz4Decompress(Uint8List src, int decompressedLen) {
  final dst = Uint8List(decompressedLen);
  var s = 0;
  var d = 0;
  while (s < src.length) {
    final token = src[s++];
    var litLen = token >> 4;
    if (litLen == 15) {
      int b;
      do {
        if (s >= src.length) {
          throw const CorruptionException('LZ4 block ends inside a literal length');
        }
        b = src[s++];
        litLen += b;
      } while (b == 255);
    }
    if (s + litLen > src.length || d + litLen > dst.length) {
      throw CorruptionException('LZ4 block: $litLen literals overrun the buffer');
    }
    dst.setRange(d, d + litLen, src, s);
    s += litLen;
    d += litLen;
    if (s >= src.length) break;
    if (s + 2 > src.length) {
      throw const CorruptionException('LZ4 block ends inside a match offset');
    }
    final offset = src[s] | (src[s + 1] << 8);
    s += 2;
    if (offset == 0 || offset > d) {
      throw CorruptionException(
          'LZ4 match offset $offset points outside the output');
    }
    var matchLen = token & 0x0F;
    if (matchLen == 15) {
      int b;
      do {
        if (s >= src.length) {
          throw const CorruptionException('LZ4 block ends inside a match length');
        }
        b = src[s++];
        matchLen += b;
      } while (b == 255);
    }
    matchLen += _minMatch;
    if (d + matchLen > dst.length) {
      throw CorruptionException('LZ4 match of $matchLen overruns the output');
    }
    // Byte at a time on purpose: an overlapping match (offset < length) is
    // legal and is how LZ4 encodes a run, so a block copy would be wrong.
    var m = d - offset;
    for (var i = 0; i < matchLen; i++) {
      dst[d++] = dst[m++];
    }
  }
  if (d != decompressedLen) {
    throw CorruptionException(
        'LZ4 block decoded to $d bytes, expected $decompressedLen');
  }
  return dst;
}

/// Compresses [src] into a raw LZ4 block.
Uint8List lz4Compress(Uint8List src) {
  final dst = Uint8List(maxCompressedLength(src.length));
  final table = Int32List(1 << _hashBits)..fillRange(0, 1 << _hashBits, -1);
  var s = 0;
  var anchor = 0;
  var d = 0;
  // A match may start no later than twelve bytes before the end, and needs
  // four bytes to hash. Below that the whole block is literals.
  final limit = src.length - _matchEndGuard;
  while (s <= limit) {
    final h = _hash(src, s);
    final candidate = table[h];
    table[h] = s;
    if (candidate < 0 || s - candidate > 0xFFFF || !_matches(src, candidate, s)) {
      s++;
      continue;
    }
    var matchLen = _minMatch;
    final max = src.length - _lastLiterals;
    while (s + matchLen < max && src[candidate + matchLen] == src[s + matchLen]) {
      matchLen++;
    }
    d = _emit(src, dst, d, anchor, s - anchor, s - candidate, matchLen - _minMatch);
    s += matchLen;
    anchor = s;
  }
  // The last sequence has no match: trailing literals only.
  final litLen = src.length - anchor;
  d = _emitToken(dst, d, litLen, 0);
  d = _emitLength(dst, d, litLen, 15);
  dst.setRange(d, d + litLen, src, anchor);
  return Uint8List.sublistView(dst, 0, d + litLen);
}

int _emit(Uint8List src, Uint8List dst, int d, int anchor, int litLen,
    int offset, int matchExtra) {
  d = _emitToken(dst, d, litLen, matchExtra);
  d = _emitLength(dst, d, litLen, 15);
  dst.setRange(d, d + litLen, src, anchor);
  d += litLen;
  dst[d++] = offset & 0xFF;
  dst[d++] = (offset >> 8) & 0xFF;
  return _emitLength(dst, d, matchExtra, 15);
}

int _emitToken(Uint8List dst, int d, int litLen, int matchExtra) {
  final hi = litLen < 15 ? litLen : 15;
  final lo = matchExtra < 15 ? matchExtra : 15;
  dst[d++] = (hi << 4) | lo;
  return d;
}

int _emitLength(Uint8List dst, int d, int len, int threshold) {
  if (len < threshold) return d;
  var rest = len - threshold;
  while (rest >= 255) {
    dst[d++] = 255;
    rest -= 255;
  }
  dst[d++] = rest;
  return d;
}

bool _matches(Uint8List src, int a, int b) =>
    src[a] == src[b] &&
    src[a + 1] == src[b + 1] &&
    src[a + 2] == src[b + 2] &&
    src[a + 3] == src[b + 3];

int _hash(Uint8List src, int i) {
  final v = src[i] | (src[i + 1] << 8) | (src[i + 2] << 16) | (src[i + 3] << 24);
  // 0x9E3779B1 is the 32-bit golden-ratio constant; the product is masked back
  // to 32 bits because Dart's int is 64-bit and the shift below assumes 32.
  return ((v * 0x9E3779B1) & 0xFFFFFFFF) >> (32 - _hashBits);
}

// ---------------------------------------------------------------------------
// The codec dispatch of `spec/01-container.md` section 7.
// ---------------------------------------------------------------------------

/// Compresses [raw] under [codec], or returns `null` to store it as it is.
///
/// `null` is the answer both for `page_codec = 0` and for a payload that does
/// not compress by section 7's 12.5 % margin — the two cases are the same
/// decision to the caller, which is why they are one return value.
Uint8List? compressPayload(int codec, Uint8List raw) {
  switch (codec) {
    case Codec.none:
      return null;
    case Codec.lz4:
      final out = lz4Compress(raw);
      return worthCompressing(raw.length, out.length) ? out : null;
    case Codec.zstd:
      throw const UnsupportedFeatureException(
          'codec 2 (Zstd) needs feature bit ZSTD, which this build does not set');
    default:
      throw CorruptionException('unknown codec id $codec');
  }
}

/// Decompresses [data] under [codec] to exactly [payloadLen] bytes.
Uint8List decompressPayload(int codec, Uint8List data, int payloadLen) {
  switch (codec) {
    case Codec.none:
      return Uint8List.fromList(data);
    case Codec.lz4:
      return lz4Decompress(data, payloadLen);
    case Codec.zstd:
      throw const UnsupportedFeatureException(
          'this build cannot decompress Zstd (feature bit ZSTD)');
    default:
      throw CorruptionException('unknown codec id $codec');
  }
}
