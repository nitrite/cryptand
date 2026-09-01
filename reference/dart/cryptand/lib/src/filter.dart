/// The segment membership filter, `spec/04-segments.md` section 2.4.
///
/// The chapter is emphatic about why this file is specified to the bit:
///
///   > "Specified to the bit, because a filter that disagrees between
///   >  languages produces **wrong results**, not slow ones -- a false
///   >  *negative* silently loses a key."
///
/// Everything below the hash -- block count, block selection, the probe
/// sequence, bit order within a block, the derivation of `k`, and the page
/// layout -- is implemented exactly as the spec states, and
/// `test/filter_test.dart` checks each against the text.
///
/// **The 64-bit hash is a parameter here, not a constant.** The spec names
/// XXH3-64. See [Hash64] and `REPORT.md` section "XXH3-64" for why this
/// reference does not ship an unverified one.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'container.dart';
import 'crc32c.dart';
import 'errors.dart';

/// A 64-bit hash of a user key, seeded.
typedef Hash64 = int Function(List<int> key);

/// Bits per block. `spec/04-segments.md` section 2.4: 512 bits (64 bytes),
/// so a probe touches exactly one cache line and one 64-byte read.
const int kBlockBits = 512;
const int kBlockBytes = kBlockBits ~/ 8;

/// `k = max(1, min(16, round(filter_bits_per_key * ln 2)))`.
int probesFor(int bitsPerKey) {
  final k = (bitsPerKey * 0.6931471805599453).round();
  return k < 1 ? 1 : (k > 16 ? 16 : k);
}

/// `block_count = max(1, ceil(entry_count * filter_bits_per_key / 512))`.
int blockCountFor(int distinctKeys, int bitsPerKey) {
  final n = (distinctKeys * bitsPerKey + kBlockBits - 1) ~/ kBlockBits;
  return n < 1 ? 1 : n;
}

/// A blocked Bloom filter over a segment's user keys.
final class BlockedBloom {
  BlockedBloom._(this.blocks, this.blockCount, this.bitsPerKey, this.probes,
      this.distinctKeys, this._hash);

  factory BlockedBloom.build(
    Iterable<List<int>> userKeys, {
    required int bitsPerKey,
    required int distinctKeys,
    Hash64 hash = crcHash64,
  }) {
    final blockCount = blockCountFor(distinctKeys, bitsPerKey);
    final probes = probesFor(bitsPerKey);
    final f = BlockedBloom._(Uint8List(blockCount * kBlockBytes), blockCount,
        bitsPerKey, probes, distinctKeys, hash);
    for (final k in userKeys) {
      f._add(k);
    }
    return f;
  }

  final Uint8List blocks;
  final int blockCount;
  final int bitsPerKey;
  final int probes;
  final int distinctKeys;
  final Hash64 _hash;

  /// `block = (h1 * block_count) >> 32`, a u64 multiply keeping the high half.
  int _blockOf(int h1) => (h1 * blockCount) >> 32;

  void _add(List<int> key) {
    final h = _hash(key);
    final h1 = h & 0xFFFFFFFF;
    final h2 = ((h >>> 32) | 1) & 0xFFFFFFFF; // forced ODD
    final base = _blockOf(h1) * kBlockBytes;
    var probe = h1;
    for (var i = 0; i < probes; i++) {
      final bit = probe & (kBlockBits - 1);
      // Bit b of a block is bit (b mod 8) of byte (b div 8), counting bits
      // from the least-significant end of the byte.
      blocks[base + (bit >> 3)] |= 1 << (bit & 7);
      probe = (probe + h2) & 0xFFFFFFFF;
    }
  }

  bool mayContain(List<int> key) {
    final h = _hash(key);
    final h1 = h & 0xFFFFFFFF;
    final h2 = ((h >>> 32) | 1) & 0xFFFFFFFF;
    final base = _blockOf(h1) * kBlockBytes;
    var probe = h1;
    for (var i = 0; i < probes; i++) {
      final bit = probe & (kBlockBits - 1);
      if (blocks[base + (bit >> 3)] & (1 << (bit & 7)) == 0) return false;
      probe = (probe + h2) & 0xFFFFFFFF;
    }
    return true;
  }

  /// Filter page payload, section 2.4.
  Uint8List encodePayload() {
    final w = ByteWriter(blocks.length + 24)
      ..u32(0x43465031) // "CFP1"
      ..u32(blockCount)
      ..u16(bitsPerKey)
      ..u16(probes)
      ..u64(distinctKeys)
      ..bytes(blocks);
    return w.takeBytes();
  }

  static BlockedBloom decodePayload(Uint8List payload,
      {Hash64 hash = crcHash64}) {
    final r = ByteReader(payload);
    if (r.u32() != 0x43465031) {
      throw const CorruptionException('bad filter page magic (expected CFP1)');
    }
    final blockCount = r.u32();
    final bitsPerKey = r.u16();
    // Section 2.4: "a reader MUST use this value, not recompute it", so that a
    // future minor version can change the derivation without invalidating
    // existing files.
    final probes = r.u16();
    final distinctKeys = r.u64();
    if (blockCount < 1 || probes < 1 || probes > 16) {
      throw const CorruptionException('filter header out of range');
    }
    final need = blockCount * kBlockBytes;
    if (need > r.remaining) {
      throw CorruptionException(
          'filter declares $blockCount blocks but has ${r.remaining} bytes');
    }
    return BlockedBloom._(r.bytesCopy(need), blockCount, bitsPerKey, probes,
        distinctKeys, hash);
  }

  /// Serializes into whole pages, head page type `SEGMENT_FILTER`.
  List<Uint8List> encodePages(int pageSize) {
    final payload = encodePayload();
    final perPage = pageSize - PageHeader.size;
    final pageCount = (payload.length + perPage - 1) ~/ perPage;
    final out = <Uint8List>[];
    for (var i = 0; i < pageCount; i++) {
      final page = Uint8List(pageSize);
      final start = i * perPage;
      final n = (payload.length - start).clamp(0, perPage);
      page.setRange(PageHeader.size, PageHeader.size + n, payload, start);
      PageHeader(
        pageType: PageType.segmentFilter,
        flags: i == 0 ? PageFlags.extentHead : 0,
        treeId: TreeId.noTree,
        extentPages: i == 0 ? pageCount : 1,
        payloadLen: n,
      ).writeInto(page);
      out.add(page);
    }
    return out;
  }
}

/// The reference implementation's 64-bit hash.
///
/// **This is not XXH3-64**, which `spec/04-segments.md` section 2.4 names.
///
/// XXH3-64 is a ~500-line algorithm with seven length-dependent branches and a
/// fixed 192-byte secret table. This reference cannot verify an XXH3
/// implementation against the canonical vectors in the environment it was
/// written in, and shipping an *unverified* hash in the artifact that other
/// SDKs are meant to match would bake any error into the contract -- as false
/// negatives, which lose keys silently.
///
/// So the filter is built over two independent CRC-32C evaluations instead:
/// CRC-32C is already mandatory for every page (`spec/00-conventions.md`
/// section 6), is already verified here against the RFC 3720 vectors, and is
/// hardware-accelerated on every target. `test/filter_test.dart` measures the
/// false-positive rate this produces against the rates section 2.4 predicts.
///
/// `REPORT.md` carries the recommendation that follows from that measurement.
int crcHash64(List<int> key) {
  final lo = crc32c(key);
  // A second, independent evaluation over a domain-separated copy.
  final salted = Uint8List(key.length + 4);
  salted.setRange(0, key.length, key);
  salted[key.length] = 0x9E;
  salted[key.length + 1] = 0x37;
  salted[key.length + 2] = 0x79;
  salted[key.length + 3] = 0xB9;
  final hi = crc32c(salted);
  return (hi << 32) | lo;
}
