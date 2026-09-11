/// The segment membership filter, `spec/04-segments.md` section 2.4.
///
/// The chapter is emphatic about why this file is specified to the bit:
///
///   > "Specified to the bit, because a filter that disagrees between
///   >  languages produces **wrong results**, not slow ones -- a false
///   >  *negative* silently loses a key."
///
/// Block count, block selection, the probe sequence, bit order within a block,
/// the derivation of `k`, the page layout and **the hash itself** are all
/// implemented exactly as the spec states, and `test/filter_test.dart` checks
/// each against the text.
///
/// The hash is [cfh64], specified in full in `spec/04-segments.md` §2.4.1. It
/// replaced XXH3-64 during phase 1 of this implementation: see `REPORT.md`.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'container.dart';
import 'errors.dart';

/// A 64-bit hash of a user key.
///
/// A parameter only so that `tool/experiments/` can measure alternatives.
/// Conforming files use [cfh64] and nothing else.
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
    Hash64 hash = cfh64,
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

  bool mayContain(List<int> key) => mayContainHash(_hash(key));

  /// [mayContain] for a key whose hash the caller already has -- which must be
  /// this filter's hash of it; a filter decoded from a segment uses [cfh64].
  bool mayContainHash(int h) {
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
      {Hash64 hash = cfh64}) {
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

/// CFH-64, the filter hash of `spec/04-segments.md` §2.4.1.
///
/// Every operation is a wrapping 64-bit multiply, an XOR, a logical shift or a
/// rotate — four things every target language has on its widest integer. There
/// is no table, no secret, and nothing to look up: the twenty lines below are
/// the whole definition, and the spec prints them.
///
/// **Why not XXH3-64**, which the spec named until phase 1. Roughly 500 lines,
/// seven length-dependent branches, and a 192-byte secret table, guarding the
/// one structure in the format whose failure mode is a silent false *negative*
/// — a lost key. Three independent reimplementations of that from the paper is
/// a risk out of all proportion to what a Bloom filter needs.
///
/// **Why not CRC-32C**, which is already mandatory for every page and would
/// have been free. CRC is affine in its initial state, so any pair of CRC-32C
/// evaluations over the same key is affinely related and carries **32 bits of
/// entropy, not 64** — a finalizer spreads those bits but cannot create more.
/// `tool/experiments/hash_entropy2.dart` measures it: over 4 000 000 random
/// keys the CRC pair collided 1868 times against 1863 predicted by the 2^32
/// birthday bound, and CFH-64 collided zero times. Each such collision is a
/// *guaranteed* false positive, and they grow as n^2 / 2^33.
int cfh64(List<int> key) =>
    key is Uint8List ? _cfh64Bytes(key) : _cfh64(key);

/// [cfh64] over a byte array, with its own call site: through `List<int>`
/// every element read is a polymorphic call, and the point read hashes its
/// key once per read.
int _cfh64Bytes(Uint8List key) => _cfh64(key);

@pragma('vm:prefer-inline')
int _cfh64(List<int> key) {
  const p1 = 0x9E3779B185EBCA87;
  const p2 = -0x3D4D51C2D82B14B1; // 0xC2B2AE3D27D4EB4F as a signed 64-bit int
  const p3 = 0x165667B19E3779F9;
  const m1 = -0x40A7B892E31B1A47; // 0xBF58476D1CE4E5B9
  const m2 = -0x6B2FB644ECCEEE15; // 0x94D049BB133111EB

  final n = key.length;
  var h = p1 ^ (n * p2);
  var i = 0;
  while (n - i >= 8) {
    // Little-endian 64-bit word, per spec/00-conventions.md section 3.
    var w = 0;
    for (var j = 7; j >= 0; j--) {
      w = (w << 8) | (key[i + j] & 0xFF);
    }
    h ^= w * p2;
    h = _rotl64(h, 31) * p1;
    i += 8;
  }
  // The final 0..7 bytes, folded most-significant byte first.
  var tail = 0;
  while (i < n) {
    tail = (tail << 8) | (key[i] & 0xFF);
    i++;
  }
  h ^= tail * p3;
  h = _rotl64(h, 27) * p1;

  h = (h ^ (h >>> 30)) * m1;
  h = (h ^ (h >>> 27)) * m2;
  return h ^ (h >>> 31);
}

int _rotl64(int x, int n) => (x << n) | (x >>> (64 - n));
