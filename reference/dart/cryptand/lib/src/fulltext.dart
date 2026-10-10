/// The full-text index — `spec/07-fulltext.md` §1 and §4.
///
/// Three trees per index (`term_dict`, `term_index`, `postings`) and a postings
/// block layout whose one structural claim is §4.4's:
///
/// > "Because blocks are ≤128 postings, a high-frequency term's index is many
/// > small blocks and an update rewrites one of them, not the whole posting
/// > list. This is the property that the current
/// > `Map<String token, List<NitriteId>>` layout in all three SDKs lacks —
/// > there, every update to a common word rewrites a list that can be the size
/// > of the collection."
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'cke.dart';
import 'cve.dart';
import 'errors.dart';
import 'value.dart';

/// §4.1: "A term's postings are split into blocks of at most 128 documents."
const int kPostingsBlockMax = 128;

/// One document's posting within a block.
final class Posting {
  const Posting(this.docId, this.freq, [this.positions = const []]);

  final int docId;

  /// Term frequency in that document.
  final int freq;

  /// Token positions, present only when the index declares `positions = true`.
  final List<int> positions;

  @override
  String toString() => 'Posting($docId, freq $freq)';
}

/// A postings block, §4.2.
///
/// The layout is a raw byte structure stored as the payload of a CVE `BYTES`
/// value "so that `04-segments.md` §2.2's 'an INLINE cell holds a CVE value'
/// holds without exception and `cryptand dump` can walk any tree without
/// knowing what kind it is. The two-byte cost is the price of one uniform
/// rule."
final class PostingsBlock {
  const PostingsBlock(this.postings, {required this.hasPositions});

  final List<Posting> postings;
  final bool hasPositions;

  static const int version = 1;
  static const int flagHasPositions = 0x01;

  int get firstDoc => postings.first.docId;

  /// The raw block bytes of §4.2 — not yet wrapped in a CVE `BYTES`.
  Uint8List encodeRaw() {
    if (postings.isEmpty) {
      throw const InvalidArgumentException('a postings block cannot be empty');
    }
    if (postings.length > kPostingsBlockMax) {
      throw LimitException(
          'a postings block holds at most $kPostingsBlockMax documents, got '
          '${postings.length} (spec/07-fulltext.md section 4.1)');
    }
    for (var i = 1; i < postings.length; i++) {
      if (postings[i].docId <= postings[i - 1].docId) {
        throw const InvalidArgumentException(
            'document ids inside a block must be strictly increasing');
      }
    }

    final w = ByteWriter(64 + postings.length * 8)
      ..u8(version)
      ..u8(hasPositions ? flagHasPositions : 0)
      ..u16(postings.length)
      ..u64(_zigzagEncode(postings.first.docId));

    // §4.2: "zigzag deltas from the previous doc id". Ids inside a block are
    // strictly increasing so the deltas are positive; zigzag is used anyway
    // "so that a future out-of-order writer is representable rather than
    // undefined".
    for (var i = 1; i < postings.length; i++) {
      w.uvar(_zigzagEncode(postings[i].docId - postings[i - 1].docId));
    }
    for (final p in postings) {
      w.uvar(p.freq);
    }

    if (hasPositions) {
      final pw = ByteWriter(postings.length * 8);
      for (final p in postings) {
        if (p.positions.length != p.freq) {
          throw InvalidArgumentException(
              'document ${p.docId} declares freq ${p.freq} but carries '
              '${p.positions.length} positions');
        }
        var prev = 0;
        for (var i = 0; i < p.positions.length; i++) {
          if (i > 0 && p.positions[i] <= prev) {
            throw InvalidArgumentException(
                'positions within document ${p.docId} must be strictly '
                'increasing');
          }
          pw.uvar(i == 0 ? p.positions[i] : p.positions[i] - prev);
          prev = p.positions[i];
        }
      }
      final pos = pw.takeBytes();
      // §4.2: "Positions are byte-length-prefixed as a group so that a scorer
      // that only needs frequencies can skip them without decoding."
      w
        ..uvar(pos.length)
        ..bytes(pos);
    }
    return w.takeBytes();
  }

  /// The tree value: the raw block wrapped in a CVE `BYTES`.
  Uint8List encode() => encodeValue(CBytes(encodeRaw()));

  static PostingsBlock decodeRaw(Uint8List raw) {
    final r = ByteReader(raw);
    final v = r.u8();
    if (v != version) {
      throw CorruptionException('postings block version $v, expected $version');
    }
    final flags = r.u8();
    final hasPositions = flags & flagHasPositions != 0;
    if (flags & ~flagHasPositions != 0) {
      throw const CorruptionException('reserved postings block flags are set');
    }
    final count = r.u16();
    if (count < 1 || count > kPostingsBlockMax) {
      throw CorruptionException('postings block declares $count documents');
    }

    final docs = <int>[_zigzagDecode(r.u64())];
    for (var i = 1; i < count; i++) {
      docs.add(docs.last + _zigzagDecode(r.uvar()));
    }
    final freqs = [for (var i = 0; i < count; i++) r.uvar()];

    final positions = <List<int>>[];
    if (hasPositions) {
      final len = r.uvar();
      final pr = ByteReader(r.bytesCopy(len));
      for (var i = 0; i < count; i++) {
        final list = <int>[];
        var prev = 0;
        for (var k = 0; k < freqs[i]; k++) {
          final d = pr.uvar();
          prev = k == 0 ? d : prev + d;
          list.add(prev);
        }
        positions.add(list);
      }
    }

    return PostingsBlock([
      for (var i = 0; i < count; i++)
        Posting(docs[i], freqs[i], hasPositions ? positions[i] : const [])
    ], hasPositions: hasPositions);
  }

  static PostingsBlock decode(Uint8List treeValue) =>
      decodeRaw(
          expectValue<CBytes>(decodeValue(treeValue), 'postings block').value);

  /// §4.1's key: `CKE(Array[U32 term_id, NITRITE_ID first_doc_of_block])`.
  ///
  /// "Blocks for one term are therefore contiguous and in document order, and
  /// a posting can be located by seeking directly to a document id — which is
  /// what an intersection of two terms needs."
  static Uint8List keyFor(int termId, int firstDoc) => encodeKey(CArray([
        CInt.of(NumType.u32, termId),
        CNitriteId(firstDoc),
      ]));

  /// Splits a document-ordered posting list into blocks of ≤128.
  static List<PostingsBlock> split(List<Posting> postings,
      {required bool hasPositions}) {
    final out = <PostingsBlock>[];
    for (var i = 0; i < postings.length; i += kPostingsBlockMax) {
      final end = (i + kPostingsBlockMax).clamp(0, postings.length);
      out.add(PostingsBlock(postings.sublist(i, end),
          hasPositions: hasPositions));
    }
    return out;
  }
}

int _zigzagEncode(int v) => (v << 1) ^ (v >> 63);
int _zigzagDecode(int v) => (v >>> 1) ^ -(v & 1);

/// A `term_dict` entry, §1.
final class TermEntry {
  const TermEntry(this.id, this.df, this.ttf);

  final int id;

  /// Document frequency. §1: "both are maintained for scoring and MUST be
  /// accurate after a merge."
  final int df;

  /// Total term frequency.
  final int ttf;

  Uint8List encode() => encodeValue(CDoc({
        'id': CInt.of(NumType.u32, id),
        'df': CInt.of(NumType.u32, df),
        'ttf': CInt.of(NumType.u64, ttf),
      }));

  static TermEntry decode(Uint8List bytes) {
    final d = expectValue<CDoc>(decodeValue(bytes), 'term entry');
    int u(String f) => expectField<CInt>(d, f, 'term entry').magnitude.lo;
    return TermEntry(u('id'), u('df'), u('ttf'));
  }

  @override
  String toString() => 'TermEntry(#$id, df $df, ttf $ttf)';
}
