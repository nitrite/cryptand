import 'dart:typed_data';

import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/vlog.dart';
import 'package:test/test.dart';

/// F-138: a value-log record length is file data; it is checked before any
/// offset is computed from it.
void main() {
  for (final hostile in [
    [0x00], // 0: shorter than the CRC
    [0x80, 0x80, 0x80, 0x80, 0x08], // 2^31
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01], // 2^64 - 1
  ]) {
    test('F-138: record_len ${hostile.length}-byte uvar', () {
      final seg = VlogSegment(
          id: 1, tier: 0, heatClass: 0, pageSize: 4096, capacity: 4096);
      seg.append(16, Uint8List.fromList([1, 2]), Uint8List(300));
      seg.extent.setRange(VlogSegment.dataOffset,
          VlogSegment.dataOffset + hostile.length, hostile);
      expect(() => seg.scan().toList(), throwsA(isA<CorruptionException>()));
    });
    test('F-138: record_len ${hostile.length}-byte uvar behind a valid pointer',
        () {
      final seg = VlogSegment(
          id: 1, tier: 0, heatClass: 0, pageSize: 4096, capacity: 4096);
      final ptr = seg.append(16, Uint8List.fromList([1, 2]), Uint8List(300))!;
      seg.extent.setRange(VlogSegment.dataOffset,
          VlogSegment.dataOffset + hostile.length, hostile);
      expect(() => seg.read(ptr, (_) {}), throwsA(isA<CorruptionException>()));
    });
  }

  // Dart's uvar returns 2^63..2^64-1 as a negative int; an upper-bound check
  // alone lets it through.
  for (final len in [
    [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], // 2^63
    [0x80, 0x80, 0x80, 0x80, 0x80, 0x20], // 2^40
  ]) {
    test('F-138: a cell suffix length of ${len.length} bytes is corrupt', () {
      final page = Uint8List(4096);
      const base = 40; // PageHeader.size
      final bd = ByteData.view(page.buffer);
      bd.setUint16(base, 1, Endian.little); // cell_count
      bd.setUint16(base + 6, 1, Endian.little); // leaf
      bd.setUint16(base + 16, 100, Endian.little); // cell 0 at base + 100
      page.setRange(base + 100, base + 100 + len.length, len);
      final n = Node(page, 0);
      for (final read in <void Function()>[
        () => n.keyAt(0),
        () => n.compareSuffix(0, Uint8List(4)),
        () => n.recordAt(0),
        () => n.seqAt(0),
      ]) {
        expect(read, throwsA(isA<CorruptionException>()));
      }
    });
  }
}
