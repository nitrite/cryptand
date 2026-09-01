/// CRC-32C (Castagnoli), `spec/00-conventions.md` section 6.
///
/// Polynomial 0x1EDC6F41, reflected (0x82F63B78), init 0xFFFFFFFF,
/// final xor 0xFFFFFFFF.
///
/// A note the spec makes and this file repeats because it is load-bearing:
/// **CRC-32C is error detection, never integrity** (`spec/14-security.md`
/// section 9.4). Anyone who edits the file can recompute it.
library;

import 'dart:typed_data';

final Uint32List _table = _buildTable();

Uint32List _buildTable() {
  final t = Uint32List(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? (0x82F63B78 ^ (c >> 1)) : (c >> 1);
    }
    t[i] = c;
  }
  return t;
}

/// CRC-32C over `bytes[start..end)`, returned as an unsigned 32-bit value.
int crc32c(List<int> bytes, [int start = 0, int? end]) {
  final stop = end ?? bytes.length;
  var crc = 0xFFFFFFFF;
  for (var i = start; i < stop; i++) {
    crc = _table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
  }
  return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
}
