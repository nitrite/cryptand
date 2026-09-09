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

/// Slicing-by-8 tables, built once.
///
/// **This was a byte-at-a-time table**, which is the textbook implementation
/// and eight times slower than this one. `spec/00-conventions.md` section 6
/// chose CRC-32C because "it is hardware-accelerated on every current ARM and
/// x86, and because every target language already has it", and Dart has
/// neither an intrinsic nor a CRC in its core library — so the table is what
/// there is, and the width of the table is the whole choice.
///
/// It is not a small cost, because every page carries a checksum over its whole
/// `page_size` bytes and it is computed on every page written. Measured on the
/// cross-language CRUD matrix, the flushes inside a 20 000-document create
/// wrote 13 MB of pages and spent about 50 ms doing it, nearly all of it here.
final List<Uint32List> _tables = _buildTables();

List<Uint32List> _buildTables() {
  final t = List<Uint32List>.generate(8, (_) => Uint32List(256));
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? (0x82F63B78 ^ (c >> 1)) : (c >> 1);
    }
    t[0][i] = c;
  }
  for (var n = 1; n < 8; n++) {
    for (var i = 0; i < 256; i++) {
      final prev = t[n - 1][i];
      t[n][i] = ((prev >> 8) ^ t[0][prev & 0xFF]) & 0xFFFFFFFF;
    }
  }
  return t;
}

/// CRC-32C over `bytes[start..end)`, returned as an unsigned 32-bit value.
int crc32c(List<int> bytes, [int start = 0, int? end]) {
  final stop = end ?? bytes.length;
  final t0 = _tables[0];
  var crc = 0xFFFFFFFF;
  var i = start;
  // Eight bytes at a time. `w0` folds the running CRC in, as the reflected
  // slicing-by-N formulation requires; `w1` is the next four bytes on their own.
  while (stop - i >= 8) {
    final w0 = (bytes[i] |
            (bytes[i + 1] << 8) |
            (bytes[i + 2] << 16) |
            (bytes[i + 3] << 24)) ^
        crc;
    final w1 = bytes[i + 4] |
        (bytes[i + 5] << 8) |
        (bytes[i + 6] << 16) |
        (bytes[i + 7] << 24);
    crc = _tables[7][w0 & 0xFF] ^
        _tables[6][(w0 >> 8) & 0xFF] ^
        _tables[5][(w0 >> 16) & 0xFF] ^
        _tables[4][(w0 >> 24) & 0xFF] ^
        _tables[3][w1 & 0xFF] ^
        _tables[2][(w1 >> 8) & 0xFF] ^
        _tables[1][(w1 >> 16) & 0xFF] ^
        t0[(w1 >> 24) & 0xFF];
    i += 8;
  }
  for (; i < stop; i++) {
    crc = t0[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
  }
  return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
}
