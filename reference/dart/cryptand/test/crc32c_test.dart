import 'dart:convert';
import 'package:cryptand/src/crc32c.dart';
import 'package:test/test.dart';

void main() {
  // The canonical CRC-32C check value, from RFC 3720 appendix B and every
  // other implementation: CRC-32C("123456789") == 0xE3069283.
  test('canonical check value', () {
    expect(crc32c(ascii.encode('123456789')), 0xE3069283);
  });

  test('empty input is zero', () => expect(crc32c(const []), 0));

  // RFC 3720 appendix B vectors: 32 bytes of a repeated value.
  test('RFC 3720 vectors', () {
    expect(crc32c(List.filled(32, 0x00)), 0x8A9136AA);
    expect(crc32c(List.filled(32, 0xFF)), 0x62A8AB43);
    expect(crc32c(List.generate(32, (i) => i)), 0x46DD794E);
    expect(crc32c(List.generate(32, (i) => 31 - i)), 0x113FDB5C);
  });

  test('range arguments select a slice', () {
    final padded = [9, 9, ...ascii.encode('123456789'), 9];
    expect(crc32c(padded, 2, padded.length - 1), 0xE3069283);
  });
}
