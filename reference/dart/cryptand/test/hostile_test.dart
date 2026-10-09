/// `spec/14-security.md` section 9.1 — a decoder fed a hostile file MUST fail
/// with a typed corruption error "rather than an allocation failure, a panic,
/// an abort, or an unbounded recursion".
///
/// Section 9.3 requires structure-aware fuzzing and `fuzz_test.dart` provides
/// it. What random mutation cannot do is *reliably* reach one named 4-byte
/// field: the segment filter's `block_count` is a specific u32 at a specific
/// offset, and 3 000 random mutations over this corpus find it perhaps one
/// time in six. Bugs of that class live at the *boundaries* of a named field,
/// and boundaries are enumerable — so this sweep is deterministic and
/// exhaustive where the fuzzer is random.
///
/// For one page of every `page_type` in the shared corpus, every u32-aligned
/// slot in the 40-byte header and in the first 32 bytes of payload is set to
/// each of six boundary values, the page checksum is repaired (section 9.4:
/// an attacker recomputes it trivially, so leaving it broken would test the
/// CRC and not the decoder), and the file is opened, verified, scanned **and
/// point-read**.
///
/// The point read is not decoration. A scan and a `get` are different
/// decoders, and only `get` consults `04-segments.md` section 2.4's filter, so
/// a harness that only scans cannot reach the filter header at all.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

const List<int> boundaries = [0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF];

String get corpusFile {
  final here = Directory.current.path;
  return '$here/../../conformance/files/v1.0-core.cryptand';
}

/// Opens, verifies, scans and point-reads — the four decoders a hostile file
/// reaches. Throws a [CryptandException] for any typed refusal, which is a
/// pass; anything else escaping is the failure this test exists to find.
void exercise(String path) {
  final db = DatabaseFile.open(path);
  db.engine.verifyStructure();
  for (final (_, d) in db.catalog.all) {
    final rows = db.engine.scanTree(d.treeId).take(8).toList();
    for (final e in rows) {
      db.engine.get(d.treeId, decodeKey(e.cke));
    }
  }
}

void main() {
  final original = File(corpusFile).existsSync()
      ? File(corpusFile).readAsBytesSync()
      : null;

  if (original == null) {
    test('the conformance corpus is present', () {
      fail('$corpusFile does not exist; run '
          '`dart run tool/generate_corpus.dart`');
    });
    return;
  }

  test(
      'every u32 field at every boundary yields a typed error and never a crash',
      () {
    final sb = Superblock.tryDecode(Uint8List.sublistView(original, 0, 4096));
    if (sb == null) fail('slot 0 of the corpus does not decode');
    final pageSize = sb.pageSize;
    final pages = original.length ~/ pageSize;

    // One page of each `page_type` present. The decoder is per type, not per
    // page, so a second page of the same type re-tests the same code.
    final byType = <int, int>{};
    for (var p = 2; p < pages; p++) {
      final at = p * pageSize;
      final page = Uint8List.sublistView(original, at, at + pageSize);
      int type;
      try {
        type = PageHeader.read(page).pageType;
      } on CryptandException {
        continue;
      }
      if (type == PageType.free) continue;
      byType.putIfAbsent(type, () => p);
    }
    expect(byType.length, greaterThanOrEqualTo(4),
        reason: 'the corpus should cover several page types, '
            'saw ${byType.keys.toList()}');

    // Every u32-aligned slot in the header, and in the first 32 bytes of
    // payload — where every count and length field of every page type lives.
    final slots = <int>[
      for (var i = 0; i < PageHeader.size ~/ 4 + 8; i++) i * 4
    ];

    final tmp = File('${Directory.systemTemp.path}/cryptand-sweep-$pid.cryptand');
    var cases = 0, refused = 0, accepted = 0;

    for (final entry in byType.entries) {
      final page = entry.value;
      for (final slot in slots) {
        for (final value in boundaries) {
          final b = Uint8List.fromList(original);
          final at = page * pageSize + slot;
          if (at + 4 > b.length) continue;
          ByteData.sublistView(b).setUint32(at, value, Endian.little);

          // Repair the checksum, so the decoder is what refuses the file.
          final off = page * pageSize;
          final img = Uint8List.sublistView(b, off, off + pageSize);
          ByteData.sublistView(img).setUint32(
              0,
              crc32c(img, 4, PageHeader.checksumEnd(img, img[4])),
              Endian.little);

          tmp.writeAsBytesSync(b, flush: true);
          cases++;
          try {
            exercise(tmp.path);
            accepted++;
          } on CryptandException {
            // A named, typed refusal. This is the contract.
            refused++;
          }
          // Anything else — RangeError, StateError, OutOfMemory — escapes and
          // fails the test, which is section 9.1's requirement.
        }
      }
    }
    if (tmp.existsSync()) tmp.deleteSync();

    print('field-boundary sweep: $cases cases over ${byType.length} page '
        'types — $refused refused with a named error, $accepted read cleanly, '
        '0 uncaught');
    expect(cases, greaterThan(200), reason: 'the sweep did not run');
    // A control: if nothing was ever refused the sweep reaches no decoder and
    // would pass against a reader that validates nothing.
    expect(refused, greaterThan(0),
        reason: 'no mutation was refused — the sweep reaches no decoder');
  }, timeout: const Timeout(Duration(minutes: 10)));

  // PLAN M3.5: every minimized fuzz file (page CRCs already repaired) is a
  // typed refusal or a clean read in Dart too. F-107: a segment ref asked for
  // a 66 GB extent.
  test('every fuzz-regress file is refused or read', () {
    final dir = Directory('${Directory.current.path}/../../conformance/files/fuzz-regress');
    final files = dir.listSync().whereType<File>().toList();
    expect(files, isNotEmpty);
    for (final f in files) {
      try {
        exercise(f.path);
      } on CryptandException {
        // A named, typed refusal.
      }
    }
  });
}
