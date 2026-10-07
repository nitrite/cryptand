/// Generates the conformance vectors of `spec/11-conformance.md` section 6 and
/// `spec/14-security.md` section 13.
///
///     dart run tool/generate_vectors.dart
///
/// Output goes to `../../conformance/vectors/`, one JSON file per group.
/// `test/conformance_test.dart` reads them back and checks every assertion, so
/// the vectors are self-verifying and a regression in either direction fails
/// the suite.
///
/// The vectors are the contract. `spec/11-conformance.md` section 7:
/// "Conformance is defined as passing the vectors, not as matching the
/// reference implementation's source." Where this generator and the spec
/// disagree, the spec wins and this generator is wrong.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/cow.dart';
import 'package:cryptand/src/crc32c.dart';
import 'package:cryptand/src/lz4.dart';
import 'package:cryptand/src/analyzer.dart';
import 'package:cryptand/src/argon2.dart';
import 'package:cryptand/src/catalog.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/index.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/security.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

import '../test/torture.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// A stable, language-neutral rendering of a value, so another SDK can build
/// the same input without sharing this code.
Map<String, Object?> describe(CValue v) => switch (v) {
      CNull() => {'t': 'null'},
      CBool() => {'t': 'bool', 'v': v.value},
      CInt() => {
          't': 'int',
          'w': v.type.name,
          'v': (v.negative ? '-' : '') + v.magnitude.toBigInt().toString(),
        },
      CFloat() => {
          't': 'float',
          'w': v.type.name,
          // Bits, not a decimal literal: a decimal round trip through another
          // language's parser is exactly the kind of drift this format exists
          // to remove.
          'bits': v.type == NumType.f64
              ? hex((ByteData(8)..setFloat64(0, v.value)).buffer.asUint8List())
              : hex((ByteData(4)..setFloat32(0, v.value)).buffer.asUint8List()),
        },
      CStr() => {'t': 'str', 'utf8': hex(encodeUtf8Strict(v.value))},
      CBytes() => {'t': 'bytes', 'v': hex(v.value)},
      CChar() => {'t': 'char', 'v': v.scalar},
      CTimestamp() => {'t': 'timestamp', 'millis': v.millis},
      CTimestampNs() => {'t': 'timestamp_ns', 'secs': v.secs, 'nanos': v.nanos},
      CZoned() => {'t': 'zoned', 'millis': v.millis, 'zone': v.zoneId},
      CDate() => {'t': 'date', 'days': v.days},
      CTime() => {'t': 'time', 'nanos': v.nanos},
      CDuration() => {'t': 'duration', 'secs': v.secs, 'nanos': v.nanos},
      CUuid() => {'t': 'uuid', 'v': hex(v.bytes)},
      CNitriteId() => {'t': 'nitrite_id', 'v': v.id.toString()},
      CRegex() => {'t': 'regex', 'pattern': v.pattern, 'flags': v.flags},
      CArray() => {'t': 'array', 'items': v.items.map(describe).toList()},
      CDec128() => {'t': 'dec128', 'v': hex(v.bytes)},
      CVector() => {
          't': 'vector',
          'dtype': v.dtype.name,
          'dim': v.dim,
          'f32': v.f32Values?.toList(),
        },
      CGeometry() => {'t': 'geometry', 'wkb': hex(v.wkb)},
      COpaque() => {
          't': 'opaque',
          'origin': v.origin,
          'type_name': v.typeName,
          'data': hex(v.data),
        },
      CMap() => {
          't': 'map',
          'entries': v.entries
              .map((e) => {'k': describe(e.$1), 'v': describe(e.$2)})
              .toList(),
        },
      CDoc() => {
          't': 'doc',
          'fields': v.fields.map((k, x) => MapEntry(k, describe(x))),
        },
      CBlobRef() => {
          't': 'blob_ref',
          'start_page': v.startPage,
          'byte_len': v.byteLen,
          'crc32c': v.crc32c
        },
      COverflowRef() => {
          't': 'overflow_ref',
          'inline': hex(v.inline),
          'next_page': v.nextPage
        },
      CVlogRef() => {
          't': 'vlog_ref',
          'segment_id': v.segmentId,
          'offset': v.offset,
          'len': v.len
        },
      CUnknown() => {
          't': 'unknown',
          'tag': v.unknownTag,
          'payload': hex(v.payload)
        },
    };

void write(String dir, String name, Object body) {
  final f = File('$dir/$name.json');
  f.parent.createSync(recursive: true);
  f.writeAsStringSync('${const JsonEncoder.withIndent('  ').convert(body)}\n');
  stdout.writeln('  ${f.path.padRight(56)} ${f.lengthSync() ~/ 1024} KiB');
}

const header = {
  'format': 'Cryptand File Format',
  'format_version': '1.0',
  'generator': 'cryptand-dart/0.1.0-phase1',
  'note': 'The spec is normative. Where a vector and spec/ disagree, the spec '
      'wins and the vector is wrong (spec/11-conformance.md section 7).',
};

void main(List<String> args) {
  final root = args.isNotEmpty ? args.first : '../../conformance/vectors';
  stdout.writeln('Generating conformance vectors into $root');
  stdout.writeln('');
  _cke(root);
  _numbers(root);
  _cve(root);
  _strings(root);
  _documents(root);
  _container(root);
  _codec(root);
  _filter(root);
  _security(root);
  _index(root);
  _indexEntries(root);
  _catalog(root);
  _analyzer(root);
  stdout.writeln('');
  stdout.writeln('Done. Run `dart test test/conformance_test.dart` to verify.');
}

void _cke(String root) {
  final cases = <Map<String, Object?>>[];
  void add(CValue v, String note) => cases.add(
      {'value': describe(v), 'cke': hex(encodeKey(v)), 'note': note});

  add(const CNull(), 'spec section 9 worked example');
  add(const CBool(false), 'FALSE < TRUE, section 8 rule 9');
  add(const CBool(true), 'spec section 9 worked example');
  add(CInt.i32(0), 'zero has an empty ordering region');
  add(CInt.i32(5), 'spec section 9 worked example');
  add(CFloat.f64(5.0), 'same ordering region as I32(5), type code 0x0B');
  add(CInt.i32(-5), 'negatives are the complemented body');
  add(CInt.i32(-9), 'larger magnitude sorts lower');
  add(const CStr('ab'), 'spec section 9 worked example');
  add(const CStr('abc'), 'a prefix sorts before its extension');
  add(const CStr('a\u0000b'), 'an embedded NUL escapes as 00 01');
  add(const CStr(''), 'the empty string is the terminator alone');
  add(const CNitriteId(1), 'spec section 9 worked example');
  add(const CNitriteId(-1), 'the sign bit is flipped so i64 sorts unsigned');
  add(const CNitriteId(-0x8000000000000000), 'i64 minimum');
  add(const CNitriteId(0x7FFFFFFFFFFFFFFF), 'i64 maximum');
  add(CArray([const CStr('ab'), const CNitriteId(1)]),
      'spec section 9 worked example: a non-unique index key');
  add(CArray([]), 'ELEM_END alone');
  add(const CTimestamp(1000), 'one instant subclass');
  add(CTimestampNs(1, 0), 'byte-identical to TIMESTAMP(1000)');
  add(const CTimestamp(2000), 'sorts above TIMESTAMP_NS(1, 0)');
  add(const CTimestamp(-1), 'floor division: secs -1, nanos 999000000');
  add(const CZoned(1000, 'Asia/Kolkata'), 'the zone is not part of the key');
  add(const CDate(0), 'epoch day');
  add(const CDate(-719162), 'year 1 AD, exercising the i32 sign');
  add(CTime(86399999999999), 'one nanosecond before midnight');
  add(CDuration(-5, 500000000), 'a negative duration with nanos');
  add(CUuid(List.generate(16, (i) => i)), 'RFC 4122 network byte order');
  add(CChar(0x1F408), 'a supplementary-plane scalar');
  add(CBytes([0, 0, 1, 0xFF]), 'BYTES uses the same escape as STRING');

  write(root, 'cke/values', {
    ...header,
    'chapter': 'spec/03-key-encoding.md',
    'cases': cases,
    'rejects': [
      {'cke': 'b0', 'why': 'unknown group tag'},
      {'cke': '6061', 'why': 'truncated body'},
      {'cke': '606100020000', 'why': 'non-canonical escape'},
      {'cke': '300340027f000002', 'why': 'mantissa first byte below 0x80'},
      {'cke': '3003400200000002', 'why': 'empty mantissa'},
      {'cke': '30034002a000000d', 'why': 'type code 0x0D is reserved'},
      {'cke': '4002800000000000000100000000',
        'why': 'temporal subclass 0x02 is reserved'},
      {'cke': '0000', 'why': 'trailing bytes after a complete key'},
    ],
  });
}

void _numbers(String root) {
  final all = <CValue>[...torturedIntegers(), ...torturedFloats()];
  final sorted = [...all]
    ..sort((a, b) => compareKeys(encodeKey(a), encodeKey(b)));
  write(root, 'numbers/torture', {
    ...header,
    'chapter': 'spec/03-key-encoding.md section 4',
    'invariant': 'CKE order refines logical order: a non-zero comparison never '
        'inverts, and numerically equal values differ only in the trailing '
        'type code and are adjacent (section 1).',
    'count': all.length,
    'entries': [
      for (final v in all) {'value': describe(v), 'cke': hex(encodeKey(v))}
    ],
    'sorted_by_cke': [for (final v in sorted) hex(encodeKey(v))],
    'lossy_decodings': [
      {
        'why': 'negative zero decodes as positive zero (section 7)',
        'input': describe(CFloat.f64(-0.0)),
        'cke': hex(encodeKey(CFloat.f64(-0.0))),
        'decodes_to': describe(CFloat.f64(0.0)),
      },
      {
        'why': 'a NaN payload is not preserved (section 7)',
        'cke': hex(encodeKey(CFloat.f64(double.nan))),
        'decodes_to': describe(CFloat.f64(double.nan)),
      },
      {
        'why': 'every instant-valued tag decodes as TIMESTAMP_NS (section 7)',
        'input': describe(const CTimestamp(1500)),
        'cke': hex(encodeKey(const CTimestamp(1500))),
        'decodes_to': describe(CTimestampNs(1, 500000000)),
      },
    ],
  });
}

void _cve(String root) {
  final cases = <Map<String, Object?>>[];
  void add(CValue v, String note) => cases.add(
      {'value': describe(v), 'cve': hex(encodeValue(v)), 'note': note});

  add(const CNull(), 'one byte');
  add(const CBool(true), 'one byte');
  add(CInt.varInt(1), 'INT_VAR is the canonical compact form');
  add(CInt.varInt(-1), 'zigzag');
  add(CInt.i64(1), 'fixed width when the declared width matters');
  add(intOf(NumType.i128, BigInt.two.pow(127) - BigInt.one), 'i128 maximum');
  add(intOf(NumType.i128, -BigInt.two.pow(127)), 'i128 minimum');
  add(intOf(NumType.u128, BigInt.two.pow(128) - BigInt.one), 'u128 maximum');
  add(CFloat.f64(double.nan), 'NaN canonicalized on encode');
  add(const CStr('Backerei-Strasse 12'), 'UTF-8');
  add(CBytes([0, 255]), 'raw bytes');
  add(const CNitriteId(-0x8000000000000000), 'signed i64, exchanged as such');
  add(CArray([const CNull(), CInt.varInt(7)]), 'byte_len then count');
  add(
      CMap([
        (CInt.i32(1), const CStr('one')),
        (CInt.i32(2), const CStr('two')),
      ]),
      'entries sorted by CKE(key)');
  add(CVector.f32([1.5, -2.25]), 'a first-class vector');
  add(COpaque('java', 'org.dizitart.Thing', [0xCA, 0xFE]),
      'the interchange escape hatch');
  add(CUnknown(0x90, [1, 2, 3]),
      'a reserved tag: length-prefixed so it can be preserved (section 1.1)');

  write(root, 'cve/values', {
    ...header,
    'chapter': 'spec/02-value-encoding.md',
    'cases': cases,
    'rejects': [
      {'cve': '13ffffff7f', 'why': 'BYTES length past the buffer'},
      {'cve': '20ffffff7f', 'why': 'ARRAY length past the buffer'},
      {'cve': '2002e807', 'why': 'ARRAY count exceeds its own byte span'},
      {'cve': '0000', 'why': 'trailing bytes'},
      {'cve': '1d', 'why': 'a reserved tag with no length prefix'},
      {'cve': '1100d80000', 'why': 'CHAR is not a Unicode scalar value'},
    ],
  });
}

void _strings(String root) {
  final cases = <Map<String, Object?>>[];
  void add(String s, String note) => cases.add({
        'utf8': hex(encodeUtf8Strict(s)),
        'cke': hex(encodeKey(CStr(s))),
        'cve': hex(encodeValue(CStr(s))),
        'note': note,
      });
  add('', 'empty');
  add('a', 'ASCII');
  add('ab', 'prefix of the next');
  add('abc', 'extends the previous, so it sorts after');
  add('a\u0000b', 'embedded NUL: escapes as 00 01, sorts between a and ab');
  add('\u00e9', 'NFC: e-acute as one code point');
  add('e\u0301', 'NFD: e + combining acute. The format applies NO '
      'normalization, so this is a DIFFERENT key from the NFC form.');
  add('\u00df', 'sharp s: simple lowercase, not full case folding');
  add('\u{1F408}', 'supplementary plane, 4 UTF-8 bytes');
  add('\u{10FFFF}', 'the last scalar value');
  write(root, 'strings/cases', {
    ...header,
    'chapter': 'spec/00-conventions.md section 4, '
        'spec/03-key-encoding.md section 3.1',
    'rule': 'Strings compare by UTF-8 byte order. No locale, no case folding, '
        'no normalization. NFC and NFD forms of the same text are different '
        'keys.',
    'cases': cases,
    'rejects_on_write': [
      {'why': 'unpaired high surrogate', 'utf16': 'd800'},
      {'why': 'unpaired low surrogate', 'utf16': 'dc00'},
    ],
    'rejects_on_read': [
      {'utf8': 'c328', 'why': 'ill-formed UTF-8, MUST NOT become U+FFFD'},
      {'utf8': 'eda080', 'why': 'CESU-8 surrogate'},
    ],
  });
}

void _documents(String root) {
  final dict = NameDict.withReservedFields()
    ..intern('alpha')
    ..intern('zulu');
  final doc = CDoc({
    '_id': const CNitriteId(7),
    'zulu': const CStr('z'),
    'alpha': CInt.varInt(1),
    'mango': const CStr('inline name, not in the dictionary'),
  });
  final w = ByteWriter();
  writeDoc(w, doc, dict: dict);
  final noDict = ByteWriter();
  writeDoc(noDict, doc);
  final withUnknown = CArray([
    CInt.varInt(1),
    CUnknown(0xC5, [7, 7, 7]),
    const CStr('after'),
  ]);

  write(root, 'documents/cases', {
    ...header,
    'chapter': 'spec/02-value-encoding.md section 5',
    'dictionary': [
      for (final (id, name) in dict.entries) {'name_id': id, 'name': name}
    ],
    'cases': [
      {
        'note': 'field table sorted by resolved name bytes, mixed dictionary '
            'and inline names',
        'value': describe(doc),
        'cve_with_dictionary': hex(w.takeBytes()),
        'cve_without_dictionary': hex(noDict.takeBytes()),
        'field_order': ['_id', 'alpha', 'mango', 'zulu'],
      },
      {
        'note': 'an unknown tag inside an array survives, which needs the '
            'length prefix of section 1.1',
        'value': describe(withUnknown),
        'cve': hex(encodeValue(withUnknown)),
      },
    ],
    'reserved_field_ids': {
      '_id': 1,
      '_revision': 2,
      '_modified': 3,
      '_source': 4,
      '_type': 5,
    },
  });
}

void _container(String root) {
  final sb = Superblock(
    pageSize: 4096,
    commitId: 1,
    profile: Profile.mobile,
    // `12-profiles.md` section 1's row. Now 0 in every profile, and measured
    // rather than assumed: a page is a fixed-size slot, so a compressed page
    // occupies the same slot and is written with the same page_size-byte
    // write. See `01-container.md` section 7 for the numbers.
    pageCodec: Profile.mobile.pageCodec,
    databaseUuid: Uint8List.fromList(List.generate(16, (i) => i)),
    createdUtcMs: 1767225600000,
    modifiedUtcMs: 1767225600000,
    writerId: 'cryptand-vectors/1.0',
  );
  final page = Uint8List(4096);
  const PageHeader(
    pageType: PageType.btreeLeaf,
    treeId: 17,
    commitId: 1,
    payloadLen: 4056,
  ).writeInto(page);

  write(root, 'container/layout', {
    ...header,
    'chapter': 'spec/01-container.md sections 2 and 3',
    'superblock': {
      'note': 'mobile profile, commit 1, uuid 000102..0f',
      'bytes': hex(sb.encode()),
      'field_offsets': {
        'magic': Sb.magic,
        'version_major': Sb.versionMajor,
        'page_size_log2': Sb.pageSizeLog2,
        'commit_id': Sb.commitId,
        'vlog_min': Sb.vlogMin,
        'profile': Sb.profile,
        'next_nonce': Sb.nextNonce,
        'sb_mac': Sb.sbMac,
        'keyslots': Sb.keyslots,
        'checksum': Sb.checksum,
      },
      'expected': {
        'vlog_min': 1024,
        'page_size': 4096,
        'page_codec': 0,
        'rule': 'vlog_min MUST be <= page_size / 4 '
            '(spec/00-conventions.md section 8)',
        'codec_rule': 'page_codec is 0 on every profile: a page is a '
            'fixed-size slot, so compressing one occupies the same slot and '
            'writes the same page_size bytes -- measured identical in bytes '
            'to device, page count and file size. A reader MUST still decode '
            'a compressed page (spec/01-container.md section 7)',
      },
    },
    'page_header': {
      'size': PageHeader.size,
      'bytes': hex(Uint8List.sublistView(page, 0, PageHeader.size)),
      'field_offsets': {
        'checksum': 0,
        'page_type': 4,
        'flags': 5,
        'codec_or_reserved': 6,
        'tree_id': 8,
        'extent_pages': 12,
        'commit_id': 16,
        'payload_len': 24,
        'stored_len': 28,
        'nonce': 32,
      },
      // Defect 59. This note lived only in the committed JSON for three days,
      // hand-edited after the file was generated -- so the next `dart run
      // tool/generate_vectors.dart` silently reverted offset 28 to `reserved`
      // and dropped the note. A generated file that is hand-edited stops being
      // generated; the edit belongs here.
      'stored_len_note': '14-security.md section 5.2. The reserved u32 at '
          'offset 28 carries the number of payload bytes actually stored on '
          'the page, after compression and after encryption; 0 means "same as '
          'payload_len". 01-container.md section 3 defines payload_len as the '
          'uncompressed, unencrypted length while 14-security.md section 5.2 '
          'says the AEAD tag is inside payload_len -- the two cannot both '
          'hold, and a decryptor needs the exact stored length while a '
          'decompressor needs the plaintext length, so both are kept.',
    },
    'crc32c': [
      {
        'input': hex(utf8.encode('123456789')),
        'crc': crc32c(utf8.encode('123456789'))
      },
      {'input': '', 'crc': crc32c(const [])},
    ],
  });
}

/// `spec/01-container.md` section 7 -- LZ4 block format, codec id 1.
///
/// **Only the decoder is normative.** Any conforming LZ4 block decompresses to
/// the same output whatever produced it, so a reader is checked against these
/// blocks and a *writer* is not: three implementations may compress the same
/// page to three different lengths and still read each other's files. That is
/// the same freedom `08-spatial.md` section 2.3 gives the R-tree split
/// algorithm, and for the same reason.
///
/// The blocks below were produced by three independent compressors -- this one,
/// Rust's `lz4_flex` and the Java implementation -- and every one of the three
/// decoders reads all of them. A vector set generated by one compressor would
/// only prove that its own decoder is its own inverse.
void _codec(String root) {
  final cases = <Map<String, Object?>>[];
  void add(String note, Uint8List plain) {
    cases.add({
      'note': note,
      'plain': hex(plain),
      'plain_len': plain.length,
      'lz4': hex(lz4Compress(plain)),
    });
  }

  Uint8List filled(int n, int b) => Uint8List(n)..fillRange(0, n, b);
  Uint8List gen(int n, int Function(int) f) =>
      Uint8List.fromList(List.generate(n, f));

  add('empty', Uint8List(0));
  add('one byte', Uint8List.fromList([0x41]));
  add('four bytes, the minimum match length', filled(4, 0x41));
  // 11, 12 and 13 straddle the end-of-block guard: the last five bytes are
  // always literals and the last match must start at least twelve bytes before
  // the end, so an off-by-one in a compressor's limit lands exactly here.
  add('eleven bytes, just below the end-of-block guard', filled(11, 0x41));
  add('twelve bytes, at the end-of-block guard', filled(12, 0x41));
  add('thirteen bytes, just above it', filled(13, 0x41));
  add('a long run, which is an overlapping match', filled(4056, 0x41));
  add('a short period, so every position matches', gen(4056, (i) => i % 7));
  add('long runs of a few values', gen(4056, (i) => (i ~/ 64) % 3));
  add('incompressible: section 7 stores this uncompressed',
      gen(4056, (i) => (i * 2654435761) >>> 24 & 0xFF));
  final b = BytesBuilder();
  var i = 0;
  while (b.length < 4056) {
    b.add(Uint8List.fromList(
        '{"_id":${i++},"name":"widget","kind":"tool","qty":7}'.codeUnits));
  }
  add('document-shaped, which is what a page actually holds',
      Uint8List.sublistView(b.toBytes(), 0, 4056));

  write(root, 'codec/lz4', {
    ...header,
    'chapter': 'spec/01-container.md section 7',
    'note': 'Only the decoder is normative: a reader MUST decode every block '
        'here to its recorded plaintext. A writer is NOT required to reproduce '
        'these bytes -- any conforming LZ4 block is legal, and three '
        'implementations compress the same page to three different lengths.',
    'threshold': {
      'rule': 'a page is stored compressed only if compression saves >= 12.5 % '
          'of the payload',
      'formula': 'compressed + raw / 8 <= raw',
      'cases': [
        {'raw': 4096, 'compressed': 3584, 'worth': true},
        {'raw': 4096, 'compressed': 3585, 'worth': false},
        {'raw': 4096, 'compressed': 4096, 'worth': false},
      ],
    },
    'refuse': {
      'note': 'Every block here MUST be refused, never decoded to a short or '
          'oversized buffer (spec/14-security.md section 9).',
      'cases': [
        {'lz4': 'f0ff', 'plain_len': 4096, 'why': 'literals overrun the source'},
        {'lz4': '50010203', 'plain_len': 2, 'why': 'literals overrun the output'},
        {'lz4': '0f100000', 'plain_len': 64, 'why': 'match offset before the output'},
        {'lz4': '10410000', 'plain_len': 64, 'why': 'match offset of zero'},
        {
          'lz4': '1f410100ffff00',
          'plain_len': 8,
          'why': 'match length overruns the output',
        },
      ],
    },
    'cases': cases,
  });
}

void _filter(String root) {
  final keys = [
    for (var i = 0; i < 1000; i++)
      userKeyPrefix(17, encodeKey(CNitriteId(1000000 + i)))
  ];
  final f = BlockedBloom.build(keys, bitsPerKey: 16, distinctKeys: keys.length);
  write(root, 'filter/blocked_bloom', {
    ...header,
    'chapter': 'spec/04-segments.md section 2.4',
    'reproduce': {
      'note': 'keys are userKeyPrefix(17, CKE(NitriteId(1000000 + i))) for i '
          'in [0, key_count)',
      'tree_id': 17,
      'first_id': 1000000,
      'key_count': keys.length,
      'bits_per_key': 16,
    },
    'hash': 'CFH-64, spec/04-segments.md section 2.4.1 -- specified in full in '
        'the spec, twenty lines of wrapping multiply, xor, shift and rotate. '
        'It replaced XXH3-64 during phase 1 of the reference implementation.',
    'structure': {
      'block_bits': kBlockBits,
      'probes_for_bits_per_key': {
        '10': probesFor(10),
        '12': probesFor(12),
        '14': probesFor(14),
        '16': probesFor(16),
      },
      'block_count_examples': {
        '32 keys at 16 bits': blockCountFor(32, 16),
        '33 keys at 16 bits': blockCountFor(33, 16),
        '1000 keys at 16 bits': blockCountFor(1000, 16),
      },
    },
    'cfh64_vectors': {
      for (final k in <String>['', 'a', 'abc', '12345678', '123456789',
        'the quick brown fox jumps over the lazy dog'])
        hex(encodeUtf8Strict(k)):
            BigInt.from(cfh64(encodeUtf8Strict(k))).toUnsigned(64).toRadixString(16)
    },
    'measured_false_positive_rate': {
      '10': '1.67%',
      '12': '0.87%',
      '14': '0.53%',
      '16': '0.22% - 0.24% across five key shapes',
      'method': '200k keys inserted, 2M absent keys probed',
      'note': 'blocked Bloom. The earlier 0.04% and 1% in the spec were '
          'classic-Bloom figures for the same bits per key; blocking costs '
          'roughly 7x that, and the read tail survives it (04 section 4.1).',
    },
    'blocks': hex(f.blocks),
    'header_note': 'header_bytes is the WHOLE 20-byte filter page header of '
        'section 2.4 -- u32 magic, u32 block_count, u16 bits_per_key, '
        'u16 probes, u64 distinct_keys -- and the blocks begin at byte 20.',
    'header_bytes': hex(Uint8List.sublistView(f.encodePayload(), 0, 20)),
  });
}

void _security(String root) {
  final master = Uint8List.fromList(List.generate(32, (i) => i));
  final uuid = Uint8List.fromList(List.generate(16, (i) => 0xA0 + i));
  write(root, 'security/derivation', {
    ...header,
    'chapter': 'spec/14-security.md sections 3.4 and 4.2',
    'hkdf_rfc5869_case1': {
      'ikm': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      'salt': '000102030405060708090a0b0c',
      'info': 'f0f1f2f3f4f5f6f7f8f9',
      'length': 42,
      'okm': hex(hkdf(
          Uint8List.fromList(List.filled(22, 0x0b)),
          Uint8List.fromList(List.generate(13, (i) => i)),
          Uint8List.fromList(List.generate(10, (i) => 0xf0 + i)),
          42)),
    },
    'subkeys': {
      'master_key': hex(master),
      'database_uuid': hex(uuid),
      'info_prefix': 'cryptand/v1/',
      'page': hex(deriveSubkey(master, uuid, Purpose.page)),
      'vlog': hex(deriveSubkey(master, uuid, Purpose.vlog)),
      'sbmac': hex(deriveSubkey(master, uuid, Purpose.sbMac)),
    },
    'nonces': [
      {
        'domain': NonceDomain.page,
        'counter': 1,
        'object_id': 2,
        'offset': 0,
        'nonce': hex(buildNonce(NonceDomain.page, 1, 2, 0)),
      },
      {
        'domain': NonceDomain.vlogRecord,
        'counter': 72623859790382856,
        'object_id': 1229782938247303441,
        'offset': 72057594037927935,
        'nonce': hex(buildNonce(NonceDomain.vlogRecord, 72623859790382856,
            1229782938247303441, 72057594037927935)),
      },
    ],
    'nonce_watermark': {
      'gap': kNonceGap,
      'rule': 'On open, publish persisted + gap DURABLY before allocating '
          'anything; allocate upward from persisted; never reach the published '
          'value without publishing again.',
    },
    'keyslot': {
      'size': Keyslot.size,
      'count': Sb.keyslotCount,
      'offset_in_superblock': Sb.keyslots,
      'field_offsets': {
        'state': 0,
        'kdf': 1,
        'label_len': 2,
        't_cost': 4,
        'm_cost_kib': 8,
        'parallelism': 12,
        'salt': 16,
        'wrap_nonce': 48,
        'wrapped_key': 72,
        'wrap_tag': 104,
        'label': 120,
      },
      'wrap_aad': 'database_uuid || slot_index:u8',
    },
    'argon2id': {
      'note': 'RFC 9106 section 5.3, reproduced by this implementation. '
          'Carried here so another SDK checks its KDF against the same bytes '
          'rather than against this implementation.',
      'version': kArgon2Version,
      'type': 'Argon2id (y = 2)',
      'params': {
        'memory_kib': 32,
        'passes': 3,
        'parallelism': 4,
        'tag_length': 32,
      },
      'password': hex(Uint8List(32)..fillRange(0, 32, 0x01)),
      'salt': hex(Uint8List(16)..fillRange(0, 16, 0x02)),
      'secret': hex(Uint8List(8)..fillRange(0, 8, 0x03)),
      'associated_data': hex(Uint8List(12)..fillRange(0, 12, 0x04)),
      'h0': hex(_rfc9106.h0),
      'tag': hex(_rfc9106.tag),
    },
    'profile_costs': {
      'note': 'spec/14-security.md section 3.2. Present so an SDK can check '
          'it derives the same KEK at each profile cost, and so the numbers '
          'have one machine-readable home.',
      'mobile': {'t_cost': 3, 'm_cost_kib': 65536, 'parallelism': 1},
      'tablet': {'t_cost': 3, 'm_cost_kib': 131072, 'parallelism': 2},
      'desktop': {'t_cost': 4, 'm_cost_kib': 262144, 'parallelism': 4},
      'server': {'t_cost': 4, 'm_cost_kib': 262144, 'parallelism': 4},
      'writer_floor': {'t_cost': 2, 'm_cost_kib': 16384, 'parallelism': 1},
    },
    'not_implemented': <String>[],
  });
}

/// RFC 9106 section 5.3, computed once.
final _rfc9106 = argon2id(
  password: Uint8List(32)..fillRange(0, 32, 0x01),
  salt: Uint8List(16)..fillRange(0, 16, 0x02),
  secret: Uint8List(8)..fillRange(0, 8, 0x03),
  associatedData: Uint8List(12)..fillRange(0, 12, 0x04),
  memoryKiB: 32,
  passes: 3,
  parallelism: 4,
  tagLength: 32,
);

void _index(String root) {
  final entries = [
    for (final (v, id) in <(CValue, int)>[
      (const CStr('red'), 7),
      (const CStr('blue'), 7),
      (CInt.i32(5), 3),
      (CFloat.f64(5.0), 4),
      (const CNull(), 9),
    ])
      {
        'indexed_value': describe(v),
        'nitrite_id': id,
        'key': hex(encodeKey(CArray([v, CNitriteId(id)]))),
      }
  ];
  write(root, 'index/layout', {
    ...header,
    'chapter': 'spec/06-indexes.md',
    'layout': 'key = CKE(Array[v1..vk, NitriteId]), value = EMPTY',
    'entries': entries,
    'range_construction': {
      'rule': 'Numeric bounds MUST be built from N(v), never CKE(v). '
          'spec/03-key-encoding.md section 8.2.',
      'eq_5_any_numeric_type': {
        'lower': hex(KeyRange.eqNumeric(CInt.i32(5)).lower),
        'upper': hex(KeyRange.eqNumeric(CInt.i32(5)).upper!),
        'contains': [
          hex(encodeKey(CInt.of(NumType.i8, 5))),
          hex(encodeKey(CInt.i32(5))),
          hex(encodeKey(CFloat.f64(5.0))),
          hex(encodeKey(intOf(NumType.u128, BigInt.from(5)))),
        ],
      },
      'array_prefix_numeric_5': hex(Keys.arrayPrefixNumeric([CInt.i32(5)])),
      'starts_with_abc': {
        'lower': hex(KeyRange.startsWith('abc').lower),
        'upper': hex(KeyRange.startsWith('abc').upper!),
      },
    },
  });
}


/// `spec/06-indexes.md` sections 3-5: which entries a *document* produces.
///
/// The layout vector above pins the key encoding; this one pins the
/// derivation, which is where the three SDKs differ most today — array
/// explosion, the null/absent/sparse table, the cartesian product cap, and the
/// only escaping in the format.
void _indexEntries(String root) {
  CDoc d(Map<String, CValue> f) => CDoc(f);

  final cases = <Map<String, Object?>>[];
  void add(String note, IndexDescriptor idx, CDoc doc, CValue id) {
    cases.add({
      'note': note,
      'fields': idx.fields,
      'index_type': idx.indexType,
      'sparse': idx.sparse,
      'document': describe(doc),
      'nitrite_id': describe(id),
      'keys': [for (final k in indexKeysFor(idx, doc, id)) hex(k)],
    });
  }

  const single = IndexDescriptor(
      indexType: IndexType.nonUnique, dataTree: 20, fields: ['tags']);
  const nested = IndexDescriptor(
      indexType: IndexType.nonUnique,
      dataTree: 20,
      fields: ['orders.items.sku']);
  const compound = IndexDescriptor(
      indexType: IndexType.unique, dataTree: 20, fields: ['country', 'city']);
  const sparse = IndexDescriptor(
      indexType: IndexType.nonUnique,
      dataTree: 20,
      fields: ['tags'],
      sparse: true);
  const escaped = IndexDescriptor(
      indexType: IndexType.nonUnique, dataTree: 20, fields: [r'a\.b.c']);

  add('one entry per array element (section 4)', single,
      d({'tags': CArray([const CStr('red'), const CStr('blue')])}),
      const CNitriteId(7));
  add('duplicate elements produce one entry, not two', single,
      d({'tags': CArray([const CStr('red'), const CStr('red')])}),
      const CNitriteId(7));
  add('a present null is indexed as NULL (section 3)', single,
      d({'tags': const CNull()}), const CNitriteId(9));
  add('an absent field is indexed as NULL (section 3)', single, d({}),
      const CNitriteId(9));
  add('sparse skips an absent field entirely (section 3)', sparse, d({}),
      const CNitriteId(9));
  add('sparse still indexes a present null', sparse,
      d({'tags': const CNull()}), const CNitriteId(9));
  add('array traversal flattens the rest of the path (section 5)', nested,
      d({
        'orders': CArray([
          d({
            'items': CArray([
              d({'sku': const CStr('a')}),
              d({'sku': const CStr('b')}),
            ])
          }),
          d({
            'items': CArray([d({'sku': const CStr('c')})])
          }),
        ])
      }),
      const CNitriteId(11));
  add('a compound index takes the cartesian product (section 4)', compound,
      d({
        'country': const CStr('fr'),
        'city': CArray([const CStr('paris'), const CStr('lyon')])
      }),
      const CNitriteId(12));
  const through = IndexDescriptor(
      indexType: IndexType.nonUnique, dataTree: 20, fields: ['a.b']);
  // F-058: section 4 is one entry per element, so an empty array has none --
  // it is not an absent field.
  add('an empty array produces no entries (section 4)', single,
      d({'tags': CArray([])}), const CNitriteId(14));
  // F-059: section 5, "an unresolvable path is treated as an absent field",
  // also when it fails inside an array traversal.
  add('a path no array element resolves is absent: NULL (section 5)', through,
      d({'a': CArray([const CStr('x'), CInt.i32(1)])}),
      const CNitriteId(15));
  add('array elements lacking the field: absent, NULL (section 5)', through,
      d({'a': CArray([d({'c': const CStr('x')})])}), const CNitriteId(16));
  add(r'\. is a literal dot in a field path (section 5)', escaped,
      d({'a.b': d({'c': const CStr('x')})}), const CNitriteId(13));

  write(root, 'index/entries', {
    ...header,
    'chapter': 'spec/06-indexes.md sections 3-5',
    'cap_per_document': kMaxIndexEntriesPerDocument,
    'field_path_escapes': {
      'note': 'The only escaping in the format, and only inside index field '
          'paths (section 5).',
      r'a\.b.c': splitFieldPath(r'a\.b.c'),
      r'a\\b': splitFieldPath(r'a\\b'),
      'a.b.c': splitFieldPath('a.b.c'),
    },
    'cases': cases,
  });
}

/// `spec/05-catalog.md`: reserved tree ids, descriptor fields, and the
/// normative index-type spellings.
void _catalog(String root) {
  final store = PageStore();
  final catalog = Catalog(store);
  final orders = catalog.create('orders|2026+eu',
      kind: TreeKind.data,
      keyKind: 'nitrite_id',
      params: {'type': const CStr(DataTreeType.collection)});
  final repo = catalog.create('org.dizitart.no2.Employee+archive',
      kind: TreeKind.data,
      keyKind: 'nitrite_id',
      params: {
        'type': const CStr(DataTreeType.repository),
        'entity': const CStr('org.dizitart.no2.Employee'),
        'key': const CStr('archive'),
      });
  final idx = catalog.create('idx:orders|2026+eu:country,city:unique',
      kind: TreeKind.index,
      owner: 'orders|2026+eu',
      params: const IndexDescriptor(
              indexType: IndexType.unique,
              dataTree: 17,
              fields: ['country', 'city'])
          .params);

  Map<String, Object?> desc(String name, TreeDescriptor d) => {
        'name': name,
        'name_key': hex(encodeKey(CStr(name))),
        'tree_id': d.treeId,
        'kind': d.kind,
        'levelled': d.levelled,
        // `created` is a wall clock and cannot be pinned; every other field can.
        'descriptor_without_created':
            hex(encodeValue(CDoc({...d.doc.fields}..remove('created')))),
      };

  write(root, 'catalog/trees', {
    ...header,
    'chapter': 'spec/05-catalog.md',
    'reserved_tree_ids': {
      'catalog': TreeId.catalog,
      'free_space': TreeId.freeSpace,
      'attributes': TreeId.attributes,
      'tree_index': TreeId.treeIndex,
      'repair_log': TreeId.repairLog,
      'users': TreeId.users,
      'manifest': TreeId.manifest,
      'vlog_stats': TreeId.vlogStats,
      'checkpoints': TreeId.checkpoints,
      'change_feed': TreeId.changeFeed,
      'first_user_tree': TreeId.firstUserTree,
    },
    'index_type_names': {
      'note': 'section 10: lower snake case, no hyphens, no camel case. '
          'These five are the only portable names.',
      'values': IndexType.portable.toList()..sort(),
    },
    'levelled_kinds': TreeKind.levelled.toList()..sort(),
    'store_metadata_key': hex(encodeKey(const CStr(Attributes.storeKey))),
    'trees': [
      desc('orders|2026+eu', orders),
      desc('org.dizitart.no2.Employee+archive', repo),
      desc('idx:orders|2026+eu:country,city:unique', idx),
    ],
  });
}


/// `spec/11-conformance.md` §6's `analyzer/` set: "text → expected
/// token+position stream for `cryptand.std.v1`".
///
/// This is the vector set the chapter cares most about, and §2 says why: an
/// analyzer that differs between languages produces "an index that is silently
/// wrong in a way no checksum catches". Every case below is a place two
/// reasonable implementations diverge.
void _analyzer(String root) {
  final std = Analyzer();
  final withStops = Analyzer(stopwords: ['the', 'a']);

  Map<String, Object?> caseOf(String note, Analyzer a, String text) => {
        'note': note,
        'stopwords': a.stopwords.toList()..sort(),
        // The input as code points, so another SDK builds the same string
        // without depending on how this JSON was transported.
        'input_cps': [for (final r in text.runes) r],
        'tokens': [
          for (final t in a.analyze(text))
            {
              'text_cps': [for (final r in t.text.runes) r],
              'position': t.position,
            }
        ],
      };

  write(root, 'analyzer/std_v1', {
    ...header,
    'chapter': 'spec/07-fulltext.md section 2.2',
    'analyzer': Analyzer.std,
    'unicode_version': Analyzer.unicodeVersionImplemented,
    'pipeline': [
      'decode UTF-8; non-string values skipped',
      'NFKC',
      'UAX #29 word boundaries; keep segments with >=1 Alphabetic or '
          'Numeric_Type != None',
      'Simple_Lowercase_Mapping (NOT full folding, NOT locale-sensitive)',
      'drop segments longer than 64 code points',
      'drop stopwords',
      'apply the stemmer',
      'emit with the PRE-FILTER segment index as the position',
    ],
    'cases': [
      caseOf('the chapter opening example', std, 'Bäckerei-Straße 12'),
      caseOf('simple lowercasing, not full folding: SS vs ss', std, 'STRAẞE'),
      caseOf('the Turkish I: locale-independent', std, 'I İ ı'),
      caseOf('NFKC folds a ligature before segmenting', std, 'ﬁle ﬂow'),
      caseOf('NFKC folds a circled digit to a numeric', std, '① ②'),
      caseOf('decomposed and composed forms agree', std, 'café café'),
      caseOf('punctuation-only segments are dropped', std, 'a -- b ++ c'),
      caseOf('an apostrophe stays inside a word (WB6/WB7)', std, "don't"),
      caseOf('a decimal stays one token (WB11/WB12)', std, '3.14 1,000'),
      caseOf('CJK segments per UAX #29', std, '東京都は日本'),
      caseOf('a regional-indicator pair is one segment (WB15/16)',
          std, 'flag \u{1F1EF}\u{1F1F5} end'),
      caseOf('ZWJ joins an emoji sequence (WB3c)',
          std, 'a \u{1F468}‍\u{1F469} b'),
      caseOf('a 65 code point segment is dropped, 64 survives',
          std, '${"x" * 64} ${"y" * 65}'),
      caseOf('stopwords leave a POSITION GAP, not a shift',
          withStops, 'the quick a brown fox'),
    ],
  });
}
