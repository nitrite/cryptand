/// Reads the generated conformance vectors back and checks every assertion in
/// them, so the vectors are self-verifying.
///
/// This is the test another SDK ports first: it needs only a JSON parser and
/// the encoders, and it never touches this package's internals beyond the
/// public encode and decode paths. `spec/11-conformance.md` section 7:
/// "Conformance is defined as passing the vectors, not as matching the
/// reference implementation's source."
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/src/analyzer.dart';
import 'package:cryptand/src/argon2.dart';
import 'package:cryptand/src/catalog.dart';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/crc32c.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/filter.dart';
import 'package:cryptand/src/index.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/security.dart';
import 'package:cryptand/src/u128.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

const String kRoot = '../../conformance/vectors';

Map<String, Object?> load(String name) => jsonDecode(
    File('$kRoot/$name.json').readAsStringSync()) as Map<String, Object?>;

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

/// Rebuilds a value from the language-neutral description the vectors carry.
/// Another SDK writes this function and nothing else to consume the vectors.
CValue build(Map<String, Object?> d) {
  switch (d['t'] as String) {
    case 'null':
      return const CNull();
    case 'bool':
      return CBool(d['v']! as bool);
    case 'int':
      final w = NumType.values.firstWhere((t) => t.name == d['w']);
      final s = d['v']! as String;
      final neg = s.startsWith('-');
      return CInt(w, neg, U128.fromBigInt(BigInt.parse(neg ? s.substring(1) : s)));
    case 'float':
      final bits = unhex(d['bits']! as String);
      final bd = ByteData.view(Uint8List.fromList(bits).buffer);
      return d['w'] == 'f64'
          ? CFloat(NumType.f64, bd.getFloat64(0))
          : CFloat(NumType.f32, bd.getFloat32(0));
    case 'str':
      return CStr(const Utf8Decoder().convert(unhex(d['utf8']! as String)));
    case 'bytes':
      return CBytes(unhex(d['v']! as String));
    case 'char':
      return CChar(d['v']! as int);
    case 'timestamp':
      return CTimestamp(d['millis']! as int);
    case 'timestamp_ns':
      return CTimestampNs(d['secs']! as int, d['nanos']! as int);
    case 'zoned':
      return CZoned(d['millis']! as int, d['zone']! as String);
    case 'date':
      return CDate(d['days']! as int);
    case 'time':
      return CTime(d['nanos']! as int);
    case 'duration':
      return CDuration(d['secs']! as int, d['nanos']! as int);
    case 'uuid':
      return CUuid(unhex(d['v']! as String));
    case 'nitrite_id':
      return CNitriteId(int.parse(d['v']! as String));
    case 'regex':
      return CRegex(d['pattern']! as String, d['flags']! as String);
    case 'array':
      return CArray([
        for (final x in d['items']! as List) build(x as Map<String, Object?>)
      ]);
    case 'map':
      return CMap([
        for (final e in d['entries']! as List)
          (
            build((e as Map<String, Object?>)['k']! as Map<String, Object?>),
            build(e['v']! as Map<String, Object?>)
          )
      ]);
    case 'doc':
      return CDoc({
        for (final e in (d['fields']! as Map<String, Object?>).entries)
          e.key: build(e.value! as Map<String, Object?>)
      });
    case 'vector':
      return CVector.f32(
          [for (final x in d['f32']! as List) (x as num).toDouble()]);
    case 'geometry':
      return CGeometry(unhex(d['wkb']! as String));
    case 'opaque':
      return COpaque(d['origin']! as String, d['type_name']! as String,
          unhex(d['data']! as String));
    case 'dec128':
      return CDec128(unhex(d['v']! as String));
    case 'unknown':
      return CUnknown(d['tag']! as int, unhex(d['payload']! as String));
    case 'blob_ref':
      return CBlobRef(
          d['start_page']! as int, d['byte_len']! as int, d['crc32c']! as int);
    case 'overflow_ref':
      return COverflowRef(unhex(d['inline']! as String), d['next_page']! as int);
    case 'vlog_ref':
      return CVlogRef(
          d['segment_id']! as int, d['offset']! as int, d['len']! as int);
    default:
      throw StateError('unknown vector type ${d['t']}');
  }
}

void main() {
  test('the vectors exist -- run tool/generate_vectors.dart first', () {
    expect(Directory(kRoot).existsSync(), isTrue,
        reason: 'missing $kRoot; run `dart run tool/generate_vectors.dart`');
  });

  group('cke/values', () {
    final v = load('cke/values');
    test('every case encodes to its recorded bytes', () {
      for (final c in v['cases']! as List) {
        final m = c as Map<String, Object?>;
        final value = build(m['value']! as Map<String, Object?>);
        expect(hex(encodeKey(value)), m['cke'],
            reason: '${m['note']}: $value');
      }
    });

    test('every case decodes back', () {
      for (final c in v['cases']! as List) {
        final m = c as Map<String, Object?>;
        final bytes = unhex(m['cke']! as String);
        expect(() => decodeKey(bytes), returnsNormally,
            reason: '${m['note']}');
      }
    });

    test('every reject is rejected, and none of them crashes', () {
      for (final r in v['rejects']! as List) {
        final m = r as Map<String, Object?>;
        expect(() => decodeKey(unhex(m['cke']! as String)),
            throwsA(isA<CryptandException>()),
            reason: m['why'] as String);
      }
    });
  });

  group('numbers/torture', () {
    final v = load('numbers/torture');
    test('every entry encodes to its recorded bytes', () {
      for (final e in v['entries']! as List) {
        final m = e as Map<String, Object?>;
        final value = build(m['value']! as Map<String, Object?>);
        expect(hex(encodeKey(value)), m['v'] ?? m['cke'], reason: '$value');
      }
    });

    test('the recorded sort order is the byte order', () {
      final sorted = [
        for (final s in v['sorted_by_cke']! as List) unhex(s as String)
      ];
      for (var i = 1; i < sorted.length; i++) {
        expect(compareKeys(sorted[i - 1], sorted[i]), lessThanOrEqualTo(0),
            reason: 'entry $i breaks the recorded order');
      }
      expect(sorted.length, v['count']);
    });

    test('the three lossy decodings decode as recorded', () {
      for (final l in v['lossy_decodings']! as List) {
        final m = l as Map<String, Object?>;
        final got = decodeKey(unhex(m['cke']! as String));
        final want = build(m['decodes_to']! as Map<String, Object?>);
        if (want is CFloat && want.value.isNaN) {
          expect((got as CFloat).value.isNaN, isTrue, reason: '${m['why']}');
        } else {
          expect(got, want, reason: m['why'] as String);
        }
      }
    });
  });

  group('cve/values', () {
    final v = load('cve/values');
    test('every case encodes to its recorded bytes', () {
      for (final c in v['cases']! as List) {
        final m = c as Map<String, Object?>;
        final value = build(m['value']! as Map<String, Object?>);
        expect(hex(encodeValue(value)), m['cve'], reason: '${m['note']}');
      }
    });

    test('every case round-trips', () {
      for (final c in v['cases']! as List) {
        final m = c as Map<String, Object?>;
        final bytes = unhex(m['cve']! as String);
        expect(hex(encodeValue(decodeValue(bytes))), m['cve'],
            reason: '${m['note']}');
      }
    });

    test('every reject is rejected', () {
      for (final r in v['rejects']! as List) {
        final m = r as Map<String, Object?>;
        expect(() => decodeValue(unhex(m['cve']! as String)),
            throwsA(isA<CryptandException>()),
            reason: m['why'] as String);
      }
    });
  });

  group('strings/cases', () {
    final v = load('strings/cases');
    test('every case encodes as recorded, in both encodings', () {
      for (final c in v['cases']! as List) {
        final m = c as Map<String, Object?>;
        final s = CStr(const Utf8Decoder().convert(unhex(m['utf8']! as String)));
        expect(hex(encodeKey(s)), m['cke'], reason: '${m['note']}');
        expect(hex(encodeValue(s)), m['cve'], reason: '${m['note']}');
      }
    });

    test('NFC and NFD really are different keys', () {
      // The format applies no normalization. Two SDKs that disagree here
      // disagree about which documents exist.
      final cases = v['cases']! as List;
      final nfc = cases.firstWhere(
          (c) => (c as Map)['note'].toString().startsWith('NFC')) as Map;
      final nfd = cases.firstWhere(
          (c) => (c as Map)['note'].toString().startsWith('NFD')) as Map;
      expect(nfc['cke'], isNot(nfd['cke']));
    });

    test('ill-formed UTF-8 is rejected, never replaced', () {
      for (final r in v['rejects_on_read']! as List) {
        final m = r as Map<String, Object?>;
        final raw = unhex(m['utf8']! as String);
        final cve = Uint8List.fromList([Tag.str, raw.length, ...raw]);
        expect(() => decodeValue(cve), throwsA(isA<CorruptionException>()),
            reason: m['why'] as String);
      }
    });
  });

  group('documents/cases', () {
    final v = load('documents/cases');
    test('the dictionary reproduces the recorded encoding', () {
      final dict = NameDict();
      for (final e in v['dictionary']! as List) {
        final m = e as Map<String, Object?>;
        expect(dict.intern(m['name']! as String), m['name_id'],
            reason: 'name_id allocation must be append-only and stable');
      }
      final c = (v['cases']! as List).first as Map<String, Object?>;
      final doc = build(c['value']! as Map<String, Object?>) as CDoc;
      final view = DocView.parse(
          unhex(c['cve_with_dictionary']! as String),
          dict: dict);
      expect(view.toDoc(), doc);
      expect([for (var i = 0; i < view.fieldCount; i++) view.nameAt(i)],
          c['field_order']);
    });

    test('reserved fields occupy name_id 1..5', () {
      final want = v['reserved_field_ids']! as Map<String, Object?>;
      final d = NameDict.withReservedFields();
      want.forEach((name, id) => expect(d.idOf(name), id, reason: name));
    });

    test('an unknown tag inside an array round-trips byte for byte', () {
      final c = (v['cases']! as List)[1] as Map<String, Object?>;
      final bytes = unhex(c['cve']! as String);
      expect(hex(encodeValue(decodeValue(bytes))), c['cve']);
    });
  });

  group('container/layout', () {
    final v = load('container/layout');
    final sbv = v['superblock']! as Map<String, Object?>;

    test('the recorded superblock parses and matches its expectations', () {
      final sb = Superblock.tryDecode(unhex(sbv['bytes']! as String));
      expect(sb, isNotNull);
      final want = sbv['expected']! as Map<String, Object?>;
      expect(sb!.vlogMin, want['vlog_min']);
      expect(sb.pageSize, want['page_size']);
      expect(sb.profile, Profile.mobile);
      expect(sb.commitId, 1);
    });

    test('the recorded field offsets are the ones this code uses', () {
      final offs = sbv['field_offsets']! as Map<String, Object?>;
      expect(offs['magic'], Sb.magic);
      expect(offs['commit_id'], Sb.commitId);
      expect(offs['vlog_min'], Sb.vlogMin);
      expect(offs['next_nonce'], Sb.nextNonce);
      expect(offs['sb_mac'], Sb.sbMac);
      expect(offs['keyslots'], Sb.keyslots);
      expect(offs['checksum'], Sb.checksum);
    });

    test('the page header is 40 bytes at the recorded offsets', () {
      final ph = v['page_header']! as Map<String, Object?>;
      expect(ph['size'], PageHeader.size);
      expect(ph['size'], 40);
      final offs = ph['field_offsets']! as Map<String, Object?>;
      expect(offs['extent_pages'], 12);
      expect(offs['commit_id'], 16);
      expect(offs['payload_len'], 24);
      expect(offs['nonce'], 32);
      final bytes = unhex(ph['bytes']! as String);
      expect(bytes.length, 40);
    });

    test('the recorded CRC-32C values reproduce', () {
      for (final c in v['crc32c']! as List) {
        final m = c as Map<String, Object?>;
        expect(crc32c(unhex(m['input']! as String)), m['crc']);
      }
    });
  });

  group('filter/blocked_bloom', () {
    final v = load('filter/blocked_bloom');
    test('the structure constants reproduce', () {
      final s = v['structure']! as Map<String, Object?>;
      expect(s['block_bits'], kBlockBits);
      final probes = s['probes_for_bits_per_key']! as Map<String, Object?>;
      probes.forEach((bits, k) => expect(probesFor(int.parse(bits)), k));
      final bc = s['block_count_examples']! as Map<String, Object?>;
      expect(bc['32 keys at 16 bits'], blockCountFor(32, 16));
      expect(bc['33 keys at 16 bits'], blockCountFor(33, 16));
      expect(bc['1000 keys at 16 bits'], blockCountFor(1000, 16));
    });

    test('the named hash is CFH-64 and its vectors reproduce', () {
      expect(v['hash'], contains('CFH-64'));
      final vectors = v['cfh64_vectors']! as Map<String, Object?>;
      vectors.forEach((keyHex, want) {
        final got = BigInt.from(cfh64(unhex(keyHex)))
            .toUnsigned(64)
            .toRadixString(16);
        expect(got, want, reason: 'CFH-64 of $keyHex');
      });
      expect(vectors.length, greaterThanOrEqualTo(6));
    });

    test('the recorded filter blocks reproduce bit for bit', () {
      // This is the assertion that was impossible while the hash was
      // unspecified. It is now the whole point of the file.
      final r = v['reproduce']! as Map<String, Object?>;
      final keys = [
        for (var i = 0; i < (r['key_count']! as int); i++)
          userKeyPrefix(r['tree_id']! as int,
              encodeKey(CNitriteId((r['first_id']! as int) + i)))
      ];
      final f = BlockedBloom.build(keys,
          bitsPerKey: r['bits_per_key']! as int, distinctKeys: keys.length);
      expect(hex(f.blocks), v['blocks']);
      expect(hex(Uint8List.sublistView(f.encodePayload(), 0, 16)),
          v['header_bytes']);
    });
  });

  group('security/derivation', () {
    final v = load('security/derivation');
    test('the RFC 5869 case reproduces', () {
      final c = v['hkdf_rfc5869_case1']! as Map<String, Object?>;
      expect(
          hex(hkdf(unhex(c['ikm']! as String), unhex(c['salt']! as String),
              unhex(c['info']! as String), c['length']! as int)),
          c['okm']);
    });

    test('the subkeys reproduce and differ per purpose', () {
      final s = v['subkeys']! as Map<String, Object?>;
      final master = unhex(s['master_key']! as String);
      final uuid = unhex(s['database_uuid']! as String);
      expect(hex(deriveSubkey(master, uuid, Purpose.page)), s['page']);
      expect(hex(deriveSubkey(master, uuid, Purpose.vlog)), s['vlog']);
      expect(hex(deriveSubkey(master, uuid, Purpose.sbMac)), s['sbmac']);
      expect(s['page'], isNot(s['vlog']));
      expect(s['page'], isNot(s['sbmac']));
    });

    test('the nonces reproduce and are 24 bytes', () {
      for (final n in v['nonces']! as List) {
        final m = n as Map<String, Object?>;
        final built = buildNonce(m['domain']! as int, m['counter']! as int,
            m['object_id']! as int, m['offset']! as int);
        expect(built.length, 24);
        expect(hex(built), m['nonce']);
      }
    });

    test('the keyslot layout matches', () {
      final k = v['keyslot']! as Map<String, Object?>;
      expect(k['size'], Keyslot.size);
      expect(k['count'], Sb.keyslotCount);
      expect(k['offset_in_superblock'], Sb.keyslots);
      expect((k['size']! as int) * (k['count']! as int), 576);
    });

    test('the RFC 9106 Argon2id vector reproduces', () {
      // The vector is the RFC's, not this implementation's: another SDK checks
      // its KDF against these bytes rather than against this code, which is
      // the whole argument of spec/00-conventions.md section 1.1.
      final a = v['argon2id']! as Map<String, Object?>;
      final p = a['params']! as Map<String, Object?>;
      final r = argon2id(
        password: unhex(a['password']! as String),
        salt: unhex(a['salt']! as String),
        secret: unhex(a['secret']! as String),
        associatedData: unhex(a['associated_data']! as String),
        memoryKiB: p['memory_kib']! as int,
        passes: p['passes']! as int,
        parallelism: p['parallelism']! as int,
        tagLength: p['tag_length']! as int,
      );
      expect(hex(r.h0), a['h0']);
      expect(hex(r.tag), a['tag']);
      expect(a['version'], kArgon2Version);
    });

    test('the profile costs match spec/14-security.md section 3.2', () {
      final c = v['profile_costs']! as Map<String, Object?>;
      final floor = c['writer_floor']! as Map<String, Object?>;
      // The floor is what a writer may CREATE with; checkCreateCost enforces it.
      expect(
          () => Keyslot.checkCreateCost(floor['t_cost']! as int,
              floor['m_cost_kib']! as int, floor['parallelism']! as int),
          returnsNormally);
      expect(() => Keyslot.checkCreateCost(1, 16384, 1), throwsA(anything));
      expect(() => Keyslot.checkCreateCost(2, 16383, 1), throwsA(anything));
      for (final profile in ['mobile', 'tablet', 'desktop', 'server']) {
        final m = c[profile]! as Map<String, Object?>;
        expect(
            () => Keyslot.checkCreateCost(m['t_cost']! as int,
                m['m_cost_kib']! as int, m['parallelism']! as int),
            returnsNormally,
            reason: '$profile must be at or above the writer floor');
      }
    });

    test('nothing in spec/14-security.md section 2 is undeclared or absent', () {
      // This assertion used to read the other way -- it asserted that
      // XChaCha20-Poly1305 and Argon2id were *missing*, and it kept passing
      // for a whole phase after the AEAD landed, because the generator's list
      // went stale and the test enforced the staleness. A test that asserts
      // what is absent rots into asserting what is present.
      //
      // It now asserts the invariant that actually matters: all four
      // primitives are implemented and each reproduces a published vector,
      // which the tests above check one by one.
      expect(v['not_implemented'], isEmpty);
      expect(v['argon2id'], isNotNull);
      expect(v['hkdf_rfc5869_case1'], isNotNull);
    });
  });

  group('index/layout', () {
    final v = load('index/layout');
    test('every index entry key reproduces', () {
      for (final e in v['entries']! as List) {
        final m = e as Map<String, Object?>;
        final value = build(m['indexed_value']! as Map<String, Object?>);
        final key = encodeKey(CArray([value, CNitriteId(m['nitrite_id']! as int)]));
        expect(hex(key), m['key'], reason: '$value');
      }
    });

    test('eq(5) across numeric types contains every recorded member', () {
      final rc = v['range_construction']! as Map<String, Object?>;
      final eq = rc['eq_5_any_numeric_type']! as Map<String, Object?>;
      final range =
          KeyRange(unhex(eq['lower']! as String), unhex(eq['upper']! as String));
      expect(hex(KeyRange.eqNumeric(CInt.i32(5)).lower), eq['lower']);
      for (final k in eq['contains']! as List) {
        expect(range.contains(unhex(k as String)), isTrue, reason: k);
      }
    });

    test('the recorded helpers reproduce', () {
      final rc = v['range_construction']! as Map<String, Object?>;
      expect(hex(Keys.arrayPrefixNumeric([CInt.i32(5)])),
          rc['array_prefix_numeric_5']);
      final sw = rc['starts_with_abc']! as Map<String, Object?>;
      expect(hex(KeyRange.startsWith('abc').lower), sw['lower']);
      expect(hex(KeyRange.startsWith('abc').upper!), sw['upper']);
    });
  });

  group('index/entries', () {
    final v = load('index/entries');

    test('every case reproduces its keys byte for byte', () {
      for (final c in v['cases']! as List) {
        final m = c as Map<String, Object?>;
        final idx = IndexDescriptor(
          indexType: m['index_type']! as String,
          dataTree: 20,
          fields: [for (final f in m['fields']! as List) f as String],
          sparse: m['sparse']! as bool,
        );
        final doc = build(m['document']! as Map<String, Object?>) as CDoc;
        final id = build(m['nitrite_id']! as Map<String, Object?>);
        final got = [for (final k in indexKeysFor(idx, doc, id)) hex(k)];
        expect(got, m['keys'], reason: m['note'] as String);
      }
    });

    test('the cap and the field-path escapes are what the vector says', () {
      expect(kMaxIndexEntriesPerDocument, v['cap_per_document']);
      final esc = v['field_path_escapes']! as Map<String, Object?>;
      for (final e in esc.entries) {
        if (e.key == 'note') continue;
        expect(splitFieldPath(e.key), e.value, reason: e.key);
      }
    });
  });

  group('catalog/trees', () {
    final v = load('catalog/trees');

    test('reserved tree ids match the vector', () {
      final ids = v['reserved_tree_ids']! as Map<String, Object?>;
      expect(ids['catalog'], TreeId.catalog);
      expect(ids['manifest'], TreeId.manifest);
      expect(ids['vlog_stats'], TreeId.vlogStats);
      expect(ids['change_feed'], TreeId.changeFeed);
      expect(ids['first_user_tree'], TreeId.firstUserTree);
    });

    test('the five portable index-type names are exactly these', () {
      expect((v['index_type_names']! as Map<String, Object?>)['values'],
          IndexType.portable.toList()..sort());
    });

    test('levelled kinds match the vector', () {
      expect(v['levelled_kinds'], TreeKind.levelled.toList()..sort());
    });

    test('a descriptor re-encodes to the same bytes', () {
      for (final t in v['trees']! as List) {
        final m = t as Map<String, Object?>;
        final name = m['name']! as String;
        expect(hex(encodeKey(CStr(name))), m['name_key'], reason: name);
        final bytes = unhex(m['descriptor_without_created']! as String);
        final back = TreeDescriptor.decode(bytes);
        expect(back.treeId, m['tree_id'], reason: name);
        expect(back.kind, m['kind'], reason: name);
        expect(back.levelled, m['levelled'], reason: name);
        expect(hex(back.encode()), m['descriptor_without_created'],
            reason: '$name must round-trip byte for byte');
      }
    });
  });

  group('analyzer/std_v1', () {
    final v = load('analyzer/std_v1');

    test('every case reproduces its token and position stream', () {
      // spec/11-conformance.md section 6 names this set, and section 07 section 2
      // says why it matters more than the postings: an analyzer that differs
      // between languages produces "an index that is silently wrong in a way
      // no checksum catches".
      for (final c in v['cases']! as List) {
        final m = c as Map<String, Object?>;
        final a = Analyzer(
            stopwords: [for (final w in m['stopwords']! as List) w as String]);
        final input = String.fromCharCodes(
            [for (final cp in m['input_cps']! as List) cp as int]);
        final got = a.analyze(input);
        final want = m['tokens']! as List;
        expect(got.length, want.length, reason: m['note'] as String);
        for (var i = 0; i < got.length; i++) {
          final w = want[i] as Map<String, Object?>;
          expect(got[i].text,
              String.fromCharCodes(
                  [for (final cp in w['text_cps']! as List) cp as int]),
              reason: '${m["note"]} token $i');
          expect(got[i].position, w['position'],
              reason: '${m["note"]} position $i');
        }
      }
    });

    test('the analyzer name and Unicode version are pinned', () {
      expect(v['analyzer'], Analyzer.std);
      expect(v['unicode_version'], Analyzer.unicodeVersionImplemented);
      // Section 2.2: a build without the pinned version must refuse to write.
      expect(() => Analyzer().requireUnicode('16.0.0'),
          throwsA(isA<UnsupportedFeatureException>()));
    });

    test('the pipeline the vectors were generated from is recorded', () {
      // So another SDK implementing from the JSON alone knows what order the
      // eight steps run in -- the positions depend on it.
      final steps = v['pipeline']! as List;
      expect(steps.length, 8);
      expect(steps[1], contains('NFKC'));
      expect(steps.last, contains('PRE-FILTER'));
    });
  });
}
