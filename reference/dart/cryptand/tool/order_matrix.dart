/// Dumps the `spec/02-value-encoding.md` section 8 comparison matrix for the
/// shared `order/values.json` corpus, for cross-implementation diffing.
///
///   dart run tool/order_matrix.dart [out]
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';

Uint8List unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

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
    default:
      throw ArgumentError('unhandled vector value type: ${d['t']}');
  }
}

void main(List<String> args) {
  final out = args.isNotEmpty ? args[0] : '/tmp/order_dart.txt';
  final path = '${Directory.current.path}/../../conformance/vectors/order/values.json';
  final doc = jsonDecode(File(path).readAsStringSync()) as Map<String, Object?>;
  final entries = (doc['entries']! as List).cast<Map<String, Object?>>();
  final values = [
    for (final e in entries) build(e['value']! as Map<String, Object?>)
  ];
  final rows = <String>[];
  for (final a in values) {
    final b = StringBuffer();
    for (final c in values) {
      final r = compareValues(a, c);
      b.write(r < 0 ? '-' : (r == 0 ? '0' : '+'));
    }
    rows.add(b.toString());
  }
  File(out).writeAsStringSync('${rows.join('\n')}\n');
  stderr.writeln('wrote $out (${values.length} values)');
}
