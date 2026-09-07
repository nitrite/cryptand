/// Dumps the `spec/08-spatial.md` section 4 predicate matrices and checks the
/// section 1 reject list, for cross-implementation diffing.
///
///   dart run tool/spatial_matrix.dart [out]
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';

Uint8List unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

void main(List<String> args) {
  final out = args.isNotEmpty ? args[0] : '/tmp/spatial_dart.txt';
  final path =
      '${Directory.current.path}/../../conformance/vectors/spatial/geometries.json';
  final doc = jsonDecode(File(path).readAsStringSync()) as Map<String, Object?>;
  final entries = (doc['geometries']! as List).cast<Map<String, Object?>>();
  final names = [for (final e in entries) e['name']! as String];
  final gs = [for (final e in entries) decodeWkb(unhex(e['wkb']! as String))];

  // Envelopes.
  var bad = 0;
  for (var i = 0; i < gs.length; i++) {
    final want =
        (entries[i]['envelope']! as List).map((e) => (e as num).toDouble()).toList();
    final e = gs[i].envelope();
    final got = [e.min[0], e.min[1], e.max[0], e.max[1]];
    if ('$want' != '$got') {
      stderr.writeln('envelope ${names[i]}: want $want got $got');
      bad++;
    }
  }

  // Rejects.
  for (final r in (doc['rejects']! as List).cast<Map<String, Object?>>()) {
    var refused = false;
    try {
      decodeWkb(unhex(r['wkb']! as String));
    } on CryptandException {
      refused = true;
    }
    if (!refused) {
      stderr.writeln('reject ${r['name']} was ACCEPTED: ${r['why']}');
      bad++;
    }
  }

  // Big-endian must be accepted.
  final be = doc['accept_big_endian']! as Map<String, Object?>;
  try {
    decodeWkb(unhex(be['wkb']! as String));
  } on CryptandException catch (e) {
    stderr.writeln('big-endian WKB was refused: $e');
    bad++;
  }

  final buf = StringBuffer();
  for (final kind in ['intersects', 'contains', 'within']) {
    buf.writeln(kind);
    for (final a in gs) {
      for (final b in gs) {
        final r = switch (kind) {
          'intersects' => Spatial.intersects(a, b),
          'contains' => Spatial.contains(a, b),
          _ => Spatial.within(a, b),
        };
        buf.write(r ? '1' : '0');
      }
      buf.writeln();
    }
  }
  File(out).writeAsStringSync(buf.toString());
  stderr.writeln('wrote $out (${gs.length} geometries, $bad problems)');
  if (bad > 0) exitCode = 1;
}
