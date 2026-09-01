import 'dart:typed_data';
import 'package:cryptand/src/cke.dart';
import 'package:cryptand/src/segment.dart';
import 'package:cryptand/src/value.dart';

String hx(List<int> b) => b.map((x)=>x.toRadixString(16).padLeft(2,'0')).join('');

void main() {
  for (final n in [1, 2, 3, 50, 127, 128, 129, 200, 500, 2000, 20000, 200000, 700000]) {
    final b = SegmentBuilder(pageSize: 4096, segmentId: 1, treeId: 17);
    for (var i = 0; i < n; i++) {
      b.add(SegEntry(internalKey(17, encodeKey(CNitriteId(1767225600000*4194304+i)), 1, Op.put),
          ValueKind.inline, Uint8List(16)));
    }
    final s = Segment(b.build(), 4096);
    final keys = <Uint8List>[];
    final c = s.cursor()..seekFirst();
    while (c.isValid) { keys.add(c.key()); c.next(); }
    var bad = 0; int? firstBad;
    for (var i = 0; i < keys.length; i++) {
      final p = s.cursor()..seekCeiling(keys[i]);
      if (!p.isValid || compareKeys(p.key(), keys[i]) != 0) { bad++; firstBad ??= i; }
    }
    print('n=$n pages=${s.pageCount} height=${s.height} scanned=${keys.length} badSeeks=$bad firstBad=$firstBad');
    if (bad > 0 && n <= 2000) {
      final i = firstBad!;
      print('  want ${hx(keys[i])}');
      final p = s.cursor()..seekCeiling(keys[i]);
      print('  got  ${p.isValid ? hx(p.key()) : "invalid"}');
    }
  }
}
