import 'dart:typed_data';
/// Why is an aged scan 2.14x when every value-log segment is individually
/// key-clustered and locality_debt reads 0%?
import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/value.dart';
import 'package:cryptand/src/vlog.dart';
import '../../bench/harness.dart';

class Lcg { Lcg(this.s); int s;
  int next() => s = s*6364136223846793005+1442695040888963407;
  int below(int n) => (next() >>> 1) % n; }

void main() {
  final dict = benchDict();
  final e = Engine(pageSize: 4096, vlogMin: 256, memtableEntries: 5000);
  const n = 20000;
  Uint8List doc(int i) { final w = ByteWriter(); writeDoc(w, benchDoc(i), dict: dict); return w.takeBytes(); }

  for (var i = 0; i < n; i++) { e.put(17, CNitriteId(snowflakeId(i)), doc(i)); }
  e.compact();
  void dump(String label) {
    final cold = e.vlog.segments.values.where((s) => s.tier == VlogTier.cold && s.liveRecords > 0).toList();
    final hot = e.vlog.segments.values.where((s) => s.tier == VlogTier.hot && s.liveRecords > 0).toList();
    print('$label: cold segments with live data = ${cold.length}, hot = ${hot.length}');
    print('   live bytes ${e.vlog.liveBytes}  allocated ${e.vlog.allocatedBytes}  '
        'debt ${(e.vlog.localityDebt*100).toStringAsFixed(1)}%');
    for (final s in cold.take(12)) {
      print('   cold seg ${s.id}: live ${s.liveRecords}/${s.records} recs, clustered=${s.clustered}');
    }
  }
  dump('fresh');
  final rng = Lcg(0xA6ED);
  for (var round = 0; round < 10; round++) {
    for (var i = 0; i < n; i++) { final t = rng.below(n); e.put(17, CNitriteId(snowflakeId(t)), doc(t)); }
    e.compact();
  }
  dump('aged');

  // How fragmented is a key-ordered scan across cold segments?
  final r = e.scanDocuments();
  print('');
  print('scan: $r');
}
