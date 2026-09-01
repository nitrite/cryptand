/// What does keeping an aged scan at 1.00x cost in writes?
import 'dart:typed_data';
import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/value.dart';
import '../../bench/harness.dart';

class Lcg { Lcg(this.s); int s;
  int next() => s = s*6364136223846793005+1442695040888963407;
  int below(int n) => (next() >>> 1) % n; }

void main() {
  final dict = benchDict();
  const n = 20000, rounds = 10;
  Uint8List doc(int i) { final w = ByteWriter(); writeDoc(w, benchDoc(i), dict: dict); return w.takeBytes(); }
  final unit = doc(0).length;
  final logicalBytes = (n + rounds * n) * unit;

  print('$n docs of ~$unit B, then ${rounds}x that many random updates.');
  print('Logical value bytes written: ${(logicalBytes/1048576).toStringAsFixed(1)} MiB');
  print('');
  print('policy                         ratio  v/row  segs  spaceAmp  valueWA  initial  promoted');
  for (final e in {
    'debt trigger (20%)': Engine(pageSize:4096, vlogMin:256, memtableEntries:5000, localityDebtPct: 20),
    'debt trigger (50%)': Engine(pageSize:4096, vlogMin:256, memtableEntries:5000, localityDebtPct: 50),
    'space target only': Engine(pageSize:4096, vlogMin:256, memtableEntries:5000, localityDebtPct: 1000, vlogSpaceTargetPct: 150),
    'no collection at all': Engine(pageSize:4096, vlogMin:256, memtableEntries:5000, localityDebtPct: 1000, vlogSpaceTargetPct: 1000000),
  }.entries) {
    final eng = e.value;
    for (var i = 0; i < n; i++) { eng.put(17, CNitriteId(snowflakeId(i)), doc(i)); }
    eng.compact();
    final fresh = eng.scanDocuments();
    final rng = Lcg(0xA6ED);
    for (var r = 0; r < rounds; r++) {
      for (var i = 0; i < n; i++) { final t = rng.below(n); eng.put(17, CNitriteId(snowflakeId(t)), doc(t)); }
      eng.compact();
    }
    final aged = eng.scanDocuments();
    final wa = eng.vlog.totalBytesAppended / logicalBytes;
    final promoted = eng.vlog.promotedBytes / logicalBytes;
    print('${e.key.padRight(30)} '
        '${(aged.totalPageReads/fresh.totalPageReads).toStringAsFixed(2).padLeft(5)}  '
        '${aged.valueReadsPerScannedRow.toStringAsFixed(3).padLeft(5)}  '
        '${aged.liveVlogSegments.toString().padLeft(4)}  '
        '${aged.spaceAmplification.toStringAsFixed(2).padLeft(8)}  '
        '${wa.toStringAsFixed(2).padLeft(7)}  '
        '${(wa-promoted).toStringAsFixed(2).padLeft(7)}  '
        '${promoted.toStringAsFixed(2).padLeft(8)}');
  }
}
