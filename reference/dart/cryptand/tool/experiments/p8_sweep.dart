/// The aged-scan ratio and the value-log space target are the same knob.
/// Sweep it and see.
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
  const n = 20000;
  Uint8List doc(int i) { final w = ByteWriter(); writeDoc(w, benchDoc(i), dict: dict); return w.takeBytes(); }

  print('target%  fresh  aged   ratio  v/row  liveSegs  spaceAmp  coldGCs  writeAmp');
  for (final target in [120, 130, 150, 200, 400, 100000]) {
    final e = Engine(pageSize: 4096, vlogMin: 256, memtableEntries: 5000,
        vlogSpaceTargetPct: target, cachePages: 256);
    for (var i = 0; i < n; i++) { e.put(17, CNitriteId(snowflakeId(i)), doc(i)); }
    e.compact();
    final fresh = e.scanDocuments();
    final rng = Lcg(0xA6ED);
    for (var round = 0; round < 10; round++) {
      for (var i = 0; i < n; i++) { final t = rng.below(n); e.put(17, CNitriteId(snowflakeId(t)), doc(t)); }
      e.compact();
    }
    final aged = e.scanDocuments();
    // Rough write amplification of the value side: total bytes ever appended
    // to the value log divided by the logical bytes written.
    final logical = (n + 10 * n) * (fresh.bytes / n);
    final written = e.vlog.totalBytesAppended;
    print('${target.toString().padLeft(7)}  '
        '${fresh.totalPageReads.toString().padLeft(5)}  '
        '${aged.totalPageReads.toString().padLeft(5)}  '
        '${(aged.totalPageReads/fresh.totalPageReads).toStringAsFixed(2).padLeft(5)}  '
        '${aged.valueReadsPerScannedRow.toStringAsFixed(3).padLeft(5)}  '
        '${aged.liveVlogSegments.toString().padLeft(8)}  '
        '${aged.spaceAmplification.toStringAsFixed(2).padLeft(8)}  '
        '${e.coldCollections.toString().padLeft(7)}  '
        '${(written/logical).toStringAsFixed(2).padLeft(8)}');
  }
}
