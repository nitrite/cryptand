import 'dart:io';
import 'dart:typed_data';
import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/database.dart';
import 'package:cryptand/src/engine.dart';
import 'package:cryptand/src/value.dart';

const int tree = 16;
int snowflakeId(int i) => 1767225600000 * 4194304 + i * 4096 + 1;
CDoc doc(int i, int rev) {
  final pad = i.toString().padLeft(6, '0');
  String v(String p) => '$p-$pad-${rev % 10}'.padRight(19, 'y');
  return CDoc({
    '_id': CNitriteId(snowflakeId(i)),
    'custAddr1_ln': CStr(v('addr1')), 'custAddr2_ln': CStr(v('addr2')),
    'custCityName': CStr(v('city')), 'custPostCode': CStr(v('post')),
    'custCountryX': CStr(v('ctry')), 'custEmailAdr': CStr(v('mail')),
    'custPhoneNum': CStr(v('phon')), 'ordReference': CStr(v('ordr')),
    'ordStatusTxt': CStr(v('stat')), 'ordCurrencyC': CStr(v('curr')),
    'ordNotesText': CStr(v('note')), 'whseLocation': CStr(v('whse')),
    'carrierName_': CStr(v('carr')), 'trackingNumb': CStr(v('trak')),
    'ordTotMinorU': CInt.varInt(1299 + i), 'ordTaxMinorU': CInt.varInt(216),
    'ordShipMinor': CInt.varInt(499),
    'placedAtUtcM': const CTimestamp(1767225000000),
    'dispatchUtcM': const CTimestamp(1767225600000),
  });
}
int next(int s) { s ^= (s << 13); s ^= (s >>> 7); s ^= (s << 17); return s; }
int below(int seed, int n) => (seed >>> 32) % n;

void main(List<String> args) {
  final n = args.isNotEmpty ? int.parse(args[0]) : 20000;
  final secs = args.length > 1 ? int.parse(args[1]) : 10;
  final db = Database(engine: Engine(
    pageSize: Profile.desktop.pageSize, vlogMin: Profile.desktop.vlogMin,
    memtableEntries: 4096, levels: LevelPolicy.desktop));
  final e = db.engine;
  CValue key(int i) => CNitriteId(snowflakeId(i));
  final v0 = <Uint8List>[for (var i = 0; i < n; i++) encodeValue(doc(i, 0))];
  for (var i = 0; i < n; i++) { e.put(tree, key(i), v0[i]); }
  e.flush(); e.compact();
  var seed = 0x51EDC0DE;
  final sw = Stopwatch()..start();
  var count = 0;
  while (sw.elapsedMicroseconds < secs * 1000000) {
    for (var k = 0; k < 10000; k++) {
      seed = next(seed);
      e.get(tree, key(below(seed, n)));
      count++;
    }
  }
  stdout.writeln('read_ops_per_s=${(count / (sw.elapsedMicroseconds / 1e6)).toStringAsFixed(0)}');
}
