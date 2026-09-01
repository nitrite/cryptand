import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cve.dart';
import '../bench/harness.dart';

double med(int reps, void Function() f) {
  final xs = <double>[];
  for (var r = 0; r < reps; r++) {
    final sw = Stopwatch()..start(); f(); sw.stop();
    xs.add(sw.elapsedMicroseconds.toDouble());
  }
  xs.sort(); return xs[xs.length ~/ 2];
}

void main() {
  final dict = benchDict();
  final w = ByteWriter(); writeDoc(w, benchDoc(42), dict: dict);
  final b = w.takeBytes();
  const n = 50000;

  for (var warm = 0; warm < 3; warm++) {
    for (var i = 0; i < n; i++) { DocView.parse(b, dict: dict)['trackingNumb']; }
  }

  final tParse = med(7, () { for (var i=0;i<n;i++) DocView.parse(b, dict: dict); });
  final tParse1 = med(7, () { for (var i=0;i<n;i++) DocView.parse(b, dict: dict)['trackingNumb']; });
  final tParseAll = med(7, () { for (var i=0;i<n;i++) DocView.parse(b, dict: dict).toDoc(); });
  final v = DocView.parse(b, dict: dict);
  final tField = med(7, () { for (var i=0;i<n;i++) v['trackingNumb']; });
  final tGet1 = med(7, () { for (var i=0;i<n;i++) DocView.parse(b, dict: dict).get('trackingNumb'); });
  final tFieldAll = med(7, () { for (var i=0;i<n;i++) v.toDoc(); });

  double ns(double us) => us*1000/n;
  print('parse only            ${ns(tParse).toStringAsFixed(0)} ns');
  print('parse + 1 field       ${ns(tParse1).toStringAsFixed(0)} ns');
  print('parse + all 20        ${ns(tParseAll).toStringAsFixed(0)} ns');
  print('1 field, parsed view  ${ns(tField).toStringAsFixed(0)} ns');
  print('all 20, parsed view   ${ns(tFieldAll).toStringAsFixed(0)} ns');
  print('');
  print('parse + get (1 pass)  ${ns(tGet1).toStringAsFixed(0)} ns');
  print('parse is ${(100*tParse/tParse1).toStringAsFixed(0)}% of a single-field read');
  print('field-only ratio all/1 = ${(tFieldAll/tField).toStringAsFixed(2)}x');
}
