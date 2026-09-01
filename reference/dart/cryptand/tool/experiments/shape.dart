import 'package:cryptand/src/bytes.dart';
import 'package:cryptand/src/cve.dart';
import '../bench/harness.dart';
void main(){
  final d = benchDoc(42);
  final names = d.fields.keys;
  final nameLen = names.map((n)=>n.length).reduce((a,b)=>a+b)/names.length;
  final dict = benchDict();
  final w = ByteWriter(); writeDoc(w, d, dict: dict);
  final w2 = ByteWriter(); writeDoc(w2, d);
  print('fields=${names.length} avg name=${nameLen.toStringAsFixed(1)}B');
  print('CVE+dict=${w.length}B  CVE inline-names=${w2.length}B');
  final valueBytes = w.length - 4 - names.length*2;
  print('approx value area=${valueBytes}B  avg value=${(valueBytes/names.length).toStringAsFixed(1)}B');
}
