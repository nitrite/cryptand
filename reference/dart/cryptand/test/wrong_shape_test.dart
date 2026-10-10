// F-118: records read from the file with the wrong shape are corruption, not
// a TypeError.
import 'package:cryptand/src/catalog.dart';
import 'package:cryptand/src/checkpoint.dart';
import 'package:cryptand/src/cve.dart';
import 'package:cryptand/src/errors.dart';
import 'package:cryptand/src/index.dart';
import 'package:cryptand/src/value.dart';
import 'package:test/test.dart';

void main() {
  final corrupt = throwsA(isA<CorruptionException>());

  test('a descriptor field of the wrong type', () {
    final d = TreeDescriptor(CDoc({'root': CStr('x'), 'params': CBool(true)}));
    expect(() => d.root, corrupt);
    expect(() => d.params, corrupt);
  });

  test('index params of the wrong shape', () {
    final d = TreeDescriptor(CDoc({'params': CDoc({'index_type': CBool(true)})}));
    expect(() => IndexDescriptor.fromDescriptor(d), corrupt);
  });

  test('a checkpoint with a non-timestamp created', () {
    final bytes = encodeValue(CDoc({
      for (final f in [
        'commit_id', 'seq', 'catalog_root', 'freelist_root', 'attributes_root',
        'manifest_root', 'vlog_stats_root', 'changefeed_root'
      ])
        f: CInt.of(NumType.u64, 1),
      'created': CBool(true),
    }));
    expect(() => Checkpoint.decode('c', bytes), corrupt);
  });
}
