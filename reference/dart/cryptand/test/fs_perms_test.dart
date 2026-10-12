// PLAN 4.7: files the engine creates are owner-only. Dart has no lock sidecar.
@TestOn('!windows')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

void main() {
  test('save and create make 0600 files', () {
    final dir = Directory.systemTemp.createTempSync('perm');
    addTearDown(() => dir.deleteSync(recursive: true));
    int mode(String p) => File(p).statSync().mode & 511;

    final plain = '${dir.path}/plain.cryptand';
    DatabaseFile.save(Database(engine: Engine(vlogMin: 256)), plain);
    expect(mode(plain), 384);

    final enc = '${dir.path}/enc.cryptand';
    DatabaseFile.create(enc,
        credential: Uint8List(32), kdf: Keyslot.kdfRaw);
    expect(mode(enc), 384);
  });
}
