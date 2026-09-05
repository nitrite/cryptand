// A minimal end-to-end use of the Cryptand reference implementation:
// create an encrypted `.cryptand` file, write documents through a collection,
// close it, reopen it with the key, and read them back.
//
// The same file can be opened by the Rust reference implementation
// (`reference/rust/cryptand`) — see `reference/conformance/interop/`.

import 'dart:io';

import 'package:cryptand/cryptand.dart';

void main() {
  final dir = Directory.systemTemp.createTempSync('cryptand-example-');
  final path = '${dir.path}/people.cryptand';

  // A 32-byte content key. In a real application this comes from a platform
  // keystore or an Argon2id-derived password (see spec/14-security.md).
  final key = List<int>.generate(32, (i) => i);

  // --- write ------------------------------------------------------------
  final db = DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw);
  final people = db.createCollection('people');

  for (var i = 0; i < 100; i++) {
    people.put(
      CNitriteId(i),
      CDoc({
        'name': CStr('person-$i'),
        'age': CInt.i32(20 + i % 50),
      }),
    );
  }
  db.engine.flush();
  DatabaseFile.save(db, path);

  // --- read back -------------------------------------------------------
  final reopened = DatabaseFile.open(path, key: key);
  final loaded = reopened.collection('people')!;
  final doc = loaded.get(const CNitriteId(42))!;
  print('id 42 -> name=${doc['name']} age=${doc['age']}');
  print('documents: ${loaded.all.length}');

  // The wrong key is refused, indistinguishably from a missing keyslot.
  try {
    DatabaseFile.open(path, key: List.filled(32, 0xFF));
  } on CannotUnlockException {
    print('wrong key rejected');
  }

  dir.deleteSync(recursive: true);
}
