/// PLAN M3.4 — Dart has no coverage-guided fuzzer, so every Rust cargo-fuzz
/// and Java Jazzer corpus entry is replayed through the Dart decoder its
/// target exercises. Each input is a typed refusal ([CryptandException]) or a
/// clean read; a round trip that decodes must re-encode stably. Anything else
/// (RangeError, StateError, ...) is a finding.
///
/// `CRYPTAND_CORPUS_DIRS` is a `:`-separated list of corpus roots whose
/// subdirectories are named after targets, Rust (`open_file`) or Java
/// (`openFile`) style. Unset, the test is skipped: the corpora are 1.4 GB and
/// not in git.
// ponytail: `segment` is not replayed on its own (open_file reaches segments
// through the reader); add it if a segment-only crash ever shows up.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

import '../harness/fuzz.dart';

final _key = Uint8List.fromList(List.generate(32, (i) => i + 1));

/// As Rust's `common::repair_crcs`: a mutant that fails its CRC reaches no
/// decoder.
Uint8List _repaired(Uint8List data) {
  final b = Uint8List.fromList(data);
  final sb = b.length >= 4096 ? Superblock.tryDecode(Uint8List.sublistView(b, 0, 4096)) : null;
  final ps = sb?.pageSize ?? 4096;
  if (ps < 512 || ps > 65536) return b;
  for (var p = 2; p < b.length ~/ ps; p++) {
    try {
      repairChecksum(b, p, ps);
    } on Object {
      // not a page header: nothing to repair
    }
  }
  return b;
}

void _open(Uint8List data, List<int>? key, String tmp) {
  File(tmp).writeAsBytesSync(_repaired(data));
  final db = DatabaseFile.openReadOnly(tmp, key: key == null ? null : Uint8List.fromList(key));
  try {
    db.engine.verifyStructure();
    for (final (_, d) in db.catalog.all) {
      for (final e in db.engine.scanTree(d.treeId).take(8)) {
        db.engine.get(d.treeId, decodeKey(e.cke));
      }
    }
  } finally {
    db.engine.close(flushMemtable: false);
  }
}

NameDict _dict() {
  final d = NameDict();
  for (var i = 1; i < 4; i++) {
    d.intern('name$i');
  }
  return d;
}

void _check(bool ok, String what) {
  if (!ok) throw StateError(what);
}

bool _eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void _cve(Uint8List data) {
  final d = _dict();
  final e = encodeValue(decodeValue(data, dict: d), dict: d);
  _check(_eq(encodeValue(decodeValue(e, dict: d), dict: d), e), 'CVE encode is not stable');
}

void _cke(Uint8List data) {
  final mid = data.isEmpty ? 0 : data[0] % data.length;
  for (final part in [Uint8List.sublistView(data, 0, mid), Uint8List.sublistView(data, mid)]) {
    try {
      final e = encodeKey(decodeKey(part));
      _check(_eq(encodeKey(decodeKey(e)), e), 'CKE decode∘encode is not the identity');
    } on CryptandException {
      // one half refused; the other still runs
    }
  }
}

void _wkb(Uint8List data) {
  final e = encodeWkb(decodeWkb(data));
  _check(_eq(encodeWkb(decodeWkb(e)), e), 'WKB encode is not stable');
}

void _superblock(Uint8List data) {
  Superblock.tryDecode(data);
  for (var o = 0; o + Keyslot.size <= data.length; o += Keyslot.size) {
    try {
      Keyslot.decode(Uint8List.sublistView(data, o, o + Keyslot.size), 0);
    } on CryptandException {
      // refused
    }
  }
}

void _analyzer(Uint8List data) {
  final String s;
  try {
    s = utf8.decode(data);
  } on FormatException {
    return;
  }
  final k = nfkc(s), c = nfc(s);
  _check(nfkc(k) == k, 'NFKC is not idempotent');
  _check(nfc(c) == c, 'NFC is not idempotent');
}

void main() {
  final roots = Platform.environment['CRYPTAND_CORPUS_DIRS'];
  final tmp = '${Directory.systemTemp.createTempSync('corpus-').path}/db.cryptand';
  final targets = <String, void Function(Uint8List)>{
    'open_file': (b) => _open(b, null, tmp),
    'openFile': (b) => _open(b, null, tmp),
    'open_encrypted': (b) => _open(b, _key, tmp),
    'openEncrypted': (b) => _open(b, _key, tmp),
    'cve_decode': _cve,
    'cveDecode': _cve,
    'cke_roundtrip': _cke,
    'ckeRoundtrip': _cke,
    'wkb': _wkb,
    'superblock_keyslot': _superblock,
    'superblockKeyslot': _superblock,
    'analyzer': _analyzer,
  };

  test('every Rust and Java corpus entry is refused or read by Dart', () {
    var runs = 0, refused = 0;
    final failures = <String>[];
    for (final root in roots!.split(':')) {
      for (final dir in Directory(root).listSync().whereType<Directory>()) {
        final run = targets[dir.uri.pathSegments.lastWhere((s) => s.isNotEmpty)];
        if (run == null) continue;
        for (final f in dir.listSync().whereType<File>()) {
          runs++;
          try {
            run(f.readAsBytesSync());
          } on CryptandException {
            refused++;
          } on Object catch (x, st) {
            failures.add('${f.path}: ${x.runtimeType}: $x');
            if (Platform.environment['CORPUS_STACK'] != null) print(st);
          }
        }
      }
    }
    print('corpus replay: $runs inputs, $refused refused, ${failures.length} failures');
    expect(runs, greaterThan(0), reason: 'no corpus found under $roots');
    expect(failures, isEmpty, reason: failures.take(50).join('\n'));
  }, skip: roots == null ? 'set CRYPTAND_CORPUS_DIRS' : false, timeout: Timeout.none);
}
