/// `spec/14-security.md` §9.3 — "structure-aware fuzzing of the reader ...
/// **and an equivalent for each SDK**. A parser for a format read from
/// untrusted sources that has never been fuzzed is not finished."
///
/// This is Dart's equivalent of `cryptand fuzz`. Read `lib/src/fuzz.dart` for
/// why the checksum is repaired after every mutation; without that, the whole
/// exercise measures CRC-32C.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptand/cryptand.dart';

import '../harness/fuzz.dart';
import 'package:test/test.dart';

const int t = 16;

String tmp(String tag) {
  final d = Directory.systemTemp.createTempSync('cryptand-fuzz-$tag-');
  return '${d.path}/db.cryptand';
}

/// A fixture with structure worth mutating: several segments, a value log, an
/// index, a catalog and a name dictionary. A fixture of one segment fuzzes one
/// decoder.
Uint8List fixtureImage(String path) {
  final db = Database(engine: Engine(memtableEntries: 60, vlogMin: 256));
  final c = db.createCollection('orders');
  final idx = c.createIndex(['country']);
  const countries = ['de', 'fr', 'uk', 'in', 'us'];
  for (var i = 0; i < 300; i++) {
    final big = i % 10 == 0;
    c.put(
        CNitriteId(i),
        CDoc({
          '_id': CNitriteId(i),
          'seq': CInt.of(NumType.i32, i),
          'country': CStr(countries[i % 5]),
          'note': CBytes(
              Uint8List(big ? 900 : 40)..fillRange(0, big ? 900 : 40, i % 251)),
        }));
    if (i % 60 == 59) db.engine.flush();
  }
  assert(idx.treeId != 0);
  db.engine.flush();
  db.engine.drainCompaction();
  DatabaseFile.save(db, path);
  return File(path).readAsBytesSync();
}

/// Opens a mutant, verifies it, and **reads every document**. All three: the
/// verifier walks structure and checksums, and the decoders that turn bytes
/// into values only run when something reads.
int readEverything(Uint8List mutant, String path) {
  File(path).writeAsBytesSync(mutant, flush: true);
  final db = DatabaseFile.open(path);
  var findings = db.engine.verifyStructure().findings.length;
  final c = db.collection('orders');
  if (c == null) return findings + 1;
  for (var i = 0; i < 300; i++) {
    c.get(CNitriteId(i));
  }
  // The scan and the index lookup are separate decoders from the point read,
  // and the index entry's key encoding is a third.
  for (final _ in c.all) {
    findings += 0;
  }
  for (final (tree, _) in c.indexes) {
    for (final _ in c.lookup(tree, KeyRange(Uint8List(0), null))) {
      findings += 0;
    }
  }
  return findings;
}

void main() {
  test('the fixture has enough structure for a fuzz run to mean anything', () {
    final path = tmp('targets');
    final image = fixtureImage(path);
    final targets = fuzzTargets(image, 4096);
    // Two superblock slots plus a header and a payload head per headed page.
    expect(targets.length, greaterThan(20),
        reason: 'a fixture with no headed pages fuzzes nothing');
    expect(targets.map((x) => x.what).where((w) => w.contains('payload')).length,
        greaterThan(8));
  });

  test('a repaired checksum is what lets a mutation reach the decoder', () {
    // The control that makes the run above meaningful. `01-container.md` §3's
    // checksum is verified "before decompression and before decryption", so a
    // mutant with a stale checksum dies at the container gate and no decoder
    // sees a byte. This asserts the repair actually moves the population.
    final path = tmp('control');
    final image = fixtureImage(path);
    final targets = fuzzTargets(image, 4096);

    var reachedWithRepair = 0;
    var reachedWithout = 0;
    for (var seed = 1; seed <= 60; seed++) {
      final rng = FuzzRng(seed);
      final repaired = mutate(image, targets, rng, 4096);
      // The same mutation without the repair: recover it by restoring every
      // stale checksum, which is exactly what leaving the repair out does.
      final stale = Uint8List.fromList(repaired);
      for (var p = 2; p * 4096 < stale.length; p++) {
        if (!_pageDiffers(image, repaired, p, 4096)) continue;
        stale.setRange(p * 4096, p * 4096 + 4, image, p * 4096);
      }
      if (_opens(repaired, path)) reachedWithRepair++;
      if (_opens(stale, path)) reachedWithout++;
    }
    expect(reachedWithRepair, greaterThan(reachedWithout),
        reason: 'if the repair changes nothing, this fuzzer measures CRC-32C');
  });

  test('no mutant escapes the typed-error contract of §9.1', () {
    final path = tmp('run');
    final image = fixtureImage(path);
    final mutantPath = tmp('mutant');
    // `-Dcryptand.fuzz.iterations` / `.seeds` widen the run without editing
    // it: CI runs the default, a soak run passes them and gets hours.
    const iterations =
        int.fromEnvironment('cryptand.fuzz.iterations', defaultValue: 600);
    const seeds = int.fromEnvironment('cryptand.fuzz.seeds', defaultValue: 1);
    final report = FuzzReport();
    for (var s = 0; s < seeds; s++) {
      final one = fuzzImage(
        image: image,
        pageSize: 4096,
        iterations: iterations,
        seed: 0xF0FF + s * 7919,
        read: (m) => readEverything(m, mutantPath),
      );
      if (seeds > 1) print('seed ${0xF0FF + s * 7919}: $one');
      for (final o in FuzzOutcome.values) {
        report.counts[o] = report.counts[o]! + one.counts[o]!;
      }
      report.failures.addAll(one.failures);
    }
    printOnFailure(report.toString());
    // §9.1: "MUST fail with a typed corruption error rather than an allocation
    // failure, a panic, an abort, or an unbounded recursion." Every failure
    // this library raises is a `CryptandException`; anything else is the
    // violation, and the mutant that caused it is in the report so it can be
    // replayed.
    expect(report.failures, isEmpty,
        reason: report.failures.take(5).map((f) => f.detail).join('\n'));
    // A run in which nothing reached a decoder has measured nothing.
    expect(report.reachedReader, greaterThan(50),
        reason: 'too few mutants reached the reader: $report');
  });
}

bool _pageDiffers(Uint8List a, Uint8List b, int page, int pageSize) {
  final off = page * pageSize;
  for (var i = off + 4; i < off + pageSize && i < a.length; i++) {
    if (a[i] != b[i]) return true;
  }
  return false;
}

bool _opens(Uint8List image, String path) {
  File(path).writeAsBytesSync(image, flush: true);
  try {
    DatabaseFile.open(path);
    return true;
  } on CryptandException {
    return false;
  } catch (_) {
    return true; // reached the reader, and badly; the run below reports it
  }
}
