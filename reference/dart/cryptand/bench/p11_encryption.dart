/// **P11 — the cost of encryption.**
///
/// `design/performance-model.md` §5: "With encryption enabled, sustained insert
/// and point-read throughput … stay within **5 %** of the unencrypted figures,
/// and **open latency rises by the Argon2id cost and nothing else**. *Measure:*
/// the full §8 matrix run twice, `cipher = 0` and `cipher = 1`, **reporting open
/// latency separately from steady-state throughput — averaging them together is
/// how an encryption overhead number becomes meaningless.**"
///
/// So the two halves are reported separately and never combined.
///
/// **What this can and cannot establish.** The steady-state half is a claim
/// about the ratio of cipher work to *storage* work, and this implementation
/// has no storage under it — extents are in memory (`REPORT.md` §5). A
/// pure-Dart XChaCha20 against an in-memory buffer is therefore the **worst
/// case for the prediction**, not the target case: on a real device the storage
/// is the slow part and the cipher hides behind it. What the numbers below do
/// establish is the cipher's cost per page in isolation, which is the quantity
/// a real device's ratio is computed *from*.
///
/// The open-latency half is measured directly and is portable, because
/// Argon2id's cost is CPU and memory by construction — that is what it is for.
library;

import 'dart:typed_data';

import 'package:cryptand/src/aead.dart';
import 'package:cryptand/src/argon2.dart';

import 'harness.dart';

const int kPageSize = 4096;

double _medianMs(int reps, void Function() body) =>
    medianMicros(reps, body) / 1000.0;

void main() {
  print('# P11 -- the cost of encryption\n');
  print('Two halves, reported separately, because §5 says averaging them');
  print('together is how an encryption overhead number becomes meaningless.\n');

  // ---------------------------------------------------------------------
  print('## 1. Open latency -- the Argon2id cost\n');
  print('`spec/14-security.md` §3.2 sets cost per profile and targets');
  print('~250 ms on a phone / ~500 ms on a desktop. This machine is neither,');
  print('so the figure to read is the SHAPE: cost tracks m_cost x t_cost, and');
  print('it is paid once per open.\n');
  print('| profile | t_cost | m_cost | p | measured |');
  print('| --- | --- | --- | --- | --- |');

  final password = 'correct horse battery staple'.codeUnits;
  final salt = Uint8List(32)..fillRange(0, 32, 0x5A);
  for (final p in <({String name, int t, int m, int lanes})>[
    (name: 'floor (§3.2 minimum)', t: 2, m: 16384, lanes: 1),
    (name: 'mobile', t: 3, m: 65536, lanes: 1),
    (name: 'tablet', t: 3, m: 131072, lanes: 2),
    (name: 'desktop / server', t: 4, m: 262144, lanes: 4),
  ]) {
    final ms = _medianMs(
        3,
        () => argon2id(
            password: password,
            salt: salt,
            memoryKiB: p.m,
            passes: p.t,
            parallelism: p.lanes));
    print('| ${p.name} | ${p.t} | ${p.m ~/ 1024} MiB | ${p.lanes} '
        '| ${ms.toStringAsFixed(0)} ms |');
  }
  print('');
  print('This is single-threaded: RFC 9106 lanes are parallelisable and this');
  print('implementation does not parallelise them, so a threaded SDK reaches');
  print('the same tag in less wall time at p > 1. The cost is a floor, not a');
  print('ceiling.\n');

  // ---------------------------------------------------------------------
  print('## 2. Steady state -- the per-page cipher cost\n');

  final key = Uint8List(32)..fillRange(0, 32, 0x2B);
  final nonce = Uint8List(24)..fillRange(0, 24, 0x11);
  final page = Uint8List(kPageSize - 40);
  for (var i = 0; i < page.length; i++) {
    page[i] = (i * 31) & 0xFF;
  }
  final aad = Uint8List(24);

  const reps = 200;
  const pagesPerRep = 64;

  final encMs = _medianMs(reps, () {
    for (var i = 0; i < pagesPerRep; i++) {
      xchacha20Poly1305Encrypt(
          key: key, nonce24: nonce, plaintext: page, aad: aad);
    }
  });
  final r = xchacha20Poly1305Encrypt(
      key: key, nonce24: nonce, plaintext: page, aad: aad);
  final decMs = _medianMs(reps, () {
    for (var i = 0; i < pagesPerRep; i++) {
      xchacha20Poly1305Decrypt(
          key: key,
          nonce24: nonce,
          ciphertext: r.ciphertext,
          tag: r.tag,
          aad: aad);
    }
  });

  final encPerPage = encMs * 1000 / pagesPerRep;
  final decPerPage = decMs * 1000 / pagesPerRep;
  final mbPerSec = (kPageSize / (encPerPage / 1e6)) / (1 << 20);

  print('| operation | per 4 KiB page | throughput |');
  print('| --- | --- | --- |');
  print('| encrypt + tag | ${encPerPage.toStringAsFixed(1)} us '
      '| ${mbPerSec.toStringAsFixed(0)} MiB/s |');
  print('| verify + decrypt | ${decPerPage.toStringAsFixed(1)} us '
      '| ${((kPageSize / (decPerPage / 1e6)) / (1 << 20)).toStringAsFixed(0)} MiB/s |');
  print('');
  print('P11 asks whether the cipher hides behind the storage. It does when');
  print('the device is slower than the number above. For reference:');
  print('');
  print('| storage | sequential | cipher is the bottleneck? |');
  print('| --- | --- | --- |');
  for (final s in <({String name, int mbs})>[
    (name: 'UFS 3.1 phone (write)', mbs: 700),
    (name: 'SATA SSD', mbs: 550),
    (name: 'NVMe Gen3', mbs: 3000),
    (name: 'NVMe Gen4', mbs: 7000),
  ]) {
    final bound = s.mbs > mbPerSec;
    print('| ${s.name} | ~${s.mbs} MiB/s | ${bound ? "**yes**" : "no"} |');
  }
  print('');
  print('Read that as a statement about THIS implementation, not about the');
  print('format: pure-Dart XChaCha20 with no SIMD is the slowest reasonable');
  print('implementation of the primitive. A Rust or Java SDK using a vectorised');
  print('ChaCha20 runs several times faster, which moves every row above.');
  print('P11 stays UNMEASURED against its own terms until it is run on a real');
  print('device with real storage; what is established here is the constant');
  print('that measurement will divide by.');
}
