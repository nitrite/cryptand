/// `spec/14-security.md` section 9.3 — structure-aware fuzzing of the reader.
///
/// > "A parser for a format read from untrusted sources that has never been
/// > fuzzed is not finished."
///
/// The rule names `cryptand fuzz` for the reference implementation "**and an
/// equivalent for each SDK**", so this is Dart's. Two things about it are not
/// obvious and are the reason it finds anything:
///
///  * **Structure-aware.** Most of a database's bytes are unused value-log
///    record space and page tail padding, so uniform bit flips land where no
///    decoder ever looks. The targets here are the fields a hostile file would
///    actually edit: the two superblock slots, every page header, and the head
///    of every payload behind one.
///
///  * **The checksum is repaired after the mutation.** A fuzzer that mutates a
///    checksummed page and leaves the checksum alone measures CRC-32C and
///    nothing else — every payload mutation dies at the gate of
///    `01-container.md` section 3 before a decoder sees a byte. Measured on the
///    Rust implementation, repairing the checksum moves 58 % of mutations from
///    "refused at open" to "reached the reader", which is the whole population
///    this rule is about. `14-security.md` section 9.4 is the same point from
///    the other side: CRC "is trivially recomputed by anyone who edits the
///    file", so an attacker's file always has a valid one.
///
/// The oracle is [CryptandException]. Every failure this library raises is a
/// member of that sealed class, so anything else reaching the caller — a
/// `RangeError`, a `StateError`, an `OutOfMemoryError`, a stack overflow — is a
/// section 9.1 violation: "MUST fail with a typed corruption error rather than
/// an allocation failure, a panic, an abort, or an unbounded recursion."
library;

import 'dart:typed_data';

import 'package:cryptand/src/container.dart';
import 'package:cryptand/src/crc32c.dart';
import 'package:cryptand/src/errors.dart';

/// What one mutant did to the reader.
enum FuzzOutcome {
  /// The reader refused it with a typed [CryptandException]. The good case.
  refused,

  /// The reader opened it and its verifier named a finding. Also good.
  reported,

  /// The reader accepted it and reported nothing. Not a failure: an
  /// unencrypted file has no tamper detection at all (section 9.4), and a
  /// mutation in a reserved byte or an unread field changes nothing a reader
  /// may act on.
  benign,

  /// The reader threw something outside [CryptandException]. A section 9.1
  /// violation.
  untyped,

  /// The reader did not return inside the budget.
  hung,
}

final class FuzzFinding {
  const FuzzFinding(this.outcome, this.detail, this.mutant);

  final FuzzOutcome outcome;
  final String detail;

  /// The bytes that produced it, so a finding can be replayed.
  final Uint8List mutant;

  @override
  String toString() => '${outcome.name}: $detail';
}

final class FuzzReport {
  final Map<FuzzOutcome, int> counts = {for (final o in FuzzOutcome.values) o: 0};
  final List<FuzzFinding> failures = [];

  int get iterations => counts.values.fold(0, (a, b) => a + b);

  /// Section 9.3 passes only if nothing escaped the typed-error contract.
  bool get clean => failures.isEmpty;

  /// A run in which nothing reached a decoder has measured nothing — the same
  /// "control that cannot fail" this project has met repeatedly. If almost
  /// every mutant is refused at the container gate, the targets are wrong.
  int get reachedReader => counts[FuzzOutcome.reported]! + counts[FuzzOutcome.benign]!;

  @override
  String toString() {
    final c = counts;
    return 'fuzz: $iterations mutants, '
        '${c[FuzzOutcome.refused]} refused, '
        '${c[FuzzOutcome.reported]} reported, '
        '${c[FuzzOutcome.benign]} benign, '
        '${c[FuzzOutcome.untyped]} UNTYPED, '
        '${c[FuzzOutcome.hung]} HUNG';
  }
}

/// A byte range a hostile file would plausibly edit.
final class FuzzTarget {
  const FuzzTarget(this.offset, this.length, this.what);
  final int offset;
  final int length;
  final String what;
}

/// xorshift64. Deterministic on purpose: a fuzz failure that cannot be
/// replayed from its seed is a bug report nobody can act on.
final class FuzzRng {
  FuzzRng(int seed) : _s = seed == 0 ? 0x243F6A8885A308D3 : seed;
  int _s;

  int next() {
    _s ^= (_s << 13) & 0xFFFFFFFFFFFFFFFF;
    _s ^= _s >>> 7;
    _s ^= (_s << 17) & 0xFFFFFFFFFFFFFFFF;
    return _s;
  }

  int below(int n) => n <= 0 ? 0 : next().toUnsigned(63) % n;
}

/// Derives the target list from [image]: the two superblock slots, then every
/// page that carries a header (`01-container.md` section 3) plus the head of
/// its payload.
///
/// Interior pages of a multi-page extent carry no header, and section 3 says a
/// verifier "MUST NOT report a missing page header on them as corruption" — so
/// a page whose header does not parse is skipped rather than treated as a
/// target, which is also why the count is a meaningful signal.
List<FuzzTarget> fuzzTargets(Uint8List image, int pageSize) {
  final t = <FuzzTarget>[
    const FuzzTarget(0, 4096, 'superblock slot A'),
  ];
  if (image.length >= pageSize + 4096) {
    t.add(FuzzTarget(pageSize, 4096, 'superblock slot B'));
  }
  final pages = image.length ~/ pageSize;
  for (var p = 2; p < pages; p++) {
    final off = p * pageSize;
    final PageHeader h;
    try {
      h = PageHeader.read(Uint8List.sublistView(image, off, off + pageSize),
          pageId: p);
    } on CryptandException {
      continue;
    }
    if (h.pageType == PageType.free || h.payloadLen == 0) continue;
    t.add(FuzzTarget(off, PageHeader.size, 'page $p header'));
    final n = h.payloadLen < 256 ? h.payloadLen : 256;
    if (off + PageHeader.size + n <= image.length) {
      t.add(FuzzTarget(off + PageHeader.size, n, 'page $p payload head'));
    }
  }
  return t;
}

/// Applies one mutation set to a copy of [image] and repairs the checksum of
/// every page it touched.
///
/// The mutations are the four an editor of a hostile file actually makes: a
/// bit flip, a byte to `0x00`, a byte to `0xFF`, and a run of `0xFF` — the last
/// one because a length field only becomes an allocation bomb when *all* its
/// bytes are set, and a single flipped bit almost never does that.
Uint8List mutate(Uint8List image, List<FuzzTarget> targets, FuzzRng rng,
    int pageSize) {
  final b = Uint8List.fromList(image);
  final touched = <int>{};
  final n = 1 + rng.below(4);
  for (var i = 0; i < n; i++) {
    final t = targets[rng.below(targets.length)];
    final at = t.offset + rng.below(t.length < 1 ? 1 : t.length);
    if (at >= b.length) continue;
    switch (rng.below(4)) {
      case 0:
        b[at] ^= 1 << rng.below(8);
      case 1:
        b[at] = 0x00;
      case 2:
        b[at] = 0xFF;
      default:
        final w = 1 + rng.below(8);
        for (var k = 0; k < w && at + k < b.length; k++) {
          b[at + k] = 0xFF;
        }
    }
    touched.add(at ~/ pageSize);
  }
  // Section 3: `checksum` is CRC-32C over bytes 4..page_size-1 as stored. The
  // superblock slots (pages 0 and 1) have their own rule and are left alone;
  // a mutation there is meant to be caught, and is.
  for (final p in touched) {
    if (p < 2) continue;
    repairChecksum(b, p, pageSize);
  }
  return b;
}

/// Recomputes the section 3 checksum of page [page] in [image], in place.
///
/// Anything that edits a page and wants the edit to reach a *decoder* has to
/// call this, because section 3's checksum "verifies before decompression and
/// before decryption" — an edit that leaves it stale is caught at the container
/// gate and nothing behind it ever runs. That is true of a fuzzer's mutation
/// and equally of a deliberately-corrupt conformance file, which is why this is
/// shared rather than written twice.
///
/// Uses [PageHeader.checksumEnd], not `page_size`: a value-log head page
/// checksums only its immutable header region, because records are appended
/// into its tail for the life of the segment. A repair that covers the whole
/// page writes a checksum that is wrong the moment it is written.
void repairChecksum(Uint8List image, int page, int pageSize) {
  final off = page * pageSize;
  if (off + pageSize > image.length) return;
  final p = Uint8List.sublistView(image, off, off + pageSize);
  final c = crc32c(p, 4, PageHeader.checksumEnd(p, p[4]));
  image[off] = c & 0xFF;
  image[off + 1] = (c >>> 8) & 0xFF;
  image[off + 2] = (c >>> 16) & 0xFF;
  image[off + 3] = (c >>> 24) & 0xFF;
}

/// Runs [read] against [iterations] mutants of [image] and classifies each.
///
/// [read] MUST open the mutant, verify it, and read every document in it —
/// **all three**. Verification alone is not enough: it walks structure and
/// checksums, and the decoders that turn bytes into values (CVE, CKE, the
/// value-log record, an index entry) only run when something reads. It should
/// return the number of findings its verifier named, or throw.
FuzzReport fuzzImage({
  required Uint8List image,
  required int pageSize,
  required int Function(Uint8List mutant) read,
  int iterations = 500,
  int seed = 0xF0FF,
}) {
  final targets = fuzzTargets(image, pageSize);
  if (targets.length <= 2) {
    throw InvalidArgumentException(
        'the image holds no headed pages to fuzz; the fixture has too little '
        'structure for this to measure anything');
  }
  final rng = FuzzRng(seed);
  final report = FuzzReport();
  for (var i = 0; i < iterations; i++) {
    final mutant = mutate(image, targets, rng, pageSize);
    FuzzOutcome outcome;
    var detail = '';
    try {
      final findings = read(mutant);
      outcome = findings == 0 ? FuzzOutcome.benign : FuzzOutcome.reported;
    } on CryptandException {
      outcome = FuzzOutcome.refused;
    } catch (e, st) {
      // Section 9.1: anything outside the sealed class is the violation. The
      // stack is kept because the mutant alone does not say which decoder let
      // it through, and a fuzz finding nobody can locate is not actionable.
      outcome = FuzzOutcome.untyped;
      detail = '${e.runtimeType}: $e\n'
          '${st.toString().split('\n').take(6).join('\n')}';
    }
    report.counts[outcome] = report.counts[outcome]! + 1;
    if (outcome == FuzzOutcome.untyped || outcome == FuzzOutcome.hung) {
      report.failures.add(FuzzFinding(outcome, detail, mutant));
    }
  }
  return report;
}
