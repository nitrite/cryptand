/// The verification pass — `spec/01-container.md` §9 and the invariants of
/// `spec/04-segments.md` §11.
///
/// **Verification reports; it does not fix.** `13-operations.md` §3 is repair,
/// and §4 is containment. A verifier that throws on the first problem is not
/// one: the point is a complete list of what is wrong and precisely which key
/// ranges it affects.
///
/// Two of §11's invariants are here because the reference implementation
/// violated them and nothing caught it:
///
///   * **§11.6** — "segments at the last level do not overlap". Phase 5 found
///     the last level had *silently* stopped being disjoint, returning stale
///     versions under 338 passing tests, because the compaction's overlap test
///     compared internal keys rather than user keys (`04-segments.md` §3.1.1).
///     This check is what would have caught it.
///   * **§11.5** — the manifest entry matches the segment header on every
///     duplicated field. `13-operations.md` §3: "A verifier MUST check
///     header-against-manifest agreement on every duplicated field, or the
///     redundancy rots unnoticed until the day it is needed" — the day being
///     the one where the manifest is damaged and has to be rebuilt from the
///     headers.
library;

import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'errors.dart';
import 'security.dart';
import 'engine.dart';
import 'manifest.dart';
import 'segment.dart';
import 'vlog.dart';

/// What a finding *means*, which decides what may be done about it.
///
/// `spec/01-container.md` section 9 states the taxonomy in two sentences and
/// both are load-bearing: "A leak is repairable. A double-allocation is
/// corruption. **A failed AEAD tag or `sb_mac` is neither** — it is tampering,
/// and MUST be reported as its own class (`14-security.md` section 6.2),
/// because 'your disk has a bad sector' and 'someone edited your database' call
/// for different responses."
///
/// This implementation had no class at all until the shared conformance corpus
/// asked three readers the same question. Every finding was a bare string, so a
/// caller could not tell a reclaimable page from a tampered one, and
/// `13-operations.md` section 3's rule — repair runs over corruption and MUST
/// NOT run over tampering — was not expressible.
enum FindingClass {
  /// A checksum mismatch, a broken invariant, a double-allocation.
  corruption,

  /// A failed AEAD tag or `sb_mac`. Never repaired: repairing tampered data is
  /// laundering it.
  tampering,

  /// A page neither reachable nor free. Costs space and nothing else, and
  /// `13-operations.md` section 3 reclaims it.
  leak,

  /// A bound exceeded that the format permits exceeding — a locality debt over
  /// its target, say. Not a defect in the file.
  warning,
}

/// One thing a verifier found.
final class Finding {
  const Finding(this.invariant, this.message,
      {this.segmentId, this.kind = FindingClass.corruption});

  /// The §11 invariant number, or a `01` §9 step.
  final String invariant;
  final String message;
  final int? segmentId;
  final FindingClass kind;

  @override
  String toString() => '[$invariant/${kind.name}]'
      '${segmentId != null ? " seg $segmentId" : ""} $message';
}

/// What one verification pass found. Empty means clean.
final class VerifyReport {
  VerifyReport(this.findings, this.segmentsChecked, this.entriesChecked);

  final List<Finding> findings;
  final int segmentsChecked;
  final int entriesChecked;

  /// Findings of one class.
  List<Finding> of(FindingClass c) =>
      [for (final f in findings) if (f.kind == c) f];

  /// Nothing at all was found — including leaks and warnings.
  bool get isClean => findings.isEmpty;

  /// **The file is sound**, which is the question a caller usually has.
  ///
  /// A leak is not a damaged file; it is wasted space in a sound one, and
  /// section 9 says so. A verifier that reported them alongside corruption made
  /// a file with a few orphaned pages look like damage. (Tree 1's own pages
  /// were leaked by every save until it was rebuilt rather than edited; see
  /// `CowTree.rebuildFresh`.)
  bool get isSound =>
      of(FindingClass.corruption).isEmpty && of(FindingClass.tampering).isEmpty;

  @override
  String toString() => isClean
      ? 'clean: $segmentsChecked segments, $entriesChecked entries'
      : '${findings.length} findings over $segmentsChecked segments:\n'
          '${findings.join("\n")}';
}

/// Runs `spec/04-segments.md` §11 over an engine's live segments.
extension EngineVerify on Engine {
  /// Verifies structure. [deep] also walks every entry of every segment,
  /// which is what invariants 1, 3, 4, 5 and 7 need.
  VerifyReport verifyStructure({bool deep = true}) {
    final f = <Finding>[];
    var segs = 0;
    var entries = 0;

    final byLevel = <int, List<SegmentRef>>{};
    for (var l = 0; l <= lastLevel; l++) {
      byLevel[l] = refsAt(l);
    }

    for (final entry in byLevel.entries) {
      for (final ref in entry.value) {
        final seg = extents[ref.segmentId];
        if (seg == null) {
          f.add(Finding('01§9.2',
              'manifest names segment ${ref.segmentId} with no extent',
              segmentId: ref.segmentId));
          continue;
        }
        segs++;

        // 01 §9 step 2: page checksums.
        try {
          seg.verifyChecksums();
        } on Exception catch (e) {
          f.add(Finding('01§9.2', 'checksum failure: $e',
              segmentId: ref.segmentId));
          continue; // nothing below can be trusted
        }

        _checkHeaderAgainstManifest(f, ref, seg, entry.key);
        if (deep) entries += _checkContents(f, ref, seg);
      }
    }

    _checkDisjointness(f, byLevel);
    _checkLocalityDebt(f);
    _checkPageAccounting(f);
    return VerifyReport(f, segs, entries);
  }

  /// `spec/01-container.md` section 9 step 7 — "reconciles reachable pages
  /// against the free tree and reports leaks (neither reachable nor free) and
  /// double-allocations".
  ///
  /// This step did not exist. The Java and Rust implementations both had it,
  /// and the shared conformance corpus is what made that visible: Java reported
  /// nine leaked pages in a file this implementation wrote and called clean.
  /// Nine is the count `design/tradeoff-analysis.md` defect 55 predicts — tree
  /// 1's own pages, leaked by one commit, a property of the format rather than
  /// of the writer — so the file was in fact fine and the verifier that said so
  /// was the one that could not have said otherwise.
  ///
  /// A double-allocation is the finding that matters here and it is corruption:
  /// two live structures naming one page means one of them is about to be
  /// overwritten by a write to the other.
  void _checkPageAccounting(List<Finding> f) {
    final owner = <int, String>{};
    void claim(Iterable<int> pages, String what) {
      for (final p in pages) {
        final prior = owner[p];
        if (prior != null) {
          f.add(Finding('01§9.7', 'page $p is claimed by both $prior and $what',
              kind: FindingClass.corruption));
          continue;
        }
        owner[p] = what;
      }
    }

    final trees = <(CowTree, String)>[
      (manifest.tree, 'the manifest'),
      (freelist, 'the free tree'),
      (checkpoints.tree, 'the checkpoint tree'),
      (changeFeed.tree, 'the change feed'),
      for (final MapEntry(key: name, value: tree) in outerTrees.entries)
        (tree, name),
    ];
    for (final (tree, name) in trees) {
      try {
        claim(tree.reachablePages(), name);
      } on CryptandException catch (e) {
        f.add(Finding('01§9.7', '$name is not walkable: ${e.runtimeType}',
            kind: FindingClass.corruption));
      }
    }
    // `startPage` and `pages` come out of the file and are untrusted. Yielding
    // them lazily and refusing an extent that runs past the end of the file is
    // section 9.1's "bounds-check ... **before allocating**": the materialized
    // form below built one list element per declared page, so a manifest entry
    // claiming 0xFFFFFFFF pages asked for a 32 GiB list before anything looked
    // at it. That is the same hazard the leak report at the end of this method
    // already caps itself against, reached by two callers it did not cover.
    Iterable<int> extentPages(int startPage, int pages, String what) sync* {
      final limit = store.pageCount;
      if (pages < 0 ||
          startPage < 0 ||
          pages > limit ||
          startPage > limit ||
          startPage + pages > limit) {
        f.add(Finding(
            '01§9.7',
            '$what claims $pages pages from $startPage, '
            'but the file holds $limit',
            kind: FindingClass.corruption));
        return;
      }
      for (var i = 0; i < pages; i++) {
        yield startPage + i;
      }
    }

    for (final ref in manifest.all) {
      if (ref.startPage == 0 || ref.pages == 0) continue;
      claim(extentPages(ref.startPage, ref.pages, 'segment ${ref.segmentId}'),
          'segment ${ref.segmentId}');
    }
    for (final seg in vlog.segments.values) {
      if (seg.startPage == 0) continue;
      claim(
          extentPages(seg.startPage, seg.pageCount,
              'value-log segment ${seg.id}'),
          'value-log segment ${seg.id}');
    }

    final free = <int>{};
    for (final e in store.freeExtents) {
      // F-114: the free list is the file's word too.
      free.addAll(extentPages(e.startPage, e.pages, 'free extent'));
    }
    // Pages 0 and 1 are the superblock slots, reserved before anything is
    // allocated and owned by no tree.
    //
    // **The findings are capped.** `page_count` comes out of the file, and one
    // finding per leaked page means a hostile superblock claiming four billion
    // pages drives the verifier into four billion allocations — section 9.1's
    // "MUST NOT ... allocate unboundedly" applies to the verifier's own output,
    // not only to its decoders. The count is exact either way; only the list of
    // page ids is bounded, and the page ids are the part that repeats.
    const maxListed = 64;
    var leaked = 0;
    for (var p = 2; p < store.pageCount; p++) {
      if (owner.containsKey(p) || free.contains(p)) continue;
      leaked++;
      if (leaked <= maxListed) {
        f.add(Finding('01§9.7', 'page $p is neither reachable nor free',
            kind: FindingClass.leak));
      }
    }
    if (leaked > maxListed) {
      f.add(Finding('01§9.7',
          '$leaked pages are neither reachable nor free; '
          'the first $maxListed are listed above',
          kind: FindingClass.leak));
    }
  }

  /// §11.5 — the manifest entry matches the header on every duplicated field.
  void _checkHeaderAgainstManifest(
      List<Finding> f, SegmentRef ref, Segment seg, int level) {
    final h = seg.header;
    void ne(String field, Object a, Object b) {
      if (a != b) {
        f.add(Finding('11.5', '$field: manifest $a, header $b',
            segmentId: ref.segmentId));
      }
    }

    ne('segment_id', ref.segmentId, h.segmentId);
    ne('level', level, h.level);
    // `group` is in the header for no other reason than this: it is part of
    // the manifest key and nothing else would recover it after a rebuild.
    ne('group', ref.group, h.group);
    ne('min_seq', ref.minSeq, h.minSeq);
    ne('max_seq', ref.maxSeq, h.maxSeq);
    ne('entries', ref.entries, h.entryCount);
    ne('tombstones', ref.tombstones, h.tombstoneCount);
    ne('min_expiry', ref.minExpiry, h.minExpiry);
    ne('range_deletes', ref.hasRangeDeletes, h.hasRangeDeletes);
    if (compareKeys(ref.minKey, h.minKey) != 0) {
      f.add(Finding('11.5', 'min_key differs between manifest and header',
          segmentId: ref.segmentId));
    }
    if (compareKeys(ref.maxKey, h.maxKey) != 0) {
      f.add(Finding('11.5', 'max_key differs between manifest and header',
          segmentId: ref.segmentId));
    }
  }

  /// Invariants 1, 3, 4, 5 and 7 over a segment's entries.
  int _checkContents(List<Finding> f, SegmentRef ref, Segment seg) {
    final h = seg.header;
    Uint8List? prev;
    var n = 0;
    var minSeq = -1;
    var maxSeq = 0;
    var minExpiry = 0;
    var tombstones = 0;

    final c = seg.cursor()..seekFirst();
    while (c.isValid) {
      final k = c.key();
      // §11.1: internal keys strictly increase within and across pages.
      if (prev != null && compareKeys(prev, k) >= 0) {
        f.add(Finding('11.1', 'keys are not strictly increasing at entry $n',
            segmentId: ref.segmentId));
      }
      prev = k;
      n++;

      final p = parseInternalKey(k);
      if (minSeq < 0 || p.seq < minSeq) minSeq = p.seq;
      if (p.seq > maxSeq) maxSeq = p.seq;
      if (p.op == Op.delete) tombstones++;

      // §11.7: every key in a segment passes that segment's filter. A false
      // negative here is a LOST KEY, not a slow lookup.
      final filter = seg.filter;
      if (filter != null) {
        final user = Uint8List.sublistView(k, 0, k.length - 9);
        if (!filter.mayContain(user)) {
          f.add(Finding('11.7',
              'filter false negative at entry $n — a key that is present '
              'would not be found', segmentId: ref.segmentId));
        }
      }

      final rec = c.record();
      if (rec.expiryMs != null) {
        if (minExpiry == 0 || rec.expiryMs! < minExpiry) {
          minExpiry = rec.expiryMs!;
        }
      }

      // §11.8: every VLOG pointer resolves to a record whose stored key
      // matches. A dangling pointer is the failure mode no checksum catches,
      // because the key side is intact.
      if (rec.valueKind == ValueKind.vlog) {
        try {
          vlog.readValue(VlogPointer.decode(rec.value));
        } on Exception catch (e) {
          f.add(Finding('11.8', 'VLOG pointer does not resolve at entry $n: $e',
              segmentId: ref.segmentId));
        }
      }
      c.next();
    }

    // §11.5: min_seq/max_seq/min_expiry match contents; min_key/max_key BOUND
    // them (§2.1 permits shortening, so equality is not required).
    if (n > 0) {
      if (h.minSeq != minSeq) {
        f.add(Finding('11.5', 'header min_seq ${h.minSeq} != actual $minSeq',
            segmentId: ref.segmentId));
      }
      if (h.maxSeq != maxSeq) {
        f.add(Finding('11.5', 'header max_seq ${h.maxSeq} != actual $maxSeq',
            segmentId: ref.segmentId));
      }
      if (h.minExpiry != minExpiry) {
        f.add(Finding('11.5',
            'header min_expiry ${h.minExpiry} != actual $minExpiry',
            segmentId: ref.segmentId));
      }
      if (h.entryCount != n) {
        f.add(Finding('11.3', 'header entry_count ${h.entryCount} != actual $n',
            segmentId: ref.segmentId));
      }
      if (h.tombstoneCount != tombstones) {
        f.add(Finding('11.5',
            'header tombstones ${h.tombstoneCount} != actual $tombstones',
            segmentId: ref.segmentId));
      }
    }
    return n;
  }

  /// §11.6 — segments at the last level do not overlap; segments within one
  /// tiered level-group do not overlap.
  ///
  /// **On user keys.** `04-segments.md` §3.1.1: an internal key carries `~seq`,
  /// so two segments holding different versions of one key occupy disjoint
  /// internal-key ranges and an internal-key test reports them as fine. That
  /// is precisely the defect this check exists to catch.
  void _checkDisjointness(List<Finding> f, Map<int, List<SegmentRef>> byLevel) {
    Uint8List low(Uint8List b) =>
        b.length >= 13 ? Uint8List.sublistView(b, 0, b.length - 9) : b;

    for (final entry in byLevel.entries) {
      final level = entry.key;
      final groups = <int, List<SegmentRef>>{};
      for (final r in entry.value) {
        (groups[r.group] ??= []).add(r);
      }
      // L0 is explicitly overlapping (§3.1), so it is exempt.
      if (level == 0) continue;

      for (final g in groups.entries) {
        final refs = [...g.value]
          ..sort((a, b) => compareKeys(low(a.minKey), low(b.minKey)));
        for (var i = 1; i < refs.length; i++) {
          final prev = refs[i - 1];
          final cur = refs[i];
          if (compareKeys(low(cur.minKey), prev.maxKey) <= 0) {
            f.add(Finding(
                '11.6',
                'segments ${prev.segmentId} and ${cur.segmentId} overlap in '
                'user keys at level $level group ${g.key}'
                '${level == lastLevel ? " (the levelled level MUST be disjoint)" : ""}',
                segmentId: cur.segmentId));
          }
        }
      }
    }
  }

  /// `spec/01-container.md` §9 step 8 — "when the file is encrypted **and a
  /// key is supplied**, verifies `sb_mac`, every page's AEAD tag, and that no
  /// `(key, nonce)` pair occurs twice anywhere in the file".
  ///
  /// It exists because the other implementation's verifier is what caught the
  /// last defect here: a superblock whose `sb_mac` no longer described its own
  /// fields opened, read and verified perfectly on this side, because this
  /// side did not look. A verifier that checks less than the format specifies
  /// is a verifier that certifies whatever it happens to implement.
  List<Finding> verifyEncryption() {
    final f = <Finding>[];
    final sb = superblock;
    final ring = keys;
    if (sb == null || sb.cipher == 0 || ring == null) return f;
    try {
      verifySuperblockMac(ring.macKey, sb.encode());
    } on TamperException catch (e) {
      f.add(Finding('01 §9.8', e.message));
    }
    // Every page's tag, and §4's uniqueness over the nonces they carry. A
    // repeated `(key, nonce)` "discloses their XOR and leaks the Poly1305
    // authentication key, which turns tampering detection off" — so it is
    // checked over the whole page space, not sampled.
    final seen = <int>{};
    for (var p = 2; p < store.pageCount; p++) {
      final Uint8List raw;
      try {
        raw = store.readClear(p);
      } on CryptandException {
        continue;
      }
      if (raw.every((b) => b == 0)) continue;
      final PageHeader h;
      try {
        h = PageHeader.read(raw, pageId: p);
      } on CryptandException {
        continue; // an interior extent page carries no header (§3)
      }
      if (!h.isEncrypted) continue;
      if (!seen.add(h.nonce)) {
        f.add(Finding('14 §4', 'nonce ${h.nonce} is used by more than one page',
            segmentId: null));
      }
      try {
        store.read(p); // decrypts, which is the tag check
      } on TamperException catch (e) {
        f.add(Finding('01 §9.8', 'page $p: ${e.message}'));
      } on CryptandException {
        // A checksum failure is corruption and belongs to step 2, which has
        // already reported it; §9 is explicit that the two are not the same
        // class.
      }
    }
    return f;
  }

  /// §11.11 — `locality_debt` is at or below `locality_debt_pct`.
  void _checkLocalityDebt(List<Finding> f) {
    final debt = vlog.localityDebt * 100;
    if (debt > localityDebtPct) {
      f.add(Finding('11.11',
          'locality_debt ${debt.toStringAsFixed(1)}% exceeds '
          'locality_debt_pct $localityDebtPct%'));
    }
  }
}
