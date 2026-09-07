/// Backup — `spec/13-operations.md` §2.
///
/// The property the whole chapter rests on is immutability: "The source
/// database stays open and writable throughout. Nothing is locked; nothing is
/// quiesced. That falls out of immutability — every extent the backup reads is
/// one nothing will ever modify."
///
/// Three rules here are normative and two of them are security rules:
///
///   * a backup MUST NOT copy the source's `database_uuid` — two files sharing
///     one break incremental backup **and, on an encrypted file, share a
///     content key**, because `14-security.md` §3.4 derives subkeys with the
///     uuid as HKDF salt;
///   * the **ciphertext copy is the exception**, and for exactly that reason:
///     it is the *same* cryptographic object, so it must keep the same key
///     binding — and therefore MUST NOT be opened for writing while the source
///     is being written, since two writers allocating from one `next_nonce`
///     lineage collide;
///   * an unencrypted backup of an encrypted database is a **silent
///     downgrade**, and MUST be refused unless the caller asks for it by name.
library;

import 'dart:typed_data';

import 'engine.dart';
import 'errors.dart';
import 'manifest.dart';
import 'verify.dart';

/// §2.1's two modes for an encrypted source, plus the plain case.
enum BackupMode {
  /// The source is not encrypted.
  plaintext,

  /// Copy extents byte for byte. The backup needs the source's
  /// `database_uuid` and keyslots, so its uuid **cannot** change. For an
  /// untrusted destination — the backup tool never needs the key.
  ciphertextCopy,

  /// Decrypt and re-encrypt under a fresh master key and a new
  /// `database_uuid`. For a rotation, a compacting backup, or handing a copy
  /// to someone who should have a different credential.
  reEncrypted,

  /// An unencrypted copy of an encrypted database. §2.1: "a silent
  /// downgrade. An implementation MUST refuse it unless the caller asks for it
  /// by name, and MUST report it in the result."
  decryptedDowngrade,
}

final class BackupResult {
  const BackupResult({
    required this.mode,
    required this.segmentsCopied,
    required this.segmentsSkipped,
    required this.bytesCopied,
    required this.databaseUuid,
    required this.writers,
    required this.warnings,
    required this.verified,
  });

  final BackupMode mode;
  final int segmentsCopied;

  /// §2.2: an incremental backup copies "every segment whose id is absent from
  /// the destination's manifest" — these are the ones already there.
  final int segmentsSkipped;

  final int bytesCopied;
  final Uint8List databaseUuid;
  final List<String> writers;
  final List<String> warnings;

  /// §2.3: "An implementation MUST run the verification pass over a restored
  /// file before reporting success."
  final bool verified;

  @override
  String toString() => '${mode.name}: $segmentsCopied copied, '
      '$segmentsSkipped skipped, $bytesCopied B'
      '${warnings.isEmpty ? "" : "\n  !! ${warnings.join("\n  !! ")}"}';
}

/// §2.1 and §2.2.
final class Backup {
  Backup._();

  /// An online full backup, §2.1.
  ///
  /// [destination] must be a fresh engine. The source stays readable and
  /// writable throughout — nothing is locked and nothing is quiesced, because
  /// every extent the backup reads is immutable.
  static BackupResult full(
    Engine source,
    Engine destination, {
    BackupMode mode = BackupMode.plaintext,
    required Uint8List newUuid,
    String backupToolId = 'cryptand-backup',
    bool compacting = false,
    bool allowDowngrade = false,
  }) =>
      _copy(source, destination,
          mode: mode,
          newUuid: newUuid,
          backupToolId: backupToolId,
          compacting: compacting,
          allowDowngrade: allowDowngrade,
          incremental: false);

  /// An incremental backup, §2.2.
  ///
  /// "Because `segment_id` and `vlog_segment_id` are globally unique and never
  /// reused, an incremental backup is a set difference." Nothing diffs file
  /// contents; the destination's manifest already records which ids it holds.
  ///
  /// This is the property an LSM's immutable segments give and an in-place
  /// B-tree cannot: **the backup's size is proportional to what changed, not
  /// to what the changes touched.**
  static BackupResult incremental(
    Engine source,
    Engine destination, {
    BackupMode mode = BackupMode.plaintext,
    String backupToolId = 'cryptand-backup',
    bool allowDowngrade = false,
  }) =>
      _copy(source, destination,
          mode: mode,
          newUuid: destination.databaseUuid,
          backupToolId: backupToolId,
          compacting: false,
          allowDowngrade: allowDowngrade,
          incremental: true);

  static BackupResult _copy(
    Engine source,
    Engine destination, {
    required BackupMode mode,
    required Uint8List newUuid,
    required String backupToolId,
    required bool compacting,
    required bool allowDowngrade,
    required bool incremental,
  }) {
    final warnings = <String>[];

    if (mode == BackupMode.decryptedDowngrade && !allowDowngrade) {
      throw const InvalidArgumentException(
          'an unencrypted backup of an encrypted database is a silent '
          'downgrade and MUST be asked for by name '
          '(spec/13-operations.md section 2.1)');
    }
    if (mode == BackupMode.decryptedDowngrade) {
      warnings.add('the backup is UNENCRYPTED while the source is encrypted');
    }

    // §2.1's uuid rule, and its one exception.
    if (mode == BackupMode.ciphertextCopy) {
      destination.databaseUuid = Uint8List.fromList(source.databaseUuid);
      warnings.add(
          'ciphertext copy keeps the source database_uuid: it is the same '
          'cryptographic object. It MUST NOT be opened for writing while the '
          'source is being written — two writers allocating from one '
          'next_nonce lineage collide (spec/14-security.md section 4.1)');
    } else {
      if (_sameBytes(newUuid, source.databaseUuid)) {
        throw const InvalidArgumentException(
            'a backup MUST NOT copy the source database_uuid: two files '
            'sharing one break incremental backup and, on an encrypted file, '
            'share a content key (spec/13-operations.md section 2.1)');
      }
      destination.databaseUuid = Uint8List.fromList(newUuid);
    }

    // §2.1: "its `writers` list carried over plus the backup tool's id".
    final writers = [...source.writers];
    if (!writers.contains(backupToolId)) writers.add(backupToolId);
    destination.writers
      ..clear()
      ..addAll(writers);

    // The set difference of §2.2. For a full backup the destination is empty,
    // so every id is absent and everything is copied — one code path.
    final have = <int>{
      for (var l = 0; l <= destination.lastLevel; l++)
        for (final r in destination.refsAt(l)) r.segmentId
    };

    var copied = 0;
    var skipped = 0;
    var bytes = 0;
    final wanted = <int>{};

    for (var l = 0; l <= source.lastLevel; l++) {
      for (final ref in source.refsAt(l)) {
        wanted.add(ref.segmentId);
        if (have.contains(ref.segmentId)) {
          skipped++;
          continue;
        }
        final seg = source.extents[ref.segmentId]!;
        destination.extents[ref.segmentId] = seg;
        destination.manifest.add(SegmentRef.of(seg, level: l, group: ref.group));
        copied++;
        bytes += seg.extent.length;
      }
    }

    // §2.2: "Deleted segments are dropped from the destination's manifest and
    // their extents freed there."
    if (incremental) {
      for (var l = 0; l <= destination.lastLevel; l++) {
        for (final r in [...destination.refsAt(l)]) {
          if (!wanted.contains(r.segmentId)) {
            destination.manifest.remove(r);
            destination.extents.remove(r.segmentId);
          }
        }
      }
    }
    destination.clearLevelCache();
    destination.visibleSeq = source.visibleSeq;
    destination.commitId = source.commitId;

    if (compacting) {
      // §2.1: "A backup MAY compact as it copies... it is the recommended way
      // to reclaim space fully."
      destination.compact();
    }

    // §2.3: verify before reporting success.
    final report = destination.verifyStructure(deep: false);
    if (!report.isSound) {
      warnings.add('verification found ${report.findings.length} problems');
    }

    return BackupResult(
      mode: mode,
      segmentsCopied: copied,
      segmentsSkipped: skipped,
      bytesCopied: bytes,
      databaseUuid: destination.databaseUuid,
      writers: writers,
      warnings: warnings,
      verified: report.isSound,
    );
  }

  static bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
