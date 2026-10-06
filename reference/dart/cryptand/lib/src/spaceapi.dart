/// The compaction and space-management API — `spec/13-operations.md` §5.
///
/// §5 lists nine operations an implementation MUST expose, and closes with the
/// line that ties the chapter to `12-profiles.md`:
///
/// > "None may block longer than `max_foreground_stall_ms` per step."
///
/// That is now satisfiable rather than aspirational: `04-segments.md` §5.2's
/// stepwise compaction landed in phase 9, so every operation below that does
/// real merging is expressed as steps over a resumable job.
///
/// The key-management half is `14-security.md` §8: `add_key`/`remove_key` are
/// one superblock write and touch no data, and `crypto_erase` is the only
/// erase that means anything on flash.
library;

import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'engine.dart';
import 'errors.dart';
import 'security.dart';
import 'value.dart';

/// What one maintenance call did, so a caller pacing work can decide whether
/// to come back.
final class MaintenanceStep {
  const MaintenanceStep({required this.done, required this.bytesProcessed});

  /// False when there is more to do — call again.
  final bool done;
  final int bytesProcessed;

  @override
  String toString() =>
      '${done ? "done" : "more to do"}, $bytesProcessed B this step';
}

extension EngineSpaceApi on Engine {
  /// `compact(range?)`, §5 — full or ranged compaction to the last level.
  ///
  /// Incremental and resumable: each call does at most [budgetBytes] and
  /// reports whether more remains. `compact()` on [Engine] is the bulk form,
  /// which `12-profiles.md` §4 exempts from the stall budget because the
  /// caller asked for it.
  MaintenanceStep compactStep({int? budgetBytes}) {
    final budget = budgetBytes ?? compactionStepBytes;
    final before = _totalMerged(this);
    flush();
    maybeCompact(budgetBytes: budget);
    final done = !hasPendingCompaction && _levelsSettled(this);
    return MaintenanceStep(
        done: done, bytesProcessed: _totalMerged(this) - before);
  }

  /// `collect()`, §5 — a value-log GC pass (`04-segments.md` §6.8).
  MaintenanceStep collect() {
    final before = vlog.allocatedBytes;
    vlog
      ..sealOpen()
      ..reclaimEmpty(referenced: referencedVlogSegments);
    return MaintenanceStep(
        done: true, bytesProcessed: before - vlog.allocatedBytes);
  }

  /// `cluster()`, §5 — drive `locality_debt` back under its bound
  /// (`04-segments.md` §6.9).
  MaintenanceStep cluster() {
    final before = vlog.localityDebt;
    collectWhileOverDebt(maxPasses: 1);
    return MaintenanceStep(
      done: vlog.localityDebt * 100 <= localityDebtPct,
      bytesProcessed: ((before - vlog.localityDebt) * vlog.allocatedBytes).round().abs(),
    );
  }

  /// `shrink()`, §5 — relocate live extents downward and truncate.
  ///
  /// Reports what *would* be reclaimed. This implementation holds extents in
  /// memory with no file under them (`REPORT.md` §5), so there is nothing to
  /// truncate; the number is the orphaned page count the free tree would own.
  MaintenanceStep shrink() => MaintenanceStep(
        done: true,
        bytesProcessed: store.freedPages * store.pageSize,
      );

  /// `add_key()`, §5 and `14-security.md` §3.3 — one superblock write, no data
  /// touched.
  Keyslot addKey({
    required Uint8List masterKey,
    required Uint8List kek,
    required int slotIndex,
    required Uint8List wrapNonce,
    required Uint8List salt,
    int kdf = Keyslot.kdfArgon2id,
    int tCost = 3,
    int mCostKib = 65536,
    int parallelism = 1,
    String label = 'password',
  }) =>
      wrapMasterKey(
        masterKey: masterKey,
        kek: kek,
        databaseUuid: databaseUuid,
        slotIndex: slotIndex,
        wrapNonce: wrapNonce,
        salt: salt,
        kdf: kdf,
        tCost: tCost,
        mCostKib: mCostKib,
        parallelism: parallelism,
        label: label,
      );

  /// `remove_key()`, §5.
  ///
  /// **§3.3: an implementation MUST refuse to remove the last occupied slot
  /// while `cipher ≠ 0`** — that is crypto-erase, "and it MUST be asked for by
  /// name". Removing the last key by accident destroys the database, so the
  /// two operations are deliberately not the same call.
  Uint8List removeKey(Uint8List keyslotArea, int slotIndex,
      {required bool encrypted}) {
    final occupied = <int>[];
    for (var i = 0; i < Sb.keyslotCount; i++) {
      final raw = Uint8List.sublistView(
          keyslotArea, i * Keyslot.size, (i + 1) * Keyslot.size);
      if (Keyslot.decode(raw, i).state == Keyslot.occupied) occupied.add(i);
    }
    if (!occupied.contains(slotIndex)) {
      throw InvalidArgumentException('keyslot $slotIndex is not occupied');
    }
    if (encrypted && occupied.length == 1) {
      throw const InvalidArgumentException(
          'refusing to remove the last occupied keyslot of an encrypted '
          'database: that is crypto_erase, and it must be asked for by name '
          '(spec/14-security.md section 3.3)');
    }
    final out = Uint8List.fromList(keyslotArea);
    out.fillRange(slotIndex * Keyslot.size, (slotIndex + 1) * Keyslot.size, 0);
    return out;
  }

  /// `crypto_erase()`, §5 and `14-security.md` §8.2 — zero every keyslot in
  /// **both** superblock slots. Irreversible.
  ///
  /// §14 §8.2's argument for why this is the only erase that means anything:
  /// on flash, overwriting a page does not overwrite the cell it used to
  /// occupy, so destroying the wrapped key is the erase that holds.
  Uint8List cryptoErase(Uint8List keyslotArea) =>
      Uint8List(keyslotArea.length);
}

bool _levelsSettled(Engine e) {
  if (e.refsAt(0).length >= e.levels.l0Trigger) return false;
  for (var l = 1; l < e.lastLevel; l++) {
    if (e.refsAt(l).length > e.levels.tierWidth ||
        e.groupsAt(l).length > e.levels.overlapBound) {
      return false;
    }
  }
  return true;
}

int _totalMerged(Engine e) => e.vlog.allocatedBytes;

/// Re-exported so callers of the space API do not need a second import.
Uint8List ckeOf(CValue v) => encodeKey(v);
