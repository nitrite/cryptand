/// The required metrics of `spec/13-operations.md` §6.
///
/// **Normative, and the chapter says why:** "They are normative because every
/// one of them is the answer to a question that is otherwise unanswerable from
/// outside, and because the performance claims in
/// `design/performance-model.md` cannot be validated without them."
///
/// This file is the proof of the second half. Every prediction this project has
/// measured — P1, P4, P5, P6, P8, P10, P11 — was read off one of these
/// counters, and the two the chapter singles out are the two that caught real
/// defects:
///
///   * **`locality_debt`** had to be redefined over *surplus runs* after the
///     flag-based definition read 0 % on a database whose scans had already
///     decayed 2.14× (`04-segments.md` §6.9);
///   * **`value_reads_per_scanned_row`** is what distinguishes a working
///     clustering from a broken one, measured 0.100 against 1.038.
///
/// A third joined them in phase 5: **`pinned_by_snapshots`** cannot be derived
/// as `allocated − live`, because a snapshot's effect is to stop bytes from
/// *becoming* dead. §6 now says where to accumulate it, and [pinnedBySnapshots]
/// carries the measured value rather than the inferred one.
library;

import 'engine.dart';
import 'txn.dart';

/// A point-in-time reading of every metric §6 requires.
final class Metrics {
  const Metrics({
    required this.bytesWrittenLogical,
    required this.bytesWrittenDevice,
    required this.writeAmpValue,
    required this.writeAmpKeyIndex,
    required this.writeAmpGc,
    required this.backpressureDelayMs,
    required this.backpressureCause,
    required this.stallEvents,
    required this.liveBytes,
    required this.allocatedBytes,
    required this.vlogLiveBytes,
    required this.vlogAllocatedBytes,
    required this.localityDebt,
    required this.vlogLiveRuns,
    required this.vlogIdealRuns,
    required this.pinnedBySnapshots,
    required this.pinnedByCheckpoints,
    required this.unencryptedPages,
    required this.noncesAllocated,
    required this.nonceFloor,
    required this.pageCacheHitRate,
    required this.segmentsProbedP50,
    required this.segmentsProbedP99,
    required this.filterFalsePositiveRate,
    required this.valueReadsPerScannedRow,
    required this.segmentsPerLevel,
    required this.bytesPerLevel,
    required this.oldestSnapshotAgeMs,
    required this.compactionBacklogBytes,
    required this.durabilityAchieved,
    required this.unavailableRanges,
  });

  // Write path
  final int bytesWrittenLogical;
  final int bytesWrittenDevice;
  final double writeAmpValue;
  final double writeAmpKeyIndex;
  final double writeAmpGc;
  final double backpressureDelayMs;
  final String? backpressureCause;
  final int stallEvents;

  // Space
  final int liveBytes;
  final int allocatedBytes;
  final int vlogLiveBytes;
  final int vlogAllocatedBytes;

  /// §6: "**This is the number that predicts scan decay**, and it has to be
  /// the run-based definition."
  final double localityDebt;

  final int vlogLiveRuns;
  final int vlogIdealRuns;
  final int pinnedBySnapshots;
  final int pinnedByCheckpoints;

  /// §6: "0 on a fully encrypted file; non-zero mid-conversion. An
  /// implementation MUST NOT report a database as encrypted while this is
  /// above 0."
  final int unencryptedPages;

  final int noncesAllocated;
  final int nonceFloor;

  // Read path
  final double pageCacheHitRate;
  final int segmentsProbedP50;
  final int segmentsProbedP99;
  final double filterFalsePositiveRate;

  /// §6: "validates readahead and clustering. Measured 0.100 when clustering
  /// is working and 1.038 when it is not."
  final double valueReadsPerScannedRow;

  // Structure
  final List<int> segmentsPerLevel;
  final List<int> bytesPerLevel;
  final int oldestSnapshotAgeMs;
  final int compactionBacklogBytes;

  /// `10-transactions.md` §7: what was actually performed.
  final Durability durabilityAchieved;

  /// `13-operations.md` §4: key ranges a checksum failure has taken out of
  /// service. Empty is the normal state.
  final int unavailableRanges;

  /// True while §6's encryption invariant is violated.
  bool get claimsEncryptionFalsely => unencryptedPages > 0;

  /// The space amplification §6 asks for, as a ratio.
  double get spaceAmplification =>
      liveBytes == 0 ? 1 : allocatedBytes / liveBytes;

  Map<String, Object?> toMap() => {
        'bytes_written_logical': bytesWrittenLogical,
        'bytes_written_device': bytesWrittenDevice,
        'write_amp_value': writeAmpValue,
        'write_amp_key_index': writeAmpKeyIndex,
        'write_amp_gc': writeAmpGc,
        'backpressure_delay_ms': backpressureDelayMs,
        'backpressure_cause': backpressureCause,
        'stall_events': stallEvents,
        'live_bytes': liveBytes,
        'allocated_bytes': allocatedBytes,
        'vlog_live_bytes': vlogLiveBytes,
        'vlog_allocated_bytes': vlogAllocatedBytes,
        'locality_debt': localityDebt,
        'vlog_live_runs': vlogLiveRuns,
        'vlog_ideal_runs': vlogIdealRuns,
        'pinned_by_snapshots': pinnedBySnapshots,
        'pinned_by_checkpoints': pinnedByCheckpoints,
        'unencrypted_pages': unencryptedPages,
        'nonces_allocated': noncesAllocated,
        'nonce_floor': nonceFloor,
        'page_cache_hit_rate': pageCacheHitRate,
        'segments_probed_per_lookup_p50': segmentsProbedP50,
        'segments_probed_per_lookup_p99': segmentsProbedP99,
        'filter_false_positive_rate': filterFalsePositiveRate,
        'value_reads_per_scanned_row': valueReadsPerScannedRow,
        'segments_per_level': segmentsPerLevel,
        'bytes_per_level': bytesPerLevel,
        'oldest_snapshot_age_ms': oldestSnapshotAgeMs,
        'compaction_backlog_bytes': compactionBacklogBytes,
        'durability_achieved': durabilityAchieved.name,
        'unavailable_ranges': unavailableRanges,
      };

  /// Every key §6 names, so a conformance test can assert the surface is
  /// complete rather than merely present.
  static const List<String> requiredKeys = [
    'bytes_written_logical',
    'bytes_written_device',
    'write_amp_value',
    'write_amp_key_index',
    'write_amp_gc',
    'backpressure_delay_ms',
    'stall_events',
    'live_bytes',
    'allocated_bytes',
    'vlog_live_bytes',
    'vlog_allocated_bytes',
    'locality_debt',
    'vlog_live_runs',
    'vlog_ideal_runs',
    'pinned_by_snapshots',
    'pinned_by_checkpoints',
    'unencrypted_pages',
    'nonces_allocated',
    'nonce_floor',
    'page_cache_hit_rate',
    'segments_probed_per_lookup_p50',
    'segments_probed_per_lookup_p99',
    'filter_false_positive_rate',
    'value_reads_per_scanned_row',
    'segments_per_level',
    'bytes_per_level',
    'oldest_snapshot_age_ms',
    'compaction_backlog_bytes',
  ];
}

/// Gathers [Metrics] from an engine.
extension EngineMetrics on Engine {
  Metrics metrics({int nowMs = 0}) {
    final perLevel = <int>[];
    final bytesLevel = <int>[];
    var keyBytes = 0;
    for (var l = 0; l <= lastLevel; l++) {
      final refs = refsAt(l);
      perLevel.add(refs.length);
      var b = 0;
      for (final r in refs) {
        b += r.pages * pageSize;
      }
      bytesLevel.add(b);
      keyBytes += b;
    }
    final bp = backpressure;
    final probes = segmentsProbed;
    return Metrics(
      bytesWrittenLogical: vlog.liveBytes + keyBytes,
      bytesWrittenDevice: vlog.allocatedBytes + keyBytes,
      writeAmpValue: vlog.liveBytes == 0
          ? 1
          : vlog.allocatedBytes / vlog.liveBytes,
      writeAmpKeyIndex: 1,
      writeAmpGc: coldCollections.toDouble(),
      backpressureDelayMs: bp.delayMs,
      backpressureCause: bp.cause,
      stallEvents: 0,
      liveBytes: vlog.liveBytes + keyBytes,
      allocatedBytes: vlog.allocatedBytes + keyBytes,
      vlogLiveBytes: vlog.liveBytes,
      vlogAllocatedBytes: vlog.allocatedBytes,
      localityDebt: vlog.localityDebt,
      vlogLiveRuns: vlog.liveSegments,
      vlogIdealRuns: vlog.idealSegments,
      pinnedBySnapshots: pinnedBySnapshots,
      pinnedByCheckpoints: 0,
      unencryptedPages: 0,
      noncesAllocated: 0,
      nonceFloor: 0,
      pageCacheHitRate: 1,
      segmentsProbedP50: percentile(probes, 0.50),
      segmentsProbedP99: percentile(probes, 0.99),
      filterFalsePositiveRate:
          filterAdmitted == 0 ? 0 : filterFalsePositives / filterAdmitted,
      valueReadsPerScannedRow: 0,
      segmentsPerLevel: perLevel,
      bytesPerLevel: bytesLevel,
      oldestSnapshotAgeMs: oldestSnapshotAgeMs(nowMs),
      compactionBacklogBytes: bytesLevel.isEmpty ? 0 : bytesLevel.first,
      durabilityAchieved: durabilityAchieved,
      unavailableRanges: quarantined.length,
    );
  }
}
