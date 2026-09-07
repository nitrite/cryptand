/// Device profiles — `spec/12-profiles.md`.
///
/// A profile is "a named set of superblock constants that changes how a
/// **writer** behaves and nothing about how a file is read". That sentence is
/// the whole design, and §2 states the consequence: a `mobile`-profile file and
/// a `server`-profile file are **the same format**, so a phone-written database
/// opens on a desktop with no export step.
///
/// The constants that already live on [Profile] in `container.dart` are the
/// structural ones. This file adds the *behavioural* ones §4 and §5 make
/// normative — the foreground stall budget, the compaction step size, the
/// scheduling policy and the host hints — plus `set_profile` and `reprofile`
/// from §6.
library;

import 'container.dart';
import 'engine.dart';

/// The behavioural constants of `spec/12-profiles.md` §1 that are not already
/// superblock fields on [Profile].
extension ProfileBehaviour on Profile {
  /// §4, **normative for every profile**: "An implementation MUST NOT block a
  /// caller's thread for longer than this in any single operation that the
  /// application did not explicitly request as a bulk operation."
  int get maxForegroundStallMs => switch (this) {
        Profile.mobile || Profile.custom => 8,
        Profile.tablet => 8,
        Profile.desktop => 25,
        Profile.server => 100,
      };

  /// §1 and `04-segments.md` §5.2 — the unit a compaction decomposes into.
  int get compactionStepBytes => switch (this) {
        Profile.mobile || Profile.custom => 256 << 10,
        Profile.tablet => 1 << 20,
        Profile.desktop => 8 << 20,
        Profile.server => 32 << 20,
      };

  int get memtableShards => switch (this) {
        Profile.mobile || Profile.custom => 1,
        Profile.tablet => 2,
        Profile.desktop => 8,
        Profile.server => 32,
      };

  int get compactionThreads => switch (this) {
        Profile.mobile || Profile.custom => 1,
        Profile.tablet => 2,
        Profile.desktop => 4,
        Profile.server => 8,
      };

  /// §5: on `mobile` and `tablet`, non-urgent maintenance SHOULD wait for a
  /// hint. "Non-urgent" means everything except what backpressure requires —
  /// "the engine must never deadlock waiting for a hint that never arrives."
  bool get defersMaintenance =>
      this == Profile.mobile || this == Profile.tablet;

  /// §3.2 of `14-security.md`, gathered here because it is a profile constant.
  ({int tCost, int mCostKib, int parallelism}) get argon2 => switch (this) {
        Profile.mobile ||
        Profile.custom =>
          (tCost: 3, mCostKib: 65536, parallelism: 1),
        Profile.tablet => (tCost: 3, mCostKib: 131072, parallelism: 2),
        _ => (tCost: 4, mCostKib: 262144, parallelism: 4),
      };
}

/// The host hints of `spec/12-profiles.md` §5.
final class HostHints {
  const HostHints({
    this.idle = false,
    this.charging = false,
    this.thermalPressure = false,
  });

  /// No user interaction in progress: run deferred compaction, GC, clustering.
  final bool idle;

  /// On external power: raise pacing, allow full-file maintenance.
  final bool charging;

  /// Hot or throttled: reduce to a trickle — **never stop entirely**.
  final bool thermalPressure;

  static const HostHints none = HostHints();
}

/// A record of one foreground operation's duration, for §4's budget.
final class StallSample {
  const StallSample(this.operation, this.micros);
  final String operation;
  final int micros;
  double get ms => micros / 1000.0;
}

/// Profile behaviour on an engine: the stall budget, host hints and §6's
/// profile switch.
extension EngineProfile on Engine {
  static final Expando<_ProfileState> _state = Expando();

  _ProfileState get _p => _state[this] ??= _ProfileState();

  Profile get profile => _p.profile;

  HostHints get hints => _p.hints;
  set hints(HostHints h) => _p.hints = h;

  /// Every foreground operation timed since the last reset, §4.
  List<StallSample> get stallSamples => _p.samples;

  /// Operations that exceeded `max_foreground_stall_ms`, §4.
  List<StallSample> get stallViolations => [
        for (final s in _p.samples)
          if (s.ms > profile.maxForegroundStallMs) s
      ];

  void resetStallSamples() => _p.samples.clear();

  /// Runs [body] under §4's budget, recording how long it took.
  ///
  /// Recording rather than enforcing is deliberate: §4's requirement is on the
  /// *implementation's* decomposition (`04-segments.md` §5.2), and the way to
  /// check it is to measure real operations against the budget rather than to
  /// wrap them in a timeout that would hide the problem.
  T timedForeground<T>(String operation, T Function() body) {
    final sw = Stopwatch()..start();
    final r = body();
    sw.stop();
    _p.samples.add(StallSample(operation, sw.elapsedMicroseconds));
    return r;
  }

  /// §5: whether non-urgent maintenance should run now.
  ///
  /// "The engine must never deadlock waiting for a hint that never arrives" —
  /// so backpressure overrides the hint entirely.
  bool get shouldRunMaintenance {
    if (backpressure.isApplied) return true; // urgent: never deferred
    if (!profile.defersMaintenance) return true;
    return hints.idle || hints.charging;
  }

  /// §5: the pacing multiplier a hint implies. Never zero — thermal pressure
  /// reduces maintenance "to a trickle; never stop entirely".
  double get maintenancePacing {
    if (hints.thermalPressure) return 0.1;
    if (hints.charging) return 2.0;
    return 1.0;
  }

  /// `set_profile(p)`, §6.
  ///
  /// Writes the new constants; **existing data converts lazily, through
  /// ordinary compaction**. `page_size` is the one constant that cannot
  /// change — it is fixed at creation, and changing it needs a full copy
  /// through `13-operations.md` §2.
  void setProfile(Profile p) {
    if (p.pageSize != pageSize && p != Profile.custom) {
      throw InvalidProfileChange(
          'page_size is fixed at creation: this file is $pageSize B and '
          '${p.name} wants ${p.pageSize} B. Changing it requires a full copy '
          '(spec/13-operations.md section 2).');
    }
    _p.profile = p;
    // `01-container.md` §7 — the codec is a profile constant, and a profile
    // change is exactly when the *default* for newly written pages should move.
    // Existing pages keep their own flags, which is what makes the mixture §7
    // permits legal rather than a repair job.
    store.pageCodec = p.pageCodec;
  }

  /// `reprofile()`, §6 — force the conversion eagerly rather than waiting for
  /// organic compaction. MUST be incremental and resumable.
  ///
  /// Here that is one full compaction, which is the eager form; the resumable
  /// form is `04-segments.md` §5.2's stepwise compaction, which this
  /// implementation does not have (`REPORT.md` §5).
  void reprofile() => compact();
}

/// `set_profile` was asked for something the format fixes at creation.
final class InvalidProfileChange implements Exception {
  const InvalidProfileChange(this.message);
  final String message;
  @override
  String toString() => 'InvalidProfileChange: $message';
}

final class _ProfileState {
  Profile profile = Profile.desktop;
  HostHints hints = HostHints.none;
  final List<StallSample> samples = [];
}
