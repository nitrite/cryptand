/// Error taxonomy of `spec/00-conventions.md` section 9.
///
/// The spec is emphatic that these MUST NOT be conflated: "your disk has a bad
/// sector" and "someone edited your database" call for different responses.
library;

/// Base class for every failure this library raises. Nothing here extends
/// [Error]: all of these are recoverable conditions a caller must handle.
sealed class CryptandException implements Exception {
  const CryptandException(this.message);
  final String message;
  @override
  String toString() => '$runtimeType: $message';
}

/// The bytes are not what the format says they should be. Accidental damage.
final class CorruptionException extends CryptandException {
  const CorruptionException(super.message, {this.pageId, this.offset});

  /// The page the damage was found in, when known. `spec/13-operations.md`
  /// section 4 requires corruption to name what it affects.
  final int? pageId;
  final int? offset;

  @override
  String toString() {
    final where = [
      if (pageId != null) 'page $pageId',
      if (offset != null) 'offset $offset',
    ].join(', ');
    return where.isEmpty
        ? 'CorruptionException: $message'
        : 'CorruptionException: $message ($where)';
  }
}

/// An authentication tag failed. Deliberate modification, not damage.
/// `spec/14-security.md` section 6.2 requires this to be its own class.
final class TamperException extends CryptandException {
  const TamperException(super.message, {this.pageId});
  final int? pageId;
}

/// A declared length would not fit its container, or exceeds a limit in
/// `spec/00-conventions.md` section 8. Raised *before* any allocation:
/// section 9.1 of `spec/14-security.md` makes that a security requirement.
final class LimitException extends CryptandException {
  const LimitException(super.message);
}

/// The file requires something this implementation cannot do.
final class UnsupportedFeatureException extends CryptandException {
  const UnsupportedFeatureException(super.message);
}

/// The caller asked the library to write something the format forbids.
final class InvalidArgumentException extends CryptandException {
  const InvalidArgumentException(super.message);
}

/// A read landed inside a key range that corruption has made unavailable.
///
/// `spec/13-operations.md` section 4 requires exactly this shape: a damaged
/// page MUST NOT make the whole database unreadable, so a reader keeps serving
/// every key outside the affected range and fails inside it "with a specific
/// corruption error naming the range, never with a wrong or empty answer".
///
/// It is distinct from [CorruptionException] because the two call for different
/// responses: this one says *which* keys are gone and implies the rest are
/// fine, which is what a caller needs in order to degrade rather than stop.
final class UnavailableRangeException extends CryptandException {
  const UnavailableRangeException(super.message,
      {required this.segmentId, required this.treeIds});

  final int segmentId;

  /// Section 4 step 5: the trees whose indexes a planner must not silently
  /// substitute a scan of, because the results would be incomplete.
  final List<int> treeIds;
}

/// A transaction's write set collided with a batch sequenced after it began.
/// `spec/10-transactions.md` section 3: "On conflict the transaction aborts;
/// the format does not define automatic retry."
/// `spec/14-security.md` section 3.3 and `spec/00-conventions.md` section 9:
/// an encrypted file, and no keyslot accepted the credential.
///
/// One class for both causes on purpose — section 3.3 requires that "a failure
/// across all slots be indistinguishable from 'no such slot'", so a missing
/// key, a wrong key and a keyslot lifted from another database all read the
/// same to a caller.
final class CannotUnlockException extends CryptandException {
  const CannotUnlockException()
      : super('cannot unlock: no keyslot accepted the key');
}

/// `spec/01-container.md` section 10 — another process holds the writer lock.
///
/// Its own class because section 10 forbids the one alternative: an
/// implementation "MUST NOT fall back to opening anyway".
final class LockedException extends CryptandException {
  const LockedException(super.message);
}

final class ConflictException extends CryptandException {
  const ConflictException(super.message, {this.key});

  /// The first colliding key, as `tree_id:CKE` hex, for diagnosis.
  final String? key;
}
