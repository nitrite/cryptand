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
