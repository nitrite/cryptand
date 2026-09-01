/// The hard limits of `spec/00-conventions.md` section 8.
///
/// Every one of these is checked *before* an allocation. Section 9.1 of
/// `spec/14-security.md` makes that a security requirement rather than a
/// robustness one: opening a file another party produced is what this format
/// is for, so every reader is a parser of hostile input.
library;

import 'errors.dart';

/// Legal `page_size` values; `page_size_log2` is 12..16.
const List<int> kPageSizes = [4096, 8192, 16384, 32768, 65536];

/// `spec/00-conventions.md` section 8: document nesting depth.
const int kMaxDepth = 100;

/// `spec/00-conventions.md` section 8: document field count.
const int kMaxFieldCount = 65535;

/// `spec/00-conventions.md` section 4: a `uvar` is at most 10 bytes.
const int kMaxUvarBytes = 10;

/// Absolute ceiling on an encoded key, before the page-relative cap applies.
const int kMaxKeyBytesAbsolute = 4096;

/// `spec/00-conventions.md` section 8: encoded key length is
/// `page_size / 4`, and at most 4 KiB.
int maxKeyBytes(int pageSize) =>
    (pageSize ~/ 4) < kMaxKeyBytesAbsolute ? pageSize ~/ 4 : kMaxKeyBytesAbsolute;

/// `spec/00-conventions.md` section 8: inline value length is `page_size / 4`.
int maxInlineValueBytes(int pageSize) => pageSize ~/ 4;

/// `spec/00-conventions.md` section 8: `vlog_min` MUST be at most
/// `page_size / 4`, otherwise the writer's own inline threshold names values
/// that cannot be stored inline.
void checkVlogMin(int vlogMin, int pageSize) {
  if (vlogMin < 1 || vlogMin > pageSize ~/ 4) {
    throw InvalidArgumentException(
        'vlog_min $vlogMin outside 1..${pageSize ~/ 4} for page_size $pageSize');
  }
}

void checkPageSize(int pageSize) {
  if (!kPageSizes.contains(pageSize)) {
    throw InvalidArgumentException(
        'page_size $pageSize is not one of $kPageSizes');
  }
}
