/// The change feed — `spec/13-operations.md` §7.
///
/// Reserved tree 9, keyed `CKE(Array[U32 tree_id, U64 seq])`. Entries are
/// appended **in the same batch as the mutation**, so the feed is exactly
/// consistent with the data — there is no window in which a change exists and
/// its feed entry does not, and none in which the reverse is true.
///
/// §7 states why it exists and why it is off by default:
///
/// > "Nitrite has a replication layer, and the alternative — a full scan
/// > comparing `_revision` fields — is the thing every sync implementation does
/// > badly. A monotonic per-record `seq` is already in the format; the feed
/// > just makes it addressable in seq order."
///
/// > "It is **optional and off by default**, because it costs a write per
/// > mutation and most databases do not sync."
library;

import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'errors.dart';
import 'value.dart';

/// One entry of tree 9.
final class Change {
  const Change({
    required this.treeId,
    required this.seq,
    required this.op,
    required this.key,
    this.id,
  });

  final int treeId;
  final int seq;

  /// `"put"`, `"delete"` or `"range_delete"`.
  final String op;

  /// The CKE key the mutation touched.
  final Uint8List key;

  /// The document id, when the tree has them.
  final CValue? id;

  Uint8List encode() => encodeValue(CDoc({
        'op': CStr(op),
        'key': CBytes(key),
        if (id != null) 'id': id!,
      }));

  static Change decode(Uint8List keyBytes, Uint8List value) {
    final k = expectValue<CArray>(decodeKey(keyBytes), 'change feed key');
    if (k.items.length < 2) {
      throw const CorruptionException(
          'change feed key: expected (tree_id, seq), found fewer items');
    }
    final d = expectValue<CDoc>(decodeValue(value), 'change feed record');
    return Change(
      treeId: expectValue<CInt>(k.items[0], 'change feed tree_id').magnitude.lo,
      seq: expectValue<CInt>(k.items[1], 'change feed seq').magnitude.lo,
      op: expectField<CStr>(d, 'op', 'change feed record').value,
      key: expectField<CBytes>(d, 'key', 'change feed record').value,
      id: d['id'],
    );
  }

  @override
  String toString() => 'Change(tree $treeId, seq $seq, $op)';
}

/// Tree 9.
final class ChangeFeed {
  ChangeFeed(PageStore store, {int root = 0})
      : tree = CowTree(store, treeId: TreeId.changeFeed, root: root);

  final CowTree tree;

  int get root => tree.root;

  /// `changefeed_retain_seq` — entries older than this many seq behind the
  /// newest are dropped by compaction, §7.
  int retainSeq = 100000;

  /// `changefeed_retain_ms`, "whichever is reached first".
  int retainMs = 7 * 24 * 60 * 60 * 1000;

  static Uint8List keyOf(int treeId, int seq) => encodeKey(CArray([
        CInt.of(NumType.u32, treeId),
        CInt.of(NumType.u64, seq),
      ]));

  void append(Change c) => tree.put(keyOf(c.treeId, c.seq), c.encode());

  /// `read_changes(tree, from_seq)`, §7.
  ///
  /// "A range scan, and because the key is `(tree_id, seq)` it is
  /// sequential" — the ordering the replication layer needs falls out of the
  /// key rather than out of a sort.
  Iterable<Change> read(int treeId, {int fromSeq = 0, int? toSeq}) sync* {
    final lower = keyOf(treeId, fromSeq);
    final upper = toSeq == null ? keyOf(treeId + 1, 0) : keyOf(treeId, toSeq);
    for (final (k, v) in tree.scan(lower: lower, upper: upper)) {
      yield Change.decode(k, v);
    }
  }

  Iterable<Change> get all sync* {
    for (final (k, v) in tree.scan()) {
      yield Change.decode(k, v);
    }
  }

  /// Drops entries past retention, §7. Returns how many went.
  int prune({required int newestSeq}) {
    final floor = newestSeq - retainSeq;
    if (floor <= 0) return 0;
    var n = 0;
    for (final c in all.toList()) {
      if (c.seq < floor) {
        tree.remove(keyOf(c.treeId, c.seq));
        n++;
      }
    }
    return n;
  }
}
