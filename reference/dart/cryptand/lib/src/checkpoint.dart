/// Checkpoints — `spec/13-operations.md` §1.
///
/// A checkpoint is a **named, retained snapshot**: reserved tree 8, one small
/// write, costing nothing until the data diverges from it. §1's closing line is
/// the point of the feature — "an undo point around a migration or a risky bulk
/// operation for the price of one tree entry, which is not something the
/// current storage backends can offer at any price."
///
/// Two rules here are load-bearing and both are about what a restore does
/// *not* touch:
///
///   * **`checkpoint_root` is deliberately not captured.** Restoring must not
///     delete the other checkpoints, so a restore keeps the *current*
///     `checkpoint_root` and replaces the other eight roots. An earlier draft
///     also omitted `changefeed_root`, which left a restore pairing the current
///     change feed with an older manifest.
///   * **Restore rolls back roots, never counters.** `next_seq`, `next_tree_id`,
///     `next_segment_id`, `next_vlog_segment_id` and — critically —
///     `next_nonce` keep their current values. Rolling `next_nonce` back would
///     hand out nonce values the abandoned commits already used, and the pages
///     that used them are still in the file: same key, same nonce, two
///     plaintexts (`14-security.md` §4.1).
library;

import 'dart:typed_data';

import 'cke.dart';
import 'container.dart';
import 'cow.dart';
import 'cve.dart';
import 'errors.dart';
import 'txn.dart';
import 'value.dart';

/// One entry of tree 8.
final class Checkpoint {
  const Checkpoint({
    required this.name,
    required this.commitId,
    required this.seq,
    required this.created,
    required this.catalogRoot,
    required this.freelistRoot,
    required this.attributesRoot,
    required this.manifestRoot,
    required this.vlogStatsRoot,
    required this.changefeedRoot,
    this.expires,
  });

  factory Checkpoint.of(String name, Snapshot s, {int? expires}) => Checkpoint(
        name: name,
        commitId: s.commitId,
        seq: s.seq,
        created: s.takenAtMs,
        catalogRoot: s.catalogRoot,
        freelistRoot: s.freelistRoot,
        attributesRoot: s.attributesRoot,
        manifestRoot: s.manifestRoot,
        vlogStatsRoot: s.vlogStatsRoot,
        changefeedRoot: s.changefeedRoot,
        expires: expires,
      );

  final String name;
  final int commitId;
  final int seq;
  final int created;
  final int catalogRoot;
  final int freelistRoot;
  final int attributesRoot;
  final int manifestRoot;
  final int vlogStatsRoot;
  final int changefeedRoot;

  /// §1: an implementation MUST honour this and drop the checkpoint past it.
  final int? expires;

  bool isExpired(int nowMs) => expires != null && expires! <= nowMs;

  /// The snapshot this checkpoint restores to.
  ///
  /// `checkpoint_root` is 0 because it is not captured — a reader at a
  /// checkpoint sees the *current* set of checkpoints, which is what keeps a
  /// restore from deleting its own siblings.
  Snapshot get snapshot => Snapshot(
        seq: seq,
        commitId: commitId,
        catalogRoot: catalogRoot,
        freelistRoot: freelistRoot,
        attributesRoot: attributesRoot,
        manifestRoot: manifestRoot,
        vlogStatsRoot: vlogStatsRoot,
        checkpointRoot: 0,
        changefeedRoot: changefeedRoot,
        takenAtMs: created,
      );

  Uint8List encode() => encodeValue(CDoc({
        'commit_id': CInt.of(NumType.u64, commitId),
        'seq': CInt.of(NumType.u64, seq),
        'created': CTimestamp(created),
        'catalog_root': CInt.of(NumType.u64, catalogRoot),
        'freelist_root': CInt.of(NumType.u64, freelistRoot),
        'attributes_root': CInt.of(NumType.u64, attributesRoot),
        'manifest_root': CInt.of(NumType.u64, manifestRoot),
        'vlog_stats_root': CInt.of(NumType.u64, vlogStatsRoot),
        'changefeed_root': CInt.of(NumType.u64, changefeedRoot),
        if (expires != null) 'expires': CTimestamp(expires!),
      }));

  static Checkpoint decode(String name, Uint8List bytes) {
    final d = expectValue<CDoc>(decodeValue(bytes), 'checkpoint record');
    int u(String f) =>
        expectField<CInt>(d, f, 'checkpoint record').magnitude.lo;
    return Checkpoint(
      name: name,
      commitId: u('commit_id'),
      seq: u('seq'),
      created: (d['created']! as CTimestamp).millis,
      catalogRoot: u('catalog_root'),
      freelistRoot: u('freelist_root'),
      attributesRoot: u('attributes_root'),
      manifestRoot: u('manifest_root'),
      vlogStatsRoot: u('vlog_stats_root'),
      changefeedRoot: u('changefeed_root'),
      expires: (d['expires'] as CTimestamp?)?.millis,
    );
  }

  /// §1 is explicit that this field is absent, and the absence is the design.
  bool get capturesCheckpointRoot => false;

  @override
  String toString() => 'Checkpoint($name, seq $seq, commit $commitId)';
}

/// Tree 8.
final class CheckpointStore {
  CheckpointStore(PageStore store, {int root = 0})
      : tree = CowTree(store, treeId: TreeId.checkpoints, root: root);

  final CowTree tree;

  int get root => tree.root;

  static Uint8List _key(String name) => encodeKey(CStr(name));

  Checkpoint? get(String name) {
    final v = tree.get(_key(name));
    return v == null ? null : Checkpoint.decode(name, v);
  }

  void put(Checkpoint c) {
    if (c.name.isEmpty) {
      throw const InvalidArgumentException('a checkpoint name cannot be empty');
    }
    tree.put(_key(c.name), c.encode());
  }

  bool remove(String name) => tree.remove(_key(name));

  Iterable<Checkpoint> get all sync* {
    for (final (k, v) in tree.scan()) {
      yield Checkpoint.decode(
          expectValue<CStr>(decodeKey(k), 'checkpoint name').value, v);
    }
  }

  /// Drops every checkpoint whose `expires` has passed, §1.
  List<String> dropExpired(int nowMs) {
    final gone = <String>[];
    for (final c in all.toList()) {
      if (c.isExpired(nowMs)) {
        remove(c.name);
        gone.add(c.name);
      }
    }
    return gone;
  }
}
