/// Copy-on-write B+trees: the reserved trees of `spec/05-catalog.md` §2.
///
/// `spec/04-segments.md` §3.3 is the whole rationale: trees 0–15 are **not**
/// levelled segment sets. They are small, hot and almost entirely cached, and
/// levelling them would mean the manifest needed a manifest. They use the page
/// format of §2.2 — the same encoder, [encodeNodePage] — written
/// copy-on-write: a write copies the path from leaf to root, appends the
/// copied pages, and publishes a new root.
///
/// **What this file simplifies, stated rather than hidden.** Freed pages are
/// recorded but not reclaimed: the free tree of `spec/01-container.md` §6 is
/// keyed by `commit_id` and only becomes interesting once `min_retained_commit`
/// does, which needs the snapshot set of `spec/10-transactions.md` §8. And an
/// underfull page is never merged with a sibling — only an empty one is
/// unlinked, and a root with one child is collapsed. Both are space effects,
/// not correctness ones, and [PageStore.freedPages] makes the first measurable.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'cke.dart';
import 'limits.dart';
import 'errors.dart';
import 'segment.dart';

/// The file's page space: allocate, read, write.
///
/// In memory, like the segment extents of phase 2 — `REPORT.md` §5 states the
/// limit that follows and it is unchanged here. Page *identity* and page
/// *granularity* are real, which is what the counters measure.
final class PageStore {
  PageStore({this.pageSize = 4096}) {
    checkPageSize(pageSize);
    _pages.add(Uint8List(pageSize)); // page 0: the superblock
  }

  final int pageSize;
  final List<Uint8List> _pages = [];
  final List<int> _freed = [];

  int pageReads = 0;
  int pageWrites = 0;

  int get pageCount => _pages.length;

  /// Pages a copy-on-write path copy has orphaned and the free tree would own.
  int get freedPages => _freed.length;

  /// Bytes the store has allocated, live and orphaned alike.
  int get allocatedBytes => _pages.length * pageSize;

  void resetCounters() {
    pageReads = 0;
    pageWrites = 0;
  }

  int alloc() {
    _pages.add(Uint8List(pageSize));
    return _pages.length - 1;
  }

  void free(int pageId) {
    if (pageId != 0) _freed.add(pageId);
  }

  Uint8List read(int pageId) {
    if (pageId < 1 || pageId >= _pages.length) {
      throw CorruptionException('page $pageId is outside the store');
    }
    pageReads++;
    return _pages[pageId];
  }

  void write(int pageId, Uint8List page) {
    if (page.length != pageSize) {
      throw InvalidArgumentException(
          'page $pageId is ${page.length} B, expected $pageSize');
    }
    pageWrites++;
    _pages[pageId] = page;
  }
}

/// One node held for editing: the decoded form of a §2.2 page.
final class _Node {
  _Node(this.isLeaf, this.keys, this.payloads);

  final bool isLeaf;
  final List<Uint8List> keys;
  final List<Uint8List> payloads;

  int get count => keys.length;

  /// `subtree_entries`, which is what makes `skip(n)` cost O(height) (§2.2).
  int get subtreeEntries {
    if (isLeaf) return keys.length;
    var n = 0;
    for (final p in payloads) {
      n += childOf(p).$2;
    }
    return n;
  }

  static _Node decode(Uint8List page, int pageId) {
    final n = Node(page, pageId);
    final keys = <Uint8List>[];
    final payloads = <Uint8List>[];
    for (var i = 0; i < n.cellCount; i++) {
      keys.add(n.keyAt(i));
      final r = n.payloadAt(i);
      if (n.isLeaf) {
        final kindFlags = r.u8();
        if (kindFlags & 0x0F != ValueKind.inline) {
          throw CorruptionException(
              'copy-on-write leaf cell $i has value_kind ${kindFlags & 0x0F}; '
              'reserved trees hold inline values only');
        }
        payloads.add(leafPayload(r.bytesCopy(r.uvar())));
      } else {
        final child = r.u64();
        final entries = r.u64();
        payloads.add(childPayload(child, entries));
      }
    }
    return _Node(n.isLeaf, keys, payloads);
  }

  /// A leaf cell payload: `u8 kind_flags = INLINE || uvar len || value`.
  static Uint8List leafPayload(Uint8List value) => (ByteWriter(value.length + 6)
        ..u8(ValueKind.inline)
        ..uvar(value.length)
        ..bytes(value))
      .takeBytes();

  static Uint8List childPayload(int page, int entries) =>
      (ByteWriter(16)..u64(page)..u64(entries)).takeBytes();

  static Uint8List valueOf(Uint8List payload) {
    final r = ByteReader(payload)..u8();
    return r.bytesCopy(r.uvar());
  }

  static (int, int) childOf(Uint8List payload) {
    final r = ByteReader(payload);
    return (r.u64(), r.u64());
  }
}

/// A reserved tree: a copy-on-write B+tree over [store].
///
/// [root] is the published root page id; 0 means the tree is empty, which is
/// what an unset superblock root field says.
final class CowTree {
  CowTree(this.store, {required this.treeId, this.root = 0});

  final PageStore store;
  final int treeId;
  int root;

  /// Pages written since the last [resetCounters], i.e. the copy-on-write
  /// cost of the edits made. A path copy is `height` pages, not one.
  int pagesCopied = 0;

  void resetCounters() {
    pagesCopied = 0;
    store.resetCounters();
  }

  bool get isEmpty => root == 0;

  int get entryCount =>
      root == 0 ? 0 : _load(root).subtreeEntries;

  _Node _load(int pageId) => _Node.decode(store.read(pageId), pageId);

  int _write(_Node n) {
    final id = store.alloc();
    store.write(
        id,
        encodeNodePage(
          pageSize: store.pageSize,
          isLeaf: n.isLeaf,
          keys: n.keys,
          payloads: n.payloads,
          subtreeEntries: n.subtreeEntries,
          treeId: treeId,
        ));
    pagesCopied++;
    return id;
  }

  // -------------------------------------------------------------------------
  // Reading
  // -------------------------------------------------------------------------

  Uint8List? get(Uint8List key) {
    if (root == 0) return null;
    var pageId = root;
    while (true) {
      final n = _load(pageId);
      if (n.isLeaf) {
        final i = _find(n.keys, key);
        return i < 0 ? null : _Node.valueOf(n.payloads[i]);
      }
      pageId = _Node.childOf(n.payloads[_descend(n.keys, key)]).$1;
    }
  }

  /// Every entry in `[lower, upper)`, in key order.
  ///
  /// A generator rather than a cursor: §8 makes cursors the only iteration
  /// mechanism over *segments*, where an O(1) `next` is what fixes the paged
  /// scan of `research/nitrite-survey.md` §7. A reserved tree is bounded and
  /// cached, and a recursive walk over it is the same asymptotics with a
  /// tenth of the code.
  Iterable<(Uint8List, Uint8List)> scan(
      {Uint8List? lower, Uint8List? upper}) sync* {
    if (root == 0) return;
    yield* _walk(root, lower, upper);
  }

  Iterable<(Uint8List, Uint8List)> _walk(
      int pageId, Uint8List? lower, Uint8List? upper) sync* {
    final n = _load(pageId);
    if (n.isLeaf) {
      for (var i = 0; i < n.count; i++) {
        final k = n.keys[i];
        if (lower != null && compareKeys(k, lower) < 0) continue;
        if (upper != null && compareKeys(k, upper) >= 0) return;
        yield (k, _Node.valueOf(n.payloads[i]));
      }
      return;
    }
    final start = lower == null ? 0 : _descend(n.keys, lower);
    for (var i = start; i < n.count; i++) {
      // Separators are lower bounds on their subtree, so a child whose
      // separator is already at or past `upper` holds nothing in range.
      if (upper != null && i > start && compareKeys(n.keys[i], upper) >= 0) {
        return;
      }
      yield* _walk(_Node.childOf(n.payloads[i]).$1, lower, upper);
    }
  }

  /// Index of [key], or `-1`.
  static int _find(List<Uint8List> keys, Uint8List key) {
    var lo = 0, hi = keys.length - 1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      final c = compareKeys(keys[mid], key);
      if (c == 0) return mid;
      if (c < 0) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return -1;
  }

  /// Insertion point: the first index whose key is >= [key].
  static int _lowerBound(List<Uint8List> keys, Uint8List key) {
    var lo = 0, hi = keys.length;
    while (lo < hi) {
      final mid = (lo + hi) >> 1;
      if (compareKeys(keys[mid], key) < 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /// The child to descend into: the last separator <= [key], clamped to 0.
  ///
  /// The clamp is what lets a separator be a child's exact minimum key rather
  /// than an artificial `UNBOUNDED_BELOW`: a key below every separator still
  /// belongs in the leftmost subtree, and after it is inserted there that
  /// subtree's minimum is simply lower than its separator. The invariant the
  /// descent needs is only that a separator never *exceeds* its subtree's
  /// minimum.
  static int _descend(List<Uint8List> keys, Uint8List key) {
    var lo = 0, hi = keys.length - 1, ans = -1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      if (compareKeys(keys[mid], key) <= 0) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans < 0 ? 0 : ans;
  }

  // -------------------------------------------------------------------------
  // Writing
  // -------------------------------------------------------------------------

  void put(Uint8List key, Uint8List value) =>
      _edit(key, _Node.leafPayload(value));

  bool remove(Uint8List key) {
    if (root == 0) return false;
    if (get(key) == null) return false;
    _edit(key, null);
    return true;
  }

  /// Inserts, replaces or removes one key and republishes the root.
  void _edit(Uint8List key, Uint8List? payload) {
    if (root == 0) {
      if (payload == null) return;
      // Through _publish, not straight to _write: a first entry too large for
      // a page must be refused by the same check every later one meets.
      _publish([(0, _Node(true, [Uint8List.fromList(key)], [payload]), -1)]);
      return;
    }

    // Descend, remembering the pages to copy on the way back up.
    final path = <(int, _Node, int)>[]; // (pageId, node, childIndex)
    var pageId = root;
    while (true) {
      final n = _load(pageId);
      if (n.isLeaf) {
        path.add((pageId, n, -1));
        break;
      }
      final i = _descend(n.keys, key);
      path.add((pageId, n, i));
      pageId = _Node.childOf(n.payloads[i]).$1;
    }

    final leaf = path.last.$2;
    final at = _lowerBound(leaf.keys, key);
    final hit = at < leaf.count && compareKeys(leaf.keys[at], key) == 0;
    if (payload == null) {
      if (!hit) return;
      leaf.keys.removeAt(at);
      leaf.payloads.removeAt(at);
    } else if (hit) {
      leaf.payloads[at] = payload;
    } else {
      leaf.keys.insert(at, Uint8List.fromList(key));
      leaf.payloads.insert(at, payload);
    }

    _publish(path);
  }

  /// Writes the copied path back up, splitting where a page no longer fits.
  void _publish(List<(int, _Node, int)> path) {
    var level = path.length - 1;
    var replacements = _split(path[level].$2);
    store.free(path[level].$1);

    while (level > 0) {
      final children = [for (final n in replacements) (_write(n), n)];
      final (parentId, parent, childIndex) = path[level - 1];
      store.free(parentId);

      parent.keys.removeAt(childIndex);
      parent.payloads.removeAt(childIndex);
      for (var i = 0; i < children.length; i++) {
        final (id, n) = children[i];
        if (n.count == 0) continue; // an emptied page is unlinked, not written
        parent.keys.insert(childIndex + i, Uint8List.fromList(n.keys.first));
        parent.payloads
            .insert(childIndex + i, _Node.childPayload(id, n.subtreeEntries));
      }
      replacements = _split(parent);
      level--;
    }

    if (replacements.length == 1) {
      final only = replacements.first;
      if (only.count == 0) {
        root = 0;
      } else if (!only.isLeaf && only.count == 1) {
        // A root with one child is a chain of one; its child is already a
        // valid root, so the level is dropped rather than written.
        root = _Node.childOf(only.payloads[0]).$1;
      } else {
        root = _write(only);
      }
      return;
    }
    // The root split: a new level above it.
    final keys = <Uint8List>[];
    final payloads = <Uint8List>[];
    for (final n in replacements) {
      if (n.count == 0) continue;
      keys.add(Uint8List.fromList(n.keys.first));
      payloads.add(_Node.childPayload(_write(n), n.subtreeEntries));
    }
    root = _write(_Node(false, keys, payloads));
  }

  /// Splits [n] until every part fits one page.
  List<_Node> _split(_Node n) {
    if (n.count == 0 ||
        nodePageBytes(n.keys, n.payloads) <= store.pageSize) {
      return [n];
    }
    if (n.count == 1) {
      throw LimitException(
          'a single cell of ${nodePageBytes(n.keys, n.payloads)} B does not '
          'fit a ${store.pageSize} B page');
    }
    final mid = n.count >> 1;
    final left = _Node(n.isLeaf, n.keys.sublist(0, mid), n.payloads.sublist(0, mid));
    final right = _Node(n.isLeaf, n.keys.sublist(mid), n.payloads.sublist(mid));
    return [..._split(left), ..._split(right)];
  }

  /// Height in pages from the root to a leaf, root included. 0 when empty.
  int get height {
    if (root == 0) return 0;
    var h = 1;
    var n = _load(root);
    while (!n.isLeaf) {
      h++;
      n = _load(_Node.childOf(n.payloads[0]).$1);
    }
    return h;
  }
}
