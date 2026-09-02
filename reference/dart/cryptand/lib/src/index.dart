/// Secondary indexes, `spec/06-indexes.md`.
///
/// One layout, for all three index types, in all languages:
///
/// ```
/// key   = CKE( Array[ v1, v2, …, vk, NitriteId ] )
/// value = EMPTY
/// ```
///
/// That is the whole design, and the consequences are what retire the three
/// different layouts of `research/nitrite-survey.md` §5: insert and remove are
/// O(1) point operations rather than a read-modify-write of a growing id list;
/// a prefix query is a range scan; a scan yields the indexed values *and* the
/// document id, so a covering query never touches the data tree; and the
/// `LOWER/EXACT/UPPER` sentinel byte that Java's `IndexEntryKey` and Dart's
/// `IndexKey._Bound` persist in every stored key is gone, because `successor()`
/// builds the bound outside the key.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'catalog.dart';
import 'cke.dart';
import 'errors.dart';
import 'value.dart';

/// One index's definition, §2.
final class IndexDescriptor {
  const IndexDescriptor({
    required this.indexType,
    required this.dataTree,
    required this.fields,
    this.sparse = false,
    this.collation,
  });

  /// §2: "uniqueness is `index_type == "unique"` and nothing else." An earlier
  /// draft also carried a `"unique": BOOL`; two records of one fact drift, and
  /// nothing said which wins.
  final String indexType;

  /// The binding that matters; `owner` is the human-readable mirror.
  final int dataTree;

  /// Field *paths*, in order. `.` nests, `\.` escapes a literal dot.
  final List<String> fields;

  final bool sparse;
  final String? collation;

  bool get unique => indexType == IndexType.unique;

  Map<String, CValue> get params => {
        'index_type': CStr(indexType),
        'data_tree': CInt.of(NumType.u32, dataTree),
        'fields': CArray([for (final f in fields) CStr(f)]),
        if (sparse) 'sparse': const CBool(true),
        if (collation != null) 'collation': CStr(collation!),
      };

  static IndexDescriptor fromDescriptor(TreeDescriptor d) {
    final p = d.params;
    return IndexDescriptor(
      indexType: (p['index_type']! as CStr).value,
      dataTree: ((p['data_tree']! as CInt).magnitude).lo,
      fields: [for (final f in (p['fields']! as CArray).items) (f as CStr).value],
      sparse: (p['sparse'] as CBool?)?.value ?? false,
      collation: (p['collation'] as CStr?)?.value,
    );
  }

  /// §2: "Index tree names are for people." Nothing parses this.
  String suggestedName(String dataTreeName) =>
      'idx:$dataTreeName:${fields.join(",")}:$indexType';
}

/// §4: a writer MUST cap the cartesian product at this many entries per
/// document and report an error beyond it "rather than write an unbounded
/// number of index rows".
const int kMaxIndexEntriesPerDocument = 1024;

/// Splits a field path on unescaped `.`.
///
/// §5: "A path component that is itself a literal `.` is escaped as `\.`; a
/// literal backslash is `\\`. **This is the only escaping in the format**, and
/// it exists only inside index field paths."
List<String> splitFieldPath(String path) {
  final out = <String>[];
  final buf = StringBuffer();
  for (var i = 0; i < path.length; i++) {
    final c = path[i];
    if (c == r'\') {
      if (i + 1 >= path.length) {
        throw InvalidArgumentException(
            'field path "$path" ends with a dangling backslash');
      }
      final n = path[++i];
      if (n != '.' && n != r'\') {
        throw InvalidArgumentException(
            r'field path "' '$path' r'" escapes "\' '$n", but only \\. and '
            r'\\ are escapes');
      }
      buf.write(n);
    } else if (c == '.') {
      out.add(buf.toString());
      buf.clear();
    } else {
      buf.write(c);
    }
  }
  out.add(buf.toString());
  return out;
}

/// Resolves [path] against [doc], flattening array traversal.
///
/// §5: "Traversing an array field applies the remainder of the path to every
/// element and flattens the results (so `orders.items.sku` indexes every sku in
/// every item of every order)." An empty result means the path is unresolvable,
/// which §3 treats as an absent field.
List<CValue> resolvePath(CDoc doc, String path) {
  var current = <CValue>[doc];
  for (final part in splitFieldPath(path)) {
    final next = <CValue>[];
    for (final v in current) {
      if (v is CDoc) {
        final child = v[part];
        if (child != null) next.add(child);
      } else if (v is CArray) {
        for (final item in v.items) {
          if (item is CDoc) {
            final child = item[part];
            if (child != null) next.add(child);
          }
        }
      }
    }
    current = next;
    if (current.isEmpty) return const [];
  }
  // A terminal array contributes one entry per element, §4.
  final out = <CValue>[];
  for (final v in current) {
    if (v is CArray) {
      out.addAll(v.items);
    } else {
      out.add(v);
    }
  }
  return out;
}

/// The index keys one document produces, §3–§5.
///
/// Returns the CKE `ARRAY` keys, in the order the cartesian product is walked.
/// An empty list means the document is not indexed at all, which happens only
/// under `sparse` (§3).
List<Uint8List> indexKeysFor(
  IndexDescriptor idx,
  CDoc doc,
  CValue documentId,
) {
  // Per field: the list of values it contributes. A missing field is one NULL
  // unless the index is sparse, in which case the document is skipped.
  final perField = <List<CValue>>[];
  for (final path in idx.fields) {
    final vs = resolvePath(doc, path);
    if (vs.isEmpty) {
      if (idx.sparse) return const [];
      perField.add(const [CNull()]);
      continue;
    }
    for (final v in vs) {
      if (!isKeyEncodable(v)) {
        // §6: attempting to index a value with no CKE encoding MUST fail with
        // a clear error naming the field and the type. DEC128 is the
        // surprising member of that list; `03-key-encoding.md` §4.4 has why.
        throw InvalidArgumentException(
            'field "$path" holds a ${v.runtimeType} (CVE tag ${v.tag}), which '
            'has no CKE encoding and cannot be indexed '
            '(spec/06-indexes.md section 6)');
      }
    }
    // §4: "Duplicate elements produce one entry, not two."
    final seen = <String>{};
    final unique = <CValue>[];
    for (final v in vs) {
      if (seen.add(_hex(encodeKey(v)))) unique.add(v);
    }
    perField.add(unique);
  }

  var total = 1;
  for (final f in perField) {
    total *= f.length;
    if (total > kMaxIndexEntriesPerDocument) {
      throw LimitException(
          'this document would produce $total index entries for '
          '${idx.fields.join(",")}, over the cap of '
          '$kMaxIndexEntriesPerDocument (spec/06-indexes.md section 4)');
    }
  }

  var combos = <List<CValue>>[const []];
  for (final values in perField) {
    final next = <List<CValue>>[];
    for (final prefix in combos) {
      for (final v in values) {
        next.add([...prefix, v]);
      }
    }
    combos = next;
  }
  // A key repeated across combinations is written once: the second write is a
  // no-op on an identical key (§4).
  final seen = <String>{};
  final out = <Uint8List>[];
  for (final c in combos) {
    final k = encodeKey(CArray([...c, documentId]));
    if (seen.add(_hex(k))) out.add(k);
  }
  return out;
}

/// Whether the uniqueness check of §1 applies to [values].
///
/// §3: "A **unique** index treats every `NULL` as distinct… Concretely, the
/// uniqueness check is **skipped** whenever any of `v1…vk` is `NULL`; it is not
/// that the check runs and passes."
bool uniquenessApplies(List<CValue> values) =>
    values.every((v) => v is! CNull);

/// The values of one index entry, without the trailing document id.
List<CValue> indexEntryValues(Uint8List key, int fieldCount) {
  final a = decodeKey(key) as CArray;
  return a.items.sublist(0, fieldCount);
}

/// The document id of one index entry: always the last element.
CValue indexEntryId(Uint8List key) {
  final a = decodeKey(key) as CArray;
  return a.items.last;
}

/// The scans §7 permits, and no others.
///
/// "An index tree supports exactly these, and an SDK's planner MUST express
/// every indexed predicate as one of them." Every one is built from the helpers
/// of `03-key-encoding.md` §8 and from no others — which is the point: a bound
/// assembled by hand is how `field >= 5` comes to miss an `I8(5)`.
class IndexScan {
  IndexScan._();

  /// Equality on a prefix of the indexed fields.
  static KeyRange eqPrefix(List<CValue> prefix) =>
      KeyRange.prefix(Keys.prefixOfArray(prefix));

  /// Equality on a prefix whose **last** element is numeric and should match
  /// across every numeric type, so `eq(5)` matches `I32(5)` and `F64(5.0)`.
  static KeyRange eqPrefixNumeric(List<CValue> prefix) =>
      KeyRange.prefix(Keys.arrayPrefixNumeric(prefix));

  /// A range on the j-th field after equality on `v1…v(j-1)`.
  ///
  /// **Numeric bounds are built from `N(v)`, never from `CKE(v)`.** A bound
  /// carrying the type code cuts between numeric *types* rather than numeric
  /// values; `03-key-encoding.md` §8.2 has the worked failure, and it is one of
  /// the four defects the third review round found that would have returned
  /// wrong answers.
  static KeyRange range(
    List<CValue> equalityPrefix, {
    CValue? lower,
    bool lowerInclusive = true,
    CValue? upper,
    bool upperInclusive = false,
  }) {
    final head = (ByteWriter()..bytes(Keys.prefixOfArray(equalityPrefix)))
      ..u8(0x01);
    final base = head.takeBytes();

    Uint8List body(CValue v) =>
        v is CInt || v is CFloat ? Keys.numberPrefix(v) : encodeKey(v);

    Uint8List cat(Uint8List a, Uint8List b) =>
        Uint8List(a.length + b.length)
          ..setRange(0, a.length, a)
          ..setRange(a.length, a.length + b.length, b);

    Uint8List lo;
    if (lower == null) {
      lo = base;
    } else {
      final k = cat(base, body(lower));
      lo = lowerInclusive ? k : (Keys.successor(k) ?? k);
    }

    Uint8List? hi;
    if (upper == null) {
      hi = Keys.successor(base);
    } else {
      final k = cat(base, body(upper));
      hi = upperInclusive ? Keys.successor(k) : k;
    }
    return KeyRange(lo, hi);
  }

  /// `starts_with` on a string in the j-th position,
  /// `03-key-encoding.md` §8.3.
  static KeyRange startsWith(List<CValue> equalityPrefix, String s) {
    final w = ByteWriter()
      ..bytes(Keys.prefixOfArray(equalityPrefix))
      ..u8(0x01)
      ..bytes(Keys.stringPrefix(s));
    return KeyRange.prefix(w.takeBytes());
  }

  /// A full scan of the index.
  static KeyRange all() => KeyRange(Keys.unboundedBelow, null);
}

String _hex(Uint8List b) {
  final sb = StringBuffer();
  for (final x in b) {
    sb.write(x.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}
