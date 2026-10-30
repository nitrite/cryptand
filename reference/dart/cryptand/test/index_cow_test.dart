/// F-195 / F-196 (ports of Java's `RTreeIncrementalTest` and
/// `VectorGraphTest`): the copy-on-write R-tree and the incremental Vamana
/// graph answer as brute force does through writes, early write-backs and a
/// reopen, and their pages are owned (verify is sound).
library;

import 'dart:io';
import 'dart:math' as math;

import 'package:cryptand/cryptand.dart';
import 'package:test/test.dart';

String _path(String tag) =>
    '${Directory.systemTemp.createTempSync('cryptand-$tag-').path}/db.cryptand';

Database _fresh(String path) {
  DatabaseFile.save(Database(engine: Engine()), path);
  return DatabaseFile.open(path);
}

void _sound(Database db) {
  final r = db.engine.verifyStructure(claims: db.indexClaims());
  expect(r.findings, isEmpty);
}

Geometry _pt(double x, double y) =>
    Geometry(type: GeometryType.point, hasZ: false, hasM: false, coords: [Coord(x, y)]);

Geometry _rect(double x0, double y0, double x1, double y1) => Geometry(
      type: GeometryType.polygon,
      hasZ: false,
      hasM: false,
      rings: [
        [Coord(x0, y0), Coord(x1, y0), Coord(x1, y1), Coord(x0, y1), Coord(x0, y0)]
      ],
    );

CDoc _at(double x, double y) => CDoc({'loc': CGeometry(encodeWkb(_pt(x, y)))});

void main() {
  test('random writes with early write-backs match brute force, before and after reopen', () {
    final saved = rtreeDirtyBudget;
    rtreeDirtyBudget = 8; // write back early and often
    addTearDown(() => rtreeDirtyBudget = saved);
    final path = _path('rtree-cow');
    var db = _fresh(path);
    final rnd = math.Random(195);
    final live = <int, (double, double)>{};
    final ids = <int>[];
    var next = 1;
    var c = db.createCollection('c');
    final sp = c.createSpatialIndex('loc');

    Set<int> brute(double x0, double y0, double x1, double y1) => {
          for (final e in live.entries)
            if (e.value.$1 >= x0 && e.value.$1 <= x1 && e.value.$2 >= y0 && e.value.$2 <= y1)
              e.key
        };

    for (var step = 0; step < 20000; step++) {
      final op = rnd.nextInt(10);
      final x = rnd.nextDouble() * 100, y = rnd.nextDouble() * 100;
      if (op < 6 || ids.isEmpty) {
        final id = next++;
        c.put(CNitriteId(id), _at(x, y));
        ids.add(id);
        live[id] = (x, y);
      } else if (op < 8) {
        final id = ids[rnd.nextInt(ids.length)];
        if (live.containsKey(id)) {
          c.put(CNitriteId(id), _at(x, y));
          live[id] = (x, y);
        }
      } else {
        final id = ids[rnd.nextInt(ids.length)];
        c.remove(CNitriteId(id));
        live.remove(id);
      }
      if (step % 2000 == 1999) db.engine.commit();
      if (step % 500 == 0) {
        final qx = rnd.nextDouble() * 90, qy = rnd.nextDouble() * 90;
        expect(sp.intersects(_rect(qx, qy, qx + 10, qy + 10)).toSet(),
            brute(qx, qy, qx + 10, qy + 10),
            reason: 'step $step');
      }
    }
    final all = _rect(-1, -1, 101, 101);
    expect(sp.intersects(all).length, live.length);
    expect(sp.size, live.length);
    db.engine.commit();
    expect(sp.tree.verify(), isEmpty);
    _sound(db);
    db.engine.close();

    db = DatabaseFile.open(path);
    c = db.collection('c')!;
    final sp2 = c.spatialIndexes.single;
    expect(sp2.size, live.length);
    expect(sp2.intersects(all).toSet(), live.keys.toSet());
    // nearestK: the 10 returned are among the 10 nearest by brute force.
    final knn = sp2.nearestK(const Coord(50, 50), 10);
    expect(knn.length, 10);
    final d = [
      for (final p in live.values) math.sqrt(math.pow(p.$1 - 50, 2) + math.pow(p.$2 - 50, 2))
    ]..sort();
    for (final (id, dist) in knn) {
      final p = live[id]!;
      expect(math.sqrt(math.pow(p.$1 - 50, 2) + math.pow(p.$2 - 50, 2)),
          lessThanOrEqualTo(d[9]), reason: 'knn $id');
      expect(dist, lessThanOrEqualTo(d[9]));
    }
    _sound(db);
    db.engine.close();
  });

  double l2(List<double> a, List<double> b) {
    var s = 0.0;
    for (var i = 0; i < a.length; i++) {
      s += (a[i] - b[i]) * (a[i] - b[i]);
    }
    return math.sqrt(s);
  }

  double recall(VectorIndex index, Map<int, List<double>> live, math.Random rnd, int dim) {
    var found = 0;
    const queries = 50;
    for (var q = 0; q < queries; q++) {
      final query = [for (var i = 0; i < dim; i++) rnd.nextDouble()];
      final all = [for (final e in live.entries) (e.key, l2(query, e.value))]
        ..sort((a, b) => a.$2.compareTo(b.$2));
      final truth = {for (final h in all.take(10)) h.$1};
      final hits = index.search(query, 10);
      expect(hits.length, 10);
      for (final (id, dist) in hits) {
        expect(live.containsKey(id), isTrue, reason: 'deleted document returned');
        expect(dist, closeTo(l2(query, live[id]!), 1e-6));
        if (truth.contains(id)) found++;
      }
    }
    return found / (queries * 10);
  }

  test('recall@10 against brute force stays high through deletes and a reopen', () {
    final saved = adjacencyDirtyBudget;
    adjacencyDirtyBudget = 8;
    addTearDown(() => adjacencyDirtyBudget = saved);
    final path = _path('vector-graph');
    var db = _fresh(path);
    const dim = 16;
    final rnd = math.Random(196);
    final live = <int, List<double>>{};
    final ids = <int>[];
    final c = db.createCollection('c');
    final index = c.createVectorIndex('emb', dim: dim, initialSlots: 16);
    for (var i = 0; i < 4000; i++) {
      final v = [for (var k = 0; k < dim; k++) rnd.nextDouble()];
      final f = CVector.f32(v);
      c.put(CNitriteId(i + 1), CDoc({'emb': f}));
      ids.add(i + 1);
      live[i + 1] = f.f32Values!; // what the region holds: f32
      if (i % 1000 == 999) db.engine.commit();
    }
    for (var i = 0; i < 400; i++) {
      final id = ids[rnd.nextInt(ids.length)];
      c.remove(CNitriteId(id));
      live.remove(id);
    }
    final r = recall(index, live, rnd, dim);
    expect(r, greaterThanOrEqualTo(0.95), reason: 'recall $r');
    expect(index.fallbacks, 0, reason: 'searches answered by the scan, not the graph');
    expect(index.verifyMaps(), isEmpty);
    db.engine.commit();
    _sound(db);
    db.engine.close();

    db = DatabaseFile.open(path);
    final reopened = db.collection('c')!.vectorIndexes.single;
    expect(reopened.size, live.length);
    final r2 = recall(reopened, live, rnd, dim);
    expect(r2, greaterThanOrEqualTo(0.95), reason: 'recall after reopen $r2');
    expect(reopened.fallbacks, 0);
    _sound(db);
    db.engine.close();
  });

  test('an encrypted file keeps its vector region and graph sealed and readable', () {
    final path = _path('vector-enc');
    final key = List<int>.generate(32, (i) => i);
    var db = DatabaseFile.create(path, credential: key, kdf: Keyslot.kdfRaw);
    final c = db.createCollection('c');
    final index = c.createVectorIndex('emb', dim: 4, initialSlots: 4);
    for (var i = 1; i <= 300; i++) {
      c.put(CNitriteId(i), CDoc({'emb': CVector.f32([i.toDouble(), 0, 0, 1])}));
    }
    expect(index.search([1, 0, 0, 1], 1).single.$1, 1);
    db.engine.commit();
    _sound(db);
    db.engine.close();
    db = DatabaseFile.open(path, key: key);
    final again = db.collection('c')!.vectorIndexes.single;
    expect(again.search([299, 0, 0, 1], 3).map((h) => h.$1), [299, 298, 300]);
    _sound(db);
    db.engine.close();
  });

  test('F-201: a clustered index is navigable beyond the entry point\'s cluster', () {
    // 50 tight clusters of 70 in 128-d: each outgrows m = 32. Without the far
    // slots recall was 0.025: a search never left the entry point's cluster.
    const k = 50, p = 70, dim = 128;
    final rnd = math.Random(201);
    final centres = [
      for (var c = 0; c < k; c++) [for (var d = 0; d < dim; d++) rnd.nextDouble()]
    ];
    final c = Database().createCollection('c');
    final index = c.createVectorIndex('emb', dim: dim, initialSlots: 64);
    final live = <int, List<double>>{};
    for (var i = 0; i < k * p; i++) {
      final f = CVector.f32([for (final x in centres[i % k]) x + 0.15 * (rnd.nextDouble() - 0.5)]);
      c.put(CNitriteId(i + 1), CDoc({'emb': f}));
      live[i + 1] = f.f32Values!;
    }
    var found = 0;
    for (var q = 0; q < 40; q++) {
      final query = [for (final x in centres[q * k ~/ 40]) x + 0.15 * (rnd.nextDouble() - 0.5)];
      final all = [for (final e in live.entries) (e.key, l2(query, e.value))]
        ..sort((a, b) => a.$2.compareTo(b.$2));
      final truth = {for (final h in all.take(10)) h.$1};
      for (final (id, _) in index.search(query, 10)) {
        if (truth.contains(id)) found++;
      }
    }
    expect(found / 400, greaterThanOrEqualTo(0.9), reason: 'recall ${found / 400}');
  }, timeout: const Timeout(Duration(minutes: 5)));
}
