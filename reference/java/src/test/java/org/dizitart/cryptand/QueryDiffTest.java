package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.IndexKeys;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Compare;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;
import java.util.TreeSet;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * M1.5 query differential: an index scan built from {@code 06-indexes.md} §7's
 * helpers against a brute-force model using {@code 02-value-encoding.md} §8's
 * logical order. {@code -Dquery.seeds=N} for a sweep.
 */
class QueryDiffTest {

    private static final NumType[] WIDTHS = {NumType.I8, NumType.I32, NumType.I64, NumType.U64, NumType.F64, NumType.F32};
    private static final String[] WORDS = {"", "a", "ab", "abc", "b", "ba"};

    private static Value scalar(SplittableRandom r) {
        int k = r.nextInt(10);
        if (k == 0) return Value.NULL;
        if (k == 1) return new Value.Bool(r.nextBoolean());
        if (k < 4) return new Value.Str(WORDS[r.nextInt(6)]);
        long n = r.nextInt(11) - 3; // small, so values collide across types
        NumType w = WIDTHS[r.nextInt(6)];
        switch (w) {
            case U64: return Value.integer(w, Math.abs(n));
            case F64: case F32: return new Value.Float(w, n + (r.nextInt(3) == 0 ? 0.5 : 0.0));
            default: return Value.integer(w, n);
        }
    }

    private static Value.Doc doc(SplittableRandom r) {
        Map<String, Value> f = new LinkedHashMap<>();
        int k = r.nextInt(8);
        if (k == 1) {
            List<Value> items = new ArrayList<>();
            for (int i = r.nextInt(4); i > 0; i--) items.add(scalar(r));
            f.put("v", new Value.Array(items));
        } else if (k > 1) {
            f.put("v", scalar(r));
        }
        return Value.Doc.of(f);
    }

    private static void runSeed(Path dir, long seed) {
        SplittableRandom r = new SplittableRandom(seed);
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.durability = Superblock.Durability.OS;
        try (Database db = Database.create(dir.resolve("q" + seed + ".cryptand"), o)) {
            Collection c = db.collection("q");
            Collection.IndexBinding idx = c.createIndex(List.of("v"), false, false);
            Map<Long, Value.Doc> live = new LinkedHashMap<>();
            for (int i = 20 + r.nextInt(60); i > 0; i--) {
                Value.Doc d = doc(r);
                live.put(c.insert(d), d);
                if (r.nextInt(6) == 0) {
                    long gone = new ArrayList<>(live.keySet()).get(r.nextInt(live.size()));
                    c.remove(gone);
                    live.remove(gone);
                }
            }
            for (int q = 0; q < 40; q++) {
                Value b = scalar(r);
                int k = r.nextInt(7);
                String label;
                List<Long> got;
                Predicate<Value> pred;
                if (k == 0 && b instanceof Value.Str) {
                    Value.Str s = ((Value.Str) b);
                    label = "starts_with " + s;
                    got = idx.startsWith(List.of(), s.value());
                    pred = x -> x instanceof Value.Str && ((Value.Str) x).value().startsWith(s.value());
                } else if (k <= 1) {
                    label = "eq " + b;
                    got = Compare.isNumeric(b) ? idx.findNumeric(List.of(b)) : idx.find(List.of(b));
                    pred = x -> Compare.compare(x, b) == 0;
                } else {
                    IndexKeys.Cmp op = IndexKeys.Cmp.values()[(k - 2) % 4];
                    label = op + " " + b;
                    got = idx.range(List.of(), op, b);
                    pred = x -> {
                        int c0 = Compare.compare(x, b);
                        switch (op) {
                            case GT: return c0 > 0;
                            case GE: return c0 >= 0;
                            case LT: return c0 < 0;
                            case LE: return c0 <= 0;
                            default: throw new AssertionError(op);
                        }
                    };
                }
                TreeSet<Long> want = new TreeSet<>();
                live.forEach((id, d) -> {
                    List<Value> vs = IndexKeys.resolve(d, List.of("v"));
                    if (vs == null) vs = List.of(Value.NULL);
                    if (vs.stream().anyMatch(pred)) want.add(id);
                });
                assertEquals(List.copyOf(want), List.copyOf(new TreeSet<>(got)), "seed " + seed + " query " + q + ": " + label);
            }
        }
    }

    @Test
    void anIndexScanAnswersWhatAFullScanAnswers(@TempDir Path dir) {
        long n = Long.getLong("query.seeds", 50);
        for (long seed = 0; seed < n; seed++) {
            runSeed(dir, seed);
        }
    }
}
