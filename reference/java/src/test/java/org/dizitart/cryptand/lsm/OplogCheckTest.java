package org.dizitart.cryptand.lsm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dizitart.cryptand.Snapshot;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Model checker (PLAN M1.2), the Java port of Rust's {@code oplog_check}:
 * replays an op-log ({@code reference/conformance/oplog/}) against
 * {@link Engine} and a sorted map, comparing every read and the full-scan
 * digest at the end and after every {@code reopen}.
 *
 * <p>Replays {@code regress/*.jsonl}, and every {@code *.jsonl} in
 * {@code -Doplog.dir=DIR} when set ({@code tools/oplog_java.sh} fills one
 * from Rust's {@code oplog_gen}; ponytail: no Java generator, Rust's is the
 * one source of logs).
 */
class OplogCheckTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] KEY = new byte[32];
    private static final Comparator<byte[]> MEMCMP = Arrays::compareUnsigned;

    static {
        Arrays.fill(KEY, (byte) 7);
    }

    /** One model row: value and absolute expiry (0 = none). */
    record Cell(byte[] v, long x) {}

    /** tree → key → cell. */
    static final class Model extends TreeMap<Integer, TreeMap<byte[], Cell>> {
        Model copy() {
            Model m = new Model();
            forEach((t, tree) -> m.put(t, new TreeMap<>(tree)));
            return m;
        }

        TreeMap<byte[], Cell> tree(int t) {
            return computeIfAbsent(t, k -> new TreeMap<>(MEMCMP));
        }
    }

    static byte[] valueBytes(int n, long seed) {
        ByteBuffer b = ByteBuffer.allocate(n + 8).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        long state = seed;
        while (b.position() < n) {
            state += 0x9E3779B97F4A7C15L;
            long z = state;
            z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
            z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
            b.putLong(z ^ (z >>> 31));
        }
        return Arrays.copyOf(b.array(), n);
    }

    static byte[] unhex(String s) {
        return HexFormat.of().parseHex(s);
    }

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    static byte[] cke(byte[] raw) {
        return Cke.encode(new Value.Bytes(raw));
    }

    static byte[] fromCke(byte[] k) {
        return ((Value.Bytes) Cke.decode(k)).value();
    }

    static String shortV(byte[] v) {
        return v == null ? "absent" : v.length + " bytes " + hex(Arrays.copyOf(v, Math.min(8, v.length))) + "…";
    }

    static final class Diverged extends RuntimeException {
        Diverged(String m) {
            super(m);
        }
    }

    static final class Run {
        final Path path;
        final boolean encrypted;
        final Profile profile;
        final int trees;
        Engine e;
        Model model = new Model();
        /**
         * Model after each user batch, keyed by the batch's last seq: what a
         * snapshot at that seq or above (up to the next batch) sees. The
         * engine's own threads also take seqs, so tips are not contiguous.
         */
        final TreeMap<Long, Model> history = new TreeMap<>();
        /** Last seq → first seq of each user batch. */
        final TreeMap<Long, Long> batchFirst = new TreeMap<>();
        final Map<Long, Snapshot> snaps = new HashMap<>();
        final Map<Long, Model> snapModels = new HashMap<>();
        long clock;
        /** Run the background compactor's round after every op, at a deterministic point. */
        boolean maintain = Boolean.getBoolean("oplog.maintain");

        Run(Path path, boolean encrypted, Profile profile, int trees) {
            this.path = path;
            this.encrypted = encrypted;
            this.profile = profile;
            this.trees = trees;
        }

        Engine.Options options() {
            Engine.Options o = new Engine.Options();
            o.profile = profile;
            // `none`: the writer acknowledges itself, so a lone put is not an fsync.
            o.durability = Superblock.Durability.NONE;
            o.clock = () -> clock;
            o.backgroundCompaction = !Boolean.getBoolean("oplog.idle");
            if (encrypted) {
                o.encrypt = true;
                o.rawKey = KEY.clone();
            }
            return o;
        }

        /** Commits a user batch and records the model it leaves, keyed by its last seq. */
        void commit(Engine.Batch b) {
            int n = b.size();
            long last = b.commit();
            history.put(last, model.copy());
            batchFirst.put(last, last - n + 1);
        }

        List<byte[][]> modelScan(Model m, int t, byte[] lo, byte[] hi) {
            List<byte[][]> out = new ArrayList<>();
            TreeMap<byte[], Cell> tree = m.get(t);
            if (tree == null) {
                return out;
            }
            for (var en : tree.entrySet()) {
                byte[] k = en.getKey();
                if ((lo == null || MEMCMP.compare(k, lo) >= 0) && (hi == null || MEMCMP.compare(k, hi) < 0)
                        && (en.getValue().x == 0 || en.getValue().x > clock)) {
                    out.add(new byte[][]{k, en.getValue().v});
                }
            }
            return out;
        }

        List<byte[][]> engineScan(int t, byte[] lo, byte[] hi, Snapshot s) {
            List<byte[][]> out = new ArrayList<>();
            byte[] l = lo == null ? null : cke(lo);
            byte[] h = hi == null ? null : cke(hi);
            try (Engine.Cursor c = s == null ? e.scan(t, l, h, false) : e.scan(t, l, h, false, s.seq(), clock)) {
                while (c.next()) {
                    // Java's cursor includes its upper bound (F-025); the op-log's is exclusive.
                    if (h != null && Arrays.equals(c.row().key(), h)) {
                        break;
                    }
                    out.add(new byte[][]{fromCke(c.row().key()), c.row().value()});
                }
            }
            return out;
        }

        void compareScan(int t, List<byte[][]> want, List<byte[][]> got) {
            int n = Math.min(want.size(), got.size());
            int i = 0;
            while (i < n && Arrays.equals(want.get(i)[0], got.get(i)[0]) && Arrays.equals(want.get(i)[1], got.get(i)[1])) {
                i++;
            }
            if (i == n && want.size() == got.size()) {
                return;
            }
            throw new Diverged("scan t=" + t + ": model " + want.size() + " rows, engine " + got.size()
                    + " rows; first difference at row " + i + ": model " + row(want, i) + " engine " + row(got, i));
        }

        static String row(List<byte[][]> rows, int i) {
            return i < rows.size() ? "k=" + hex(rows.get(i)[0]) + " " + shortV(rows.get(i)[1]) : "end";
        }

        /** §9's integrity pass: damage diverges; a LEAK (repairable) and POLICY (maintenance not run in idle replays) do not. */
        void verify() {
            for (var f : org.dizitart.cryptand.ops.Verify.run(e).findings()) {
                if (f.kind() != org.dizitart.cryptand.ops.Verify.Kind.LEAK && f.kind() != org.dizitart.cryptand.ops.Verify.Kind.POLICY) {
                    throw new Diverged("verify: " + f.kind() + " " + f.message());
                }
            }
        }

        String digestCheck() throws Exception {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            for (int t = 1; t <= trees; t++) {
                List<byte[][]> got = engineScan(t, null, null, null);
                compareScan(t, modelScan(model, t, null, null), got);
                for (byte[][] r : got) {
                    d.update(ByteBuffer.allocate(8).putInt(t).putInt(r[0].length).array());
                    d.update(r[0]);
                    d.update(ByteBuffer.allocate(4).putInt(r[1].length).array());
                    d.update(r[1]);
                }
            }
            return hex(d.digest());
        }

        void write(JsonNode w, Engine.Batch b) {
            int t = w.get("t").asInt();
            byte[] k = unhex(w.get("k").asText());
            switch (w.get("op").asText()) {
                case "put" -> {
                    byte[] v = valueBytes(w.get("v").get("n").asInt(), w.get("v").get("s").asLong());
                    long x = w.has("x") ? w.get("x").asLong() : 0;
                    model.tree(t).put(k, new Cell(v, x));
                    if (x != 0) {
                        b.putWithExpiry(t, cke(k), v, x);
                    } else {
                        b.put(t, cke(k), v);
                    }
                }
                case "del" -> {
                    model.tree(t).remove(k);
                    b.remove(t, cke(k));
                }
                default -> throw new Diverged(w.get("op") + " not allowed here");
            }
        }

        Snapshot at(JsonNode j) {
            if (!j.has("at")) {
                return null;
            }
            Snapshot s = snaps.get(j.get("at").asLong());
            if (s == null) {
                throw new IllegalArgumentException("invalid log");
            }
            return s;
        }

        void step(JsonNode j) throws Exception {
            switch (j.get("op").asText()) {
                case "put", "del" -> {
                    Engine.Batch b = e.batch();
                    write(j, b);
                    commit(b);
                }
                case "range_del" -> {
                    int t = j.get("t").asInt();
                    byte[] lo = unhex(j.get("lo").asText()), hi = unhex(j.get("hi").asText());
                    model.tree(t).subMap(lo, hi).clear();
                    commit(e.batch().removeRange(t, cke(lo), cke(hi)));
                }
                case "batch" -> {
                    Engine.Batch b = e.batch();
                    for (JsonNode w : j.get("ops")) {
                        write(w, b);
                    }
                    commit(b);
                }
                case "get" -> {
                    int t = j.get("t").asInt();
                    byte[] k = unhex(j.get("k").asText());
                    Snapshot s = at(j);
                    Model m = s == null ? model : snapModels.get(j.get("at").asLong());
                    Cell c = m.containsKey(t) ? m.get(t).get(k) : null;
                    byte[] want = c == null || (c.x != 0 && c.x <= clock) ? null : c.v;
                    byte[] got = s == null ? e.get(t, cke(k)) : e.get(t, cke(k), s.seq(), clock);
                    if (!Arrays.equals(want, got)) {
                        throw new Diverged("get t=" + t + " k=" + hex(k) + ": model " + shortV(want) + " engine " + shortV(got));
                    }
                }
                case "scan" -> {
                    int t = j.get("t").asInt();
                    byte[] lo = j.has("lo") ? unhex(j.get("lo").asText()) : null;
                    byte[] hi = j.has("hi") ? unhex(j.get("hi").asText()) : null;
                    Snapshot s = at(j);
                    Model m = s == null ? model : snapModels.get(j.get("at").asLong());
                    compareScan(t, modelScan(m, t, lo, hi), engineScan(t, lo, hi, s));
                }
                case "snapshot" -> {
                    long id = j.get("id").asLong();
                    if (snaps.containsKey(id)) {
                        throw new IllegalArgumentException("invalid log");
                    }
                    Snapshot s = e.pin();
                    // A snapshot sees the published superblock's visible_seq: some earlier step's tip.
                    Map.Entry<Long, Long> inside = batchFirst.ceilingEntry(s.seq());
                    if (inside != null && inside.getValue() <= s.seq() && s.seq() < inside.getKey()) {
                        throw new Diverged("snapshot seq " + s.seq() + " splits batch "
                                + inside.getValue() + ".." + inside.getKey());
                    }
                    Model m = history.floorEntry(s.seq()).getValue();
                    snaps.put(id, s);
                    snapModels.put(id, m);
                }
                case "release" -> {
                    Snapshot s = snaps.remove(j.get("id").asLong());
                    if (s == null) {
                        throw new IllegalArgumentException("invalid log");
                    }
                    snapModels.remove(j.get("id").asLong());
                    e.unpin(s);
                }
                case "commit", "checkpoint" -> e.commitNow(true); // ponytail: durability is the engine option, not per commit
                case "compact" -> {
                    e.compact();
                    e.collectIfNeeded(); // Rust's compact runs GC while over debt
                }
                case "shrink" -> e.shrink();
                case "ttl_advance" -> clock += j.get("ms").asLong();
                case "reopen" -> {
                    if (!snaps.isEmpty()) {
                        throw new IllegalArgumentException("invalid log");
                    }
                    e.commitNow(true);
                    e.close();
                    e = Engine.open(path, options());
                    history.clear();
                    batchFirst.clear();
                    history.put(Snapshot.of(e.superblock()).seq(), model.copy());
                    verify();
                    digestCheck();
                }
                default -> throw new Diverged("unknown op " + j.get("op"));
            }
            if (maintain) {
                e.maintain();
            }
            // Nothing below the published visible_seq can be snapshotted again.
            Long floor = history.floorKey(Snapshot.of(e.superblock()).seq());
            if (floor != null) {
                history.headMap(floor).clear();
                batchFirst.headMap(floor).clear();
            }
        }
    }

    /** Replays one log; returns the digest or throws Diverged("line N: …"). */
    static String replay(List<String> lines, Path dir) throws Exception {
        return replay(lines, dir, Boolean.getBoolean("oplog.maintain"));
    }

    static String replay(List<String> lines, Path dir, boolean maintain) throws Exception {
        JsonNode h = JSON.readTree(lines.get(0));
        if (h.path("oplog").asInt() != 1) {
            throw new Diverged("line 1: not an oplog v1");
        }
        Profile profile = switch (h.path("profile").asText("desktop")) {
            case "mobile" -> Profile.MOBILE;
            case "tablet" -> Profile.TABLET;
            case "server" -> Profile.SERVER;
            default -> Profile.DESKTOP;
        };
        Path path = dir.resolve("oplog-" + h.path("seed").asText() + ".cff");
        Files.deleteIfExists(path);
        Run r = new Run(path, h.path("encrypted").asBoolean(), profile, h.path("trees").asInt(1));
        r.maintain = maintain;
        r.e = Engine.create(path, r.options());
        try {
            r.history.put(0L, new Model());
            for (int n = 1; n < lines.size(); n++) {
                if (lines.get(n).isBlank()) {
                    continue;
                }
                JsonNode j = JSON.readTree(lines.get(n));
                try {
                    r.step(j);
                } catch (RuntimeException x) {
                    if (Boolean.getBoolean("oplog.trace")) {
                        x.printStackTrace();
                    }
                    throw new Diverged("line " + (n + 1) + ": " + j.get("op") + " — " + x);
                }
            }
            try {
                r.verify();
                return r.digestCheck();
            } catch (RuntimeException x) {
                throw new Diverged("end: " + x);
            }
        } finally {
            for (Snapshot s : r.snaps.values()) {
                r.e.unpin(s);
            }
            try {
                r.e.close();
            } catch (RuntimeException ignored) {
                // already failing
            }
            Files.deleteIfExists(path);
        }
    }

    /** The model effect of one op without an engine: lines another language played (M1.3). */
    static long modelApply(Model m, long clock, JsonNode j) {
        switch (j.get("op").asText()) {
            case "put" -> m.tree(j.get("t").asInt()).put(unhex(j.get("k").asText()),
                    new Cell(valueBytes(j.get("v").get("n").asInt(), j.get("v").get("s").asLong()),
                            j.has("x") ? j.get("x").asLong() : 0));
            case "del" -> m.tree(j.get("t").asInt()).remove(unhex(j.get("k").asText()));
            case "range_del" -> m.tree(j.get("t").asInt())
                    .subMap(unhex(j.get("lo").asText()), unhex(j.get("hi").asText())).clear();
            case "batch" -> {
                for (JsonNode w : j.get("ops")) {
                    clock = modelApply(m, clock, w);
                }
            }
            case "ttl_advance" -> clock += j.get("ms").asLong();
            default -> {
            }
        }
        return clock;
    }

    /**
     * M1.3, one leg of a cross-language hop, as Rust's {@code oplog_check --hop}:
     * lines before {@code from} (1-based, header = 1) update only the model;
     * {@code db} is created ({@code from} = 2) or opened as another language
     * left it and its digest checked; lines {@code [from, to)} are replayed;
     * then commit, close, keep the file.
     */
    static String hop(List<String> lines, Path db, int from, int to) throws Exception {
        JsonNode h = JSON.readTree(lines.get(0));
        Profile profile = switch (h.path("profile").asText("desktop")) {
            case "mobile" -> Profile.MOBILE;
            case "tablet" -> Profile.TABLET;
            case "server" -> Profile.SERVER;
            default -> Profile.DESKTOP;
        };
        Run r = new Run(db, h.path("encrypted").asBoolean(), profile, h.path("trees").asInt(1));
        for (String l : lines.subList(1, from - 1)) {
            r.clock = modelApply(r.model, r.clock, JSON.readTree(l));
        }
        r.e = from == 2 ? Engine.create(db, r.options()) : Engine.open(db, r.options());
        try {
            r.history.put(Snapshot.of(r.e.superblock()).seq(), r.model.copy());
            try {
                r.digestCheck();
            } catch (RuntimeException x) {
                throw new Diverged("at open: " + x.getMessage());
            }
            for (int n = from - 1; n < to - 1; n++) {
                JsonNode j = JSON.readTree(lines.get(n));
                try {
                    r.step(j);
                } catch (RuntimeException x) {
                    throw new Diverged("line " + (n + 1) + ": " + j.get("op") + " — " + x);
                }
            }
            r.e.commitNow(true);
            r.verify();
            return r.digestCheck();
        } finally {
            r.e.close();
        }
    }

    static List<Path> logs(Path dir) throws Exception {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.toString().endsWith(".jsonl")).sorted().toList();
        }
    }

    static void replayAll(List<Path> files, Path tmp, boolean... maintain) throws Exception {
        List<String> fails = new ArrayList<>();
        for (Path f : files) {
            for (boolean m : maintain.length == 0 ? new boolean[]{Boolean.getBoolean("oplog.maintain")} : maintain) {
                try {
                    replay(Files.readAllLines(f), tmp, m);
                } catch (RuntimeException x) {
                    fails.add(f.getFileName() + (m ? " (maintain)" : "") + ": " + x.getMessage());
                }
            }
        }
        assertTrue(fails.isEmpty(), fails.size() + "/" + files.size() + " logs diverge:\n" + String.join("\n", fails));
    }

    /**
     * {@code java -cp … OplogCheckTest FILE.jsonl…} replays; {@code --shrink FILE}
     * prints a minimal still-failing log (greedy chunk removal, as Rust's).
     */
    public static void main(String[] args) throws Exception {
        if (args[0].equals("--hop")) {
            try {
                System.out.println("ok digest " + hop(Files.readAllLines(Path.of(args[1])), Path.of(args[2]),
                        Integer.parseInt(args[3]), Integer.parseInt(args[4])));
            } catch (Diverged x) {
                System.out.println("FAIL " + x.getMessage());
                System.exit(1);
            }
            return;
        }
        Path tmp = Files.createTempDirectory("oplog_check");
        if (args[0].equals("--shrink")) {
            List<String> lines = new ArrayList<>(Files.readAllLines(Path.of(args[1])));
            lines.removeIf(String::isBlank);
            for (int chunk = (lines.size() - 1) / 2; chunk >= 1; ) {
                boolean dropped = false;
                for (int i = 1; i < lines.size(); ) {
                    int end = Math.min(i + chunk, lines.size());
                    List<String> trial = new ArrayList<>(lines.subList(0, i));
                    trial.addAll(lines.subList(end, lines.size()));
                    if (fails(trial, tmp)) {
                        lines = trial;
                        dropped = true;
                    } else {
                        i = end;
                    }
                }
                if (!dropped) {
                    chunk /= 2;
                }
            }
            lines.forEach(System.out::println);
            System.err.println(lines.size() + " lines");
            return;
        }
        for (String f : args) {
            try {
                System.out.println(f + ": ok digest " + replay(Files.readAllLines(Path.of(f)), tmp));
            } catch (RuntimeException x) {
                System.out.println(f + ": FAIL " + x.getMessage());
            }
        }
    }

    /** Fails in any of 5 replays: the engine's own threads make some divergences racy. */
    private static boolean fails(List<String> lines, Path tmp) throws Exception {
        for (int i = 0; i < 5; i++) {
            try {
                replay(lines, tmp);
            } catch (RuntimeException x) {
                if (x.getMessage() != null && x.getMessage().contains("invalid log")) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    @Test
    void valueBytesMatchTheRustVector() {
        assertArrayEquals(ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putLong(0xE220A8397B1DCDAFL).array(), valueBytes(8, 0));
        assertArrayEquals(new byte[]{(byte) 0xAF, (byte) 0xCD, 0x1D}, valueBytes(3, 0));
        assertEquals(0, valueBytes(0, 5).length);
    }

    @Test
    void regressLogsReplay(@TempDir Path tmp) throws Exception {
        List<Path> files = logs(Path.of("../conformance/oplog/regress"));
        assertFalse(files.isEmpty());
        // Twice: as logged, and with maintain() after every op (F-031 needs a
        // maintenance round between its writes; Rust compacts synchronously).
        replayAll(files, tmp, false, true);
    }

    @Test
    void generatedLogsReplay(@TempDir Path tmp) throws Exception {
        String dir = System.getProperty("oplog.dir");
        org.junit.jupiter.api.Assumptions.assumeTrue(dir != null, "set -Doplog.dir to replay generated logs");
        replayAll(logs(Path.of(dir)), tmp);
    }
}
