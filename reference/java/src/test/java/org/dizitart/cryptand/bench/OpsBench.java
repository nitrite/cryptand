package org.dizitart.cryptand.bench;

import org.dizitart.cryptand.Collection;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The cross-language operational benchmark — see
 * {@code reference/bench/README.md}.
 *
 * <p>The Java port had <strong>no benchmarks at all</strong>, while Rust and
 * Dart each carried a set for the {@code P1}–{@code P11} predictions of
 * {@code design/performance-model.md}. Those measure the <em>design</em>. This
 * measures what "performance claim" usually means to a person choosing a
 * database — what the implementation does per second, and what it costs on the
 * device — and prints the same rows as the other two so the three can be put
 * next to each other.
 *
 * <p>{@code design/performance-model.md} §8's rule governs the output: <strong>a
 * counter is the primary result and wall time is an observation.</strong> Page
 * reads per lookup is comparable across a change; microseconds are not, and are
 * labelled.
 *
 * <p>Run it with
 * {@code mvn -q -B compile exec:java -Dexec.mainClass=org.dizitart.cryptand.bench.OpsBench}.
 */
public final class OpsBench {

    private OpsBench() {
    }

    private static final int TREE_DOCS = 20_000;

    /** Snowflake-shaped ids: a long shared prefix, as §1 assumes. */
    private static long snowflake(long i) {
        return 1_767_225_600_000L * 4_194_304L + i * 4096L + 1L;
    }

    /**
     * §1's document shape: 20 fields, names averaging 12 B, values averaging
     * 20 B, giving a ~516 B logical record. Built to that shape deliberately —
     * every density figure in §6 is costed against it, so a smaller document
     * would flatter the name dictionary and understate decode work.
     */
    private static Value.Doc doc(long i) {
        String pad = String.format("%06d", i);
        Map<String, Value> f = new LinkedHashMap<>();
        f.put("_id", new Value.NitriteId(snowflake(i)));
        String[] names = {"custAddr1_ln", "custAddr2_ln", "custCityName", "custPostCode",
                "custCountryX", "custEmailAdr", "custPhoneNum", "ordReference",
                "ordStatusTxt", "ordCurrencyC", "ordNotesText", "whseLocation",
                "carrierName_", "trackingNumb"};
        String[] prefixes = {"addr1", "addr2", "city", "post", "ctry", "mail", "phon",
                "ordr", "stat", "curr", "note", "whse", "carr", "trak"};
        for (int k = 0; k < names.length; k++) {
            StringBuilder v = new StringBuilder(prefixes[k]).append('-').append(pad).append("-x");
            while (v.length() < 19) {
                v.append('y');
            }
            f.put(names[k], new Value.Str(v.toString()));
        }
        f.put("ordTotMinorU", Value.integer(NumType.INT_VAR, 1299 + i));
        f.put("ordTaxMinorU", Value.integer(NumType.INT_VAR, 216));
        f.put("ordShipMinor", Value.integer(NumType.INT_VAR, 499));
        f.put("placedAtUtcM", new Value.Timestamp(1_767_225_000_000L));
        f.put("dispatchUtcM", new Value.Timestamp(1_767_225_600_000L));
        return new Value.Doc(f);
    }

    /**
     * {@code counter} and {@code observation} are the two words the other two
     * implementations print too, so a comparison script filters on them rather
     * than on a hand-maintained list of row names.
     */
    private static void row(String name, Object value, String unit, boolean primary) {
        System.out.println(name + "=" + value + " unit=" + unit
                + " kind=" + (primary ? "counter" : "observation"));
    }

    private static long percentile(List<Long> xs, double p) {
        if (xs.isEmpty()) {
            return 0;
        }
        List<Long> s = new ArrayList<>(xs);
        Collections.sort(s);
        return s.get((int) Math.round((s.size() - 1) * p));
    }

    private static String f(double v, int d) {
        return String.format("%." + d + "f", v);
    }

    private static Engine.Options options(int codec) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static final class Filled {
        private final long logical;
        private final double secs;
        private final Collection.IndexBinding index;

        public Filled(long logical, double secs, Collection.IndexBinding index) {
            this.logical = logical;
            this.secs = secs;
            this.index = index;
        }

        public long logical() {
            return logical;
        }

        public double secs() {
            return secs;
        }

        public Collection.IndexBinding index() {
            return index;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Filled)) {
                return false;
            }
            Filled that = (Filled) o;
            return logical == that.logical
                    && Double.compare(secs, that.secs) == 0
                    && java.util.Objects.equals(index, that.index);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(logical, secs, index);
        }

        @Override
        public String toString() {
            return "Filled[" + "logical=" + logical + ", " + "secs=" + secs + ", " + "index=" + index + "]";
        }
    }

    private static Filled fill(Database db, int n, boolean withIndex) {
        Collection c = db.collection("orders");
        Collection.IndexBinding idx =
                withIndex ? c.createIndex(List.of("ordStatusTxt"), false, false) : null;
        long logical = 0;
        long t0 = System.nanoTime();
        for (long i = 0; i < n; i++) {
            Value.Doc d = doc(i);
            logical += Cve.encode(d).length;
            c.insert(d);
        }
        db.commit();
        double secs = (System.nanoTime() - t0) / 1e9;
        return new Filled(logical, secs, idx);
    }

    private static Path tmp(String tag) throws IOException {
        Path d = Files.createTempDirectory("cryptand-ops-" + tag + "-");
        return d.resolve("db.cryptand");
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : TREE_DOCS;
        System.out.println("# cryptand ops bench -- java");
        System.out.println("# implementation=java documents=" + n
                + " profile=desktop durability=os");

        // ------------------------------------------------------------------
        // insert
        // ------------------------------------------------------------------
        Path path = tmp("main");
        long deviceBytes;
        long spaceBytes;
        long logical;
        double secs;
        try (Database db = Database.create(path, options(Superblock.Codec.NONE))) {
            Filled r = fill(db, n, true);
            logical = r.logical();
            secs = r.secs();
            db.engine().maintain();
            db.commit();
            // `13-operations.md` §6's own required metrics, not the file
            // length. The file is grown in large chunks, so `Files.size` is
            // preallocated space: it reported **35x** the logical bytes, a
            // number that describes the allocator and not the engine. §6
            // already defines the two quantities this row wants, and all three
            // implementations already compute them.
            deviceBytes = db.engine().bytesWrittenDevice();
            long logicalWritten = db.engine().bytesWrittenLogical();

            spaceBytes = db.engine().pager().pageCount()
                    * (long) db.engine().superblock().pageSize();

            row("insert_docs_per_s", f(n / secs, 0), "docs/s", false);
            row("insert_bytes_device", deviceBytes, "bytes", false);
            row("insert_logical_bytes", logicalWritten, "bytes", true);
            // An **observation**, not a counter, on this implementation: see
            // the note on `bytesOn` below. The compactor runs in the
            // background, so what has reached the device at the moment this is
            // read is not a property of the workload.
            row("write_amplification",
                    f((double) deviceBytes / Math.max(1, logicalWritten), 3), "ratio", false);
        }

        // ------------------------------------------------------------------
        // point read -- through a reopened file, and after maintenance, so it
        // measures the engine rather than the memtable. A benchmark that reads
        // what it just wrote measures neither.
        // ------------------------------------------------------------------
        try (Database db = Database.open(path, options(Superblock.Codec.NONE))) {
            Collection c = db.collection("orders");
            long seed = 0x51EDC0DEL;
            // Warm the path. On a JVM the first thousand reads are the
            // interpreter, not the engine, and reporting those would describe
            // a runtime nobody keeps running.
            for (int i = 0; i < 2000; i++) {
                seed = next(seed);
                c.get(snowflake(Math.floorMod(seed, n)));
            }
            long readsBefore = db.engine().pager().pageReads();
            int reads = Math.min(5000, n);
            List<Long> samples = new ArrayList<>(reads);
            for (int i = 0; i < reads; i++) {
                seed = next(seed);
                long id = snowflake(Math.floorMod(seed, n));
                long t = System.nanoTime();
                Value.Doc got = c.get(id);
                samples.add(System.nanoTime() - t);
                if (got == null) {
                    throw new IllegalStateException("the fixture must hold every id it reads");
                }
            }
            long pageReads = db.engine().pager().pageReads() - readsBefore;
            row("point_read_us_p50", f(percentile(samples, 0.50) / 1000.0, 2), "us", false);
            row("point_read_us_p99", f(percentile(samples, 0.99) / 1000.0, 2), "us", false);
            row("point_read_page_reads", f((double) pageReads / reads, 3), "pages/lookup", true);

            // ----------------------------------------------------------
            // scan
            // ----------------------------------------------------------
            long scanBefore = db.engine().pager().pageReads();
            long t = System.nanoTime();
            int rows = 0;
            try (Engine.Cursor cur = c.scan(false)) {
                while (cur.next()) {
                    rows++;
                }
            }
            double scanSecs = (System.nanoTime() - t) / 1e9;
            long scanPages = db.engine().pager().pageReads() - scanBefore;
            if (rows != n) {
                throw new IllegalStateException("the scan returned " + rows + " of " + n);
            }
            row("scan_rows_per_s", f(rows / scanSecs, 0), "rows/s", false);
            row("scan_page_reads_per_row", f((double) scanPages / rows, 4), "pages/row", true);

            // ----------------------------------------------------------
            // index lookup
            // ----------------------------------------------------------
            List<Collection.IndexBinding> idxs = c.indexes();
            if (!idxs.isEmpty()) {
                Collection.IndexBinding ix = idxs.get(0);
                List<Long> s = new ArrayList<>();
                int probes = Math.min(2000, n);
                for (int i = 0; i < probes; i++) {
                    Value key = doc(i).fields().get("ordStatusTxt");
                    long t0 = System.nanoTime();
                    ix.find(List.of(key));
                    s.add(System.nanoTime() - t0);
                }
                row("index_lookup_us_p50", f(percentile(s, 0.50) / 1000.0, 2), "us", false);
            }
        }

        // ------------------------------------------------------------------
        // the codec -- and the row is here because it measures ZERO, which is
        // why page_codec is 0 in every profile now. 01-container.md §7 carries
        // the reasoning: a page is a fixed-size slot, so a compressed page
        // occupies the same slot and is written with the same page_size-byte
        // write. The row stays so that a container shape which *does* make it
        // pay shows up here rather than in an argument.
        // ------------------------------------------------------------------
        Path path2 = tmp("codec");
        long bytesOn;
        try (Database db = Database.create(path2, options(Superblock.Codec.LZ4))) {
            db.engine().pager().setPageCodec(Superblock.Codec.LZ4);
            fill(db, n, true);
            db.engine().maintain();
            db.commit();
            // **Not `bytesWrittenDevice` here.** That counter varies 2.2x
            // between two runs of the *same* configuration on this
            // implementation, because the background compactor has done a
            // variable amount of work by the time it is read -- and a codec
            // comparison built on it reported a 27 % "saving" that was
            // entirely noise, contradicting a controlled measurement already
            // written into `01-container.md` §7. `pageCount` is deterministic
            // for a given workload, and it is also the right question: does
            // compression reduce the space the database occupies?
            bytesOn = db.engine().pager().pageCount()
                    * (long) db.engine().superblock().pageSize();
        }
        row("codec_bytes_on", bytesOn, "bytes", true);
        row("codec_bytes_off", spaceBytes, "bytes", true);
        row("codec_saving", f(1.0 - (double) bytesOn / spaceBytes, 4), "ratio", true);

        // ------------------------------------------------------------------
        // the cipher, on the write path -- P11
        // ------------------------------------------------------------------
        Path path3 = tmp("enc");
        Engine.Options enc = options(Superblock.Codec.NONE);
        enc.encrypt = true;
        // §3.3's `kdf = 0` credential: the 32 supplied bytes are the KEK. An
        // Argon2id keyslot here would put half a second of key derivation into
        // a throughput number and measure the KDF, which P11 already does on
        // its own.
        enc.rawKey = new byte[32];
        double encSecs;
        try (Database db = Database.create(path3, enc)) {
            encSecs = fill(db, n, true).secs();
        }
        row("cipher_write_ratio", f(encSecs / secs, 3), "ratio", false);

        System.out.println("# done");
    }

    /** xorshift, so a run reproduces. */
    private static long next(long s) {
        s ^= s << 13;
        s ^= s >>> 7;
        s ^= s << 17;
        return s;
    }
}
