package org.dizitart.cryptand;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.fuzz.Fuzz;
import org.dizitart.cryptand.key.IndexKeys;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code spec/14-security.md} §9.3 — "structure-aware fuzzing of the reader ...
 * <strong>and an equivalent for each SDK</strong>. A parser for a format read
 * from untrusted sources that has never been fuzzed is not finished."
 *
 * <p>Read {@link Fuzz} for why the checksum is repaired after every mutation;
 * without that, the whole exercise measures CRC-32C.
 */
class FuzzTest {

    private static final int PAGE_SIZE = 8192;
    private static final String[] COUNTRIES = {"de", "fr", "uk", "in", "us"};

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 60;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    /**
     * A fixture with structure worth mutating: several segments, a value log, an
     * index, a catalog and a name dictionary. A fixture of one segment fuzzes
     * one decoder.
     */
    private static byte[] fixture(Path path) throws IOException {
        try (Database db = Database.create(path, options())) {
            Collection c = db.collection("orders");
            c.createIndex(List.of("country"), false, false);
            for (int i = 0; i < 300; i++) {
                boolean big = i % 10 == 0;
                byte[] note = new byte[big ? 900 : 40];
                java.util.Arrays.fill(note, (byte) (i % 251));
                Map<String, Value> f = new LinkedHashMap<>();
                f.put("_id", new Value.NitriteId(i));
                f.put("seq", Value.i32(i));
                f.put("country", new Value.Str(COUNTRIES[i % 5]));
                f.put("note", new Value.Bytes(note));
                c.insert(Value.Doc.of(f));
            }
            db.engine().compact();
        }
        return Files.readAllBytes(path);
    }

    /**
     * Opens a mutant, verifies it, and <strong>reads every document</strong>.
     * All three: the verifier walks structure and checksums, and the decoders
     * that turn bytes into values only run when something reads.
     */
    private static int readEverything(byte[] mutant, Path path) {
        try {
            Files.write(path, mutant);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
        Engine.Options o = options();
        o.readOnly = true;
        try (Database db = Database.open(path, o)) {
            int findings = Verify.run(db.engine()).findings().size();
            Collection c = db.collection("orders");
            for (int i = 0; i < 300; i++) {
                c.get(i);
            }
            try (Engine.Cursor cur = c.scan(false)) {
                while (cur.next()) {
                    cur.row();
                }
            }
            for (Collection.IndexBinding b : c.indexes()) {
                b.scan(new IndexKeys.Scan(new byte[0], null));
            }
            return findings;
        }
    }

    @Test
    @DisplayName("the fixture has enough structure for a fuzz run to mean anything")
    void targetsExist(@TempDir Path dir) throws IOException {
        byte[] image = fixture(dir.resolve("db.cryptand"));
        List<Fuzz.Target> t = Fuzz.targets(image, PAGE_SIZE);
        assertTrue(t.size() > 20, "a fixture with no headed pages fuzzes nothing: " + t.size());
        assertTrue(t.stream().filter(x -> x.what().contains("payload")).count() > 8);
    }

    @Test
    @DisplayName("a repaired checksum is what lets a mutation reach the decoder")
    void checksumRepairIsTheControl(@TempDir Path dir) throws IOException {
        // The control that makes the run below meaningful. §3's checksum is
        // verified "before decompression and before decryption", so a mutant
        // with a stale checksum dies at the container gate and no decoder sees a
        // byte. This asserts the repair actually moves the population.
        byte[] image = fixture(dir.resolve("db.cryptand"));
        List<Fuzz.Target> targets = Fuzz.targets(image, PAGE_SIZE);
        Path probe = dir.resolve("probe.cryptand");
        int withRepair = 0;
        int without = 0;
        for (int seed = 1; seed <= 40; seed++) {
            byte[] repaired = Fuzz.mutate(image, targets, new Fuzz.Rng(seed), PAGE_SIZE);
            byte[] stale = repaired.clone();
            for (int p = 2; (p + 1) * PAGE_SIZE <= stale.length; p++) {
                if (!pageDiffers(image, repaired, p)) {
                    continue;
                }
                System.arraycopy(image, p * PAGE_SIZE, stale, p * PAGE_SIZE, 4);
            }
            if (opens(repaired, probe)) {
                withRepair++;
            }
            if (opens(stale, probe)) {
                without++;
            }
        }
        assertTrue(withRepair > without,
                "if the repair changes nothing, this fuzzer measures CRC-32C: "
                        + withRepair + " vs " + without);
    }

    @Test
    @DisplayName("no mutant escapes the typed-error contract of section 9.1")
    void noUntypedFailure(@TempDir Path dir) throws IOException {
        byte[] image = fixture(dir.resolve("db.cryptand"));
        Path mutant = dir.resolve("mutant.cryptand");
        // `cryptand.fuzz.iterations` and `.seeds` widen the run without
        // editing it: CI runs the default, a soak run passes -D and gets hours.
        int iterations = Integer.getInteger("cryptand.fuzz.iterations", 600);
        int seeds = Integer.getInteger("cryptand.fuzz.seeds", 1);
        Fuzz.Report r = new Fuzz.Report();
        for (int s = 0; s < seeds; s++) {
            Fuzz.Report one = Fuzz.run(image, PAGE_SIZE, iterations, 0xF0FF + s * 7919L,
                    m -> readEverything(m, mutant));
            System.out.println("seed " + (0xF0FF + s * 7919L) + ": " + one);
            r.refused += one.refused;
            r.reported += one.reported;
            r.benign += one.benign;
            r.failures.addAll(one.failures);
        }
        System.out.println(r);
        // §9.1: "MUST fail with a typed corruption error rather than an
        // allocation failure, a panic, an abort, or an unbounded recursion."
        // Every failure this library raises is a CryptandException; anything
        // else is the violation, and the mutant that caused it is in the report
        // so it can be replayed.
        assertTrue(r.clean(), () -> r + "\n"
                + r.failures.stream().limit(5).map(Fuzz.Finding::detail)
                        .reduce("", (a, b) -> a + "\n" + b));
        // A run in which nothing reached a decoder has measured nothing.
        assertTrue(r.reachedReader() > 50, "too few mutants reached the reader: " + r);
    }

    private static boolean pageDiffers(byte[] a, byte[] b, int page) {
        int off = page * PAGE_SIZE;
        for (int i = off + 4; i < off + PAGE_SIZE && i < a.length; i++) {
            if (a[i] != b[i]) {
                return true;
            }
        }
        return false;
    }

    private static boolean opens(byte[] image, Path path) {
        try {
            Files.write(path, image);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
        Engine.Options o = options();
        o.readOnly = true;
        try (Database db = Database.open(path, o)) {
            return true;
        } catch (CryptandException e) {
            return false;
        } catch (Throwable e) {
            return true; // reached the reader, and badly; the run above reports it
        }
    }
}
