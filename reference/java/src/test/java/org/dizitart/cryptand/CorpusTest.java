package org.dizitart.cryptand;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Map;
import java.util.TreeMap;

import org.dizitart.cryptand.tool.Interop;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code spec/11-conformance.md} §6 and {@code spec/14-security.md} §13 — the
 * shared corpus of golden and deliberately broken files.
 *
 * <blockquote>"Conformance is defined as passing the vectors, not as matching
 * the reference implementation's source."</blockquote>
 *
 * <p>The corpus's value is that these bytes were written by a <em>different</em>
 * implementation. Its first run here produced two disagreements: every golden
 * file came back with nine findings, because this runner counted {@code LEAK}
 * alongside corruption and a copy-on-write container leaks tree 1's own pages
 * by one commit as a property of the format; and §6.1's cipher downgrade was
 * reported as an {@code InvalidArgumentException} rather than tampering,
 * because {@code sb_mac} was verified only when the superblock said the file
 * was encrypted — which is the one field the MAC exists to protect.
 */
class CorpusTest {

    private static Path corpusDir() {
        // target/test-classes -> target -> java -> reference
        return Paths.get(System.getProperty("user.dir"))
                .getParent()
                .resolve("conformance")
                .resolve("files");
    }

    @Test
    @DisplayName("the shared conformance corpus passes")
    void corpus() throws IOException {
        Path dir = corpusDir();
        if (!Files.exists(dir.resolve("manifest.json"))) {
            // §6's suite is mandatory, so a run that skips it must say why
            // rather than go green.
            fail(dir + " is missing; generate it with "
                    + "`dart run tool/generate_corpus.dart` in reference/dart/cryptand");
        }
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.out;
        int failed;
        try {
            System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
            failed = Interop.corpus(dir.toString());
        } finally {
            System.setOut(original);
        }
        String text = captured.toString(StandardCharsets.UTF_8);
        System.out.print(text);
        assertEquals(0, failed, () -> "the corpus reported failures:\n" + text);
        // A run that checked nothing must not pass. The corpus is the one test
        // here whose fixtures live outside this module's build, so an empty or
        // truncated directory is a realistic way for it to silently stop
        // measuring.
        assertTrue(text.lines().filter(l -> l.contains("ok    ")).count() >= 15,
                "too few files were checked; is the corpus complete?\n" + text);
    }

    @Test
    @DisplayName("reading the corpus does not modify it")
    void corpusIsReadOnly() throws Exception {
        // The corpus is the fixture §6 defines conformance *by*, so a runner
        // that writes to it moves the target on every run.
        //
        // This one did, and nothing here could see it. `Database.open` records
        // the writer id when the handle is writable (`05-catalog.md` §7), and
        // the corpus runner opened every file writable, so a plain
        // `mvn test` left 12 of the 18 files modified — superblock `commit_id`
        // advanced, a page appended — `v1.0-corrupt-*` and `v1.0-security-*`
        // included. Two things followed, and the second is the worse: a
        // parallel run of another implementation's suite failed on files it
        // was only reading, because these were write-locked; and this runner
        // **wrote to files it was about to report as corrupt**.
        //
        // The check is on the bytes rather than on the open mode, because the
        // property that matters is "the corpus did not change", and a future
        // write from some other path would satisfy an open-mode assertion.
        Path dir = corpusDir();
        if (!Files.exists(dir.resolve("manifest.json"))) {
            fail(dir + " is missing; generate it with "
                    + "`dart run tool/generate_corpus.dart` in reference/dart/cryptand");
        }
        Map<String, String> before = digestCorpus(dir);
        assertTrue(before.size() >= 15, "too few corpus files to be measuring anything");

        PrintStream original = System.out;
        try {
            System.setOut(new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
            Interop.corpus(dir.toString());
        } finally {
            System.setOut(original);
        }

        Map<String, String> after = digestCorpus(dir);
        assertEquals(before, after, "reading the conformance corpus modified it");
    }

    /** SHA-256 of every corpus file, by name. */
    private static Map<String, String> digestCorpus(Path dir) throws Exception {
        Map<String, String> out = new TreeMap<>();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (var files = Files.list(dir)) {
            for (Path p : files.collect(java.util.stream.Collectors.toList())) {
                if (!Files.isRegularFile(p)) {
                    continue;
                }
                md.reset();
                out.put(p.getFileName().toString(),
                        org.dizitart.cryptand.util.Hex.format(md.digest(Files.readAllBytes(p))));
            }
        }
        return out;
    }
}
