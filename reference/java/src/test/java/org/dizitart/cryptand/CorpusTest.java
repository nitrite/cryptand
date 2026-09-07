package org.dizitart.cryptand;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

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
}
