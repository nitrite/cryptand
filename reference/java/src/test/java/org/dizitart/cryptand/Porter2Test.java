package org.dizitart.cryptand;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Porter2 against <strong>Snowball's own</strong> vocabulary for release 3.1.0
 * — 42 649 words, which is the only check that distinguishes one release from
 * another.
 */
class Porter2Test {

    @Test
    @DisplayName("every word of Snowball's English vocabulary stems as 3.1.0 says")
    void snowballVocabulary() throws IOException {
        Path voc = Path.of("..", "conformance", "snowball", "voc-3.1.0.txt");
        Path out = Path.of("..", "conformance", "snowball", "output-3.1.0.txt");
        assertTrue(Files.exists(voc), "Snowball's vocabulary is present");
        List<String> words = Files.readAllLines(voc, StandardCharsets.UTF_8);
        List<String> expected = Files.readAllLines(out, StandardCharsets.UTF_8);
        assertEquals(words.size(), expected.size());
        assertEquals(42_649, words.size());

        List<String> mismatches = new ArrayList<>();
        int wrong = 0;
        for (int i = 0; i < words.size(); i++) {
            String got = Porter2.stem(words.get(i));
            if (!got.equals(expected.get(i))) {
                wrong++;
                if (mismatches.size() < 60) {
                    mismatches.add(words.get(i) + " -> " + got + ", expected " + expected.get(i));
                }
            }
        }
        assertEquals(List.of(), mismatches, wrong + " of " + words.size() + " differ");
    }

    /**
     * The pairs §2.4 names as having changed at 3.0.0, plus the {@code skis}
     * exception that 3.0.0 removed and 3.1.0 restored.
     */
    @Test
    @DisplayName("the release-sensitive words stem the 3.1.0 way")
    void releaseSensitiveWords() {
        assertEquals("ski", Porter2.stem("skis"), "3.1.0 restored this exception");
        assertEquals("sky", Porter2.stem("skies"));
        assertEquals("biolog", Porter2.stem("biologist"), "3.0.0 added -ogist -> -og");
        assertEquals("biolog", Porter2.stem("biology"));
    }

    @Test
    @DisplayName("the stemmer name pins the release")
    void nameCarriesTheRelease() {
        assertEquals("porter2:en:3.1.0", Porter2.NAME);
    }
}
