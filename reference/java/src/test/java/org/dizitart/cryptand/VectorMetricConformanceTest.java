package org.dizitart.cryptand;

import com.fasterxml.jackson.databind.JsonNode;
import org.dizitart.cryptand.index.VectorIndex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code spec/09-vector.md} §8.1 — the metrics, numerically.
 *
 * <p>§5's descriptor names {@code "cosine" | "l2" | "dot"} and §8 said nothing
 * about what they compute. "Ordered nearest first" needs a value where smaller
 * means closer, and a dot product is a <em>similarity</em> — so an
 * implementation returning it unchanged sorts every result set backwards while
 * satisfying every other sentence in the chapter. §8.1 pins all three, and this
 * is the shared vector for it.
 *
 * <p>The {@code wide_1024} case is the one with teeth: it fails for an
 * implementation that accumulates in {@code float} rather than {@code double}.
 */
class VectorMetricConformanceTest {

    @Test
    @DisplayName("every published metric value is reproduced")
    void metrics() {
        JsonNode doc = Vectors.load("vector/metrics.json");
        double tol = doc.get("tolerance").asDouble();
        JsonNode cases = doc.get("cases");
        assertTrue(cases.size() >= 8, "the metric corpus is suspiciously small");

        for (JsonNode c : cases) {
            float[] a = floats(c.get("a"));
            float[] b = floats(c.get("b"));
            for (String metric : List.of("l2", "dot", "cosine")) {
                double want = c.get(metric).asDouble();
                double got = VectorIndex.distance(metric, a, b);
                assertTrue(Math.abs(got - want) <= tol,
                        c.get("name").asText() + "/" + metric + ": want " + want
                                + ", got " + got + " (delta " + Math.abs(got - want)
                                + ", tolerance " + tol + ")\n  "
                                + c.path("note").asText(""));
            }
        }
    }

    private static float[] floats(JsonNode n) {
        float[] out = new float[n.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = (float) n.get(i).asDouble();
        }
        return out;
    }
}
