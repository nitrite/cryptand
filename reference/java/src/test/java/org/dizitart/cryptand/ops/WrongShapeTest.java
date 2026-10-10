package org.dizitart.cryptand.ops;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;

/** F-118: records read from the file with the wrong shape are corruption, not a JVM exception. */
class WrongShapeTest {
    private static final Value EMPTY = Value.Doc.of(Map.of());

    @Test
    void checkpointOfTheWrongShape() {
        assertThrows(CorruptionException.class, () -> Checkpoint.fromValue("c", EMPTY));
        assertThrows(CorruptionException.class, () -> Checkpoint.fromValue("c", new Value.Bool(true)));
    }

    @Test
    void changeFeedEntryOfTheWrongShape() {
        byte[] key = Cke.encode(new Value.Array(List.of()));
        assertThrows(CorruptionException.class, () -> ChangeFeed.fromEntry(key, EMPTY));
    }
}
