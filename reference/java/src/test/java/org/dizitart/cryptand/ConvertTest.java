package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** F-072: 13 §5 {@code encrypt()}/{@code decrypt()} and 14 §8.3/§8.4's conversion in place. */
class ConvertTest {

    private static final int T = TreeId.FIRST_USER_TREE;
    private static final int N = 600;

    private static byte[] key(int i) {
        return Cke.encode(new Value.NitriteId(i));
    }

    /** Inline, value-log (every 7th) and blob (every 97th) values, so every object kind converts. */
    private static byte[] value(int i) {
        int len = i % 97 == 0 ? 300_000 : i % 7 == 0 ? 3000 : 40;
        byte[] v = Arrays.copyOf(("value-" + i + "-").getBytes(StandardCharsets.UTF_8), len);
        Arrays.fill(v, ("value-" + i + "-").length(), len, (byte) 'x');
        return v;
    }

    private static Engine.Options opts(byte[] rawKey) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 150;
        o.durability = Superblock.Durability.OS;
        o.rawKey = rawKey;
        o.encrypt = rawKey != null;
        return o;
    }

    private static byte[] k() {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) 9);
        return k;
    }

    private static void fill(Engine e) {
        for (int i = 0; i < N; i++) {
            e.batch().put(T, key(i), value(i)).commit();
        }
        e.commitNow(true);
    }

    private static void check(Engine e, int n, String what) {
        for (int i = 0; i < n; i++) {
            assertArrayEquals(value(i), e.get(T, key(i)), what + ": key " + i);
        }
        Verify.Report r = Verify.run(e);
        assertTrue(r.clean(), what + ": " + r);
    }

    private static Engine.Options reopen(byte[] rawKey) {
        Engine.Options o = opts(rawKey);
        o.encrypt = false;
        return o;
    }

    @Test
    void encryptInPlaceConvertsEverythingAndSurvivesReopenMidway(@TempDir Path dir) {
        Path f = dir.resolve("encrypt.cryptand");
        try (Engine e = Engine.create(f, opts(null))) {
            fill(e);
            e.encrypt(null, k());
            Engine.Conversion c = e.conversion();
            assertTrue(c.remaining > 0, "nothing to convert? " + c);
            assertFalse(e.fullyEncrypted(), "14 §8.3: not encrypted while plaintext remains");
            e.batch().put(T, key(N), value(N)).commit();
        }
        // Half-converted is a valid file (14 §8.4), and needs the key now.
        assertThrows(RuntimeException.class, () -> Engine.open(f, reopen(null)).close());
        try (Engine e = Engine.open(f, reopen(k()))) {
            check(e, N + 1, "half-converted");
            int steps = 0;
            while (e.convertStep()) {
                assertTrue(++steps < 20, "conversion does not converge: " + e.conversion());
            }
            assertTrue(e.fullyEncrypted(), "converted: " + e.conversion());
            check(e, N + 1, "converted");
        }
        try (Engine e = Engine.open(f, reopen(k()))) {
            assertTrue(e.fullyEncrypted());
            check(e, N + 1, "reopened");
        }
    }

    @Test
    void encryptRefusesAnEncryptedFile(@TempDir Path dir) {
        try (Engine e = Engine.create(dir.resolve("twice.cryptand"), opts(k()))) {
            assertThrows(InvalidArgumentException.class, () -> e.encrypt(null, k()));
        }
    }

    @Test
    void decryptNeedsConfirmationResumesAfterReopenAndLeavesNoKeyslots(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("decrypt.cryptand");
        try (Engine e = Engine.create(f, opts(k()))) {
            fill(e);
            assertThrows(InvalidArgumentException.class, () -> e.decrypt(Engine.ConfirmDecrypt.NO),
                    "14 §8.3: decrypt MUST be confirmed");
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            assertTrue(e.convertStep());
        }
        try (Engine e = Engine.open(f, reopen(k()))) {
            check(e, N, "half-decrypted");
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            int steps = 0;
            while (e.convertStep()) {
                assertTrue(++steps < 20, "decrypt does not converge: " + e.conversion());
            }
            assertFalse(e.fullyEncrypted());
        }
        try (Engine e = Engine.open(f, reopen(null))) {
            assertEquals(Superblock.Cipher.NONE, e.superblock().cipher);
            check(e, N, "decrypted");
        }
        byte[] bytes = Files.readAllBytes(f);
        for (int slot : new int[] {0, 8192}) {
            for (int i = slot + 3512; i < slot + 3512 + 576; i++) {
                assertEquals(0, bytes[i], "keyslots left in the slot at " + slot);
            }
            for (int i = slot + 296; i < slot + 328; i++) {
                assertEquals(0, bytes[i], "14 §6.2: sb_mac left in the slot at " + slot);
            }
        }
    }
}
