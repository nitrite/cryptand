package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.Snapshot;
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

    private static byte[] k(int b) {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) b);
        return k;
    }

    @Test
    void rotateMasterKeyRekeysEverythingAndDropsTheOldKeys(@TempDir Path dir) {
        Path f = dir.resolve("rotate.cryptand");
        Engine e = Engine.create(f, opts(k(1)));
        fill(e);
        e.addKey(null, k(2), "second");
        e = Engine.rotateMasterKey(e, null, k(3));
        try {
            check(e, N, "rotated");
            e.batch().put(T, key(N), value(N)).commit();
        } finally {
            e.close();
        }
        assertFalse(Files.exists(dir.resolve("rotate.cryptand.rotate")));
        for (int old : new int[] {1, 2}) {
            assertThrows(CannotUnlockException.class, () -> Engine.open(f, reopen(k(old))).close(),
                    "the old key " + old + " still opens the file");
        }
        try (Engine r = Engine.open(f, reopen(k(3)))) {
            check(r, N + 1, "reopened after rotation");
        }
    }

    @Test
    void rotateAHalfEncryptedFile(@TempDir Path dir) {
        Path f = dir.resolve("rotate-half.cryptand");
        Engine e = Engine.create(f, opts(null));
        fill(e);
        e.encrypt(null, k(1));
        e.batch().put(T, key(N), value(N)).commit();
        e = Engine.rotateMasterKey(e, null, k(4));
        try {
            check(e, N + 1, "half-encrypted, rotated");
            int steps = 0;
            while (e.convertStep()) {
                assertTrue(++steps < 20, "conversion does not converge: " + e.conversion());
            }
            check(e, N + 1, "then converted");
        } finally {
            e.close();
        }
    }

    /** F-104: a free page's bytes may be anything; a garbage stored length must not size an allocation. */
    @Test
    void rotateSkipsAFreePageWithAHugeStoredLength(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("rotate-free.cryptand");
        Engine e = Engine.create(f, opts(k(1)));
        fill(e);
        e.batch().removeRange(T, key(0), key(N)).commit();
        e.compact();
        e.commitNow(true);
        assertFalse(e.pager().freeList().isEmpty(), "no free page to plant garbage in");
        int ps = e.pager().pageSize();
        byte[] junk = new byte[ps];
        org.dizitart.cryptand.container.PageHeader h = new org.dizitart.cryptand.container.PageHeader();
        h.flags = org.dizitart.cryptand.container.PageHeader.Flags.ENCRYPTED;
        h.storedLen = 0x7FFF_FFF0;
        h.writeInto(junk);
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f.toFile(), "rw")) {
            for (org.dizitart.cryptand.container.Pager.FreeExtent x : e.pager().freeList()) {
                for (long p = x.startPage(); p < x.startPage() + x.pages(); p++) {
                    raf.seek(p * ps);
                    raf.write(junk);
                }
            }
        }
        e = Engine.rotateMasterKey(e, null, k(3));
        e.close();
    }

    /**
     * Conversion runs under a live snapshot, as in Rust: the snapshot keeps
     * reading the versions it pinned through encrypt and decrypt.
     */
    @Test
    void convertsUnderLiveSnapshot(@TempDir Path dir) {
        Engine e = Engine.create(dir.resolve("snap.cryptand"), opts(null));
        try {
            fill(e);
            Snapshot snap = e.pin();
            for (int i = 0; i < N; i += 2) {
                e.batch().put(T, key(i), value(i + N)).commit();
            }
            e.commitNow(true);
            e.encrypt(null, k(1));
            while (e.convertStep()) {
                // until nothing plaintext remains
            }
            assertTrue(e.fullyEncrypted());
            for (int i = 0; i < N; i++) {
                assertArrayEquals(value(i), e.get(T, key(i), snap.seq(), 0), "encrypted, snapshot: key " + i);
            }
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            while (e.convertStep()) {
                // until nothing encrypted remains
            }
            for (int i = 0; i < N; i++) {
                assertArrayEquals(value(i), e.get(T, key(i), snap.seq(), 0), "decrypted, snapshot: key " + i);
                assertArrayEquals(value(i % 2 == 0 ? i + N : i), e.get(T, key(i)), "decrypted: key " + i);
            }
            // Torture seeds 3505, 1094: encrypted again under a fresh master, and
            // decrypted again; the snapshot's segments are sealed under older ones.
            for (int round = 0; round < 2; round++) {
                e.encrypt(null, k(1));
                while (e.convertStep()) {
                    // until nothing plaintext remains
                }
                e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
                while (e.convertStep()) {
                    // until nothing encrypted remains
                }
                for (int i = 0; i < N; i++) {
                    assertArrayEquals(value(i), e.get(T, key(i), snap.seq(), 0), "round " + round + ", snapshot: key " + i);
                }
            }
            e.unpin(snap);
        } finally {
            e.close();
        }
    }

    /**
     * F-081: values whose pointers are still in the memtable (no flush before
     * encrypt()) survive the conversion, later writes, a rotation and a decrypt.
     */
    @Test
    void memtableHeldValuesSurviveEncryptRotateDecrypt(@TempDir Path dir) {
        Path f = dir.resolve("memtable.cryptand");
        Engine.Options o = opts(null);
        o.memtableEntries = 100_000; // nothing flushes on its own
        Engine e = Engine.create(f, o);
        for (int i = 0; i < 100; i++) {
            e.batch().put(T, key(i), value(i)).commit();
        }
        e.encrypt(null, k(1));
        int steps = 0;
        while (e.convertStep()) {
            assertTrue(++steps < 20, "conversion does not converge: " + e.conversion());
        }
        for (int i = 100; i < 200; i++) {
            e.batch().put(T, key(i), value(i)).commit();
        }
        e.commitNow(true);
        check(e, 200, "encrypted");
        e = Engine.rotateMasterKey(e, null, k(5));
        try {
            check(e, 200, "rotated");
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            while (e.convertStep()) {
                // until nothing encrypted remains
            }
            check(e, 200, "decrypted");
        } finally {
            e.close();
        }
    }

    /**
     * F-085, M2.2 torture seed 101100: a value written under encryption, then
     * range-deleted, so decrypt() leaves its segment retired; a backup resolved
     * the shadowed value and found no key.
     */
    @Test
    void rangeDeletedValueIsNotResolvedByBackup(@TempDir Path dir) {
        Engine.Options o = opts(null);
        o.durability = Superblock.Durability.NONE; // as the op-log harness runs
        o.backgroundCompaction = false;
        byte[] big = new byte[7315];
        Arrays.fill(big, (byte) 7);
        Engine e = Engine.create(dir.resolve("rd.cryptand"), o);
        try {
            e.encrypt(null, k(1));
            while (e.convertStep()) {
                // until nothing plaintext remains
            }
            e.batch().put(T, key(1), big).commit();
            e.batch().removeRange(T, key(0), key(5)).commit();
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            while (e.convertStep()) {
                // until nothing encrypted remains
            }
            org.dizitart.cryptand.ops.Backup.full(e, dir.resolve("rd.bak"),
                    org.dizitart.cryptand.ops.Backup.Mode.PLAINTEXT, false);
            assertEquals(null, e.get(T, key(1)));
        } finally {
            e.close();
        }
    }

    /**
     * F-098, M2.2 torture seed 103375: a blob written under encryption and
     * still held by the memtable when decrypt() runs; the census saw only
     * segments, so the cipher was dropped with the blob still sealed.
     */
    @Test
    void memtableHeldBlobSurvivesDecrypt(@TempDir Path dir) {
        Engine.Options o = opts(new byte[32]);
        o.durability = Superblock.Durability.NONE; // as the op-log harness runs
        byte[] big = new byte[300_000];
        Arrays.fill(big, (byte) 7);
        Engine e = Engine.create(dir.resolve("blob.cryptand"), o);
        try {
            e.batch().put(T, key(1), big).commit();
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            while (e.convertStep()) {
                // until nothing encrypted remains
            }
            assertArrayEquals(big, e.get(T, key(1)));
        } finally {
            e.close();
        }
    }

    /**
     * M2.2 torture seed 106: a value written under encryption and still held
     * by the memtable when decrypt() runs; then a plaintext backup reads it.
     */
    @Test
    void memtableHeldValueSurvivesDecryptThenBackup(@TempDir Path dir) {
        Path f = dir.resolve("dec.cryptand");
        Engine.Options o = opts(new byte[32]);
        o.durability = Superblock.Durability.NONE; // as the op-log harness runs
        byte[] big = new byte[6044];
        Arrays.fill(big, (byte) 7);
        Engine e = Engine.create(f, o);
        try {
            e.batch().put(T, key(1), big).commit();
            e.decrypt(Engine.ConfirmDecrypt.REMOVE_ENCRYPTION);
            while (e.convertStep()) {
                // until nothing encrypted remains
            }
            assertArrayEquals(big, e.get(T, key(1)));
            org.dizitart.cryptand.ops.Backup.full(e, dir.resolve("dec.bak"),
                    org.dizitart.cryptand.ops.Backup.Mode.PLAINTEXT, false);
            e.commitNow(true);
            assertArrayEquals(big, e.get(T, key(1)));
        } finally {
            e.close();
        }
        try (Engine back = Engine.open(dir.resolve("dec.bak"), opts(null))) {
            assertArrayEquals(big, back.get(T, key(1)));
        }
    }

}
