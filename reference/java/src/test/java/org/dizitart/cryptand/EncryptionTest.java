package org.dizitart.cryptand;

import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.crypto.Argon2id;
import org.dizitart.cryptand.crypto.FileCipher;
import org.dizitart.cryptand.crypto.Keyslot;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.util.Crc32c;
import org.dizitart.cryptand.value.Value;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Encryption end to end — {@code spec/14-security.md} §13's mandatory tests,
 * as far as they can be run inside one implementation. The cross-SDK encrypted
 * round trip is the round-trip gate's business.
 */
class EncryptionTest {

    private static final int TREE = TreeId.FIRST_USER_TREE;

    private static byte[] key(String s) {
        return Cke.encode(new Value.Str(s));
    }

    private static byte[] val(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * A raw keyslot, not Argon2id: §3.2's parameters are a deliberate
     * {@code ~500 ms} on a desktop, and paying that in every test would buy
     * nothing the {@link CryptoPrimitivesTest} RFC 9106 vector does not already
     * prove. The Argon2id path has its own test below, once.
     */
    private static Engine.Options encrypted(byte[] rawKey) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 64;
        o.encrypt = true;
        o.rawKey = rawKey;
        o.durability = Superblock.Durability.OS;
        return o;
    }

    private static byte[] testKey() {
        byte[] k = new byte[32];
        new Random(4242).nextBytes(k);
        return k;
    }

    @Test
    @DisplayName("an encrypted database round-trips through close and reopen")
    void roundTrip(@TempDir Path dir) {
        Path f = dir.resolve("enc.cryptand");
        byte[] k = testKey();
        byte[] big = new byte[4096];
        new Random(9).nextBytes(big);
        try (Engine e = Engine.create(f, encrypted(k))) {
            assertEquals(Superblock.Cipher.XCHACHA20_POLY1305, e.superblock().cipher);
            for (int i = 0; i < 200; i++) {
                e.batch().put(TREE, key("k" + i), val("v" + i)).commit();
            }
            e.batch().put(TREE, key("separated"), big).commit();
        }
        Engine.Options open = new Engine.Options();
        open.profile = Profile.DESKTOP;
        open.durability = Superblock.Durability.OS;
        open.rawKey = k;
        try (Engine e = Engine.open(f, open)) {
            for (int i = 0; i < 200; i++) {
                assertArrayEquals(val("v" + i), e.get(TREE, key("k" + i)), "k" + i);
            }
            assertArrayEquals(big, e.get(TREE, key("separated")));
        }
    }

    @Test
    @DisplayName("the plaintext is not in the file")
    void plaintextIsNotOnDisk(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("secret.cryptand");
        byte[] k = testKey();
        String secret = "the-account-number-is-9042-1177";
        try (Engine e = Engine.create(f, encrypted(k))) {
            for (int i = 0; i < 50; i++) {
                e.batch().put(TREE, key("row" + i), val(secret + i)).commit();
            }
        }
        byte[] raw = Files.readAllBytes(f);
        assertFalse(contains(raw, val("the-account-number-is")),
                "an inline value appeared in the clear");
    }

    @Test
    @DisplayName("a separated value is not in the file either")
    void separatedPlaintextIsNotOnDisk(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("secret2.cryptand");
        byte[] k = testKey();
        byte[] payload = new byte[2048];
        byte[] marker = val("MARKER-9042-1177");
        System.arraycopy(marker, 0, payload, 100, marker.length);
        try (Engine e = Engine.create(f, encrypted(k))) {
            e.batch().put(TREE, key("doc"), payload).commit();
        }
        assertFalse(contains(Files.readAllBytes(f), marker),
                "a value-log record appeared in the clear");
    }

    @Test
    @DisplayName("the wrong key is refused, identically to a missing slot")
    void wrongKey(@TempDir Path dir) {
        Path f = dir.resolve("wrong.cryptand");
        byte[] k = testKey();
        try (Engine e = Engine.create(f, encrypted(k))) {
            e.batch().put(TREE, key("x"), val("y")).commit();
        }
        Engine.Options bad = new Engine.Options();
        byte[] other = testKey();
        other[0] ^= 0x01;
        bad.rawKey = other;
        CannotUnlockException a = assertThrows(CannotUnlockException.class, () -> Engine.open(f, bad));

        Engine.Options none = new Engine.Options();
        CannotUnlockException b = assertThrows(CannotUnlockException.class, () -> Engine.open(f, none));
        assertEquals(a.getMessage(), b.getMessage(),
                "a wrong password and an absent one must report identically");
    }

    /**
     * {@code v1.0-security-tamper-sb}: {@code cipher} forced to 0 in the
     * superblock. The MAC covers every field that governs how the file is
     * interpreted, which is what makes the downgrade detectable at all.
     */
    @Test
    @DisplayName("editing the superblock is reported as tampering, not corruption")
    void tamperedSuperblock(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("tsb.cryptand");
        byte[] k = testKey();
        try (Engine e = Engine.create(f, encrypted(k))) {
            e.batch().put(TREE, key("x"), val("y")).commit();
        }
        byte[] raw = Files.readAllBytes(f);
        int pageSize = 8192;
        // Whichever slot is live, edit both: `writer_id`'s first byte is inside
        // the MAC and outside every other check.
        for (int off : new int[]{0, pageSize}) {
            raw[off + 256] ^= 0x01;
            fixCrc(raw, off);
        }
        Files.write(f, raw);
        Engine.Options open = new Engine.Options();
        open.rawKey = k;
        assertThrows(TamperingException.class, () -> Engine.open(f, open));
    }

    @Test
    @DisplayName("a flipped ciphertext byte in a page is tampering")
    void tamperedPage(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("tpage.cryptand");
        byte[] k = testKey();
        try (Engine e = Engine.create(f, encrypted(k))) {
            for (int i = 0; i < 100; i++) {
                e.batch().put(TREE, key("k" + i), val("value-" + i)).commit();
            }
        }
        byte[] raw = Files.readAllBytes(f);
        int pageSize = 8192;
        int touched = 0;
        // Every encrypted leaf, because a file holds freed pages nothing reads:
        // tampering with one of those proves nothing either way.
        for (long page = 2; (page + 1) * pageSize <= raw.length; page++) {
            int base = (int) (page * pageSize);
            PageHeader h = PageHeader.parse(raw, base);
            if (h.pageType != PageHeader.Type.BTREE_LEAF || !h.isSet(PageHeader.Flags.ENCRYPTED)) {
                continue;
            }
            raw[base + PageHeader.BYTES + 4] ^= 0x01;
            // Recompute the page CRC, so this is tampering and not corruption.
            // An attacker can always recompute a checksum, which is exactly
            // §9.4's point that CRC is error detection and never integrity.
            int crc = Crc32c.of(raw, base + 4, pageSize - 4);
            raw[base] = (byte) crc;
            raw[base + 1] = (byte) (crc >>> 8);
            raw[base + 2] = (byte) (crc >>> 16);
            raw[base + 3] = (byte) (crc >>> 24);
            touched++;
        }
        assertTrue(touched > 0, "the file holds encrypted leaf pages");
        Files.write(f, raw);

        Engine.Options open = new Engine.Options();
        open.rawKey = k;
        assertThrows(TamperingException.class, () -> {
            try (Engine e = Engine.open(f, open)) {
                for (int i = 0; i < 100; i++) {
                    e.get(TREE, key("k" + i));
                }
            }
        });
    }

    /**
     * §13's nonce-uniqueness test, in the form one process can run: write past
     * the published floor, reopen repeatedly, and assert that no
     * {@code (key, nonce)} pair occurs twice anywhere in the file.
     *
     * <p>This is the test that catches the crash-reuse defect §4.1 describes,
     * and nothing else catches it: every affected page verifies perfectly.
     */
    @Test
    @DisplayName("no nonce is ever issued twice, across sessions")
    void nonceUniqueness(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("nonce.cryptand");
        byte[] k = testKey();
        for (int session = 0; session < 5; session++) {
            Engine.Options o = session == 0 ? encrypted(k) : new Engine.Options();
            o.profile = Profile.DESKTOP;
            o.memtableEntries = 64;
            o.durability = Superblock.Durability.OS;
            o.rawKey = k;
            try (Engine e = session == 0 ? Engine.create(f, o) : Engine.open(f, o)) {
                for (int i = 0; i < 100; i++) {
                    e.batch().put(TREE, key("s" + session + "-" + i), val("v" + i)).commit();
                }
            }
        }
        byte[] raw = Files.readAllBytes(f);
        int pageSize = 8192;
        Set<Long> seen = new HashSet<>();
        List<Long> duplicates = new ArrayList<>();
        for (long page = 2; (page + 1) * pageSize <= raw.length; page++) {
            int base = (int) (page * pageSize);
            PageHeader h = PageHeader.parse(raw, base);
            if (!h.isSet(PageHeader.Flags.ENCRYPTED) || h.nonce == 0) {
                continue;
            }
            if (!seen.add(h.nonce)) {
                duplicates.add(h.nonce);
            }
        }
        assertTrue(duplicates.isEmpty(), "nonce reused: " + duplicates);
        assertFalse(seen.isEmpty(), "the file holds encrypted pages at all");
    }

    /**
     * §13's key-rotation test: add a keyslot, remove the original, reopen with
     * the new credential only, and confirm the old one fails.
     */
    @Test
    @DisplayName("a keyslot can be added and the original removed")
    void keyRotation(@TempDir Path dir) {
        byte[] uuid = new byte[16];
        new Random(3).nextBytes(uuid);
        byte[] master = FileCipher.randomMasterKey();
        byte[] first = testKey();
        byte[] second = testKey();
        second[31] ^= 0x7F;

        Keyslot[] slots = new Keyslot[Keyslot.COUNT];
        slots[0] = FileCipher.wrapWithRawKey(master, uuid, 0, first, "one");
        for (int i = 1; i < Keyslot.COUNT; i++) {
            slots[i] = new Keyslot();
        }
        assertArrayEquals(master, FileCipher.unwrap(slots, uuid, null, first));

        slots[1] = FileCipher.wrapWithRawKey(master, uuid, 1, second, "two");
        slots[0] = new Keyslot();
        assertArrayEquals(master, FileCipher.unwrap(slots, uuid, null, second));
        assertThrows(CannotUnlockException.class, () -> FileCipher.unwrap(slots, uuid, null, first));
    }

    /**
     * §3.3: the AAD binds a slot to its file, so a keyslot lifted from another
     * database does not unwrap here — an attacker cannot graft a slot whose
     * password they know onto a file they want to read.
     */
    @Test
    @DisplayName("a keyslot from another database does not unwrap")
    void foreignSlot() {
        byte[] uuidA = new byte[16];
        byte[] uuidB = new byte[16];
        new Random(1).nextBytes(uuidA);
        new Random(2).nextBytes(uuidB);
        byte[] master = FileCipher.randomMasterKey();
        byte[] kek = testKey();
        Keyslot[] grafted = new Keyslot[]{
                FileCipher.wrapWithRawKey(master, uuidA, 0, kek, "one"),
                new Keyslot(), new Keyslot(), new Keyslot()};
        assertThrows(CannotUnlockException.class, () -> FileCipher.unwrap(grafted, uuidB, null, kek));
    }

    /** The Argon2id path, once, at the profile's real cost. */
    @Test
    @DisplayName("a password-derived keyslot opens the file")
    void passwordKeyslot(@TempDir Path dir) {
        Path f = dir.resolve("pw.cryptand");
        byte[] password = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);
        Engine.Options create = new Engine.Options();
        create.profile = Profile.MOBILE;
        create.memtableEntries = 64;
        create.encrypt = true;
        create.durability = Superblock.Durability.OS;
        create.password = password.clone();
        try (Engine e = Engine.create(f, create)) {
            e.batch().put(TREE, key("hello"), val("world")).commit();
        }
        Engine.Options open = new Engine.Options();
        open.profile = Profile.MOBILE;
        open.durability = Superblock.Durability.OS;
        open.password = password.clone();
        try (Engine e = Engine.open(f, open)) {
            assertArrayEquals(val("world"), e.get(TREE, key("hello")));
        }
    }

    private static void fixCrc(byte[] raw, int off) {
        int crc = Crc32c.of(raw, off, Superblock.CHECKSUM_OFFSET);
        raw[off + Superblock.CHECKSUM_OFFSET] = (byte) crc;
        raw[off + Superblock.CHECKSUM_OFFSET + 1] = (byte) (crc >>> 8);
        raw[off + Superblock.CHECKSUM_OFFSET + 2] = (byte) (crc >>> 16);
        raw[off + Superblock.CHECKSUM_OFFSET + 3] = (byte) (crc >>> 24);
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
