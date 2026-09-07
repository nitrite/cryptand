package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Feature;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.crypto.Argon2id;
import org.dizitart.cryptand.crypto.Keyslot;
import org.dizitart.cryptand.crypto.Security;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Key derivation, nonces and keyslots — {@code spec/14-security.md}.
 */
class SecurityConformanceTest {

    private static JsonNode vector() {
        return Vectors.load("security/derivation.json");
    }

    /**
     * RFC 5869's own test case 1, which is the point of naming a standard
     * algorithm: an SDK checks its HKDF against the RFC rather than against
     * another implementation of Cryptand.
     */
    @Test
    @DisplayName("HKDF-SHA256 reproduces RFC 5869 test case 1")
    void hkdfRfc5869() {
        JsonNode c = vector().get("hkdf_rfc5869_case1");
        byte[] okm = Security.hkdf(
                Vectors.hex(c.get("salt").asText()),
                Vectors.hex(c.get("ikm").asText()),
                Vectors.hex(c.get("info").asText()),
                c.get("length").asInt());
        assertEquals(c.get("okm").asText(), Vectors.hex(okm));
    }

    @Test
    @DisplayName("the three subkeys are derived exactly as published")
    void subkeys() {
        JsonNode s = vector().get("subkeys");
        byte[] master = Vectors.hex(s.get("master_key").asText());
        byte[] uuid = Vectors.hex(s.get("database_uuid").asText());
        assertEquals(Security.INFO_PREFIX, s.get("info_prefix").asText());

        assertEquals(s.get("page").asText(),
                Vectors.hex(Security.deriveSubkey(master, uuid, Security.Purpose.PAGE)));
        assertEquals(s.get("vlog").asText(),
                Vectors.hex(Security.deriveSubkey(master, uuid, Security.Purpose.VLOG)));
        assertEquals(s.get("sbmac").asText(),
                Vectors.hex(Security.deriveSubkey(master, uuid, Security.Purpose.SB_MAC)));
    }

    /**
     * §3.4: the three subkeys must be independent, because pages and value-log
     * records use different nonce spaces and reusing one key across two
     * independently-constructed spaces is how nonce collisions become possible
     * again.
     */
    @Test
    @DisplayName("the subkeys are independent of each other")
    void subkeysAreDistinct() {
        byte[] master = new byte[32];
        byte[] uuid = new byte[16];
        byte[] page = Security.deriveSubkey(master, uuid, Security.Purpose.PAGE);
        byte[] vlog = Security.deriveSubkey(master, uuid, Security.Purpose.VLOG);
        byte[] mac = Security.deriveSubkey(master, uuid, Security.Purpose.SB_MAC);
        assertNotEquals(Vectors.hex(page), Vectors.hex(vlog));
        assertNotEquals(Vectors.hex(page), Vectors.hex(mac));
        assertNotEquals(Vectors.hex(vlog), Vectors.hex(mac));
    }

    /**
     * Using {@code database_uuid} as the HKDF salt is what makes two files with
     * the same password have different content keys, so a nonce repeated across
     * files is harmless. {@code 13-operations.md} §2.1 forbids a backup copying
     * the source uuid, and this is why that rule is load-bearing for security
     * rather than only for tooling.
     */
    @Test
    @DisplayName("two files with the same master key derive different content keys")
    void uuidSeparatesFiles() {
        byte[] master = new byte[32];
        byte[] a = Security.deriveSubkey(master, Vectors.hex("00000000000000000000000000000001"),
                Security.Purpose.PAGE);
        byte[] b = Security.deriveSubkey(master, Vectors.hex("00000000000000000000000000000002"),
                Security.Purpose.PAGE);
        assertNotEquals(Vectors.hex(a), Vectors.hex(b));
    }

    @Test
    @DisplayName("the 24-byte nonce is built exactly as published")
    void nonces() {
        int n = 0;
        for (JsonNode c : vector().get("nonces")) {
            byte[] nonce = Security.buildNonce(
                    c.get("domain").asInt(),
                    c.get("counter").asLong(),
                    c.get("object_id").asLong(),
                    c.get("offset").asLong());
            assertEquals(24, nonce.length);
            assertEquals(c.get("nonce").asText(), Vectors.hex(nonce));
            n++;
        }
        assertEquals(2, n);
    }

    @Test
    @DisplayName("an offset that does not fit a u56 is refused rather than truncated")
    void nonceOffsetIsBounded() {
        assertThrows(InvalidArgumentException.class,
                () -> Security.buildNonce(Security.NonceDomain.VLOG_RECORD, 1, 1, 1L << 56));
    }

    /**
     * §4.1. The floor must be <em>published</em>, not derived as
     * {@code next_nonce - GAP}: deriving it wrapped to a floor that had never
     * been written — silently in a release build, and with an arithmetic panic
     * in a debug one, which is why both profiles have to be run.
     */
    @Test
    @DisplayName("the nonce gap is the published value")
    void nonceGap() {
        assertEquals(vector().get("nonce_watermark").get("gap").asLong(), Security.NONCE_GAP);
    }

    @Test
    @DisplayName("the keyslot layout matches the published offsets")
    void keyslotLayout() {
        JsonNode k = vector().get("keyslot");
        assertEquals(Keyslot.BYTES, k.get("size").asInt());
        assertEquals(Keyslot.COUNT, k.get("count").asInt());
        assertEquals(Keyslot.OFFSET_IN_SUPERBLOCK, k.get("offset_in_superblock").asInt());
        assertEquals(Keyslot.OFFSET_IN_SUPERBLOCK + Keyslot.COUNT * Keyslot.BYTES, 4088,
                "the four slots must end where the superblock's final reserved bytes begin");

        JsonNode o = k.get("field_offsets");
        // The offsets are asserted against a slot this implementation builds,
        // so a field written in the right order at the wrong place fails here.
        Keyslot slot = new Keyslot();
        slot.state = Keyslot.STATE_OCCUPIED;
        slot.kdf = Keyslot.KDF_ARGON2ID;
        slot.tCost = 0x11111111;
        slot.mCostKib = 0x22222222;
        slot.parallelism = 0x33333333;
        java.util.Arrays.fill(slot.salt, (byte) 0x44);
        java.util.Arrays.fill(slot.wrapNonce, (byte) 0x55);
        java.util.Arrays.fill(slot.wrappedKey, (byte) 0x66);
        java.util.Arrays.fill(slot.wrapTag, (byte) 0x77);
        slot.label = "password";

        byte[] bytes = slot.encode();
        assertEquals(Keyslot.BYTES, bytes.length);
        assertEquals(Keyslot.STATE_OCCUPIED, bytes[o.get("state").asInt()]);
        assertEquals(Keyslot.KDF_ARGON2ID, bytes[o.get("kdf").asInt()]);
        assertEquals(8, bytes[o.get("label_len").asInt()]);
        assertEquals(0x11, bytes[o.get("t_cost").asInt()]);
        assertEquals(0x22, bytes[o.get("m_cost_kib").asInt()]);
        assertEquals(0x33, bytes[o.get("parallelism").asInt()]);
        assertEquals(0x44, bytes[o.get("salt").asInt()]);
        assertEquals(0x55, bytes[o.get("wrap_nonce").asInt()]);
        assertEquals(0x66, bytes[o.get("wrapped_key").asInt()]);
        assertEquals(0x77, bytes[o.get("wrap_tag").asInt()]);
        assertEquals('p', bytes[o.get("label").asInt()]);

        Keyslot back = Keyslot.decode(bytes, 0);
        assertEquals("password", back.label);
        assertEquals(0x11111111, back.tCost);
        assertTrue(back.occupied());
    }

    /**
     * §3.3: {@code kdf = 0} takes a key the host already holds — an OS keychain
     * item, a hardware-backed key — and the 32 supplied bytes <em>are</em> the
     * KEK, so {@code salt}, {@code t_cost}, {@code m_cost_kib} and
     * {@code parallelism} MUST be written as zero. Leaving stale Argon2id costs
     * in a raw slot invites a reader to run a KDF that was never used.
     */
    @Test
    @DisplayName("a raw keyslot writes its KDF parameters as zero")
    void rawKeyslotZeroesKdfParameters() {
        Keyslot slot = new Keyslot();
        slot.state = Keyslot.STATE_OCCUPIED;
        slot.kdf = Keyslot.KDF_RAW;
        slot.tCost = 3;
        slot.mCostKib = 65536;
        slot.parallelism = 1;
        java.util.Arrays.fill(slot.salt, (byte) 0xAB);

        Keyslot back = Keyslot.decode(slot.encode(), 0);
        assertEquals(0, back.tCost);
        assertEquals(0, back.mCostKib);
        assertEquals(0, back.parallelism);
        assertArrayEquals(new byte[32], back.salt);
    }

    /**
     * §3.3: the AAD binds a slot to its file, so a keyslot lifted from another
     * database does not unwrap here. Without it an attacker could graft a slot
     * whose password they know onto a file they want to read.
     */
    @Test
    @DisplayName("the wrap AAD is the uuid plus the slot index, and differs per slot")
    void wrapAadBindsSlotToFile() {
        assertEquals("database_uuid || slot_index:u8", vector().get("keyslot").get("wrap_aad").asText());
        byte[] uuid = Vectors.hex("000102030405060708090a0b0c0d0e0f");
        assertEquals("000102030405060708090a0b0c0d0e0f00", Vectors.hex(Keyslot.wrapAad(uuid, 0)));
        assertEquals("000102030405060708090a0b0c0d0e0f01", Vectors.hex(Keyslot.wrapAad(uuid, 1)));
        assertNotEquals(Vectors.hex(Keyslot.wrapAad(uuid, 0)),
                Vectors.hex(Keyslot.wrapAad(Vectors.hex("0f0e0d0c0b0a09080706050403020100"), 0)));
    }

    @Test
    @DisplayName("a keyslot state outside 0 and 1 is corruption")
    void badKeyslotStateIsCorruption() {
        byte[] bytes = new Keyslot().encode();
        bytes[0] = 9;
        assertThrows(CorruptionException.class, () -> Keyslot.decode(bytes, 0));
    }

    @Test
    @DisplayName("all four slots round-trip through the superblock's keyslot area")
    void keyslotAreaRoundTrips() {
        Keyslot[] slots = new Keyslot[Keyslot.COUNT];
        for (int i = 0; i < Keyslot.COUNT; i++) {
            slots[i] = new Keyslot();
            slots[i].state = i < 2 ? Keyslot.STATE_OCCUPIED : Keyslot.STATE_EMPTY;
            slots[i].label = "slot" + i;
        }
        byte[] area = Keyslot.encodeAll(slots);
        assertEquals(576, area.length);

        Superblock sb = Superblock.forProfile(Profile.DESKTOP);
        sb.cipher = Superblock.Cipher.XCHACHA20_POLY1305;
        sb.featuresRequired |= Feature.bit(Feature.CIPHER);
        sb.keyslots = area;
        Superblock back = Superblock.decode(sb.encode());

        Keyslot[] decoded = Keyslot.decodeAll(back.keyslots);
        assertTrue(decoded[0].occupied());
        assertTrue(decoded[1].occupied());
        assertFalse(decoded[2].occupied());
        assertEquals("slot1", decoded[1].label);
    }

    @Test
    @DisplayName("the per-profile Argon2id costs match the published table")
    void profileCosts() {
        JsonNode costs = vector().get("profile_costs");
        assertEquals(3, costs.get("mobile").get("t_cost").asInt());
        assertEquals(65536, costs.get("mobile").get("m_cost_kib").asInt());
        assertEquals(1, costs.get("mobile").get("parallelism").asInt());
        assertEquals(4, costs.get("desktop").get("t_cost").asInt());
        assertEquals(262144, costs.get("desktop").get("m_cost_kib").asInt());
    }

    @Test
    @DisplayName("equality on authenticated bytes is constant time")
    void constantTimeEquals() {
        byte[] a = Vectors.hex("00112233");
        assertTrue(Security.constantTimeEquals(a, Vectors.hex("00112233")));
        assertFalse(Security.constantTimeEquals(a, Vectors.hex("00112234")));
        assertFalse(Security.constantTimeEquals(a, Vectors.hex("001122")));
    }
}
