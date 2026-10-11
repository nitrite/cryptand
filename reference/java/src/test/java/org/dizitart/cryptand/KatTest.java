package org.dizitart.cryptand;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dizitart.cryptand.crypto.Argon2id;
import org.dizitart.cryptand.crypto.Blake2b;
import org.dizitart.cryptand.crypto.Security;
import org.dizitart.cryptand.crypto.XChaCha20Poly1305;
import org.dizitart.cryptand.util.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * PLAN M4.2: the primitive KATs in {@code conformance/vectors/kat}, shared with
 * the Rust and Dart suites. HChaCha20, BLAKE2b and Argon2id are hand-rolled
 * here, so this is where a silent mismatch would hide. Java's BLAKE2b is
 * unkeyed only (the format never keys it), so the keyed reference KAT runs in
 * Rust and Dart; Argon2id's vectors cover the unkeyed path end to end.
 */
class KatTest {

    private static JsonNode rows(String name) throws Exception {
        JsonNode n = new ObjectMapper().readTree(Path.of("..", "conformance", "vectors", "kat", name).toFile());
        assertFalse(n.isEmpty(), name + " is empty");
        return n;
    }

    private static byte[] h(JsonNode r, String k) {
        return Hex.parse(r.get(k).asText());
    }

    @Test
    void chacha20Poly1305Wycheproof() throws Exception {
        // The JDK's cipher, which XChaCha20Poly1305 feeds the HChaCha20 subkey to.
        int i = 0;
        for (JsonNode r : rows("chacha20_poly1305.json")) {
            Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(h(r, "key"), "ChaCha20"), new IvParameterSpec(h(r, "nonce")));
            c.updateAAD(h(r, "aad"));
            String at = "row " + i++;
            if (r.get("valid").asText().equals("01")) {
                assertArrayEquals(h(r, "msg"), c.doFinal(h(r, "ct")), at);
            } else {
                assertThrows(AEADBadTagException.class, () -> c.doFinal(h(r, "ct")), at);
            }
        }
    }

    @Test
    void xchacha20Poly1305Wycheproof() throws Exception {
        int i = 0;
        for (JsonNode r : rows("xchacha20_poly1305.json")) {
            String at = "row " + i++;
            byte[] key = h(r, "key"), nonce = h(r, "nonce"), aad = h(r, "aad"), ct = h(r, "ct");
            if (r.get("valid").asText().equals("01")) {
                assertArrayEquals(ct, XChaCha20Poly1305.encrypt(key, nonce, aad, h(r, "msg")), at);
                assertArrayEquals(h(r, "msg"), XChaCha20Poly1305.decrypt(key, nonce, aad, ct, at), at);
            } else {
                assertThrows(TamperingException.class, () -> XChaCha20Poly1305.decrypt(key, nonce, aad, ct, at), at);
            }
        }
    }

    @Test
    void hkdfSha256Wycheproof() throws Exception {
        int i = 0;
        for (JsonNode r : rows("hkdf_sha256.json")) {
            byte[] okm = h(r, "okm");
            assertArrayEquals(okm, Security.hkdf(h(r, "salt"), h(r, "ikm"), h(r, "info"), okm.length), "row " + i++);
        }
    }

    @Test
    void hmacSha256Wycheproof() throws Exception {
        int i = 0;
        for (JsonNode r : rows("hmac_sha256.json")) {
            byte[] tag = h(r, "tag");
            byte[] got = Security.hmacSha256(h(r, "key"), h(r, "msg"));
            assertArrayEquals(tag, Arrays.copyOf(got, tag.length), "row " + i++);
        }
    }

    @Test
    void blake2bUnkeyed() throws Exception {
        int i = 0;
        for (JsonNode r : rows("blake2b_unkeyed.json")) {
            byte[] d = h(r, "digest");
            assertArrayEquals(d, Blake2b.hash(d.length, h(r, "msg")), "row " + i++);
        }
    }

    @Test
    void argon2idRfc9106AndReference() throws Exception {
        for (JsonNode r : rows("argon2id.json")) {
            byte[] tag = h(r, "tag");
            assertArrayEquals(tag, Argon2id.hash(h(r, "password"), h(r, "salt"), h(r, "secret"), h(r, "ad"),
                    r.get("t").asInt(), r.get("m").asInt(), r.get("p").asInt(), tag.length), r.get("source").asText());
        }
    }
}
