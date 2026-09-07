package org.dizitart.cryptand;

import org.dizitart.cryptand.crypto.Argon2id;
import org.dizitart.cryptand.crypto.Blake2b;
import org.dizitart.cryptand.crypto.Security;
import org.dizitart.cryptand.crypto.XChaCha20Poly1305;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The four primitives of {@code spec/14-security.md} §2, each checked against
 * <strong>its own published standard</strong> rather than against another
 * implementation. That is the property §2 says it chose them for: "an
 * implementation is checked against the vectors, not against another
 * implementation."
 */
class CryptoPrimitivesTest {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replaceAll("\\s", ""));
    }

    @Test
    @DisplayName("BLAKE2b-512 reproduces RFC 7693 appendix A")
    void blake2bRfc7693() {
        assertArrayEquals(
                hex("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                        + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
                Blake2b.hash(64, "abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("BLAKE2b-512 of the empty string")
    void blake2bEmpty() {
        assertArrayEquals(
                hex("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                        + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
                Blake2b.hash(64, new byte[0]));
    }

    @Test
    @DisplayName("HChaCha20 reproduces the CFRG draft's vector")
    void hchacha20() {
        byte[] key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = hex("000000090000004a0000000031415927");
        assertArrayEquals(
                hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"),
                XChaCha20Poly1305.hchacha20(key, nonce));
    }

    /** draft-irtf-cfrg-xchacha-03 §A.3.1. */
    @Test
    @DisplayName("XChaCha20-Poly1305 reproduces the CFRG draft's AEAD vector")
    void xchachaAead() {
        byte[] key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        byte[] aad = hex("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = ("Ladies and Gentlemen of the class of '99: If I could offer you "
                + "only one tip for the future, sunscreen would be it.").getBytes(StandardCharsets.UTF_8);
        byte[] expected = hex(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfacc"
                        + "bed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39"
                        + "ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945"
                        + "b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
                        + "21f9664c97637da9768812f615c68b13b52e"
                        + "c0875924c1c7987947deafd8780acf49");
        byte[] got = XChaCha20Poly1305.encrypt(key, nonce, aad, pt);
        assertArrayEquals(expected, got);
        assertArrayEquals(pt, XChaCha20Poly1305.decrypt(key, nonce, aad, got, "the draft vector"));
    }

    /**
     * A modified byte is <strong>tampering</strong>, not corruption.
     * {@code 01-container.md} §9: "your disk has a bad sector" and "someone
     * edited your database" call for different responses, and this one MUST NOT
     * be repaired.
     */
    @Test
    @DisplayName("a flipped ciphertext byte, a flipped AAD byte and a wrong key all report tampering")
    void tamperingIsItsOwnClass() {
        byte[] key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        byte[] aad = hex("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
        byte[] ct = XChaCha20Poly1305.encrypt(key, nonce, aad, pt);

        byte[] flipped = ct.clone();
        flipped[3] ^= 0x01;
        assertThrows(TamperingException.class,
                () -> XChaCha20Poly1305.decrypt(key, nonce, aad, flipped, "page"));

        byte[] otherAad = aad.clone();
        otherAad[0] ^= 0x01;
        assertThrows(TamperingException.class,
                () -> XChaCha20Poly1305.decrypt(key, nonce, otherAad, ct, "page"));

        byte[] otherKey = key.clone();
        otherKey[0] ^= 0x01;
        assertThrows(TamperingException.class,
                () -> XChaCha20Poly1305.decrypt(otherKey, nonce, aad, ct, "page"));
    }

    /** RFC 9106 §5.3's Argon2id vector, secret and associated data included. */
    @Test
    @DisplayName("Argon2id reproduces RFC 9106 section 5.3")
    void argon2idRfc9106() {
        byte[] password = new byte[32];
        Arrays.fill(password, (byte) 0x01);
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0x02);
        byte[] secret = new byte[8];
        Arrays.fill(secret, (byte) 0x03);
        byte[] ad = new byte[12];
        Arrays.fill(ad, (byte) 0x04);
        assertArrayEquals(
                hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
                Argon2id.hash(password, salt, secret, ad, 3, 32, 4, 32));
    }

    /**
     * §3.2's floors, checked when <em>creating</em> a keyslot. On open the
     * parameters come from the file and are used as they are: the superblock
     * MAC is what stops an attacker weakening them, and deriving under
     * different ones would report "wrong password" for a correct one.
     */
    @Test
    @DisplayName("weak Argon2id parameters are refused at create time")
    void argon2CreateFloors() {
        assertThrows(InvalidArgumentException.class,
                () -> Argon2id.checkCreateParameters(1, 65536, 1));
        assertThrows(InvalidArgumentException.class,
                () -> Argon2id.checkCreateParameters(3, 8192, 1));
        assertThrows(InvalidArgumentException.class,
                () -> Argon2id.checkCreateParameters(3, 65536, 0));
        Argon2id.checkCreateParameters(3, 65536, 1);
    }

    @Test
    @DisplayName("the nonce is 24 bytes, little-endian, with the fields §4.2 names")
    void nonceConstruction() {
        byte[] n = Security.buildNonce(Security.NonceDomain.PAGE, 1, 2, 0);
        assertEquals(24, n.length);
        assertArrayEquals(hex("010100000000000000020000000000000000000000000000"), n);
    }
}
