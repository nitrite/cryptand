package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code spec/05-catalog.md} §8 and {@code spec/14-security.md} §10 — tree 5's
 * credential records, read back from a file an attacker controls.
 *
 * <p>The KDF parameters in a <b>keyslot</b> are deliberately used as stored:
 * §3.2 says "on open it MUST use whatever the slot says — the superblock MAC
 * (§6) is what prevents an attacker weakening those numbers". That reasoning
 * does <b>not</b> carry to tree 5. {@code sb_mac} covers the superblock, not a
 * tree's contents, and §10 explicitly contemplates users on an <em>unencrypted</em>
 * database — where nothing authenticates this record at all.
 *
 * <p>So {@code params} here is attacker-controlled input to an allocator, and
 * §9.1 applies with full force: it "applies to every implementation, whether or
 * not it supports encryption, because T5 does not require the attacker to have
 * a key". A {@code m_cost_kib} of 0xFFFFFFFF is a 4 TiB allocation request; the
 * requirement is a typed error, not an {@code OutOfMemoryError} and not the
 * {@code NegativeArraySizeException} that a u32 narrowed to a signed int
 * produces on the way there.
 */
class HostileUserRecordTest {

    @TempDir
    Path dir;

    private static Value.Doc record(String username, long tCost, long mCostKib, long parallelism,
                                    byte[] salt, byte[] hash, String kdf) {
        Map<String, Value> params = new LinkedHashMap<>();
        params.put("t_cost", Value.integer(NumType.U32, tCost));
        params.put("m_cost_kib", Value.integer(NumType.U32, mCostKib));
        params.put("parallelism", Value.integer(NumType.U32, parallelism));
        Map<String, Value> r = new LinkedHashMap<>();
        r.put("username", new Value.Str(username));
        r.put("kdf", new Value.Str(kdf));
        r.put("params", Value.Doc.of(params));
        r.put("salt", new Value.Bytes(salt));
        r.put("hash", new Value.Bytes(hash));
        return Value.Doc.of(r);
    }

    /** Writes {@code doc} into tree 5 under {@code username}, as an edited file would hold it. */
    private static void poison(Database db, String username, Value.Doc doc) {
        db.engine().lockStructure();
        try {
            db.engine().usersTree().put(Cke.encode(new Value.Str(username)),
                    Cve.encode(doc));
        } finally {
            db.engine().unlockStructure();
        }
        db.commit();
    }

    private Database open() {
        Engine.Options o = new Engine.Options();
        o.durability = Superblock.Durability.NONE;
        return Database.create(dir.resolve("users.cryptand"), o);
    }

    @Test
    @DisplayName("a user record with hostile KDF parameters is refused, not obeyed")
    void hostileKdfParameters() {
        try (Database db = open()) {
            byte[] pw = "correct horse".getBytes(StandardCharsets.UTF_8);
            db.addUser("alice", pw, org.dizitart.cryptand.container.Profile.DESKTOP);

            // 4 TiB of Argon2id memory, one edited field away.
            poison(db, "alice", record("alice", 2, 0xFFFFFFFFL, 1,
                    new byte[32], new byte[32], "argon2id"));
            assertThrows(CryptandException.class, () -> db.authenticate("alice", pw),
                    "an m_cost_kib of 0xFFFFFFFF must be a typed error, not an allocation");

            // 0x7FFFFFFF passes Argon2id's own RFC floor check and asks for
            // ~2 TiB: the floor is not a ceiling.
            poison(db, "alice", record("alice", 2, 0x7FFFFFFFL, 1,
                    new byte[32], new byte[32], "argon2id"));
            assertThrows(CryptandException.class, () -> db.authenticate("alice", pw),
                    "an m_cost_kib of 0x7FFFFFFF must be a typed error, not an allocation");

            // t_cost of 0xFFFFFFFF is the same attack against time rather than space.
            poison(db, "alice", record("alice", 0xFFFFFFFFL, 65536, 1,
                    new byte[32], new byte[32], "argon2id"));
            assertThrows(CryptandException.class, () -> db.authenticate("alice", pw));

            // Below §3.2's floor: t_cost 1, m_cost 8 KiB — a hash anyone can grind.
            poison(db, "alice", record("alice", 1, 8, 1,
                    new byte[32], new byte[32], "argon2id"));
            assertThrows(CryptandException.class, () -> db.authenticate("alice", pw));

            // parallelism 0 is a division by zero in every Argon2 implementation.
            poison(db, "alice", record("alice", 2, 65536, 0,
                    new byte[32], new byte[32], "argon2id"));
            assertThrows(CryptandException.class, () -> db.authenticate("alice", pw));
        }
    }

    @Test
    @DisplayName("a structurally broken user record is refused, not dereferenced")
    void structurallyBrokenRecord() {
        try (Database db = open()) {
            byte[] pw = "correct horse".getBytes(StandardCharsets.UTF_8);
            db.addUser("bob", pw, org.dizitart.cryptand.container.Profile.DESKTOP);

            // §8: `kdf` MUST be "argon2id". Anything else is not a KDF this
            // implementation may guess at.
            poison(db, "bob", record("bob", 2, 65536, 1,
                    new byte[32], new byte[32], "scrypt"));
            assertThrows(CryptandException.class, () -> db.authenticate("bob", pw));

            // A record missing `salt` entirely — `field()` returns null, and the
            // cast that follows is a NullPointerException rather than an error.
            Map<String, Value> r = new LinkedHashMap<>();
            r.put("username", new Value.Str("bob"));
            r.put("kdf", new Value.Str("argon2id"));
            r.put("hash", new Value.Bytes(new byte[32]));
            poison(db, "bob", Value.Doc.of(r));
            assertThrows(CryptandException.class, () -> db.authenticate("bob", pw));

            // Tree 5 holding something that is not a document at all.
            db.engine().lockStructure();
            try {
                db.engine().usersTree().put(Cke.encode(new Value.Str("bob")),
                        Cve.encode(new Value.Str("not a record")));
            } finally {
                db.engine().unlockStructure();
            }
            db.commit();
            assertThrows(CryptandException.class, () -> db.authenticate("bob", pw));
        }
    }

    @Test
    @DisplayName("an unknown user is still a plain false, not an error")
    void unknownUserIsFalse() {
        try (Database db = open()) {
            assertFalse(db.authenticate("nobody", "x".getBytes(StandardCharsets.UTF_8)));
        }
    }
}
