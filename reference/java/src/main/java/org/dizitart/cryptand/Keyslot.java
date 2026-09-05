package org.dizitart.cryptand;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * One wrapped copy of the master key — {@code spec/14-security.md} §3.3.
 *
 * <p>Four slots at superblock offset 3512, 144 bytes each. The master key is
 * random and each slot holds it wrapped under a key-encryption key, so
 * <strong>changing a password is one superblock write</strong> rather than a
 * re-encryption of the file — and destroying the slots is the only erase that
 * means anything on flash, where overwriting is not.
 *
 * <p>The AAD for the wrap is {@code database_uuid || slot_index:u8}, which binds
 * a slot to its file: a keyslot lifted from another database does not unwrap
 * here, so an attacker cannot graft a slot whose password they know onto a file
 * they want to read.
 */
public final class Keyslot {

    public static final int BYTES = 144;
    public static final int COUNT = 4;
    public static final int OFFSET_IN_SUPERBLOCK = 3512;

    public static final int STATE_EMPTY = 0;
    public static final int STATE_OCCUPIED = 1;

    /** The caller supplies 32 key bytes directly, and those bytes <em>are</em> the KEK. */
    public static final int KDF_RAW = 0;
    /** Argon2id over a password, at {@code t_cost} / {@code m_cost_kib} / {@code parallelism}. */
    public static final int KDF_ARGON2ID = 1;

    public int state = STATE_EMPTY;
    public int kdf = KDF_RAW;
    public int tCost;
    public int mCostKib;
    public int parallelism;
    public byte[] salt = new byte[32];
    public byte[] wrapNonce = new byte[24];
    public byte[] wrappedKey = new byte[32];
    public byte[] wrapTag = new byte[16];
    /** UTF-8, not secret, for tooling: {@code "password"}, {@code "keyring"}, {@code "recovery"}. */
    public String label = "";

    public boolean occupied() {
        return state == STATE_OCCUPIED;
    }

    /** The AAD that binds this slot to its file. */
    public static byte[] wrapAad(byte[] databaseUuid, int slotIndex) {
        if (databaseUuid.length != 16) {
            throw new InvalidArgumentException("database_uuid is 16 bytes, got " + databaseUuid.length);
        }
        byte[] aad = Arrays.copyOf(databaseUuid, 17);
        aad[16] = (byte) slotIndex;
        return aad;
    }

    public byte[] encode() {
        byte[] labelBytes = Utf8.encode(label);
        if (labelBytes.length > 16) {
            throw new InvalidArgumentException("keyslot label is longer than 16 bytes: " + label);
        }
        ByteWriter w = new ByteWriter(BYTES);
        w.u8(state).u8(kdf).u8(labelBytes.length).u8(0);
        // kdf = 0 takes a key the host already holds, so salt and the Argon2id
        // costs MUST be written as zero.
        boolean raw = kdf == KDF_RAW;
        w.u32(raw ? 0 : tCost).u32(raw ? 0 : mCostKib).u32(raw ? 0 : parallelism);
        w.bytes(raw ? new byte[32] : fixed(salt, 32));
        w.bytes(fixed(wrapNonce, 24));
        w.bytes(fixed(wrappedKey, 32));
        w.bytes(fixed(wrapTag, 16));
        w.bytes(Arrays.copyOf(labelBytes, 16));
        w.u64(0);
        byte[] out = w.toBytes();
        if (out.length != BYTES) {
            throw new IllegalStateException("keyslot is " + out.length + " bytes, expected " + BYTES);
        }
        return out;
    }

    public static Keyslot decode(byte[] bytes, int offset) {
        ByteReader r = new ByteReader(bytes, offset, BYTES);
        Keyslot k = new Keyslot();
        k.state = r.u8();
        if (k.state != STATE_EMPTY && k.state != STATE_OCCUPIED) {
            throw new CorruptionException("keyslot state is " + k.state + ", must be 0 or 1");
        }
        k.kdf = r.u8();
        int labelLen = r.u8();
        if (labelLen > 16) {
            throw new CorruptionException("keyslot label_len is " + labelLen + ", must be at most 16");
        }
        r.skip(1);
        k.tCost = r.u32();
        k.mCostKib = r.u32();
        k.parallelism = r.u32();
        k.salt = r.bytes(32);
        k.wrapNonce = r.bytes(24);
        k.wrappedKey = r.bytes(32);
        k.wrapTag = r.bytes(16);
        byte[] label = r.bytes(16);
        k.label = new String(label, 0, labelLen, StandardCharsets.UTF_8);
        return k;
    }

    /** All four slots out of a superblock's 576-byte keyslot area. */
    public static Keyslot[] decodeAll(byte[] keyslotArea) {
        if (keyslotArea.length < COUNT * BYTES) {
            throw new LimitException("keyslot area is " + keyslotArea.length + " bytes, need " + (COUNT * BYTES));
        }
        Keyslot[] slots = new Keyslot[COUNT];
        for (int i = 0; i < COUNT; i++) {
            slots[i] = decode(keyslotArea, i * BYTES);
        }
        return slots;
    }

    public static byte[] encodeAll(Keyslot[] slots) {
        byte[] out = new byte[COUNT * BYTES];
        for (int i = 0; i < Math.min(COUNT, slots.length); i++) {
            if (slots[i] != null) {
                System.arraycopy(slots[i].encode(), 0, out, i * BYTES, BYTES);
            }
        }
        return out;
    }

    private static byte[] fixed(byte[] src, int n) {
        return src.length == n ? src : Arrays.copyOf(src, n);
    }
}
