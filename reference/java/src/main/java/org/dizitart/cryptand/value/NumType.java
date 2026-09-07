package org.dizitart.cryptand.value;

import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.util.Tag;
import org.dizitart.cryptand.util.U128;

/**
 * The declared width of a numeric value.
 *
 * <p>Two numberings hang off each constant and they are <em>different</em>:
 * {@link #cveTag()} is the CVE type tag of {@code spec/02-value-encoding.md}
 * §1, and {@link #ckeCode()} is the CKE type code of
 * {@code spec/03-key-encoding.md} §4.3. Conflating them is a way for two
 * implementations to disagree while both look right.
 *
 * <p>{@code spec/02-value-encoding.md} §1.2: <strong>the declared width is
 * metadata, never semantics.</strong> All numeric tags form one domain compared
 * by exact numeric value, so {@code I32(5)} equals {@code I64(5)} equals
 * {@code F64(5.0)}. The width exists only to round-trip the source type.
 */
public enum NumType {

    I8("i8", Tag.I8, 0x00, 8, true),
    I16("i16", Tag.I16, 0x01, 16, true),
    I32("i32", Tag.I32, 0x02, 32, true),
    I64("i64", Tag.I64, 0x03, 64, true),
    I128("i128", Tag.I128, 0x04, 128, true),
    U8("u8", Tag.U8, 0x05, 8, false),
    U16("u16", Tag.U16, 0x06, 16, false),
    U32("u32", Tag.U32, 0x07, 32, false),
    U64("u64", Tag.U64, 0x08, 64, false),
    U128("u128", Tag.U128, 0x09, 128, false),
    F32("f32", Tag.F32, 0x0A, 32, true),
    F64("f64", Tag.F64, 0x0B, 64, true),
    INT_VAR("intVar", Tag.INT_VAR, 0x0C, 64, true),

    /**
     * {@code 0x0D} is <em>reserved</em> in CKE, not assigned to this.
     * {@code spec/03-key-encoding.md} §4.4 removed {@code DEC128} from the key
     * domain because a decimal fraction — {@code 0.1} being the obvious one —
     * has no exact binary {@code m × 2^e} form, so it can neither be encoded
     * exactly nor ordered against an {@code f64} without silently rounding one
     * of them. It keeps its CVE tag and stores fine; it just has no key.
     */
    DEC128("dec128", Tag.DEC128, -1, 128, true);

    private final String wireName;
    private final int cveTag;
    private final int ckeCode;
    private final int bits;
    private final boolean signed;

    NumType(String wireName, int cveTag, int ckeCode, int bits, boolean signed) {
        this.wireName = wireName;
        this.cveTag = cveTag;
        this.ckeCode = ckeCode;
        this.bits = bits;
        this.signed = signed;
    }

    /** The name used in the shared conformance vectors, e.g. {@code "intVar"}. */
    public String wireName() {
        return wireName;
    }

    public int cveTag() {
        return cveTag;
    }

    /** The CKE type code of §4.3, or {@code -1} when the type has no key encoding. */
    public int ckeCode() {
        return ckeCode;
    }

    /** Declared width in bits. {@code INT_VAR} is 64: it is the compact form of an {@code i64}. */
    public int bits() {
        return bits;
    }

    public boolean isSigned() {
        return signed;
    }

    public boolean isFloat() {
        return this == F32 || this == F64;
    }

    public boolean isKeyEncodable() {
        return ckeCode >= 0;
    }

    public static NumType byWireName(String name) {
        for (NumType t : values()) {
            if (t.wireName.equals(name)) {
                return t;
            }
        }
        throw new InvalidArgumentException("unknown numeric width: " + name);
    }

    /** The type whose CKE code is {@code code}, or {@code null} if none. */
    public static NumType byCkeCode(int code) {
        for (NumType t : values()) {
            if (t.ckeCode == code) {
                return t;
            }
        }
        return null;
    }
}
