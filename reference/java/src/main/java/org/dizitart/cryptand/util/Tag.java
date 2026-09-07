package org.dizitart.cryptand.util;

import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.value.NumType;

/**
 * CVE type tags, {@code spec/02-value-encoding.md} §1.
 *
 * <p>These are the <em>CVE</em> tags. They are not the CKE group tags of
 * {@code spec/03-key-encoding.md} §2, nor the CKE numeric type codes of §4.3,
 * and all three are different numberings over overlapping sets of types. Two
 * implementations can silently disagree by confusing them, so each numbering
 * lives in exactly one place: here, in {@link Cke}, and in {@link NumType}.
 */
public final class Tag {

    private Tag() {
    }

    public static final int NULL = 0x00;
    public static final int FALSE = 0x01;
    public static final int TRUE = 0x02;
    public static final int I8 = 0x03;
    public static final int I16 = 0x04;
    public static final int I32 = 0x05;
    public static final int I64 = 0x06;
    public static final int I128 = 0x07;
    public static final int U8 = 0x08;
    public static final int U16 = 0x09;
    public static final int U32 = 0x0A;
    public static final int U64 = 0x0B;
    public static final int U128 = 0x0C;
    public static final int INT_VAR = 0x0D;
    public static final int F32 = 0x0E;
    public static final int F64 = 0x0F;
    public static final int DEC128 = 0x10;
    public static final int CHAR = 0x11;
    public static final int STR = 0x12;
    public static final int BYTES = 0x13;
    public static final int TIMESTAMP = 0x14;
    public static final int TIMESTAMP_NS = 0x15;
    public static final int ZONED = 0x16;
    public static final int DATE = 0x17;
    public static final int TIME = 0x18;
    public static final int DURATION = 0x19;
    public static final int UUID = 0x1A;
    public static final int NITRITE_ID = 0x1B;
    public static final int REGEX = 0x1C;
    public static final int ARRAY = 0x20;
    public static final int MAP = 0x21;
    public static final int DOC = 0x22;
    public static final int VECTOR = 0x23;
    public static final int GEOMETRY = 0x24;
    public static final int BLOB_REF = 0x30;
    public static final int OVERFLOW_REF = 0x31;
    public static final int VLOG_REF = 0x32;
    public static final int OPAQUE = 0x7F;

    /**
     * Whether {@code tag} is one of the reserved or implementation-private
     * ranges, which {@code spec/02-value-encoding.md} §1.1 requires to be
     * encoded as {@code u8 tag || uvar byte_len || bytes}.
     *
     * <p>Without that rule §4 of {@code spec/11-conformance.md} — "an unknown
     * CVE type tag round-trips byte for byte" — is a promise no reader can
     * keep: an {@code ARRAY} stores values back to back with no offsets, so an
     * unknown tag inside one is unskippable and a reader meeting it would have
     * to abandon every known sibling with it.
     */
    public static boolean isUnassigned(int tag) {
        return (tag >= 0x1D && tag <= 0x1F)
                || (tag >= 0x25 && tag <= 0x2F)
                || (tag >= 0x33 && tag <= 0x7E)
                || (tag >= 0x80 && tag <= 0xFF);
    }
}
