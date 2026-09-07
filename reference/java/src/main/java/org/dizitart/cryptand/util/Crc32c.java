package org.dizitart.cryptand.util;

import java.util.zip.CRC32C;

/**
 * CRC-32C (Castagnoli), {@code spec/00-conventions.md} §6.
 *
 * <p>Polynomial {@code 0x1EDC6F41}, reflected, init {@code 0xFFFFFFFF}, final
 * xor {@code 0xFFFFFFFF}. Chosen because it is hardware-accelerated on every
 * current ARM and x86, and because every target language already has it — in
 * Java's case since 9, as {@link CRC32C}, which is why this class is a
 * three-line delegation rather than a table.
 *
 * <p>A checksum covers every byte of its page or header <strong>except the four
 * bytes of the checksum field itself</strong>, over the bytes <em>as stored</em>
 * — after compression and after encryption, so verification precedes decoding.
 * There are exactly two placements: first field for an ordinary page (covering
 * {@code 4 … page_size-1}), last field for the superblock (covering
 * {@code 0 … 4091}).
 */
public final class Crc32c {

    private Crc32c() {
    }

    public static int of(byte[] data) {
        return of(data, 0, data.length);
    }

    public static int of(byte[] data, int offset, int length) {
        CRC32C crc = new CRC32C();
        crc.update(data, offset, length);
        return (int) crc.getValue();
    }
}
