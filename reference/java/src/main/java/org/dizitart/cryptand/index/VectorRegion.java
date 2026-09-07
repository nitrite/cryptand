package org.dizitart.cryptand.index;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.LimitException;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Pager;
import org.dizitart.cryptand.crypto.FileCipher;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;

/**
 * A flat vector region — {@code spec/09-vector.md} §2.
 *
 * <p>A contiguous, page-aligned extent whose slots are addressed by a global
 * {@code slot_id} spanning the region chain. Three properties of the layout are
 * load-bearing:
 *
 * <ul>
 *   <li><strong>{@code data_offset} is page-aligned</strong>, so an
 *       implementation that can {@code mmap} reads vectors as slices with no
 *       copy and its resident memory is bounded by the OS page cache. This
 *       implementation reads positionally instead — the layout is identical and
 *       only the access method differs, which is what §2 says of Dart too.
 *   <li><strong>An encrypted region cannot be sliced in place</strong>
 *       ({@code 14-security.md} §5.4), so the OS stops bounding memory and the
 *       implementation must. Fully supported, materially harder to keep inside a
 *       budget, and said rather than discovered.
 *   <li><strong>{@code stride} may exceed the natural vector size</strong> so
 *       slots land on 64-byte boundaries for SIMD. It is a {@code u16}, so
 *       {@code dim x sizeof(dtype)} is capped at 65535 — a model beyond that is
 *       served by splitting the vector across two indexes, because a 64 KiB
 *       vector is not an embedding a proximity graph is the right structure for.
 * </ul>
 */
public final class VectorRegion {

    /** {@code "CRY_VEC"} + {@code 0x1A}. */
    public static final byte[] MAGIC = {0x43, 0x52, 0x59, 0x5F, 0x56, 0x45, 0x43, 0x1A};

    public static final int HEADER_BYTES = 64;

    public static final int DTYPE_F32 = 0;
    public static final int DTYPE_F16 = 1;
    public static final int DTYPE_I8 = 2;
    public static final int DTYPE_U8_PQ = 3;

    public int dim;
    public int dtype;
    public int stride;
    public long slotCount;
    public long liveCount;
    public long dataOffset;
    public long nextRegion;

    public long startPage;
    public int pages;

    public static int elementBytes(int dtype) {
        return switch (dtype) {
            case DTYPE_F32 -> 4;
            case DTYPE_F16 -> 2;
            case DTYPE_I8, DTYPE_U8_PQ -> 1;
            default -> throw new InvalidArgumentException("vector dtype " + dtype + " is not 0..3");
        };
    }

    /**
     * The natural size of one vector, plus the {@code f32 scale, f32 zero_point}
     * that follow an {@code i8} slot inside its stride.
     */
    public static int naturalStride(int dim, int dtype) {
        int base = dim * elementBytes(dtype);
        return dtype == DTYPE_I8 ? base + 8 : base;
    }

    public byte[] encodeHeader() {
        ByteWriter w = new ByteWriter(HEADER_BYTES);
        w.bytes(MAGIC);
        w.u32(dim).u8(dtype).u8(0).u16(stride);
        w.u64(slotCount).u64(liveCount).u64(dataOffset).u64(nextRegion);
        for (int i = 0; i < 16; i++) {
            w.u8(0);
        }
        if (w.length() != HEADER_BYTES) {
            throw new IllegalStateException("vector region header is " + w.length()
                    + " bytes, expected " + HEADER_BYTES);
        }
        return w.toBytes();
    }

    public static VectorRegion decodeHeader(byte[] payload) {
        ByteReader r = new ByteReader(payload);
        byte[] magic = r.bytes(8);
        if (!java.util.Arrays.equals(magic, MAGIC)) {
            throw new CorruptionException("vector region magic is "
                    + java.util.HexFormat.of().formatHex(magic) + ", expected 435259 5f5645431a");
        }
        VectorRegion v = new VectorRegion();
        v.dim = r.u32();
        v.dtype = r.u8();
        r.skip(1);
        v.stride = r.u16();
        v.slotCount = r.u64();
        v.liveCount = r.u64();
        v.dataOffset = r.u64();
        v.nextRegion = r.u64();
        if (v.stride < naturalStride(v.dim, v.dtype)) {
            throw new CorruptionException("vector region stride " + v.stride
                    + " is below the natural size " + naturalStride(v.dim, v.dtype));
        }
        return v;
    }

    /**
     * Allocates a region for {@code slots} vectors.
     *
     * <p>Slot 0 of the first region is reserved and never used, so
     * {@code slot_id = 0} is a null pointer.
     */
    public static VectorRegion create(Pager pager, int dim, int dtype, long slots) {
        int natural = naturalStride(dim, dtype);
        if (natural > 0xFFFF) {
            throw new LimitException("a vector of " + dim + " x " + elementBytes(dtype)
                    + " bytes exceeds the u16 stride field; split it across two indexes"
                    + " (spec/09-vector.md §2)");
        }
        VectorRegion v = new VectorRegion();
        v.dim = dim;
        v.dtype = dtype;
        // Round to 64 bytes so slots land on a SIMD boundary, while staying
        // inside the u16 field.
        int aligned = (natural + 63) / 64 * 64;
        v.stride = aligned <= 0xFFFF ? aligned : natural;
        v.slotCount = slots;
        v.liveCount = 0;
        // Page-aligned, so a region can be mapped and sliced where the host can.
        v.dataOffset = pager.pageSize();
        long bytes = v.dataOffset + slots * (long) v.stride;
        int pages = (int) ((bytes + pager.pageSize() - 1) / pager.pageSize());
        v.startPage = pager.allocate(pages);
        v.pages = pages;

        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.VECTOR_REGION;
        h.flags = PageHeader.Flags.EXTENT_HEAD;
        h.extentPages = pages;
        h.commitId = pager.commitId();
        byte[] header = v.encodeHeader();
        h.payloadLen = header.length;
        byte[] head = new byte[pager.pageSize()];
        System.arraycopy(header, 0, head, PageHeader.BYTES, header.length);
        // The head page's checksum covers only its own header material: the
        // slots begin at data_offset and are rewritten for the life of the
        // region, exactly as a value-log segment's records are.
        h.writeInto(head, PageHeader.BYTES + HEADER_BYTES);
        pager.file().write(pager.offsetOf(v.startPage), head);
        return v;
    }

    public static VectorRegion open(Pager pager, long startPage) {
        byte[] page = pager.readRaw(startPage);
        PageHeader h = PageHeader.verify(page, startPage, PageHeader.BYTES + HEADER_BYTES);
        if (h.pageType != PageHeader.Type.VECTOR_REGION) {
            throw new CorruptionException("page " + startPage + " has type " + h.pageType
                    + ", expected VECTOR_REGION", startPage, null);
        }
        byte[] header = new byte[HEADER_BYTES];
        System.arraycopy(page, PageHeader.BYTES, header, 0, HEADER_BYTES);
        VectorRegion v = decodeHeader(header);
        v.startPage = startPage;
        v.pages = h.extentPages;
        return v;
    }

    private long offsetOf(Pager pager, long slot) {
        if (slot < 0 || slot >= slotCount) {
            throw new InvalidArgumentException("slot " + slot + " outside 0.." + (slotCount - 1));
        }
        return pager.offsetOf(startPage) + dataOffset + slot * (long) stride;
    }

    /** Writes one vector, padding the rest of the stride with zeros. */
    public void write(Pager pager, long slot, float[] vector) {
        if (vector.length != dim) {
            throw new InvalidArgumentException("vector has " + vector.length
                    + " dimensions, the region declares " + dim);
        }
        byte[] buf = new byte[stride];
        ByteWriter w = new ByteWriter(stride);
        for (float f : vector) {
            switch (dtype) {
                case DTYPE_F32 -> w.f32(f);
                case DTYPE_F16 -> w.u16(Half.toBits(f));
                default -> throw new InvalidArgumentException(
                        "dtype " + dtype + " needs quantized codes, not raw floats");
            }
        }
        byte[] body = w.toBytes();
        System.arraycopy(body, 0, buf, 0, body.length);
        writeRaw(pager, slot, buf);
    }

    public void writeRaw(Pager pager, long slot, byte[] slotBytes) {
        byte[] buf = slotBytes.length == stride ? slotBytes : java.util.Arrays.copyOf(slotBytes, stride);
        if (pager.crypto() instanceof FileCipher) {
            writeEncrypted(pager, slot, buf);
            return;
        }
        pager.file().write(offsetOf(pager, slot), buf);
    }

    public float[] read(Pager pager, long slot) {
        byte[] buf = readRaw(pager, slot);
        ByteReader r = new ByteReader(buf);
        float[] out = new float[dim];
        for (int i = 0; i < dim; i++) {
            out[i] = switch (dtype) {
                case DTYPE_F32 -> r.f32();
                case DTYPE_F16 -> Half.toFloat(r.u16());
                default -> throw new InvalidArgumentException(
                        "dtype " + dtype + " holds quantized codes, not raw floats");
            };
        }
        return out;
    }

    public byte[] readRaw(Pager pager, long slot) {
        if (pager.crypto() instanceof FileCipher) {
            return readEncrypted(pager, slot);
        }
        byte[] buf = new byte[stride];
        pager.file().readFully(offsetOf(pager, slot), buf, 0, stride);
        return buf;
    }

    // ==================================================================
    // §5.4: an encrypted extent is chunked per page, read-modify-write
    // ==================================================================

    private int chunkOf(Pager pager, long slot) {
        long byteOffset = dataOffset + slot * (long) stride - pager.pageSize();
        return (int) (byteOffset / FileCipher.chunkPlaintextBytes(pager.pageSize())) + 1;
    }

    private void writeEncrypted(Pager pager, long slot, byte[] buf) {
        FileCipher cipher = (FileCipher) pager.crypto();
        int chunkBytes = FileCipher.chunkPlaintextBytes(pager.pageSize());
        long logical = dataOffset - pager.pageSize() + slot * (long) stride;
        int written = 0;
        while (written < buf.length) {
            int chunk = (int) ((logical + written) / chunkBytes) + 1;
            int within = (int) ((logical + written) % chunkBytes);
            int n = Math.min(chunkBytes - within, buf.length - written);
            byte[] plain = readChunk(pager, cipher, chunk, chunkBytes);
            System.arraycopy(buf, written, plain, within, n);
            // A partial-chunk write is a read-modify-write under a FRESH
            // counter, never a patch in place: rewriting a chunk under a fixed
            // counter is the same key and the same nonce over different
            // plaintext, which is the whole failure §4 exists to prevent.
            byte[] sealed = cipher.encryptChunk(startPage, chunk, plain);
            pager.file().write(pager.offsetOf(startPage + chunk), sealed);
            written += n;
        }
    }

    private byte[] readEncrypted(Pager pager, long slot) {
        FileCipher cipher = (FileCipher) pager.crypto();
        int chunkBytes = FileCipher.chunkPlaintextBytes(pager.pageSize());
        long logical = dataOffset - pager.pageSize() + slot * (long) stride;
        byte[] out = new byte[stride];
        int read = 0;
        while (read < stride) {
            int chunk = (int) ((logical + read) / chunkBytes) + 1;
            int within = (int) ((logical + read) % chunkBytes);
            int n = Math.min(chunkBytes - within, stride - read);
            byte[] plain = readChunk(pager, cipher, chunk, chunkBytes);
            System.arraycopy(plain, within, out, read, n);
            read += n;
        }
        return out;
    }

    private byte[] readChunk(Pager pager, FileCipher cipher, int chunk, int chunkBytes) {
        byte[] page = new byte[pager.pageSize()];
        pager.file().readFully(pager.offsetOf(startPage + chunk), page, 0, pager.pageSize());
        boolean blank = true;
        for (int i = 0; i < 8 && blank; i++) {
            blank = page[i] == 0;
        }
        if (blank) {
            // Never written: an all-zero chunk decrypts to nothing, and a
            // freshly allocated region is all zeros by construction.
            return new byte[chunkBytes];
        }
        byte[] plain = cipher.decryptChunk(startPage, chunk, java.util.Arrays.copyOf(page, 8 + chunkBytes + 16));
        return java.util.Arrays.copyOf(plain, chunkBytes);
    }

    /** IEEE 754 binary16, for {@code dtype = 1}. */
    static final class Half {
        private Half() {
        }

        static int toBits(float value) {
            int bits = Float.floatToRawIntBits(value);
            int sign = (bits >>> 16) & 0x8000;
            int exponent = ((bits >>> 23) & 0xFF) - 127 + 15;
            int mantissa = bits & 0x7FFFFF;
            if (exponent <= 0) {
                return sign;
            }
            if (exponent >= 0x1F) {
                return sign | 0x7C00;
            }
            return sign | (exponent << 10) | (mantissa >>> 13);
        }

        static float toFloat(int half) {
            int sign = (half & 0x8000) << 16;
            int exponent = (half >>> 10) & 0x1F;
            int mantissa = half & 0x3FF;
            if (exponent == 0) {
                return Float.intBitsToFloat(sign);
            }
            if (exponent == 0x1F) {
                return Float.intBitsToFloat(sign | 0x7F800000 | (mantissa << 13));
            }
            return Float.intBitsToFloat(sign | ((exponent - 15 + 127) << 23) | (mantissa << 13));
        }
    }
}
