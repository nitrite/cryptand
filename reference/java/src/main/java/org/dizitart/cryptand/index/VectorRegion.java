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
    /**
     * The head page's {@code flags.ENCRYPTED}: how this region's data is chunked
     * (14 §5.4), whatever key is in hand now (14 §5.2, F-073).
     */
    public boolean encrypted;

    public static int elementBytes(int dtype) {
        switch (dtype) {
            case DTYPE_F32: return 4;
            case DTYPE_F16: return 2;
            case DTYPE_I8: case DTYPE_U8_PQ: return 1;
            default: throw new InvalidArgumentException("vector dtype " + dtype + " is not 0..3");
        }
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
                    + org.dizitart.cryptand.util.Hex.format(magic) + ", expected 435259 5f5645431a");
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
        // Round to 64 bytes so slots land on a SIMD boundary, while staying
        // inside the u16 field.
        int aligned = (natural + 63) / 64 * 64;
        return allocate(pager, dim, dtype, aligned <= 0xFFFF ? aligned : natural, slots);
    }

    private static VectorRegion allocate(Pager pager, int dim, int dtype, int stride, long slots) {
        VectorRegion v = new VectorRegion();
        v.dim = dim;
        v.dtype = dtype;
        v.stride = stride;
        v.slotCount = slots;
        v.liveCount = 0;
        // Page-aligned, so a region can be mapped and sliced where the host can.
        v.dataOffset = pager.pageSize();
        // F-075, 14 §5.4: an encrypted data area is chunked at page_size - 24,
        // so it needs more pages than ceil(len / page_size).
        v.encrypted = pager.seals() && pager.crypto() instanceof FileCipher;
        long chunk = v.encrypted ? FileCipher.chunkPlaintextBytes(pager.pageSize()) : pager.pageSize();
        int pages = (int) (1 + (slots * (long) v.stride + chunk - 1) / chunk);
        v.startPage = pager.allocate(pages);
        v.pages = pages;

        PageHeader h = new PageHeader();
        h.pageType = PageHeader.Type.VECTOR_REGION;
        h.flags = PageHeader.Flags.EXTENT_HEAD;
        h.extentPages = pages;
        h.commitId = pager.commitId();
        byte[] header = v.encodeHeader();
        h.payloadLen = header.length;
        // F-075: an ordinary page, sealed when the file seals (14 §5.1 exempts
        // only the value-log head page), with 01 §3's whole-page checksum. The
        // slots begin at data_offset = page_size, so nothing else is on it.
        pager.writeAt(pager.offsetOf(v.startPage), pager.buildExtentPage(v.startPage, h, header));
        // A reused extent holds whatever was there; a sealed chunk is read
        // before it is rewritten, so a never-written one must read as blank.
        byte[] zeros = new byte[pager.pageSize() * Math.min(128, Math.max(1, pages - 1))];
        for (long p = 1; p < pages; p += zeros.length / pager.pageSize()) {
            int n = (int) Math.min(zeros.length / pager.pageSize(), pages - p);
            pager.writeAt(pager.offsetOf(v.startPage + p), n * pager.pageSize() == zeros.length
                    ? zeros : java.util.Arrays.copyOf(zeros, n * pager.pageSize()));
        }
        return v;
    }

    public static VectorRegion open(Pager pager, long startPage) {
        PageHeader h = PageHeader.parse(pager.readRaw(startPage), 0);
        if (h.pageType != PageHeader.Type.VECTOR_REGION) {
            throw new CorruptionException("page " + startPage + " has type " + h.pageType
                    + ", expected VECTOR_REGION", startPage, null);
        }
        VectorRegion v = decodeHeader(java.util.Arrays.copyOf(pager.readPage(startPage), HEADER_BYTES));
        v.startPage = startPage;
        v.pages = h.extentPages;
        v.encrypted = h.isSet(PageHeader.Flags.ENCRYPTED);
        return v;
    }

    /**
     * F-072 g, 14 §8.3: a copy of this region laid out for the file's current
     * mode (sealed or clear), same header and stride. The caller frees this
     * extent and repoints the descriptor. A chunk never written (all zero, or
     * past the end of the file) stays unwritten.
     */
    public VectorRegion relocate(Pager pager) {
        VectorRegion v = allocate(pager, dim, dtype, stride, slotCount);
        int ps = pager.pageSize();
        int step = encrypted ? FileCipher.chunkPlaintextBytes(ps) : ps;
        long len = slotCount * (long) stride;
        long base = pager.offsetOf(startPage) + dataOffset;
        long off = 0;
        for (int idx = 0; off < len; idx++) {
            int take = (int) Math.min(step, len - off);
            long at = base + (long) idx * ps;
            if (at + ps <= pager.file().size()) {
                byte[] raw = new byte[ps];
                pager.file().readFully(at, raw, 0, ps);
                boolean blank = true;
                for (int i = 0; i < ps && blank; i++) {
                    blank = raw[i] == 0;
                }
                if (!blank) {
                    byte[] data = encrypted ? readChunk(pager, cipherOf(pager), idx, step) : raw;
                    v.writeData(pager, off, java.util.Arrays.copyOf(data, take));
                }
            }
            off += take;
        }
        v.liveCount = liveCount; // in memory; the head is rewritten by nobody
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
                case DTYPE_F32: w.f32(f); break;
                case DTYPE_F16: w.u16(Half.toBits(f)); break;
                default: throw new InvalidArgumentException(
                        "dtype " + dtype + " needs quantized codes, not raw floats");
            }
        }
        byte[] body = w.toBytes();
        System.arraycopy(body, 0, buf, 0, body.length);
        writeRaw(pager, slot, buf);
    }

    public void writeRaw(Pager pager, long slot, byte[] slotBytes) {
        byte[] buf = slotBytes.length == stride ? slotBytes : java.util.Arrays.copyOf(slotBytes, stride);
        offsetOf(pager, slot); // bounds
        writeData(pager, slot * (long) stride, buf);
    }

    public float[] read(Pager pager, long slot) {
        byte[] buf = readRaw(pager, slot);
        ByteReader r = new ByteReader(buf);
        float[] out = new float[dim];
        for (int i = 0; i < dim; i++) {
            switch (dtype) {
                case DTYPE_F32: out[i] = r.f32(); break;
                case DTYPE_F16: out[i] = Half.toFloat(r.u16()); break;
                default: throw new InvalidArgumentException(
                        "dtype " + dtype + " holds quantized codes, not raw floats");
            }
        }
        return out;
    }

    public byte[] readRaw(Pager pager, long slot) {
        if (encrypted) {
            return readEncrypted(pager, slot);
        }
        byte[] buf = new byte[stride];
        pager.file().readFully(offsetOf(pager, slot), buf, 0, stride);
        return buf;
    }

    // ==================================================================
    // §5.4: an encrypted extent is chunked per page, read-modify-write
    // ==================================================================

    /** Writes {@code buf} at {@code logical} bytes into the data area. */
    private void writeData(Pager pager, long logical, byte[] buf) {
        if (!encrypted) {
            pager.writeAt(pager.offsetOf(startPage) + dataOffset + logical, buf);
            return;
        }
        FileCipher cipher = cipherOf(pager);
        int chunkBytes = FileCipher.chunkPlaintextBytes(pager.pageSize());
        int written = 0;
        while (written < buf.length) {
            int chunk = (int) ((logical + written) / chunkBytes);
            int within = (int) ((logical + written) % chunkBytes);
            int n = Math.min(chunkBytes - within, buf.length - written);
            byte[] plain = readChunk(pager, cipher, chunk, chunkBytes);
            System.arraycopy(buf, written, plain, within, n);
            // A partial-chunk write is a read-modify-write under a FRESH
            // counter, never a patch in place: rewriting a chunk under a fixed
            // counter is the same key and the same nonce over different
            // plaintext, which is the whole failure §4 exists to prevent.
            byte[] sealed = cipher.encryptChunk(startPage, chunk, plain);
            pager.writeAt(pager.offsetOf(startPage + 1 + chunk), sealed);
            written += n;
        }
    }

    private byte[] readEncrypted(Pager pager, long slot) {
        FileCipher cipher = cipherOf(pager);
        int chunkBytes = FileCipher.chunkPlaintextBytes(pager.pageSize());
        long logical = dataOffset - pager.pageSize() + slot * (long) stride;
        byte[] out = new byte[stride];
        int read = 0;
        while (read < stride) {
            int chunk = (int) ((logical + read) / chunkBytes);
            int within = (int) ((logical + read) % chunkBytes);
            int n = Math.min(chunkBytes - within, stride - read);
            byte[] plain = readChunk(pager, cipher, chunk, chunkBytes);
            System.arraycopy(plain, within, out, read, n);
            read += n;
        }
        return out;
    }

    private FileCipher cipherOf(Pager pager) {
        if (!(pager.crypto() instanceof FileCipher)) {
            throw new org.dizitart.cryptand.CannotUnlockException(
                    "vector region at page " + startPage + " is encrypted and no key is available");
        }
        return (FileCipher) pager.crypto();
    }

    private byte[] readChunk(Pager pager, FileCipher cipher, int chunk, int chunkBytes) {
        long at = pager.offsetOf(startPage + 1 + chunk);
        if (at + pager.pageSize() > pager.file().size()) {
            return new byte[chunkBytes]; // allocated, never written: past the end of the file
        }
        byte[] page = new byte[pager.pageSize()];
        pager.file().readFully(at, page, 0, pager.pageSize());
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
