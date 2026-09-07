package org.dizitart.cryptand.index;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.util.ByteReader;
import org.dizitart.cryptand.util.ByteWriter;
import org.dizitart.cryptand.value.NumType;
import org.dizitart.cryptand.value.Value;

import java.util.ArrayList;
import java.util.List;

/**
 * A postings block — {@code spec/07-fulltext.md} §4.
 *
 * <p>At most 128 documents per block, keyed by the block's first document id,
 * so blocks for one term are contiguous and in document order and a posting can
 * be located by seeking straight to a document id — which is what intersecting
 * two terms needs.
 *
 * <p><strong>An update rewrites one block, not the whole posting list.</strong>
 * That is the property the current {@code Map<String, List<NitriteId>>} layout
 * in all three SDKs lacks: there, every update to a common word rewrites a list
 * that can be the size of the collection.
 *
 * <p>The block is a raw byte layout stored as the payload of a CVE
 * {@code BYTES} value, so that {@code 04-segments.md} §2.2's "an INLINE cell
 * holds a CVE value" holds without exception and a generic dump can walk a tree
 * without knowing what kind it is. Two bytes is the price of one uniform rule.
 */
public final class Postings {

    public static final int MAX_PER_BLOCK = 128;
    public static final int VERSION = 1;
    public static final int FLAG_HAS_POSITIONS = 0x01;

    /** One document's posting: its id, its term frequency, and optionally its positions. */
    public record Posting(long nitriteId, int frequency, int[] positions) {

        public Posting(long nitriteId, int frequency) {
            this(nitriteId, frequency, null);
        }
    }

    private Postings() {
    }

    /** {@code CKE(Array[U32 term_id, NITRITE_ID first_doc])}. */
    public static byte[] key(int termId, long firstDoc) {
        return Cke.encode(new Value.Array(List.of(
                Value.integer(NumType.U32, termId),
                new Value.NitriteId(firstDoc))));
    }

    public static byte[] encode(List<Posting> postings, boolean withPositions) {
        if (postings.isEmpty() || postings.size() > MAX_PER_BLOCK) {
            throw new InvalidArgumentException("a postings block holds 1.." + MAX_PER_BLOCK
                    + " documents, got " + postings.size());
        }
        ByteWriter w = new ByteWriter(16 + postings.size() * 4);
        w.u8(VERSION);
        w.u8(withPositions ? FLAG_HAS_POSITIONS : 0);
        w.u16(postings.size());
        w.u64(postings.get(0).nitriteId());
        long previous = postings.get(0).nitriteId();
        for (int i = 1; i < postings.size(); i++) {
            long id = postings.get(i).nitriteId();
            if (id <= previous) {
                throw new InvalidArgumentException("postings in a block must strictly increase");
            }
            // Zigzag even though the deltas are positive, so a future
            // out-of-order writer is representable rather than undefined.
            w.ivar(id - previous);
            previous = id;
        }
        for (Posting p : postings) {
            w.uvar(p.frequency());
        }
        if (withPositions) {
            ByteWriter pos = new ByteWriter(64);
            for (Posting p : postings) {
                int[] ps = p.positions() == null ? new int[0] : p.positions();
                long last = 0;
                for (int i = 0; i < ps.length; i++) {
                    pos.uvar(i == 0 ? ps[i] : ps[i] - last);
                    last = ps[i];
                }
            }
            byte[] body = pos.toBytes();
            // Length-prefixed as a group, so a scorer that only needs
            // frequencies skips them without decoding.
            w.uvar(body.length).bytes(body);
        }
        return w.toBytes();
    }

    public static List<Posting> decode(byte[] block) {
        ByteReader r = new ByteReader(block);
        int version = r.u8();
        if (version != VERSION) {
            throw new CorruptionException("postings block version " + version + ", expected " + VERSION);
        }
        int flags = r.u8();
        boolean positions = (flags & FLAG_HAS_POSITIONS) != 0;
        int count = r.u16();
        if (count < 1 || count > MAX_PER_BLOCK) {
            throw new CorruptionException("postings block declares " + count
                    + " documents, outside 1.." + MAX_PER_BLOCK);
        }
        long[] ids = new long[count];
        ids[0] = r.u64();
        for (int i = 1; i < count; i++) {
            ids[i] = ids[i - 1] + r.ivar();
        }
        int[] freq = new int[count];
        for (int i = 0; i < count; i++) {
            freq[i] = (int) r.uvar();
        }
        List<Posting> out = new ArrayList<>(count);
        if (!positions) {
            for (int i = 0; i < count; i++) {
                out.add(new Posting(ids[i], freq[i]));
            }
            return out;
        }
        int bytes = r.uvarLength("postings positions area");
        ByteReader pr = new ByteReader(r.bytesView(), r.position(), bytes);
        for (int i = 0; i < count; i++) {
            int[] ps = new int[freq[i]];
            long last = 0;
            for (int j = 0; j < freq[i]; j++) {
                long delta = pr.uvar();
                last = j == 0 ? delta : last + delta;
                ps[j] = (int) last;
            }
            out.add(new Posting(ids[i], freq[i], ps));
        }
        return out;
    }
}
