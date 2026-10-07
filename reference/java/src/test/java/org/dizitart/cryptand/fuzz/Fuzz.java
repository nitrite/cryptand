package org.dizitart.cryptand.fuzz;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.ToIntFunction;

import org.dizitart.cryptand.CorruptionException;
import org.dizitart.cryptand.CryptandException;
import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.lsm.VlogSegment;
import org.dizitart.cryptand.util.Crc32c;

/**
 * {@code spec/14-security.md} §9.3 — structure-aware fuzzing of the reader.
 *
 * <p>"A parser for a format read from untrusted sources that has never been
 * fuzzed is not finished." The rule names {@code cryptand fuzz} for the
 * reference implementation "<strong>and an equivalent for each SDK</strong>",
 * so this is Java's.
 *
 * <p>Two things about it are not obvious and are the reason it finds anything:
 *
 * <ul>
 *   <li><strong>Structure-aware.</strong> Most of a database's bytes are unused
 *       value-log record space and page tail padding, so uniform bit flips land
 *       where no decoder ever looks. The targets here are the fields a hostile
 *       file would actually edit: the two superblock slots, every page header,
 *       and the head of every payload behind one.
 *   <li><strong>The checksum is repaired after the mutation.</strong> A fuzzer
 *       that mutates a checksummed page and leaves the checksum alone measures
 *       CRC-32C and nothing else — every payload mutation dies at the gate of
 *       {@code 01-container.md} §3 before a decoder sees a byte. §9.4 is the
 *       same point from the other side: a CRC "is trivially recomputed by
 *       anyone who edits the file", so an attacker's file always has a valid
 *       one.
 * </ul>
 *
 * <p>The oracle is {@link CryptandException}. Every failure this library raises
 * is one, so anything else reaching the caller — an {@code
 * ArrayIndexOutOfBoundsException}, a {@code NegativeArraySizeException}, an
 * {@code OutOfMemoryError}, a {@code StackOverflowError} — is a §9.1 violation:
 * "MUST fail with a typed corruption error rather than an allocation failure, a
 * panic, an abort, or an unbounded recursion."
 */
public final class Fuzz {

    private Fuzz() {
    }

    /** What one mutant did to the reader. */
    public enum Outcome {
        /** Refused with a typed {@link CryptandException}. The good case. */
        REFUSED,
        /** Opened, and the verifier named a finding. Also good. */
        REPORTED,
        /**
         * Accepted with nothing reported. Not a failure: an unencrypted file has
         * no tamper detection at all (§9.4), and a mutation in a reserved byte
         * or an unread field changes nothing a reader may act on.
         */
        BENIGN,
        /** Threw something outside {@link CryptandException}. A §9.1 violation. */
        UNTYPED
    }

    /** A byte range a hostile file would plausibly edit. */
    public static final class Target {
        private final int offset;
        private final int length;
        private final String what;

        public Target(int offset, int length, String what) {
            this.offset = offset;
            this.length = length;
            this.what = what;
        }

        public int offset() {
            return offset;
        }

        public int length() {
            return length;
        }

        public String what() {
            return what;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Target)) {
                return false;
            }
            Target that = (Target) o;
            return offset == that.offset
                    && length == that.length
                    && java.util.Objects.equals(what, that.what);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(offset, length, what);
        }

        @Override
        public String toString() {
            return "Target[" + "offset=" + offset + ", " + "length=" + length + ", " + "what=" + what + "]";
        }
    }

    public static final class Finding {
        private final Outcome outcome;
        private final String detail;
        private final byte[] mutant;

        public Finding(Outcome outcome, String detail, byte[] mutant) {
            this.outcome = outcome;
            this.detail = detail;
            this.mutant = mutant;
        }

        public Outcome outcome() {
            return outcome;
        }

        public String detail() {
            return detail;
        }

        public byte[] mutant() {
            return mutant;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Finding)) {
                return false;
            }
            Finding that = (Finding) o;
            return java.util.Objects.equals(outcome, that.outcome)
                    && java.util.Objects.equals(detail, that.detail)
                    && java.util.Objects.equals(mutant, that.mutant);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(outcome, detail, mutant);
        }

        @Override
        public String toString() {
            return outcome + ": " + detail;
        }
    }

    /** The result of a run. */
    public static final class Report {
        public int refused;
        public int reported;
        public int benign;
        public final List<Finding> failures = new ArrayList<>();

        public int iterations() {
            return refused + reported + benign + failures.size();
        }

        /** §9.3 passes only if nothing escaped the typed-error contract. */
        public boolean clean() {
            return failures.isEmpty();
        }

        /**
         * A run in which nothing reached a decoder has measured nothing. If
         * almost every mutant is refused at the container gate, the targets are
         * wrong — the same "control that cannot fail" this project has met
         * repeatedly.
         */
        public int reachedReader() {
            return reported + benign;
        }

        @Override
        public String toString() {
            return "fuzz: " + iterations() + " mutants, " + refused + " refused, "
                    + reported + " reported, " + benign + " benign, "
                    + failures.size() + " UNTYPED";
        }
    }

    /**
     * xorshift64. Deterministic on purpose: a fuzz failure that cannot be
     * replayed from its seed is a bug report nobody can act on.
     */
    public static final class Rng {
        private long s;

        public Rng(long seed) {
            this.s = seed == 0 ? 0x243F6A8885A308D3L : seed;
        }

        public long next() {
            s ^= s << 13;
            s ^= s >>> 7;
            s ^= s << 17;
            return s;
        }

        public int below(int n) {
            return n <= 0 ? 0 : (int) Long.remainderUnsigned(next(), n);
        }
    }

    /**
     * The end of the checksummed range for a page, which is the whole page
     * except on a value-log segment's head: its records begin at {@code
     * data_offset}, <em>inside</em> the head page, so a checksum over the whole
     * page would be stale from the first append onward.
     *
     * <p>A repair that gets this wrong writes a checksum that is invalid the
     * moment it is written, and the mutation is then "caught" by the repair
     * rather than by the reader — a fuzzer that silently measures itself.
     */
    static int checksumEnd(byte[] image, int offset, int pageSize) {
        int type = image[offset + 4] & 0xFF;
        if (type != PageHeader.Type.VLOG_SEGMENT) {
            return pageSize;
        }
        int at = offset + PageHeader.BYTES + 32;
        if (at + 4 > image.length) {
            return pageSize;
        }
        long off = (image[at] & 0xFFL)
                | ((image[at + 1] & 0xFFL) << 8)
                | ((image[at + 2] & 0xFFL) << 16)
                | ((image[at + 3] & 0xFFL) << 24);
        return off > PageHeader.BYTES && off <= pageSize ? (int) off : pageSize;
    }

    /**
     * Derives the target list from {@code image}: the two superblock slots, then
     * every page carrying a header ({@code 01-container.md} §3) plus the head of
     * its payload.
     *
     * <p>Interior pages of a multi-page extent carry no header, and §3 says a
     * verifier "MUST NOT report a missing page header on them as corruption" —
     * so a page whose header does not parse is skipped rather than targeted.
     */
    public static List<Target> targets(byte[] image, int pageSize) {
        List<Target> t = new ArrayList<>();
        t.add(new Target(0, 4096, "superblock slot A"));
        if (image.length >= pageSize + 4096) {
            t.add(new Target(pageSize, 4096, "superblock slot B"));
        }
        int pages = image.length / pageSize;
        for (int p = 2; p < pages; p++) {
            int off = p * pageSize;
            byte[] page = new byte[pageSize];
            System.arraycopy(image, off, page, 0, pageSize);
            PageHeader h;
            try {
                h = PageHeader.verify(page, p, checksumEnd(image, off, pageSize));
            } catch (CryptandException e) {
                continue;
            }
            if (h.pageType == PageHeader.Type.FREE || h.payloadLen == 0) {
                continue;
            }
            t.add(new Target(off, PageHeader.BYTES, "page " + p + " header"));
            int n = Math.min(h.payloadLen, 256);
            if (off + PageHeader.BYTES + n <= image.length) {
                t.add(new Target(off + PageHeader.BYTES, n, "page " + p + " payload head"));
            }
        }
        return t;
    }

    /**
     * Applies one mutation set to a copy of {@code image} and repairs the
     * checksum of every page it touched.
     *
     * <p>The mutations are the four an editor of a hostile file actually makes:
     * a bit flip, a byte to {@code 0x00}, a byte to {@code 0xFF}, and a run of
     * {@code 0xFF} — the last because a length field only becomes an allocation
     * bomb when <em>all</em> its bytes are set, and one flipped bit almost never
     * does that.
     */
    public static byte[] mutate(byte[] image, List<Target> targets, Rng rng, int pageSize) {
        byte[] b = image.clone();
        Set<Integer> touched = new LinkedHashSet<>();
        int n = 1 + rng.below(4);
        for (int i = 0; i < n; i++) {
            Target t = targets.get(rng.below(targets.size()));
            int at = t.offset() + rng.below(Math.max(t.length(), 1));
            if (at >= b.length) {
                continue;
            }
            switch (rng.below(4)) {
                case 0: b[at] ^= (byte) (1 << rng.below(8)); break;
                case 1: b[at] = 0x00; break;
                case 2: b[at] = (byte) 0xFF; break;
                default: {
                    int w = 1 + rng.below(8);
                    for (int k = 0; k < w && at + k < b.length; k++) {
                        b[at + k] = (byte) 0xFF;
                    }
                }
                    break;
            }
            touched.add(at / pageSize);
        }
        // §3: `checksum` is CRC-32C over bytes 4..checksumEnd-1 as stored. The
        // superblock slots (pages 0 and 1) have their own rule and are left
        // alone; a mutation there is meant to be caught, and is.
        for (int p : touched) {
            if (p < 2) {
                continue;
            }
            int off = p * pageSize;
            if (off + pageSize > b.length) {
                continue;
            }
            int end = checksumEnd(b, off, pageSize);
            int c = Crc32c.of(b, off + 4, end - 4);
            b[off] = (byte) c;
            b[off + 1] = (byte) (c >>> 8);
            b[off + 2] = (byte) (c >>> 16);
            b[off + 3] = (byte) (c >>> 24);
        }
        return b;
    }

    /**
     * Runs {@code read} against {@code iterations} mutants of {@code image} and
     * classifies each.
     *
     * <p>{@code read} MUST open the mutant, verify it, and read every document
     * in it — <strong>all three</strong>. Verification alone is not enough: it
     * walks structure and checksums, and the decoders that turn bytes into
     * values (CVE, CKE, the value-log record, an index entry) only run when
     * something reads. It returns the number of findings its verifier named, or
     * throws.
     */
    public static Report run(byte[] image, int pageSize, int iterations, long seed,
            ToIntFunction<byte[]> read) {
        List<Target> targets = targets(image, pageSize);
        if (targets.size() <= 2) {
            throw new InvalidArgumentException(
                    "the image holds no headed pages to fuzz; the fixture has too little "
                            + "structure for this to measure anything");
        }
        Rng rng = new Rng(seed);
        Report report = new Report();
        for (int i = 0; i < iterations; i++) {
            byte[] mutant = mutate(image, targets, rng, pageSize);
            try {
                int findings = read.applyAsInt(mutant);
                if (findings == 0) {
                    report.benign++;
                } else {
                    report.reported++;
                }
            } catch (CryptandException e) {
                report.refused++;
            } catch (Throwable e) {
                // §9.1: anything outside the sealed hierarchy is the violation.
                // `Throwable`, not `Exception`: `OutOfMemoryError` and
                // `StackOverflowError` are exactly the two failures §9.1 names
                // by name, and both are `Error`s.
                StackTraceElement[] st = e.getStackTrace();
                StringBuilder sb = new StringBuilder(e.getClass().getName() + ": " + e.getMessage());
                for (int k = 0; k < Math.min(st.length, 6); k++) {
                    sb.append("\n    at ").append(st[k]);
                }
                report.failures.add(new Finding(Outcome.UNTYPED, sb.toString(), mutant));
            }
        }
        return report;
    }

    /** Unused import guard: {@link VlogSegment#DATA_OFFSET} documents the constant above. */
    static final int VLOG_DATA_OFFSET = VlogSegment.DATA_OFFSET;

    static {
        if (VLOG_DATA_OFFSET != PageHeader.BYTES + 64) {
            throw new CorruptionException("VlogSegment.DATA_OFFSET moved; checksumEnd assumes it");
        }
    }
}
