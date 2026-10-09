package org.dizitart.cryptand;

import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.util.Crc32c;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code spec/14-security.md} §9.1 — a decoder fed a hostile file MUST fail
 * with a typed corruption error "rather than an allocation failure, a panic, an
 * abort, or an unbounded recursion".
 *
 * <p>§9.3 requires structure-aware fuzzing and {@link FuzzTest} provides it.
 * What random mutation cannot do is <em>reliably</em> reach one named 4-byte
 * field: the segment filter's {@code block_count} is a specific u32 at a
 * specific offset, and 3 000 random mutations over this corpus find it perhaps
 * one time in six. Bugs of that class live at the <em>boundaries</em> of a
 * named field, and boundaries are enumerable — so this sweep is deterministic
 * and exhaustive where the fuzzer is random.
 *
 * <p>For one page of every {@code page_type} in the shared corpus, every
 * u32-aligned slot in the 40-byte header and in the first 32 bytes of payload
 * is set to each of six boundary values, the page checksum is repaired (§9.4:
 * an attacker recomputes it trivially, so leaving it broken would test the CRC
 * and not the decoder), and the file is opened, verified, scanned <b>and
 * point-read</b>.
 *
 * <p>The point read is not decoration. A scan and a {@code get} are different
 * decoders, and only {@code get} consults {@code 04-segments.md} §2.4's filter,
 * so a harness that only scans cannot reach the filter header at all.
 */
class HostileTest {

    private static final int[] BOUNDARIES = {
            0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF
    };

    private static Path corpusFile() {
        return Paths.get(System.getProperty("user.dir"))
                .getParent()
                .resolve("conformance")
                .resolve("files")
                .resolve("v1.0-core.cryptand");
    }

    /**
     * Opens, verifies, scans and point-reads — the four decoders a hostile file
     * reaches. A {@link CryptandException} is a typed refusal and a pass;
     * anything else escaping is what this test exists to find.
     */
    private static void exercise(Path path) {
        Engine.Options o = new Engine.Options();
        o.readOnly = true;
        try (Database db = Database.open(path, o)) {
            Verify.run(db.engine());
            for (Map.Entry<String, TreeDescriptor> e : db.catalog().entrySet()) {
                int tree = e.getValue().treeId();
                int seen = 0;
                try (Engine.Cursor c = db.engine().scan(tree, null, null, false)) {
                    while (c.next() && seen++ < 8) {
                        db.engine().get(tree, c.row().key());
                    }
                }
            }
        }
    }

    /** F-106 (M3 Jazzer superblockKeyslot): a short keyslot is a typed error, not an index error. */
    @Test
    void aShortKeyslotIsATypedError() {
        org.junit.jupiter.api.Assertions.assertThrows(CryptandException.class,
                () -> org.dizitart.cryptand.crypto.Keyslot.decode(new byte[150], 100));
    }

    /** PLAN M3.5: every minimized fuzz file (page CRCs repaired) is a typed refusal or a clean read. */
    @Test
    void everyFuzzRegressFileIsRefusedOrRead(@org.junit.jupiter.api.io.TempDir Path tmp) throws IOException {
        Path dir = corpusFile().getParent().resolve("fuzz-regress");
        int n = 0;
        try (java.util.stream.Stream<Path> files = Files.list(dir)) {
            for (Path f : (Iterable<Path>) files::iterator) {
                Path copy = Files.copy(f, tmp.resolve(f.getFileName()));
                try {
                    exercise(copy);
                } catch (CryptandException typed) {
                    // a named, typed refusal
                }
                n++;
            }
        }
        assertTrue(n > 0, "the fuzz-regress corpus is empty");
    }

    @Test
    @DisplayName("every u32 field at every boundary yields a typed error and never a crash")
    void fieldBoundarySweep() throws IOException {
        Path corpus = corpusFile();
        if (!Files.exists(corpus)) {
            fail(corpus + " is missing; generate it with "
                    + "`dart run tool/generate_corpus.dart` in reference/dart/cryptand");
        }
        byte[] original = Files.readAllBytes(corpus);
        Superblock sb = Superblock.decode(java.util.Arrays.copyOf(original, 4096));
        int pageSize = sb.pageSize();
        int pages = original.length / pageSize;

        // One page of each page_type present. The decoder is per type, not per
        // page, so a second page of the same type re-tests the same code.
        Map<Integer, Integer> byType = new TreeMap<>();
        for (int p = 2; p < pages; p++) {
            try {
                PageHeader h = PageHeader.parse(original, p * pageSize);
                if (h.pageType == PageHeader.Type.FREE) {
                    continue;
                }
                byType.putIfAbsent(h.pageType, p);
            } catch (RuntimeException ignored) {
                // Not a headed page.
            }
        }
        assertTrue(byType.size() >= 4,
                "the corpus should cover several page types, saw " + byType.keySet());

        Path tmp = Files.createTempFile("cryptand-sweep", ".cryptand");
        int cases = 0;
        int refused = 0;
        int accepted = 0;

        for (Map.Entry<Integer, Integer> e : byType.entrySet()) {
            int page = e.getValue();
            for (int slot = 0; slot < PageHeader.BYTES + 32; slot += 4) {
                for (int value : BOUNDARIES) {
                    byte[] b = original.clone();
                    int at = page * pageSize + slot;
                    if (at + 4 > b.length) {
                        continue;
                    }
                    ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(at, value);

                    // Repair the checksum, so the decoder is what refuses.
                    int off = page * pageSize;
                    int end = checksumEnd(b, off, pageSize);
                    ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
                            .putInt(off, Crc32c.of(b, off + 4, end - off - 4));
                    Files.write(tmp, b);

                    cases++;
                    try {
                        exercise(tmp);
                        accepted++;
                    } catch (CryptandException ok) {
                        // A named, typed refusal. This is the contract.
                        refused++;
                    } catch (OutOfMemoryError | StackOverflowError fatal) {
                        throw new AssertionError("page_type " + e.getKey()
                                + ": setting the u32 at offset " + slot + " to "
                                + Integer.toHexString(value) + " produced "
                                + fatal.getClass().getSimpleName()
                                + ". §9.1 requires a typed corruption error.", fatal);
                    }
                    // Any other RuntimeException escapes and fails the test,
                    // which is §9.1's requirement.
                }
            }
        }
        Files.deleteIfExists(tmp);

        System.out.printf("field-boundary sweep: %d cases over %d page types — "
                + "%d refused with a named error, %d read cleanly, 0 uncaught%n",
                cases, byType.size(), refused, accepted);
        assertTrue(cases > 200, "the sweep did not run: " + cases + " cases");
        // A control: if nothing was ever refused the sweep reaches no decoder
        // and would pass against a reader that validates nothing.
        assertTrue(refused > 0, "no mutation was refused — the sweep reaches no decoder");
    }

    /** The checksum scope of the page at {@code off}; a value-log head page
     *  checksums only {@code 4 … data_offset}. */
    private static int checksumEnd(byte[] b, int off, int pageSize) {
        try {
            PageHeader h = PageHeader.parse(b, off);
            if (h.pageType == PageHeader.Type.VLOG_SEGMENT) {
                int dataOffset = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
                        .getInt(off + PageHeader.BYTES + 32);
                if (dataOffset > PageHeader.BYTES && dataOffset <= pageSize) {
                    return off + dataOffset;
                }
            }
        } catch (RuntimeException ignored) {
            // Fall through to the whole page.
        }
        return off + pageSize;
    }
}
