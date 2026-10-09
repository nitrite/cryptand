package org.dizitart.cryptand.fuzz;

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.dizitart.cryptand.CryptandException;
import org.dizitart.cryptand.Database;
import org.dizitart.cryptand.TreeDescriptor;
import org.dizitart.cryptand.container.PageHeader;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.crypto.Keyslot;
import org.dizitart.cryptand.geom.Geometry;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.text.Analyzer;
import org.dizitart.cryptand.text.Unicode;
import org.dizitart.cryptand.value.Compare;
import org.dizitart.cryptand.value.Cve;
import org.dizitart.cryptand.value.Value;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * PLAN M3.3: the Rust cargo-fuzz targets, for Java. A {@link CryptandException}
 * is a typed refusal and a pass (14 §9.1); anything else escaping is a crash.
 *
 * <pre>JAZZER_FUZZ=1 mvn test -Djacoco.skip=true -Dtest=JazzerTest#openFile</pre>
 */
class JazzerTest {

    /** The conformance corpus key (`manifest.json`, v1.0-encrypted.cryptand). */
    private static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            KEY[i] = (byte) (i + 1);
        }
    }

    private static final Path TMP = tmp();

    private static Path tmp() {
        try {
            return Files.createTempDirectory("cryptand-jazzer");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** An attacker who edits a page recomputes its CRC (14 §9.4), so the decoders meet the bytes. */
    static void repairCrcs(byte[] b) {
        int ps = 4096;
        try {
            ps = Superblock.decode(Arrays.copyOf(b, 4096)).pageSize();
        } catch (RuntimeException notASuperblock) {
            // keep 4096
        }
        if (ps < 512 || ps > 65536) {
            return;
        }
        for (int p = 2; (long) (p + 1) * ps <= b.length; p++) {
            byte[] page = Arrays.copyOfRange(b, p * ps, (p + 1) * ps);
            try {
                PageHeader.parse(page, 0).writeInto(page);
            } catch (RuntimeException notAPage) {
                continue;
            }
            System.arraycopy(page, 0, b, p * ps, ps);
        }
    }

    private static void exercise(byte[] data, byte[] key) throws IOException {
        byte[] b = data.clone();
        repairCrcs(b);
        Path f = TMP.resolve("fuzz.cryptand");
        Files.write(f, b);
        // Saves the file as the reader sees it, for `conformance/files/fuzz-regress/`.
        String dump = System.getenv("CRYPTAND_FUZZ_DUMP");
        if (dump != null) {
            Files.write(Path.of(dump), b);
        }
        Engine.Options o = new Engine.Options();
        o.readOnly = true;
        o.rawKey = key;
        try (Database db = Database.open(f, o)) {
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
        } catch (CryptandException typed) {
            // a refusal
        }
    }

    @FuzzTest(maxDuration = "2h")
    void openFile(byte[] data) throws IOException {
        exercise(data, null);
    }

    @FuzzTest(maxDuration = "2h")
    void openEncrypted(byte[] data) throws IOException {
        exercise(data, KEY);
    }

    @FuzzTest(maxDuration = "2h")
    void cveDecode(byte[] data) {
        Value v;
        try {
            v = Cve.decode(data);
        } catch (CryptandException typed) {
            return;
        }
        byte[] e = Cve.encode(v);
        assertArrayEquals(e, Cve.encode(Cve.decode(e)), "CVE encode is not stable");
    }

    private static byte[] canon(byte[] b) {
        Value v;
        try {
            v = Cke.decode(b);
        } catch (CryptandException typed) {
            return null;
        }
        byte[] e;
        try {
            e = Cke.encode(v);
        } catch (CryptandException unencodable) {
            return null;
        }
        assertArrayEquals(e, Cke.encode(Cke.decode(e)), "CKE decode∘encode is not the identity");
        return e;
    }

    @FuzzTest(maxDuration = "2h")
    void ckeRoundtrip(byte[] data) {
        int mid = data.length == 0 ? 0 : (data[0] & 0xFF) % data.length;
        byte[] ea = canon(Arrays.copyOfRange(data, 0, mid));
        byte[] eb = canon(Arrays.copyOfRange(data, mid, data.length));
        if (ea == null || eb == null) {
            return;
        }
        int logical;
        try {
            logical = Integer.signum(Compare.compare(Cke.decode(ea), Cke.decode(eb)));
        } catch (CryptandException unordered) {
            return;
        }
        if (logical != 0) {
            assertEquals(logical, Integer.signum(Cke.compare(ea, eb)), "memcmp order disagrees with §8");
        }
    }

    @FuzzTest(maxDuration = "2h")
    void wkb(byte[] data) {
        try {
            Geometry.parse(data);
            Geometry.intersects(data, data);
        } catch (CryptandException typed) {
            // a refusal
        }
    }

    @FuzzTest(maxDuration = "2h")
    void analyzer(byte[] data) {
        String s = new String(data, StandardCharsets.UTF_8);
        String n = Unicode.nfkc(s);
        assertEquals(n, Unicode.nfkc(n), "NFKC is not idempotent");
        String c = Unicode.nfc(s);
        assertEquals(c, Unicode.nfc(c), "NFC is not idempotent");
        Analyzer.standard().analyze(s);
    }

    @FuzzTest(maxDuration = "2h")
    void superblockKeyslot(byte[] data) {
        try {
            Superblock.decode(data);
        } catch (CryptandException typed) {
            // a refusal
        }
        for (int at = 0; at < data.length; at += Keyslot.BYTES) {
            try {
                Keyslot.decode(data, at);
            } catch (CryptandException typed) {
                // a refusal
            }
        }
    }
}
