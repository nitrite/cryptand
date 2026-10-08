package org.dizitart.cryptand;

import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Verify;
import org.dizitart.cryptand.value.Value;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * M2.3: disk full. Needs a small volume: {@code tools/enospc.sh} mounts a
 * 200 MB image and sets {@code CRYPTAND_ENOSPC_DIR}; skipped without it.
 */
class EnospcTest {
    private static final int T = TreeId.FIRST_USER_TREE;

    private static byte[] key(long i) {
        return Cke.encode(new Value.NitriteId(i));
    }

    private static byte[] value(long i) {
        byte[] v = Arrays.copyOf(("value-" + i + "-").getBytes(StandardCharsets.UTF_8), i % 5 == 0 ? 9000 : 700);
        Arrays.fill(v, ("value-" + i + "-").length(), v.length, (byte) 'x');
        return v;
    }

    private static Engine.Options opts(boolean encrypted) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.MOBILE;
        o.durability = Superblock.Durability.SYNC;
        if (encrypted) {
            o.encrypt = true;
            o.rawKey = new byte[32];
            Arrays.fill(o.rawKey, (byte) 9);
        }
        return o;
    }

    private static void clean(Engine e, long acked, String what) {
        for (long i = 0; i < acked; i++) {
            byte[] got;
            try {
                got = e.get(T, key(i));
            } catch (RuntimeException x) {
                throw new AssertionError(what + ": acked key " + i + ": " + x, x);
            }
            assertArrayEquals(value(i), got, what + ": acked key " + i + " lost");
        }
        Verify.Report r = Verify.run(e);
        List<Verify.Finding> bad = new ArrayList<>();
        for (Verify.Kind k : Verify.Kind.values()) {
            if (k != Verify.Kind.POLICY) { // advisory, as Rust's warnings
                bad.addAll(r.of(k));
            }
        }
        assertTrue(bad.isEmpty(), what + ": " + r);
    }

    private static void run(Path dir, boolean encrypted) throws Exception {
        Path path = dir.resolve(encrypted ? "java-enc.cff" : "java.cff");
        Path ballast = dir.resolve("java.ballast");
        Files.deleteIfExists(path);
        Files.write(ballast, new byte[100 << 20]); // freed later
        Engine e = Engine.create(path, opts(encrypted));
        long i = 0;
        long acked = 0;
        RuntimeException err = null;
        // Every 50 puts is one durable commit; `acked` counts what it made durable.
        while (err == null) {
            try {
                Engine.Batch b = e.batch();
                for (int j = 0; j < 50; j++) {
                    b.put(T, key(i + j), value(i + j));
                }
                b.commit();
                e.commitNow(true);
                i += 50;
                acked = i;
            } catch (RuntimeException x) {
                err = x;
            }
            assertTrue(i < 10_000_000, "the device never filled");
        }
        if (!(err instanceof UncheckedIOException) && !(err.getCause() instanceof java.io.IOException)) {
            fail("a full device is an I/O error", err);
        }
        System.err.println("java" + (encrypted ? " enc" : "") + ": full after " + acked + " acked: " + err);
        for (int j = 0; j < 20; j++) {
            try {
                e.batch().put(T, key(i + j), value(i + j)).commit();
                e.commitNow(true);
            } catch (RuntimeException expected) {
                // still full: any typed failure, never a hang
            }
        }
        try {
            e.close();
        } catch (RuntimeException expected) {
            // closing publishes, which may not fit
        }
        e = Engine.open(path, opts(encrypted));
        clean(e, acked, "reopened while full");
        try {
            e.close();
        } catch (UncheckedIOException expected) {
            // still full
        }
        Files.delete(ballast);
        e = Engine.open(path, opts(encrypted));
        long base = 1_000_000_000L;
        // Background compaction may still meet a full device for a while
        // (it rewrites beside itself); a commit that fails is not durable and
        // says so, and an application retries. It must succeed in the end.
        for (long j = 0; j < 2000; j++) {
            long deadline = System.nanoTime() + 30_000_000_000L;
            while (true) {
                try {
                    e.batch().put(T, key(base + j), value(j)).commit();
                    break;
                } catch (UncheckedIOException x) {
                    assertTrue(System.nanoTime() < deadline, "work never resumed: " + x);
                    Thread.sleep(200);
                }
            }
        }
        e.commitNow(true);
        // A full compaction rewrites the data beside itself and may still not
        // fit (a fresh value-log segment preallocates its extent); it fails cleanly.
        try {
            e.compact();
        } catch (UncheckedIOException expected) {
            // still a working database; checked below
        }
        clean(e, acked, "resumed");
        e.close();
        e = Engine.open(path, opts(encrypted));
        try {
            clean(e, acked, "resumed, reopened");
            for (long j = 0; j < 2000; j++) {
                assertArrayEquals(value(j), e.get(T, key(base + j)));
            }
        } finally {
            e.close();
        }
        Files.delete(path);
    }

    @Test
    void aFullDeviceFailsCleanlyAndRecovers() throws Exception {
        String dir = System.getenv("CRYPTAND_ENOSPC_DIR");
        assumeTrue(dir != null, "needs tools/enospc.sh");
        run(Path.of(dir), false);
        run(Path.of(dir), true);
    }
}
