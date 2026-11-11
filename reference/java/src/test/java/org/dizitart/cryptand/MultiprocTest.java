package org.dizitart.cryptand;

import org.dizitart.cryptand.container.LockSidecar;
import org.dizitart.cryptand.container.TreeId;
import org.dizitart.cryptand.lsm.Engine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code 13-operations.md} §8, PLAN A1.5: readers in other processes, run as
 * {@link MultiprocChild}.
 */
class MultiprocTest {
    static final int TREE = TreeId.FIRST_USER_TREE;
    static final int ROWS = 5_000;

    static byte[] key(long n) {
        return MultiprocChild.key(n);
    }

    static byte[] doc(int fill) {
        return MultiprocChild.doc(fill);
    }

    static final class Reader implements AutoCloseable {
        final Process p;
        final BufferedReader out;
        final OutputStream in;

        Reader(Path db) throws Exception {
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            p = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    MultiprocChild.class.getName(), "reader", db.toString())
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            out = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
            in = p.getOutputStream();
        }

        String line(String prefix) throws Exception {
            for (String l; (l = out.readLine()) != null; ) {
                if (l.startsWith(prefix)) {
                    return l;
                }
            }
            throw new AssertionError("reader exited before " + prefix);
        }

        void go() throws Exception {
            in.write("go\n".getBytes(StandardCharsets.UTF_8));
            in.flush();
        }

        @Override
        public void close() {
            p.destroyForcibly();
        }
    }

    static Engine populated(Path db) {
        return MultiprocChild.populated(db);
    }

    static void churn(Engine e) {
        MultiprocChild.churn(e);
    }

    @Test
    @DisplayName("a pinned reader process scans its snapshot while the writer reclaims")
    void pinnedReaderScansWhileWriterReclaims(@TempDir Path dir) throws Exception {
        Path db = dir.resolve("pin.cryptand");
        try (Engine e = populated(db); Reader r = new Reader(db)) {
            long pinned = e.superblock().commitId;
            String mode = r.line("mode=");
            assertTrue(mode.startsWith("mode=slotted") && mode.endsWith("commit=" + pinned), mode);
            churn(e);
            assertTrue(e.superblock().minRetainedCommit < pinned, "the live slot must hold the floor");
            r.go();
            assertEquals("rows=" + ROWS + " bad=0", r.line("rows=").trim());
        }
    }

    @Test
    @DisplayName("a killed reader's slot is reclaimed after three heartbeats")
    void killedReaderIsReclaimed(@TempDir Path dir) throws Exception {
        Path db = dir.resolve("kill.cryptand");
        try (Engine e = populated(db)) {
            long pinned = e.superblock().commitId;
            try (Reader r = new Reader(db)) {
                assertTrue(r.line("mode=").startsWith("mode=slotted"));
                r.p.destroyForcibly().waitFor();
            }
            e.batch().put(TREE, key(0), doc(9)).commit();
            e.commitNow();
            assertTrue(e.superblock().minRetainedCommit < pinned, "a fresh dead slot still pins");
            Thread.sleep(LockSidecar.STALE_MULTIPLIER * LockSidecar.DEFAULT_HEARTBEAT_MS + 500);
            e.batch().put(TREE, key(0), doc(8)).commit();
            e.commitNow();
            assertTrue(e.superblock().minRetainedCommit >= pinned, "floor still pinned");
            try (LockSidecar s = LockSidecar.openReader(db, LockSidecar.DEFAULT_HEARTBEAT_MS)) {
                assertTrue(s.slots().stream().allMatch(LockSidecar.Slot::isFree));
            }
        }
    }

    @Test
    @DisplayName("racing reader processes claim distinct slots")
    void racingReadersClaimDistinctSlots(@TempDir Path dir) throws Exception {
        Path db = dir.resolve("race.cryptand");
        List<Reader> readers = new ArrayList<>();
        try (Engine e = populated(db)) {
            for (int i = 0; i < 8; i++) {
                readers.add(new Reader(db));
            }
            Set<String> idx = new HashSet<>();
            for (Reader r : readers) {
                String m = r.line("mode=slotted");
                idx.add(m.split(" ")[1]);
            }
            assertEquals(8, idx.size(), idx.toString());
        } finally {
            readers.forEach(Reader::close);
        }
    }

    @Test
    @DisplayName("two readers in one process keep their own slots")
    void twoReadersInOneProcess(@TempDir Path dir) {
        Path db = dir.resolve("same.cryptand");
        Engine.Options ro = new Engine.Options();
        ro.readOnly = true;
        try (Engine e = populated(db)) {
            Engine a = Engine.open(db, ro);
            e.batch().put(TREE, key(0), doc(9)).commit();
            e.commitNow();
            Engine b = Engine.open(db, ro);
            assertEquals(2, live(db));
            a.close();
            assertEquals(1, live(db));
            assertEquals(e.superblock().commitId, b.readerSlot().commitId());
            b.close();
            assertEquals(0, live(db));
        }
        try (LockSidecar s = LockSidecar.openReader(db, LockSidecar.DEFAULT_HEARTBEAT_MS)) {
            assertEquals(0, s.writerPid(), "closed: no live writer");
        }
    }

    static long live(Path db) {
        try (LockSidecar s = LockSidecar.openReader(db, LockSidecar.DEFAULT_HEARTBEAT_MS)) {
            return s.slots().stream().filter(x -> !x.isFree()).count();
        }
    }

    @Test
    @DisplayName("a full sidecar opens volatile, says why, and revalidates")
    void fullSidecarIsVolatile(@TempDir Path dir) {
        Path db = dir.resolve("full.cryptand");
        Engine.Options ro = new Engine.Options();
        ro.readOnly = true;
        List<Engine> held = new ArrayList<>();
        try (Engine e = populated(db)) {
            for (int i = 0; i < 64; i++) {
                held.add(Engine.open(db, ro));
            }
            try (Engine v = Engine.open(db, ro)) {
                assertNull(v.readerSlot());
                assertEquals(LockSidecar.Volatile.SIDECAR_FULL, v.volatileReason());
                assertNotNull(v.get(TREE, key(1)));
                held.forEach(Engine::close);
                held.clear();
                churn(e);
                assertThrows(LockedException.class, () -> v.get(TREE, key(1)));
            }
        } finally {
            held.forEach(Engine::close);
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    @DisplayName("a read-only sidecar opens volatile and says why")
    void readOnlySidecarIsVolatile(@TempDir Path dir) throws Exception {
        Path db = dir.resolve("ro.cryptand");
        populated(db).close();
        Files.setPosixFilePermissions(LockSidecar.pathFor(db), PosixFilePermissions.fromString("r--------"));
        Engine.Options ro = new Engine.Options();
        ro.readOnly = true;
        try (Engine r = Engine.open(db, ro)) {
            assertEquals(LockSidecar.Volatile.SIDECAR_READ_ONLY, r.volatileReason());
            assertFalse(r.writerAlive());
        }
    }

    @Test
    @DisplayName("a reader with no sidecar creates one with no writer")
    void noSidecarIsCreated(@TempDir Path dir) throws Exception {
        Path db = dir.resolve("none.cryptand");
        populated(db).close();
        Files.delete(LockSidecar.pathFor(db));
        Engine.Options ro = new Engine.Options();
        ro.readOnly = true;
        try (Engine r = Engine.open(db, ro)) {
            assertNotNull(r.readerSlot());
            assertFalse(r.writerAlive());
        }
    }
}
