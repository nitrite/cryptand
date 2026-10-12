package org.dizitart.cryptand;

import org.dizitart.cryptand.container.LockSidecar;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.ops.Backup;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** PLAN 4.7: created files are owner-only; the lock sidecar never follows a symlink. */
@DisabledOnOs(OS.WINDOWS)
class FsPermsTest {
    @TempDir Path dir;

    private static Engine.Options options() {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        return o;
    }

    private static String mode(Path p) throws Exception {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    @Test
    void createdFilesAreOwnerOnly() throws Exception {
        Path db = dir.resolve("p.cryptand");
        Engine.create(db, options()).close();
        assertEquals("rw-------", mode(db));

        LockSidecar.of(db).close();
        assertEquals("rw-------", mode(db.resolveSibling("p.cryptand-lock")));

        // Files.copy keeps the source's mode; restore must not.
        Files.setPosixFilePermissions(db, PosixFilePermissions.fromString("rw-r--r--"));
        Path dst = dir.resolve("r.cryptand");
        Backup.restore(db, dst, options());
        assertEquals("rw-------", mode(dst));
    }

    @Test
    void sidecarRefusesASymlink() throws Exception {
        Path victim = dir.resolve("victim");
        Files.write(victim, new byte[] {'k'});
        Path db = dir.resolve("l.cryptand");
        Files.createSymbolicLink(db.resolveSibling("l.cryptand-lock"), victim);
        assertThrows(java.io.UncheckedIOException.class, () -> LockSidecar.of(db));
        assertArrayEquals(new byte[] {'k'}, Files.readAllBytes(victim));
    }
}
