package org.dizitart.cryptand;

import org.dizitart.cryptand.container.LockSidecar;
import org.dizitart.cryptand.container.Profile;
import org.dizitart.cryptand.container.Superblock;
import org.dizitart.cryptand.key.Cke;
import org.dizitart.cryptand.lsm.Engine;
import org.dizitart.cryptand.value.Value;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * A process for {@code 13-operations.md} §8 tests, in-language and across
 * languages ({@code reference/conformance/interop/multiproc.py}). No JUnit, so
 * it runs on {@code target/classes:target/test-classes}.
 *
 * <pre>
 *   reader PATH : print the mode; on a line, scan tree 16 and print rows/bad; on a line, exit
 *   writer PATH : create, 5000 rows of 200 x 1, print ready; on a line, churn and print
 *                 the floor; on a line, close
 * </pre>
 */
public final class MultiprocChild {
    static final int TREE = 16;
    static final int ROWS = 5_000;

    static byte[] key(long n) {
        return Cke.encode(Value.i64(n));
    }

    static byte[] doc(int fill) {
        byte[] d = new byte[200];
        Arrays.fill(d, (byte) fill);
        return d;
    }

    static Engine populated(Path db) {
        Engine.Options o = new Engine.Options();
        o.profile = Profile.DESKTOP;
        o.memtableEntries = 1 << 20;
        o.durability = Superblock.Durability.OS;
        Engine e = Engine.create(db, o);
        for (int i = 0; i < ROWS; i++) {
            e.batch().put(TREE, key(i), doc(1)).commit();
        }
        e.commitNow();
        return e;
    }

    /** Overwrite every row, compact and shrink: every extent of an old snapshot is freed. */
    static void churn(Engine e) {
        for (int round = 2; round < 6; round++) {
            for (int i = 0; i < ROWS; i++) {
                e.batch().put(TREE, key(i), doc(round)).commit();
            }
            e.commitNow();
            e.compact();
            e.commitNow();
        }
        e.shrink();
        e.commitNow();
    }

    public static void main(String[] args) throws Exception {
        Path db = Path.of(args[1]);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        if (args[0].equals("writer")) {
            try (Engine e = populated(db)) {
                System.out.println("ready commit=" + e.superblock().commitId);
                System.out.flush();
                in.readLine();
                churn(e);
                System.out.println("churned floor=" + e.superblock().minRetainedCommit);
                System.out.flush();
                in.readLine();
            }
            return;
        }
        Engine.Options o = new Engine.Options();
        o.readOnly = true;
        try (Engine e = Engine.open(db, o)) {
            LockSidecar.Slot s = e.readerSlot();
            System.out.println(s != null
                    ? "mode=slotted index=" + s.index() + " commit=" + s.commitId()
                    : "mode=volatile reason=" + e.volatileReason());
            System.out.flush();
            in.readLine();
            try {
                int rows = 0;
                int bad = 0;
                try (Engine.Cursor c = e.scan(TREE, null, null, false)) {
                    while (c.next()) {
                        rows++;
                        if (!Arrays.equals(doc(1), c.row().value())) {
                            bad++;
                        }
                    }
                }
                System.out.println("rows=" + rows + " bad=" + bad);
            } catch (RuntimeException x) {
                System.out.println("error=" + x);
            }
            System.out.flush();
            in.readLine();
        }
    }
}
