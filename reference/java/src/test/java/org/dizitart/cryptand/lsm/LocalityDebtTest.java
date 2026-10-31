package org.dizitart.cryptand.lsm;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LocalityDebtTest {
    @Test
    void f209RunsPackedWithWholeRecordsHaveNoDebt() {
        // 22 full clustered runs of three 256 KiB values framed past a quarter
        // of a 1 MiB run: the fewest possible. Dividing by the segment size
        // asked for 17 and read 22.7 %.
        List<VlogStats> runs = new ArrayList<>();
        for (int i = 0; i < 22; i++) {
            VlogStats s = new VlogStats();
            s.tier = VlogSegment.TIER_COLD;
            s.clustered = true;
            s.records = s.liveRecords = 3;
            s.bytes = s.liveBytes = 3 * ((256 << 10) + 64);
            runs.add(s);
        }
        assertEquals(0.0, Vlog.localityDebt(runs, 1 << 20));
    }
}
