//! `11-conformance.md` §6's foreground-stall test, in a test binary of its own.
//!
//! It is a **wall-clock** test — "no single foreground operation may exceed
//! `max_foreground_stall_ms`" — so it measures the machine as well as the
//! engine. Cargo runs test binaries one at a time, and this file holds one
//! test, so the measurement is not competing with the rest of the suite for
//! cores. That is a property of the harness, not a weakening of the bound.

mod support;
use support::*;

use cryptand::container::Profile;
use cryptand::value::Value;

const T: u32 = 16;

// ---------------------------------------------------------------------------
// "A foreground-stall test is mandatory for mobile and tablet."
// ---------------------------------------------------------------------------

#[test]
fn no_foreground_operation_exceeds_the_mobile_stall_budget() {
    let (_t, mut e) = engine("stall", Profile::Mobile);
    e.memtable_entry_limit = 200;
    let budget = e.profile.max_foreground_stall_ms as u128;
    assert_eq!(budget, 8, "mobile's budget is half a 60 Hz frame");
    // Warm the segment-builder path: a cold first flush is compile and cache
    // cost, not the property under test.
    for i in 0..600i64 {
        e.put(T, &Value::NitriteId(1_000_000 + i), b"warm").unwrap();
        if e.memtable_pressure().0 >= 200 {
            e.flush().unwrap();
            e.maybe_compact(None).unwrap();
        }
    }
    let mut worst = 0u128;
    let mut violations = 0;
    for i in 0..4000i64 {
        let t0 = std::time::Instant::now();
        e.put(T, &Value::NitriteId(i), b"x").unwrap();
        if e.memtable_pressure().0 >= 200 {
            e.flush().unwrap();
            // §5.2's bounded, interruptible step -- the whole point.
            e.maybe_compact(None).unwrap();
        }
        let ms = t0.elapsed().as_millis();
        worst = worst.max(ms);
        if ms > budget {
            violations += 1;
        }
    }
    println!("foreground stall: worst {worst} ms, budget {budget} ms, {violations} violations");
    assert_eq!(violations, 0, "worst foreground operation was {worst} ms against an {budget} ms budget");
}

