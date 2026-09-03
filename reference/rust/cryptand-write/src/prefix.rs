//! A durable watermark that advances **only over a contiguous prefix of
//! completed ranges**.
//!
//! `10-transactions.md` §2.3 invariant 2 states this for a value-log segment's
//! `bytes`: "A writer that reserved a range and died leaves a hole; advancing
//! past it publishes garbage as a live record." §8's `visible_seq` is the same
//! rule over sequence numbers — a batch whose seq range is complete is still
//! invisible while an older batch's range is not.

use std::collections::BTreeMap;

/// Completed ranges, keyed by start, merged as they meet.
#[derive(Default, Debug)]
pub struct Watermark {
    at: u64,
    /// Completed ranges strictly above `at`, none of them adjacent to it.
    holes: BTreeMap<u64, u64>,
}

impl Watermark {
    pub fn new(at: u64) -> Watermark {
        Watermark { at, holes: BTreeMap::new() }
    }

    pub fn get(&self) -> u64 {
        self.at
    }

    /// Records `[start, end)` as complete and returns the new watermark.
    /// A range that starts below the watermark is a double completion and is
    /// ignored rather than allowed to move it backwards.
    pub fn complete(&mut self, start: u64, end: u64) -> u64 {
        if end <= self.at {
            return self.at;
        }
        self.holes.insert(start, end.max(*self.holes.get(&start).unwrap_or(&0)));
        while let Some((&s, &e)) = self.holes.iter().next() {
            if s > self.at {
                break; // a hole: some reservation below this one never completed
            }
            self.at = self.at.max(e);
            self.holes.remove(&s);
        }
        self.at
    }

    /// Ranges recorded but not yet reachable — non-zero exactly while a hole
    /// below them is outstanding.
    pub fn pending(&self) -> usize {
        self.holes.len()
    }
}
