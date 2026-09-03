//! `14-security.md` §4.1 / `10-transactions.md` §2.3 invariant 3 — the nonce
//! reservation watermark.
//!
//! The rule that matters is the *publish first* half. A session that crashes
//! without publishing leaves the watermark unmoved, and the next session
//! computes the same start and reissues the same nonces; under a stream cipher
//! that discloses both plaintexts and the authentication key, and no checksum
//! or tag catches it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub const GAP: u64 = 1 << 20;

pub struct NonceAllocator {
    next: AtomicU64,
    /// The durably published floor. No allocated value ever reaches it.
    published: AtomicU64,
    publishing: Mutex<()>,
    gap: u64,
}

impl NonceAllocator {
    /// Rule 1: on open, before allocating anything, durably publish
    /// `persisted + gap`. `publish` is the durable write.
    pub fn open(persisted: u64, gap: u64, publish: &mut dyn FnMut(u64)) -> NonceAllocator {
        let floor = persisted + gap;
        publish(floor);
        NonceAllocator {
            next: AtomicU64::new(persisted),
            published: AtomicU64::new(floor),
            publishing: Mutex::new(()),
            gap,
        }
    }

    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Acquire)
    }

    /// Rules 2 and 3: allocate upward from the persisted value, never reaching
    /// the published one; on reaching it, publish `published + gap` and only
    /// then continue.
    ///
    /// The fast path is one `fetch_add`, the same idiom as `next_seq`. A value
    /// drawn at or above the floor is **discarded, not used** — nonces need not
    /// be dense, and handing one out before its floor is durable is the whole
    /// defect this guards.
    pub fn allocate(&self, publish: &mut dyn FnMut(u64)) -> u64 {
        loop {
            let v = self.next.fetch_add(1, Ordering::Relaxed);
            if v < self.published.load(Ordering::Acquire) {
                return v;
            }
            let _held = self.publishing.lock().unwrap();
            let floor = self.published.load(Ordering::Acquire);
            if v >= floor {
                let next_floor = floor + self.gap;
                publish(next_floor);
                self.published.store(next_floor, Ordering::Release);
            }
        }
    }
}
