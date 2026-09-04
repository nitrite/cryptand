//! **P11 — what security costs.** `14-security.md` §12 is stated as
//! predictions rather than measurements; this is the measurement.
//!
//! Run: `cargo run --release --bin p11_encryption [pages]`

#[path = "harness.rs"]
mod harness;
use harness::*;

use std::time::Instant;

use cryptand::container::{feature, Durability, Profile};
use cryptand::engine::Engine;
use cryptand::profile::ProfileConstants;
use cryptand::security::{self, keyslot, make_keyslot, KeyRing};
use cryptand::value::Value;

fn main() {
    let n = arg(0, 20_000);

    // 1. The AEAD's steady-state throughput over page-sized buffers.
    let master = security::random_bytes::<32>();
    let ring = KeyRing::from_master(master, [1u8; 16], 0);
    let header = vec![0u8; 40];
    let page = vec![9u8; 8192 - 40];
    let t0 = Instant::now();
    let mut ct = Vec::new();
    for i in 0..n {
        ct = ring.encrypt_page(i, i, &header, &page).unwrap();
    }
    let enc = t0.elapsed().as_secs_f64();
    let t1 = Instant::now();
    for i in 0..n {
        ring.decrypt_page(n - 1, n - 1, &header, &ct).unwrap();
        let _ = i;
    }
    let dec = t1.elapsed().as_secs_f64();
    let mib = n as f64 * page.len() as f64 / (1024.0 * 1024.0);
    row("XChaCha20-Poly1305 encrypt", format!("{:.0} MiB/s ({:.1} us / 8 KiB page)", mib / enc, enc * 1e6 / n as f64));
    row("XChaCha20-Poly1305 decrypt", format!("{:.0} MiB/s ({:.1} us / 8 KiB page)", mib / dec, dec * 1e6 / n as f64));
    row("tag overhead per page", format!("{:.2} %", 16.0 * 100.0 / 8192.0));
    row("counter + tag per value-log record", "24 B");

    // 2. Argon2id at each profile's cost — the dominant term in opening an
    //    encrypted database, and deliberate. §3.2: an implementation MUST NOT
    //    lower it to feel faster.
    for p in [Profile::Mobile, Profile::Tablet, Profile::Desktop, Profile::Server] {
        let c = ProfileConstants::of(p);
        let t = Instant::now();
        let slot = make_keyslot(
            &master,
            &[1u8; 16],
            0,
            b"correct horse battery staple",
            1,
            c.argon2_t_cost,
            c.argon2_m_cost_kib,
            c.argon2_parallelism,
            "pw",
        )
        .unwrap();
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        let target = match p {
            Profile::Mobile | Profile::Tablet => 250.0,
            _ => 500.0,
        };
        row(
            &format!("Argon2id {} (t={} m={} MiB p={})", p.name(), c.argon2_t_cost, c.argon2_m_cost_kib / 1024, c.argon2_parallelism),
            format!("{ms:.0} ms  (§3.2 target ~{target:.0} ms)"),
        );
        let _ = slot;
    }

    // 3. End to end: the same write load with and without the cipher.
    let mut results = Vec::new();
    for encrypt in [false, true] {
        let b = Bench::new(if encrypt { "p11-on" } else { "p11-off" });
        let mut e = Engine::create(&b.path, Profile::Desktop).unwrap();
        if encrypt {
            let slot =
                make_keyslot(&master, &e.sb.database_uuid, 0, &[7u8; 32], 0, 0, 0, 0, "host").unwrap();
            e.sb.keyslots[..keyslot::SIZE].copy_from_slice(&slot.encode());
            e.sb.cipher = 1;
            e.sb.set_feature(feature::CIPHER, true);
            e.keys = Some(KeyRing::from_master(master, e.sb.database_uuid, 0));
            e.commit(Durability::Sync).unwrap();
        }
        let value = vec![3u8; 700];
        let t = Instant::now();
        for i in 0..(n as i64 / 4) {
            e.put(16, &Value::NitriteId(i), &value).unwrap();
        }
        e.flush().unwrap();
        e.commit(Durability::Sync).unwrap();
        let secs = t.elapsed().as_secs_f64();
        let bytes = e.pager.bytes_written_device;
        results.push((secs, bytes));
        row(
            &format!("write {} separated values, cipher {}", n / 4, if encrypt { "on " } else { "off" }),
            format!("{:.2} s  {:.1} MiB to device", secs, bytes as f64 / (1024.0 * 1024.0)),
        );
    }
    row("cipher cost on the write path", format!("{:.2}x", results[1].0 / results[0].0));
    println!(
        "\n§12: \"on any device whose storage is slower than 1-3 GB/s per core -- every phone,\n\
         every SATA SSD -- encryption is not the bottleneck. On fast NVMe it becomes measurable.\""
    );
}
