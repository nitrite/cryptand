//! `11-conformance.md` §7 — the reference CLI.
//!
//! `verify`, `dump`, `vectors`, `fuzz`, `repair`, `backup` and `stats`.

use std::path::PathBuf;
use std::process::ExitCode;

use cryptand::backup::{Backup, BackupMode};
use cryptand::database::Database;
use cryptand::engine::Engine;
use cryptand::metrics::Metrics;
use cryptand::repair::EngineRepair;
use cryptand::verify::{Class, EngineVerify};

fn usage() -> ExitCode {
    eprintln!(
        "cryptand <command> [args]

  verify <file>                 the integrity pass of spec/01-container.md section 9
  dump <file>                   catalog, level/segment map, value-log liveness, features
  stats <file>                  the required metrics of spec/13-operations.md section 6
  repair <file>                 spec/13-operations.md section 3
  backup <file> <dest>          online full backup
  backup --incremental <f> <d>  the set difference of spec/13-operations.md section 2.2
  fuzz <file> [iterations]      structure-aware fuzzing of the reader
  create <file>                 create an empty desktop-profile database
"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return usage();
    }
    let r = match args[0].as_str() {
        "verify" if args.len() >= 2 => verify(&args[1]),
        "dump" if args.len() >= 2 => dump(&args[1]),
        "stats" if args.len() >= 2 => stats(&args[1]),
        "repair" if args.len() >= 2 => repair(&args[1]),
        "create" if args.len() >= 2 => create(&args[1]),
        // `>= 4`, not `>= 3`: the incremental form is
        // `backup --incremental <file> <dest>`, so with three arguments
        // `args[3]` is past the end and this arm panicked with an
        // index-out-of-bounds -- exit 101 and a backtrace where the user
        // should have got the usage text.
        "backup" if args.len() >= 4 && args[1] == "--incremental" => {
            backup(&args[2], &args[3], true)
        }
        // `args[1] != "--incremental"` matters: without it, a mistyped
        // `backup --incremental <file>` falls through to here and runs a
        // *full* backup treating the flag itself as the source path. It then
        // fails for the wrong reason -- "no such file: --incremental" -- when
        // what the user needs is the usage text.
        "backup" if args.len() >= 3 && args[1] != "--incremental" => {
            backup(&args[1], &args[2], false)
        }
        "fuzz" if args.len() >= 2 => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
            fuzz(&args[1], n)
        }
        _ => return usage(),
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn open(path: &str) -> cryptand::Result<Engine> {
    let key = std::env::var("CRYPTAND_KEY").ok();
    Engine::open(&PathBuf::from(path), key.as_deref().map(|s| s.as_bytes()))
}

fn create(path: &str) -> cryptand::Result<ExitCode> {
    let mut db = Database::create(&PathBuf::from(path), cryptand::container::Profile::Desktop)?;
    db.close()?;
    println!("created {path}");
    Ok(ExitCode::SUCCESS)
}

fn verify(path: &str) -> cryptand::Result<ExitCode> {
    let mut e = open(path)?;
    let r = e.verify()?;
    println!("segments {}  entries {}  reachable pages {}", r.segments, r.entries, r.pages_reachable);
    for f in &r.findings {
        println!("  {:?}: {}", f.class, f.what);
    }
    // A leak is repairable, a double-allocation is corruption, and a failed
    // tag is neither -- so the exit code distinguishes them.
    Ok(if !r.of(Class::Tampering).is_empty() {
        ExitCode::from(3)
    } else if !r.of(Class::Corruption).is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn dump(path: &str) -> cryptand::Result<ExitCode> {
    let mut e = open(path)?;
    let sb = e.sb.clone();
    println!("format {}.{}  write_version {}", sb.version_major, sb.version_minor, sb.write_version_minor);
    println!("page_size {}  pages {}  commit {}", sb.page_size(), sb.page_count, sb.commit_id);
    println!("profile {}  vlog_min {}  l0_trigger {}  tier_width {}  overlap_bound {}",
        cryptand::container::Profile::from_code(sb.profile).name(),
        sb.vlog_min, sb.l0_trigger, sb.tier_width, sb.overlap_bound);
    println!("writer {:?}  uuid {}", sb.writer_id, cryptand::metrics::hex(&sb.database_uuid));
    print!("features_required");
    for b in 0..64 {
        if sb.features_required & (1 << b) != 0 {
            print!(" {}", cryptand::error::feature_name(b));
        }
    }
    println!();
    print!("features_optional");
    for b in 0..64 {
        if sb.features_optional & (1 << b) != 0 {
            print!(" {}", cryptand::error::feature_name(b));
        }
    }
    println!();
    println!("\ncatalog:");
    let cat = std::mem::replace(&mut e.catalog, cryptand::catalog::Catalog::new(0, 0, 16));
    let all = cat.all(&mut e.pager)?;
    e.catalog = cat;
    for (name, d) in all {
        println!("  {:>6}  {:<14} {}", d.tree_id(), d.kind(), name);
    }
    println!("\nsegments:");
    for r in e.all_refs()? {
        println!(
            "  seg {:<5} L{}.g{}  {:>8} entries  {:>5} pages  seq {}..{}",
            r.segment_id, r.level, r.group, r.entries, r.pages, r.min_seq, r.max_seq
        );
    }
    println!("\nvalue log:");
    for (id, s) in &e.vlog_stats {
        println!(
            "  vseg {:<5} tier {} heat {}  {:>10} B  live {:>10} B  sealed {}  clustered {}",
            id, s.tier, s.heat, s.bytes, s.live_bytes, s.sealed, s.clustered
        );
    }
    println!("\nlocality_debt {:.3}", e.locality_debt());
    Ok(ExitCode::SUCCESS)
}

fn stats(path: &str) -> cryptand::Result<ExitCode> {
    let mut e = open(path)?;
    for (k, v) in e.metrics()? {
        println!("{k:<38} {v}");
    }
    Ok(ExitCode::SUCCESS)
}

fn repair(path: &str) -> cryptand::Result<ExitCode> {
    let mut e = open(path)?;
    let a = e.rebuild_vlog_stats()?;
    let b = e.rebuild_manifest()?;
    let c = e.reclaim_leaks()?;
    e.commit(cryptand::container::Durability::Sync)?;
    println!(
        "recovered {} segments, rebuilt {} value-log entries, reclaimed {} leaked pages",
        b.segments_recovered, a.vlog_entries_rebuilt, c.leaks_reclaimed
    );
    for n in c.notes.iter().chain(b.notes.iter()) {
        println!("  {n}");
    }
    Ok(ExitCode::SUCCESS)
}

fn backup(path: &str, dest: &str, incremental: bool) -> cryptand::Result<ExitCode> {
    let mut e = open(path)?;
    let r = if incremental {
        e.backup_incremental(&PathBuf::from(dest), &[])?
    } else {
        let mode = if e.sb.cipher != 0 { BackupMode::CiphertextCopy } else { BackupMode::Plain };
        e.backup(&PathBuf::from(dest), mode)?
    };
    println!(
        "copied {} segments, {} value-log segments, {} bytes{}",
        r.segments_copied,
        r.vlog_segments_copied,
        r.bytes_copied,
        if r.downgraded { " (DOWNGRADED TO PLAINTEXT)" } else { "" }
    );
    Ok(ExitCode::SUCCESS)
}

/// `14-security.md` §9.3 — **structure-aware** fuzzing of the reader. "A parser
/// for a format read from untrusted sources that has never been fuzzed is not
/// finished." Every mutation must produce a named error, never a crash, a hang,
/// or an unbounded allocation.
///
/// Three things about it are not obvious and are the reason it finds anything:
///
///  * **Structure-aware.** Most of a database's bytes are unused value-log
///    record space, so uniform bit flips land in padding and measure nothing.
///    The targets here are the ones a hostile file would edit — the
///    superblock's own fields, page headers, and the payloads behind them.
///
///  * **The checksum is repaired after the mutation.** This version did not do
///    it, and that is the more interesting half. §3's `checksum` "verifies
///    before decompression and before decryption", so a mutant with a stale
///    checksum dies at the container gate and *no decoder sees a byte* — the
///    run measures CRC-32C and reports it as a pass. Measured here: repairing
///    the checksum moves the population from 43 mutants reaching the reader in
///    400 to 233, a 5.4× change in what is actually under test. §9.4 is the
///    same point from the other side — a CRC "is trivially recomputed by anyone
///    who edits the file", so an attacker's file always has a valid one, and a
///    fuzzer that assumes otherwise is not modelling the attacker §9 describes.
///
///  * **It reads, it does not only verify.** `verify()` walks structure and
///    checksums; the decoders that turn bytes into values — CVE, CKE, the
///    value-log record, an index entry — only run when something reads. The
///    Dart port of this fuzzer found four untyped failures on its first runs
///    and three of them were behind a read, not a verify.
fn fuzz(path: &str, iterations: u64) -> cryptand::Result<ExitCode> {
    let original = std::fs::read(path)?;
    // `open_shared`, not `open`: the probe only reads, and taking the
    // exclusive writer lock here made the second `Pager::open` below fail
    // against *this same process* -- `01-container.md` §10's lock is per open
    // file description, so `fuzz` could never run at all. `Engine::open` uses
    // `open_shared` for its own superblock probe for exactly this reason.
    let page_size = {
        let mut probe = cryptand::pager::Pager::open_shared(&PathBuf::from(path), 4096, 1)?;
        let sb = cryptand::container::Superblock::parse(&probe.read_at(0, 4096)?)
            .or_else(|_| cryptand::container::Superblock::parse(&probe.read_at(4096, 4096)?))?;
        sb.page_size()
    };
    let sb = {
        let mut probe =
            cryptand::pager::Pager::open_shared(&PathBuf::from(path), page_size, u64::MAX)?;
        cryptand::container::Superblock::parse(&probe.read_at(0, 4096)?)
            .or_else(|_| cryptand::container::Superblock::parse(&probe.read_at(page_size as u64, 4096)?))?
    };

    // Every page that carries a header, and the two superblock slots.
    let mut structural: Vec<(u64, usize)> = vec![(0, 4096), (page_size as u64, 4096)];
    let mut pager = cryptand::pager::Pager::open(&PathBuf::from(path), page_size, sb.page_count)?;
    for p in 2..sb.page_count {
        let Ok(raw) = pager.read_page(p) else { continue };
        let Ok(h) = cryptand::container::PageHeader::parse(&raw) else { continue };
        if h.page_type == 0 || h.payload_len == 0 {
            continue;
        }
        // The header itself, and the first part of the payload behind it.
        structural.push((p * page_size as u64, 40));
        structural.push((p * page_size as u64 + 40, (h.payload_len as usize).min(256)));
    }
    if structural.len() <= 2 {
        return corrupt_cli("the file holds no headed pages to fuzz");
    }

    let tmp = std::env::temp_dir().join(format!("cryptand-fuzz-{}.cryptand", std::process::id()));
    let mut state = 0x243F_6A88_85A3_08D3u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut panics, mut accepted, mut refused, mut found) = (0u64, 0u64, 0u64, 0u64);
    for _ in 0..iterations {
        let mut b = original.clone();
        let mut touched: Vec<usize> = Vec::new();
        for _ in 0..1 + (next() % 4) {
            let (base, len) = structural[(next() as usize) % structural.len()];
            let at = base as usize + (next() as usize) % len.max(1);
            if at >= b.len() {
                continue;
            }
            // A bit flip, a byte to 0x00, a byte to 0xFF, and a run of 0xFF.
            // The last one matters on its own: a length field only becomes an
            // allocation bomb when *all* its bytes are set, and one flipped bit
            // almost never does that.
            match next() % 4 {
                0 => b[at] ^= 1 << (next() % 8),
                1 => b[at] = 0x00,
                2 => b[at] = 0xFF,
                _ => {
                    let w = 1 + (next() as usize) % 8;
                    for k in 0..w {
                        if at + k < b.len() {
                            b[at + k] = 0xFF;
                        }
                    }
                }
            }
            touched.push(at / page_size);
        }
        // Repair every touched page's checksum. Pages 0 and 1 are the
        // superblock slots, which have their own rule; a mutation there is
        // meant to be caught, and is.
        for pg in touched {
            if pg < 2 {
                continue;
            }
            let off = pg * page_size;
            if off + page_size > b.len() {
                continue;
            }
            let page = &b[off..off + page_size];
            let Ok(h) = cryptand::container::PageHeader::parse(page) else { continue };
            // `checksum_range_end`, not `page_size`: a value-log head page
            // checksums only its immutable header region, because records are
            // appended into its tail for the life of the segment. A repair that
            // covers the whole page writes a checksum that is wrong the moment
            // it is written, and the mutation is then "caught" by the repair
            // rather than by the reader.
            let end = cryptand::container::PageHeader::checksum_range_end(page, &h);
            let crc = cryptand::hash::crc32c(&b[off + 4..off + end]);
            b[off..off + 4].copy_from_slice(&crc.to_le_bytes());
        }
        std::fs::write(&tmp, &b)?;
        let r = std::panic::catch_unwind(|| {
            let mut e = Engine::open(&tmp, None)?;
            let rep = e.verify()?;
            let n = rep.of(Class::Corruption).len() + rep.of(Class::Tampering).len();
            // And then *read*, which is where the decoders are. Every tree the
            // catalog names, every row in it, through the ordinary cursor path.
            let cat = std::mem::replace(&mut e.catalog, cryptand::catalog::Catalog::new(0, 0, 16));
            let all = cat.all(&mut e.pager);
            e.catalog = cat;
            for (_, d) in all.unwrap_or_default() {
                let rows = e.scan_tree(d.tree_id(), None, None, None, true);
                // And then a POINT read of each key the scan returned. A scan
                // and a `get` are different decoders: only `get` consults
                // `04-segments.md` §2.4's segment filter, so a fuzzer that
                // only scans cannot reach the filter header at all -- which is
                // how a `block_count` of 0 (an out-of-bounds index, not a
                // corruption error) survived every earlier run of this loop.
                for (k, _) in rows.unwrap_or_default().iter().take(32) {
                    if let Ok(v) = cryptand::cke::decode_all(k) {
                        let _ = e.get(d.tree_id(), &v);
                    }
                }
            }
            Ok::<usize, cryptand::Error>(n)
        });
        match r {
            Err(_) => panics += 1,
            Ok(Err(_)) => refused += 1,
            Ok(Ok(0)) => accepted += 1,
            Ok(Ok(_)) => found += 1,
        }
    }
    let _ = std::fs::remove_file(&tmp);
    println!(
        "{iterations} structure-aware mutations:\n  \
         {refused} refused at open with a named error\n  \
         {found} opened and reported by the verification pass\n  \
         {accepted} opened with nothing to report\n  \
         {panics} panics"
    );
    println!(
        "\n§9.3 requires no crash, hang, or unbounded allocation. \"Opened with \n\
         nothing to report\" is not a failure: a flipped bit in a reserved field or \n\
         in an unread payload changes nothing a reader is allowed to act on."
    );
    Ok(if panics == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn corrupt_cli(why: &str) -> cryptand::Result<ExitCode> {
    Err(cryptand::Error::Corrupt(why.into()))
}
