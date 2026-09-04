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
        "backup" if args.len() >= 3 && args[1] == "--incremental" => {
            backup(&args[2], &args[3], true)
        }
        "backup" if args.len() >= 3 => backup(&args[1], &args[2], false),
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

/// `14-security.md` §9.3 — structure-aware fuzzing of the reader. "A parser
/// for a format read from untrusted sources that has never been fuzzed is not
/// finished." Every mutation must produce a named error, never a crash, a hang,
/// or an unbounded allocation.
fn fuzz(path: &str, iterations: u64) -> cryptand::Result<ExitCode> {
    let original = std::fs::read(path)?;
    let tmp = std::env::temp_dir().join("cryptand-fuzz.cryptand");
    let mut state = 0x243F_6A88_85A3_08D3u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut panics = 0u64;
    let mut opened = 0u64;
    let mut refused = 0u64;
    for _ in 0..iterations {
        let mut b = original.clone();
        let n = 1 + (next() % 8) as usize;
        for _ in 0..n {
            let at = (next() as usize) % b.len();
            b[at] ^= 1 << (next() % 8);
        }
        std::fs::write(&tmp, &b)?;
        let r = std::panic::catch_unwind(|| {
            let mut e = Engine::open(&tmp, None)?;
            let rep = e.verify()?;
            Ok::<usize, cryptand::Error>(rep.findings.len())
        });
        match r {
            Err(_) => panics += 1,
            Ok(Ok(_)) => opened += 1,
            Ok(Err(_)) => refused += 1,
        }
    }
    let _ = std::fs::remove_file(&tmp);
    println!("{iterations} mutations: {opened} opened, {refused} refused with a named error, {panics} panics");
    Ok(if panics == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}
